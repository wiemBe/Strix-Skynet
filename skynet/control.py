"""Operator messages to agents of a running Strix scan, through the bridge in ``strix_bridge.py``.

Skynet side only: picks the launcher, talks to the bridge's local control endpoint, keeps an encrypted audit of
every message and mirrors the delivery states the bridge reports. States never claim more than was observed:

    sending    stored here, not yet answered by the bridge
    queued     accepted by the bridge for the agent's next model call
    delivered  added to the agent's context (its SDK session and that model call)
    expired    the agent or scan ended before its next model call; never delivered
    rejected   refused (agent not active, budget pause, shutting down, ...)
    unknown    no answer from the bridge (timeout). It may have been accepted; it is never resent automatically.
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import re
import stat
import subprocess
import threading
from pathlib import Path
from typing import Any

from . import crypto, db
from .config import PROJECT_DIR, RUNTIME_DIR

log = logging.getLogger("skynet.control")

BRIDGE = Path(__file__).resolve().parent / "strix_bridge.py"
PROTOCOL = 1
MAX_CONTENT = 4000
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
OPEN_STATES = ("sending", "queued", "unknown")
_FORWARD = {"sending": {"queued", "delivered", "expired", "rejected", "unknown"},
            "unknown": {"queued", "delivered", "expired", "rejected"},
            "queued": {"delivered", "expired"}}
_lock = threading.RLock()
_version_cache: dict[tuple[str, float], str] = {}


class Unavailable(Exception):
    """Messaging cannot be used for this scan; the message says why."""


# ---------------------------------------------------------------- launcher choice
def runtime_python() -> Path:
    return Path(os.environ.get("SKYNET_STRIX_RUNTIME") or PROJECT_DIR / ".strix-runtime" / "bin" / "python").expanduser()


def runtime_version(py: Path) -> str:
    try:
        key = (str(py), py.stat().st_mtime)
    except OSError:
        return ""
    if key not in _version_cache:
        try:
            r = subprocess.run([str(py), "-I", "-c", "import importlib.metadata as m; print(m.version('strix-agent'))"],
                               capture_output=True, text=True, timeout=30)
            _version_cache[key] = r.stdout.strip() if r.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""
    return _version_cache[key]


def _binary_version(text: str) -> str:
    m = re.search(r"(\d+\.\d+\.\d+)", text or "")
    return m.group(1) if m else ""


def bridge_status(settings: dict[str, str], binary_version_text: str) -> dict[str, Any]:
    """Whether new scans start through the bridge. The runtime must be the same Strix version as the configured
    binary, so enabling messaging never silently switches the scan engine to another version."""
    if settings.get("agent_messaging", "1") != "1":
        return {"available": False, "reason": "Agent messaging is turned off in Settings."}
    py = runtime_python()
    if not py.is_file():
        return {"available": False, "reason": f"The Strix runtime for agent messaging is not installed ({py})."}
    rv, bv = runtime_version(py), _binary_version(binary_version_text)
    if not rv:
        return {"available": False, "reason": "The Strix runtime could not report its version."}
    if not bv or rv != bv:
        return {"available": False, "runtime_version": rv,
                "reason": f"Strix runtime {rv} does not match the configured Strix binary {bv or 'unknown'}."}
    return {"available": True, "runtime_version": rv, "reason": ""}


def manifest_path(sid: int) -> Path:
    return RUNTIME_DIR / f"scan_{sid}_control.json"


def state_path(sid: int) -> Path:
    return RUNTIME_DIR / f"scan_{sid}_control_state.json"


def bridge_command(sid: int, strix_args: list[str]) -> tuple[list[str], dict[str, str]]:
    env = {"SKYNET_CONTROL_MANIFEST": str(manifest_path(sid)), "SKYNET_CONTROL_STATE": str(state_path(sid))}
    for p in (manifest_path(sid), state_path(sid)):
        p.unlink(missing_ok=True)      # a stale file from an earlier process must never be trusted
    return [str(runtime_python()), "-I", "-u", str(BRIDGE), *strix_args], env


# ---------------------------------------------------------------- bridge I/O
def _read_private(path: Path) -> dict[str, Any] | None:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
            log.warning("ignoring control file with unsafe permissions: %s", path.name)
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _manifest(scan: dict[str, Any]) -> dict[str, Any]:
    if scan.get("control_mode") != "bridge":
        raise Unavailable("This scan was started without the messaging bridge.")
    if scan.get("status") != "running" or not scan.get("pid"):
        raise Unavailable("Messages can only be sent while the scan is running.")
    m = _read_private(manifest_path(scan["id"]))
    if not m:
        raise Unavailable("The scan's control endpoint is not ready yet (the sandbox may still be starting).")
    port = m.get("port")
    if (m.get("protocol") != PROTOCOL or m.get("pid") != scan["pid"] or not isinstance(port, int)
            or not 1024 <= port <= 65535 or not isinstance(m.get("token"), str)):
        raise Unavailable("The scan's control endpoint did not pass validation.")
    return m


def _call(m: dict[str, Any], method: str, path: str, body: dict[str, Any] | None = None,
          timeout: float = 10.0) -> tuple[int, dict[str, Any]]:
    """Fixed host 127.0.0.1 and the validated port only; http.client never follows redirects."""
    c = http.client.HTTPConnection("127.0.0.1", m["port"], timeout=timeout)
    try:
        raw = json.dumps(body).encode() if body is not None else None
        c.request(method, path, body=raw, headers={"Authorization": f"Bearer {m['token']}", "Host": "127.0.0.1",
                                                   "Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read(256 * 1024)
        return r.status, (json.loads(data) if data else {})
    finally:
        c.close()


def agents(scan: dict[str, Any]) -> dict[str, Any]:
    code, data = _call(_manifest(scan), "GET", "/v1/agents", timeout=5)
    if code != 200:
        raise Unavailable(data.get("reason") or "The scan is not accepting messages.")
    return data


# ---------------------------------------------------------------- audit + states
def _set_state(row_id: int, state: str, reason: str | None = None, **extra: Any) -> None:
    row = db.q1("SELECT state FROM agent_messages WHERE id=?", (row_id,))
    if not row or state == row["state"] or state not in _FORWARD.get(row["state"], set()):
        return
    data = {"state": state, "updated_at": db.now_iso(), **{k: v for k, v in extra.items() if v}}
    if reason is not None:
        data["reason"] = reason[:500]
    db.update("agent_messages", row_id, data)


def _apply(row_id: int, resp: dict[str, Any]) -> None:
    if resp.get("ok"):
        _set_state(row_id, resp.get("state") or "queued", resp.get("reason") or "",
                   accepted_at=resp.get("accepted_at"), delivered_at=resp.get("delivered_at"))
    else:
        _set_state(row_id, "rejected", resp.get("reason") or resp.get("code") or "Rejected by the scan.")


def send(scan: dict[str, Any], agent_id: str, agent_name: str, content: str, request_id: str,
         user: str = "") -> dict[str, Any]:
    """Idempotent by request_id: the same ID with the same content re-asks the bridge (which dedupes), so a retry
    after a timeout can never produce a second message. The same ID with different content is a conflict."""
    content = (content or "").strip()
    if not REQUEST_ID_RE.match(request_id or ""):
        raise ValueError("Invalid request ID.")
    if not agent_id or len(agent_id) > 64:
        raise ValueError("Select an agent.")
    if not content:
        raise ValueError("Write a message first.")
    if len(content) > MAX_CONTENT:
        raise ValueError(f"Messages are limited to {MAX_CONTENT} characters.")
    with _lock:
        row = db.q1("SELECT * FROM agent_messages WHERE request_id=?", (request_id,))
        if row:
            same = (row["scan_id"] == scan["id"] and row["agent_id"] == agent_id
                    and crypto.vault_decrypt(row["content_enc"]) == content)
            if not same:
                raise FileExistsError("This request ID was already used for a different message.")
            if row["state"] not in ("sending", "unknown"):
                return out_row(row)
            row_id = row["id"]
        else:
            _manifest(scan)           # refuse before storing anything if the endpoint is not usable
            row_id = db.insert("agent_messages", {
                "scan_id": scan["id"], "request_id": request_id, "agent_id": agent_id, "agent_name": agent_name[:120],
                "content_enc": crypto.vault_encrypt(content), "state": "sending", "reason": "",
                "created_by": user, "created_at": db.now_iso(), "updated_at": db.now_iso()})
    try:
        code, resp = _call(_manifest(scan), "POST", "/v1/messages",
                           {"request_id": request_id, "agent_id": agent_id, "content": content})
    except Unavailable as e:
        if row:   # an earlier attempt may have reached Strix: never turn that into a final "rejected"
            sync(scan)
            raise
        _set_state(row_id, "rejected", str(e))
        return out_row(db.get("agent_messages", row_id))
    except (OSError, http.client.HTTPException, ValueError):
        code, resp = 0, {}
    if code == 200:
        _apply(row_id, resp)
    elif code in (400, 401, 404, 413):
        _set_state(row_id, "rejected", "The scan's control endpoint refused the request.")
    elif code == 503 and resp.get("code") == "scan_not_ready":
        _set_state(row_id, "rejected", resp.get("reason") or "The scan is not accepting messages.")
    else:
        _set_state(row_id, "unknown", "No confirmation from Strix. The message may have been accepted; "
                                      "it was not resent automatically.")
    return out_row(db.get("agent_messages", row_id))


def recheck(scan: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """Ask the bridge about an unconfirmed message with its original request ID and content. The bridge
    deduplicates by request ID, so this can never create a second copy."""
    if row.get("scan_id") != scan["id"]:
        raise ValueError("Message not found.")
    if row.get("state") not in ("sending", "unknown"):
        return out_row(row)
    try:
        content = crypto.vault_decrypt(row["content_enc"])
    except crypto.DecryptError as e:
        raise Unavailable("The stored message could not be decrypted.") from e
    return send(scan, row["agent_id"], row.get("agent_name") or "", content, row["request_id"], row.get("created_by") or "")


def sync(scan: dict[str, Any]) -> None:
    """Mirror states from the bridge's state file (request IDs and states only, no content)."""
    data = _read_private(state_path(scan["id"]))
    if not data or data.get("protocol") != PROTOCOL:
        return
    by_rid = {m.get("request_id"): m for m in data.get("messages") or [] if isinstance(m, dict)}
    for row in db.q("SELECT id, request_id, state FROM agent_messages WHERE scan_id=? AND state IN (?,?,?)",
                    (scan["id"], *OPEN_STATES)):
        m = by_rid.get(row["request_id"])
        if m:
            _set_state(row["id"], str(m.get("state")), m.get("reason") or "",
                       accepted_at=m.get("accepted_at"), delivered_at=m.get("delivered_at"))


def finalize(scan: dict[str, Any]) -> None:
    """Called when the scan process has ended, before runtime files are removed."""
    sync(scan)
    for row in db.q("SELECT id, state FROM agent_messages WHERE scan_id=? AND state IN (?,?,?)",
                    (scan["id"], *OPEN_STATES)):
        _set_state(row["id"], "expired", "The scan ended before the agent's next model call."
                   if row["state"] == "queued" else "The scan ended without Strix confirming this message.")


def out_row(row: dict[str, Any] | None, redactor: Any = None) -> dict[str, Any]:
    if not row:
        return {}
    try:
        text = crypto.vault_decrypt(row.get("content_enc"))
    except crypto.DecryptError:
        text = ""
    if redactor is not None:
        text = redactor.text(text, strict=True)
    return {k: row.get(k) for k in ("id", "request_id", "agent_id", "agent_name", "state", "reason", "created_by",
                                    "created_at", "accepted_at", "delivered_at", "updated_at")} | {"content": text}


def history(scan: dict[str, Any], redactor: Any) -> list[dict[str, Any]]:
    rows = db.q("SELECT * FROM agent_messages WHERE scan_id=? ORDER BY id DESC LIMIT 50", (scan["id"],))
    return [out_row(r, redactor) for r in rows]


def availability(scan: dict[str, Any]) -> dict[str, Any]:
    if scan.get("control_mode") != "bridge":
        reason = scan.get("control_note") or "This scan was started without the messaging bridge."
        return {"available": False, "reason": reason}
    try:
        _manifest(scan)
    except Unavailable as e:
        return {"available": False, "reason": str(e)}
    return {"available": True, "reason": ""}

