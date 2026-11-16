"""Browser view (SKY-05): what Strix really offers, per agent, without publishing pixels.

Verified against the installed Strix 1.7.0 source (.strix-runtime):
  * Agents drive a headless Chromium inside the sandbox with the agent-browser CLI through exec_command.
    There is no live stream, no CDP endpoint exposed to the host and no screenshot API in the Strix viewer.
  * A screenshot reaches the record only when an agent loads it with the SDK view_image tool; it is then stored as
    an input_image block in that agent's session (agents.db). Older ones are replaced by Strix with
    "[older screenshot elided ...]" to bound context, and the sandbox (with its screenshot folder) is removed
    when the scan ends.
So "Live" is never shown. Images are attributed to the agent whose session holds them.

Image policy: Skynet's masking works on text only and cannot find credentials or personal data inside an image,
so image bytes are never served (not even to the signed-in admin). Only metadata is shown. Reading this module's
output never navigates, sends a request or touches the scan.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redact import Redactor

FRESH_SECONDS = 120
ELIDED = ("[older screenshot elided", "[screenshot omitted from inherited context", "[image rejected by the model")
CAPABILITY = {
    "stream": False,
    "screenshots": "agent_loaded_only",
    "image_policy": "withheld",
    "reason": "Strix 1.7 has no live browser stream. Agents use a headless browser inside the sandbox; a screenshot "
              "is recorded only when an agent loads it with view_image.",
    "policy": "Images are not shown: Skynet cannot mask credentials or personal data inside images. Metadata only.",
    "fresh_seconds": FRESH_SECONDS,
}


def _iso(at: str | None) -> str | None:
    if not at:
        return None
    at = str(at).replace(" ", "T")
    return at if at.endswith("Z") or "+" in at[10:] else at + "Z"


def screenshots(run_dir: Path | None, agent_id: str, red: Redactor) -> list[dict[str, Any]]:
    path = run_dir / ".state" / "agents.db" if run_dir else None
    if not path or not path.is_file() or not agent_id:
        return []
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)) as c:
            rows = c.execute("SELECT id, message_data, created_at FROM agent_messages WHERE session_id=? AND "
                             "json_extract(message_data,'$.type') IN ('function_call','function_call_output') "
                             "AND (message_data LIKE '%input_image%' OR message_data LIKE '%screenshot%' "
                             "OR json_extract(message_data,'$.name')='view_image') ORDER BY id", (agent_id,)).fetchall()
            from .evidence import rewritten
            bursts = rewritten(c)
    except sqlite3.Error:
        return []
    args: dict[str, Any] = {}
    out = []
    for mid, raw, at in rows:
        try:
            m = json.loads(raw)
        except ValueError:
            continue
        cid = str(m.get("call_id") or "")
        if m.get("type") == "function_call":
            if m.get("name") == "view_image":
                try:
                    args[cid] = json.loads(m.get("arguments") or "{}")
                except ValueError:
                    args[cid] = {}
            continue
        blocks = m.get("output") if isinstance(m.get("output"), list) else []
        images = [b for b in blocks if isinstance(b, dict) and b.get("type") == "input_image"]
        elided = [b for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)
                  and b["text"].startswith(ELIDED)]
        if not images and not elided and cid not in args:
            continue
        url = str((images[0] if images else {}).get("image_url") or "")
        out.append({"key": f"{run_dir.name}:shot:{cid}", "call_id": cid, "agent_id": agent_id,
                    "stored_at": None if (agent_id, at) in bursts else _iso(at),
                    "time_source": None if (agent_id, at) in bursts else "session_store",
                    "state": "stored" if images else "elided" if elided else "not_recorded",
                    "media_type": url[5:url.index(";")] if url.startswith("data:") and ";" in url else None,
                    "approx_bytes": int(len(url.split(",", 1)[-1]) * 3 / 4) if images else None,
                    "sandbox_path": red.text(str((args.get(cid) or {}).get("path") or ""), True) or None,
                    "image_withheld": True})
    return out


def view(scan: dict[str, Any], run_dir: Path | None, agent_id: str, red: Redactor,
         now: datetime | None = None) -> dict[str, Any]:
    shots = screenshots(run_dir, agent_id, red)
    stored = [s for s in shots if s["state"] == "stored"]
    latest = stored[-1] if stored else None
    active = scan.get("status") in ("queued", "running", "stopping")
    if not run_dir:
        freshness, label = "unavailable", "Unavailable"
    elif not latest:
        freshness, label = "unavailable", "No screenshot recorded"
    elif not active:
        freshness, label = "recorded", "Recorded"
    else:
        now = now or datetime.now(timezone.utc)
        try:   # a rewritten session has no trustworthy stored time -> never "Latest"
            age = (now - datetime.fromisoformat(latest["stored_at"].replace("Z", "+00:00"))).total_seconds()
        except (ValueError, AttributeError, TypeError):
            age = None
        freshness, label = ("latest", "Latest screenshot") if age is not None and age <= FRESH_SECONDS else ("stale", "Stale")
    return {"agent_id": agent_id, "scan_id": scan["id"], "run_name": scan.get("run_name"), "capability": CAPABILITY,
            "freshness": freshness, "freshness_label": label, "latest": latest, "screenshots": shots[-50:],
            "checked_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")}
