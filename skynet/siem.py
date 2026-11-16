"""RFC 5424 audit export with a durable outbox. No network work in audit.record().

TCP/TLS use octet-counted framing. A successful send is a transport handoff, never
an ingestion acknowledgement. Retries can duplicate an event; event_id is stable.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import threading
import time
import uuid

from . import db, vault

DEFAULTS = {"enabled": False, "host": "", "port": 6514, "transport": "tls", "facility": 16,
            "source_hostname": "skynet", "ca_file": "", "server_name": "", "client_cert": "", "client_key": ""}
ERRORS = {"tls": "TLS authentication or certificate validation failed.", "dns": "Collector name could not be resolved.",
          "timeout": "Collector connection timed out.", "network": "Collector connection or send failed.",
          "masking": "Audit masking context is unavailable; no unmasked event was sent.",
          "config": "Saved collector configuration could not be loaded."}
_wake, _stop = threading.Event(), threading.Event()
_worker = None
_start_lock = threading.Lock()
_dispatch_lock = threading.Lock()


def _host(value, optional=False):
    value = str(value or "").strip()
    if not value and optional:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not value or len(value) > 253 or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", p)
                                           for p in value.rstrip(".").split(".")):
        raise ValueError("Collector must be an IP address or DNS name, without a scheme, path or credentials.")
    return value.rstrip(".")


def validate(body):
    if not isinstance(body, dict) or set(body) - set(DEFAULTS):
        raise ValueError("Unknown syslog setting.")
    out = {**DEFAULTS, **body}
    if not isinstance(out["enabled"], bool):
        raise ValueError("Enabled must be true or false.")
    if out["transport"] not in ("udp", "tcp", "tls"):
        raise ValueError("Transport must be UDP, TCP or TLS.")
    for k, low, high in (("port", 1, 65535), ("facility", 0, 23)):
        try:
            if isinstance(out[k], bool) or str(int(out[k])) != str(out[k]).strip() or not low <= int(out[k]) <= high:
                raise ValueError()
            out[k] = int(out[k])
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"{k.title()} must be an integer between {low} and {high}.") from None
    out["host"] = _host(out["host"], optional=not out["enabled"])
    out["server_name"] = _host(out["server_name"], optional=True)
    source = str(out["source_hostname"] or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", source):
        raise ValueError("Source hostname must be 1–255 ASCII letters, digits, dots, underscores or hyphens.")
    out["source_hostname"] = source
    for key in ("ca_file", "client_cert", "client_key"):
        value = str(out[key] or "").strip()
        if value and (not Path(value).is_absolute() or any(ord(c) < 32 for c in value) or len(value) > 1024):
            raise ValueError("TLS file paths must be absolute server paths without control characters.")
        out[key] = value
    if out["transport"] != "tls":
        for key in ("ca_file", "server_name", "client_cert", "client_key"):
            out[key] = ""
    elif bool(out["client_cert"]) != bool(out["client_key"]):
        raise ValueError("Provide both a client certificate and its private key, or neither.")
    return out


def configuration():
    row = db.q1("SELECT * FROM syslog_config WHERE id=1")
    return {**row, "settings": {**DEFAULTS, **json.loads(row["settings"])}}


def save(body):
    config = validate(body)
    with db._lock:
        c = db.conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            old = configuration()
            if config != old["settings"]:
                generation = old["generation"] + 1
                c.execute("UPDATE syslog_config SET settings=?, enabled=?, generation=? WHERE id=1",
                          (json.dumps(config), int(config["enabled"]), generation))
                # Do not send a previous destination's backlog to a newly selected SIEM.
                c.execute("UPDATE syslog_outbox SET state='superseded' WHERE state='pending' AND generation<>?", (generation,))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    _wake.set()
    return public()


def public():
    config = configuration()
    counts = {r["state"]: r["n"] for r in db.q("SELECT state,COUNT(*) AS n FROM syslog_outbox GROUP BY state")}
    last = db.q1("SELECT last_attempt_at,transport_handoff_at,last_error FROM syslog_outbox "
                 "WHERE generation=? AND attempts>0 ORDER BY last_attempt_at DESC,audit_id DESC LIMIT 1", (config["generation"],)) or {}
    failure = db.q1("SELECT last_error,last_attempt_at FROM syslog_outbox WHERE generation=? "
                    "AND state='pending' AND last_error<>'' ORDER BY last_attempt_at DESC,audit_id DESC LIMIT 1", (config["generation"],)) or {}
    handoff = db.q1("SELECT MAX(transport_handoff_at) AS at FROM syslog_outbox WHERE generation=?", (config["generation"],))
    handed_off = db.q1("SELECT COUNT(*) AS n FROM syslog_outbox WHERE transport_handoff_at IS NOT NULL")["n"]
    return {"settings": config["settings"], "instance_id": config["instance_id"], "generation": config["generation"],
            "status": {"worker_running": bool(_worker and _worker.is_alive()), "pending": counts.get("pending", 0),
                       "handed_off": handed_off, "overflow": counts.get("overflow", 0),
                       "superseded": counts.get("superseded", 0), "last_attempt_at": last.get("last_attempt_at"),
                       "last_handoff_at": handoff["at"], "last_error": ERRORS.get(failure.get("last_error"), ""),
                       "last_error_at": failure.get("last_attempt_at"),
                       "ingestion_confirmed": False, "pending_limit": 10000}}


def message(event, config, instance_id):
    red = vault.stored_redactor()
    # Project only audit metadata: no request body, prompt, evidence or raw runtime log.
    fields = ("id", "at", "actor", "actor_id", "actor_role", "action", "object_type", "object_id", "summary", "method", "path", "status", "ip")
    payload = red.obj({k: event.get(k) for k in fields}, strict=True)
    payload.update(schema="skynet.audit.v1", event_id=f"{instance_id}:{event['id']}")
    host = red.text(config["source_hostname"], strict=True)
    host = host if re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", host) else "-"
    # Header action is also masked; MSGID is restricted to RFC PRINTUSASCII.
    action = red.text(str(event.get("action") or "audit"), strict=True)
    action = re.sub(r"[^A-Za-z0-9_.-]", "_", action)[:32] or "audit"
    at = str(event.get("at") or "")
    try:
        timestamp = datetime.fromisoformat(at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        timestamp = "-"
    status = event.get("status") or 0
    severity = 3 if status >= 500 else 4 if status >= 400 else 6
    # ASCII JSON represents Unicode with escapes, avoids BOM ambiguity and log injection.
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return f"<{config['facility'] * 8 + severity}>1 {timestamp} {host} skynet {os.getpid()} {action} - {body}".encode("ascii")


def send(config, packet):
    if config["transport"] == "udp":
        family, kind, proto, _, addr = socket.getaddrinfo(config["host"], config["port"], type=socket.SOCK_DGRAM)[0]
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(3)
            sock.sendto(packet, addr)
        return
    context = None
    if config["transport"] == "tls":
        try:
            context = ssl.create_default_context(cafile=config["ca_file"] or None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if config["client_cert"]:
                # Never allow OpenSSL to prompt on the server's stdin for a key password.
                context.load_cert_chain(config["client_cert"], config["client_key"], password=lambda: "")
        except (OSError, ValueError):
            raise ssl.SSLError("TLS trust or client certificate could not be loaded") from None
    with socket.create_connection((config["host"], config["port"]), timeout=3) as raw:
        frame = str(len(packet)).encode("ascii") + b" " + packet
        if config["transport"] == "tls":
            with context.wrap_socket(raw, server_hostname=config["server_name"] or config["host"]) as tls:
                tls.sendall(frame)
        else:
            raw.sendall(frame)


def _error(exc):
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return "network"


def test(body):
    config = validate(body)
    if not config["host"]:
        raise ValueError("Set a collector address before testing.")
    event = {"id": "test-" + uuid.uuid4().hex, "at": db.now_iso(), "actor": "system", "action": "syslog.probe", "summary": "Skynet syslog integration test", "status": 200}
    try:
        packet = message(event, config, configuration()["instance_id"])
    except Exception:
        return {"ok": False, "message": ERRORS["masking"], "ingestion_confirmed": False}
    try:
        send(config, packet)
        return {"ok": True, "message": "Test handed to transport. Verify receipt in your SIEM; ingestion is not acknowledged.", "ingestion_confirmed": False}
    except (OSError, ValueError) as exc:
        return {"ok": False, "message": ERRORS[_error(exc)], "ingestion_confirmed": False}


def dispatch_once(now=None):
    """One due event, no DB lock held during networking. Safe for one service process."""
    if not _dispatch_lock.acquire(blocking=False):
        return False
    try:
        now = time.time() if now is None else now
        started = time.monotonic()
        config = configuration()
        if not config["enabled"]:
            return False
        row = db.q1("SELECT o.*,a.at,a.actor,a.actor_id,a.actor_role,a.action,a.object_type,a.object_id,a.summary AS audit_summary,a.method,a.path,a.status,a.ip "
                    "FROM syslog_outbox o JOIN audit_log a ON a.id=o.audit_id "
                    "WHERE o.state='pending' AND o.generation=? AND o.next_attempt_at<=? ORDER BY o.audit_id LIMIT 1", (config["generation"], now))
        if not row:
            return False
        error = ""
        try:
            packet = message({**row, "id": row["audit_id"], "summary": row["audit_summary"]}, config["settings"], config["instance_id"])
        except Exception:
            error = "masking"
        if not error:
            try:
                # A disabled/changed config must not start another send. One already
                # in flight can finish; bytes already handed off cannot be revoked.
                latest = configuration()
                if latest["generation"] != config["generation"] or not latest["enabled"]:
                    return True
                send(config["settings"], packet)
            except (OSError, ValueError) as exc:
                error = _error(exc)
        at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        db.execute("UPDATE syslog_outbox SET attempts=attempts+1,last_attempt_at=?,last_error=?,"
                   "state=CASE WHEN state='superseded' THEN state ELSE ? END,"
                   "transport_handoff_at=?,next_attempt_at=? WHERE audit_id=? AND generation=?",
                   (at, error, "pending" if error else "handed_off", None if error else at,
                    now + max(0, time.monotonic() - started) + min(300, 2 ** min(row["attempts"] + 1, 9)) if error else 0,
                    row["audit_id"], config["generation"]))
        return True
    finally:
        _dispatch_lock.release()


def _loop():
    while not _stop.is_set():
        try:
            if dispatch_once():
                continue
        except Exception:
            # Do not recurse into audit/log export or expose exception text with secrets.
            pass
        _wake.wait(1)
        _wake.clear()


def start():
    global _worker
    with _start_lock:
        if _worker and _worker.is_alive():
            return
        _stop.clear()
        _worker = threading.Thread(target=_loop, name="skynet-syslog", daemon=True)
        _worker.start()


def stop():
    _stop.set()
    _wake.set()
    if _worker:
        _worker.join(timeout=1)
