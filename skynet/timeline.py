"""Unified, read-only event timeline for a scan (SKY-06). Replay is a client-side cursor over these records:
building or paging the timeline never sends a request, calls a tool, messages an agent or starts a scan.

Every event has a stable key derived from its source identity, never from agents.db row ids (Strix rewrites a
session by clearing and re-inserting it, which renumbers rows and resets their stored time):
  tool call / result   run:call:<call_id> / run:result:<call_id>
  agent message        run:msg:<agent>:<content digest>:<n-th identical message in that session>
  HTTP request         run:caido:<Caido request id>            (Caido's own request time)
  finding              run:finding:<Strix id>                  (Strix finding timestamp)
  coverage record      run:coverage:<surface digest>:<recorded|updated>
  session evidence     run:auth:<profile id>:<Caido request id>
  operator message     skynet:msg:<request id>:<sent|accepted|in_context|ended>
  scan lifecycle       skynet:scan:<scan id>:<created|started|finished>

Times keep their source: "source" (the producing system's own clock), "skynet" (Skynet's records) or
"session_store" (when Strix stored the item in the agent session). A session-store time shared by many items of
one session indicates a rewrite and is reported as unavailable instead of being used. Ties are flagged; no order
or causality between different sources is asserted.
"""
from __future__ import annotations

import hashlib
import base64
import json
import sqlite3
import threading
import secrets
from contextlib import closing
from pathlib import Path
from typing import Any

from . import activity, db, evidence, runs, session_health, vault

KINDS = {"agent_message": "Agent message", "tool_call": "Tool call", "tool_result": "Tool result",
         "http_request": "HTTP request", "session": "Session evidence", "instruction": "Operator instruction",
         "finding": "Finding", "coverage": "Coverage record", "scan": "Scan"}
SUMMARY = 280


class EventBatch(list):
    """Carry the exact masking context of this list, even during concurrent cache rebuilds."""
    def __init__(self, values, masking_revision: str):
        super().__init__(values)
        self.masking_revision = masking_revision


_cache: dict[int, tuple[str, list[dict[str, Any]], float, float]] = {}   # sig, events, built at, build seconds
_seen: dict[int, dict[str, str]] = {}   # scan -> key -> when Skynet first saw the event (ingest time, this process)
_changed: dict[int, dict[str, tuple[str, str, int]]] = {}  # digest, last change time, ingestion sequence
_sequence: dict[int, int] = {}
_epoch = secrets.token_hex(16)   # old process cursors trigger a full resync, even if the system clock moved
_lock = threading.Lock()


def _digest(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _iso(at: Any) -> str | None:
    if not at:
        return None
    s = str(at).strip().replace(" UTC", "Z").replace(" ", "T")
    return s if s.endswith("Z") or "+" in s[10:] else s + "Z"


def _sig(scan: dict[str, Any], run_dir: Path | None) -> str:
    parts = [scan.get("status"), scan.get("finished_at"), vault.masking_revision(scan)]
    for f in (".state/agents.db", ".state/agents.db-wal", ".state/agents.json", "vulnerabilities.json", "coverage.json"):
        try:
            parts.append((run_dir / f).stat().st_mtime_ns if run_dir else "-")
        except OSError:
            parts.append("-")
    m = db.q1("SELECT COUNT(*) n, MAX(updated_at) u FROM agent_messages WHERE scan_id=?", (scan["id"],)) or {}
    parts += [m.get("n"), m.get("u")]
    return json.dumps(parts, default=str)


def _ev(red: Any, key: str, kind: str, at: str | None, time_source: str | None, summary: str, **kw: Any) -> dict[str, Any]:
    # Mask before truncating: a cut must never expose the prefix of a secret.
    return {"key": key, "kind": kind, "kind_label": KINDS[kind], "at": at,
            "time_source": time_source if at else None, "summary": red.text(str(summary or ""), True)[:SUMMARY], **kw}


def _agent_events(run_dir: Path, run: str, red: Any) -> list[dict[str, Any]]:
    path = run_dir / ".state" / "agents.db"
    if not path.is_file():
        return []
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as c:
            rows = c.execute("SELECT id, session_id, message_data, created_at FROM agent_messages ORDER BY session_id, id").fetchall()
            bursts = evidence.rewritten(c)
    except sqlite3.Error:
        return []
    names: dict[str, str] = {}
    seen: dict[str, int] = {}
    out = []
    for mid, sid, raw, at in rows:
        try:
            m = json.loads(raw)
        except ValueError:
            continue
        typ, cid = m.get("type"), str(m.get("call_id") or "")
        rewritten = (sid, at) in bursts
        when = None if rewritten else _iso(at)
        common = {"agent_id": sid, "seq": mid, "time_note": "Timestamp unavailable: Strix appears to have rewritten "
                  "this agent's session store (many items share one stored second), so that time is the rewrite time." if rewritten else
                  "Time Strix stored the item in the agent session."}
        if typ == "function_call":
            names[cid] = m.get("name") or ""
            text, _ = activity._text(m.get("arguments"), red)
            out.append(_ev(red, f"{run}:call:{cid}", "tool_call", when, "session_store", f"{m.get('name')}: {text}",
                           tool=m.get("name"), call_id=cid, **common))
        elif typ == "function_call_output":
            text, _ = activity._text(m.get("output"), red)
            out.append(_ev(red, f"{run}:result:{cid}", "tool_result", when, "session_store", text, tool=names.get(cid),
                           call_id=cid, **common))
        elif typ == "message" and m.get("role") == "assistant" and isinstance(m.get("content"), list):
            text = "\n".join(v.get("text") for v in m["content"] if isinstance(v, dict) and v.get("type") == "output_text"
                             and isinstance(v.get("text"), str))
            if not text.strip():
                continue
            d = _digest(sid, text)
            n = seen.get(d, 0)
            seen[d] = n + 1
            out.append(_ev(red, f"{run}:msg:{sid}:{d}:{n}", "agent_message", when, "session_store", text, **common))
    return out


def _build(scan: dict[str, Any], run_dir: Path | None, red: Any) -> list[dict[str, Any]]:
    run = scan.get("run_name") or (run_dir.name if run_dir else f"scan{scan['id']}")
    ev: list[dict[str, Any]] = []
    for phase, k in (("created", "created_at"), ("started", "started_at"), ("finished", "finished_at")):
        if scan.get(k):
            ev.append(_ev(red, f"skynet:scan:{scan['id']}:{phase}", "scan", _iso(scan[k]), "skynet",
                          f"Scan {phase}" + (f" ({scan['status']})" if phase == "finished" else ""), seq=0))
    for r in db.q("SELECT * FROM agent_messages WHERE scan_id=? ORDER BY id", (scan["id"],)):
        for phase, k, label in (("sent", "created_at", "Instruction sent"), ("accepted", "accepted_at", "Accepted by Strix"),
                                ("in_context", "delivered_at", "Added to agent context")):
            if r.get(k):
                ev.append(_ev(red, f"skynet:msg:{r['request_id']}:{phase}", "instruction", _iso(r[k]), "skynet",
                              f"{label} · {r.get('agent_name') or r['agent_id']}", agent_id=r["agent_id"],
                              message_id=r["id"], phase=phase, seq=r["id"]))
        if r["state"] in ("expired", "rejected", "unknown"):
            ev.append(_ev(red, f"skynet:msg:{r['request_id']}:ended", "instruction", _iso(r.get("updated_at")), "skynet",
                          f"{ {'expired': 'Not delivered', 'rejected': 'Rejected', 'unknown': 'Unconfirmed'}[r['state']]} · "
                          f"{r.get('agent_name') or r['agent_id']}", agent_id=r["agent_id"], message_id=r["id"],
                          phase=r["state"], seq=r["id"]))
    if run_dir:
        ev += _agent_events(run_dir, run, red)
        for x in evidence.load(run_dir).values():
            li = x.get("listed")
            if not li:
                continue
            ev.append(_ev(red, f"{run}:caido:{x['request_id']}", "http_request", li.get("request_at"), "source",
                          f"{li.get('method')} {li.get('path')} → " + (f"HTTP {li['status']}" if li.get("status") is not None else "no response"),
                          request_id=x["request_id"], agent_id=(x["listed_by"] or [None])[0], full=evidence.full(x),
                          time_note="Caido's own request time.", seq=int(x["request_id"]) if x["request_id"].isdigit() else 0))
        h = session_health.evaluate(scan, run_dir)
        for p in h["profiles"]:
            for s in p["signals"]:
                ev.append(_ev(red, f"{run}:auth:{p['profile_id']}:{s['request_id']}", "session", s["at"],
                              "source" if s["time_source"] == "caido" else "session_store",
                              f"{s['label']} · {p['name']} · {s['method']} {s['path']} (HTTP {s['status']})",
                              agent_id=s["agent_id"], request_id=s["request_id"], signal=s["signal"], seq=0))
        vulns = runs._load_json(run_dir / "vulnerabilities.json")
        for v in vulns if isinstance(vulns, list) else []:
            if isinstance(v, dict) and v.get("id"):
                ev.append(_ev(red, f"{run}:finding:{v['id']}", "finding", _iso(v.get("timestamp")), "source",
                              f"{str(v.get('severity') or '').upper()} · {v.get('title')}", strix_id=str(v["id"]),
                              agent_id=v.get("agent_id"), seq=0, time_note="Strix finding timestamp."))
        cov = runs._load_json(run_dir / "coverage.json")
        for e in (cov or {}).get("entries") or [] if isinstance(cov, dict) else []:
            if not isinstance(e, dict):
                continue
            d = _digest(e.get("surface"), e.get("risk_area"))
            for phase, k in (("recorded", "recorded_at"), ("updated", "updated_at")):
                if e.get(k):
                    # coverage.json is a mutable snapshot, not an outcome revision history.
                    # Its latest outcome cannot be attributed to the original creation time.
                    summary = ("Coverage record created" if phase == "recorded" else
                               str(e.get("outcome_label") or e.get("outcome") or "Coverage record updated"))
                    ev.append(_ev(red, f"{run}:coverage:{d}:{phase}", "coverage", _iso(e[k]), "source",
                                  f"{summary} · {e.get('surface')} ({e.get('risk_area')})",
                                  seq=0, recorded_by=e.get("recorded_by"), time_note="Strix coverage record time."))
    # One entry per key (re-ingest / re-poll / resume can never duplicate).
    uniq: dict[str, dict[str, Any]] = {}
    for e in ev:
        uniq.setdefault(e["key"], e)
    timed = sorted((e for e in uniq.values() if e["at"]), key=lambda e: (e["at"], e["kind"], e.get("seq") or 0, e["key"]))
    untimed = sorted((e for e in uniq.values() if not e["at"]), key=lambda e: (e["kind"], e.get("seq") or 0, e["key"]))
    for i, e in enumerate(timed):
        e["same_time"] = (i > 0 and timed[i - 1]["at"] == e["at"]) or (i + 1 < len(timed) and timed[i + 1]["at"] == e["at"])
    for e in untimed:
        e["time_note"] = e.get("time_note") or "Timestamp unavailable."
    return timed + untimed


def events(scan: dict[str, Any], run_dir: Path | None) -> list[dict[str, Any]]:
    import time
    sig = _sig(scan, run_dir)
    with _lock:
        hit = _cache.get(scan["id"])
        if hit and hit[0] == sig:
            return hit[1]
        # A large live run changes its files every second; when a build is expensive (>= 0.5 s), rebuild at most
        # every 3x its cost. Cheap builds and finished scans are always fresh.
        if (hit and json.loads(hit[0])[2] == json.loads(sig)[2] and hit[3] >= 0.5
                and scan.get("status") in ("queued", "running", "stopping")
                and time.monotonic() - hit[2] < 3 * hit[3]):
            return hit[1]
    started = time.monotonic()
    from datetime import datetime, timezone
    red = vault.scan_redactor(scan)
    # Summaries are masked in _ev before truncation. Identity/ordering fields are machine ids and are left as they
    # are: strict masking would read "...:session:3" or "sid=..." in a key as a credential and merge distinct keys.
    fixed = {"key", "kind", "kind_label", "at", "time_source", "seq", "same_time", "phase", "signal", "full"}
    out = EventBatch(({k: (v if k in fixed or not isinstance(v, (str, list, dict)) else red.obj(v, True))
                      for k, v in e.items()} for e in _build(scan, run_dir, red)), json.loads(sig)[2])
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with _lock:
        seen = _seen.setdefault(scan["id"], {})
        changed = _changed.setdefault(scan["id"], {})
        seq = _sequence.get(scan["id"], 0) + 1
        _sequence[scan["id"]] = seq
        for e in out:
            digest = _digest(json.dumps(e, sort_keys=True, default=str))
            previous = changed.get(e["key"])
            changed[e["key"]] = previous if previous and previous[0] == digest else (digest, now, seq)
            e["skynet_seen_at"] = seen.setdefault(e["key"], now)
            e["skynet_updated_at"] = changed[e["key"]][1]
            e["ingest_sequence"] = changed[e["key"]][2]
        _cache[scan["id"]] = (sig, out, time.monotonic(), time.monotonic() - started)
    return out


def _cursor(point: tuple[int, str]) -> str:
    return "v2:" + base64.urlsafe_b64encode(json.dumps([_epoch, *point]).encode()).decode()


def _cursor_point(value: str) -> tuple[int, str] | None:
    if not value.startswith("v2:"):
        return None  # old clients/processes must reload their history
    try:
        data = json.loads(base64.urlsafe_b64decode(value[3:]))
        if (isinstance(data, list) and len(data) == 3 and isinstance(data[0], str)
                and type(data[1]) is int and data[1] >= 0 and isinstance(data[2], str)):
            return (data[1], data[2]) if data[0] == _epoch else None
    except (ValueError, TypeError):
        pass
    raise ValueError("Invalid timeline cursor")


def page(scan: dict[str, Any], run_dir: Path | None, kinds: list[str] | None = None, agent_id: str | None = None,
         q: str = "", offset: int = 0, limit: int = 200, seen_after: str | None = None) -> dict[str, Any]:
    """seen_after is an opaque (process epoch, ingestion sequence, key) cursor, independent of source clocks.
    Return updates as well as new events. Clients replace by stable key and reload on reset_required."""
    allev = events(scan, run_dir)
    point = lambda e: (e["ingest_sequence"], e["key"])
    high = max((point(e) for e in allev), default=(0, ""))
    def matches(e):
        return ((not kinds or e["kind"] in kinds) and (not agent_id or e.get("agent_id") == agent_id)
                and (not q or q.lower() in e["summary"].lower()))
    sel = [e for e in allev if matches(e)]
    total = len(sel)
    reset_required = False
    limit = max(1, min(500, limit))
    offset = max(0, offset)
    removed = []
    if seen_after:
        after = _cursor_point(seen_after)
        reset_required = after is None
        # Advance through all changes, including records that stopped matching this client's filter.
        # Those keys must be removed from an already-rendered view, rather than kept with old text.
        changes = sorted((e for e in allev if after is None or point(e) > after), key=point)
        batch = changes[offset:offset + limit]
        sel = [e for e in changes if matches(e)]
        items = [e for e in batch if matches(e)]
        removed = [e["key"] for e in batch if not matches(e)]
        more = offset + len(batch) < len(changes)
        now = _cursor(point(batch[-1]) if more and batch else high)
    else:
        items = sel[offset:offset + limit]
        more = offset + len(items) < len(sel)
        now = _cursor(high)
    timed = [e["at"] for e in sel if e["at"]]
    return {"events": items, "offset": offset, "limit": limit, "total": total, "now": now,
            "removed_keys": removed,
            "has_more": more, "reset_required": reset_required, "masking_revision": allev.masking_revision,
            "matched": len(sel),
            "all_total": len(allev), "untimed": sum(1 for e in sel if not e["at"]),
            "range": [timed[0], timed[-1]] if timed else None, "kinds": KINDS,
            "live": scan.get("status") in ("queued", "running", "stopping"),
            "note": "Times keep their source. Events with the same time are not ordered relative to each other, and "
                    "order in time does not show cause."}
