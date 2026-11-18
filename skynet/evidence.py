"""Read-only HTTP exchange records that agents pulled through Strix's Caido proxy tools.

Shared source for session health (SKY-02), the coverage matrix (SKY-03), the timeline (SKY-06) and the finding
evidence workspace (SKY-07). Nothing here writes to the run folder or sends traffic.

What Strix actually records (1.7):
  list_requests  metadata only: Caido request id, method, host, port, path, TLS, response status and Caido's own
                 created_at for the request and the response (the only machine source time for traffic). Caido writes
                 it without a zone and not in UTC; it is converted only when the zone can be derived from GMT Date
                 headers in the same run (caido_offset), otherwise it is treated as unavailable.
  view_request   the full raw request or response for one Caido id, when the agent asked for it. A page that is
                 truncated / has_more is kept but marked incomplete.
  repeat_request / send_request return a response without a new Caido id, so they are not exchange records.
Caido ids are per sandbox, i.e. per Strix run: every key here is scoped by run name.

Raw text never leaves this module unmasked: `public()` applies the scan's redactor. Credential binding checks
(HMAC digests, see verify._binding) run on the raw headers before masking.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .redact import Redactor

MAX_BODY = 64_000


def _decoded(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            pass
    return raw


def parse_http(content: Any, response: bool = False, complete: bool = True) -> dict[str, Any] | None:
    """Share the verification parser's body-framing rules. A completed bodiless request may lack Caido's
    separator; a response or request with an unrecorded body may not."""
    from .verify import _http
    return _http(content, response, complete_request=complete)


def _iso(at: str | None) -> str | None:
    if not at:
        return None
    at = str(at).replace(" ", "T")
    if at.endswith("Z") or "+" in at[10:]:
        return at
    return at + "Z"   # Strix / Caido store naive UTC


REWRITE_BURST = 25   # heuristic: this many items of one session in one stored second = a Strix session rewrite
                     # (normal runs observed here peak at 18 per second; a real rewrite showed 240)


def rewritten(c: sqlite3.Connection) -> set[tuple[str, str]]:
    """(session_id, created_at) pairs whose stored time is a Strix rewrite time, not the item's own time."""
    return {(s, a) for s, a, n in c.execute(
        "SELECT session_id, created_at, COUNT(*) FROM agent_messages GROUP BY session_id, created_at") if n >= REWRITE_BURST}


def load(run_dir: Path | None) -> dict[str, dict[str, Any]]:
    """-> {caido_request_id: exchange} with RAW (unmasked) content. Internal use only."""
    out: dict[str, dict[str, Any]] = {}
    path = run_dir / ".state" / "agents.db" if run_dir else None
    if not path or not path.is_file():
        return out
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as c:
            rows = c.execute(
                "SELECT id, session_id, message_data, created_at FROM agent_messages WHERE "
                "json_extract(message_data,'$.type') IN ('function_call','function_call_output') ORDER BY id").fetchall()
            bursts = rewritten(c)
    except sqlite3.Error:
        return out
    calls: dict[str, tuple[str, Any]] = {}
    for mid, sid, raw, at in rows:
        try:
            m = json.loads(raw)
        except (ValueError, TypeError):
            continue
        cid = str(m.get("call_id") or "")
        if m.get("type") == "function_call":
            if m.get("name") in ("view_request", "list_requests"):
                calls[cid] = (m["name"], _decoded(m.get("arguments")))
            continue
        if cid not in calls:
            continue
        name, args = calls[cid]
        data = _decoded(m.get("output"))
        if not isinstance(data, dict) or not data.get("success", True):
            continue
        if name == "list_requests":
            for e in data.get("entries") or []:
                q, resp = e.get("request") or {}, e.get("response") or {}
                rid = str(q.get("id") or "")
                if not rid:
                    continue
                x = out.setdefault(rid, _blank(rid))
                x["listed"] = {"method": str(q.get("method") or "").upper(), "host": str(q.get("host") or "").lower(),
                               "port": q.get("port"), "path": q.get("path") or "", "tls": bool(q.get("is_tls")),
                               "status": resp.get("status_code"), "_request_naive": q.get("created_at"),
                               "_response_naive": resp.get("created_at") if resp else None}
                if sid not in x["listed_by"]:
                    x["listed_by"].append(sid)
        elif name == "view_request" and isinstance(args, dict):
            rid, part = str(args.get("request_id") or ""), args.get("part", "request")
            if not rid or part not in ("request", "response") or not isinstance(data.get("content"), str):
                continue
            x = out.setdefault(rid, _blank(rid))
            complete = not (data.get("truncated") or data.get("has_more"))
            parsed = parse_http(data["content"], part == "response", complete)
            prev = x[part]
            # Prefer a complete, parseable view; never let a later partial page replace a complete one.
            if prev is None or (not prev["complete"] and complete) or (prev["complete"] == complete and parsed and not prev["parsed"]):
                x[part] = {"raw": data["content"], "parsed": parsed, "complete": complete and bool(parsed),
                           "clipped": len(data["content"]) > MAX_BODY, "agent_id": sid, "message_id": mid,
                           "call_id": cid, "stored_at": None if (sid, at) in bursts else _iso(at)}
            if sid not in x["viewed_by"]:
                x["viewed_by"].append(sid)
    _apply_offset(out)
    return out


def caido_offset(out: dict[str, dict[str, Any]]) -> int | None:
    """Caido's created_at carries no time zone and is not UTC in practice (it follows the sandbox clock's zone).
    Derive the zone offset (seconds, multiple of 15 min) from full responses whose Date header (always GMT) can be
    compared with Caido's own response time. None when no consistent comparison exists."""
    from collections import Counter
    from email.utils import parsedate_to_datetime
    from datetime import datetime, timezone
    votes: Counter[int] = Counter()
    for x in out.values():
        resp = (x.get("response") or {}).get("parsed")
        naive = (x.get("listed") or {}).get("_response_naive") or (x.get("listed") or {}).get("_request_naive")
        if not resp or not naive or not resp["headers"].get("date"):
            continue
        try:
            sent = parsedate_to_datetime(resp["headers"]["date"]).astimezone(timezone.utc)
            local = datetime.fromisoformat(naive[:19]).replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            continue
        diff = (local - sent).total_seconds()
        rounded = int(round(diff / 900.0) * 900)
        if abs(diff - rounded) <= 120 and abs(rounded) <= 14 * 3600:
            votes[rounded] += 1
    if not votes:
        return None
    (best, n), = votes.most_common(1)
    return best if n * 2 > sum(votes.values()) else None   # conflicting evidence -> unknown


def _apply_offset(out: dict[str, dict[str, Any]]) -> None:
    from datetime import datetime, timedelta, timezone
    off = caido_offset(out)
    for x in out.values():
        li = x.get("listed")
        if not li:
            continue
        for k in ("request", "response"):
            naive = li.pop(f"_{k}_naive", None)
            li[f"{k}_at"] = None
            if naive and off is not None:
                try:
                    t = datetime.fromisoformat(naive[:26]).replace(tzinfo=timezone.utc) - timedelta(seconds=off)
                    li[f"{k}_at"] = t.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                except ValueError:
                    pass
        li["caido_offset_minutes"] = off // 60 if off is not None else None


def _blank(rid: str) -> dict[str, Any]:
    return {"request_id": rid, "listed": None, "listed_by": [], "viewed_by": [], "request": None, "response": None}


def full(x: dict[str, Any]) -> bool:
    """A full exchange: both the complete request and the complete response were viewed."""
    return bool(x.get("request") and x["request"]["complete"] and x.get("response") and x["response"]["complete"])


def location(x: dict[str, Any], hmap: dict[str, str]) -> tuple[str, int | None, str, str]:
    """-> (host, port, METHOD, normalized path) from the full request, else the list_requests metadata."""
    from . import scope
    req = (x.get("request") or {}).get("parsed")
    if req:
        url = req["url"]
        if not url.startswith(("http://", "https://")):
            url = "http://" + req["headers"].get("host", "") + url
        _, host, port, path = scope.split(url)
        return hmap.get(host, host), port, req["method"], scope.norm_path(path)
    li = x.get("listed") or {}
    if li:
        return hmap.get(li["host"], li["host"]), li.get("port"), li.get("method") or "", scope.norm_path(li.get("path") or "")
    return "", None, "", ""


def status(x: dict[str, Any]) -> int | None:
    resp = (x.get("response") or {}).get("parsed")
    if resp:
        return resp["status"]
    return (x.get("listed") or {}).get("status")


def source_time(x: dict[str, Any]) -> str | None:
    """Caido's own request time in UTC (machine source), when the agent listed it and Caido's zone is known."""
    return (x.get("listed") or {}).get("request_at")


def date_header(x: dict[str, Any]) -> str | None:
    """The response's own Date header (GMT), a source time independent of Caido's zone."""
    from email.utils import parsedate_to_datetime
    from datetime import timezone
    resp = (x.get("response") or {}).get("parsed")
    if not resp or not resp["headers"].get("date"):
        return None
    try:
        return parsedate_to_datetime(resp["headers"]["date"]).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def best_time(x: dict[str, Any]) -> tuple[str | None, str | None]:
    """-> (time, source): Caido request time, else the response Date header, else when the agent viewed the
    response ("viewed": later than the exchange itself, never used to order conflicting evidence)."""
    if source_time(x):
        return source_time(x), "caido"
    if date_header(x):
        return date_header(x), "date_header"
    at = (x.get("response") or {}).get("stored_at")
    return (at, "viewed") if at else (None, None)


def public(x: dict[str, Any], red: Redactor, run_name: str, roles: dict[str, Any] | None = None) -> dict[str, Any]:
    """Masked, display-safe view. Bodies are plain text: the UI must render them as text nodes."""
    def part(p: dict[str, Any] | None) -> dict[str, Any] | None:
        if not p:
            return None
        return {"text": red.text(p["raw"], strict=True)[:MAX_BODY], "complete": p["complete"], "clipped": p["clipped"],
                "agent_id": p["agent_id"], "stored_at": p["stored_at"], "call_id": p["call_id"]}
    li = x.get("listed")
    return {"key": f"{run_name}:{x['request_id']}", "run_name": run_name, "request_id": x["request_id"],
            "request": part(x.get("request")), "response": part(x.get("response")),
            "listed": red.obj(li, True) if li else None, "full": full(x), "status": status(x),
            "source_time": source_time(x), "viewed_by": x["viewed_by"], "listed_by": x["listed_by"],
            **(roles or {})}
