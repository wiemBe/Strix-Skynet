"""Scan telemetry: model-call volume, retries, latency, cost source, token use and tool activity for one Strix run.

Everything here is read from files Strix writes; Strix exposes no telemetry API. Sources:
  strix.log         structured per-request lines ``strix.llm.request_log: llm_request ... in= out= cached= cost=
                    duration_ms= ttft_ms= outcome= agent= attempt=`` (newer Strix), the DEBUG ``openai.agents:
                    Calling LLM`` line (one per model-call attempt, all versions) and, for retries, the WARNING
                    ``strix.core.execution: ... replaying turn (attempt n/5, backoff ...): <ErrorClass>(...)`` line.
  run.json          llm_usage: the cumulative, authoritative token totals, per-provider/per-agent breakdown and the
                    final cost. Re-read in full each time (small, rewritten by Strix as it goes).
  .state/agents.db  function_call rows give per-agent tool-use counts (session_id == the run.json agent_id).

Parsing is incremental: strix.log is read from a stored, line-aligned byte offset and agents.db from the last row
id seen, so a long scan is not re-parsed every 15 s. Accumulators live in the stored telemetry JSON under ``_acc``.

Time zones: strix.log timestamps are naive *system local* time; agents.db and run.json are UTC. Local log times are
converted with the host's own offset (astimezone), never SKYNET_TIMEZONE. Missing numbers are reported as null (the
UI shows "veri yok"), never as 0, so an unpriced model is not shown as free.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db

log = logging.getLogger("skynet.telemetry")

# ---- strix.log patterns (verified against real runs) ----------------------
_TS = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
_LINE_TS = re.compile("^" + _TS + " ")
_CALLING = re.compile(r"openai\.agents: Calling LLM\b")
_VIEWER = re.compile(r"strix\.interface\.viewer\.server:")
_REQ = re.compile(r"strix\.llm\.request_log: llm_request (.+)$")
_REPLAY = re.compile(r"replaying turn \(attempt (\d+)/(\d+), backoff [\d.]+s\): ([\w.]+)")
_COST_NA = re.compile(r"LiteLLM cost estimate unavailable")
_KV = re.compile(r"(\w+)=(\S+)")
_LOCAL_FMT = "%Y-%m-%d %H:%M:%S.%f"

RETRY_CLASSES = ("rate_limit", "timeout", "connection")


def _classify(err_class: str) -> str:
    e = err_class.lower()
    if "ratelimit" in e or "rate_limit" in e:
        return "rate_limit"
    if "timeout" in e:
        return "timeout"
    return "connection"


def _fresh_acc() -> dict[str, Any]:
    return {"calling_llm": 0, "llm_requests": 0, "llm_errors": 0,
            "retries": {k: 0 for k in RETRY_CLASSES}, "retries_total": 0,
            "duration_ms": 0, "ttft_ms": 0, "ttft_n": 0, "req_models": {},
            "cost_na": False, "last_activity_local": "", "tools": {}}


# ---------------------------------------------------------------- log parsing
def _read_lines(path: Path, offset: int) -> tuple[list[str], int, bool]:
    """Complete lines appended since `offset`. Returns (lines, new line-aligned offset, reset?)."""
    try:
        size = path.stat().st_size
    except OSError:
        return [], offset, False
    reset = False
    if offset > size:          # file was truncated/rewritten (shouldn't happen for append-only logs)
        offset, reset = 0, True
    if offset >= size:
        return [], offset, reset
    with path.open("rb") as f:
        f.seek(offset)
        chunk = f.read(size - offset)
    nl = chunk.rfind(b"\n")
    if nl == -1:               # no complete line yet; wait for more
        return [], offset, reset
    text = chunk[:nl].decode("utf-8", errors="replace")
    return text.split("\n"), offset + nl + 1, reset


def _parse_log(path: Path, offset: int, acc: dict[str, Any]) -> int:
    lines, new_offset, reset = _read_lines(path, offset)
    if reset:
        acc.clear()
        acc.update(_fresh_acc())
        lines, new_offset, _ = _read_lines(path, 0)
    for ln in lines:
        if not ln or _VIEWER.search(ln):
            continue
        m = _LINE_TS.match(ln)
        if m and m.group(1) > acc["last_activity_local"]:
            acc["last_activity_local"] = m.group(1)
        if _CALLING.search(ln):
            acc["calling_llm"] += 1
            continue
        mr = _REQ.search(ln)
        if mr:
            acc["llm_requests"] += 1
            kv = dict(_KV.findall(mr.group(1)))
            if kv.get("outcome") and kv["outcome"] != "success":
                acc["llm_errors"] += 1
            for k in ("duration_ms",):
                if kv.get(k, "-").isdigit():
                    acc[k] += int(kv[k])
            if kv.get("ttft_ms", "-").isdigit():
                acc["ttft_ms"] += int(kv["ttft_ms"]); acc["ttft_n"] += 1
            if kv.get("model"):
                acc["req_models"][kv["model"]] = acc["req_models"].get(kv["model"], 0) + 1
            continue
        mre = _REPLAY.search(ln)
        if mre:
            cls = _classify(mre.group(3))
            acc["retries"][cls] += 1
            acc["retries_total"] += 1
            continue
        if _COST_NA.search(ln):
            acc["cost_na"] = True
    return new_offset


# ---------------------------------------------------------------- agents.db (tool counts)
def _parse_tools(path: Path, after_id: int, acc: dict[str, Any]) -> int:
    if not path.exists():
        return after_id
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        rows = c.execute(
            "SELECT id, session_id, json_extract(message_data,'$.name') AS name FROM agent_messages "
            "WHERE id > ? AND json_extract(message_data,'$.type')='function_call' ORDER BY id", (after_id,)).fetchall()
        c.close()
    except sqlite3.Error as e:
        log.warning("agents.db tool read failed (%s): %s", path.parent.parent.name, e)
        return after_id
    max_id = after_id
    tools = acc["tools"]
    for rid, sid, name in rows:
        max_id = max(max_id, rid)
        if not name:
            continue
        per = tools.setdefault(sid or "?", {})
        per[name] = per.get(name, 0) + 1
    return max_id


# ---------------------------------------------------------------- run.json (authoritative totals)
def _local_to_utc(ts: str) -> str | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, _LOCAL_FMT).astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return None


def _usage(run_json: dict[str, Any]) -> dict[str, Any]:
    return run_json.get("llm_usage") or {}


def _cached(u: dict[str, Any]) -> int | None:
    det = u.get("input_tokens_details")
    if isinstance(det, list):
        return sum(int((d or {}).get("cached_tokens") or 0) for d in det) or None
    if isinstance(det, dict):
        return int(det.get("cached_tokens") or 0) or None
    return None


def _cost(u: dict[str, Any], cost_na: bool) -> dict[str, Any]:
    c = u.get("cost")
    if c is None:
        return {"value": None, "source": "unknown",
                "note": "Strix maliyet bilgisi yazmadı." if not cost_na else "Strix model fiyatını hesaplayamadı."}
    c = float(c)
    if c > 0 and u.get("providers"):
        return {"value": c, "source": "provider", "note": "Sağlayıcının bildirdiği tutar."}
    if c > 0:
        return {"value": c, "source": "estimate", "note": "LiteLLM tahmini."}
    # c == 0
    return {"value": None, "source": "unknown",
            "note": "Strix model fiyatını hesaplayamadı." if cost_na else "Maliyet bilgisi yok."}


def _tokens(u: dict[str, Any]) -> dict[str, Any] | None:
    if not u:
        return None
    out = {"input": u.get("input_tokens"), "output": u.get("output_tokens"),
           "total": u.get("total_tokens"), "cached": _cached(u)}
    return out if any(v is not None for v in out.values()) else None


def _agents(u: dict[str, Any], tools: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    out = []
    for a in u.get("agents") or []:
        aid = a.get("agent_id")
        tc = tools.get(aid, {})
        out.append({"agent_id": aid, "name": a.get("agent_name") or aid, "model": a.get("model"),
                    "requests": a.get("requests"), "tokens": a.get("total_tokens"),
                    "cost": a.get("cost") if (a.get("cost") or 0) > 0 else None,
                    "tools_total": sum(tc.values()), "tools": dict(sorted(tc.items(), key=lambda x: -x[1]))})
    return out


# ---------------------------------------------------------------- public build
def _build(run_json: dict[str, Any], acc: dict[str, Any]) -> dict[str, Any]:
    u = _usage(run_json)
    attempts = max(acc["calling_llm"], acc["llm_requests"]) or None
    completed = u.get("requests")
    tool_totals: dict[str, int] = {}
    for per in acc["tools"].values():
        for name, n in per.items():
            tool_totals[name] = tool_totals.get(name, 0) + n
    return {
        "available": bool(u or attempts or tool_totals or acc["last_activity_local"]),
        "requests": {"completed": completed, "attempts": attempts, "errors": acc["llm_errors"] or None},
        "retries": {"total": acc["retries_total"], **acc["retries"]},
        "latency": {"avg_request_ms": round(acc["duration_ms"] / acc["llm_requests"]) if acc["llm_requests"] else None,
                    "avg_ttft_ms": round(acc["ttft_ms"] / acc["ttft_n"]) if acc["ttft_n"] else None},
        "cost": _cost(u, acc["cost_na"]),
        "tokens": _tokens(u),
        "tools": {"total": sum(tool_totals.values()) or None,
                  "by_name": dict(sorted(tool_totals.items(), key=lambda x: -x[1]))},
        "agents": _agents(u, acc["tools"]),
        "last_activity": _local_to_utc(acc["last_activity_local"]),
        "models": _models(u, acc["req_models"]),
    }


def _models(u: dict[str, Any], req_models: dict[str, int]) -> list[str]:
    """Model ids used, deduplicated: run.json carries the provider-prefixed form (openrouter/x), the log the
    bare form (x); keep the longer when one is a path suffix of the other."""
    names = {a.get("model") for a in u.get("agents") or [] if a.get("model")}
    names |= set(req_models)
    out = set(names)
    for n in names:
        for other in names:
            if other != n and other.endswith("/" + n):
                out.discard(n)   # n is the bare suffix of a prefixed id already present
                break
    return sorted(out)


# ---------------------------------------------------------------- entry points
def collect(scan: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    """Parse new output since the last call, persist, and return the public telemetry dict. Never raises."""
    sid = scan["id"]
    try:
        row = db.q1("SELECT * FROM scan_telemetry WHERE scan_id=?", (sid,)) or {}
        stored = row.get("telemetry") if isinstance(row.get("telemetry"), dict) else {}
        acc = stored.get("_acc") or _fresh_acc()
        for k, v in _fresh_acc().items():          # tolerate older rows missing a key
            acc.setdefault(k, v)
        offset = int(row.get("log_offset") or 0)
        max_id = int(row.get("agents_max_id") or 0)
        from . import runs
        rj = runs._load_json(run_dir / "run.json") or {}
        offset = _parse_log(run_dir / "strix.log", offset, acc)
        max_id = _parse_tools(run_dir / ".state" / "agents.db", max_id, acc)
        pub = _build(rj, acc)
        payload = {**pub, "_acc": acc}
        db.execute(
            "INSERT INTO scan_telemetry (scan_id, run_name, collected_at, log_offset, agents_max_id, telemetry) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET run_name=excluded.run_name, "
            "collected_at=excluded.collected_at, log_offset=excluded.log_offset, "
            "agents_max_id=excluded.agents_max_id, telemetry=excluded.telemetry",
            (sid, run_dir.name, db.now_iso(), offset, max_id, json.dumps(payload)))
        return pub
    except Exception:
        log.exception("telemetry collect failed for scan %s", sid)
        return {}


def get(scan_id: int) -> dict[str, Any] | None:
    """Stored telemetry for the API (without the internal accumulators)."""
    row = db.q1("SELECT telemetry, collected_at FROM scan_telemetry WHERE scan_id=?", (scan_id,))
    if not row or not isinstance(row.get("telemetry"), dict):
        return None
    t = {k: v for k, v in row["telemetry"].items() if k != "_acc"}
    t["collected_at"] = row.get("collected_at")
    return t
