"""Management report data for one target or one campaign (rendered as a printable page; Save as PDF in the browser).

Rules (see docs/FEATURE_BACKLOG.md): no invented data. There is no remediation deadline (SLA) in Skynet, so the
report shows the age of open findings and time-to-fix instead of "deadline compliance". Cancelled, failed or
interrupted scans are drawn in the trend but marked incomplete, never presented as an improvement. Coverage comes
from one named scan. Finding text passes through the vault redactor, like every other findings response.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from . import campaigns, coverage_matrix, db, findings_store, runs, vault

TREND_SCANS = 12
TOP_OPEN = 6
SEVERITIES = runs.SEVERITIES


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    text = str(v).strip()
    if text.upper().endswith(" UTC") or text.upper().endswith("UTC"):   # e.g. coverage-style "2026-11-15 09:10:00 UTC"
        text = text[:-3].strip() + "+00:00"
    try:
        d = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _days(a: datetime | None, b: datetime | None) -> float | None:
    return None if not a or not b else max(0.0, (b - a).total_seconds() / 86400)


def _stats(values: list[float]) -> dict[str, Any]:
    return {"n": len(values), "median": round(median(values), 1) if values else None,
            "max": round(max(values), 1) if values else None}


def _complete(s: dict[str, Any]) -> bool:
    return s["status"] == "completed" and ((s.get("summary") or {}).get("run_status") in (None, "completed"))


def _trend(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [s for s in scans if s.get("trigger") != "verify" and s["status"] not in ("queued", "running", "stopping")]
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    rows = sorted(rows, key=lambda s: (_dt(s.get("started_at") or s.get("created_at")) or epoch, s["id"]))[-TREND_SCANS:]
    out = []
    for s in rows:
        counts = (s.get("summary") or {}).get("counts") or {}
        out.append({"scan_id": s["id"], "at": s.get("started_at") or s.get("created_at"), "status": s["status"],
                    "complete": _complete(s), "target_name": s.get("target_name"), "scan_mode": s.get("scan_mode"),
                    "counts": {k: int(counts.get(k) or 0) for k in SEVERITIES} if counts else None})
    return out


def _coverage(scans: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Coverage summary of the most recent completed (non-verification) scan that has an output folder."""
    for s in scans:   # newest first
        if s.get("trigger") == "verify" or not _complete(s) or not s.get("run_dir"):
            continue
        rd = Path(s["run_dir"])
        if not rd.is_dir():
            continue
        m = coverage_matrix.build(s, rd)
        counts = {k: 0 for k in coverage_matrix.STATUS}
        for c in m.get("cells") or []:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        return {"scan_id": s["id"], "at": s.get("started_at"), "target_name": s.get("target_name"),
                "available": bool(m.get("available")), "counts": counts, "labels": coverage_matrix.STATUS_LABEL,
                "cells": sum(counts.values()), "complete": m.get("complete"), "gaps": (m.get("gaps") or [])[:3],
                "rule": m.get("rule")}
    return None


def _findings(scan_ids: list[int], now: datetime) -> dict[str, Any]:
    groups = findings_store.groups_for_scans(scan_ids)
    summary = findings_store.summary(groups)
    open_age: dict[str, list[float]] = {s: [] for s in SEVERITIES}
    fix_days: dict[str, list[float]] = {s: [] for s in SEVERITIES}
    top = []
    for g in groups:
        sev = g["severity"] if g["severity"] in open_age else "info"
        first = _dt(g.get("first_seen_at"))
        if g["remediation"] == "open":
            age = _days(first, now)
            if age is not None:
                open_age[sev].append(age)
            top.append((g, age))
        elif g["remediation"] == "fixed":
            d = _days(first, _dt(g.get("remediation_at")))
            if d is not None:
                fix_days[sev].append(d)
    top.sort(key=lambda x: (-runs.SEV_RANK.get(x[0]["severity"], 0), -(x[1] or 0)))
    open_rows = []
    for g, age in top[:TOP_OPEN]:
        red = vault.finding_redactor(g["id"])
        open_rows.append(red.obj({"id": g["id"], "title": g.get("title"), "severity": g["severity"], "cwe": g.get("cwe"),
                                  "where": " ".join(x for x in (g.get("method"), g.get("endpoint")) if x), "host": g.get("host"),
                                  "target_name": g.get("target_name"), "first_seen_at": g.get("first_seen_at"),
                                  "last_seen_at": g.get("last_seen_at"), "age_days": None if age is None else round(age),
                                  "occurrences": g.get("occurrences"), "seen_after_fix": bool(g.get("seen_after_fix"))}, True))
    all_fix = [d for v in fix_days.values() for d in v]
    return {"summary": summary, "open_total": sum(summary["open_counts"].values()), "open_more": max(0, len(top) - TOP_OPEN),
            "open_age": {s: _stats(v) for s, v in open_age.items()},
            "time_to_fix": {**{s: _stats(v) for s, v in fix_days.items()}, "all": _stats(all_fix)},
            "top_open": open_rows}


def _scan_stats(scans: list[dict[str, Any]]) -> dict[str, Any]:
    regular = [s for s in scans if s.get("trigger") != "verify"]
    done = [s for s in regular if _complete(s)]
    ended = [s for s in regular if s["status"] not in ("queued", "running", "stopping")]
    dates = sorted(d for d in (s.get("started_at") or s.get("created_at") for s in regular) if d)
    return {"total": len(regular), "completed": len(done), "incomplete": len(ended) - len(done),
            "active": len(regular) - len(ended), "verifications": len(scans) - len(regular),
            "first_at": dates[0] if dates else None, "last_at": dates[-1] if dates else None,
            "last_completed_at": max((s.get("started_at") or "" for s in done), default=None) or None}


def for_target(tid: int) -> dict[str, Any]:
    t = db.get("targets", tid)
    scans = db.list_scans(target_id=tid, limit=5000)
    now = datetime.now(timezone.utc)
    return {"kind": "target", "id": tid, "name": t["name"], "environment": t.get("environment"),
            "subtitle": t.get("base_url"), "generated_at": now.isoformat(timespec="seconds"),
            "scans": _scan_stats(scans), "trend": _trend(scans), "coverage": _coverage(scans),
            "findings": _findings([s["id"] for s in scans], now), "targets": None, **_notes()}


def for_campaign(cid: int) -> dict[str, Any]:
    c = db.get("campaigns", cid)
    ids = campaigns.scan_ids(cid)
    scans = sorted((db.get_scan(i) for i in ids), key=lambda s: (s.get("started_at") or s.get("created_at") or "", s["id"]),
                   reverse=True)
    now = datetime.now(timezone.utc)
    per_target = []
    for tid in campaigns.target_ids(cid):
        t = db.get("targets", tid)
        if not t:
            continue
        ts = [s for s in scans if s.get("target_id") == tid]
        f = findings_store.summary(findings_store.groups_for_scans([s["id"] for s in ts]))
        cov = _coverage(ts)
        per_target.append({"id": tid, "name": t["name"], "environment": t.get("environment"), "scans": _scan_stats(ts),
                           "open_counts": f["open_counts"], "coverage": cov and {k: cov[k] for k in ("scan_id", "counts", "cells", "available")}})
    return {"kind": "campaign", "id": cid, "name": c["name"], "environment": c.get("environment") or None,
            "subtitle": (c.get("description") or "").strip()[:200], "campaign_status": c.get("status"),
            "generated_at": now.isoformat(timespec="seconds"), "scans": _scan_stats(scans), "trend": _trend(scans),
            "coverage": None, "findings": _findings(ids, now), "targets": per_target, **_notes()}


def _notes() -> dict[str, Any]:
    return {"notes": [
        "Findings come from Strix agents, grouped by fingerprint (a correlation, not proof of one root cause).",
        "\"Fixed\" is an analyst's status in Skynet, not proof; a finding missing from a later scan is not counted as fixed.",
        "Incomplete scans (cancelled, failed, interrupted) are marked in the trend; their lower counts are not an improvement.",
        "Coverage \"Tested\" needs a verified test with linked evidence; it does not mean secure. No SLA data exists for deadline compliance.",
    ]}
