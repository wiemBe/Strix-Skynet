"""Management report data for one target or one campaign (rendered as a printable page; Save as PDF in the browser).

Rules (see docs/FEATURE_BACKLOG.md): no invented data. There is no remediation deadline (SLA) in Skynet, so the
report shows the age of open findings and time-to-fix instead of "deadline compliance". Cancelled, failed or
interrupted scans are drawn in the trend but marked incomplete, never presented as an improvement. Coverage comes
from one named scan. Finding text passes through the vault redactor, like every other findings response.
"""
from __future__ import annotations

import html
import re
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
    return None if not a or not b or b < a else (b - a).total_seconds() / 86400


def _scan_key(s: dict[str, Any]) -> tuple[datetime, int]:
    return (_dt(s.get("started_at")) or _dt(s.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc), s["id"])


def _stats(values: list[float]) -> dict[str, Any]:
    return {"n": len(values), "median": round(median(values), 1) if values else None,
            "max": round(max(values), 1) if values else None}


def _complete(s: dict[str, Any]) -> bool:
    return s["status"] == "completed" and ((s.get("summary") or {}).get("run_status") in (None, "completed"))


def _trend(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [s for s in scans if s.get("trigger") != "verify" and s["status"] not in ("queued", "running", "stopping")]
    rows = sorted(rows, key=_scan_key)[-TREND_SCANS:]
    out = []
    for s in rows:
        counts = (s.get("summary") or {}).get("counts") or {}
        out.append({"scan_id": s["id"], "at": s.get("started_at") or s.get("created_at"), "status": s["status"],
                    "complete": _complete(s), "target_name": s.get("target_name"), "scan_mode": s.get("scan_mode"),
                    "counts": {k: int(counts.get(k) or 0) for k in SEVERITIES} if counts else None})
    return out


def _coverage(scans: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Coverage summary of the most recent completed (non-verification) scan that has an output folder."""
    for s in sorted(scans, key=_scan_key, reverse=True):
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
    fixed_unknown = 0
    for g in groups:
        sev = g["severity"] if g["severity"] in open_age else "info"
        first = _dt(g.get("first_seen_at"))
        if g["remediation"] == "open":
            age = _days(first, now)
            if age is not None:
                open_age[sev].append(age)
            top.append((g, age))
        elif g["remediation"] == "fixed":
            d = _days(first, _dt(g.get("fixed_at")))
            if d is not None:
                fix_days[sev].append(d)
            else:
                fixed_unknown += 1
    top.sort(key=lambda x: (-runs.SEV_RANK.get(x[0]["severity"], 0), -(x[1] or 0)))
    # Include every status in the detailed register; summary keeps only the top open findings.
    by_id = {}
    for g in groups:
        age = _days(_dt(g.get("first_seen_at")), now) if g["remediation"] == "open" else None
        red = vault.finding_redactor(g["id"])
        by_id[g["id"]] = red.obj({"id": g["id"], "title": g.get("title"), "severity": g["severity"], "cwe": g.get("cwe"),
                                  "where": " ".join(x for x in (g.get("method"), g.get("endpoint")) if x), "host": g.get("host"),
                                  "target_name": g.get("target_name"), "first_seen_at": g.get("first_seen_at"),
                                  "last_seen_at": g.get("last_seen_at"), "age_days": None if age is None else round(age, 2),
                                  "remediation": g["remediation"], "remediation_note": g.get("remediation_note"),
                                  "fixed_at": g.get("fixed_at"), "scan_ids": g.get("scan_ids_here") or [],
                                  "occurrences": g.get("occurrences_here", 0), "seen_after_fix": bool(g.get("seen_after_fix"))}, True)
    open_rows = [by_id[g["id"]] for g, _ in top[:TOP_OPEN]]
    register = sorted(groups, key=lambda g: (findings_store.REMEDIATION.index(g["remediation"])
                      if g["remediation"] in findings_store.REMEDIATION else 99,
                      -runs.SEV_RANK.get(g["severity"], 0), g["id"]))
    all_fix = [d for v in fix_days.values() for d in v]
    return {"summary": summary, "open_total": sum(summary["open_counts"].values()), "open_more": max(0, len(top) - TOP_OPEN),
            "open_age": {s: _stats(v) for s, v in open_age.items()},
            "time_to_fix": {**{s: _stats(v) for s, v in fix_days.items()}, "all": _stats(all_fix)},
            "fixed_time_unknown": fixed_unknown,
            "open_age_unknown": sum(1 for _, age in top if age is None),
            "top_open": open_rows, "register": [by_id[g["id"]] for g in register]}


def _scan_stats(scans: list[dict[str, Any]]) -> dict[str, Any]:
    regular = [s for s in scans if s.get("trigger") != "verify"]
    done = [s for s in regular if _complete(s)]
    ended = [s for s in regular if s["status"] not in ("queued", "running", "stopping")]
    dates = sorted(d for d in (_dt(s.get("started_at")) or _dt(s.get("created_at")) for s in regular) if d)
    completed_dates = [_dt(s.get("started_at")) or _dt(s.get("created_at")) for s in done]
    completed_dates = [d for d in completed_dates if d]
    return {"total": len(regular), "completed": len(done), "incomplete": len(ended) - len(done),
            "active": len(regular) - len(ended), "verifications": len(scans) - len(regular),
            "findings_unavailable": sum(1 for s in done if (s.get("summary") or {}).get("counts") is None
                                        or (s.get("summary") or {}).get("findings_available") is False),
            "first_at": dates[0].isoformat() if dates else None, "last_at": dates[-1].isoformat() if dates else None,
            "last_completed_at": max(completed_dates).isoformat() if completed_dates else None}


def _scope(t: dict[str, Any]) -> dict[str, Any]:
    return {"name": t["name"], "base_url": t.get("base_url"), "in_scope": t.get("in_scope") or [],
            "out_of_scope": t.get("out_of_scope") or [], "extra_targets": t.get("extra_targets") or []}


def _executive(scans: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]:
    """Deterministic statements from recorded data, never an inferred security score."""
    counts = findings["summary"]["open_counts"]
    total = findings["open_total"]
    if not scans["completed"]:
        headline = "Assessment incomplete"
    elif counts["critical"] or counts["high"]:
        headline = "Critical or high findings remain open"
    elif scans.get("findings_unavailable"):
        headline = "Finding data incomplete"
    elif total:
        headline = "Open findings need remediation"
    else:
        headline = "No findings currently marked open"
    actions = []
    if counts["critical"] or counts["high"]:
        priority = " and ".join(f"{counts[s]} {s}" for s in ("critical", "high") if counts[s])
        noun = "finding" if counts["critical"] + counts["high"] == 1 else "findings"
        actions.append(f"Prioritize triage and remediation of {priority} open {noun}.")
    if scans.get("findings_unavailable"):
        actions.append(f"Restore or review finding data for {scans['findings_unavailable']} completed scans; missing results are not zero findings.")
    if findings["summary"]["seen_after_fix"]:
        actions.append(f"Review {findings['summary']['seen_after_fix']} findings seen again after being marked fixed.")
    if scans["incomplete"] or not scans["completed"]:
        actions.append("Complete a full assessment; incomplete runs cannot establish an improvement in security.")
    if scans["active"]:
        actions.append(f"Re-generate this report after {scans['active']} queued or active scans finish.")
    if not actions:
        actions.append("Triage remaining open findings and verify remediation with fresh evidence." if total else
                       "Continue periodic testing; absence of open findings does not establish that the application is secure.")
    return {"headline": headline,
            "summary": f"{total} open finding groups out of {findings['summary']['unique']} recorded; "
                       f"{scans['completed']} of {scans['total']} assessment scans completed. "
                       "Remediation statuses are analyst decisions, not independent verification.",
            "actions": actions}


def _finish(data: dict[str, Any]) -> dict[str, Any]:
    data["executive"] = _executive(data["scans"], data["findings"])
    return vault.stored_redactor().obj(data, strict=True)


def for_target(tid: int) -> dict[str, Any]:
    t = db.get("targets", tid)
    scans = db.list_scans(target_id=tid, limit=-1)
    now = datetime.now(timezone.utc)
    return _finish({"kind": "target", "id": tid, "name": t["name"], "environment": t.get("environment"),
            "subtitle": t.get("base_url"), "generated_at": now.isoformat(timespec="seconds"),
            "scans": _scan_stats(scans), "trend": _trend(scans), "coverage": _coverage(scans),
            "findings": _findings([s["id"] for s in scans], now), "targets": None,
            "scope": {"description": "", "targets": [_scope(t)]}, **_notes()})


def for_campaign(cid: int) -> dict[str, Any]:
    c = db.get("campaigns", cid)
    red = vault.stored_redactor()
    scans = sorted(db.q(db.SCAN_SELECT + " WHERE s.campaign_id=?", (cid,)), key=_scan_key, reverse=True)
    ids = [s["id"] for s in scans]
    now = datetime.now(timezone.utc)
    per_target = []
    scope_targets = []
    # Retained campaign scans still count after a target is unlinked from the campaign.
    tids = set(campaigns.target_ids(cid)) | {s["target_id"] for s in scans if s.get("target_id")}
    for tid in sorted(tids):
        t = db.get("targets", tid)
        if not t:
            continue
        scope_targets.append(_scope(t))
        ts = [s for s in scans if s.get("target_id") == tid]
        f = findings_store.summary(findings_store.groups_for_scans([s["id"] for s in ts]))
        cov = _coverage(ts)
        per_target.append({"id": tid, "name": t["name"], "environment": t.get("environment"), "scans": _scan_stats(ts),
                           "open_counts": f["open_counts"], "coverage": cov and {k: cov[k] for k in ("scan_id", "counts", "cells", "available")}})
    return _finish({"kind": "campaign", "id": cid, "name": c["name"], "environment": c.get("environment") or None,
            "subtitle": red.text(c.get("description"), strict=True).strip()[:200], "campaign_status": c.get("status"),
            "generated_at": now.isoformat(timespec="seconds"), "scans": _scan_stats(scans), "trend": _trend(scans),
            "coverage": None, "findings": _findings(ids, now), "targets": per_target,
            "scope": {"description": c.get("scope") or "", "targets": scope_targets}, **_notes()})


def _notes() -> dict[str, Any]:
    return {"notes": [
        "Findings come from Strix agents, grouped by fingerprint (a correlation, not proof of one root cause).",
        "\"Fixed\" is an analyst's status in Skynet, not proof; a finding missing from a later scan is not counted as fixed.",
        "Incomplete scans (cancelled, failed, interrupted) are marked in the trend; their lower counts are not an improvement.",
        "Time to fix uses recorded transitions to Fixed. Historical fixed findings without a reliable transition time are excluded, not counted as zero.",
        "Coverage \"Tested\" needs a verified test with linked evidence; it does not mean secure. No SLA data exists for deadline compliance.",
        "This report includes all retained scans in this selection; the chart shows only the latest 12 ended assessment scans. Scope and finding statuses reflect current settings, not historical snapshots.",
    ]}


def markdown(data: dict[str, Any]) -> str:
    """Portable detailed report from the same redacted data used by the preview."""
    def text(value: Any) -> str:
        # Target/agent text stays literal, including HTML, Markdown links and table delimiters.
        value = html.escape(str(value if value is not None else "—"), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value).replace("\r", "").replace("\n", "<br>")

    def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
        return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |",
                *["| " + " | ".join(text(v) for v in row) + " |" for row in rows], ""]

    def days(value: Any) -> str:
        return "—" if value is None else "< 1 day" if value < 1 else f"{value:g} days"

    f, sc = data["findings"], data["scans"]
    lines = [f"# Security report: {text(data['name'])}", "", f"- Type: {text(data['kind'])}",
             f"- Environment: {text(data.get('environment'))}", f"- Generated: {text(data['generated_at'])}",
             f"- Prepared by: {text(data.get('generated_by'))}", f"- Timezone: {text(data.get('timezone'))}",
             f"- Period: {text(sc['first_at'])} – {text(sc['last_at'])}", "", text(data.get("subtitle") or ""), "", "## Executive summary", "",
             f"### {text(data['executive']['headline'])}", "", text(data["executive"]["summary"]), "",
             *[f"- {text(a)}" for a in data["executive"]["actions"]], "", "## Findings and remediation", ""]
    lines += table(["Severity", "Open", "Median open age", "Oldest open", "Fixed with known time", "Median time to fix"],
                   [[s.title(), f["summary"]["open_counts"][s], days(f["open_age"][s]["median"]), days(f["open_age"][s]["max"]),
                     f["time_to_fix"][s]["n"], days(f["time_to_fix"][s]["median"])] for s in SEVERITIES])
    lines += [f"Remediation states: {text(', '.join(f'{k}: {v}' for k, v in f['summary']['remediation'].items()))}.",
              f"Fixed findings excluded from time metrics: {f['fixed_time_unknown']}. Open findings with unknown age: {f['open_age_unknown']}.",
              "", "## Scope (current configuration)", "", text(data["scope"]["description"]), ""]
    for t in data["scope"]["targets"]:
        lines += [f"### {text(t['name'])}", "", f"- Base URL: {text(t['base_url'])}",
                  f"- Additional targets: {text(', '.join(t['extra_targets']) or 'None configured')}",
                  f"- In scope: {text(', '.join(t['in_scope']) or 'Base URL and additional targets; no explicit rules')}",
                  f"- Out of scope: {text(', '.join(t['out_of_scope']) or 'None configured')}", ""]
    lines += ["## Assessment scans", "", f"Completed: {sc['completed']} / {sc['total']}; incomplete: {sc['incomplete']}; "
              f"queued or active: {sc['active']}; verification runs: {sc['verifications']}.", "",
              "Latest ended assessment scans (up to 12; counts are per run, not deduplicated groups):", ""]
    lines += table(["Scan", "Target", "Date", "Status", "Complete", "C / H / M / L / I"],
                   [[t["scan_id"], t["target_name"], t["at"], t["status"], "Yes" if t["complete"] else "No — not comparable",
                     " / ".join(str(t["counts"][s]) for s in SEVERITIES) if t["counts"] is not None else "Unavailable"]
                    for t in data["trend"]])
    lines += ["## Test coverage", ""]
    coverages = [(data["name"], data["coverage"])] if data["kind"] == "target" else [(t["name"], t["coverage"]) for t in data["targets"]]
    for name, cov in coverages:
        lines += [f"### {text(name)}", ""]
        if not cov:
            lines += ["No completed assessment has a readable coverage source.", ""]
            continue
        lines += [f"Source: scan #{cov['scan_id']}. " + ("Coverage data available." if cov["available"] else "Coverage data unavailable."), ""]
        lines += table(["Status", "Cells"], [[k.replace("_", " ").title(), v] for k, v in cov["counts"].items()])
        lines += [*[f"- {text(g)}" for g in cov.get("gaps") or []], ""]
    lines += [f"## Complete finding register ({len(f['register'])})", ""]
    if not f["register"]:
        lines += ["No findings recorded. This does not establish that the application is secure.", ""]
    for g in f["register"]:
        lines += [f"### Finding #{g['id']}: {text(g['title'] or 'Untitled finding')}", "",
                  f"- Severity: {text(g['severity'])} · Status: {text(g['remediation'])} · CWE: {text(g['cwe'])}",
                  f"- Target: {text(g['target_name'])} · Host: {text(g['host'])}", f"- Location: {text(g['where'])}",
                  f"- First seen: {text(g['first_seen_at'])} · Last seen: {text(g['last_seen_at'])}",
                  f"- Open for: {days(g['age_days'])} · Marked fixed: {text(g['fixed_at'])}",
                  f"- Occurrences in this selection: {g['occurrences']} · Source scans: {text(', '.join('#' + str(i) for i in g['scan_ids']))}", "",
                  f"Analyst note: {text(g['remediation_note'] or 'None')}",
                  *(["", "**Seen again after being marked fixed; review required.**"] if g["seen_after_fix"] else []), ""]
    lines += ["## Methodology and limitations", "", *[f"- {text(n)}" for n in data["notes"]], ""]
    return "\n".join(lines)
