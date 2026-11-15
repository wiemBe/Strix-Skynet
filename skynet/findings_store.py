"""Persisted, deduplicated findings.

Strix numbers findings per run (vuln-0001, vuln-0002 ...), so the same issue found again by a later scan gets an
unrelated id. Skynet groups occurrences into a "unique finding" per target using a fingerprint of
host + HTTP method + normalized endpoint + CWE (falls back to CWE + normalized title when Strix gives no endpoint).
Every occurrence keeps its source run/scan. Occurrences are keyed by run, not by scan: a resumed scan continues
the same Strix run and must not count its findings twice.

Remediation (open / fixed / accepted / false_positive) is a manual decision on the unique finding and is
independent of campaign status. A "fixed" finding that shows up again in a later run is flagged, not reopened
behind the user's back.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import db, runs, scope

REMEDIATION = ("open", "fixed", "accepted", "false_positive")


def _cwe(v: Any) -> str:
    m = re.search(r"(\d+)", str(v or ""))
    return f"CWE-{m.group(1)}" if m else ""


def _title(t: str) -> str:
    return re.sub(r"[^a-z]+", " ", (t or "").lower()).strip()[:120]


def locate(v: dict[str, Any], hmap: dict[str, str]) -> tuple[str, str, str]:
    """-> (host, METHOD, normalized endpoint path) for a Strix finding."""
    scheme, host, port, tpath = scope.split(str(v.get("target") or ""))
    host = hmap.get(host, host)
    ep = str(v.get("endpoint") or "").strip()
    path = ""
    if ep:
        first = ep.split()[0]
        if "://" in first:
            _, h2, _, p2 = scope.split(first)
            host, path = hmap.get(h2, h2) or host, p2
        else:
            path = first
        path = scope.norm_path(path)
    method = str(v.get("method") or "").upper().strip()
    return host, (method if method in scope.METHODS else ""), path


def fingerprint(v: dict[str, Any], hmap: dict[str, str]) -> str:
    host, method, path = locate(v, hmap)
    cwe = _cwe(v.get("cwe"))
    if path and cwe:
        basis = f"ep|{host}|{method}|{path}|{cwe}"
    else:
        basis = f"t|{host}|{cwe}|{path}|{_title(v.get('title'))}"
    return hashlib.sha1(basis.encode()).hexdigest()


def ingest(scan: dict[str, Any], run_dir: Path) -> dict[str, int]:
    """Idempotent: re-running for the same run only updates. Uses the final vulnerabilities.json only."""
    tid, run = scan.get("target_id"), run_dir.name
    data = runs._load_json(run_dir / "vulnerabilities.json")
    if not tid or not isinstance(data, list):
        return {"findings": 0, "new_groups": 0}
    meta = runs._load_json(run_dir / "run.json") or {}
    hmap = scope.host_map(meta.get("targets_info") or [])
    when = meta.get("end_time") or scan.get("finished_at") or meta.get("start_time") or db.now_iso()
    new_groups = 0
    for v in data:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        fp = fingerprint(v, hmap)
        host, method, path = locate(v, hmap)
        sev = str(v.get("severity") or "info").lower()
        g = db.q1("SELECT id FROM finding_groups WHERE target_id=? AND fingerprint=?", (tid, fp))
        if g:
            gid = g["id"]
        else:
            gid = db.execute("INSERT INTO finding_groups (target_id, fingerprint, title, severity, cwe, method, endpoint, host) "
                             "VALUES (?,?,?,?,?,?,?,?)", (tid, fp, v.get("title"), sev, _cwe(v.get("cwe")), method, path, host))
            new_groups += 1
        db.execute("INSERT INTO finding_occurrences (group_id, scan_id, run_name, strix_id, title, severity, cvss, observed_at) "
                   "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(run_name, strix_id) DO UPDATE SET group_id=excluded.group_id, "
                   "scan_id=excluded.scan_id, title=excluded.title, severity=excluded.severity, cvss=excluded.cvss",
                   (gid, scan["id"], run, str(v["id"]), v.get("title"), sev, v.get("cvss"), when))
    _refresh_groups(tid)
    return {"findings": len(data), "new_groups": new_groups}


def _refresh_groups(tid: int) -> None:
    """Recompute first/last seen and the latest title/severity from occurrences (order-independent)."""
    for g in db.q("SELECT id FROM finding_groups WHERE target_id=?", (tid,)):
        occ = db.q("SELECT * FROM finding_occurrences WHERE group_id=? ORDER BY observed_at, id", (g["id"],))
        if not occ:
            continue
        first, last = occ[0], occ[-1]
        db.execute("UPDATE finding_groups SET first_seen_at=?, first_scan_id=?, last_seen_at=?, last_scan_id=?, "
                   "title=?, severity=? WHERE id=?",
                   (first["observed_at"], first["scan_id"], last["observed_at"], last["scan_id"], last["title"],
                    last["severity"], g["id"]))


GROUP_SELECT = ("SELECT g.*, t.name AS target_name, "
                "(SELECT COUNT(*) FROM finding_occurrences o WHERE o.group_id=g.id) AS occurrences, "
                "(SELECT COUNT(DISTINCT o.run_name) FROM finding_occurrences o WHERE o.group_id=g.id) AS runs, "
                "(SELECT MAX(o.observed_at) FROM finding_occurrences o WHERE o.group_id=g.id AND g.remediation='fixed' "
                " AND g.remediation_at IS NOT NULL AND o.observed_at > g.remediation_at) AS seen_after_fix "
                "FROM finding_groups g LEFT JOIN targets t ON t.id=g.target_id")


def groups_for_scans(scan_ids: list[int]) -> list[dict[str, Any]]:
    """Unique findings that have at least one occurrence in the given scans, with per-selection counts."""
    if not scan_ids:
        return []
    ph = ",".join("?" * len(scan_ids))
    rows = db.q(GROUP_SELECT + f" WHERE g.id IN (SELECT group_id FROM finding_occurrences WHERE scan_id IN ({ph}))", scan_ids)
    occ = db.q(f"SELECT group_id, COUNT(*) AS n, GROUP_CONCAT(DISTINCT scan_id) AS scans FROM finding_occurrences "
               f"WHERE scan_id IN ({ph}) GROUP BY group_id", scan_ids)
    by = {o["group_id"]: o for o in occ}
    for r in rows:
        o = by.get(r["id"]) or {}
        r["occurrences_here"] = o.get("n", 0)
        r["scan_ids_here"] = sorted(int(x) for x in str(o.get("scans") or "").split(",") if x)
    rows.sort(key=lambda r: (-runs.SEV_RANK.get(r["severity"], 0), r["title"] or ""))
    return rows


def summary(groups: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {s: 0 for s in runs.SEVERITIES}
    rem = {r: 0 for r in REMEDIATION}
    open_counts = {s: 0 for s in runs.SEVERITIES}
    for g in groups:
        sev = g["severity"] if g["severity"] in counts else "info"
        counts[sev] += 1
        rem[g["remediation"]] = rem.get(g["remediation"], 0) + 1
        if g["remediation"] == "open":
            open_counts[sev] += 1
    return {"unique": len(groups), "occurrences": sum(g.get("occurrences_here", 0) for g in groups),
            "counts": counts, "open_counts": open_counts, "remediation": rem,
            "seen_after_fix": sum(1 for g in groups if g.get("seen_after_fix"))}


def occurrences(gid: int) -> list[dict[str, Any]]:
    return db.q("SELECT o.*, s.status AS scan_status, s.started_at, s.campaign_id FROM finding_occurrences o "
                "LEFT JOIN scans s ON s.id=o.scan_id WHERE o.group_id=? ORDER BY o.observed_at DESC, o.id DESC", (gid,))
