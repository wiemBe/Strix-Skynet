"""Scan / release comparison (SKY-01), computed at read time so re-importing the same data can never create change
records or findings.

"New" is always relative to the selected reference scan. Nothing here changes remediation: a finding seen in the
reference and not in the comparison is "Not observed in this run", never "fixed". Fingerprint matches are
algorithmic candidates unless an analyst confirmed both occurrences (occurrence_reviews). Differences in scope,
mode, profiles, completion or test coverage are listed as caveats; no improvement score is produced.
Skynet records no release / build / commit identifier for scans, so every comparison is labelled a scan comparison.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import coverage_matrix, db, inventory, workspace

DONE = ("completed",)


def _run_dir(scan: dict[str, Any]) -> Path | None:
    p = Path(scan["run_dir"]) if scan.get("run_dir") else None
    return p if p and p.is_dir() else None


def _caveats(a: dict[str, Any], b: dict[str, Any], ia: dict[str, Any], ib: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for label, s, ing in (("Reference", a, ia), ("Comparison", b, ib)):
        if s["status"] not in DONE:
            out.append({"level": "warn", "text": f"{label} scan #{s['id']} is {s['status']}: its results are incomplete."})
        if ing.get("complete") is not None and not ing.get("complete"):   # stored as 0/1
            out.append({"level": "warn", "text": f"{label} scan #{s['id']}: Strix marked its coverage record incomplete."})
        elif ing.get("complete") is None:
            out.append({"level": "info", "text": f"{label} scan #{s['id']}: coverage completeness is unknown."})
        if s.get("trigger") == "verify":
            out.append({"level": "warn", "text": f"{label} scan #{s['id']} is a focused verification run, not a full scan."})
    if (a.get("scan_mode") or "") != (b.get("scan_mode") or ""):
        out.append({"level": "warn", "text": f"Scan modes differ ({a.get('scan_mode') or '—'} vs {b.get('scan_mode') or '—'}): "
                                             "test depth is not equivalent."})
    pa, pb = set(a.get("auth_profile_names") or []), set(b.get("auth_profile_names") or [])
    if pa != pb:
        out.append({"level": "warn", "text": "Authentication profiles differ: reference "
                    f"{', '.join(sorted(pa)) or 'none'}; comparison {', '.join(sorted(pb)) or 'none'}. Role coverage is not equivalent."})
    if sorted(a.get("targets") or []) != sorted(b.get("targets") or []):
        out.append({"level": "warn", "text": "The Strix targets passed to the two scans differ."})
    if (a.get("instruction") or "") != (b.get("instruction") or ""):
        out.append({"level": "info", "text": "The scans had different extra instructions."})
    if (b.get("started_at") or b.get("created_at") or "") < (a.get("started_at") or a.get("created_at") or ""):
        out.append({"level": "info", "text": "The comparison scan started before the reference scan."})
    return out


def _endpoints(run_name: str, target_id: int) -> dict[int, dict[str, Any]]:
    rows = db.q("SELECT a.id, a.method, a.path, a.host, a.port, a.key, MAX(o.tier='observed') AS observed "
                "FROM assets a JOIN asset_observations o ON o.asset_id=a.id "
                "WHERE a.target_id=? AND a.kind='endpoint' AND o.run_name=? GROUP BY a.id", (target_id, run_name))
    return {r["id"]: r for r in rows}


class _Cells(dict):
    """Origin-preserving coverage index. Missing host/port may match only one unambiguous origin."""
    def find(self, method: str, path: str, host: str | None = None, port: int | None = None) -> dict[str, Any] | None:
        hits = [c for (scheme, h, p, m, path_), c in self.items() if path_ == path and
                (not method or m in (method, "*")) and (host is None or h == host) and (port is None or p == port)]
        if len({(c.get("scheme"), c.get("host"), c.get("port")) for c in hits}) > 1:
            return None
        return max(hits, key=lambda c: _RANK[c["status"]]) if hits else None


_RANK = {"tested": 5, "partial": 4, "blocked": 3, "not_applicable": 2, "unknown": 1, "not_tested": 0}


def _cell_index(m: dict[str, Any]) -> _Cells:
    out = _Cells()
    for c in m.get("cells") or []:
        if c["endpoint"].startswith("(unmapped surface)"):
            continue
        method, _, path = c["endpoint"].partition(" ")
        key = (c.get("scheme") or "", c.get("host") or "", c.get("port"), method, path)
        cur = out.get(key)
        if not cur or _RANK[c["status"]] > _RANK[cur["status"]]:
            out[key] = c
    return out


def _role_key(role: str, roles: list[dict[str, Any]]) -> str:
    r = next((x for x in roles if x["id"] == role), None)
    return r["label"] if r and role.startswith("profile:") else role


def compare(ref_id: int, cmp_id: int) -> dict[str, Any]:
    a, b = db.get_scan(ref_id), db.get_scan(cmp_id)
    if not a or not b:
        raise LookupError("Scan not found")
    if ref_id == cmp_id:
        raise ValueError("Select two different scans.")
    if not a.get("target_id") or a.get("target_id") != b.get("target_id"):
        raise ValueError("Only scans of the same target can be compared. Different targets or environments are "
                         "not equivalent.")
    if not a.get("run_name") or not b.get("run_name"):
        raise ValueError("Both scans need a Strix output folder.")
    tid = a["target_id"]
    ia = db.q1("SELECT * FROM run_ingest WHERE run_name=?", (a["run_name"],)) or {}
    ib = db.q1("SELECT * FROM run_ingest WHERE run_name=?", (b["run_name"],)) or {}
    caveats = _caveats(a, b, ia, ib)
    if a["run_name"] == b["run_name"]:
        caveats.insert(0, {"level": "warn", "text": "Both scans are part of the same Strix run (resumed); findings "
                                                    "and observations are shared."})
    ma = coverage_matrix.build(a, _run_dir(a))
    mb = coverage_matrix.build(b, _run_dir(b))
    ca, cb = _cell_index(ma), _cell_index(mb)
    # ---------------- endpoints
    ea, eb = _endpoints(a["run_name"], tid), _endpoints(b["run_name"], tid)
    def ep(r: dict[str, Any], side_cov: _Cells) -> dict[str, Any]:
        c = side_cov.find(r["method"] or "", r["path"] or "", r["host"], r["port"])
        return {"asset_id": r["id"], "label": f"{r['method'] or '*'} {r['path']}", "host": r["host"],
                "tier": "observed" if r["observed"] else "reported",
                "coverage": {"status": c["status"], "status_label": c["status_label"]} if c else None}
    new_eps = [ep(eb[i], cb) for i in sorted(set(eb) - set(ea), key=lambda i: eb[i]["path"] or "")]
    gone = []
    for i in sorted(set(ea) - set(eb), key=lambda i: ea[i]["path"] or ""):
        r = ep(ea[i], ca)
        was_tested = (r["coverage"] or {}).get("status") == "tested"
        r["state"] = "not_tested_in_run" if was_tested else "not_observed"
        r["state_label"] = "Not tested in this run" if was_tested else "Not observed in this run"
        r["reason"] = ("Tested in the reference; this run has no record of it (absence of records is not proof of "
                       "removal)." if was_tested else "Observed in the reference; not observed in this run.")
        gone.append(r)
    # ---------------- findings
    def occ(run: str) -> dict[int, dict[str, Any]]:
        return {o["group_id"]: o for o in db.q(
            "SELECT o.*, g.title AS g_title, g.severity AS g_severity, g.remediation, g.endpoint, g.method, g.host, "
            "g.first_seen_at FROM finding_occurrences o JOIN finding_groups g ON g.id=o.group_id "
            "WHERE o.run_name=? AND g.target_id=?", (run, tid))}
    fa, fb = occ(a["run_name"]), occ(b["run_name"])
    reviews: dict[int, dict[str, Any]] = {}
    for gid in set(fa) | set(fb):
        reviews.update(workspace._reviews(gid))

    def fnd(o: dict[str, Any]) -> dict[str, Any]:
        return {"group_id": o["group_id"], "occurrence_id": o["id"], "title": o["g_title"], "severity": o["severity"],
                "endpoint": f"{o['method'] or ''} {o['endpoint'] or ''}".strip(), "remediation": o["remediation"],
                "strix_id": o["strix_id"], "correlation": workspace.correlation(o["id"], reviews)}
    new_f, again, missing = [], [], []
    for gid in sorted(set(fb) - set(fa)):
        r = fnd(fb[gid])
        r["seen_before_reference"] = (fb[gid]["first_seen_at"] or "") < (a.get("started_at") or a.get("created_at") or "")
        new_f.append(r)
    for gid in sorted(set(fa) & set(fb)):
        ra, rb = fnd(fa[gid]), fnd(fb[gid])
        states = {ra["correlation"]["state"], rb["correlation"]["state"]}
        match = ("analyst_confirmed" if states == {"analyst_confirmed"} else
                 "analyst_rejected" if "analyst_rejected" in states else "fingerprint_candidate")
        again.append({**rb, "reference_occurrence_id": ra["occurrence_id"], "match": match,
                      "match_label": {"analyst_confirmed": "Match confirmed by analyst",
                                      "analyst_rejected": "Match rejected by analyst",
                                      "fingerprint_candidate": "Fingerprint candidate (algorithmic)"}[match]})
    for gid in sorted(set(fa) - set(fb)):
        r = fnd(fa[gid])
        c = cb.find(fa[gid]["method"] or "", fa[gid]["endpoint"] or "", fa[gid]["host"])
        r["comparison_coverage"] = {"status": c["status"], "status_label": c["status_label"]} if c else None
        r["state_label"] = "Not observed in this run"
        if c and c["status"] == "tested":
            r["reason"] = ("The endpoint has test evidence in this run, but Strix did not report this finding. That is "
                           "not proof of a fix; remediation is unchanged.")
        elif c:
            r["reason"] = (f"This run's best evidence for the endpoint is “{c['status_label']}”, not a completed, "
                           "evidenced test. Remediation is unchanged.")
        else:
            r["reason"] = "This run has no coverage record or recorded request for the endpoint. Remediation is unchanged."
        missing.append(r)
    # ---------------- coverage changes
    def cells(m: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
        return {(c.get("origin", "Origin unknown"), c["endpoint"], _role_key(c["role"], m["roles"]), c["test_type"]): c
                for c in m.get("cells") or []}
    xa, xb = cells(ma), cells(mb)
    changes = []
    for k in sorted(set(xa) | set(xb)):
        sa, sb = (xa.get(k) or {}).get("status"), (xb.get(k) or {}).get("status")
        if sa == sb:
            continue
        changes.append({"origin": k[0], "endpoint": k[1], "role": k[2], "test_type": k[3],
                        "test_type_label": (xa.get(k) or xb.get(k))["test_type_label"],
                        "reference": coverage_matrix.STATUS_LABEL.get(sa, "No cell"),
                        "comparison": coverage_matrix.STATUS_LABEL.get(sb, "No cell"),
                        "reference_status": sa, "comparison_status": sb})
    scan_info = lambda s, ing: {k: s.get(k) for k in ("id", "status", "trigger", "scan_mode", "run_name", "started_at",  # noqa: E731
                                                       "finished_at", "auth_profile_names", "targets")} | {
        "coverage_complete": None if ing.get("complete") is None else bool(ing.get("complete")), "release": None}
    return {"kind": "scan_comparison", "label": "Scan comparison (no release, build or commit recorded)",
            "reference": scan_info(a, ia), "comparison": scan_info(b, ib), "caveats": caveats,
            "endpoints": {"new": new_eps, "not_observed": gone, "both": len(set(ea) & set(eb))},
            "findings": {"new": new_f, "seen_again": again, "not_observed": missing},
            "coverage_changes": changes, "wstg_version": coverage_matrix.WSTG_VERSION,
            "against_all_prior": inventory.run_diff(b["run_name"], tid),
            "note": "“New” is relative to the selected reference. No improvement score is computed."}
