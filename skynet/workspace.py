"""Finding evidence workspace (SKY-07): original evidence side by side, with analyst notes kept apart from it.

Context is one finding occurrence (an original Strix report in one run) or one verification run. Exchanges come
from evidence.py and are always masked. Where an exchange's role comes from is explicit:

  strix_link       the Strix finding lists the Caido id in http_exchange_ids (no attack/control role given)
  assessment       the verification run's agent assessment names it as a probe (attack) or control request.
                   This is the agent's statement; whether Skynet accepted the test is the verification result.
  analyst          an analyst assigned the role here (append-only history in evidence_labels)

No two records are ever paired automatically. Analyst notes, labels and correlation reviews live in their own
append-only tables and never modify run files, finding occurrences or verification records.
"""
from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from . import crypto, db, evidence, runs, verify, vault

LABELS = ("attack", "control", "context")
REVIEW = ("confirmed", "rejected", "cleared")
MAX_NOTE = 8000


def _runs_of_group(gid: int) -> dict[str, dict[str, Any]]:
    """run_name -> scan for every occurrence and verification run of the group (the access boundary)."""
    out: dict[str, dict[str, Any]] = {}
    for o in db.q("SELECT scan_id, run_name FROM finding_occurrences WHERE group_id=?", (gid,)):
        s = db.get_scan(o["scan_id"]) if o.get("scan_id") else None
        out.setdefault(o["run_name"], s or {"run_name": o["run_name"]})
    for v in db.q("SELECT scan_id FROM finding_verifications WHERE group_id=?", (gid,)):
        s = db.get_scan(v["scan_id"]) if v.get("scan_id") else None
        if s and s.get("run_name"):
            out.setdefault(s["run_name"], s)
    return out


def _run_dir(scan: dict[str, Any] | None) -> Path | None:
    p = Path(scan["run_dir"]) if scan and scan.get("run_dir") else None
    return p if p and p.is_dir() else None


def _labels(gid: int) -> dict[tuple[str, str], dict[str, Any]]:
    cur: dict[tuple[str, str], dict[str, Any]] = {}
    for r in db.q("SELECT * FROM evidence_labels WHERE group_id=? ORDER BY id", (gid,)):
        cur[(r["run_name"], r["request_id"])] = r
    return {k: v for k, v in cur.items() if v["label"] in LABELS}


def _reviews(gid: int) -> dict[int, dict[str, Any]]:
    cur: dict[int, dict[str, Any]] = {}
    for r in db.q("SELECT * FROM occurrence_reviews WHERE group_id=? ORDER BY id", (gid,)):
        cur[r["occurrence_id"]] = r
    return {k: v for k, v in cur.items() if v["decision"] != "cleared"}


def correlation(occ_id: int, reviews: dict[int, dict[str, Any]]) -> dict[str, Any]:
    r = reviews.get(occ_id)
    if not r:
        return {"state": "fingerprint_candidate", "label": "Fingerprint candidate (algorithmic)"}
    return {"state": f"analyst_{r['decision']}", "author": r["author"], "at": r["created_at"],
            "label": "Confirmed by analyst" if r["decision"] == "confirmed" else "Rejected by analyst"}


def _strix_finding(run_dir: Path | None, strix_id: str) -> dict[str, Any] | None:
    if not run_dir:
        return None
    data = runs._load_json(run_dir / "vulnerabilities.json")
    if not isinstance(data, list):
        return None
    return next((v for v in data if isinstance(v, dict) and str(v.get("id")) == str(strix_id)), None)


def build(gid: int, occurrence_id: int | None = None, verification_id: int | None = None) -> dict[str, Any]:
    group = db.get("finding_groups", gid)
    if not group:
        raise LookupError("Finding not found")
    red = vault.finding_redactor(gid)
    reviews = _reviews(gid)
    occs = db.q("SELECT o.*, s.status AS scan_status, s.trigger AS scan_trigger, s.run_dir FROM finding_occurrences o "
                "LEFT JOIN scans s ON s.id=o.scan_id WHERE o.group_id=? ORDER BY o.observed_at, o.id", (gid,))
    vers = verify.for_group(gid)
    occ_out = [{k: o.get(k) for k in ("id", "scan_id", "run_name", "strix_id", "title", "severity", "observed_at",
                                      "scan_status", "scan_trigger")} | {"correlation": correlation(o["id"], reviews)}
               for o in occs]
    ctx: dict[str, Any] = {"kind": None}
    if verification_id:
        v = next((x for x in vers if x["id"] == verification_id), None)
        if not v:
            raise LookupError("Verification not found for this finding")
        ctx = _verification_context(group, v)
    else:
        o = next((x for x in occs if x["id"] == occurrence_id), None) if occurrence_id else (occs[-1] if occs else None)
        if occurrence_id and not o:
            raise LookupError("Occurrence not found for this finding")
        if o:
            ctx = _occurrence_context(o)
    labels = _labels(gid)
    for x in ctx.get("exchanges", []):
        lab = labels.get((x["run_name"], x["request_id"]))
        if lab:
            x["role"], x["role_source"] = lab["label"], "analyst"
            x["role_by"], x["role_at"] = lab["author"], lab["created_at"]
    names: dict[str, str] = {}
    if ctx.get("run_dir"):
        names = {a["id"]: a["name"] for a in runs.agents(Path(ctx["run_dir"]))["agents"]}
    ctx.pop("run_dir", None)
    out = {"group": {k: group.get(k) for k in ("id", "title", "severity", "cwe", "method", "endpoint", "host",
                                                 "remediation", "remediation_note", "remediation_at")},
           "occurrences": occ_out, "verifications": vers, "context": ctx, "agent_names": names,
           "notes": notes(gid), "masking_note": "Content is masked with the scan's known secrets and credential "
           "patterns. Differences inside masked values are not visible."}
    return red.obj(out, True)


def _occurrence_context(o: dict[str, Any]) -> dict[str, Any]:
    scan = db.get_scan(o["scan_id"]) if o.get("scan_id") else None
    rd = _run_dir(scan)
    ctx = {"kind": "occurrence", "occurrence_id": o["id"], "run_name": o["run_name"], "scan_id": o.get("scan_id"),
           "scan_trigger": (scan or {}).get("trigger"), "strix_id": o["strix_id"], "exchanges": [], "gaps": [],
           "run_dir": str(rd) if rd else None, "screenshots": "No screenshots are linked to Strix findings."}
    if not rd:
        ctx["gaps"].append("The run output folder is missing; the original evidence cannot be shown.")
        return ctx
    v = _strix_finding(rd, o["strix_id"])
    if not v:
        ctx["gaps"].append("The original finding is not in this run's vulnerabilities.json (file missing or changed).")
        return ctx
    ctx["finding_fields"] = {k: v.get(k) for k in ("evidence", "poc_description", "poc_script_code", "endpoint",
                                                   "method", "timestamp", "agent_name") if v.get(k)}
    ids = [str(i) for i in v.get("http_exchange_ids") or []]
    ex = evidence.load(rd)
    red = vault.scan_redactor(scan)
    if not ids:
        ctx["gaps"].append("Strix did not link any HTTP exchange to this finding.")
    for rid in ids:
        x = ex.get(rid)
        if not x:
            ctx["exchanges"].append({"key": f"{o['run_name']}:{rid}", "run_name": o["run_name"], "request_id": rid,
                                     "missing": True, "role": "unassigned", "role_source": "strix_link",
                                     "reason": "Linked by Strix, but no agent viewed or listed this request in the "
                                               "run's records."})
            continue
        ctx["exchanges"].append(evidence.public(x, red, o["run_name"], {"role": "unassigned", "role_source": "strix_link"}))
    ctx["pairing_note"] = ("Strix links these exchanges to the finding without saying which is the attack or the "
                           "control. Assign roles yourself; Skynet does not pair them.")
    return ctx


def _verification_context(group: dict[str, Any], v: dict[str, Any]) -> dict[str, Any]:
    scan = db.get_scan(v["scan_id"]) if v.get("scan_id") else None
    rd = _run_dir(scan)
    ctx = {"kind": "verification", "verification_id": v["id"], "scan_id": v.get("scan_id"),
           "run_name": (scan or {}).get("run_name"), "result": v.get("result"), "result_label": v.get("result_label"),
           "result_note": v.get("note"), "test_executed": (v.get("verification_evidence") or {}).get("test_executed"),
           "exchanges": [], "gaps": [], "run_dir": str(rd) if rd else None,
           "screenshots": "No screenshots are linked to verification runs."}
    if not rd:
        ctx["gaps"].append("The verification run's output folder is missing; its evidence cannot be shown.")
        return ctx
    try:
        report, _ = verify._evidence(rd, group["id"])
    except Exception:  # noqa: BLE001 - unreadable store is a gap, not an error page
        report = None
    if not report:
        ctx["gaps"].append("The run has no verification assessment naming attack and control requests.")
        return ctx
    ex = evidence.load(rd)
    red = vault.scan_redactor(scan)
    for role, key in (("attack", "probe_request_ids"), ("control", "control_request_ids")):
        for rid in map(str, report.get(key) or []):
            x = ex.get(rid)
            extra = {"role": role, "role_source": "assessment"}
            if x:
                ctx["exchanges"].append(evidence.public(x, red, ctx["run_name"], extra))
            else:
                ctx["exchanges"].append({"key": f"{ctx['run_name']}:{rid}", "run_name": ctx["run_name"],
                                         "request_id": rid, "missing": True, **extra,
                                         "reason": "Named in the assessment, but no agent recorded this request."})
    ctx["assessment"] = {k: report.get(k) for k in ("outcome", "reason", "test_completed", "finding_id")}
    ctx["pairing_note"] = ("Roles come from the agent's verification assessment. The verification result above is "
                           "Skynet's evaluation of that assessment against the recorded evidence.")
    return ctx


# ---------------------------------------------------------------- exchanges by key (diff / download)
def exchange(gid: int, run_name: str, request_id: str) -> dict[str, Any]:
    scan = _runs_of_group(gid).get(run_name)
    if not scan:
        raise LookupError("This run does not belong to the finding.")
    rd = _run_dir(scan)
    x = evidence.load(rd).get(str(request_id)) if rd else None
    if not x:
        raise LookupError("No recorded exchange with this id in the run.")
    return evidence.public(x, vault.scan_redactor(scan), run_name)


def diff(gid: int, left: str, right: str, part: str = "response") -> dict[str, Any]:
    if part not in ("request", "response"):
        raise ValueError("part must be request or response")
    a, b = (exchange(gid, *k.split(":", 1)) for k in (left, right))
    ta, tb = ((x.get(part) or {}).get("text") for x in (a, b))
    if ta is None or tb is None:
        return {"available": False, "reason": f"One side has no recorded {part}."}
    ops = []
    for line in difflib.ndiff(ta.splitlines(), tb.splitlines()):
        if line.startswith("? "):
            continue
        ops.append({"op": line[0], "text": line[2:]})
    return {"available": True, "part": part, "left": left, "right": right, "ops": ops[:4000],
            "complete": bool((a.get(part) or {}).get("complete") and (b.get(part) or {}).get("complete")),
            "note": "Computed from masked content. Differences inside masked values are not visible."}


def download_text(gid: int, run_name: str, request_id: str) -> str:
    x = exchange(gid, run_name, request_id)
    parts = [f"# Skynet masked evidence export · run {run_name} · Caido request {request_id}",
             "# Secret values known to Skynet and credential patterns are masked.", ""]
    for p in ("request", "response"):
        d = x.get(p)
        parts += [f"## {p.upper()}" + ("" if (d or {}).get("complete") else " (incomplete or not recorded)"),
                  (d or {}).get("text") or "", ""]
    return "\n".join(parts)


# ---------------------------------------------------------------- analyst notes (append-only revisions)
def notes(gid: int) -> list[dict[str, Any]]:
    out = []
    red = vault.finding_redactor(gid)
    for n in db.q("SELECT * FROM analyst_notes WHERE group_id=? ORDER BY id DESC", (gid,)):
        revs = []
        for r in db.q("SELECT * FROM analyst_note_revisions WHERE note_id=? ORDER BY id DESC", (n["id"],)):
            try:
                body = crypto.vault_decrypt(r["body_enc"])
            except crypto.DecryptError:
                body = None
            revs.append({"id": r["id"], "author": r["author"], "created_at": r["created_at"],
                         "body": red.text(body, True) if body is not None else None})
        out.append({**{k: n.get(k) for k in ("id", "occurrence_id", "verification_id", "created_by", "created_at")},
                    "body": revs[0]["body"] if revs else None, "updated_at": revs[0]["created_at"] if revs else None,
                    "revisions": revs, "kind": "analyst_note"})
    return out


def _body(body: Any) -> str:
    text = str(body or "").strip()
    if not text:
        raise ValueError("Write a note first.")
    if len(text) > MAX_NOTE:
        raise ValueError(f"Notes are limited to {MAX_NOTE} characters.")
    return text


def add_note(gid: int, body: Any, author: str, occurrence_id: int | None = None,
             verification_id: int | None = None) -> int:
    text = _body(body)
    if occurrence_id and not db.q1("SELECT 1 FROM finding_occurrences WHERE id=? AND group_id=?", (occurrence_id, gid)):
        raise ValueError("Occurrence does not belong to this finding.")
    if verification_id and not db.q1("SELECT 1 FROM finding_verifications WHERE id=? AND group_id=?", (verification_id, gid)):
        raise ValueError("Verification does not belong to this finding.")
    now = db.now_iso()
    nid = db.insert("analyst_notes", {"group_id": gid, "occurrence_id": occurrence_id,
                                      "verification_id": verification_id, "created_by": author, "created_at": now})
    db.insert("analyst_note_revisions", {"note_id": nid, "body_enc": crypto.vault_encrypt(text), "author": author,
                                         "created_at": now})
    return nid


def edit_note(gid: int, nid: int, body: Any, author: str) -> None:
    if not db.q1("SELECT 1 FROM analyst_notes WHERE id=? AND group_id=?", (nid, gid)):
        raise LookupError("Note not found")
    db.insert("analyst_note_revisions", {"note_id": nid, "body_enc": crypto.vault_encrypt(_body(body)),
                                         "author": author, "created_at": db.now_iso()})


def set_label(gid: int, run_name: str, request_id: str, label: str, author: str,
              occurrence_id: int | None = None) -> None:
    if label not in (*LABELS, "clear"):
        raise ValueError("Role must be attack, control, context or clear.")
    if run_name not in _runs_of_group(gid):
        raise ValueError("This run does not belong to the finding.")
    if not str(request_id).strip() or len(str(request_id)) > 64:
        raise ValueError("Invalid request id.")
    db.insert("evidence_labels", {"group_id": gid, "occurrence_id": occurrence_id, "run_name": run_name,
                                  "request_id": str(request_id), "label": label, "author": author,
                                  "created_at": db.now_iso()})


def review(gid: int, occurrence_id: int, decision: str, note: str, author: str) -> None:
    if decision not in REVIEW:
        raise ValueError("Decision must be confirmed, rejected or cleared.")
    if not db.q1("SELECT 1 FROM finding_occurrences WHERE id=? AND group_id=?", (occurrence_id, gid)):
        raise LookupError("Occurrence not found for this finding")
    db.insert("occurrence_reviews", {"occurrence_id": occurrence_id, "group_id": gid, "decision": decision,
                                     "note": str(note or "").strip()[:2000], "author": author,
                                     "created_at": db.now_iso()})
