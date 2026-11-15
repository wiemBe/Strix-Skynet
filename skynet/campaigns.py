"""Pentest campaigns: a named engagement grouping targets, their scans and schedules.

A campaign is organizational only. It never changes how a scan runs and never touches scan history: removing a
target or archiving a campaign only unlinks, it does not delete scans or findings. Finding remediation status is a
separate, per-finding decision (see findings_store) and is independent of a campaign's own status.
"""
from __future__ import annotations

from typing import Any

from . import db, findings_store

STATUSES = ("planned", "active", "on_hold", "completed")


def payload(body: dict[str, Any]) -> dict[str, Any]:
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("Campaign name is required")
    status = body.get("status") or "planned"
    if status not in STATUSES:
        raise ValueError("Invalid status")
    env = (body.get("environment") or "").strip()
    if env and env not in ("development", "test", "staging", "production"):
        raise ValueError("Invalid environment")
    cols = {"name": name, "description": (body.get("description") or "").strip(),
            "scope": (body.get("scope") or "").strip(), "environment": env, "status": status}
    cols["completed_at"] = db.now_iso() if status == "completed" else None
    return cols


def target_ids(cid: int) -> list[int]:
    return [r["target_id"] for r in db.q("SELECT target_id FROM campaign_targets WHERE campaign_id=?", (cid,))]


def set_targets(cid: int, ids: list[int]) -> None:
    want = {int(i) for i in ids or []}
    valid = {t["id"] for t in db.q(f"SELECT id FROM targets WHERE id IN ({','.join('?' * len(want))})", list(want))} if want else set()
    have = set(target_ids(cid))
    for tid in valid - have:
        db.execute("INSERT OR IGNORE INTO campaign_targets(campaign_id, target_id, added_at) VALUES (?,?,?)",
                   (cid, tid, db.now_iso()))
    for tid in have - valid:
        db.execute("DELETE FROM campaign_targets WHERE campaign_id=? AND target_id=?", (cid, tid))


def save(body: dict[str, Any], existing: dict[str, Any] | None) -> int:
    cols = payload(body)
    if existing:
        db.update("campaigns", existing["id"], cols)
        cid = existing["id"]
    else:
        cid = db.insert("campaigns", cols)
    if "target_ids" in body:
        set_targets(cid, body.get("target_ids") or [])
    return cid


def scan_ids(cid: int) -> list[int]:
    return [s["id"] for s in db.q("SELECT id FROM scans WHERE campaign_id=?", (cid,))]


def public(c: dict[str, Any], detail: bool = False) -> dict[str, Any]:
    tids = target_ids(c["id"])
    out = dict(c)
    out["archived"] = bool(c.get("archived_at"))
    out["target_ids"] = tids
    out["targets"] = db.q(f"SELECT id, name, environment, base_url FROM targets WHERE id IN "
                          f"({','.join('?' * len(tids))}) ORDER BY name COLLATE NOCASE", tids) if tids else []
    sc = db.q1("SELECT COUNT(*) AS n, SUM(status IN ('queued','running','stopping')) AS active FROM scans "
               "WHERE campaign_id=?", (c["id"],)) or {}
    out["scan_count"] = sc.get("n") or 0
    out["active_scans"] = sc.get("active") or 0
    out["schedule_count"] = (db.q1("SELECT COUNT(*) AS n FROM schedules WHERE campaign_id=?", (c["id"],)) or {}).get("n") or 0
    if detail:
        groups = findings_store.groups_for_scans(scan_ids(c["id"]))
        out["findings"] = findings_store.summary(groups)
    return out


def can_delete(c: dict[str, Any]) -> str | None:
    """Only an archived campaign may be deleted, and deletion only unlinks (scans/schedules keep running)."""
    if not c.get("archived_at"):
        return "Archive the campaign first. Deleting it removes links only; scans and findings are preserved."
    return None


def delete(cid: int) -> None:
    db.execute("UPDATE scans SET campaign_id=NULL WHERE campaign_id=?", (cid,))
    db.execute("UPDATE schedules SET campaign_id=NULL WHERE campaign_id=?", (cid,))
    db.execute("DELETE FROM campaign_targets WHERE campaign_id=?", (cid,))
    db.delete("campaigns", cid)
