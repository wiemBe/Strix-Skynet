"""Role policy for every API route, and the append-only audit log.

One table decides both the minimum role a request needs and the action name the audit log records for it.
Reads (GET) need `viewer` unless listed; any state-changing route that is not listed needs `admin`, so a new
route is admin-only until someone decides otherwise. Request bodies are never stored: they carry vault
secrets, LLM keys, passwords and instruction text. Handlers may add a short, secret-free summary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import db

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass(frozen=True)
class Rule:
    method: str
    pattern: re.Pattern
    role: str
    action: str
    object_type: str = ""
    audit: bool = True


def _r(method: str, path: str, role: str, action: str, otype: str = "", audit: bool = True) -> Rule:
    return Rule(method, re.compile("^" + path.replace("{id}", r"(\d+)") + "$"), role, action, otype, audit)


RULES: list[Rule] = [
    # ---- reads that are admin-only
    _r("GET", "/api/settings", "admin", "settings.read", audit=False),
    _r("GET", "/api/users", "admin", "user.list", audit=False),
    _r("GET", "/api/audit", "admin", "audit.read", audit=False),
    # ---- public / every signed-in user (login is audited by its handler, with the outcome)
    _r("POST", "/api/login", "viewer", "auth.login", audit=False),
    _r("POST", "/api/logout", "viewer", "auth.logout"),
    _r("POST", "/api/settings/password", "viewer", "account.password_change", "user"),
    _r("POST", "/api/schedules/preview", "viewer", "schedule.preview", audit=False),
    # ---- analyst: run and triage scans
    _r("POST", "/api/targets", "analyst", "target.create", "target"),
    _r("PUT", "/api/targets/{id}", "analyst", "target.update", "target"),
    _r("POST", "/api/targets/{id}/scan", "analyst", "scan.start", "target"),
    _r("POST", "/api/scans/{id}/cancel", "analyst", "scan.stop", "scan"),
    _r("POST", "/api/scans/{id}/resume", "analyst", "scan.resume", "scan"),
    _r("POST", "/api/scans/{id}/messages", "analyst", "agent.instruct", "scan"),
    _r("POST", "/api/scans/{id}/messages/{id}/recheck", "analyst", "agent.instruction_recheck", "scan"),
    _r("POST", "/api/import", "analyst", "scan.import"),
    _r("POST", "/api/schedules", "analyst", "schedule.create", "schedule"),
    _r("PUT", "/api/schedules/{id}", "analyst", "schedule.update", "schedule"),
    _r("POST", "/api/schedules/{id}/pause", "analyst", "schedule.pause", "schedule"),
    _r("POST", "/api/schedules/{id}/resume", "analyst", "schedule.resume", "schedule"),
    _r("POST", "/api/campaigns", "analyst", "campaign.create", "campaign"),
    _r("PUT", "/api/campaigns/{id}", "analyst", "campaign.update", "campaign"),
    _r("POST", "/api/campaigns/{id}/archive", "analyst", "campaign.archive", "campaign"),
    _r("POST", "/api/auth-profiles/{id}/verify", "analyst", "auth_profile.verify", "auth_profile"),
    _r("POST", "/api/findings/{id}/verify", "analyst", "finding.verify", "finding"),
    _r("PATCH", "/api/findings/{id}", "analyst", "finding.status", "finding"),
    _r("POST", "/api/findings/{id}/notes", "analyst", "finding.note_add", "finding"),
    _r("PUT", "/api/findings/{id}/notes/{id}", "analyst", "finding.note_edit", "finding"),
    _r("POST", "/api/findings/{id}/labels", "analyst", "finding.evidence_label", "finding"),
    _r("POST", "/api/findings/{id}/occurrences/{id}/review", "analyst", "finding.correlation_review", "finding"),
    # ---- admin: destructive actions, secrets and configuration (named for a readable log)
    _r("DELETE", "/api/targets/{id}", "admin", "target.delete", "target"),
    _r("DELETE", "/api/scans/{id}", "admin", "scan.delete", "scan"),
    _r("DELETE", "/api/schedules/{id}", "admin", "schedule.delete", "schedule"),
    _r("DELETE", "/api/campaigns/{id}", "admin", "campaign.delete", "campaign"),
    _r("POST", "/api/llm-profiles", "admin", "llm_profile.create", "llm_profile"),
    _r("PUT", "/api/llm-profiles/{id}", "admin", "llm_profile.update", "llm_profile"),
    _r("POST", "/api/llm-profiles/{id}/default", "admin", "llm_profile.make_default", "llm_profile"),
    _r("DELETE", "/api/llm-profiles/{id}", "admin", "llm_profile.delete", "llm_profile"),
    _r("POST", "/api/llm-profiles/test", "admin", "llm_profile.test", audit=False),
    _r("POST", "/api/auth-profiles", "admin", "auth_profile.create", "auth_profile"),
    _r("PUT", "/api/auth-profiles/{id}", "admin", "auth_profile.update", "auth_profile"),
    _r("POST", "/api/auth-profiles/{id}/assign", "admin", "auth_profile.assign", "auth_profile"),
    _r("DELETE", "/api/auth-profiles/{id}", "admin", "auth_profile.delete", "auth_profile"),
    _r("PUT", "/api/settings", "admin", "settings.update"),
    _r("POST", "/api/settings/api-token", "admin", "ci_token.rotate"),
    _r("POST", "/api/users", "admin", "user.create", "user"),
    _r("PUT", "/api/users/{id}", "admin", "user.update", "user"),
    _r("POST", "/api/users/{id}/password", "admin", "user.password_reset", "user"),
    _r("DELETE", "/api/users/{id}", "admin", "user.delete", "user"),
    # ---- CI token (authenticated by X-API-Token, not by a session)
    _r("POST", "/api/ci/targets/{id}/scan", "admin", "scan.start", "target"),
]

ACTION_LABELS = {
    "auth.login": "Signed in", "auth.login_failed": "Failed sign-in", "auth.logout": "Signed out",
    "account.password_change": "Changed own password",
    "target.create": "Created target", "target.update": "Edited target", "target.delete": "Deleted target",
    "scan.start": "Started scan", "scan.stop": "Stopped scan", "scan.resume": "Resumed scan", "scan.delete": "Deleted scan",
    "scan.import": "Imported runs", "agent.instruct": "Sent instruction to agent",
    "agent.instruction_recheck": "Rechecked instruction delivery",
    "schedule.create": "Created schedule", "schedule.update": "Edited schedule", "schedule.pause": "Paused schedule",
    "schedule.resume": "Enabled schedule", "schedule.delete": "Deleted schedule",
    "campaign.create": "Created campaign", "campaign.update": "Edited campaign", "campaign.archive": "Archived/unarchived campaign",
    "campaign.delete": "Deleted campaign",
    "auth_profile.create": "Created auth profile", "auth_profile.update": "Edited auth profile",
    "auth_profile.assign": "Assigned auth profile", "auth_profile.verify": "Checked auth profile login",
    "auth_profile.delete": "Deleted auth profile",
    "llm_profile.create": "Created LLM connection", "llm_profile.update": "Edited LLM connection",
    "llm_profile.make_default": "Changed default LLM connection", "llm_profile.delete": "Deleted LLM connection",
    "finding.verify": "Started finding verification", "finding.status": "Changed finding status",
    "finding.note_add": "Added analyst note", "finding.note_edit": "Edited analyst note",
    "finding.evidence_label": "Labelled evidence", "finding.correlation_review": "Reviewed correlation",
    "settings.update": "Changed settings", "ci_token.rotate": "Rotated CI token",
    "user.create": "Created user", "user.update": "Changed user", "user.password_reset": "Reset user password",
    "user.delete": "Deleted user", "report.view": "Opened management report",
}

MUTATING = ("POST", "PUT", "PATCH", "DELETE")


def rule_for(method: str, path: str) -> tuple[Rule, list[str]]:
    """The policy rule for a request, with the numeric ids captured from the path."""
    method = "GET" if method == "HEAD" else method
    for r in RULES:
        if r.method == method:
            m = r.pattern.match(path)
            if m:
                return r, list(m.groups())
    if method in MUTATING:
        return Rule(method, re.compile(""), "admin", "api.change"), []
    return Rule(method, re.compile(""), "viewer", "api.read", audit=False), []


def allowed(role: str | None, need: str) -> bool:
    return ROLE_RANK.get(role or "", 0) >= ROLE_RANK[need]


def record(actor: str, action: str, *, actor_id: int | None = None, actor_role: str = "", object_type: str = "",
           object_id: Any = "", summary: str = "", method: str = "", path: str = "", status: int | None = None,
           ip: str = "") -> None:
    db.execute("INSERT INTO audit_log (at, actor, actor_id, actor_role, action, object_type, object_id, summary, "
               "method, path, status, ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (db.now_iso(), str(actor)[:64], actor_id, actor_role, action, object_type,
                "" if object_id is None else str(object_id)[:64], str(summary or "")[:300], method, path[:200],
                status, ip[:64]))


def entries(actor: str = "", action: str = "", q: str = "", before: int | None = None,
            limit: int = 100) -> dict[str, Any]:
    where, args = [], []
    if actor:
        where.append("actor=?"); args.append(actor)
    if action:
        where.append("(action=? OR action LIKE ?)"); args += [action, action.rstrip(".") + ".%"]
    if q:
        where.append("(summary LIKE ? OR object_id=? OR path LIKE ?)"); args += [f"%{q}%", q, f"%{q}%"]
    if before:
        where.append("id<?"); args.append(before)
    limit = max(1, min(int(limit), 500))
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    rows = db.q(sql, (*args, limit + 1))
    for r in rows:
        r["action_label"] = ACTION_LABELS.get(r["action"], r["action"])
    actors = [r["actor"] for r in db.q("SELECT DISTINCT actor FROM audit_log ORDER BY actor COLLATE NOCASE")]
    return {"entries": rows[:limit], "has_more": len(rows) > limit, "actors": actors,
            "actions": sorted(ACTION_LABELS.items(), key=lambda kv: kv[1])}
