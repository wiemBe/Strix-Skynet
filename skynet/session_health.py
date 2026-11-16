"""Per-profile, per-agent session evidence over the course of a scan (SKY-02).

Evidence comes only from full request/response pairs an agent viewed through Caido (evidence.py). An exchange is
attributed to a Vault profile only when the raw request carries that profile's credential, compared with keyed
HMAC digests (verify._binding); no credential value is read back or shown.

Signals for an exchange carrying the profile's credential:
  verified  response status equals the profile's expected status AND its identity marker is in the body
  lost      HTTP 401, or a redirect to the profile's login page / a login path
  denied    HTTP 403: an authorization refusal. It is NOT treated as a lost session.
  none      anything else (an HTTP 200 without the identity marker proves nothing)

Signal times: Caido's request time, else the response Date header, else when the agent viewed the response.
Conflicting signals ordered only by view time give Unknown. "Agent" means the agent that recorded (viewed) the
exchange in the shared Caido proxy; the agent that sent the request is not recorded by Strix.

A state belongs to one agent and one moment (the exchange it came from). It is never spread to other agents that
use the same profile, nor carried forward as proof for the rest of the scan. Without evidence the state is Unknown.
Form-login (credentials) profiles cannot be bound to recorded requests and stay Unknown; anonymous profiles are
Not applicable. Skynet's pre-check at scan start is shown separately and never counts as in-scan evidence.
"""
from __future__ import annotations

import hmac
from datetime import datetime, timedelta
import re
from pathlib import Path
from typing import Any

from . import evidence, runs, scope, vault

STATE_LABEL = {"verified": "Session verified", "lost": "Session lost", "unknown": "Unknown",
               "not_applicable": "Not applicable"}
SIGNAL_LABEL = {"verified": "Identity marker observed", "lost": "Authentication rejected",
                "denied": "Access denied (authorization)", "none": "No identity evidence"}


def _last_decisive(signals: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    if not signals:
        return None, ""
    if len({s["signal"] for s in signals}) == 1:
        return signals[-1], ""
    ambiguous = "Conflicting session signals were recorded, and their order cannot be established from source times."
    intervals = []
    for s in signals:
        if s["time_source"] in ("viewed", None) or not s.get("at"):
            return None, ambiguous
        try:
            start = datetime.fromisoformat(s["at"].replace("Z", "+00:00"))
            fraction = re.search(r"\d\d:\d\d:\d\d\.(\d+)", s["at"])
            resolution = 1 if s["time_source"] == "date_header" or not fraction else 10 ** -len(fraction[1])
            intervals.append((start, start + timedelta(seconds=resolution), s))
        except (ValueError, TypeError):
            return None, ambiguous
    latest_start = max(start for start, _, _ in intervals)
    candidates = [s for _, end, s in intervals if end > latest_start]
    if len({s["signal"] for s in candidates}) != 1:
        return None, ambiguous
    return max(intervals, key=lambda x: x[0])[2], ""


def scan_profiles(scan: dict[str, Any]) -> list[dict[str, Any]]:
    """Profiles used by the scan with their binding metadata.

    New scans carry a snapshot taken at launch. For older scans the current profile is used only when its secret
    has not been rotated since the scan started (then it is the same credential); otherwise binding is unavailable.
    """
    snap = scan.get("auth_snapshot") or []
    if snap:
        return [{**p, "binding_source": "scan_start"} for p in snap if isinstance(p, dict)]
    from .verify import profile_snapshot
    checks = {c.get("profile_id"): c for c in scan.get("auth_checks") or [] if isinstance(c, dict)}
    names = scan.get("auth_profile_names") or []
    out = []
    for i, pid in enumerate(scan.get("auth_profile_ids") or []):
        p = vault.get(pid)
        started = scan.get("started_at") or ""
        kind = (p or {}).get("kind") or (checks.get(pid) or {}).get("kind") or "unknown"
        name = (p or {}).get("name") or (names[i] if i < len(names) else f"Profile #{pid}")
        if p and started and (p.get("secret_updated_at") or "") <= started:
            snap_p = profile_snapshot([p])[0]
            out.append({**snap_p, "binding_source": "current_profile_unchanged"})
        else:
            out.append({"id": pid, "kind": kind, "name": name, "auth_bindings": [],
                        "binding_source": "unavailable"})
    return out


def _carries(p: dict[str, Any], headers: dict[str, str]) -> bool:
    from .verify import _binding
    bindings = p.get("auth_bindings") or []
    if not bindings:
        return False
    values = headers if p.get("kind") == "header" else dict(
        part.strip().split("=", 1) for part in headers.get("cookie", "").split(";") if "=" in part)
    return all(b.get("field") in values and hmac.compare_digest(
        b.get("digest") or "", _binding(p["kind"], b["field"], values[b["field"]])) for b in bindings)


def _signal(p: dict[str, Any], resp: dict[str, Any]) -> str:
    st = resp["status"]
    marker = p.get("verify_expect_text") or ""
    if marker and st == (p.get("verify_expect_status") or 200) and marker in resp["body"]:
        return "verified"
    if st == 401:
        return "lost"
    if 300 <= st < 400:
        loc = resp["headers"].get("location", "")
        login_path = scope.split(p["login_url"])[3] if p.get("login_url") else ""
        if (login_path and login_path != "/" and login_path in loc) or "login" in loc.lower() or "signin" in loc.lower():
            return "lost"
    if st == 403:
        return "denied"
    return "none"


def evaluate(scan: dict[str, Any], run_dir: Path | None, agent_names: dict[str, str] | None = None) -> dict[str, Any]:
    profiles = scan_profiles(scan)
    names = agent_names or {}
    meta = runs._load_json(run_dir / "run.json") if run_dir else None
    hmap = scope.host_map((meta or {}).get("targets_info") or [])
    ex = evidence.load(run_dir)
    run_name = scan.get("run_name") or (run_dir.name if run_dir else "")
    signals: dict[int, list[dict[str, Any]]] = {}
    evaluated = 0
    for x in ex.values():
        if not evidence.full(x):
            continue
        evaluated += 1
        req, resp = x["request"]["parsed"], x["response"]["parsed"]
        host, port, method, path = evidence.location(x, hmap)
        for idx, p in enumerate(profiles):
            if p.get("kind") not in ("header", "cookie") or not _carries(p, req["headers"]):
                continue
            sig = _signal(p, resp)
            at, src = evidence.best_time(x)
            signals.setdefault(idx, []).append({
                "signal": sig, "label": SIGNAL_LABEL[sig], "status": resp["status"], "at": at, "time_source": src,
                "agent_id": x["response"]["agent_id"], "request_key": f"{run_name}:{x['request_id']}",
                "request_id": x["request_id"], "method": method, "path": path})
    checks = {c.get("profile_id"): c for c in scan.get("auth_checks") or [] if isinstance(c, dict)}
    result = []
    for idx, p in enumerate(profiles):
        kind = p.get("kind")
        sigs = sorted(signals.get(idx, []), key=lambda s: (s["at"] or "", s["request_id"]))
        entry = {"profile_id": p.get("id"), "name": p.get("name"), "kind": kind,
                 "binding_source": p.get("binding_source"), "marker_configured": bool(p.get("verify_expect_text")),
                 "precheck": _precheck(checks.get(p.get("id"))), "agents": [], "signals": sigs, "state": "unknown",
                 "reason": ""}
        if kind == "anonymous":
            entry.update(state="not_applicable", reason="Anonymous profile: there is no session to keep.")
        elif kind == "credentials":
            entry["reason"] = ("Form login: Skynet does not know the session cookie the agent obtained, so recorded "
                               "requests cannot be bound to this profile.")
        elif p.get("binding_source") == "unavailable":
            entry["reason"] = ("The credential used by this scan is not available for comparison (profile rotated or "
                               "deleted after the scan started, and no snapshot was stored).")
        elif not sigs:
            entry["reason"] = ("No full request/response recorded by an agent carried this profile's credential."
                               if evaluated else "No agent recorded a full request/response in this run.")
        by_agent: dict[str, list[dict[str, Any]]] = {}
        for s in sigs:
            by_agent.setdefault(s["agent_id"], []).append(s)
        for aid, lst in by_agent.items():
            decisive = [s for s in lst if s["signal"] in ("verified", "lost")]
            last, reason = _last_decisive(decisive)
            reason = reason or ("" if last else ("Only authorization refusals (403) or responses without the identity marker "
                                      "were recorded." if p.get("verify_expect_text") else
                                      "No identity marker is configured for this profile in the Vault."))
            entry["agents"].append({
                "agent_id": aid, "agent_name": names.get(aid, aid),
                "state": last["signal"] if last else "unknown",
                "evidence": last, "last_signal": lst[-1], "count": len(lst), "reason": reason})
        result.append(entry)
    for e in result:
        e["state_label"] = STATE_LABEL[e["state"]]
        for a in e["agents"]:
            a["state_label"] = STATE_LABEL[a["state"]]
    return {"profiles": result, "evaluated_exchanges": evaluated, "run_name": run_name,
            "method": "Full request/response pairs viewed by agents via Caido; credential bound by keyed digest; "
                      "identity marker and expected status from the Vault profile."}


def _precheck(c: dict[str, Any] | None) -> dict[str, Any] | None:
    if not c:
        return None
    return {"result": c.get("result"), "note": c.get("note"), "at": c.get("at"),
            "label": "Skynet pre-check at scan start (not evidence of the session during the scan)"}


def for_scan(scan: dict[str, Any], run_dir: Path | None) -> dict[str, Any]:
    names = {a["id"]: a["name"] for a in runs.agents(run_dir)["agents"]} if run_dir else {}
    out = evaluate(scan, run_dir, names)
    return vault.scan_redactor(scan).obj(out, True)
