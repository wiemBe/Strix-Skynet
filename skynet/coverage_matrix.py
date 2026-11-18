"""Evidence-backed test coverage: endpoint × role × test type (SKY-03).

Two layers, kept apart:
  source claims   coverage.json entries exactly as Strix wrote them (agent-reported; the file is never modified)
  Skynet status   an evaluation of each claim against machine-recorded evidence (evidence.py)

Statuses and what each requires:
  Tested            a settled, current-version Skynet verification accepted the relevant test, and its linked
                    request/response pairs belong to this endpoint, origin, role and test category.
                    Traffic volume plus an agent's coverage claim is never test-execution evidence.
  Partially tested  the record says the test ran but only one full exchange, or only list metadata, exists for
                    the role; or the agent marked the surface needs_follow_up.
  Access blocked    every recorded full exchange for the role was refused (401/403).
  Not tested        the endpoint was observed in this run but nothing records a test or a full exchange for it.
                    (Absence of records is not proof that no request was sent; Strix does not export proxy history.)
  Not applicable    the agent recorded not_applicable; its stated reason is shown.
  Unknown           a record without evidence for the role, a surface that cannot be mapped to an endpoint, or
                    traffic without any test record.

Test types are OWASP WSTG v4.2 category ids mapped heuristically from Strix's free-text risk_area. This is not an
OWASP compliance or certification statement. Roles are Vault profile references (no secrets) plus "anonymous"
for requests without credentials and "unattributed" for credentials that match no profile of the scan.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import db, evidence, runs, scope, session_health, vault

# scheme, canonical host, effective port, method, normalized path. Unknown origins remain explicit.
Endpoint = tuple[str, str, int | None, str, str]

WSTG_VERSION = "OWASP WSTG v4.2"
WSTG_URL = "https://owasp.org/www-project-web-security-testing-guide/v42/"
WSTG = {
    "WSTG-ATHZ": ("Authorization", r"authori[sz]ation|access.?control|idor|bola|bfla|privilege|object.level|tenant"),
    "WSTG-ATHN": ("Authentication", r"authenticat|login|credential|password|mfa|2fa|impersonat|brute"),
    "WSTG-SESS": ("Session management", r"session|cookie|csrf|jwt|token fixation|logout"),
    "WSTG-INPV": ("Input validation", r"inject|sqli|xss|ssrf|traversal|command|xxe|deseriali|ssti|input valid|redirect"),
    "WSTG-BUSL": ("Business logic", r"business logic|race|workflow|mass assignment"),
    "WSTG-IDNT": ("Identity management", r"identity management|registration|enumeration|account provision"),
    "WSTG-CONF": ("Configuration & deployment", r"config|cors|header|tls|deployment|debug|exposed|admin interface"),
    "WSTG-ERRH": ("Error handling", r"error handling|stack trace|verbose error"),
    "WSTG-CRYP": ("Cryptography", r"crypt|cipher|hash"),
    "WSTG-CLNT": ("Client-side", r"client.side|dom|clickjack|postmessage"),
    "WSTG-APIT": ("API (GraphQL)", r"graphql"),
    "WSTG-INFO": ("Information gathering", r"recon|information|disclos|fingerprint|surface map"),
}
UNMAPPED = "UNMAPPED"
STATUS = ("tested", "partial", "blocked", "not_tested", "not_applicable", "unknown")
STATUS_LABEL = {"tested": "Tested", "partial": "Partially tested", "blocked": "Access blocked",
                "not_tested": "Not tested", "not_applicable": "Not applicable", "unknown": "Unknown"}
CLAIM_TESTED = ("reported", "no_issue_found", "ruled_out")
_EP = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://[^\s,;)+]+|/[^\s,;)+]*)", re.I)
_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "api-key", "x-auth-token")


def test_type(risk_area: str) -> str:
    text = (risk_area or "").lower()
    for wid, (_, rx) in WSTG.items():
        if re.search(rx, text):
            return wid
    return UNMAPPED


def type_label(wid: str) -> str:
    return WSTG[wid][0] if wid in WSTG else "Unmapped risk area"


def endpoints_of(surface: str, hmap: dict[str, str]) -> list[Endpoint]:
    """Preserve origins on full URLs. A path-only claim does not identify a host."""
    out = []
    for m in _EP.finditer(surface or ""):
        target = m.group(2)
        scheme, host, port, path = scope.split(target) if "://" in target else ("", "", None, target)
        out.append((scheme, hmap.get(host, host), port, m.group(1).upper(), scope.norm_path(path)))
    return list(dict.fromkeys(out))


def _role(req: dict[str, Any], profiles: list[dict[str, Any]]) -> str:
    for p in profiles:
        if p.get("kind") in ("header", "cookie") and session_health._carries(p, req["headers"]):
            return f"profile:{p.get('id')}"
    if any(h in req["headers"] for h in _AUTH_HEADERS):
        return "unattributed"
    return "anonymous"


def _sig(x: dict[str, Any]) -> str:
    req = x["request"]["parsed"]
    return hashlib.sha1(json.dumps([req["method"], req["url"], sorted(req["headers"].items()), req["body"]]).encode()).hexdigest()


def origin_label(ep: Endpoint) -> str:
    scheme, host, port, _, _ = ep
    return f"{scheme + '://' if scheme else '//'}{host}:{port if port is not None else '?'}" if host else "Origin unknown"


def _traffic_endpoint(x: dict[str, Any], hmap: dict[str, str], origins: set[tuple]) -> Endpoint:
    host, port, method, path = evidence.location(x, hmap)
    req = (x.get("request") or {}).get("parsed") or {}
    url = req.get("url") or ""
    if "://" in url:
        scheme = scope.split(url)[0]
    elif x.get("listed"):
        scheme = "https" if x["listed"].get("tls") else "http"
        if req:
            explicit = scope.split(req.get("headers", {}).get("host", ""))[2]
            port = explicit or x["listed"].get("port") or scope.DEFAULT_PORTS[scheme]
    else:
        matches = {s for s, h, p in origins if h == host and p == port}
        scheme = next(iter(matches)) if len(matches) == 1 else ""
    return scheme, host, port, method, path


# Only explicit CWE mappings are used to relate an accepted verification to a test category.
# Unmapped categories stay partial; free-text risk_area is insufficient for promotion to Tested.
_CWE_TYPES = {**{n: "WSTG-ATHZ" for n in (285, 639, 862, 863)},
              **{n: "WSTG-ATHN" for n in (287, 306, 307)},
              **{n: "WSTG-SESS" for n in (352, 384, 613)},
              **{n: "WSTG-INPV" for n in (22, 77, 78, 79, 89, 90, 91, 94, 98, 113, 611, 918)},
              362: "WSTG-BUSL", 840: "WSTG-BUSL"}


def _accepted_test(scan: dict[str, Any]) -> dict[str, Any] | None:
    row = db.q1("SELECT * FROM finding_verifications WHERE scan_id=? AND classification_version=2 "
                "AND result IN ('reverified','not_reproduced')", (scan.get("id"),))
    if not row or scan.get("status") != "completed":
        return None
    ev = row.get("verification_evidence") or {}
    group = db.get("finding_groups", row["group_id"])
    if ev.get("test_executed") is not True or not group or group.get("target_id") != scan.get("target_id"):
        return None
    cwe = re.fullmatch(r"(?:CWE-)?(\d+)", str(group.get("cwe") or ""), re.I)
    category = _CWE_TYPES.get(int(cwe[1])) if cwe else None
    ids = {str(rid) for rid in ev.get("request_ids") or []}
    if not category or len(ids) < 2:
        return None
    return {"id": row["id"], "category": category, "host": group.get("host"), "method": group.get("method"),
            "path": scope.norm_path(group.get("endpoint") or ""), "request_ids": ids}


def build(scan: dict[str, Any], run_dir: Path | None) -> dict[str, Any]:
    run_name = scan.get("run_name") or (run_dir.name if run_dir else "")
    base = {"available": False, "run_name": run_name, "wstg_version": WSTG_VERSION, "wstg_url": WSTG_URL,
            "statuses": STATUS_LABEL, "cells": [], "claims": [], "roles": [], "types": [], "gaps": []}
    if not run_dir:
        base["reason"] = "The run output folder is missing."
        return base
    cov = runs._load_json(run_dir / "coverage.json")
    meta = runs._load_json(run_dir / "run.json") or {}
    hmap = scope.host_map(meta.get("targets_info") or [])
    profiles = session_health.scan_profiles(scan)
    target = db.get("targets", scan.get("target_id")) if scan.get("target_id") else None
    origins = {scope.split(u)[:3] for u in [*((scan.get("targets") or [])),
               *((target or {}).get("extra_targets") or []), (target or {}).get("base_url") or ""] if "://" in u}
    origins = {(s, hmap.get(h, h), p) for s, h, p in origins if h}
    accepted = _accepted_test(scan)
    roles = [{"id": f"profile:{p.get('id')}", "label": p.get("name") or f"Profile #{p.get('id')}",
              "kind": p.get("kind"), "profile_id": p.get("id"),
              "attributable": p.get("kind") in ("header", "cookie") and bool(p.get("auth_bindings"))}
             for p in profiles if p.get("kind") != "anonymous"]
    roles.append({"id": "anonymous", "label": "Anonymous (no credential)", "kind": "anonymous", "attributable": True})
    roles.append({"id": "unattributed", "label": "Credential not matching a scan profile", "kind": "unknown",
                  "attributable": True})
    # Recorded traffic, grouped by endpoint and role.
    traffic: dict[Endpoint, dict[str, list[dict[str, Any]]]] = {}
    listed_only: dict[Endpoint, int] = {}
    for x in evidence.load(run_dir).values():
        key = _traffic_endpoint(x, hmap, origins)
        if not key[4]:
            continue
        if evidence.full(x):
            r = _role(x["request"]["parsed"], profiles)
            traffic.setdefault(key, {}).setdefault(r, []).append(x)
        elif x.get("listed"):
            listed_only[key] = listed_only.get(key, 0) + 1
    observed = _observed_endpoints(run_name, scan.get("target_id"))
    known_origins = origins | {ep[:3] for ep in set(traffic) | set(listed_only) if ep[0]}
    # Inventory may omit a scheme. Resolve that missing field only when the same host and port have one
    # known origin; never treat "unknown scheme" as a second application or merge two known origins.
    normalized_observed = set()
    for ep in observed:
        matches = {o for o in known_origins if o[1:] == ep[1:3]}
        normalized_observed.add((*next(iter(matches)), *ep[3:]) if not ep[0] and len(matches) == 1 else ep)
    observed = normalized_observed
    def find(ep: Endpoint) -> list[Endpoint]:
        scheme, host, port, method, path = ep
        return [k for k in set(traffic) | set(listed_only) | observed if k[4] == path and
                (not method or not k[3] or k[3] == method) and
                (not host or (k[:3] == (scheme, host, port)))]

    # Which recorded exchanges can be tied to a particular coverage record (see claim_links).
    agent_ids: dict[str, set[str]] = {}
    for a in runs.agents(run_dir)["agents"]:
        agent_ids.setdefault(str(a.get("name") or ""), set()).add(a["id"])
    vulns = runs._load_json(run_dir / "vulnerabilities.json")
    vulns = [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []

    entries = (cov or {}).get("entries") or [] if isinstance(cov, dict) else []
    claims, cells = [], {}
    red = vault.scan_redactor(scan)
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            continue
        claim = red.obj({"index": i, **{k: e.get(k) for k in ("surface", "risk_area", "outcome", "outcome_label", "evidence",
                                                      "recorded_by", "recorded_at", "updated_at", "source")}}, True)
        tt = test_type(e.get("risk_area") or "")
        eps = endpoints_of(e.get("surface") or "", hmap)
        claim.update(test_type=tt, endpoints=[f"{ep[3]} {origin_label(ep) + ep[4] if ep[1] else ep[4]}" for ep in eps])
        claims.append(claim)
        if not eps:
            ep = ("", "", None, "", "(unmapped surface) " + red.text(str(e.get("surface") or ""), True)[:120])
            _put(cells, (ep, "*", tt), "unknown",
                 "The surface label names no HTTP method and path, so it cannot be mapped to an endpoint.", claim=i)
            continue
        for ep in eps:
            keys = find(ep)
            candidates = keys or ([ep] if ep[1] else [(s, h, p, ep[3], ep[4]) for s, h, p in origins] or [ep])
            ambiguous = not ep[1] and len({k[:3] for k in candidates}) > 1
            linked_ids = claim_links(e, agent_ids, vulns)
            for key in candidates:
                for role in roles:
                    exs = traffic.get(key, {}).get(role["id"], [])
                    linked = [x for x in exs if _linked(x, e, linked_ids)]
                    validated = bool(not ambiguous and accepted and accepted["category"] == tt and
                        accepted["host"] == key[1] and accepted["method"] == key[3] and accepted["path"] == key[4]
                        and accepted["request_ids"] <= {x["request_id"] for x in linked})
                    status, reason = _evaluate(e.get("outcome"), exs, linked, listed_only.get(key, 0), role, claim, validated)
                    if status is None:
                        continue
                    if ambiguous:
                        reason += " The path-only coverage claim names multiple origins; its origin is not established."
                    _put(cells, (key, role["id"], tt), status, reason, claim=i, exchanges=linked or exs, run_name=run_name)
                    if validated and status == "tested":
                        cells[(key, role["id"], tt)]["verification_id"] = accepted["id"]
    # Observed endpoints that no coverage record covers.
    covered = {c[0] for c in cells}
    for key in sorted(set(traffic) | set(listed_only) | observed, key=str):
        if key in covered:
            continue
        roles_seen = traffic.get(key, {})
        if roles_seen:
            for rid, exs in roles_seen.items():
                _put(cells, (key, rid, "NONE"), "unknown",
                     "Requests were recorded, but no coverage record states which test was performed.",
                     exchanges=exs, run_name=run_name)
        elif key in listed_only:
            _put(cells, (key, "*", "NONE"), "unknown",
                 f"Only list metadata ({listed_only[key]}) was recorded; no coverage record states a test.")
        else:
            _put(cells, (key, "*", "NONE"), "not_tested",
                 "Observed in this run, but no coverage record and no full request/response exist for it. "
                 "Absence of records does not prove that no request was sent.")
    out_cells = []
    for (ep, role, tt), c in sorted(cells.items(), key=lambda item: str(item[0])):
        per = c["claim_status"]
        n_best = sum(1 for v in per.values() if v["status"] == c["status"])
        out_cells.append({"endpoint": f"{ep[3] or '*'} {ep[4]}" if not ep[4].startswith("(unmapped") else ep[4],
                          "scheme": ep[0], "host": ep[1], "port": ep[2], "method": ep[3], "path": ep[4],
                          "origin": origin_label(ep), "verification_id": c.get("verification_id"),
                          "role": role, "test_type": tt,
                          "test_type_label": "No test record" if tt == "NONE" else type_label(tt),
                          "status": c["status"], "status_label": STATUS_LABEL[c["status"]] + (
                              f" · {n_best} of {len(per)} records" if len(per) > 1 and n_best < len(per) else ""),
                          "mixed": len({v["status"] for v in per.values()}) > 1,
                          "claim_results": [{"claim": k, **v} for k, v in sorted(per.items())], "reasons": c["reasons"],
                          "claims": sorted(c["claims"]), "evidence": c["evidence"][:40],
                          "evidence_count": len(c["evidence"]), "agents": sorted(c["agents"]),
                          "last_at": max((x.get("at") or "" for x in c["evidence"]), default="") or None})
    types = sorted({c["test_type"] for c in out_cells})
    base.update(available=True, cells=out_cells, claims=claims, roles=roles,
                types=[{"id": t, "label": "No test record" if t == "NONE" else type_label(t),
                        "heuristic": t != "NONE"} for t in types],
                complete=((cov or {}).get("completeness") or {}).get("complete") if isinstance(cov, dict) else None,
                gaps=[g.get("detail") for g in (cov or {}).get("gaps") or [] if isinstance(g, dict)] if isinstance(cov, dict) else [],
                source="coverage.json" if isinstance(cov, dict) else None,
                rule="Tested requires an accepted Skynet verification for the same test category, origin, endpoint "
                     "and role, linked to its complete request/response evidence. Ordinary traffic and an agent's "
                     "coverage claim are not enough. Unsupported test categories remain partial or unknown. "
                     "Tested does not mean secure.")
    if not isinstance(cov, dict):
        base["gaps"].insert(0, "Strix did not write coverage.json for this run; no test records are available.")
    return red.obj(base, True)


def claim_links(e: dict[str, Any], agent_ids: dict[str, set[str]], vulns: list[dict[str, Any]]) -> dict[str, Any]:
    """What ties exchanges to one coverage record: the agents named as its author, the time it was last written, and
    for a "reported" record the http_exchange_ids of the finding it names (by id in its text, or by the same agent)."""
    by = str(e.get("recorded_by") or "")
    rids: set[str] = set()
    if str(e.get("outcome") or "").lower() == "reported":
        text = str(e.get("evidence") or "")
        for v in vulns:
            if (v.get("id") and str(v["id"]) in text) or (by and v.get("agent_name") == by):
                rids |= {str(i) for i in v.get("http_exchange_ids") or []}
    when = e.get("updated_at") or e.get("recorded_at") or ""
    when = str(when).replace(" UTC", "Z").replace(" ", "T") if when else ""
    return {"agents": agent_ids.get(by, set()), "until": when, "finding_rids": rids}


def _linked(x: dict[str, Any], e: dict[str, Any], links: dict[str, Any]) -> bool:
    if x["request_id"] in links["finding_rids"]:
        return True
    if not links["agents"] or not (set(x.get("viewed_by") or []) & links["agents"]):
        return False
    seen = x["response"]["stored_at"]
    if links["until"] and seen:
        return seen[:19] <= links["until"][:19]
    return True


def _evaluate(outcome: str | None, all_exs: list[dict[str, Any]], exs: list[dict[str, Any]], listed: int,
              role: dict[str, Any], claim: dict[str, Any], validated: bool = False) -> tuple[str | None, str]:
    """exs = exchanges that belong to this coverage record; all_exs = every exchange for the endpoint and role."""
    outcome = (outcome or "").lower()
    if outcome == "not_applicable":
        if role["id"] == "unattributed" or (role["id"] == "anonymous" and not all_exs):
            return None, ""
        return "not_applicable", "Agent recorded not applicable: " + str(claim.get("evidence") or "no reason given")[:600]
    if not exs and all_exs:
        if outcome not in (*CLAIM_TESTED, "needs_follow_up"):
            return "unknown", "Requests were recorded, but the coverage record does not state a completed test."
        return "partial", (f"Coverage record ({outcome}); {len(all_exs)} full request/response pairs exist for this "
                           "endpoint and role, but none belong to this record (not viewed by the agent that wrote it "
                           "before writing it, nor linked by its finding).")
    if not exs:
        if role["id"] in ("unattributed", "anonymous"):
            return None, ""   # do not invent rows for roles nothing points at
        if not role.get("attributable"):
            return "unknown", ("This profile's requests cannot be identified in recorded traffic (form login or no "
                               "credential snapshot).")
        if listed:
            return "partial", f"Coverage record ({outcome or 'no outcome'}); only list metadata ({listed}) was recorded, no full request/response."
        return "unknown", "Coverage record exists, but no full request/response for this role was recorded."
    distinct = {_sig(x) for x in exs}
    refused = [x for x in exs if evidence.status(x) in (401, 403)]
    if len(refused) == len(exs):
        return "blocked", f"All {len(exs)} recorded full exchanges for this role were refused (HTTP 401/403)."
    if outcome == "needs_follow_up":
        return "partial", "The agent marked this surface as needing follow-up."
    if outcome not in CLAIM_TESTED:
        return "unknown", "Requests were recorded, but the coverage record does not state a completed test."
    if validated and len(distinct) >= 2:
        return "tested", "Test execution accepted by Skynet verification and linked to this category, origin, endpoint and role."
    if len(distinct) >= 2:
        return "partial", "Recorded traffic and an agent claim exist, but test execution has no accepted, category-specific verification."
    return "partial", "Coverage record says tested, but only one distinct full request/response belonging to it was recorded for this role."


def _put(cells: dict, key: tuple[str, str, str], status: str, reason: str, claim: int | None = None,
         exchanges: list[dict[str, Any]] | None = None, run_name: str = "") -> None:
    rank = {"tested": 5, "partial": 4, "blocked": 3, "not_applicable": 2, "unknown": 1, "not_tested": 0}
    c = cells.setdefault(key, {"status": status, "reasons": [], "claims": set(), "evidence": [], "agents": set(),
                               "claim_status": {}})
    if rank[status] > rank[c["status"]]:
        c["status"] = status
    if reason and reason not in c["reasons"]:
        c["reasons"].append(reason)
    if claim is not None:
        c["claims"].add(claim)
        prev = c["claim_status"].get(claim)
        if not prev or rank[status] > rank[prev["status"]]:
            c["claim_status"][claim] = {"status": status, "status_label": STATUS_LABEL[status], "reason": reason}
    seen = {e["key"] for e in c["evidence"]}
    for x in exchanges or []:
        k = f"{run_name}:{x['request_id']}"
        if k in seen:
            continue
        seen.add(k)
        at, src = evidence.best_time(x)
        c["evidence"].append({"key": k, "request_id": x["request_id"], "status": evidence.status(x),
                              "at": at, "time_source": src, "agent_id": x["response"]["agent_id"]})
        c["agents"].add(x["response"]["agent_id"])


def _observed_endpoints(run_name: str, target_id: int | None) -> set[Endpoint]:
    if not run_name or not target_id:
        return set()
    rows = db.q("SELECT DISTINCT a.scheme, a.host, a.port, a.method, a.path FROM assets a JOIN asset_observations o ON o.asset_id=a.id "
                "WHERE a.target_id=? AND a.kind='endpoint' AND o.run_name=? AND o.tier='observed'", (target_id, run_name))
    return {(r["scheme"] or "", r["host"] or "", r["port"], r["method"] or "", r["path"] or "")
            for r in rows if r.get("path")}
