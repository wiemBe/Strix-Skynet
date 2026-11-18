"""Persistent discovery inventory built from what Strix actually recorded.

Sources, with an evidence tier stored on every observation:
  observed  (machine-recorded)
    proxy        Caido proxy records the agents pulled with list_requests / view_request / repeat_request /
                 send_request (agents.db). Only the requests an agent listed are visible: Strix does not export
                 the full proxy history and the sandbox (with Caido) is removed when the scan ends.
    finding      vulnerabilities.json target / endpoint / method
  reported   (written by an agent, not machine-verified)
    coverage     coverage.json entry "surface" labels (URLs / hostnames in the label only, never the prose)
    threat_model threat_models.json keys (host:port)

Technologies are taken only from response headers inside proxy records (Server, X-Powered-By, ...). Strix has no
structured technology field; prose is not mined.

Normalization: hosts lower-cased, the sandbox alias host.docker.internal mapped back to the configured host,
query strings and fragments dropped, id-like path segments collapsed to {id}, endpoint identity includes the
HTTP method. Nothing found here changes a target's scope; scope is only labelled at read time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import db, runs, scope
from .redact import Redactor

log = logging.getLogger("skynet.inventory")
KINDS = ("host", "service", "endpoint", "technology")
PROXY_TOOLS = ("list_requests", "view_request", "repeat_request", "send_request")
TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime",
                "x-drupal-cache", "x-varnish", "via")
_URL = re.compile(r"\b(?:(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(https?://[^\s,;)\]>\"'`]+)", re.I)
_HOSTTOK = re.compile(r"(?<![\w*.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::(\d{2,5}))?(?![\w-])", re.I)
_FILEEXT = re.compile(r"\.(json|yaml|yml|js|css|md|txt|html?|php|aspx?|jsp|xml|png|jpe?g|svg|py|sh)$", re.I)


def _key(kind: str, host: str, port: int | None, scheme: str, method: str, path: str, name: str) -> str:
    if kind == "host":
        return host
    if kind == "service":
        return f"{scheme or 'tcp'}://{host}:{port or ''}"
    if kind == "endpoint":
        return f"{method or '*'} {host}:{port or ''}{path}"
    return f"{host}|{name.lower()}"


def _obs(kind: str, *, host: str, source: str, tier: str, ref: str, at: str | None, port: int | None = None,
         scheme: str = "", method: str = "", path: str = "", name: str = "", version: str = "",
         evidence: str = "", attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"kind": kind, "host": host, "port": port, "scheme": scheme, "method": method, "path": path,
            "name": name, "version": version, "source": source, "tier": tier, "ref": ref, "observed_at": at,
            "evidence": evidence[:400], "attrs": attrs or {},
            "key": _key(kind, host, port, scheme, method, path, name)}


def _url_obs(url: str, method: str, hmap: dict[str, str], **kw: Any) -> list[dict[str, Any]]:
    scheme, host, port, path = scope.split(url)
    host = hmap.get(host, host)
    if not scope.valid_host(host):
        return []
    out = [_obs("host", host=host, **kw)]
    if port:
        out.append(_obs("service", host=host, port=port, scheme=scheme, **kw))
    method = (method or "").upper()
    if path and (path != "/" or method):
        out.append(_obs("endpoint", host=host, port=port, scheme=scheme, method=method if method in scope.METHODS else "",
                        path=scope.norm_path(path), **kw))
    return out


def _ro(path: Path) -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def _proxy(run_dir: Path, hmap: dict[str, str], red: Redactor) -> list[dict[str, Any]]:
    p = run_dir / ".state" / "agents.db"
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        c = _ro(p)
        calls = {r["cid"]: (r["name"], r["args"]) for r in c.execute(
            "SELECT json_extract(message_data,'$.call_id') AS cid, json_extract(message_data,'$.name') AS name, "
            "json_extract(message_data,'$.arguments') AS args FROM agent_messages "
            f"WHERE json_extract(message_data,'$.type')='function_call' AND json_extract(message_data,'$.name') IN "
            f"({','.join('?' * len(PROXY_TOOLS))})", PROXY_TOOLS)}
        if not calls:
            c.close()
            return []
        rows = c.execute("SELECT json_extract(message_data,'$.call_id') AS cid, json_extract(message_data,'$.output') AS out, "
                         "created_at FROM agent_messages WHERE json_extract(message_data,'$.type')='function_call_output'").fetchall()
        c.close()
    except sqlite3.Error as e:
        log.warning("agents.db unreadable (%s): %s", run_dir.name, e)
        return []
    req_host: dict[str, tuple[str, int | None, bool]] = {}
    pending_tech: list[tuple[str, dict[str, str], str]] = []
    for r in rows:
        if r["cid"] not in calls:
            continue
        name, args = calls[r["cid"]]
        at = (r["created_at"] or "").replace(" ", "T") + "+00:00" if r["created_at"] else None
        try:
            data = json.loads(r["out"]) if isinstance(r["out"], str) else r["out"]
            a = json.loads(args) if isinstance(args, str) and args else {}
        except ValueError:
            continue
        if not isinstance(data, dict) or not data.get("success", True):
            continue
        if name == "list_requests":
            for e in data.get("entries") or []:
                q, resp = e.get("request") or {}, e.get("response") or {}
                host = hmap.get(str(q.get("host") or "").lower(), str(q.get("host") or "").lower())
                if not scope.valid_host(host):
                    continue
                port, tls = q.get("port"), bool(q.get("is_tls"))
                req_host[str(q.get("id"))] = (host, port, tls)
                scheme = "https" if tls else "http"
                attrs = {"status": resp.get("status_code")} if resp.get("status_code") is not None else {}
                ev = f"Caido request #{q.get('id')}: {q.get('method')} {q.get('path')}" + (
                    f" → HTTP {resp['status_code']}" if resp.get("status_code") is not None else " → no response")
                kw = dict(source="proxy", tier="observed", ref=f"req:{q.get('id')}", at=at, evidence=red.text(ev, True))
                out.append(_obs("host", host=host, **kw))
                out.append(_obs("service", host=host, port=port, scheme=scheme, **kw, attrs={"tls": tls}))
                if q.get("path"):
                    out.append(_obs("endpoint", host=host, port=port, scheme=scheme, method=str(q.get("method") or "").upper(),
                                    path=scope.norm_path(q["path"]), **{**kw, "attrs": attrs}))
        elif name == "view_request":
            content = data.get("content")
            rid = str(a.get("request_id") or "")
            if not isinstance(content, str):
                continue
            head = content.split("\n\n", 1)[0].split("\r\n\r\n", 1)[0]
            lines = head.replace("\r", "").split("\n")
            if a.get("part", "request") == "request" and lines:
                m = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/", lines[0])
                hh = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("host:")), "")
                if m and hh:
                    _, host, port, _ = scope.split(hh)
                    host = hmap.get(host, host)
                    known = req_host.get(rid)
                    tls = known[2] if known else None
                    port = (known[1] if known else None) or port or (443 if tls else 80 if tls is False else None)
                    scheme = "https" if tls else "http" if tls is False else ""
                    if scope.valid_host(host):
                        req_host.setdefault(rid, (host, port, bool(tls)))
                        kw = dict(source="proxy", tier="observed", ref=f"req:{rid}", at=at,
                                  evidence=red.text(f"Caido request #{rid}: {m.group(1)} {m.group(2).split('?')[0]}", True))
                        out.append(_obs("host", host=host, **kw))
                        out.append(_obs("endpoint", host=host, port=port, scheme=scheme, method=m.group(1),
                                        path=scope.norm_path(m.group(2)), **kw))
            elif a.get("part") == "response":
                hdrs = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip() for ln in lines[1:] if ":" in ln}
                pending_tech.append((rid, hdrs, at or ""))
        elif name in ("repeat_request", "send_request"):
            resp = data.get("response") or {}
            hdrs = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
            rid = str(a.get("request_id") or "")
            if name == "send_request" and a.get("url"):
                out += _url_obs(str(a["url"]), str(a.get("method") or ""), hmap, source="proxy", tier="observed",
                                ref=f"send:{r['cid']}", at=at,
                                evidence=red.text(f"send_request: {a.get('method') or 'GET'} {str(a['url']).split('?')[0]}"
                                                  + (f" → HTTP {resp.get('status_code')}" if resp.get("status_code") else ""), True))
                _, h, prt, _ = scope.split(str(a["url"]))
                rid = rid or f"send:{r['cid']}"
                req_host.setdefault(rid, (hmap.get(h, h), prt, str(a["url"]).startswith("https")))
            pending_tech.append((rid, hdrs, at or ""))
    for rid, hdrs, at in pending_tech:
        loc = req_host.get(rid)
        if not loc:
            continue
        for hn in TECH_HEADERS:
            v = hdrs.get(hn)
            if not v or len(v) > 120:
                continue
            m = re.match(r"^([A-Za-z][\w .+-]{0,60}?)(?:[/ ]v?(\d[\w.-]*))?(?:\s*\(.*\))?$", v.strip())
            name, ver = (m.group(1).strip(), m.group(2) or "") if m else (v.strip(), "")
            if hn == "via":
                continue
            out.append(_obs("technology", host=loc[0], name=name, version=ver, source="proxy", tier="observed",
                            ref=f"hdr:{rid}:{hn}", at=at or None, attrs={"version": ver, "header": hn},
                            evidence=red.text(f"Response header {hn}: {v} (Caido request #{rid})", True)))
    return out


def _findings(run_dir: Path, hmap: dict[str, str], red: Redactor, at: str | None) -> list[dict[str, Any]]:
    from .findings_store import locate
    data = runs._load_json(run_dir / "vulnerabilities.json")
    if not isinstance(data, list):
        return []
    out = []
    for v in data:
        if not isinstance(v, dict):
            continue
        host, method, path = locate(v, hmap)
        if not scope.valid_host(host):
            continue
        scheme, _, port, _ = scope.split(str(v.get("target") or ""))
        kw = dict(source="finding", tier="observed", ref=f"finding:{v.get('id')}", at=at,
                  evidence=red.text(f"Bulgu {v.get('id')}: {v.get('title')} ({v.get('severity')})", True))
        out.append(_obs("host", host=host, **kw))
        if path:
            out.append(_obs("endpoint", host=host, port=port, scheme=scheme, method=method, path=path, **kw))
    return out


def _coverage(run_dir: Path, hmap: dict[str, str], red: Redactor, at: str | None) -> list[dict[str, Any]]:
    cov = runs._load_json(run_dir / "coverage.json") or {}
    out: list[dict[str, Any]] = []
    for e in cov.get("entries") or []:
        surf = str(e.get("surface") or "")
        if not surf:
            continue
        ref = "cov:" + hashlib.sha1(surf.encode()).hexdigest()[:16]
        ev = red.text(f"Agent record ({e.get('outcome_label') or e.get('outcome')}): {surf}", True)
        when = e.get("updated_at") or e.get("recorded_at") or at
        seen_hosts = set()
        for m in _URL.finditer(surf):
            for o in _url_obs(m.group(2).rstrip(".:"), m.group(1) or "", hmap, source="coverage", tier="reported",
                              ref=ref, at=when, evidence=ev):
                out.append(o)
                seen_hosts.add(o["host"])
        for m in _HOSTTOK.finditer(_URL.sub(" ", surf)):
            host = hmap.get(m.group(1).lower(), m.group(1).lower())
            if host in seen_hosts or _FILEEXT.search(host) or not scope.valid_host(host):
                continue
            seen_hosts.add(host)
            out.append(_obs("host", host=host, source="coverage", tier="reported", ref=ref, at=when, evidence=ev))
            if m.group(2):
                out.append(_obs("service", host=host, port=int(m.group(2)), source="coverage", tier="reported",
                                ref=ref, at=when, evidence=ev))
    return out


def _threat_models(run_dir: Path, hmap: dict[str, str], at: str | None, red: Redactor) -> list[dict[str, Any]]:
    tm = runs._load_json(run_dir / ".state" / "threat_models.json") or {}
    out = []
    for k, v in tm.items() if isinstance(tm, dict) else []:
        _, host, port, _ = scope.split(str((v or {}).get("target") or k))
        host = hmap.get(host, host)
        if not scope.valid_host(host):
            continue
        kw = dict(source="threat_model", tier="reported", ref=f"tm:{k}",
                  at=(v or {}).get("written_at") or at, evidence=red.text(f"Agent threat-model target: {k}", True))
        out.append(_obs("host", host=host, **kw))
        if port:
            out.append(_obs("service", host=host, port=port, **kw))
    return out


def extract(run_dir: Path, red: Redactor) -> list[dict[str, Any]]:
    meta = runs._load_json(run_dir / "run.json") or {}
    hmap = scope.host_map(meta.get("targets_info") or [])
    at = meta.get("end_time") or meta.get("start_time")
    obs = _proxy(run_dir, hmap, red) + _findings(run_dir, hmap, red, at) + _coverage(run_dir, hmap, red, at) \
        + _threat_models(run_dir, hmap, at, red)
    seen, uniq = set(), []
    for o in obs:
        k = (o["kind"], o["key"], o["source"], o["ref"])
        if k not in seen:
            seen.add(k)
            uniq.append(o)
    return uniq


def source_sig(run_dir: Path) -> str:
    parts = []
    for f in ("run.json", "vulnerabilities.json", "coverage.json", ".state/agents.db", ".state/agents.db-wal",
              ".state/threat_models.json"):
        try:
            parts.append(f"{f}:{(run_dir / f).stat().st_mtime_ns}")
        except OSError:
            parts.append(f"{f}:-")
    return "|".join(parts)


def _merge_attrs(obs: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    sts = sorted({o["attrs"]["status"] for o in obs if o["attrs"].get("status") is not None})
    if sts:
        out["statuses"] = sts
    tls = {o["attrs"]["tls"] for o in obs if "tls" in o["attrs"]}
    if len(tls) == 1:
        out["tls"] = tls.pop()
    vers = [o["attrs"]["version"] for o in obs if o["attrs"].get("version")]
    if vers:
        out["version"] = vers[-1]
    return out


def _change(kind: str, old: dict[str, Any], new: dict[str, Any]) -> str | None:
    if kind == "technology" and old.get("version") and new.get("version") and old["version"] != new["version"]:
        return f"Version {old['version']} → {new['version']}"
    if kind == "service" and "tls" in old and "tls" in new and old["tls"] != new["tls"]:
        return "TLS " + ("enabled" if new["tls"] else "disabled")
    if kind == "endpoint" and old.get("statuses") and new.get("statuses") and not set(old["statuses"]) & set(new["statuses"]):
        return f"HTTP response {', '.join(map(str, old['statuses']))} → {', '.join(map(str, new['statuses']))}"
    return None


def ingest(scan: dict[str, Any], run_dir: Path, red: Redactor) -> dict[str, int]:
    """Idempotent per run. Runs must be ingested in chronological order for change detection (backfill does)."""
    tid, run = scan.get("target_id"), run_dir.name
    if not tid:
        return {}
    obs = extract(run_dir, red)
    by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for o in obs:
        by_asset.setdefault((o["kind"], o["key"]), []).append(o)
    counts = {"observations": len(obs), "assets": len(by_asset), "new": 0, "changed": 0}
    for (kind, key), lst in by_asset.items():
        first = min(lst, key=lambda o: o["observed_at"] or "")
        tier = "observed" if any(o["tier"] == "observed" for o in lst) else "reported"
        attrs = _merge_attrs(lst)
        a = db.q1("SELECT * FROM assets WHERE target_id=? AND kind=? AND key=?", (tid, kind, key))
        when = max((o["observed_at"] or "") for o in lst) or db.now_iso()
        if not a:
            aid = db.execute(
                "INSERT INTO assets (target_id, kind, key, host, port, scheme, method, path, name, version, tier, "
                "first_seen_at, first_scan_id, first_run_name, last_seen_at, last_scan_id, last_run_name, attrs) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, kind, key, first["host"], first["port"], first["scheme"], first["method"], first["path"],
                 first["name"], attrs.get("version") or first["version"], tier, first["observed_at"] or when, scan["id"], run,
                 when, scan["id"], run, json.dumps(attrs)))
            counts["new"] += 1
        else:
            aid = a["id"]
            upd: dict[str, Any] = {}
            if a["last_run_name"] != run and (when >= (a["last_seen_at"] or "")):
                note = _change(kind, a.get("attrs") or {}, attrs)
                if note:
                    upd.update(changed_at=when, changed_run_name=run, change_note=note)
                    counts["changed"] += 1
                upd.update(last_seen_at=when, last_scan_id=scan["id"], last_run_name=run, attrs=json.dumps(attrs))
                if attrs.get("version"):
                    upd["version"] = attrs["version"]
            elif a["last_run_name"] == run:
                upd.update(last_scan_id=scan["id"], attrs=json.dumps(attrs), last_seen_at=max(when, a["last_seen_at"] or ""))
            if tier == "observed" and a["tier"] != "observed":
                upd["tier"] = "observed"
            if (first["observed_at"] or "") and first["observed_at"] < (a["first_seen_at"] or "9"):
                upd.update(first_seen_at=first["observed_at"], first_scan_id=scan["id"], first_run_name=run)
            if upd:
                db.execute(f"UPDATE assets SET {', '.join(f'{k}=?' for k in upd)} WHERE id=?", [*upd.values(), aid])
        for o in lst:
            db.execute("INSERT INTO asset_observations (asset_id, scan_id, run_name, source, tier, ref, evidence, attrs, observed_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id, run_name, source, ref) DO UPDATE SET "
                       "scan_id=excluded.scan_id, evidence=excluded.evidence, attrs=excluded.attrs",
                       (aid, scan["id"], run, o["source"], o["tier"], o["ref"], o["evidence"], json.dumps(o["attrs"]),
                        o["observed_at"] or when))
    return counts


# ---------------------------------------------------------------- queries
def run_diff(run_name: str, target_id: int) -> dict[str, Any]:
    """New / changed / seen / not-observed for one run, relative to everything known before it."""
    ri = db.q1("SELECT * FROM run_ingest WHERE run_name=?", (run_name,)) or {}
    seen_ids = {r["asset_id"] for r in db.q("SELECT DISTINCT asset_id FROM asset_observations WHERE run_name=?", (run_name,))}
    rows = db.q("SELECT id, kind, first_run_name, changed_run_name, first_seen_at FROM assets WHERE target_id=?", (target_id,))
    start = (db.q1("SELECT MIN(COALESCE(started_at, created_at)) AS s FROM scans WHERE run_name=?", (run_name,)) or {}).get("s") or ""
    out = {k: {"new": 0, "changed": 0, "seen": 0, "not_observed": 0} for k in KINDS}
    for r in rows:
        c = out.setdefault(r["kind"], {"new": 0, "changed": 0, "seen": 0, "not_observed": 0})
        if r["first_run_name"] == run_name:
            c["new"] += 1
        elif r["id"] in seen_ids:
            c["changed" if r["changed_run_name"] == run_name else "seen"] += 1
        elif (r["first_seen_at"] or "") < start or not start:
            c["not_observed"] += 1
    return {"by_kind": out, "complete": ri.get("complete"), "scan_status": ri.get("scan_status"),
            "scan_mode": ri.get("scan_mode"), "ingested_at": ri.get("ingested_at")}


def latest_run(target_id: int) -> str | None:
    r = db.q1("SELECT ri.run_name FROM run_ingest ri JOIN scans s ON s.run_name=ri.run_name WHERE ri.target_id=? "
              "ORDER BY COALESCE(s.started_at, s.created_at) DESC LIMIT 1", (target_id,))
    return r["run_name"] if r else None


def assets_for(target: dict[str, Any], kind: str = "", tier: str = "", scope_label: str = "",
               q: str = "") -> list[dict[str, Any]]:
    """Assets of a target, newest activity first, each tagged with its scope label (in / out / unknown) against the
    target's own rules. Filters are optional; scope is labelled at read time and never written back."""
    sql, args = "SELECT * FROM assets WHERE target_id=?", [target["id"]]
    if kind in KINDS:
        sql += " AND kind=?"; args.append(kind)
    if tier in ("observed", "reported"):
        sql += " AND tier=?"; args.append(tier)
    rows = db.q(sql + " ORDER BY last_seen_at DESC, kind, key", args)
    ql = (q or "").strip().lower()
    out = []
    for a in rows:
        a["scope"] = scope.label(target, a.get("host") or "", a.get("port"), a.get("path") or "")
        a["observation_count"] = (db.q1("SELECT COUNT(*) n FROM asset_observations WHERE asset_id=?", (a["id"],)) or {}).get("n", 0)
        if scope_label and a["scope"] != scope_label:
            continue
        if ql and ql not in f"{a.get('host','')} {a.get('path','')} {a.get('name','')} {a.get('key','')}".lower():
            continue
        out.append(a)
    return out


def observations(asset_id: int) -> list[dict[str, Any]]:
    return db.q("SELECT o.*, s.status AS scan_status, s.started_at FROM asset_observations o "
                "LEFT JOIN scans s ON s.id=o.scan_id WHERE o.asset_id=? ORDER BY o.observed_at DESC, o.id DESC", (asset_id,))


def summary_for(target_id: int) -> dict[str, Any]:
    rows = db.q("SELECT kind, tier, COUNT(*) n FROM assets WHERE target_id=? GROUP BY kind, tier", (target_id,))
    by_kind: dict[str, dict[str, int]] = {}
    for r in rows:
        d = by_kind.setdefault(r["kind"], {"observed": 0, "reported": 0, "total": 0})
        d[r["tier"]] = r["n"]
        d["total"] += r["n"]
    return {"by_kind": by_kind, "total": sum(d["total"] for d in by_kind.values())}
