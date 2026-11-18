"""URL / host normalization and scope labelling.

Scope is only *labelled* here (in / out / unknown). Nothing discovered is ever added to a target's scope
automatically: the rules the user defined on the target stay authoritative.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
# Strix rewrites loopback targets to this name inside the sandbox (see run.json targets_info).
DOCKER_HOST_ALIASES = {"host.docker.internal", "gateway.docker.internal"}
_HOST_RE = re.compile(r"^[a-z0-9._-]+$")
_ID_SEG = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,})$", re.I)
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")


def split(url_or_host: str) -> tuple[str, str, int | None, str]:
    """-> (scheme, host, port, path). Accepts URLs, host:port, bare hosts. Query and fragment are dropped."""
    s = (url_or_host or "").strip()
    if not s:
        return "", "", None, ""
    if "://" not in s:
        s = "//" + s
    try:
        u = urlsplit(s)
        host = (u.hostname or "").strip(".").lower()
        port = u.port
    except ValueError:
        return "", "", None, ""
    scheme = (u.scheme or "").lower()
    if port is None and scheme in DEFAULT_PORTS:
        port = DEFAULT_PORTS[scheme]
    return scheme, host, port, u.path or ""


def valid_host(host: str) -> bool:
    return bool(host) and bool(_HOST_RE.match(host)) and ("." in host or host == "localhost" or host.replace(".", "").isdigit())


def norm_path(path: str) -> str:
    """Strip query/fragment, collapse slashes, drop trailing slash, replace id-like segments with {id}."""
    p = (path or "").split("?", 1)[0].split("#", 1)[0].strip()
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    segs = [("{id}" if _ID_SEG.match(seg) else seg) for seg in p.split("/")]
    p = "/".join(segs)
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p


def host_map(run_targets_info: list[dict[str, Any]]) -> dict[str, str]:
    """Map sandbox-side hostnames back to what the user configured (host.docker.internal -> 127.0.0.1)."""
    out: dict[str, str] = {}
    for t in run_targets_info or []:
        orig = split(str(t.get("original") or ""))[1]
        inner = split(str(((t.get("details") or {}).get("target_url")) or ""))[1]
        if orig and inner and orig != inner:
            out[inner] = orig
    return out


def _host_match(rule_host: str, host: str) -> bool:
    if rule_host.startswith("*."):
        base = rule_host[2:]
        return host == base or host.endswith("." + base)
    return host == rule_host


def _rule(entry: str) -> tuple[str, int | None, str]:
    """A scope line -> (host, port, path_prefix). '/admin' is a path-only rule (host '')."""
    e = entry.strip()
    if e.startswith("/"):
        return "", None, e.rstrip("/") or "/"
    scheme, host, port, path = split(e)
    explicit_port = port if scheme in DEFAULT_PORTS or (":" in e.split("//")[-1].split("/")[0]) else None
    return host, explicit_port, (path.rstrip("/") if path and path != "/" else "")


def label(target: dict[str, Any], host: str, port: int | None = None, path: str = "") -> str:
    """'in' | 'out' | 'unknown' against the target's own scope rules."""
    if not host:
        return "unknown"
    path = path or "/"
    for e in target.get("out_of_scope") or []:
        rh, rp, pp = _rule(e)
        if rh and not _host_match(rh, host):
            continue
        if rp and port is not None and rp != port:
            continue
        if not rh and not pp:
            continue
        if not pp or path == pp or path.startswith(pp.rstrip("/") + "/"):
            return "unknown" if rp and port is None else "out"
    rules = [s for s in (target.get("in_scope") or []) if s.strip()]
    if not rules:  # no explicit list: the configured targets themselves define scope
        rules = [target.get("base_url") or ""] + [x for x in (target.get("extra_targets") or []) if "://" in str(x) or "." in str(x)]
    unknown_port = False
    for e in rules:
        rh, rp, pp = _rule(e)
        if not rh or not _host_match(rh, host):
            continue
        if rp and port is not None and rp != port:
            continue
        if pp and not (path == pp or path.startswith(pp + "/")):
            continue
        if rp and port is None:
            unknown_port = True
            continue
        return "in"
    return "unknown" if unknown_port or not rules else "out"
