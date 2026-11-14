"""Readers for Strix run directories (<workdir>/strix_runs/<run_name>/)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 ... critical=4

DOWNLOADABLE = {
    "report": "penetration_test_report.md",
    "sarif": "findings.sarif",
    "csv": "vulnerabilities.csv",
    "json": "vulnerabilities.json",
    "coverage": "coverage.json",
    "log": "strix.log",
}

_cache: dict[tuple[str, str], tuple[float, Any]] = {}


def _load_json(path: Path) -> Any:
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    key = (str(path), "json")
    hit = _cache.get(key)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    _cache[key] = (mtime, data)
    return data


def runs_root(workdir: str) -> Path:
    return Path(workdir).expanduser() / "strix_runs"


def list_run_dirs(workdir: str) -> list[Path]:
    root = runs_root(workdir)
    if not root.is_dir():
        return []
    return [p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")]


def run_meta(run_dir: Path) -> dict[str, Any]:
    r = _load_json(run_dir / "run.json") or {}
    usage = r.get("llm_usage") or {}
    targets = [t.get("original") for t in r.get("targets_info") or [] if t.get("original")]
    return {
        "run_name": r.get("run_name") or run_dir.name,
        "status": r.get("status"),
        "start_time": r.get("start_time"),
        "end_time": r.get("end_time"),
        "scan_mode": r.get("scan_mode"),
        "targets": targets,
        "instruction": r.get("user_instruction") or r.get("instruction") or "",
        "cost": usage.get("cost") or 0.0,
        "tokens": usage.get("total_tokens") or 0,
        "requests": usage.get("requests") or 0,
        "executive_summary": (r.get("scan_results") or {}).get("executive_summary"),
    }


_MD_FIELD = re.compile(r"^\*\*(?P<k>[^*]+):\*\*\s*(?P<v>.+)$", re.M)


def _parse_vuln_md(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = text.splitlines()[0].lstrip("# ").strip() if text else path.stem
    fields = {m["k"].strip().lower(): m["v"].strip() for m in _MD_FIELD.finditer(text[:3000])}
    cvss = fields.get("cvss")
    try:
        cvss_f = float(cvss) if cvss else None
    except ValueError:
        cvss_f = None
    return {
        "id": fields.get("id", path.stem),
        "title": title,
        "severity": fields.get("severity", "info").lower(),
        "timestamp": fields.get("found"),
        "target": fields.get("target"),
        "endpoint": fields.get("endpoint"),
        "method": fields.get("method"),
        "cwe": fields.get("cwe"),
        "cvss": cvss_f,
        "confidence": (fields.get("confidence") or "").lower(),
        "fix_effort": (fields.get("fix_effort") or "").lower(),
        "markdown": text,
        "partial": True,
    }


def findings(run_dir: Path) -> list[dict[str, Any]]:
    """Final vulnerabilities.json if present, else live per-finding markdown files."""
    data = _load_json(run_dir / "vulnerabilities.json")
    if isinstance(data, list):
        items = [dict(v) for v in data if isinstance(v, dict)]
        for v in items:
            v["severity"] = str(v.get("severity") or "info").lower()
    else:
        items = []
        vdir = run_dir / "vulnerabilities"
        if vdir.is_dir():
            for p in sorted(vdir.glob("*.md")):
                try:
                    items.append(_parse_vuln_md(p))
                except OSError:
                    continue
    items.sort(key=lambda v: (-SEV_RANK.get(v["severity"], 0), -(v.get("cvss") or 0)))
    return items


def severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for v in items:
        out[v["severity"] if v["severity"] in out else "info"] += 1
    return out


def agents(run_dir: Path) -> dict[str, Any]:
    a = _load_json(run_dir / ".state" / "agents.json") or {}
    statuses = a.get("statuses") or {}
    names = a.get("names") or {}
    parents = a.get("parent_of") or {}
    lst = [
        {"id": aid, "name": names.get(aid, aid), "status": st, "parent": parents.get(aid)}
        for aid, st in statuses.items()
    ]
    counts: dict[str, int] = {}
    for x in lst:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    return {"agents": lst, "counts": counts}


def summarize(run_dir: Path, fail_on: str | None = None) -> dict[str, Any]:
    meta = run_meta(run_dir)
    items = findings(run_dir)
    counts = severity_counts(items)
    gate = None
    if fail_on and fail_on in SEV_RANK:
        threshold = SEV_RANK[fail_on]
        gate = "fail" if any(SEV_RANK.get(v["severity"], 4) >= threshold for v in items) else "pass"
    return {
        "counts": counts,
        "total": len(items),
        "cost": meta["cost"] or None,   # Strix writes 0.0 when it cannot price the model
        "tokens": meta["tokens"],
        "requests": meta["requests"],
        "run_status": meta["status"],
        "has_report": (run_dir / DOWNLOADABLE["report"]).exists(),
        "gate": gate,
    }


_MODEL_RE = re.compile(r"LLM model resolved: (\S+)")
_CONTAINER_RE = re.compile(r"Sandbox container created: id=([0-9a-f]{6,64})")


def _log_head(run_dir: Path, limit: int = 200_000) -> str:
    try:
        with (run_dir / "strix.log").open("rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def log_model(run_dir: Path) -> str | None:
    """Model actually used: Strix records it only in strix.log ("LLM model resolved: ...")."""
    m = _MODEL_RE.search(_log_head(run_dir))
    return m.group(1) if m else None


def sandbox_containers(run_dir: Path) -> list[str]:
    """Docker container ids Strix created for this run (logged by strix.runtime.docker_client)."""
    try:
        text = (run_dir / "strix.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return sorted(set(_CONTAINER_RE.findall(text)))


def tail(path: Path, offset: int, max_bytes: int = 256_000) -> tuple[str, int]:
    """Return text appended since `offset` (or the last max_bytes when offset<0)."""
    try:
        size = path.stat().st_size
    except OSError:
        return "", 0
    if offset < 0 or offset > size:
        offset = max(0, size - max_bytes)
    with path.open("rb") as f:
        f.seek(offset)
        chunk = f.read(max_bytes)
    return chunk.decode("utf-8", errors="replace"), offset + len(chunk)
