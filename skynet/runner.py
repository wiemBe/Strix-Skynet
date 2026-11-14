"""Background execution of Strix scans: queue, process lifecycle, cancellation, recovery."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from . import db, llm, runs, targets
from .config import LOG_DIR, RUNTIME_DIR

log = logging.getLogger("skynet.runner")

ACTIVE = ("queued", "running", "stopping")
FINAL = ("completed", "failed", "cancelled", "interrupted")
_procs: dict[int, subprocess.Popen] = {}
_cancel_requested: set[int] = set()
_lock = threading.RLock()
_wake = threading.Event()
RUN_DIR_RE = re.compile(r"run_dir=([^\s,)]+)")
OUTPUT_RE = re.compile(r"strix_runs/([A-Za-z0-9._-]+)")


class Busy(Exception):
    """Raised when the target already has an active scan."""


# ---------------------------------------------------------------- environment checks
def _docker() -> str:
    return shutil.which("docker") or "/usr/local/bin/docker"


def docker_status() -> dict[str, Any]:
    try:
        out = subprocess.run([_docker(), "info", "--format", "{{.ServerVersion}}"],
                             capture_output=True, text=True, timeout=8)
        if out.returncode == 0 and out.stdout.strip():
            return {"ok": True, "version": out.stdout.strip()}
        return {"ok": False, "error": (out.stderr or out.stdout).strip()[:300]}
    except FileNotFoundError:
        return {"ok": False, "error": "docker CLI bulunamadı"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "docker info zaman aşımına uğradı"}


_docker_cache: dict[str, Any] = {"t": 0.0, "v": None}
_version_cache: dict[tuple[str, float], dict[str, Any]] = {}


def docker_status_cached(max_age: float = 10.0) -> dict[str, Any]:
    if _docker_cache["v"] is None or time.time() - _docker_cache["t"] > max_age:
        _docker_cache.update(t=time.time(), v=docker_status())
    return _docker_cache["v"]


def strix_version(bin_path: str) -> dict[str, Any]:
    """`strix --version` takes seconds (PyInstaller unpack), so cache per binary mtime."""
    try:
        key = (bin_path, Path(bin_path).expanduser().stat().st_mtime)
    except OSError:
        return {"ok": False, "version": "", "error": f"Strix bulunamadı: {bin_path}"}
    if key not in _version_cache:
        try:
            out = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=30)
            _version_cache[key] = {"ok": out.returncode == 0, "version": (out.stdout or out.stderr).strip()}
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "version": "", "error": str(e)}
    return _version_cache[key]


# ---------------------------------------------------------------- enqueue
def active_scan_for_target(target_id: int) -> dict[str, Any] | None:
    for s in db.list_scans(status=",".join(ACTIVE), target_id=target_id, limit=5):
        return s
    return None


def enqueue(target: dict[str, Any], opts: dict[str, Any], trigger: str,
            schedule_id: int | None = None, resume_run: str = "") -> int:
    """Create a queued scan. Raises Busy if this target already has a queued/running scan."""
    profile = llm.get(opts.get("llm_profile_id"))
    if not profile:
        raise ValueError("LLM bağlantı profili seçilmedi veya silinmiş.")
    with _lock:  # check-and-insert atomically so two clicks cannot start two scans
        active = active_scan_for_target(target["id"])
        if active:
            raise Busy(f"Bu hedefte zaten aktif bir tarama var (#{active['id']}, {active['status']}).")
        sid = db.insert("scans", {
            "target_id": target["id"], "schedule_id": schedule_id, "name": target["name"],
            "environment": target["environment"], "targets": targets.strix_targets(target),
            "instruction": (opts.get("instruction") or "").strip(),
            "scan_mode": opts.get("scan_mode") or target.get("default_scan_mode") or "standard",
            "max_budget": opts.get("max_budget"), "max_turns": opts.get("max_turns"),
            "fail_on": opts.get("fail_on") or "",
            "llm_profile_id": profile["id"], "llm_profile_name": profile["name"],
            "llm_provider": profile["provider"], "model": llm.strix_model(profile),
            "resume_run": resume_run, "trigger": trigger, "status": "queued",
        })
    _wake.set()
    return sid


# ---------------------------------------------------------------- worker
def start_worker() -> None:
    threading.Thread(target=_worker, daemon=True, name="skynet-queue").start()
    _wake.set()


def _worker() -> None:
    while True:
        _wake.wait(timeout=3)
        _wake.clear()
        try:
            settings = db.get_settings()
            limit = max(1, int(settings.get("max_concurrent") or 1))
            running = db.list_scans(status="running,stopping")
            queued = sorted(db.list_scans(status="queued", limit=1000), key=lambda s: s["id"])
            for scan in queued[:max(0, limit - len(running))]:
                _start(scan, settings)
        except Exception:  # the worker must never die
            log.exception("queue tick failed")


def _fail(sid: int, msg: str) -> None:
    db.update("scans", sid, {"status": "failed", "error": msg, "finished_at": db.now_iso()})
    notify(sid)


def _child_env(profile_env: dict[str, str], settings: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in llm.LLM_ENV_DENYLIST}
    env.update(profile_env)
    env.update({"STRIX_TELEMETRY": "1" if settings.get("telemetry") == "1" else "0",
                "TERM": "dumb", "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"})
    return env


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def _start(scan: dict[str, Any], settings: dict[str, str]) -> None:
    sid = scan["id"]
    bin_path = str(Path(settings.get("strix_bin") or "").expanduser())
    if not Path(bin_path).is_file():
        return _fail(sid, f"Strix binary bulunamadı: {bin_path}")
    target = db.get("targets", scan["target_id"]) if scan.get("target_id") else None
    if not target:
        return _fail(sid, "Hedef kaydı silinmiş.")
    profile = llm.get(scan.get("llm_profile_id"))
    if not profile:  # never fall back to another provider
        return _fail(sid, "Taramanın LLM profili silinmiş. Başka sağlayıcıya otomatik geçilmez; yeni tarama başlatın.")
    dock = docker_status()
    _docker_cache.update(t=time.time(), v=dock)
    if not dock["ok"]:
        return _fail(sid, "Docker çalışmıyor; Strix sandbox başlatılamaz. " + dock.get("error", ""))

    workdir = Path(settings["strix_workdir"]).expanduser()
    runs.runs_root(str(workdir)).mkdir(parents=True, exist_ok=True)
    profile_env = llm.strix_env(profile)
    child_env = _child_env(profile_env, settings)
    cfg_path = RUNTIME_DIR / f"scan_{sid}.json"
    _write_private(cfg_path, json.dumps({"env": {k: child_env[k] for k in (*profile_env, "STRIX_TELEMETRY")}}))

    cmd = [bin_path, "--non-interactive", f"--config={cfg_path}"]
    if scan.get("resume_run"):
        cmd.append(f"--resume={scan['resume_run']}")
    else:
        instr_path = RUNTIME_DIR / f"scan_{sid}_instruction.md"
        _write_private(instr_path, targets.instruction_text(target, scan.get("instruction") or ""))
        cmd += [f"--target={t}" for t in scan["targets"]]
        cmd.append(f"--instruction-file={instr_path}")
    if scan.get("scan_mode"):
        cmd.append(f"--scan-mode={scan['scan_mode']}")
    if scan.get("max_budget"):
        cmd.append(f"--max-budget={float(scan['max_budget'])}")
    if scan.get("max_turns"):
        cmd.append(f"--max-turns={int(scan['max_turns'])}")
    if scan.get("fail_on"):
        cmd.append(f"--fail-on={scan['fail_on']}")

    log_path = LOG_DIR / f"scan_{sid}.log"
    before = {p.name for p in runs.list_run_dirs(str(workdir))}
    with log_path.open("ab") as lf:
        # The command line contains only file paths, never secrets.
        lf.write(f"[skynet] {datetime.now().isoformat(timespec='seconds')} {' '.join(cmd)}\n".encode())
        lf.flush()
        try:
            proc = subprocess.Popen(cmd, cwd=workdir, env=child_env, stdout=lf, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
        except OSError as e:
            return _fail(sid, f"Strix başlatılamadı: {e}")
    resume = scan.get("resume_run") or None
    db.update("scans", sid, {"status": "running", "pid": proc.pid, "started_at": db.now_iso(), "error": None,
                             "run_name": resume,
                             "run_dir": str(runs.runs_root(str(workdir)) / resume) if resume else None})
    with _lock:
        _procs[sid] = proc
    threading.Thread(target=_monitor, args=(sid, proc, None, workdir, before), daemon=True).start()


# ---------------------------------------------------------------- monitoring
def _detect_run_dir(sid: int, workdir: Path, before: set[str]) -> Path | None:
    root = runs.runs_root(str(workdir))
    text, _ = runs.tail(LOG_DIR / f"scan_{sid}.log", 0, 400_000)
    m = RUN_DIR_RE.search(text)
    if m and Path(m.group(1)).is_dir():
        return Path(m.group(1))
    m = OUTPUT_RE.search(text)
    if m and (root / m.group(1)).is_dir():
        return root / m.group(1)
    claimed = db.claimed_run_names()
    new = [p for p in runs.list_run_dirs(str(workdir)) if p.name not in before and p.name not in claimed]
    if len(new) == 1:
        return new[0]
    if new:
        want = set((db.get("scans", sid) or {}).get("targets") or [])
        for p in new:
            if set(runs.run_meta(p)["targets"]) == want:
                return p
    return None


def _monitor(sid: int, proc: subprocess.Popen | None, pid: int | None, workdir: Path, before: set[str]) -> None:
    scan = db.get("scans", sid) or {}
    run_dir = Path(scan["run_dir"]) if scan.get("run_dir") else None
    last = 0.0
    code: int | None = None
    while True:
        alive = proc.poll() is None if proc else _pid_alive(pid or 0)
        if run_dir is None:
            run_dir = _detect_run_dir(sid, workdir, before)
            if run_dir:
                db.update("scans", sid, {"run_name": run_dir.name, "run_dir": str(run_dir)})
        if run_dir and time.time() - last > 10:
            last = time.time()
            ids = runs.sandbox_containers(run_dir)
            db.update("scans", sid, {"summary": runs.summarize(run_dir, scan.get("fail_on")),
                                     "sandbox_container": ",".join(ids) or None})
        if not alive:
            code = proc.returncode if proc else None
            break
        time.sleep(2)
    if run_dir is None:
        run_dir = _detect_run_dir(sid, workdir, before)
    finalize(sid, code, run_dir)


def _cleanup_containers(run_dir: Path | None, scan: dict[str, Any]) -> list[str]:
    """Remove sandbox containers this run created that are still alive (e.g. after SIGKILL)."""
    ids = set(runs.sandbox_containers(run_dir) if run_dir else [])
    ids |= set(filter(None, (scan.get("sandbox_container") or "").split(",")))
    removed = []
    for cid in ids:
        try:
            r = subprocess.run([_docker(), "ps", "-q", "--no-trunc", "--filter", f"id={cid}"],
                               capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                subprocess.run([_docker(), "rm", "-f", cid], capture_output=True, timeout=30)
                removed.append(cid)
        except (OSError, subprocess.TimeoutExpired):
            log.warning("could not clean up container %s", cid)
    return removed


_BOX = re.compile(r"[\u2500-\u257f]+")


def _error_summary(sid: int) -> str:
    """Strip Strix's box-drawing frame and return the block around the first error line."""
    text, _ = runs.tail(LOG_DIR / f"scan_{sid}.log", -1, 30_000)
    lines = []
    for ln in text.splitlines():
        if ln.startswith("[skynet]"):
            continue
        ln = re.sub(r"\s+", " ", _BOX.sub(" ", ln)).strip()
        if ln and ln != "STRIX":
            lines.append(ln)
    idx = next((i for i, ln in enumerate(lines) if re.search(r"FAILED|Error|ERROR|Traceback|error:", ln)), max(0, len(lines) - 12))
    return "\n".join(lines[idx:idx + 14])[:1500] or "Strix çıktı üretmedi."


def finalize(sid: int, code: int | None, run_dir: Path | None) -> None:
    scan = db.get("scans", sid) or {}
    with _lock:
        _procs.pop(sid, None)
        cancelled = sid in _cancel_requested
        _cancel_requested.discard(sid)
    summary = runs.summarize(run_dir, scan.get("fail_on")) if run_dir else None
    removed = _cleanup_containers(run_dir, scan)
    if cancelled:
        status, err = "cancelled", None
    elif code in (0, 2):  # documented: 0 = no findings (>= fail-on), 2 = findings
        status, err = "completed", None
    elif code is None:    # process outlived a GUI restart; result comes from run.json
        ok = (summary or {}).get("run_status") == "completed"
        status = "completed" if ok else "interrupted"
        err = None if ok else "Strix süreci GUI yeniden başlatılırken sonlandı; tarama otomatik yeniden başlatılmadı."
    else:
        status = "failed"
        err = f"Strix çıkış kodu {code}.\n{_error_summary(sid)}"
    if removed:
        err = (err + "\n" if err else "") + f"Artık kalan sandbox konteyneri temizlendi: {', '.join(c[:12] for c in removed)}"
    model = (runs.log_model(run_dir) if run_dir else None) or scan.get("model")
    db.update("scans", sid, {"status": status, "exit_code": code, "finished_at": db.now_iso(), "pid": None,
                             "summary": summary, "error": err, "model": model,
                             "run_name": run_dir.name if run_dir else scan.get("run_name"),
                             "run_dir": str(run_dir) if run_dir else scan.get("run_dir")})
    for f in RUNTIME_DIR.glob(f"scan_{sid}*"):
        f.unlink(missing_ok=True)
    notify(sid)
    _wake.set()


# ---------------------------------------------------------------- cancel
def cancel(sid: int) -> bool:
    scan = db.get("scans", sid)
    if not scan:
        return False
    if scan["status"] == "queued":
        db.update("scans", sid, {"status": "cancelled", "finished_at": db.now_iso()})
        return True
    pid = scan.get("pid")
    if scan["status"] not in ("running", "stopping") or not pid:
        return False
    with _lock:
        _cancel_requested.add(sid)
    db.update("scans", sid, {"status": "stopping"})

    def alive() -> bool:
        with _lock:
            proc = _procs.get(sid)
        return proc.poll() is None if proc is not None else _pid_alive(pid)

    def escalate() -> None:
        # SIGINT lets Strix write its report and tear down the sandbox; then TERM, then KILL the group.
        for sig, wait in ((signal.SIGINT, 45), (signal.SIGTERM, 20), (signal.SIGKILL, 0)):
            try:
                os.killpg(pid, sig)
            except (ProcessLookupError, PermissionError):
                return
            for _ in range(wait):
                if not alive():
                    return
                time.sleep(1)

    threading.Thread(target=escalate, daemon=True).start()
    return True


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# ---------------------------------------------------------------- startup
def recover() -> None:
    """After a GUI restart: re-attach to Strix processes that are still alive (they run in their own
    session, so they survive); mark dead ones 'interrupted'. Nothing is restarted automatically."""
    workdir = Path(db.get_settings()["strix_workdir"]).expanduser()
    for scan in db.list_scans(status="running,stopping"):
        pid = scan.get("pid")
        if pid and _pid_alive(pid):
            log.info("re-attaching scan %s (pid %s)", scan["id"], pid)
            if scan["status"] == "stopping":
                with _lock:
                    _cancel_requested.add(scan["id"])
            before = {p.name for p in runs.list_run_dirs(str(workdir))}
            threading.Thread(target=_monitor, args=(scan["id"], None, pid, workdir, before), daemon=True).start()
        else:
            finalize(scan["id"], None, Path(scan["run_dir"]) if scan.get("run_dir") else None)


def import_existing_runs() -> int:
    """Register run directories created outside the GUI (e.g. the TUI) as read-only history."""
    settings = db.get_settings()
    claimed = db.claimed_run_names()
    by_url = {t["base_url"].rstrip("/"): t for t in db.q("SELECT * FROM targets")}
    n = 0
    for p in runs.list_run_dirs(settings["strix_workdir"]):
        if p.name in claimed or not (p / "run.json").exists():
            continue
        meta = runs.run_meta(p)
        tgt = next((by_url[u.rstrip("/")] for u in meta["targets"] if u.rstrip("/") in by_url), None)
        db.insert("scans", {
            "target_id": tgt["id"] if tgt else None, "name": tgt["name"] if tgt else (meta["targets"] or [p.name])[0],
            "environment": tgt["environment"] if tgt else None, "targets": meta["targets"],
            "instruction": "", "scan_mode": meta["scan_mode"], "trigger": "cli",
            "status": "completed" if meta["status"] == "completed" else "interrupted",
            "model": runs.log_model(p), "run_name": p.name, "run_dir": str(p),
            "created_at": meta["start_time"] or db.now_iso(), "started_at": meta["start_time"],
            "finished_at": meta["end_time"], "summary": runs.summarize(p),
        })
        n += 1
    return n


# ---------------------------------------------------------------- notifications
SEV_TR = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"}


def notify(sid: int) -> None:
    url = (db.get_settings().get("webhook_url") or "").strip()
    scan = db.get_scan(sid)
    if not url or not scan:
        return
    summ = scan.get("summary") or {}
    counts = summ.get("counts") or {}
    sev = ", ".join(f"{SEV_TR[k]}: {counts[k]}" for k in SEV_TR if counts.get(k))
    gate = summ.get("gate") if scan["status"] == "completed" else None
    text = (f"Skynet: Strix taraması #{sid} {scan.get('target_name') or scan.get('name')} ({scan.get('environment') or '-'})"
            f" -> {scan['status']}" + (f" | gate: {gate}" if gate else "") + (f" | {sev}" if sev else ""))
    body = json.dumps({"text": text, "scan_id": sid, "status": scan["status"], "target": scan.get("target_name"),
                       "environment": scan.get("environment"), "counts": counts, "gate": gate}).encode()
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:  # noqa: BLE001 - best effort
        log.warning("webhook failed: %s", type(e).__name__)
