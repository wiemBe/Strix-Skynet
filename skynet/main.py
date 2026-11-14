"""FastAPI app: REST API + static UI for managing Strix scans."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from markdown_it import MarkdownIt

from . import auth, crypto, db, llm, runner, runs, scheduler, targets
from .config import COOKIE_SECURE, LOG_DIR, SESSION_HOURS, STATIC_DIR, TIMEZONE, USER_STRIX_CONFIG


class _RedactAccessLog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # never log query strings
        if record.args and isinstance(record.args, tuple) and len(record.args) >= 3:
            a = list(record.args)
            a[2] = str(a[2]).split("?", 1)[0]
            record.args = tuple(a)
        return True


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("uvicorn.access").addFilter(_RedactAccessLog())
log = logging.getLogger("skynet")

# Raw HTML disabled: reports are LLM output that may quote target responses.
md = MarkdownIt("commonmark", {"html": False}).enable("table").enable("strikethrough")
SCAN_MODES = ("quick", "standard", "deep")
SEVERITIES = runs.SEVERITIES


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    auth.bootstrap()
    if USER_STRIX_CONFIG.exists():
        try:
            llm.migrate_from_strix_cli_config(json.loads(USER_STRIX_CONFIG.read_text()))
        except (OSError, ValueError):
            pass
    n = runner.import_existing_runs()
    if n:
        log.info("imported %d existing Strix runs", n)
    runner.recover()
    import threading  # warm the slow `strix --version` cache so the first page load is fast
    threading.Thread(target=runner.strix_version, args=(db.get_settings()["strix_bin"],), daemon=True).start()
    runner.start_worker()
    scheduler.start()
    yield


app = FastAPI(title="Skynet", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

PUBLIC = {"/login", "/api/login", "/static/style.css", "/static/login.js", "/static/favicon.png", "/static/apple-touch-icon.png"}


@app.middleware("http")
async def security(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/ci/"):
        if not auth.valid_api_token(request.headers.get("x-api-token", "")):
            return JSONResponse({"detail": "Geçersiz API token"}, status_code=401)
    elif path not in PUBLIC:
        if not auth.valid_session(request.cookies.get(auth.COOKIE)):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Oturum gerekli"}, status_code=401)
            return RedirectResponse("/login", status_code=302)
        # CSRF: state-changing API calls must come from our own JS (custom header + SameSite=Strict cookie).
        if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "skynet":
            return JSONResponse({"detail": "CSRF koruması: geçersiz istek"}, status_code=403)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                               "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store" if path.startswith("/api/") else "no-cache"
    return resp


# ---------------------------------------------------------------- helpers
def bad(msg: str, code: int = 400):
    raise HTTPException(code, msg)


def _num(body: dict[str, Any], k: str, typ):
    v = body.get(k)
    if v in (None, ""):
        return None
    try:
        v = typ(v)
    except (TypeError, ValueError):
        bad(f"Geçersiz sayı: {k}")
    if v <= 0:
        bad(f"{k} sıfırdan büyük olmalı")
    return v


def _lines(v: Any) -> list[str]:
    if isinstance(v, str):
        v = v.splitlines()
    return [str(s).strip() for s in v or [] if str(s).strip() and not str(s).strip().startswith("#")]


def _scan_opts(body: dict[str, Any], target: dict[str, Any] | None = None) -> dict[str, Any]:
    mode = body.get("scan_mode") or (target or {}).get("default_scan_mode") or db.get_settings()["default_scan_mode"]
    if mode not in SCAN_MODES:
        bad("Geçersiz tarama modu")
    fail_on = body.get("fail_on") or ""
    if fail_on and fail_on not in SEVERITIES:
        bad("Geçersiz gate seviyesi")
    pid = body.get("llm_profile_id") or (target or {}).get("llm_profile_id") or (llm.default_profile() or {}).get("id")
    if not pid or not llm.get(int(pid)):
        bad("LLM bağlantı profili seçin (Ayarlar > LLM bağlantıları).")
    return {"scan_mode": mode, "fail_on": fail_on, "llm_profile_id": int(pid),
            "max_budget": _num(body, "max_budget", float), "max_turns": _num(body, "max_turns", int),
            "instruction": (body.get("instruction") or "").strip()}


def _scan_out(s: dict[str, Any] | None) -> dict[str, Any] | None:
    if not s:
        return None
    s = dict(s)
    s.pop("pid", None)
    return s


def _scan_or_404(sid: int) -> dict[str, Any]:
    return db.get_scan(sid) or bad("Tarama bulunamadı", 404)


def _target_or_404(tid: int) -> dict[str, Any]:
    return db.get("targets", tid) or bad("Hedef bulunamadı", 404)


def _run_dir(scan: dict[str, Any]) -> Path | None:
    p = Path(scan["run_dir"]) if scan.get("run_dir") else None
    return p if p and p.is_dir() else None


# ---------------------------------------------------------------- auth
@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.post("/api/login")
def login(request: Request, body: dict[str, Any] = Body(...)) -> Response:
    ip = request.client.host if request.client else "?"
    if auth.throttled(ip):
        bad("Çok fazla başarısız deneme. 5 dakika sonra tekrar deneyin.", 429)
    if not auth.check_credentials(str(body.get("username", "")), str(body.get("password", ""))):
        auth.record_failure(ip)
        bad("Kullanıcı adı veya şifre hatalı.", 401)
    auth.clear_failures(ip)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(auth.COOKIE, auth.make_session(), max_age=SESSION_HOURS * 3600, httponly=True,
                    samesite="strict", secure=COOKIE_SECURE, path="/")
    return resp


@app.post("/api/logout")
def logout() -> Response:
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.post("/api/settings/password")
def change_password(body: dict[str, Any] = Body(...)) -> dict[str, bool]:
    try:
        auth.change_password(str(body.get("current", "")), str(body.get("new", "")))
    except ValueError as e:
        bad(str(e))
    return {"ok": True}


# ---------------------------------------------------------------- overview
@app.get("/api/overview")
def overview() -> dict[str, Any]:
    st = db.get_settings()
    dp = llm.default_profile()
    active = [_scan_out(s) for s in db.list_scans(status=",".join(runner.ACTIVE), limit=50)]
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    problems = [_scan_out(s) for s in db.list_scans(status="failed,interrupted", limit=50)
                if (s.get("finished_at") or s.get("created_at") or "") >= since and s["trigger"] != "cli"][:8]
    sched_problems = db.q(
        "SELECT s.*, t.name AS target_name, e.at AS event_at FROM schedules s JOIN targets t ON t.id=s.target_id "
        "JOIN schedule_events e ON e.id = (SELECT MAX(id) FROM schedule_events WHERE schedule_id=s.id) "
        "WHERE e.outcome IN ('missed','skipped_busy','error') AND e.at >= ? ORDER BY e.at DESC LIMIT 8", (since,))
    upcoming = db.q("SELECT s.*, t.name AS target_name, t.environment FROM schedules s JOIN targets t ON t.id=s.target_id "
                    "WHERE s.enabled=1 AND s.next_run_at IS NOT NULL ORDER BY s.next_run_at LIMIT 8")
    for u in upcoming:
        u["describe"] = scheduler.describe(u)
    latest = []
    for t in db.q("SELECT * FROM targets ORDER BY name COLLATE NOCASE"):
        last = db.list_scans(status="completed", target_id=t["id"], limit=1)
        latest.append({"target_id": t["id"], "name": t["name"], "environment": t["environment"],
                       "scan": _scan_out(last[0]) if last else None})
    return {
        "docker": runner.docker_status_cached(),
        "strix": runner.strix_version(st["strix_bin"]),
        "llm_default": llm.public(dp) if dp else None,
        "telemetry": st.get("telemetry") == "1",
        "max_concurrent": int(st.get("max_concurrent") or 1),
        "active": active, "problems": problems, "schedule_problems": sched_problems,
        "upcoming": upcoming, "latest_by_target": latest, "timezone": TIMEZONE,
    }


# ---------------------------------------------------------------- LLM profiles
def _llm_payload(body: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    name = (body.get("name") or "").strip() or bad("Profil adı zorunlu")
    provider = body.get("provider")
    if provider not in llm.PROVIDERS:
        bad("Sağlayıcı OpenRouter veya LiteLLM olmalı")
    model = (body.get("model") or "").strip() or bad("Model zorunlu")
    base = (body.get("base_url") or "").strip()
    if provider == "litellm" and not base:
        bad("LiteLLM için base URL zorunlu (örn. http://litellm.internal:4000)")
    if base and urlparse(base).scheme not in ("http", "https"):
        bad("Base URL http(s) ile başlamalı")
    if body.get("api_type", "") not in llm.API_TYPES or body.get("reasoning_effort", "") not in llm.EFFORTS:
        bad("Geçersiz API tipi veya reasoning effort")
    ca = (body.get("ca_cert_path") or "").strip()
    if ca and not Path(ca).expanduser().is_file():
        bad(f"CA sertifika dosyası bulunamadı: {ca}")
    out = {"name": name, "provider": provider, "model": model, "base_url": base, "api_type": body.get("api_type", ""),
           "reasoning_effort": body.get("reasoning_effort", ""), "ca_cert_path": ca}
    key = body.get("api_key")
    if key:  # empty = keep the stored key
        out["api_key_enc"] = crypto.encrypt(str(key).strip())
    elif body.get("clear_api_key"):
        out["api_key_enc"] = ""
    elif not existing and provider == "openrouter":
        bad("OpenRouter için API anahtarı zorunlu")
    return out


@app.get("/api/llm-profiles")
def llm_list() -> list[dict[str, Any]]:
    out = []
    for p in llm.list_profiles():
        d = llm.public(p)
        d["used_by_schedules"] = db.q1("SELECT COUNT(*) AS n FROM schedules WHERE llm_profile_id=?", (p["id"],))["n"]
        out.append(d)
    return out


@app.post("/api/llm-profiles")
def llm_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    data = _llm_payload(body)
    if db.q1("SELECT id FROM llm_profiles WHERE name=?", (data["name"],)):
        bad("Bu isimde bir profil var")
    pid = db.insert("llm_profiles", data)
    if body.get("is_default") or not llm.default_profile():
        llm.set_default(pid)
    return llm.public(llm.get(pid))  # type: ignore[arg-type]


@app.put("/api/llm-profiles/{pid}")
def llm_update(pid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    existing = llm.get(pid) or bad("Profil bulunamadı", 404)
    data = _llm_payload(body, existing)
    if db.q1("SELECT id FROM llm_profiles WHERE name=? AND id<>?", (data["name"], pid)):
        bad("Bu isimde bir profil var")
    db.update("llm_profiles", pid, data)
    if body.get("is_default"):
        llm.set_default(pid)
    return llm.public(llm.get(pid))  # type: ignore[arg-type]


@app.post("/api/llm-profiles/{pid}/default")
def llm_default(pid: int) -> dict[str, bool]:
    llm.get(pid) or bad("Profil bulunamadı", 404)
    llm.set_default(pid)
    return {"ok": True}


@app.delete("/api/llm-profiles/{pid}")
def llm_delete(pid: int) -> dict[str, bool]:
    p = llm.get(pid) or bad("Profil bulunamadı", 404)
    if db.q1("SELECT id FROM schedules WHERE llm_profile_id=? LIMIT 1", (pid,)):
        bad("Bu profil zamanlamalarda kullanılıyor; önce o planlarda başka profil seçin.")
    if any(s["llm_profile_id"] == pid for s in db.list_scans(status=",".join(runner.ACTIVE), limit=500)):
        bad("Bu profille aktif tarama var")
    db.execute("UPDATE targets SET llm_profile_id=NULL WHERE llm_profile_id=?", (pid,))
    db.delete("llm_profiles", pid)
    if p["is_default"] and (rest := llm.list_profiles()):
        llm.set_default(rest[0]["id"])
    return {"ok": True}


@app.post("/api/llm-profiles/test")
def llm_test(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Test a (possibly unsaved) profile form. Uses the stored key when the form leaves it empty."""
    stored = llm.get(int(body["id"])) if body.get("id") else None
    p = {"provider": body.get("provider"), "base_url": body.get("base_url", ""), "model": body.get("model", ""),
         "ca_cert_path": body.get("ca_cert_path", "")}
    if p["provider"] not in llm.PROVIDERS:
        bad("Sağlayıcı seçin")
    key = body.get("api_key") or (crypto.decrypt(stored.get("api_key_enc")) if stored else "")
    return llm.test(p, key_override=key)


# ---------------------------------------------------------------- targets
def _target_payload(body: dict[str, Any]) -> dict[str, Any]:
    name = (body.get("name") or "").strip() or bad("Hedef adı zorunlu")
    env = body.get("environment")
    if env not in targets.ENVIRONMENTS:
        bad("Ortam development, test, staging veya production olmalı")
    base = (body.get("base_url") or "").strip() or bad("Hedef adresi zorunlu")
    extra = _lines(body.get("extra_targets"))
    for t in [base, *extra]:
        if t.startswith("-"):
            bad(f"Geçersiz hedef: {t}")
    auth_type = body.get("auth_type") or "none"
    if auth_type not in targets.AUTH_TYPES:
        bad("Geçersiz kimlik doğrulama türü")
    mode = body.get("default_scan_mode") or "standard"
    if mode not in SCAN_MODES:
        bad("Geçersiz tarama modu")
    lp = body.get("llm_profile_id") or None
    if lp and not llm.get(int(lp)):
        bad("LLM profili bulunamadı")
    out = {"name": name, "application": (body.get("application") or "").strip(), "environment": env,
           "base_url": base, "extra_targets": extra, "in_scope": _lines(body.get("in_scope")),
           "out_of_scope": _lines(body.get("out_of_scope")), "instruction": (body.get("instruction") or "").strip(),
           "auth_type": auth_type, "auth_login_url": (body.get("auth_login_url") or "").strip(),
           "auth_username": (body.get("auth_username") or "").strip(),
           "auth_header_name": (body.get("auth_header_name") or "").strip(),
           "auth_notes": (body.get("auth_notes") or "").strip(), "default_scan_mode": mode,
           "llm_profile_id": int(lp) if lp else None}
    if body.get("auth_secret"):
        out["auth_secret_enc"] = crypto.encrypt(str(body["auth_secret"]))
    if auth_type == "none":
        out["auth_secret_enc"] = ""
    return out


def _target_out(t: dict[str, Any], detail: bool = False) -> dict[str, Any]:
    d = {k: v for k, v in t.items() if k != "auth_secret_enc"}
    d["has_auth_secret"] = bool(t.get("auth_secret_enc"))
    last = db.list_scans(target_id=t["id"], limit=1)
    d["last_scan"] = _scan_out(last[0]) if last else None
    d["active_scan"] = _scan_out(runner.active_scan_for_target(t["id"]))
    nxt = db.q1("SELECT MIN(next_run_at) AS n, COUNT(*) AS c FROM schedules WHERE target_id=? AND enabled=1", (t["id"],))
    d["next_run_at"], d["active_schedules"] = nxt["n"], nxt["c"]
    if detail:
        d["instruction_preview"] = targets.instruction_text(t, with_secrets=False)
        d["strix_targets"] = targets.strix_targets(t)
    return d


@app.get("/api/targets")
def target_list() -> list[dict[str, Any]]:
    return [_target_out(t) for t in db.q("SELECT * FROM targets ORDER BY name COLLATE NOCASE")]


@app.get("/api/targets/{tid}")
def target_get(tid: int) -> dict[str, Any]:
    return _target_out(_target_or_404(tid), detail=True)


@app.post("/api/targets")
def target_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    return target_get(db.insert("targets", _target_payload(body)))


@app.put("/api/targets/{tid}")
def target_update(tid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    _target_or_404(tid)
    db.update("targets", tid, _target_payload(body))
    return target_get(tid)


@app.delete("/api/targets/{tid}")
def target_delete(tid: int) -> dict[str, bool]:
    _target_or_404(tid)
    if runner.active_scan_for_target(tid):
        bad("Hedefte aktif tarama var; önce iptal edin.")
    db.execute("DELETE FROM schedule_events WHERE schedule_id IN (SELECT id FROM schedules WHERE target_id=?)", (tid,))
    db.execute("DELETE FROM schedules WHERE target_id=?", (tid,))
    db.delete("targets", tid)  # scan history is kept and still shows the target name
    scheduler.sync()
    return {"ok": True}


@app.post("/api/targets/{tid}/scan")
def target_scan(tid: int, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    t = _target_or_404(tid)
    opts = _scan_opts(body, t)
    try:
        sid = runner.enqueue(t, opts, "manual")
    except runner.Busy as e:
        bad(str(e), 409)
    except ValueError as e:
        bad(str(e))
    return _scan_out(db.get_scan(sid))  # type: ignore[return-value]


# ---------------------------------------------------------------- schedules
def _schedule_payload(body: dict[str, Any]) -> dict[str, Any]:
    t = _target_or_404(int(body.get("target_id") or 0))
    kind = body.get("kind")
    if kind not in scheduler.KINDS:
        bad("Plan türü seçin")
    opts = _scan_opts(body, t)
    data = {"target_id": t["id"], "name": (body.get("name") or "").strip(), "kind": kind,
            "run_at": (body.get("run_at") or "").strip(), "time_of_day": (body.get("time_of_day") or "").strip(),
            "weekdays": [d for d in body.get("weekdays") or [] if d in scheduler.WEEKDAYS],
            "interval_hours": _num(body, "interval_hours", int), "cron_expr": (body.get("cron_expr") or "").strip(),
            "timezone": (body.get("timezone") or TIMEZONE).strip(), "enabled": 1 if body.get("enabled", True) else 0,
            **{k: opts[k] for k in ("scan_mode", "fail_on", "llm_profile_id", "max_budget", "max_turns")}}
    _anchor_interval(data)
    err = scheduler.validate(data)
    if err:
        bad(f"Geçersiz plan: {err}")
    return data


def _anchor_interval(data: dict[str, Any]) -> None:
    """Persist the first run of an interval plan so it does not drift on every restart."""
    if data.get("kind") == "interval" and not data.get("run_at"):
        from zoneinfo import ZoneInfo
        data["run_at"] = (datetime.now(ZoneInfo(data["timezone"])) + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M")


def _schedule_out(s: dict[str, Any]) -> dict[str, Any]:
    s = dict(s)
    s["describe"] = scheduler.describe(s)
    p = llm.get(s.get("llm_profile_id"))
    s["llm_profile_name"] = p["name"] if p else None
    s["llm_provider"] = p["provider"] if p else None
    s["last_scan"] = _scan_out(db.get_scan(s["last_scan_id"])) if s.get("last_scan_id") else None
    return s


SCHED_SELECT = ("SELECT s.*, t.name AS target_name, t.environment FROM schedules s "
                "JOIN targets t ON t.id = s.target_id")


@app.get("/api/schedules")
def schedule_list(target_id: int | None = None) -> list[dict[str, Any]]:
    if target_id:
        rows = db.q(SCHED_SELECT + " WHERE s.target_id=? ORDER BY s.enabled DESC, s.next_run_at", (target_id,))
    else:
        rows = db.q(SCHED_SELECT + " ORDER BY s.enabled DESC, s.next_run_at IS NULL, s.next_run_at")
    return [_schedule_out(s) for s in rows]


@app.get("/api/schedules/{sid}")
def schedule_get(sid: int) -> dict[str, Any]:
    s = db.q1(SCHED_SELECT + " WHERE s.id=?", (sid,)) or bad("Plan bulunamadı", 404)
    out = _schedule_out(s)
    out["events"] = db.q("SELECT * FROM schedule_events WHERE schedule_id=? ORDER BY id DESC LIMIT 50", (sid,))
    return out


@app.post("/api/schedules")
def schedule_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    sid = db.insert("schedules", _schedule_payload(body))
    scheduler.sync()
    return schedule_get(sid)


@app.put("/api/schedules/{sid}")
def schedule_update(sid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    db.get("schedules", sid) or bad("Plan bulunamadı", 404)
    db.update("schedules", sid, _schedule_payload(body))
    scheduler.sync()
    return schedule_get(sid)


@app.post("/api/schedules/{sid}/pause")
def schedule_pause(sid: int) -> dict[str, Any]:
    db.get("schedules", sid) or bad("Plan bulunamadı", 404)
    db.update("schedules", sid, {"enabled": 0})
    scheduler.sync()
    return schedule_get(sid)


@app.post("/api/schedules/{sid}/resume")
def schedule_resume(sid: int) -> dict[str, Any]:
    s = db.get("schedules", sid) or bad("Plan bulunamadı", 404)
    err = scheduler.validate(s)
    if err:
        bad(f"Plan etkinleştirilemez: {err}. Planı düzenleyin.")
    db.update("schedules", sid, {"enabled": 1})
    scheduler.sync()
    return schedule_get(sid)


@app.delete("/api/schedules/{sid}")
def schedule_delete(sid: int) -> dict[str, bool]:
    db.execute("DELETE FROM schedule_events WHERE schedule_id=?", (sid,))
    db.delete("schedules", sid)
    scheduler.sync()
    return {"ok": True}


@app.post("/api/schedules/preview")
def schedule_preview(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    data = {**body, "timezone": body.get("timezone") or TIMEZONE}
    _anchor_interval(data)
    err = scheduler.validate(data)
    return {"ok": False, "error": err, "next": []} if err else {"ok": True, "next": scheduler.preview(data)}


# ---------------------------------------------------------------- scans
@app.get("/api/scans")
def scan_list(status: str | None = None, target_id: int | None = None, schedule_id: int | None = None,
              limit: int = 300) -> list[dict[str, Any]]:
    return [_scan_out(s) for s in db.list_scans(status, target_id, schedule_id, min(limit, 2000))]  # type: ignore[misc]


@app.get("/api/scans/{sid}")
def scan_get(sid: int) -> dict[str, Any]:
    s = _scan_or_404(sid)
    out = _scan_out(s) or {}
    rd = _run_dir(s)
    out["files"] = {k: bool(rd and (rd / f).exists()) for k, f in runs.DOWNLOADABLE.items()}
    if rd:
        meta = runs.run_meta(rd)
        out["run_meta"] = {k: meta[k] for k in ("status", "start_time", "end_time", "tokens", "requests", "cost")}
        out["executive_summary_html"] = md.render(meta["executive_summary"]) if meta.get("executive_summary") else ""
        if s["status"] in runner.ACTIVE:
            out["summary"] = runs.summarize(rd, s.get("fail_on"))
    return out


@app.post("/api/scans/{sid}/cancel")
def scan_cancel(sid: int) -> dict[str, Any]:
    _scan_or_404(sid)
    if not runner.cancel(sid):
        bad("Bu tarama iptal edilemez")
    return _scan_out(db.get_scan(sid))  # type: ignore[return-value]


@app.post("/api/scans/{sid}/resume")
def scan_resume(sid: int, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    s = _scan_or_404(sid)
    if s["status"] not in ("cancelled", "failed", "interrupted") or not s.get("run_name"):
        bad("Yalnızca iptal edilmiş, başarısız veya yarıda kalmış ve çıktı klasörü olan taramalar devam ettirilebilir.")
    t = db.get("targets", s["target_id"]) if s.get("target_id") else None
    if not t:
        bad("Devam ettirmek için tarama bir hedefe bağlı olmalı.")
    base = {k: s.get(k) for k in ("scan_mode", "fail_on", "max_budget", "max_turns", "llm_profile_id")}
    try:
        new = runner.enqueue(t, _scan_opts({**base, **body}, t), "manual", resume_run=s["run_name"])
    except runner.Busy as e:
        bad(str(e), 409)
    return _scan_out(db.get_scan(new))  # type: ignore[return-value]


@app.delete("/api/scans/{sid}")
def scan_delete(sid: int) -> dict[str, bool]:
    s = _scan_or_404(sid)
    if s["status"] in runner.ACTIVE:
        bad("Aktif tarama silinemez")
    db.delete("scans", sid)  # strix_runs directory on disk is kept
    return {"ok": True}


FINDING_MD = ("description", "impact", "technical_analysis", "poc_description", "remediation_steps", "evidence",
              "assumptions", "counterevidence", "severity_change_conditions")


@app.get("/api/scans/{sid}/findings")
def scan_findings(sid: int) -> dict[str, Any]:
    rd = _run_dir(_scan_or_404(sid))
    if not rd:
        return {"source": None, "items": []}
    items = []
    for v in runs.findings(rd):
        v = dict(v)
        for f in FINDING_MD:
            if isinstance(v.get(f), str) and v[f].strip():
                v[f + "_html"] = md.render(v[f])
        if v.get("markdown"):
            v["markdown_html"] = md.render(v.pop("markdown"))
        items.append(v)
    source = "vulnerabilities.json" if (rd / "vulnerabilities.json").exists() else ("vulnerabilities/*.md" if items else None)
    return {"source": source, "items": items}


@app.get("/api/scans/{sid}/report")
def scan_report(sid: int) -> dict[str, Any]:
    rd = _run_dir(_scan_or_404(sid))
    p = rd / runs.DOWNLOADABLE["report"] if rd else None
    if not p or not p.exists():
        return {"available": False, "html": ""}
    return {"available": True, "html": md.render(p.read_text(encoding="utf-8", errors="replace"))}


@app.get("/api/scans/{sid}/agents")
def scan_agents(sid: int) -> dict[str, Any]:
    rd = _run_dir(_scan_or_404(sid))
    return runs.agents(rd) if rd else {"agents": [], "counts": {}}


@app.get("/api/scans/{sid}/log")
def scan_log(sid: int, source: str = "strix", offset: int = -1) -> dict[str, Any]:
    s = _scan_or_404(sid)
    rd = _run_dir(s)
    path = LOG_DIR / f"scan_{sid}.log" if source == "process" else (rd / "strix.log" if rd else None)
    if not path or not path.exists():
        return {"available": False, "text": "", "offset": 0}
    text, off = runs.tail(path, offset)
    return {"available": True, "text": text, "offset": off}


@app.get("/api/scans/{sid}/download/{kind}")
def scan_download(sid: int, kind: str) -> FileResponse:
    s = _scan_or_404(sid)
    rd = _run_dir(s)
    fname = runs.DOWNLOADABLE.get(kind)
    if not rd or not fname or not (rd / fname).exists():
        bad("Dosya yok", 404)
    return FileResponse(rd / fname, filename=f"{s.get('run_name') or sid}_{fname}", media_type="application/octet-stream")


@app.post("/api/import")
def import_runs() -> dict[str, int]:
    return {"imported": runner.import_existing_runs()}


# ---------------------------------------------------------------- settings
SETTINGS_KEYS = ("strix_bin", "strix_workdir", "max_concurrent", "default_scan_mode", "telemetry", "webhook_url")


@app.get("/api/settings")
def settings_get() -> dict[str, Any]:
    st = db.get_settings()
    out: dict[str, Any] = {k: st.get(k, "") for k in SETTINGS_KEYS}
    out.update(timezone=TIMEZONE, password_from_env=auth.password_from_env(),
               has_api_token=bool(st.get("api_token_enc")))
    return out


@app.put("/api/settings")
def settings_put(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    vals = {k: body[k] for k in SETTINGS_KEYS if k in body}
    if "max_concurrent" in vals:
        try:
            vals["max_concurrent"] = str(max(1, min(10, int(vals["max_concurrent"]))))
        except (TypeError, ValueError):
            bad("Eşzamanlı tarama sayısı 1-10 arası olmalı")
    if "strix_bin" in vals and not Path(str(vals["strix_bin"])).expanduser().is_file():
        bad(f"Strix binary bulunamadı: {vals['strix_bin']}")
    if "strix_workdir" in vals and not Path(str(vals["strix_workdir"])).expanduser().is_dir():
        bad(f"Çalışma klasörü yok: {vals['strix_workdir']}")
    if vals.get("default_scan_mode", "standard") not in SCAN_MODES:
        bad("Geçersiz tarama modu")
    if "telemetry" in vals:
        vals["telemetry"] = "1" if str(vals["telemetry"]).lower() in ("1", "true") else "0"
    url = str(vals.get("webhook_url") or "").strip()
    if url and urlparse(url).scheme not in ("http", "https"):
        bad("Webhook URL http(s) olmalı")
    db.set_settings(vals)
    if "strix_workdir" in vals:
        runner.import_existing_runs()
    runner._wake.set()
    return settings_get()


@app.post("/api/settings/api-token")
def settings_rotate_token() -> dict[str, str]:
    """Returns the new CI token once; it cannot be read back later."""
    return {"api_token": auth.rotate_api_token()}


# ---------------------------------------------------------------- CI API (X-API-Token)
@app.post("/api/ci/targets/{tid}/scan")
def ci_scan(tid: int, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    t = _target_or_404(tid)
    opts = _scan_opts(body, t)
    try:
        sid = runner.enqueue(t, opts, "api")
    except runner.Busy as e:
        bad(str(e), 409)
    return {"scan_id": sid, "status": "queued"}


@app.get("/api/ci/scans/{sid}")
def ci_status(sid: int) -> dict[str, Any]:
    s = _scan_or_404(sid)
    summ = s.get("summary") or {}
    return {"scan_id": sid, "status": s["status"], "finished": s["status"] not in runner.ACTIVE,
            "gate": summ.get("gate") if s["status"] == "completed" else None,
            "counts": summ.get("counts"), "run_name": s.get("run_name")}


# ---------------------------------------------------------------- static UI
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
