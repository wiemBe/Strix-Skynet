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

from . import (auth, campaigns, crypto, db, findings_store, inventory, llm, runner, runs, scheduler, targets,
               telemetry, vault)
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
    runner.start_backfill()   # ingest findings/inventory/telemetry for pre-existing runs, in the background
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
    cid = body.get("campaign_id") or None
    if cid:
        c = db.get("campaigns", int(cid)) or bad("Kampanya bulunamadı")
        if c.get("archived_at"):
            bad("Arşivlenmiş kampanyaya tarama bağlanamaz")
        cid = int(cid)
    try:
        aids = [int(x) for x in (body.get("auth_profile_ids") or [])]
    except (TypeError, ValueError):
        bad("Geçersiz kimlik profili")
    return {"scan_mode": mode, "fail_on": fail_on, "llm_profile_id": int(pid), "campaign_id": cid,
            "auth_profile_ids": aids,
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
    mode = body.get("default_scan_mode") or "standard"
    if mode not in SCAN_MODES:
        bad("Geçersiz tarama modu")
    lp = body.get("llm_profile_id") or None
    if lp and not llm.get(int(lp)):
        bad("LLM profili bulunamadı")
    # Authentication is managed through auth profiles (vault), not stored on the target. New/updated targets always
    # carry auth_type='none'; any auth_* fields in the request body are ignored.
    return {"name": name, "application": (body.get("application") or "").strip(), "environment": env,
            "base_url": base, "extra_targets": extra, "in_scope": _lines(body.get("in_scope")),
            "out_of_scope": _lines(body.get("out_of_scope")), "instruction": (body.get("instruction") or "").strip(),
            "auth_type": "none", "auth_secret_enc": "", "auth_login_url": "", "auth_username": "",
            "auth_header_name": "", "auth_notes": "", "default_scan_mode": mode,
            "llm_profile_id": int(lp) if lp else None}


def _target_out(t: dict[str, Any], detail: bool = False) -> dict[str, Any]:
    d = {k: v for k, v in t.items() if not k.startswith("auth_")}
    d["auth_profiles"] = [vault.public(p, with_usage=False) for p in vault.profiles_for_target(t["id"])]
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
        sid = runner.enqueue(t, opts, "manual", campaign_id=opts["campaign_id"],
                             auth_profile_ids=opts["auth_profile_ids"])
    except runner.Busy as e:
        bad(str(e), 409)
    except ValueError as e:   # includes vault.AuthError
        bad(str(e))
    return _scan_out(db.get_scan(sid))  # type: ignore[return-value]


# ---------------------------------------------------------------- schedules
def _schedule_payload(body: dict[str, Any]) -> dict[str, Any]:
    t = _target_or_404(int(body.get("target_id") or 0))
    kind = body.get("kind")
    if kind not in scheduler.KINDS:
        bad("Plan türü seçin")
    opts = _scan_opts(body, t)
    # Auth profiles on a schedule must be assigned to its target (same rule as a scan); validate now.
    try:
        vault.resolve(t["id"], opts["auth_profile_ids"])
    except vault.AuthError as e:
        bad(str(e))
    data = {"target_id": t["id"], "name": (body.get("name") or "").strip(), "kind": kind,
            "run_at": (body.get("run_at") or "").strip(), "time_of_day": (body.get("time_of_day") or "").strip(),
            "weekdays": [d for d in body.get("weekdays") or [] if d in scheduler.WEEKDAYS],
            "interval_hours": _num(body, "interval_hours", int), "cron_expr": (body.get("cron_expr") or "").strip(),
            "timezone": (body.get("timezone") or TIMEZONE).strip(), "enabled": 1 if body.get("enabled", True) else 0,
            "campaign_id": opts["campaign_id"], "auth_profile_ids": opts["auth_profile_ids"],
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
        exec_sum = vault.scan_redactor(s).text(meta.get("executive_summary") or "")
        out["executive_summary_html"] = md.render(exec_sum) if exec_sum else ""
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
    base = {k: s.get(k) for k in ("scan_mode", "fail_on", "max_budget", "max_turns", "llm_profile_id",
                                  "campaign_id", "auth_profile_ids")}
    opts = _scan_opts({**base, **body}, t)
    try:
        new = runner.enqueue(t, opts, "manual", resume_run=s["run_name"], campaign_id=opts["campaign_id"],
                             auth_profile_ids=opts["auth_profile_ids"])
    except runner.Busy as e:
        bad(str(e), 409)
    except ValueError as e:   # includes vault.AuthError (profile removed/unassigned since the original run)
        bad(str(e))
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
    s = _scan_or_404(sid)
    rd = _run_dir(s)
    if not rd:
        return {"source": None, "items": []}
    red = vault.scan_redactor(s)
    items = []
    for v in runs.findings(rd):
        v = red.obj(dict(v))   # mask any secret Strix copied into the finding (incl. fields not rendered below)
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
    s = _scan_or_404(sid)
    rd = _run_dir(s)
    p = rd / runs.DOWNLOADABLE["report"] if rd else None
    if not p or not p.exists():
        return {"available": False, "html": ""}
    raw = vault.scan_redactor(s).text(p.read_text(encoding="utf-8", errors="replace"))
    return {"available": True, "html": md.render(raw)}


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
    # Line-align so a secret spanning the chunk boundary is never served half-masked, then strict-redact.
    if text and not text.endswith("\n"):
        nl = text.rfind("\n")
        if nl != -1:
            off -= len(text.encode("utf-8")) - len(text[:nl + 1].encode("utf-8"))
            text = text[:nl + 1]
    return {"available": True, "text": vault.scan_redactor(s).text(text, strict=True), "offset": off}


@app.get("/api/scans/{sid}/download/{kind}")
def scan_download(sid: int, kind: str) -> Response:
    s = _scan_or_404(sid)
    rd = _run_dir(s)
    fname = runs.DOWNLOADABLE.get(kind)
    if not rd or not fname or not (rd / fname).exists():
        bad("Dosya yok", 404)
    # Strix may have copied secrets into these files; redact before handing them out (strict for the log).
    raw = (rd / fname).read_text(encoding="utf-8", errors="replace")
    red = vault.scan_redactor(s).text(raw, strict=(kind == "log"))
    return Response(red, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{s.get("run_name") or sid}_{fname}"'})


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
               has_api_token=bool(st.get("api_token_enc")),
               key_status=crypto.key_status(), schema_version=db.schema_version(),
               migrations=db.migrations_applied())
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
        sid = runner.enqueue(t, opts, "api", campaign_id=opts["campaign_id"],
                             auth_profile_ids=opts["auth_profile_ids"])
    except runner.Busy as e:
        bad(str(e), 409)
    except ValueError as e:   # includes vault.AuthError
        bad(str(e))
    return {"scan_id": sid, "status": "queued"}


@app.get("/api/ci/scans/{sid}")
def ci_status(sid: int) -> dict[str, Any]:
    s = _scan_or_404(sid)
    summ = s.get("summary") or {}
    return {"scan_id": sid, "status": s["status"], "finished": s["status"] not in runner.ACTIVE,
            "gate": summ.get("gate") if s["status"] == "completed" else None,
            "counts": summ.get("counts"), "run_name": s.get("run_name")}


# ---------------------------------------------------------------- campaigns
def _campaign_or_404(cid: int) -> dict[str, Any]:
    return db.get("campaigns", cid) or bad("Kampanya bulunamadı", 404)


@app.get("/api/campaigns")
def campaign_list(include_archived: int = 0) -> list[dict[str, Any]]:
    sql = "SELECT * FROM campaigns" + ("" if include_archived else " WHERE archived_at IS NULL")
    return [campaigns.public(c) for c in db.q(sql + " ORDER BY archived_at IS NOT NULL, name COLLATE NOCASE")]


@app.get("/api/campaigns/{cid}")
def campaign_get(cid: int) -> dict[str, Any]:
    c = _campaign_or_404(cid)
    out = campaigns.public(c, detail=True)
    out["scans"] = [_scan_out(s) for s in db.list_scans(limit=200) if s.get("campaign_id") == cid]
    out["schedules"] = [_schedule_out(s) for s in db.q(SCHED_SELECT + " WHERE s.campaign_id=?", (cid,))]
    return out


@app.post("/api/campaigns")
def campaign_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        cid = campaigns.save(body, None)
    except ValueError as e:
        bad(str(e))
    return campaign_get(cid)


@app.put("/api/campaigns/{cid}")
def campaign_update(cid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    c = _campaign_or_404(cid)
    if c.get("archived_at"):
        bad("Arşivlenmiş kampanya düzenlenemez; önce arşivden çıkarın.")
    try:
        campaigns.save(body, c)
    except ValueError as e:
        bad(str(e))
    return campaign_get(cid)


@app.post("/api/campaigns/{cid}/archive")
def campaign_archive(cid: int, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    _campaign_or_404(cid)
    db.execute("UPDATE campaigns SET archived_at=? WHERE id=?",
               (None if body.get("unarchive") else db.now_iso(), cid))
    return campaign_get(cid)


@app.delete("/api/campaigns/{cid}")
def campaign_delete(cid: int) -> dict[str, bool]:
    c = _campaign_or_404(cid)
    err = campaigns.can_delete(c)
    if err:
        bad(err)
    campaigns.delete(cid)
    return {"ok": True}


# ---------------------------------------------------------------- auth profiles (vault)
def _auth_or_404(pid: int) -> dict[str, Any]:
    return db.get("auth_profiles", pid) or bad("Kimlik profili bulunamadı", 404)


def _pause_schedules_using(pid: int, target_ids: list[int] | None, reason: str) -> int:
    """Pause (and log an event on) every enabled schedule that relies on this profile, so a scheduled scan never
    silently runs without the authentication it was configured with."""
    n = 0
    for s in vault.schedules_using(pid, target_ids):
        if s.get("enabled"):
            db.update("schedules", s["id"], {"enabled": 0})
            scheduler.event(s["id"], "error", reason)
            n += 1
    if n:
        scheduler.sync()
    return n


@app.get("/api/auth-profiles")
def auth_list() -> list[dict[str, Any]]:
    return [vault.public(p) for p in db.q("SELECT * FROM auth_profiles ORDER BY name COLLATE NOCASE")]


@app.get("/api/auth-profiles/{pid}")
def auth_get(pid: int) -> dict[str, Any]:
    return vault.public(_auth_or_404(pid))


@app.post("/api/auth-profiles")
def auth_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        pid = vault.save(body, None)
    except (ValueError, crypto.DecryptError) as e:
        bad(str(e))
    if body.get("target_ids") is not None:
        _assign_profile(pid, body.get("target_ids") or [])
    return vault.public(vault.get(pid))  # type: ignore[arg-type]


@app.put("/api/auth-profiles/{pid}")
def auth_update(pid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    existing = _auth_or_404(pid)
    try:
        vault.save(body, existing)
    except (ValueError, crypto.DecryptError) as e:
        bad(str(e))
    if body.get("target_ids") is not None:
        _assign_profile(pid, body.get("target_ids") or [])
    return vault.public(vault.get(pid))  # type: ignore[arg-type]


def _assign_profile(pid: int, target_ids: list[int]) -> None:
    want = {int(t) for t in target_ids}
    valid = {t["id"] for t in db.q(f"SELECT id FROM targets WHERE id IN ({','.join('?' * len(want))})", list(want))} if want else set()
    have = set(vault.assigned_targets(pid))
    for tid in valid - have:
        db.execute("INSERT OR IGNORE INTO auth_profile_targets(profile_id, target_id, added_at) VALUES (?,?,?)",
                   (pid, tid, db.now_iso()))
    removed = have - valid
    for tid in removed:
        db.execute("DELETE FROM auth_profile_targets WHERE profile_id=? AND target_id=?", (pid, tid))
    if removed:
        p = vault.get(pid)
        _pause_schedules_using(pid, list(removed),
                               f"“{p['name']}” kimlik profili hedeften kaldırıldığı için zamanlama duraklatıldı.")


@app.post("/api/auth-profiles/{pid}/assign")
def auth_assign(pid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    _auth_or_404(pid)
    _assign_profile(pid, body.get("target_ids") or [])
    return vault.public(vault.get(pid))  # type: ignore[arg-type]


@app.post("/api/auth-profiles/{pid}/verify")
def auth_verify(pid: int) -> dict[str, Any]:
    p = _auth_or_404(pid)
    r = vault.verify(p)
    vault.record_verify(p, r)
    return {"result": r, "profile": vault.public(vault.get(pid))}


@app.delete("/api/auth-profiles/{pid}")
def auth_delete(pid: int) -> dict[str, Any]:
    p = _auth_or_404(pid)
    paused = _pause_schedules_using(pid, None, f"“{p['name']}” kimlik profili silindiği için zamanlama duraklatıldı.")
    db.execute("DELETE FROM auth_profile_targets WHERE profile_id=?", (pid,))
    db.delete("auth_profiles", pid)
    return {"ok": True, "paused_schedules": paused}


# ---------------------------------------------------------------- inventory
@app.get("/api/targets/{tid}/inventory")
def target_inventory(tid: int, kind: str = "", tier: str = "", scope: str = "", q: str = "") -> dict[str, Any]:
    t = _target_or_404(tid)
    assets = inventory.assets_for(t, kind=kind, tier=tier, scope_label=scope, q=q)
    latest = inventory.latest_run(tid)
    return {"assets": assets, "summary": inventory.summary_for(tid),
            "diff": inventory.run_diff(latest, tid) if latest else None, "latest_run": latest}


@app.get("/api/assets/{aid}/observations")
def asset_observations(aid: int) -> dict[str, Any]:
    a = db.get("assets", aid) or bad("Varlık bulunamadı", 404)
    return {"asset": a, "observations": inventory.observations(aid)}


# ---------------------------------------------------------------- telemetry
@app.get("/api/scans/{sid}/telemetry")
def scan_telemetry(sid: int) -> dict[str, Any]:
    s = _scan_or_404(sid)
    t = telemetry.get(sid)
    if not t:
        rd = _run_dir(s)
        t = telemetry.collect(s, rd) if rd else {}
    return {"available": bool(t and t.get("available")), "telemetry": t or {}}


# ---------------------------------------------------------------- deduplicated findings
def _finding_group_out(tid: int | None, scan_ids: list[int]) -> dict[str, Any]:
    groups = findings_store.groups_for_scans(scan_ids)
    return {"groups": groups, "summary": findings_store.summary(groups)}


@app.get("/api/targets/{tid}/findings")
def target_findings(tid: int) -> dict[str, Any]:
    _target_or_404(tid)
    scan_ids = [s["id"] for s in db.list_scans(target_id=tid, limit=5000)]
    return _finding_group_out(tid, scan_ids)


@app.get("/api/campaigns/{cid}/findings")
def campaign_findings(cid: int) -> dict[str, Any]:
    _campaign_or_404(cid)
    return _finding_group_out(None, campaigns.scan_ids(cid))


@app.get("/api/findings/{gid}")
def finding_get(gid: int) -> dict[str, Any]:
    g = db.q1(findings_store.GROUP_SELECT + " WHERE g.id=?", (gid,)) or bad("Bulgu bulunamadı", 404)
    g["occurrences_list"] = findings_store.occurrences(gid)
    return g


@app.patch("/api/findings/{gid}")
def finding_patch(gid: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    db.get("finding_groups", gid) or bad("Bulgu bulunamadı", 404)
    rem = body.get("remediation")
    if rem not in findings_store.REMEDIATION:
        bad("Geçersiz durum")
    db.execute("UPDATE finding_groups SET remediation=?, remediation_note=?, remediation_at=? WHERE id=?",
               (rem, (body.get("remediation_note") or "").strip(), db.now_iso(), gid))
    return finding_get(gid)


# ---------------------------------------------------------------- static UI
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
