"""Scan schedules (APScheduler, in-memory jobs rebuilt from SQLite on every start).

Restart / failure policy (also shown in the UI):
- Schedules live in SQLite; jobs are rebuilt at startup, so nothing is lost on restart.
- A run whose time passed while the application was down (more than GRACE_SECONDS late) is NOT executed
  retroactively. It is recorded as "missed" and the schedule continues with its next occurrence.
  A missed one-time schedule is disabled.
- If the target already has a queued/running scan when a schedule fires, that run is skipped ("skipped_busy").
- A failed scan is never retried automatically.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from . import db, runner
from .config import TIMEZONE

log = logging.getLogger("skynet.scheduler")
GRACE_SECONDS = 300
KINDS = ("once", "daily", "weekly", "interval", "cron")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_sched = BackgroundScheduler(timezone=ZoneInfo(TIMEZONE),
                             job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": GRACE_SECONDS})


def _tz(s: dict[str, Any]) -> ZoneInfo:
    return ZoneInfo(s.get("timezone") or TIMEZONE)


def _hm(s: dict[str, Any]) -> tuple[int, int]:
    hh, mm = (s.get("time_of_day") or "").split(":")
    h, m = int(hh), int(mm)
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError("saat HH:MM biçiminde olmalı")
    return h, m


def build_trigger(s: dict[str, Any]):
    tz, kind = _tz(s), s.get("kind")
    if kind == "once":
        if not s.get("run_at"):
            raise ValueError("tarih/saat gerekli")
        dt = datetime.fromisoformat(s["run_at"])
        return DateTrigger(run_date=dt if dt.tzinfo else dt.replace(tzinfo=tz), timezone=tz)
    if kind == "daily":
        h, m = _hm(s)
        return CronTrigger(hour=h, minute=m, timezone=tz)
    if kind == "weekly":
        days = [d for d in s.get("weekdays") or [] if d in WEEKDAYS]
        if not days:
            raise ValueError("en az bir gün seçin")
        h, m = _hm(s)
        return CronTrigger(day_of_week=",".join(days), hour=h, minute=m, timezone=tz)
    if kind == "interval":
        hours = int(s.get("interval_hours") or 0)
        if hours < 1:
            raise ValueError("aralık en az 1 saat olmalı")
        start = datetime.fromisoformat(s["run_at"]) if s.get("run_at") else datetime.now(tz)
        return IntervalTrigger(hours=hours, start_date=start if start.tzinfo else start.replace(tzinfo=tz), timezone=tz)
    if kind == "cron":
        return CronTrigger.from_crontab((s.get("cron_expr") or "").strip(), timezone=tz)
    raise ValueError("geçersiz plan türü")


def validate(s: dict[str, Any]) -> str | None:
    try:
        ZoneInfo(s.get("timezone") or TIMEZONE)
        trig = build_trigger(s)
    except (ValueError, KeyError, TypeError) as e:
        return str(e) or "geçersiz plan"
    if s.get("kind") == "once":
        nxt = trig.get_next_fire_time(None, datetime.now(_tz(s)))
        if not nxt or nxt < datetime.now(_tz(s)):
            return "tek seferlik plan geçmiş bir zamana ayarlanamaz"
    return None


def preview(s: dict[str, Any], n: int = 5) -> list[str]:
    trig = build_trigger(s)
    out, prev, now = [], None, datetime.now(_tz(s))
    for _ in range(n):
        nxt = trig.get_next_fire_time(prev, (prev + timedelta(seconds=1)) if prev else now)
        if not nxt:
            break
        out.append(nxt.isoformat())
        prev = nxt
    return out


def describe(s: dict[str, Any]) -> str:
    k = s.get("kind")
    days_tr = dict(zip(WEEKDAYS, ("Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz")))
    if k == "once":
        return f"Tek sefer: {s.get('run_at', '').replace('T', ' ')[:16]}"
    if k == "daily":
        return f"Her gün {s.get('time_of_day')}"
    if k == "weekly":
        return "Her hafta " + ", ".join(days_tr.get(d, d) for d in s.get("weekdays") or []) + f" {s.get('time_of_day')}"
    if k == "interval":
        return f"Her {s.get('interval_hours')} saatte bir"
    return f"Cron: {s.get('cron_expr')}"


def event(schedule_id: int, outcome: str, note: str = "", scan_id: int | None = None) -> None:
    now = db.now_iso()
    db.insert("schedule_events", {"schedule_id": schedule_id, "at": now, "outcome": outcome, "note": note,
                                  "scan_id": scan_id})
    upd: dict[str, Any] = {"last_outcome": outcome, "last_note": note}
    if outcome == "started":
        upd.update(last_run_at=now, last_scan_id=scan_id)
    db.update("schedules", schedule_id, upd)


def _fire(schedule_id: int) -> None:
    s = db.get("schedules", schedule_id)
    if not s or not s["enabled"]:
        return
    target = db.get("targets", s["target_id"])
    try:
        if not target:
            raise ValueError("hedef silinmiş")
        sid = runner.enqueue(target, s, "schedule", schedule_id=schedule_id)
        event(schedule_id, "started", "", sid)
    except runner.Busy as e:
        event(schedule_id, "skipped_busy", str(e))
    except ValueError as e:
        event(schedule_id, "error", str(e))
    finally:
        if s["kind"] == "once":
            db.update("schedules", schedule_id, {"enabled": 0})
        _store_next(schedule_id)


def _store_next(schedule_id: int) -> None:
    job = _sched.get_job(f"schedule-{schedule_id}")
    nxt = job.next_run_time.isoformat() if job and job.next_run_time else None
    db.update("schedules", schedule_id, {"next_run_at": nxt})


def handle_missed() -> None:
    """Startup only: record runs whose time passed while the app was down; never run them retroactively."""
    now = datetime.now(ZoneInfo(TIMEZONE))
    for s in db.q("SELECT * FROM schedules WHERE enabled=1 AND next_run_at IS NOT NULL"):
        due = datetime.fromisoformat(s["next_run_at"])
        if (now - due).total_seconds() > GRACE_SECONDS:
            event(s["id"], "missed", f"Uygulama kapalıyken kaçırıldı (planlanan {due.strftime('%d.%m.%Y %H:%M')}); "
                                     "geriye dönük çalıştırılmadı.")
            if s["kind"] == "once":
                db.update("schedules", s["id"], {"enabled": 0, "next_run_at": None})


def sync() -> None:
    wanted = {f"schedule-{s['id']}": s for s in db.q("SELECT * FROM schedules WHERE enabled=1")}
    for job in _sched.get_jobs():
        if job.id not in wanted:
            job.remove()
    for jid, s in wanted.items():
        try:
            _sched.add_job(_fire, build_trigger(s), id=jid, args=[s["id"]], replace_existing=True)
        except ValueError as e:
            log.warning("schedule %s invalid: %s", s["id"], e)
    for s in db.q("SELECT id FROM schedules"):
        _store_next(s["id"])


def start() -> None:
    handle_missed()
    _sched.start()
    sync()
