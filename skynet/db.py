"""SQLite persistence: settings, LLM connection profiles, targets, schedules, scans."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import DB_PATH, DEFAULT_STRIX_BIN, DEFAULT_STRIX_WORKDIR

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS llm_profiles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    provider         TEXT NOT NULL,              -- openrouter | litellm
    base_url         TEXT DEFAULT '',
    api_key_enc      TEXT DEFAULT '',
    model            TEXT NOT NULL,              -- model id as the provider knows it (no strix prefix)
    api_type         TEXT DEFAULT '',            -- '' | chat_completions | responses  (STRIX_API_TYPE)
    reasoning_effort TEXT DEFAULT '',
    ca_cert_path     TEXT DEFAULT '',            -- SSL_CERT_FILE for private CAs
    is_default       INTEGER DEFAULT 0,
    created_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    application      TEXT DEFAULT '',
    environment      TEXT NOT NULL DEFAULT 'test',   -- development | test | staging | production
    base_url         TEXT NOT NULL,
    extra_targets    TEXT DEFAULT '[]',              -- repos, API specs, extra hosts (passed as --target)
    in_scope         TEXT DEFAULT '[]',
    out_of_scope     TEXT DEFAULT '[]',
    instruction      TEXT DEFAULT '',
    auth_type        TEXT DEFAULT 'none',            -- none | credentials | header
    auth_login_url   TEXT DEFAULT '',
    auth_username    TEXT DEFAULT '',
    auth_secret_enc  TEXT DEFAULT '',                -- password or header value
    auth_header_name TEXT DEFAULT '',
    auth_notes       TEXT DEFAULT '',
    default_scan_mode TEXT DEFAULT 'standard',
    llm_profile_id   INTEGER,
    created_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER NOT NULL,
    name             TEXT DEFAULT '',
    kind             TEXT NOT NULL,                  -- once | daily | weekly | interval | cron
    run_at           TEXT DEFAULT '',                -- once: local ISO datetime
    time_of_day      TEXT DEFAULT '',                -- daily/weekly: HH:MM
    weekdays         TEXT DEFAULT '[]',              -- weekly: ["mon", ...]
    interval_hours   INTEGER,
    cron_expr        TEXT DEFAULT '',
    timezone         TEXT NOT NULL,
    scan_mode        TEXT DEFAULT 'standard',
    max_budget       REAL,
    max_turns        INTEGER,
    fail_on          TEXT DEFAULT 'high',
    llm_profile_id   INTEGER NOT NULL,
    enabled          INTEGER DEFAULT 1,
    next_run_at      TEXT,                           -- persisted so missed runs can be detected after restart
    last_run_at      TEXT,
    last_scan_id     INTEGER,
    last_outcome     TEXT,                           -- started | skipped_busy | missed | error
    last_note        TEXT,
    created_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS schedule_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id INTEGER NOT NULL,
    at          TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    note        TEXT,
    scan_id     INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER,
    schedule_id      INTEGER,
    name             TEXT,
    environment      TEXT,
    targets          TEXT,                           -- JSON list actually passed to strix
    instruction      TEXT DEFAULT '',                -- user instruction only (never credentials)
    scan_mode        TEXT,
    max_budget       REAL,
    max_turns        INTEGER,
    fail_on          TEXT DEFAULT '',
    llm_profile_id   INTEGER,
    llm_profile_name TEXT,
    llm_provider     TEXT,
    model            TEXT,                           -- STRIX_LLM used (or parsed from strix.log for imports)
    resume_run       TEXT DEFAULT '',
    trigger          TEXT DEFAULT 'manual',          -- manual | schedule | api | cli
    status           TEXT DEFAULT 'queued',          -- queued|running|stopping|completed|failed|cancelled|interrupted
    run_name         TEXT,
    run_dir          TEXT,
    pid              INTEGER,
    exit_code        INTEGER,
    error            TEXT,
    summary          TEXT,
    sandbox_container TEXT,
    created_at TEXT, started_at TEXT, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_run_name ON scans(run_name);
CREATE INDEX IF NOT EXISTS idx_sched_events ON schedule_events(schedule_id, id);
"""

DEFAULT_SETTINGS: dict[str, str] = {
    "strix_bin": DEFAULT_STRIX_BIN,
    "strix_workdir": DEFAULT_STRIX_WORKDIR,   # strix writes to <workdir>/strix_runs/
    "max_concurrent": "1",
    "default_scan_mode": "standard",
    "telemetry": "0",                         # STRIX_TELEMETRY passed to strix (Strix default is 1)
    "webhook_url": "",
    "api_token_enc": "",
    "admin_password_hash": "",
}

JSON_COLS = {"targets", "extra_targets", "in_scope", "out_of_scope", "weekdays", "summary"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        for suffix in ("", "-wal", "-shm"):
            f = DB_PATH.with_name(DB_PATH.name + suffix)
            if f.exists():
                f.chmod(0o600)
    return _conn


def init() -> None:
    with _lock:
        conn().executescript(SCHEMA)
        existing = {r["key"] for r in conn().execute("SELECT key FROM settings")}
        for k, v in DEFAULT_SETTINGS.items():
            if k not in existing:
                conn().execute("INSERT INTO settings(key, value) VALUES(?, ?)", (k, v))


def q(sql: str, args: Iterable[Any] = ()) -> list[dict[str, Any]]:
    with _lock:
        rows = conn().execute(sql, list(args)).fetchall()
    return [_decode(dict(r)) for r in rows]


def q1(sql: str, args: Iterable[Any] = ()) -> dict[str, Any] | None:
    rows = q(sql, args)
    return rows[0] if rows else None


def execute(sql: str, args: Iterable[Any] = ()) -> int:
    with _lock:
        cur = conn().execute(sql, list(args))
        return int(cur.lastrowid or 0)


def _decode(d: dict[str, Any]) -> dict[str, Any]:
    for c in JSON_COLS & d.keys():
        v = d[c]
        if isinstance(v, str) and v:
            try:
                d[c] = json.loads(v)
            except ValueError:
                pass
        elif v is None:
            d[c] = {} if c == "summary" else []
    return d


def _encode(data: dict[str, Any]) -> dict[str, Any]:
    return {k: (json.dumps(v) if k in JSON_COLS and not isinstance(v, str) and v is not None else v)
            for k, v in data.items()}


TIMESTAMPED = {"llm_profiles", "targets", "schedules"}


def insert(table: str, data: dict[str, Any]) -> int:
    d = _encode(data)
    if table in TIMESTAMPED or table == "scans":
        d.setdefault("created_at", now_iso())
    if table in TIMESTAMPED:
        d.setdefault("updated_at", d["created_at"])
    cols = ", ".join(d)
    return execute(f"INSERT INTO {table} ({cols}) VALUES ({', '.join('?' for _ in d)})", d.values())


def update(table: str, row_id: int, data: dict[str, Any]) -> None:
    if not data:
        return
    d = _encode(data)
    if table in TIMESTAMPED:
        d["updated_at"] = now_iso()
    execute(f"UPDATE {table} SET {', '.join(f'{k}=?' for k in d)} WHERE id=?", [*d.values(), row_id])


def delete(table: str, row_id: int) -> None:
    execute(f"DELETE FROM {table} WHERE id=?", (row_id,))


def get(table: str, row_id: int) -> dict[str, Any] | None:
    return q1(f"SELECT * FROM {table} WHERE id=?", (row_id,))


# ---------------------------------------------------------------- settings
def get_settings() -> dict[str, str]:
    out = dict(DEFAULT_SETTINGS)
    out.update({r["key"]: r["value"] or "" for r in q("SELECT key, value FROM settings")})
    return out


def set_settings(values: dict[str, Any]) -> None:
    for k, v in values.items():
        if k in DEFAULT_SETTINGS:
            execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, "" if v is None else str(v)))


# ---------------------------------------------------------------- scans
SCAN_SELECT = ("SELECT s.*, t.name AS target_name, t.environment AS target_environment, "
               "sc.name AS schedule_name FROM scans s "
               "LEFT JOIN targets t ON t.id = s.target_id LEFT JOIN schedules sc ON sc.id = s.schedule_id")


def get_scan(sid: int) -> dict[str, Any] | None:
    return q1(SCAN_SELECT + " WHERE s.id=?", (sid,))


def list_scans(status: str | None = None, target_id: int | None = None, schedule_id: int | None = None,
               limit: int = 200) -> list[dict[str, Any]]:
    sql, args = SCAN_SELECT + " WHERE 1=1", []
    if status:
        sts = status.split(",")
        sql += f" AND s.status IN ({','.join('?' for _ in sts)})"
        args += sts
    if target_id:
        sql += " AND s.target_id=?"
        args.append(target_id)
    if schedule_id:
        sql += " AND s.schedule_id=?"
        args.append(schedule_id)
    sql += " ORDER BY COALESCE(s.started_at, s.created_at) DESC, s.id DESC LIMIT ?"
    args.append(limit)
    return q(sql, args)


def claimed_run_names() -> set[str]:
    return {r["run_name"] for r in q("SELECT run_name FROM scans WHERE run_name IS NOT NULL")}
