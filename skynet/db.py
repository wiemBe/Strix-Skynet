"""SQLite persistence: settings, LLM connection profiles, targets, schedules, scans, campaigns, auth profiles
(vault), deduplicated findings, discovery inventory and scan telemetry.

Schema changes after the first release are applied as numbered migrations (table `schema_migrations`). Before the
first pending migration runs, the database is copied to data/backups/skynet-pre-v<N>-<timestamp>.db.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import DATA_DIR, DB_PATH, DEFAULT_STRIX_BIN, DEFAULT_STRIX_WORKDIR

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

JSON_COLS = {"targets", "extra_targets", "in_scope", "out_of_scope", "weekdays", "summary",
             "auth_profile_ids", "auth_profile_names", "auth_checks", "header_names", "cookie_names",
             "attrs", "counts", "telemetry"}
DICT_COLS = {"summary", "attrs", "counts", "telemetry"}


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
        migrate()


# ---------------------------------------------------------------- migrations
MIGRATION_1 = """
-- campaigns ---------------------------------------------------------------
CREATE TABLE campaigns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    description  TEXT DEFAULT '',
    scope        TEXT DEFAULT '',               -- free-text engagement scope (target scope rules stay on targets)
    environment  TEXT DEFAULT '',               -- '' = mixed
    status       TEXT NOT NULL DEFAULT 'planned', -- planned | active | on_hold | completed (finding remediation is separate)
    completed_at TEXT,
    archived_at  TEXT,                          -- archived = read-only, hidden by default; scans are never touched
    created_at TEXT, updated_at TEXT
);
CREATE TABLE campaign_targets (
    campaign_id INTEGER NOT NULL, target_id INTEGER NOT NULL, added_at TEXT,
    PRIMARY KEY (campaign_id, target_id)
);
ALTER TABLE scans ADD COLUMN campaign_id INTEGER;
ALTER TABLE schedules ADD COLUMN campaign_id INTEGER;

-- auth profiles (vault) ---------------------------------------------------
CREATE TABLE auth_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,              -- anonymous | credentials | header | cookie
    description     TEXT DEFAULT '',
    username        TEXT DEFAULT '',            -- not secret; shown in the UI
    login_url       TEXT DEFAULT '',
    header_names    TEXT DEFAULT '[]',          -- names only; values live in secret_enc
    cookie_names    TEXT DEFAULT '[]',
    cookie_domain   TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    secret_enc      TEXT DEFAULT '',            -- vault-encrypted JSON (password / header values / cookie values)
    secret_updated_at TEXT,
    verify_url      TEXT DEFAULT '',            -- optional Skynet pre-check (header/cookie profiles)
    verify_expect_status INTEGER,
    verify_expect_text TEXT DEFAULT '',
    last_verify_at  TEXT, last_verify_ok INTEGER, last_verify_note TEXT,
    created_at TEXT, updated_at TEXT
);
CREATE TABLE auth_profile_targets (
    profile_id INTEGER NOT NULL, target_id INTEGER NOT NULL, added_at TEXT,
    PRIMARY KEY (profile_id, target_id)
);
ALTER TABLE scans ADD COLUMN auth_profile_ids TEXT DEFAULT '[]';
ALTER TABLE scans ADD COLUMN auth_profile_names TEXT DEFAULT '[]';   -- snapshot for history
ALTER TABLE scans ADD COLUMN auth_checks TEXT DEFAULT '[]';          -- pre-check results at start
ALTER TABLE scans ADD COLUMN redact_enc TEXT DEFAULT '';             -- encrypted secret values used; masking only
ALTER TABLE schedules ADD COLUMN auth_profile_ids TEXT DEFAULT '[]';

-- deduplicated findings ---------------------------------------------------
CREATE TABLE finding_groups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL,
    fingerprint   TEXT NOT NULL,
    title TEXT, severity TEXT, cwe TEXT, method TEXT, endpoint TEXT, host TEXT,
    first_seen_at TEXT, first_scan_id INTEGER, last_seen_at TEXT, last_scan_id INTEGER,
    remediation   TEXT NOT NULL DEFAULT 'open', -- open | fixed | accepted | false_positive (manual)
    remediation_note TEXT DEFAULT '', remediation_at TEXT,
    UNIQUE (target_id, fingerprint)
);
CREATE TABLE finding_occurrences (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL,
    scan_id    INTEGER,                         -- latest scan of the run (a resumed scan shares the run)
    run_name   TEXT NOT NULL,
    strix_id   TEXT NOT NULL,                   -- per-run id, e.g. vuln-0001
    title TEXT, severity TEXT, cvss REAL, observed_at TEXT,
    UNIQUE (run_name, strix_id)
);
CREATE INDEX idx_focc_group ON finding_occurrences(group_id);
CREATE INDEX idx_focc_scan ON finding_occurrences(scan_id);

-- discovery inventory ----------------------------------------------------
CREATE TABLE assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL,
    kind       TEXT NOT NULL,                   -- host | service | endpoint | technology
    key        TEXT NOT NULL,                   -- normalized identity
    host TEXT, port INTEGER, scheme TEXT, method TEXT, path TEXT, name TEXT, version TEXT,
    tier       TEXT,                            -- strongest evidence so far: observed | reported
    first_seen_at TEXT, first_scan_id INTEGER, first_run_name TEXT,
    last_seen_at TEXT, last_scan_id INTEGER, last_run_name TEXT,
    attrs      TEXT DEFAULT '{}',
    changed_at TEXT, changed_run_name TEXT, change_note TEXT,
    UNIQUE (target_id, kind, key)
);
CREATE TABLE asset_observations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id  INTEGER NOT NULL,
    scan_id   INTEGER,
    run_name  TEXT NOT NULL,
    source    TEXT NOT NULL,                    -- proxy | finding | coverage | threat_model
    tier      TEXT NOT NULL,                    -- observed | reported
    ref       TEXT NOT NULL,                    -- request id / finding id / coverage surface hash
    evidence  TEXT DEFAULT '',                  -- short, redacted
    attrs     TEXT DEFAULT '{}',
    observed_at TEXT,
    UNIQUE (asset_id, run_name, source, ref)
);
CREATE INDEX idx_aobs_asset ON asset_observations(asset_id);
CREATE INDEX idx_aobs_run ON asset_observations(run_name);
CREATE INDEX idx_assets_target ON assets(target_id, kind);

-- per-run ingestion bookkeeping (findings + inventory) ---------------------
CREATE TABLE run_ingest (
    run_name    TEXT PRIMARY KEY,
    scan_id     INTEGER,
    target_id   INTEGER,
    ingested_at TEXT,
    source_sig  TEXT,                           -- mtimes of the files read; re-ingest when they change
    complete    INTEGER,                        -- coverage.json completeness.complete (NULL = unknown)
    scan_status TEXT, scan_mode TEXT,
    counts      TEXT DEFAULT '{}'
);

-- telemetry ---------------------------------------------------------------
CREATE TABLE scan_telemetry (
    scan_id     INTEGER PRIMARY KEY,
    run_name    TEXT,
    collected_at TEXT,                          -- last time Skynet read Strix's files
    log_offset  INTEGER,                        -- incremental strix.log parse position
    agents_max_id INTEGER DEFAULT 0,            -- incremental agents.db position
    telemetry   TEXT DEFAULT '{}'
);
"""

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "kampanyalar, kimlik profilleri, bulgu tekilleştirme, envanter, telemetri", MIGRATION_1),
]


def schema_version() -> int:
    r = conn().execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return int(r["v"] or 0)


def migrations_applied() -> list[dict[str, Any]]:
    return q("SELECT * FROM schema_migrations ORDER BY version")


def _backup(version: int) -> str:
    bdir = DATA_DIR / "backups"
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    dest = bdir / f"skynet-pre-v{version}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    src.close(); dst.close()
    os.chmod(dest, 0o600)
    return str(dest)


def migrate() -> None:
    conn().execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, "
                   "note TEXT, backup TEXT)")
    current = schema_version()
    pending = [m for m in MIGRATIONS if m[0] > current]
    if not pending:
        return
    has_data = conn().execute("SELECT COUNT(*) FROM targets").fetchone()[0] or conn().execute(
        "SELECT COUNT(*) FROM scans").fetchone()[0]
    backup = _backup(pending[0][0]) if has_data else None
    for version, note, sql in pending:
        c = conn()
        c.execute("BEGIN")
        try:
            clean = "\n".join(ln.split("--", 1)[0] for ln in sql.splitlines())  # no '--' inside literals
            for stmt in (x.strip() for x in clean.split(";")):
                if stmt:
                    c.execute(stmt)
            if version in DATA_MIGRATIONS:
                DATA_MIGRATIONS[version](c)
            c.execute("INSERT INTO schema_migrations(version, applied_at, note, backup) VALUES (?,?,?,?)",
                      (version, now_iso(), note, backup))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise


def _migrate_inline_target_auth(c: sqlite3.Connection) -> None:
    """v1: targets used to carry one inline credential (auth_type/auth_username/auth_secret_enc). Move each into
    an auth profile assigned to that target and attach the target's schedules to it, so scheduled scans keep
    authenticating exactly as before. The inline columns are cleared afterwards (single copy of the secret)."""
    from . import crypto  # local import: crypto must not be needed for a plain db read
    rows = c.execute("SELECT * FROM targets WHERE auth_type IN ('credentials','header')").fetchall()
    for t in rows:
        t = dict(t)
        # decrypt_strict: a key mismatch aborts the migration (rolls back) instead of silently returning "" and
        # then wiping the only copy of the credential below.
        secret = crypto.decrypt_strict(t.get("auth_secret_enc"))
        kind = t["auth_type"]
        payload = {"password": secret} if kind == "credentials" else {"headers": {t.get("auth_header_name") or "Authorization": secret}}
        name, n = f"{t['name']} – {'kullanıcı' if kind == 'credentials' else 'token'}", 1
        while c.execute("SELECT 1 FROM auth_profiles WHERE name=?", (name,)).fetchone():
            n += 1
            name = f"{t['name']} – {'kullanıcı' if kind == 'credentials' else 'token'} {n}"
        now = now_iso()
        cur = c.execute(
            "INSERT INTO auth_profiles (name, kind, description, username, login_url, header_names, notes, secret_enc, "
            "secret_updated_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (name, kind, "Hedefteki eski kimlik doğrulama ayarından otomatik taşındı.",
             t.get("auth_username") or "" if kind == "credentials" else "", t.get("auth_login_url") or "",
             json.dumps([t.get("auth_header_name") or "Authorization"] if kind == "header" else []),
             t.get("auth_notes") or "", crypto.vault_encrypt(json.dumps(payload)) if secret else "", now, now, now))
        pid = cur.lastrowid
        c.execute("INSERT INTO auth_profile_targets(profile_id, target_id, added_at) VALUES (?,?,?)", (pid, t["id"], now))
        c.execute("UPDATE schedules SET auth_profile_ids=? WHERE target_id=?", (json.dumps([pid]), t["id"]))
        # Snapshot the secret into this target's past scans so the plaintext the old flow wrote into their run files
        # stays masked even if this new profile is later rotated or deleted (those scans have no redact_enc yet).
        if secret:
            snap = crypto.vault_encrypt(json.dumps([secret]))
            c.execute("UPDATE scans SET redact_enc=? WHERE target_id=? AND COALESCE(redact_enc,'')=''", (snap, t["id"]))
        c.execute("UPDATE targets SET auth_type='none', auth_secret_enc='', auth_username='', auth_header_name='', "
                  "auth_login_url='', auth_notes='' WHERE id=?", (t["id"],))


DATA_MIGRATIONS = {1: _migrate_inline_target_auth}


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
            d[c] = {} if c in DICT_COLS else []
    return d


def _encode(data: dict[str, Any]) -> dict[str, Any]:
    return {k: (json.dumps(v) if k in JSON_COLS and not isinstance(v, str) and v is not None else v)
            for k, v in data.items()}


TIMESTAMPED = {"llm_profiles", "targets", "schedules", "campaigns", "auth_profiles"}


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
               "sc.name AS schedule_name, cmp.name AS campaign_name FROM scans s "
               "LEFT JOIN targets t ON t.id = s.target_id LEFT JOIN schedules sc ON sc.id = s.schedule_id "
               "LEFT JOIN campaigns cmp ON cmp.id = s.campaign_id")


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
