"""Read-only deployment checks. Never imports Skynet, migrates a DB, creates a key, or starts a scan."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from zoneinfo import ZoneInfo


def settings_of(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return dict(c.execute("SELECT key,value FROM settings WHERE key IN ('strix_bin','strix_workdir')")) if "settings" in tables else {}


def key_check(database: Path, key_file: Path, key_env: str = "") -> tuple[bool, str]:
    from cryptography.fernet import Fernet, InvalidToken
    selected = key_env.encode() if key_env else key_file.read_bytes().strip() if key_file.is_file() else None
    encrypted = []
    if database.is_file():
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as c:
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table, column, is_vault in (("llm_profiles", "api_key_enc", False), ("targets", "auth_secret_enc", False),
                    ("auth_profiles", "secret_enc", True), ("scans", "redact_enc", True),
                    ("agent_messages", "content_enc", True), ("analyst_note_revisions", "body_enc", True)):
                cols = {r[1] for r in c.execute(f"PRAGMA table_info({table})")} if table in tables else set()
                if column in cols:
                    encrypted.extend((r[0], is_vault) for r in c.execute(
                        f"SELECT {column} FROM {table} WHERE COALESCE({column},'')<>''"))
            if "settings" in tables:
                encrypted.extend((r[0], False) for r in c.execute(
                    "SELECT value FROM settings WHERE key='api_token_enc' AND COALESCE(value,'')<>''"))
    if selected is None:
        return ((False, "Existing encrypted records require the existing key; nothing was generated.") if encrypted else
                (True, "New installation: first app start may create a key; doctor created nothing."))
    if not key_env and key_file.stat().st_mode & 0o077:
        return False, "Key file permissions must be 0600 (not readable by group/others)."
    try:
        base = Fernet(selected)
        vault = Fernet(base64.urlsafe_b64encode(hmac.new(selected, b"vault-v1", hashlib.sha256).digest()))
        for token, is_vault in encrypted:
            (vault if is_vault else base).decrypt(token.encode())
    except (ValueError, InvalidToken, TypeError):
        return False, "Selected key cannot decrypt stored records. Restore the existing key; do not rotate it."
    return True, f"Existing key is valid; checked {len(encrypted)} encrypted records without showing their contents."


def probe(command: list[str], timeout: int = 30) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError("Command failed (output withheld; inspect the command locally).")
    return result.stdout.strip()


def sqlite_json_check():
    with closing(sqlite3.connect(":memory:")) as c:
        return c.execute("SELECT json_extract('{\"v\":1}', '$.v')").fetchone()[0] == 1


def check(args) -> dict:
    checks = []
    def add(name, fn):
        try:
            value = fn()
            ok, detail = value if isinstance(value, tuple) else (bool(value), str(value))
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}" if isinstance(e, (ValueError, FileNotFoundError)) else type(e).__name__
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
    add("platform", lambda: (platform.system() == "Linux" and platform.machine() == "x86_64",
                              f"{platform.system()}/{platform.machine()} · libc {platform.libc_ver()}"))
    add("python", lambda: (sys.version_info >= (3, 12), platform.python_version()))
    add("timezone", lambda: str(ZoneInfo("Europe/Istanbul")))
    add("password_hash", lambda: bool(hashlib.scrypt(b"probe", salt=b"non-secret-probe", n=2**14, r=8, p=1)))
    add("dependencies", lambda: ", ".join(f"{n}={importlib.metadata.version(n)}" for n in
        ("fastapi", "uvicorn", "apscheduler", "cryptography", "markdown-it-py")))
    add("sqlite_json", sqlite_json_check)
    database = args.data / "skynet.db"
    settings = {}
    try:
        settings = settings_of(database)
    except sqlite3.Error:
        add("database_read", lambda: (False, "Existing database could not be opened read-only."))
    binary = settings.get("strix_bin") or args.strix or str(Path(__file__).resolve().parent.parent / ".strix-runtime/bin/strix")
    runtime = args.runtime
    def binary_check():
        version = probe([str(Path(binary).expanduser()), "--version"])
        return bool(re.search(r"\b1\.7\.0\b", version)), version
    add("strix_binary", binary_check)
    add("messaging_runtime", lambda: probe([str(runtime), "-I", "-c",
        "import importlib.metadata as m; from strix.core.agents import AgentCoordinator; "
        "from agents import RunConfig; assert 'call_model_input_filter' in RunConfig.__dataclass_fields__; "
        "assert m.version('strix-agent') == '1.7.0'; print('Strix 1.7.0; native coordinator and SDK filter available')"]))
    key_file = args.key_file
    legacy = args.data / "secret.key"
    if not key_file.exists() and legacy.is_file() and not os.environ.get("SKYNET_SECRET_KEY"):
        key_file = legacy
    add("encryption", lambda: key_check(database, key_file, os.environ.get("SKYNET_SECRET_KEY", "")))
    for name, path in (("data", args.data), ("key_directory", key_file.parent),
                       ("workdir", Path(settings.get("strix_workdir") or args.workdir or args.data / "work").expanduser())):
        def writable(p=path):
            while not p.exists() and p != p.parent:
                p = p.parent
            return os.access(p, os.W_OK | os.X_OK), "Existing directory or nearest parent is writable." if os.access(p, os.W_OK | os.X_OK) else "Not writable by this account."
        add(name, writable)
    if not args.skip_docker:
        add("docker", lambda: probe([shutil.which("docker") or "docker", "info", "--format", "{{.ServerVersion}}"], 15))
    return {"ok": all(c["ok"] for c in checks), "docker_checked": not args.skip_docker,
            "scan_started": False, "checks": checks}


def main():
    root = Path(__file__).resolve().parent.parent
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=Path(os.environ.get("SKYNET_DATA") or root / "data"))
    p.add_argument("--key-file", type=Path, default=Path(os.environ.get("SKYNET_SECRET_KEY_FILE") or Path.home() / ".config/skynet/secret.key"))
    p.add_argument("--strix", default=os.environ.get("SKYNET_STRIX_BIN"))
    p.add_argument("--runtime", type=Path, default=Path(os.environ.get("SKYNET_STRIX_RUNTIME") or root / ".strix-runtime/bin/python"))
    p.add_argument("--workdir", default=os.environ.get("SKYNET_STRIX_WORKDIR"))
    p.add_argument("--skip-docker", action="store_true", help="QA only: do not claim Docker or scan readiness.")
    args = p.parse_args()
    for name in ("data", "key_file"):
        setattr(args, name, getattr(args, name).expanduser().resolve())
    # Resolving bin/python's symlink selects the system interpreter and loses the venv's site-packages.
    args.runtime = args.runtime.expanduser().absolute()
    result = check(args)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
