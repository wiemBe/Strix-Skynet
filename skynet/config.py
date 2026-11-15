"""Process-level configuration. Values come from the environment or a `.env` file in the project root."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"


def _load_dotenv(path: Path) -> None:
    """Minimal KEY=VALUE loader (no interpolation). Real environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        os.environ.setdefault(k, v)


_load_dotenv(PROJECT_DIR / ".env")

DATA_DIR = Path(os.environ.get("SKYNET_DATA") or PROJECT_DIR / "data").expanduser().resolve()
DB_PATH = DATA_DIR / "skynet.db"
LOG_DIR = DATA_DIR / "logs"          # stdout/stderr of each strix process
RUNTIME_DIR = DATA_DIR / "runtime"   # per-scan --config / instruction files (0600, removed after the run)
LEGACY_SECRET_KEY_FILE = DATA_DIR / "secret.key"   # pre-vault location (next to the database); migrated away on start
ADMIN_PASSWORD_FILE = DATA_DIR / "admin_password.txt"

HOST = os.environ.get("SKYNET_HOST", "127.0.0.1")
PORT = int(os.environ.get("SKYNET_PORT", "8787"))
TIMEZONE = os.environ.get("SKYNET_TIMEZONE", "Europe/Istanbul")

ADMIN_USER = os.environ.get("SKYNET_USER", "admin")
ADMIN_PASSWORD = os.environ.get("SKYNET_PASSWORD", "")
SECRET_KEY = os.environ.get("SKYNET_SECRET_KEY", "")
# The encryption key is kept apart from application data so a copy of data/ (database backups, support
# bundles) is not enough to decrypt stored secrets. Override with SKYNET_SECRET_KEY or SKYNET_SECRET_KEY_FILE.
_xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
SECRET_KEY_FILE = Path(os.environ.get("SKYNET_SECRET_KEY_FILE") or Path(_xdg) / "skynet" / "secret.key").expanduser().resolve()
SECRET_KEY_FILE_FROM_ENV = bool(os.environ.get("SKYNET_SECRET_KEY_FILE"))
SESSION_HOURS = int(os.environ.get("SKYNET_SESSION_HOURS", "12"))
COOKIE_SECURE = os.environ.get("SKYNET_COOKIE_SECURE", "0") == "1"

# Defaults used only on first start (afterwards everything is managed in the UI / database).
# The bundled engine (scripts/setup_strix.sh) is preferred; otherwise a separately installed Strix CLI.
_BUNDLED_STRIX = PROJECT_DIR / ".strix-runtime" / "bin" / "strix"
DEFAULT_STRIX_BIN = os.environ.get("SKYNET_STRIX_BIN") or str(
    _BUNDLED_STRIX if _BUNDLED_STRIX.is_file() else Path.home() / ".strix" / "bin" / "strix")
DEFAULT_STRIX_WORKDIR = os.environ.get("SKYNET_STRIX_WORKDIR", str(Path.home()))
USER_STRIX_CONFIG = Path.home() / ".strix" / "cli-config.json"

for d in (DATA_DIR, LOG_DIR, RUNTIME_DIR):
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
