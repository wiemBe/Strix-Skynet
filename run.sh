#!/usr/bin/env bash
# Skynet başlatıcı. Yapılandırma: .env (bkz. .env.example) veya ortam değişkenleri.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a
if [ ! -x .venv/bin/python ]; then
  app_python="${SKYNET_PYTHON:-}"
  if [ -z "$app_python" ]; then
    for candidate in python3.12 python3.13 python3.14 python3; do
      if command -v "$candidate" >/dev/null 2>&1; then app_python="$candidate"; break; fi
    done
  fi
  if [ -z "$app_python" ]; then echo "Python not found; RHEL: install python3.12 and python3.12-pip." >&2; exit 1; fi
  "$app_python" -c 'import sys; assert sys.version_info >= (3, 10), "Skynet needs Python 3.10+ (RHEL default 3.9 is too old)."'
  "$app_python" -m venv .venv
  .venv/bin/python -m pip install --only-binary=:all: -r requirements-app.lock
fi
# Bundled Strix engine (vendor/strix -> .strix-runtime). A failure here never blocks Skynet itself:
# scans then use SKYNET_STRIX_BIN / the binary configured in Settings.
if [ ! -x .strix-runtime/bin/strix ]; then
  scripts/setup_strix.sh || echo "Strix runtime was not installed; see the message above." >&2
fi
exec .venv/bin/python -m skynet
