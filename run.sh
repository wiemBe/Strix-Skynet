#!/usr/bin/env bash
# Skynet başlatıcı. Yapılandırma: .env (bkz. .env.example) veya ortam değişkenleri.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
# Bundled Strix engine (vendor/strix -> .strix-runtime). A failure here never blocks Skynet itself:
# scans then use SKYNET_STRIX_BIN / the binary configured in Settings.
if [ ! -x .strix-runtime/bin/strix ]; then
  scripts/setup_strix.sh || echo "Strix runtime was not installed; see the message above." >&2
fi
[ -f .env ] && set -a && . ./.env && set +a
exec .venv/bin/python -m uvicorn skynet.main:app \
  --host "${SKYNET_HOST:-127.0.0.1}" --port "${SKYNET_PORT:-8787}" --no-access-log
