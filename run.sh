#!/usr/bin/env bash
# Skynet başlatıcı. Yapılandırma: .env (bkz. .env.example) veya ortam değişkenleri.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
[ -f .env ] && set -a && . ./.env && set +a
exec .venv/bin/python -m uvicorn skynet.main:app \
  --host "${SKYNET_HOST:-127.0.0.1}" --port "${SKYNET_PORT:-8787}" --no-access-log
