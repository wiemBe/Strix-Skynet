#!/usr/bin/env bash
# Python performs platform selection and checksum verification.
set -euo pipefail
cd "$(dirname "$0")/.."
strix_python="${SKYNET_STRIX_PYTHON:-}"
if [ -z "$strix_python" ]; then
  for candidate in python3.12 python3.13 python3.14 .strix-runtime/bin/python; do
    if command -v "$candidate" >/dev/null 2>&1; then strix_python="$candidate"; break; fi
  done
fi
if [ -z "$strix_python" ]; then
  echo "Strix requires Python 3.12–3.14. RHEL 9.4+: sudo dnf install python3.12 python3.12-pip" >&2
  echo "Or set SKYNET_STRIX_PYTHON to the interpreter path." >&2
  exit 1
fi
exec "$strix_python" scripts/setup_strix.py "$@"
