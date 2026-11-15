#!/usr/bin/env bash
# Installs the bundled Strix engine into .strix-runtime/ (a separate Python venv, never Skynet's .venv).
#
#   scripts/setup_strix.sh            # install if missing
#   scripts/setup_strix.sh --force    # rebuild from scratch
#
# Uses vendor/strix/: the official strix-agent wheel (checksum-verified), its Apache-2.0 LICENSE and the exact
# dependency set the runtime was tested with. Python: $SKYNET_STRIX_PYTHON, else the first python3.12 / 3.13 /
# 3.14 on PATH (Strix requires >= 3.12). The sandbox image itself is pulled by Strix through Docker at first scan.
set -euo pipefail
cd "$(dirname "$0")/.."

VENDOR=vendor/strix
WHEEL="$VENDOR/strix_agent-1.7.0-py3-none-macosx_11_0_arm64.whl"
RUNTIME=.strix-runtime
WANT=1.7.0

if [ "${1:-}" != "--force" ] && [ -x "$RUNTIME/bin/strix" ] \
   && [ "$("$RUNTIME/bin/python" -I -c 'import importlib.metadata as m; print(m.version("strix-agent"))' 2>/dev/null)" = "$WANT" ]; then
  echo "Strix $WANT is already installed in $RUNTIME"
  exit 0
fi

if [ "$(uname -s)-$(uname -m)" != "Darwin-arm64" ]; then
  echo "The bundled Strix wheel is for macOS on Apple silicon. On this platform install Strix yourself" >&2
  echo "(https://github.com/usestrix/strix) and set SKYNET_STRIX_BIN, or run: pip install strix-agent==$WANT" >&2
  exit 1
fi

PY="${SKYNET_STRIX_PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.12 python3.13 python3.14; do
    if command -v "$c" >/dev/null 2>&1; then PY="$(command -v "$c")"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "Strix needs Python 3.12-3.14 (none found). Install one, e.g. 'brew install python@3.12'," >&2
  echo "or point SKYNET_STRIX_PYTHON at an interpreter, then run scripts/setup_strix.sh again." >&2
  exit 1
fi

(cd "$VENDOR" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo "Checksum mismatch for $WHEEL" >&2; exit 1; }

echo "Installing Strix $WANT into $RUNTIME with $("$PY" --version 2>&1) ($PY)"
rm -rf "$RUNTIME"
"$PY" -m venv "$RUNTIME"
"$RUNTIME/bin/python" -m pip install -q --upgrade pip
"$RUNTIME/bin/python" -m pip install -q -r "$VENDOR/requirements.lock"
"$RUNTIME/bin/python" -m pip install -q --no-deps "$WHEEL"
"$RUNTIME/bin/python" -m pip check
echo "Installed: $("$RUNTIME/bin/strix" --version)"
