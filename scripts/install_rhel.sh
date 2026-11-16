#!/usr/bin/env bash
# Run on the target RHEL host after installing Python 3.12 and Docker Engine. Never starts the service.
set -euo pipefail
source_dir="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]; then
  echo "This installer targets RHEL 9.4+ x86_64." >&2; exit 1
fi
if [ "$(id -u)" != 0 ]; then echo "Run with sudo on the target RHEL host." >&2; exit 1; fi
. /etc/os-release
if [ "${ID:-}" != rhel ] || ! python3.12 -c 'import sys; sys.exit(0 if (3,12)<=sys.version_info[:2]<(3,15) else 1)'; then
  echo "RHEL and Python 3.12 are required. Install python3.12 and python3.12-pip first." >&2; exit 1
fi
if ! python3.12 - "$VERSION_ID" <<'PY'
import sys
v=tuple(map(int,sys.argv[1].split('.')[:2])); raise SystemExit(0 if (9,4)<=v<(10,0) else 1)
PY
then echo "This service installer is validated for RHEL 9.4+ (9.x)." >&2; exit 1; fi
if ! command -v docker >/dev/null || ! getent group docker >/dev/null; then
  echo "Install Docker Engine first (docs/RHEL.md). Existing Podman installations are not modified." >&2; exit 1
fi
if systemctl is-active --quiet skynet.service; then
  echo "Stop Skynet and finish/cancel its scans before updating: systemctl stop skynet" >&2; exit 1
fi
if ! id skynet >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/skynet --shell /sbin/nologin skynet
elif [ "$(id -u skynet)" = 0 ]; then echo "Refusing a root service account." >&2; exit 1; fi
install -d -m 0755 /opt/skynet
install -d -m 0700 -o skynet -g skynet /var/lib/skynet /var/lib/skynet-keys
install -d -m 0700 -o skynet -g skynet /var/lib/skynet/work
install -d -m 0700 /etc/skynet
if [ "$source_dir" != /opt/skynet ]; then
  # Explicit allowlist: never copy .env, .git, data, keys, local venvs, or QA history to the server.
  tar -C "$source_dir" -cf - skynet scripts vendor deploy requirements.txt requirements-app.lock run.sh README.md |
    tar -C /opt/skynet -xf -
  install -d -m 0755 /opt/skynet/docs
  install -m 0644 "$source_dir/docs/RHEL.md" /opt/skynet/docs/RHEL.md
  install -m 0644 "$source_dir/docs/NGINX.md" /opt/skynet/docs/NGINX.md
  install -m 0644 "$source_dir/docs/SYSLOG.md" /opt/skynet/docs/SYSLOG.md
fi
cd /opt/skynet
if [ ! -x .venv/bin/python ]; then python3.12 -m venv .venv; fi
.venv/bin/python -c 'import sys; assert sys.version_info >= (3,12), "Existing app venv is too old; preserve it and rebuild with Python 3.12."'
.venv/bin/python -m pip install --only-binary=:all: -r requirements-app.lock
.venv/bin/python -m pip check
SKYNET_STRIX_PYTHON=/usr/bin/python3.12 bash scripts/setup_strix.sh
if [ ! -e /etc/skynet/skynet.env ]; then
  install -m 0600 deploy/rhel/skynet.env.example /etc/skynet/skynet.env
else
  echo "Preserved existing /etc/skynet/skynet.env, data, and keys."
fi
install -m 0644 deploy/rhel/skynet.service /etc/systemd/system/skynet.service
systemctl daemon-reload
echo "Installed. Docker access in the service is privileged (SupplementaryGroups=docker)."
echo "Before starting: read docs/RHEL.md, restore the existing key/database if migrating, then run the doctor."
echo "Start explicitly: systemctl enable --now skynet"
