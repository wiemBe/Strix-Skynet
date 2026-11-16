"""Install the pinned, platform-specific official Strix wheel. Standard library only; no Skynet imports."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.7.0"
ARTIFACTS = {
    ("Darwin", "arm64"): "strix_agent-1.7.0-py3-none-macosx_11_0_arm64.whl",
    ("Linux", "x86_64"): "strix_agent-1.7.0-py3-none-manylinux_2_17_x86_64.whl",
}


def artifact(system: str, machine: str) -> str:
    try:
        return ARTIFACTS[(system, machine)]
    except KeyError:
        raise ValueError(f"No bundled Strix {VERSION} wheel for {system}/{machine}. "
                         "Supported: Linux/x86_64 and Darwin/arm64. Set a separately installed SKYNET_STRIX_BIN.") from None


def verify_wheel(vendor: Path, name: str) -> Path:
    expected = {}
    for line in (vendor / "SHA256SUMS").read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            expected[parts[1].lstrip("*")] = parts[0]
    wheel = vendor / name
    if name not in expected or not wheel.is_file():
        raise ValueError(f"Bundled wheel or checksum is missing: {name}")
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected[name]:
        raise ValueError(f"Checksum mismatch: {name}; nothing was installed.")
    return wheel


def installed_version(runtime: Path) -> str:
    try:
        p = subprocess.run([str(runtime / "bin/python"), "-I", "-c",
                            "import importlib.metadata as m; print(m.version('strix-agent'))"],
                           capture_output=True, text=True, timeout=30)
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def install(project: Path, force: bool = False, check_only: bool = False) -> dict:
    name = artifact(platform.system(), platform.machine())
    wheel = verify_wheel(project / "vendor/strix", name)
    lock = project / "vendor/strix/requirements.lock"
    result = {"version": VERSION, "wheel": name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
              "dependencies_sha256": hashlib.sha256(lock.read_bytes()).hexdigest()}
    if check_only:
        return result
    if not (3, 12) <= sys.version_info[:2] < (3, 15):
        raise ValueError("Strix requires Python 3.12–3.14. On RHEL 9.4+: dnf install python3.12 python3.12-pip")
    runtime = project / ".strix-runtime"
    if runtime.is_symlink():
        raise ValueError("Refusing to replace a symlinked .strix-runtime; manage that environment explicitly.")
    if not force and installed_version(runtime) == VERSION and (runtime / "bin/strix").is_file():
        return {**result, "status": "already_installed"}
    if runtime.exists() and not force:
        raise ValueError(".strix-runtime exists but is not usable. Stop Skynet/scans, then use --force; "
                         "the existing environment will be backed up, not silently deleted.")
    backup = None
    if runtime.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        backup = runtime.with_name(f".strix-runtime.backup-{stamp}")
        runtime.rename(backup)
    try:
        subprocess.run([sys.executable, "-m", "venv", str(runtime)], check=True)
        py = str(runtime / "bin/python")
        pip = [py, "-m", "pip", "--disable-pip-version-check", "--require-virtualenv"]
        subprocess.run([*pip, "install", "--only-binary=:all:", "-r", str(lock)], check=True)
        subprocess.run([*pip, "install", "--no-deps", str(wheel)], check=True)
        subprocess.run([*pip, "check"], check=True)
        if installed_version(runtime) != VERSION:
            raise ValueError("Installed Strix version does not match the pinned artifact.")
        subprocess.run([str(runtime / "bin/strix"), "--version"], check=True)
        (runtime / "skynet-install.json").write_text(json.dumps(result, indent=2) + "\n")
    except BaseException:
        if runtime.exists():
            shutil.rmtree(runtime)
        if backup:
            backup.rename(runtime)
        raise
    return {**result, "status": "installed", "previous_runtime": str(backup) if backup else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Stop scans first. Preserve the old venv and rebuild.")
    parser.add_argument("--check", action="store_true", help="Verify the selected bundled artifact without installing.")
    args = parser.parse_args()
    try:
        print(json.dumps(install(Path(__file__).resolve().parent.parent, args.force, args.check)))
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print(f"Strix setup failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
