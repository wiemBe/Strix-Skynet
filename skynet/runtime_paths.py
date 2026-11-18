"""Resolve automatic runtime paths without installing software or changing stored overrides."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def _absolute(value: str, project_dir: Path) -> str:
    path = Path(value).expanduser()
    return str(path if path.is_absolute() else project_dir / path)


def _binary(project_dir: Path) -> tuple[str, str]:
    if value := os.environ.get("SKYNET_STRIX_BIN", "").strip():
        return _absolute(value, project_dir), "environment"
    candidates = [(project_dir / ".strix-runtime/bin/strix", "bundled"),
                  (Path.home() / ".strix/bin/strix", "user installation")]
    for path, source in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path), source
    if value := shutil.which("strix"):
        return _absolute(value, project_dir), "PATH"
    # Show where the bundled installer would put it, but never install or fall back silently.
    return str(candidates[0][0]), "not found"


def _workdir(project_dir: Path, data_dir: Path) -> tuple[str, str]:
    if value := os.environ.get("SKYNET_STRIX_WORKDIR", "").strip():
        return _absolute(value, project_dir), "environment"
    home = Path.home()
    if home.is_dir() and os.access(home, os.W_OK | os.X_OK):
        return str(home), "home directory"
    # Created on scan launch, not while reading settings or importing existing runs.
    return str(data_dir / "work"), "application data"


def resolve(settings: dict[str, str], *, project_dir: Path, data_dir: Path) -> dict[str, str]:
    out = {}
    for key, (auto, source) in (("strix_bin", _binary(project_dir)),
                                ("strix_workdir", _workdir(project_dir, data_dir))):
        override = (settings.get(key) or "").strip()
        out.update({key: _absolute(override, project_dir) if override else auto,
                    key + "_override": override, key + "_source": "manual override" if override else source,
                    key + "_auto": auto})
    return out
