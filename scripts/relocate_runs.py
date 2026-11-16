"""Review/rebase stored run paths after copying an installation to Linux. No Skynet imports or scan execution."""
import argparse
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def relocate(data: Path, workdir: Path, binary: Path, apply=False, allow_missing=False):
    database = data / "skynet.db"
    if not database.is_file() or not workdir.is_dir() or not binary.is_file():
        raise ValueError("Existing database, new workdir, and new Strix executable must exist.")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as c:
        rows = c.execute("SELECT id, run_name, run_dir FROM scans WHERE run_name IS NOT NULL").fetchall()
        old_settings = dict(c.execute("SELECT key,value FROM settings WHERE key IN ('strix_bin','strix_workdir')"))
    changes, missing = [], []
    for sid, name, old in rows:
        if not name or Path(name).name != name or name in (".", ".."):
            missing.append(sid)
            continue
        path = workdir / "strix_runs" / name
        if not path.is_dir():
            missing.append(sid)
        elif str(path) != old:
            changes.append({"scan_id": sid, "run_name": name, "new_path": str(path)})
    wanted = {"strix_bin": str(binary), "strix_workdir": str(workdir)}
    result = {"applied": False, "run_path_updates": changes, "missing_scan_ids": missing, "settings": wanted}
    if not apply:
        return result
    if missing and not allow_missing:
        raise ValueError("Some run folders are missing. Restore them, or review --allow-missing (old paths are preserved).")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True)) as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT 1 FROM scans WHERE status IN ('queued','running','stopping') LIMIT 1").fetchone():
            raise ValueError("Active/queued scans exist. Stop the service and settle them before relocation.")
        if c.execute("SELECT 1 FROM schedules WHERE enabled=1 LIMIT 1").fetchone():
            raise ValueError("Pause schedules before relocation; this tool never changes their enabled state.")
        if not changes and all(old_settings.get(k) == v for k, v in wanted.items()):
            c.rollback()
            return {**result, "applied": True, "unchanged": True}
        backup_dir = data / "backups"
        backup_dir.mkdir(mode=0o700, exist_ok=True)
        backup = backup_dir / ("linux-relocation-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".db")
        # A separate reader includes committed WAL; backing up the writer with an open transaction would block.
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as src, \
             closing(sqlite3.connect(backup)) as dst:
            src.backup(dst)
        os.chmod(backup, 0o600)
        for row in changes:
            c.execute("UPDATE scans SET run_dir=? WHERE id=? AND run_name=?", (row["new_path"], row["scan_id"], row["run_name"]))
        for key, value in wanted.items():
            c.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        c.commit()
    return {**result, "applied": True, "backup": str(backup)}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--strix", type=Path, required=True)
    p.add_argument("--apply", action="store_true", help="Stop the service first. A consistent DB backup is taken.")
    p.add_argument("--allow-missing", action="store_true", help="Preserve missing historical paths rather than dropping records.")
    a = p.parse_args()
    try:
        print(json.dumps(relocate(a.data.resolve(), a.workdir.resolve(), a.strix.expanduser().absolute(), a.apply, a.allow_missing), indent=2))
    except (ValueError, sqlite3.Error, OSError) as e:
        p.exit(1, f"Relocation failed: {e}\n")
