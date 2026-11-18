"""Automatic runtime discovery, manual overrides and read-only resolution."""
import os
import tempfile
from pathlib import Path
from unittest import mock

import test_users_audit as support
from skynet import db, runtime_paths


class TestRuntimePaths(support.Base):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project, self.home, self.data = (self.root / name for name in ("project", "home", "data"))
        self.project.mkdir()
        self.home.mkdir()
        for patch in (mock.patch.dict(os.environ, {"SKYNET_STRIX_BIN": "", "SKYNET_STRIX_WORKDIR": ""}),
                      mock.patch.object(runtime_paths.Path, "home", return_value=self.home),
                      mock.patch.object(runtime_paths.shutil, "which", return_value=None)):
            patch.start()
            self.addCleanup(patch.stop)

    def binary(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)
        return path

    def resolve(self, **settings):
        return runtime_paths.resolve(settings, project_dir=self.project, data_dir=self.data)

    def test_detection_order_skips_non_executable_and_finds_late_installation(self):
        bundled = self.project / ".strix-runtime/bin/strix"
        user = self.binary(self.home / ".strix/bin/strix")
        self.assertEqual(self.resolve()["strix_bin"], str(user))
        self.binary(bundled)
        self.assertEqual(self.resolve()["strix_bin"], str(bundled))
        bundled.chmod(0o600)
        self.assertEqual(self.resolve()["strix_bin"], str(user))
        user.unlink()
        with mock.patch.object(runtime_paths.shutil, "which", return_value="/fixture/PATH/strix"):
            self.assertEqual(self.resolve()["strix_bin"], "/fixture/PATH/strix")
        self.assertEqual(self.resolve()["strix_bin_source"], "not found")

    def test_environment_and_manual_overrides_never_silently_fall_back(self):
        bundled = self.binary(self.project / ".strix-runtime/bin/strix")
        with mock.patch.dict(os.environ, {"SKYNET_STRIX_BIN": "/missing/env/strix", "SKYNET_STRIX_WORKDIR": "/missing/env/work"}):
            automatic = self.resolve()
            self.assertEqual(automatic["strix_bin"], "/missing/env/strix")
            self.assertEqual(automatic["strix_workdir"], "/missing/env/work")
            self.assertEqual(automatic["strix_bin_source"], "environment")
            manual = self.resolve(strix_bin="custom/strix", strix_workdir="/manual/work")
            self.assertEqual(manual["strix_bin"], str(self.project / "custom/strix"))
            self.assertEqual(manual["strix_bin_override"], "custom/strix")
            self.assertEqual(manual["strix_bin_source"], "manual override")
            self.assertEqual(manual["strix_workdir"], "/manual/work")
        self.assertEqual(self.resolve()["strix_bin"], str(bundled))

    def test_home_workdir_and_data_fallback_do_not_create_directories(self):
        self.assertEqual(self.resolve()["strix_workdir"], str(self.home))
        self.home.rmdir()
        self.assertEqual(self.resolve()["strix_workdir"], str(self.data / "work"))
        self.assertFalse(self.data.exists())

    def test_db_keeps_auto_mode_and_preserves_existing_manual_paths(self):
        before = {key: db.q1("SELECT value FROM settings WHERE key=?", (key,))["value"]
                  for key in ("strix_bin", "strix_workdir")}
        self.addCleanup(db.set_settings, before)
        db.set_settings({"strix_bin": "", "strix_workdir": ""})
        with mock.patch.object(db, "PROJECT_DIR", self.project), mock.patch.object(db, "DATA_DIR", self.data):
            self.assertEqual(db.get_settings()["strix_bin_source"], "not found")
            binary = self.binary(self.project / ".strix-runtime/bin/strix")
            self.assertEqual(db.get_settings()["strix_bin"], str(binary))
            self.assertEqual(db.q1("SELECT value FROM settings WHERE key='strix_bin'")["value"], "")
            db.set_settings({"strix_bin": "/old/explicit/strix"})
            self.assertEqual(db.get_settings()["strix_bin"], "/old/explicit/strix")

    def test_settings_api_manual_override_and_reset_to_automatic(self):
        before = {key: db.q1("SELECT value FROM settings WHERE key=?", (key,))["value"]
                  for key in ("strix_bin", "strix_workdir")}
        self.addCleanup(db.set_settings, before)
        binary = self.binary(self.project / "custom/strix")
        work = self.root / "manual-work"
        work.mkdir()
        admin = self.user("admin")
        with mock.patch.object(self.M.runner, "strix_version", return_value={"version": "fixture"}), \
             mock.patch.object(self.M.control, "bridge_status", return_value={"available": False}), \
             mock.patch.object(self.M.runner, "import_existing_runs") as imported, \
             mock.patch.object(db, "list_scans", return_value=[]):
            status, body = self.call("/api/settings", "PUT", {"strix_bin": str(binary), "strix_workdir": str(work)}, user=admin)
            self.assertEqual(status, 200)
            self.assertEqual(body["strix_bin_override"], str(binary))
            self.assertEqual(body["strix_workdir_source"], "manual override")
            status, body = self.call("/api/settings", "PUT", {"strix_bin": "  ", "strix_workdir": ""}, user=admin)
            self.assertEqual(status, 200)
            self.assertEqual(body["strix_bin_override"], "")
            self.assertEqual(body["strix_workdir_override"], "")
            self.assertEqual(body["strix_workdir"], str(self.home))
            self.assertEqual(db.q1("SELECT value FROM settings WHERE key='strix_workdir'")["value"], "")
            self.assertEqual(imported.call_count, 2)

    def test_invalid_manual_paths_and_running_workdir_change_are_rejected(self):
        admin = self.user("admin")
        nonexec = self.binary(self.root / "nonexec")
        nonexec.chmod(0o600)
        for body in ({"strix_bin": str(nonexec)}, {"strix_bin": "/missing/strix"}, {"strix_workdir": "/missing/work"}):
            self.assertEqual(self.call("/api/settings", "PUT", body, user=admin)[0], 400)
        with mock.patch.object(db, "list_scans", return_value=[{"status": "running"}]), \
             mock.patch.object(self.M.runner, "import_existing_runs") as imported:
            status, body = self.call("/api/settings", "PUT", {"strix_workdir": str(self.root)}, user=admin)
            self.assertEqual(status, 400)
            self.assertIn("running scans", body["detail"])
            imported.assert_not_called()

    def test_existing_run_import_uses_resolved_workdir(self):
        from skynet import runner
        with mock.patch.object(db, "get_settings", return_value={"strix_workdir": str(self.home)}), \
             mock.patch.object(runner.runs, "list_run_dirs", return_value=[]) as listing:
            self.assertEqual(runner.import_existing_runs(), 0)
            listing.assert_called_once_with(str(self.home))
