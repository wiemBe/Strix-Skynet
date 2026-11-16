"""Platform selection, installation failure recovery, and key-preserving read-only deployment checks."""
import base64
import hashlib
import hmac
import importlib.util
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


setup = module("setup_strix")
doctor = module("doctor")
relocation = module("relocate_runs")


class TestDeployment(unittest.TestCase):
    def test_relocation_is_reviewable_backed_up_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            work = root / "work"
            (work / "strix_runs/run-1").mkdir(parents=True)
            binary = root / "strix"
            binary.write_text("fixture")
            database = data / "skynet.db"
            with sqlite3.connect(database) as c:
                c.executescript("CREATE TABLE scans(id INTEGER PRIMARY KEY,run_name TEXT,run_dir TEXT,status TEXT);"
                    "CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);CREATE TABLE schedules(enabled INTEGER);")
                c.execute("INSERT INTO scans VALUES (1,'run-1','/old/mac/run-1','completed')")
                c.execute("INSERT INTO settings VALUES ('strix_bin','/old/mac/strix')")
            original = database.read_bytes()
            planned = relocation.relocate(data, work, binary)
            self.assertFalse(planned["applied"])
            self.assertEqual(database.read_bytes(), original)
            applied = relocation.relocate(data, work, binary, apply=True)
            with sqlite3.connect(applied["backup"]) as c:
                self.assertEqual(c.execute("SELECT run_dir FROM scans").fetchone()[0], "/old/mac/run-1")
            with sqlite3.connect(database) as c:
                self.assertEqual(c.execute("SELECT run_dir FROM scans").fetchone()[0], str(work / "strix_runs/run-1"))
            self.assertTrue(relocation.relocate(data, work, binary, apply=True)["unchanged"])
            self.assertEqual(len(list((data / "backups").glob("*.db"))), 1)
            with sqlite3.connect(database) as c:
                c.execute("INSERT INTO schedules VALUES (1)")
            with self.assertRaisesRegex(ValueError, "Pause schedules"):
                relocation.relocate(data, work, binary, apply=True)

    def test_official_artifacts_match_platform_and_checksums(self):
        for system, machine in (("Linux", "x86_64"), ("Darwin", "arm64")):
            path = setup.verify_wheel(ROOT / "vendor/strix", setup.artifact(system, machine))
            self.assertTrue(path.is_file())
        with self.assertRaisesRegex(ValueError, "No bundled"):
            setup.artifact("Linux", "unknown")

    def test_tampering_fails_before_any_environment_change(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            vendor = project / "vendor/strix"
            vendor.mkdir(parents=True)
            name = setup.artifact("Linux", "x86_64")
            (vendor / name).write_bytes(b"changed wheel")
            (vendor / "SHA256SUMS").write_text("0" * 64 + "  " + name)
            with mock.patch.object(setup.platform, "system", return_value="Linux"), \
                 mock.patch.object(setup.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(setup.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
                    setup.install(project, force=True)
                run.assert_not_called()
            self.assertFalse((project / ".strix-runtime").exists())

    def test_failed_force_install_restores_old_runtime_and_leaves_data_alone(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            old = p / ".strix-runtime"
            old.mkdir()
            (old / "old-runtime").write_text("preserve")
            data = p / "data"
            data.mkdir()
            (data / "key-and-data-sentinel").write_text("untouched")
            vendor = p / "vendor/strix"
            vendor.mkdir(parents=True)
            (vendor / "requirements.lock").write_text("dependency==1\n")
            wheel = vendor / "fixture.whl"
            wheel.write_bytes(b"verified by mocked verifier")
            def fail(command, **kw):
                if "venv" in command:
                    old.mkdir()
                    (old / "partial").write_text("incomplete")
                    return
                raise subprocess.CalledProcessError(1, command)
            with mock.patch.object(setup, "verify_wheel", return_value=wheel), \
                 mock.patch.object(setup.sys, "version_info", (3, 12, 0)), \
                 mock.patch.object(setup.subprocess, "run", side_effect=fail):
                with self.assertRaises(subprocess.CalledProcessError):
                    setup.install(p, force=True)
            self.assertEqual((old / "old-runtime").read_text(), "preserve")
            self.assertFalse((old / "partial").exists())
            self.assertEqual((data / "key-and-data-sentinel").read_text(), "untouched")

    def test_doctor_missing_key_never_generates_one(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            key = p / "keys/secret.key"
            database = p / "skynet.db"
            self.assertTrue(doctor.key_check(database, key)[0])
            self.assertFalse(key.exists())
            with sqlite3.connect(database) as c:
                c.execute("CREATE TABLE auth_profiles(secret_enc TEXT)")
                c.execute("INSERT INTO auth_profiles VALUES ('encrypted-existing-record')")
            before = database.read_bytes()
            self.assertFalse(doctor.key_check(database, key)[0])
            self.assertFalse(key.exists())
            self.assertEqual(database.read_bytes(), before)

    def test_doctor_verifies_master_and_vault_key_without_leaking_or_writing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            key = Fernet.generate_key()
            key_file = p / "secret.key"
            key_file.write_bytes(key)
            key_file.chmod(0o600)
            v = Fernet(base64.urlsafe_b64encode(hmac.new(key, b"vault-v1", hashlib.sha256).digest()))
            database = p / "skynet.db"
            with sqlite3.connect(database) as c:
                c.execute("CREATE TABLE llm_profiles(api_key_enc TEXT)")
                c.execute("CREATE TABLE auth_profiles(secret_enc TEXT)")
                c.execute("INSERT INTO llm_profiles VALUES (?)", (Fernet(key).encrypt(b"private-provider-key").decode(),))
                c.execute("INSERT INTO auth_profiles VALUES (?)", (v.encrypt(b"private-vault-secret").decode(),))
            before = database.read_bytes(), key_file.read_bytes()
            result = doctor.key_check(database, key_file)
            self.assertTrue(result[0])
            self.assertNotIn("private", json.dumps(result))
            self.assertEqual((database.read_bytes(), key_file.read_bytes()), before)
            key_file.write_bytes(Fernet.generate_key())
            self.assertFalse(doctor.key_check(database, key_file)[0])
            key_file.chmod(0o644)
            self.assertFalse(doctor.key_check(database, key_file)[0])

    def test_service_uses_one_queue_owner_and_shared_docker_temp_paths(self):
        service = (ROOT / "deploy/rhel/skynet.service").read_text()
        self.assertIn("ExecStart=/opt/skynet/.venv/bin/python -m skynet", service)
        self.assertNotIn("PrivateTmp=true", service)
        self.assertNotIn("--workers", service)
        self.assertIn("UMask=0077", service)
        self.assertIn("SKYNET_LOAD_DOTENV=0", service)

    def test_doctor_preserves_the_virtualenv_interpreter_path(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "runtime/bin/python"
            runtime.parent.mkdir(parents=True)
            runtime.symlink_to(Path(__import__("sys").executable))
            with mock.patch.object(doctor.sys, "argv", ["doctor.py", "--runtime", str(runtime)]), \
                 mock.patch.object(doctor, "check", return_value={"ok": True}) as check, \
                 mock.patch("builtins.print"):
                self.assertEqual(doctor.main(), 0)
            self.assertEqual(check.call_args.args[0].runtime, runtime)
