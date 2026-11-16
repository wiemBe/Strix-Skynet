"""Hermetic audit outbox/API checks and real localhost UDP/TCP/TLS receivers."""
import json
from contextlib import closing
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_users_audit import Base
from skynet import audit, db, siem, vault


def payload(packet):
    return json.loads(packet.decode("ascii").split(" - ", 1)[1])


class SIEMBase(Base):
    def setUp(self):
        super().setUp()
        siem.stop()
        siem.save(dict(siem.DEFAULTS))
        db.execute("DELETE FROM syslog_outbox")

    def tearDown(self):
        siem.stop()
        siem.save(dict(siem.DEFAULTS))

    def enable(self, **changes):
        config = {**siem.DEFAULTS, "enabled": True, "transport": "tcp", "host": "127.0.0.1", "port": 1514, **changes}
        siem.save(config)
        return config

    def event(self, **changes):
        audit.record("analyst", "target.update", summary="Edited QA target", status=200, **changes)
        return db.q1("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1")


class TestSIEM(SIEMBase):
    def test_pending_failure_remains_visible_after_another_event_succeeds(self):
        self.enable()
        first = self.event()
        second = self.event()
        with mock.patch.object(siem, "send", side_effect=[OSError("temporary failure"), None]):
            siem.dispatch_once(100)
            siem.dispatch_once(100)
        status = siem.public()["status"]
        self.assertEqual(status["pending"], 1)
        self.assertTrue(status["last_error"], "a later success must not hide an earlier pending retry")

    def test_json_shaped_audit_summaries_remain_original_strings(self):
        self.enable()
        for value in ('0', '123', 'null', 'true', 'false', '{"ticket":42}', '["one"]'):
            audit.record("system", "target.update", summary=value, status=200)
            with mock.patch.object(siem, "send") as send:
                siem.dispatch_once()
            self.assertEqual(payload(send.call_args.args[1])["summary"], value)

    def test_audit_feed_accepts_json_shaped_literal_summary(self):
        admin = self.user("admin")
        for value in ('0', '123', 'null', 'true', 'false', '{"ticket":42}', '["one"]'):
            audit.record("system", "target.update", summary=value, status=200)
            status, response = self.call("/api/audit?action=target.update", user=admin)
            self.assertEqual(status, 200)
            self.assertEqual(response["entries"][0]["summary"], value)

    def test_retry_delay_starts_after_the_slow_attempt_finishes(self):
        self.enable()
        e = self.event()
        with mock.patch.object(siem.time, "monotonic", side_effect=[10.0, 15.0]), \
                mock.patch.object(siem, "send", side_effect=TimeoutError()):
            siem.dispatch_once(100)
        row = db.q1("SELECT * FROM syslog_outbox WHERE audit_id=?", (e["id"],))
        self.assertEqual(row["next_attempt_at"], 107.0)

    def test_admin_api_validation_and_probe_does_not_enable_forwarding(self):
        admin = self.user("admin")
        for role in ("viewer", "analyst"):
            user = self.user(role)
            self.assertEqual(self.call("/api/syslog", user=user)[0], 403)
            self.assertEqual(self.call("/api/syslog", "PUT", {}, user=user)[0], 403)
            self.assertEqual(self.call("/api/syslog/test", "POST", {}, user=user)[0], 403)
        st, body = self.call("/api/syslog", user=admin)
        self.assertEqual(st, 200)
        self.assertFalse(body["settings"]["enabled"])
        for invalid in ({"transport": "http"}, {"enabled": "false"}, {"host": "https://user:password@example"},
                        {"port": 0}, {"port": 65536}, {"facility": 24}, {"verify_tls": False},
                        {"source_hostname": "bad\nhost"}, {"ca_file": "relative.pem"}, {"client_cert": "/tmp/cert"}):
            self.assertEqual(self.call("/api/syslog", "PUT", invalid, user=admin)[0], 400, invalid)
        with mock.patch.object(siem, "send") as send:
            st, body = self.call("/api/syslog/test", "POST", {**siem.DEFAULTS, "host": "127.0.0.1", "transport": "udp"}, user=admin)
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        self.assertFalse(body["ingestion_confirmed"])
        self.assertEqual(payload(send.call_args.args[1])["action"], "syslog.probe")
        self.assertFalse(siem.configuration()["enabled"])

    def test_enable_only_queues_new_events_and_never_sends_in_request(self):
        self.event()
        self.enable()
        admin = self.user("admin")
        with mock.patch.object(siem, "send") as send:
            st, _ = self.call("/api/targets", "POST", {"name": "SIEM fixture", "environment": "test", "base_url": "http://127.0.0.1:8899"}, user=admin)
        self.assertEqual(st, 200)
        send.assert_not_called()
        self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM syslog_outbox")["n"], 1)

    def test_audit_and_outbox_are_one_transaction(self):
        self.enable()
        count = db.q1("SELECT COUNT(*) AS n FROM audit_log")["n"]
        db.conn().execute("CREATE TEMP TRIGGER fail_outbox BEFORE INSERT ON syslog_outbox BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                self.event()
            self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM audit_log")["n"], count)
        finally:
            db.conn().execute("DROP TRIGGER fail_outbox")

    def test_retry_survives_restart_and_keeps_the_same_event_id(self):
        self.enable()
        e = self.event()
        with mock.patch.object(siem, "send", side_effect=TimeoutError("must not persist this text")), \
                mock.patch.object(siem.time, "monotonic", return_value=50.0):
            self.assertTrue(siem.dispatch_once(100))
        row = db.q1("SELECT * FROM syslog_outbox WHERE audit_id=?", (e["id"],))
        self.assertEqual((row["state"], row["attempts"], row["next_attempt_at"], row["last_error"]), ("pending", 1, 102.0, "timeout"))
        self.assertNotIn("must not persist", json.dumps(row))
        instance = siem.configuration()["instance_id"]
        db._conn.close()
        db._conn = None
        db.init()
        self.assertEqual(siem.configuration()["instance_id"], instance)
        self.assertFalse(siem.dispatch_once(101))
        with mock.patch.object(siem, "send") as send:
            self.assertTrue(siem.dispatch_once(103))
            self.assertFalse(siem.dispatch_once(104))
        self.assertEqual(payload(send.call_args.args[1])["event_id"], f"{instance}:{e['id']}")
        self.assertEqual(db.q1("SELECT state FROM syslog_outbox WHERE audit_id=?", (e["id"],))["state"], "handed_off")

    def test_changed_destination_supersedes_backlog_but_identical_save_does_not(self):
        config = self.enable()
        old = self.event()
        generation = siem.configuration()["generation"]
        siem.save(config)
        self.assertEqual(siem.configuration()["generation"], generation)
        self.assertEqual(siem.public()["status"]["pending"], 1)
        self.enable(port=2514)
        self.assertEqual(db.q1("SELECT state FROM syslog_outbox WHERE audit_id=?", (old["id"],))["state"], "superseded")
        new = self.event()
        with mock.patch.object(siem, "send") as send:
            siem.dispatch_once()
        self.assertEqual(send.call_args.args[0]["port"], 2514)
        self.assertTrue(payload(send.call_args.args[1])["event_id"].endswith(":"+str(new["id"])))
        self.event()
        siem.save({**siem.configuration()["settings"], "enabled": False})
        with mock.patch.object(siem, "send") as send:
            self.assertFalse(siem.dispatch_once())
        send.assert_not_called()

    def test_config_change_during_handoff_keeps_honest_attempt_metadata(self):
        self.enable()
        e = self.event()
        def change_during_send(config, packet):
            self.assertEqual(config["port"], 1514)
            self.enable(port=2514)
        with mock.patch.object(siem, "send", side_effect=change_during_send):
            siem.dispatch_once()
        row = db.q1("SELECT * FROM syslog_outbox WHERE audit_id=?", (e["id"],))
        self.assertEqual(row["state"], "superseded")
        self.assertTrue(row["transport_handoff_at"])
        self.assertEqual(siem.public()["status"]["handed_off"], 1)

    def test_v8_upgrade_has_a_backup_stable_instance_and_no_historical_replay(self):
        with tempfile.TemporaryDirectory(prefix="skynet-siem-migrate-") as tmp:
            p, old = Path(tmp), db._conn
            try:
                db._conn = None
                with mock.patch.multiple(db, DB_PATH=p/"skynet.db", DATA_DIR=p):
                    db.conn().executescript(db.SCHEMA)
                    with mock.patch.object(db, "MIGRATIONS", [m for m in db.MIGRATIONS if m[0] <= 7]):
                        db.migrate()
                    audit.record("system", "target.update", summary="Pre-syslog history")
                    db.migrate()
                    config = siem.configuration()
                    self.assertFalse(config["enabled"])
                    self.assertEqual(db.q1("SELECT COUNT(*) AS n FROM syslog_outbox")["n"], 0)
                    backup = Path(db.migrations_applied()[-1]["backup"])
                    self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                    with closing(sqlite3.connect(backup)) as c:
                        self.assertEqual(c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 1)
                        self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='syslog_config'").fetchone())
                    db.migrate()
                    self.assertEqual(siem.configuration()["instance_id"], config["instance_id"])
            finally:
                if db._conn is not None:
                    db._conn.close()
                db._conn = old

    def test_rechecks_masking_at_send_and_escapes_unicode_and_newlines(self):
        self.enable()
        secret = "late-known-siem-credential-" + uuid.uuid4().hex
        audit.record("analyst", "target.update", summary="Türkçe\n<13> forged " + secret, status=403)
        vault.save({"name": "SIEM masking " + uuid.uuid4().hex, "kind": "header", "headers": [{"name": "Authorization", "value": "Bearer " + secret}]}, None)
        with mock.patch.object(siem, "send") as send:
            siem.dispatch_once()
        packet = send.call_args.args[1]
        self.assertNotIn(b"\n", packet)
        self.assertTrue(packet.startswith(b"<132>1 "))  # local0, warning
        event = payload(packet)
        self.assertIn("Türkçe\n", event["summary"])
        self.assertNotIn(secret, json.dumps(event))
        self.assertEqual(event["schema"], "skynet.audit.v1")

    def test_unreadable_masking_context_retries_without_sending(self):
        self.enable()
        self.event()
        tid = db.insert("targets", {"name": "Masking fixture", "base_url": "http://127.0.0.1:8899"})
        sid = db.insert("scans", {"target_id": tid, "redact_enc": "unreadable"})
        try:
            with mock.patch.object(siem, "send") as send:
                siem.dispatch_once()
            send.assert_not_called()
            self.assertEqual(db.q1("SELECT last_error FROM syslog_outbox WHERE state='pending'")["last_error"], "masking")
        finally:
            db.execute("DELETE FROM scans WHERE id=?", (sid,))

    def test_pending_capacity_is_visible_and_local_audit_is_preserved(self):
        marker = "capacity-" + __import__("uuid").uuid4().hex
        db.execute("WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) "
                   "INSERT INTO audit_log(at,actor,action) SELECT '2026-11-16T00:00:00+00:00','system',? FROM seq", (marker,))
        self.enable()
        generation = siem.configuration()["generation"]
        db.execute("INSERT INTO syslog_outbox(audit_id,generation,state) SELECT id,?,'pending' FROM audit_log WHERE action=?", (generation, marker))
        e = self.event()
        self.assertEqual(db.q1("SELECT state FROM syslog_outbox WHERE audit_id=?", (e["id"],))["state"], "overflow")
        self.assertTrue(db.get("audit_log", e["id"]))
        self.assertEqual((siem.public()["status"]["pending"], siem.public()["status"]["overflow"]), (10000, 1))

    def test_udp_real_local_collector(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(3)
            self.enable(transport="udp", port=server.getsockname()[1])
            e = self.event()
            self.assertTrue(siem.dispatch_once())
            packet, _ = server.recvfrom(65535)
        self.assertEqual(payload(packet)["id"], e["id"])
        self.assertFalse(siem.public()["status"]["ingestion_confirmed"])


class TestStreamSIEM(SIEMBase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="skynet-syslog-tls-")
        p = Path(cls.tmp.name)
        cls.cert, cls.key = str(p/"cert.pem"), str(p/"key.pem")
        cfg = p/"openssl.cnf"
        cfg.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nextendedKeyUsage=serverAuth,clientAuth\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", str(cfg), "-keyout", cls.key, "-out", cls.cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def stream(self, secure=False, mutual=False, wrong_name=False, untrusted=False):
        captured = []
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(4)
            def receive():
                try:
                    with server.accept()[0] as conn:
                        conn.settimeout(4)
                        if secure:
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            context.load_cert_chain(self.cert, self.key)
                            if mutual:
                                context.verify_mode = ssl.CERT_REQUIRED
                                context.load_verify_locations(self.cert)
                            stream = context.wrap_socket(conn, server_side=True)
                        else:
                            stream = conn
                        with stream:
                            prefix = b""
                            while not prefix.endswith(b" "):
                                b = stream.recv(1)
                                if not b:
                                    return
                                prefix += b
                            size = int(prefix)
                            packet = b""
                            while len(packet) < size:
                                b = stream.recv(size-len(packet))
                                if not b:
                                    return
                                packet += b
                            captured.append(packet)
                except (OSError, ValueError):
                    pass
            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            self.enable(transport="tls" if secure else "tcp", port=server.getsockname()[1], ca_file=self.cert if secure and not untrusted else "",
                        server_name="wrong.invalid" if wrong_name else "localhost" if secure else "",
                        client_cert=self.cert if mutual else "", client_key=self.key if mutual else "")
            e = self.event()
            siem.dispatch_once()
            thread.join(5)
        if wrong_name or untrusted:
            self.assertEqual(captured, [])
            self.assertEqual(db.q1("SELECT last_error FROM syslog_outbox WHERE audit_id=?", (e["id"],))["last_error"], "tls")
        else:
            self.assertEqual(len(captured), 1)
            self.assertEqual(payload(captured[0])["id"], e["id"])

    def test_tcp_octet_counting(self):
        self.stream()

    def test_tls_validates_ca_and_hostname(self):
        self.stream(secure=True)

    def test_tls_rejects_wrong_hostname(self):
        self.stream(secure=True, wrong_name=True)

    def test_mutual_tls_with_client_certificate(self):
        self.stream(secure=True, mutual=True)

    def test_tls_rejects_untrusted_certificate_authority(self):
        self.stream(secure=True, untrusted=True)

    def test_encrypted_client_key_fails_without_prompt_or_network_connection(self):
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(Path(self.key).read_bytes(), password=None)
        encrypted = Path(self.tmp.name)/"encrypted-key.pem"
        encrypted.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.BestAvailableEncryption(b"qa-only-passphrase")))
        with mock.patch.object(siem.socket, "create_connection") as connection:
            result = siem.test({**siem.DEFAULTS, "host": "127.0.0.1", "ca_file": self.cert,
                                "client_cert": self.cert, "client_key": str(encrypted)})
        connection.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], siem.ERRORS["tls"])


if __name__ == "__main__":
    unittest.main()
