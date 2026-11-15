"""Unit tests for the campaign / vault / inventory / telemetry feature set.

Hermetic: SKYNET_DATA and SKYNET_SECRET_KEY_FILE point at a throwaway temp dir created BEFORE skynet is imported,
so importing the package never touches the real data folder, relocates the real key, or migrates the real DB.
Run: python -m unittest discover -s tests   (or: python -m pytest tests)
"""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="skynet-test-")
os.environ["SKYNET_DATA"] = str(Path(_TMP) / "data")
os.environ["SKYNET_SECRET_KEY_FILE"] = str(Path(_TMP) / "keys" / "secret.key")
os.environ.setdefault("SKYNET_PASSWORD", "unit-test-password")

from skynet import crypto, db, findings_store, inventory, redact, scope, telemetry, vault  # noqa: E402


class TestScope(unittest.TestCase):
    def test_split(self):
        self.assertEqual(scope.split("https://a.b:8443/x?y=1")[:4], ("https", "a.b", 8443, "/x"))
        self.assertEqual(scope.split("127.0.0.1:8899")[1:3], ("127.0.0.1", 8899))
        self.assertEqual(scope.split("http://h/")[2], 80)

    def test_norm_path(self):
        self.assertEqual(scope.norm_path("/api/orders/123"), "/api/orders/{id}")
        self.assertEqual(scope.norm_path("/a//b/"), "/a/b")
        self.assertEqual(scope.norm_path("/u/550e8400-e29b-41d4-a716-446655440000/x"), "/u/{id}/x")
        self.assertEqual(scope.norm_path("/p?q=1#f"), "/p")

    def test_valid_host(self):
        self.assertTrue(scope.valid_host("127.0.0.1"))
        self.assertTrue(scope.valid_host("a.example.com"))
        self.assertTrue(scope.valid_host("localhost"))
        self.assertFalse(scope.valid_host("not a host"))
        self.assertFalse(scope.valid_host(""))

    def test_label(self):
        t = {"base_url": "http://127.0.0.1:8899", "in_scope": ["127.0.0.1:8899"],
             "out_of_scope": ["/admin"], "extra_targets": []}
        self.assertEqual(scope.label(t, "127.0.0.1", 8899, "/api/me"), "in")
        self.assertEqual(scope.label(t, "127.0.0.1", 8899, "/admin/users"), "out")
        self.assertEqual(scope.label(t, "evil.com", 443, "/"), "out")  # has explicit in_scope -> others out
        t2 = {"base_url": "http://127.0.0.1:8899", "in_scope": [], "out_of_scope": [], "extra_targets": []}
        self.assertEqual(scope.label(t2, "other.com", 443, "/"), "out")   # base_url defines scope -> others out
        self.assertEqual(scope.label(t2, "", None, "/"), "unknown")        # no host -> unknown

    def test_host_map(self):
        info = [{"original": "http://127.0.0.1:8899", "details": {"target_url": "http://host.docker.internal:8899"}}]
        self.assertEqual(scope.host_map(info).get("host.docker.internal"), "127.0.0.1")


class TestFingerprint(unittest.TestCase):
    def test_stable_and_distinct(self):
        hmap = {}
        a = {"id": "vuln-1", "title": "SQLi", "severity": "high", "target": "http://h:8899",
             "endpoint": "/api/orders/5", "method": "GET", "cwe": "CWE-89"}
        b = {"id": "vuln-9", "title": "SQLi here", "severity": "high", "target": "http://h:8899",
             "endpoint": "/api/orders/77", "method": "GET", "cwe": "CWE-89"}  # same after {id} normalization
        c = {"id": "vuln-3", "title": "XSS", "severity": "medium", "target": "http://h:8899",
             "endpoint": "/api/orders/5", "method": "GET", "cwe": "CWE-79"}
        self.assertEqual(findings_store.fingerprint(a, hmap), findings_store.fingerprint(b, hmap))
        self.assertNotEqual(findings_store.fingerprint(a, hmap), findings_store.fingerprint(c, hmap))

    def test_locate_uses_hostmap(self):
        hmap = {"host.docker.internal": "127.0.0.1"}
        v = {"target": "http://host.docker.internal:8899", "endpoint": "/x", "method": "POST"}
        host, method, path = findings_store.locate(v, hmap)
        self.assertEqual((host, method, path), ("127.0.0.1", "POST", "/x"))


class TestRedact(unittest.TestCase):
    def test_value_and_variants(self):
        r = redact.Redactor(["s3cretValue123"])
        self.assertNotIn("s3cretValue123", r.text("token=s3cretValue123 end"))
        # url-encoded variant
        self.assertNotIn("s3cretValue123", r.text("x=s3cretValue123"))
        import urllib.parse
        enc = urllib.parse.quote("a b/c!", safe="")
        self.assertNotIn(enc, redact.Redactor(["a b/c!"]).text(f"q={enc}"))

    def test_strict_patterns(self):
        s = "Authorization: Bearer abcdefabcdef123456\nx-api-key: zzzzzzzzzzzzzzzz"
        out = redact.Redactor([]).text(s, strict=True)
        self.assertNotIn("abcdefabcdef123456", out)
        self.assertIn("Authorization", out)  # header name preserved
        self.assertNotIn("zzzzzzzzzzzzzzzz", out)

    def test_llm_key(self):
        self.assertNotIn("sk-or-v1-abcdefabcdefabcdef", redact.Redactor([]).text("key sk-or-v1-abcdefabcdefabcdef"))

    def test_short_values_ignored(self):
        self.assertIn("ab", redact.Redactor(["ab"]).text("ab"))  # below MIN_LEN, not masked


class TestTelemetryParse(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(telemetry._classify("RateLimitError"), "rate_limit")
        self.assertEqual(telemetry._classify("TimeoutError"), "timeout")
        self.assertEqual(telemetry._classify("litellm.APIError"), "connection")

    def test_parse_log(self):
        log = (
            "2026-11-14 23:06:56.183 DEBUG run - openai.agents: Calling LLM\n"
            "2026-11-14 23:06:59.453 DEBUG run - strix.llm.request_log: llm_request route=litellm provider=openrouter "
            "model=deepseek/x outcome=success status=200 duration_ms=3268 ttft_ms=2612 in=100 out=5 cost=0.004 agent=a1 attempt=0\n"
            "2026-11-14 23:07:00.000 WARNING run - strix.core.execution: transient model/provider error for a1; "
            "replaying turn (attempt 1/5, backoff 2.0s): RateLimitError(\"429\")\n"
            "2026-11-14 23:07:01.000 DEBUG - - strix.interface.viewer.server: viewer GET /\n"
            "2026-11-14 23:07:02.000 DEBUG run - strix.report.usage: LiteLLM cost estimate unavailable for model x\n"
        )
        p = Path(_TMP) / "strix.log"
        p.write_text(log)
        acc = telemetry._fresh_acc()
        off = telemetry._parse_log(p, 0, acc)
        self.assertEqual(acc["calling_llm"], 1)
        self.assertEqual(acc["llm_requests"], 1)
        self.assertEqual(acc["retries"]["rate_limit"], 1)
        self.assertTrue(acc["cost_na"])
        # viewer line excluded from last_activity (last real line is the cost-estimate one at 23:07:02)
        self.assertEqual(acc["last_activity_local"], "2026-11-14 23:07:02.000")
        # incremental: re-parsing from the stored offset adds nothing
        acc2 = dict(acc)
        telemetry._parse_log(p, off, acc)
        self.assertEqual(acc["llm_requests"], acc2["llm_requests"])

    def test_cost_source(self):
        self.assertEqual(telemetry._cost({"cost": 0.01, "providers": {"X": {}}}, False)["source"], "provider")
        self.assertEqual(telemetry._cost({"cost": 0.01}, False)["source"], "estimate")
        self.assertEqual(telemetry._cost({"cost": 0.0}, True)["source"], "unknown")
        self.assertIsNone(telemetry._cost({"cost": 0.0}, True)["value"])

    def test_local_to_utc(self):
        # naive local time converted using the host offset -> an aware UTC ISO string
        out = telemetry._local_to_utc("2026-11-14 23:06:55.837")
        self.assertTrue(out.endswith("+00:00"))


class TestMigration(unittest.TestCase):
    """Build a pre-migration DB with a legacy inline credential + a past scan, then migrate and assert the
    credential moved into an assigned profile and the scan got a redaction snapshot."""
    def setUp(self):
        # Fresh DB file for this test, using the already-initialised schema version 0 shape.
        self.path = Path(_TMP) / "mig.db"
        if self.path.exists():
            self.path.unlink()

    def test_inline_auth_migration(self):
        # Seed a v0 database by creating the base schema only, then inserting a legacy target + scan.
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        con.executescript(db.SCHEMA)
        secret_enc = crypto.encrypt("hunter2password")
        con.execute("INSERT INTO targets (id, name, environment, base_url, auth_type, auth_username, auth_secret_enc, "
                    "created_at, updated_at) VALUES (1,'T','test','http://127.0.0.1:8899','credentials','tester',?,?,?)",
                    (secret_enc, db.now_iso(), db.now_iso()))
        con.execute("INSERT INTO scans (id, target_id, name, status, run_name) VALUES (7,1,'T','completed','r7')")
        con.execute("INSERT INTO schedules (id, target_id, kind, timezone, llm_profile_id) VALUES (3,1,'daily','UTC',1)")
        con.commit(); con.close()
        # Run just MIGRATION_1 + its data migration against this connection.
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row   # _migrate_inline_target_auth reads rows as dicts
        con.execute("PRAGMA foreign_keys=ON")
        clean = "\n".join(ln.split("--", 1)[0] for ln in db.MIGRATION_1.splitlines())
        for stmt in (x.strip() for x in clean.split(";")):
            if stmt:
                con.execute(stmt)
        db._migrate_inline_target_auth(con)
        con.commit()
        con.row_factory = sqlite3.Row
        prof = con.execute("SELECT * FROM auth_profiles").fetchone()
        self.assertIsNotNone(prof)
        self.assertEqual(prof["kind"], "credentials")
        self.assertEqual(prof["username"], "tester")
        self.assertEqual(json.loads(crypto.vault_decrypt(prof["secret_enc"]))["password"], "hunter2password")
        # target assigned, inline secret cleared
        self.assertEqual(con.execute("SELECT target_id FROM auth_profile_targets").fetchone()["target_id"], 1)
        self.assertEqual(con.execute("SELECT auth_secret_enc FROM targets WHERE id=1").fetchone()["auth_secret_enc"], "")
        # schedule linked to the new profile
        self.assertEqual(json.loads(con.execute("SELECT auth_profile_ids FROM schedules WHERE id=3").fetchone()[0]), [prof["id"]])
        # past scan got a redaction snapshot that still decrypts to the secret
        snap = con.execute("SELECT redact_enc FROM scans WHERE id=7").fetchone()["redact_enc"]
        self.assertTrue(snap)
        self.assertIn("hunter2password", json.loads(crypto.vault_decrypt(snap)))
        con.close()


if __name__ == "__main__":
    unittest.main()
