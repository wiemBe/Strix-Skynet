"""Unit tests for the campaign / vault / inventory / telemetry feature set.

Hermetic: SKYNET_DATA and SKYNET_SECRET_KEY_FILE point at a throwaway temp dir created BEFORE skynet is imported,
so importing the package never touches the real data folder, relocates the real key, or migrates the real DB.
Run: python -m unittest discover -s tests   (or: python -m pytest tests)
"""
import json
from contextlib import closing
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

    def test_short_secrets_are_masked(self):
        self.assertNotIn("ab", redact.Redactor(["ab"]).text("password=ab"))


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


class TestVerifyClassify(unittest.TestCase):
    """Read actual Strix-shaped agents.db records; no stubbed evidence readers."""
    @classmethod
    def setUpClass(cls):
        db.init()

    def setUp(self):
        from skynet import verify
        self.V = verify
        self.tmp = tempfile.TemporaryDirectory(prefix="skynet-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.rd = Path(self.tmp.name)
        (self.rd / ".state").mkdir()
        self.c = sqlite3.connect(self.rd / ".state/agents.db")
        self.addCleanup(self.c.close)
        self.c.execute("CREATE TABLE agent_messages(id INTEGER PRIMARY KEY, session_id TEXT, message_data TEXT, created_at TEXT)")
        self.vuln = {"id": "vuln-9", "target": "http://127.0.0.1:8899", "method": "GET", "endpoint": "/api/orders/4",
                     "cwe": "CWE-639", "title": "IDOR", "evidence": "Fresh response exposes another order", "poc_description": "Compare attacker and control requests", "http_exchange_ids": ["11"]}
        self.group = {"id": 9999, "fingerprint": findings_store.fingerprint(self.vuln, {}), "host": "127.0.0.1",
                      "method": "GET", "endpoint": "/api/orders/{id}"}
        self.target = {"base_url": "http://127.0.0.1:8899", "in_scope": [], "out_of_scope": [], "extra_targets": []}
        self.profiles = [{"kind": "header", "header_names": ["Authorization"], "verify_expect_text": "identity:tester", "verify_expect_status": 200}]
        self.profiles[0]["auth_bindings"] = [{"field": "authorization", "digest": verify._binding("header", "authorization", "Bearer current-token")}]
        self.masks = ["Bearer current-token"]
        self.report = {"group_id": 9999, "outcome": "not_reproduced", "test_completed": True,
                       "reason": "Attack compared with control, access denied for foreign order",
                       "probe_request_ids": ["11"], "control_request_ids": ["12"]}

    def msg(self, value):
        self.c.execute("INSERT INTO agent_messages(message_data) VALUES (?)", (json.dumps(value),))
        self.c.commit()

    def view(self, rid, part, content, **extra):
        cid = str(self.c.execute("SELECT COUNT(*) FROM agent_messages").fetchone()[0])
        self.msg({"type": "function_call", "call_id": cid, "name": "view_request",
                  "arguments": json.dumps({"request_id": rid, "part": part})})
        self.msg({"type": "function_call_output", "call_id": cid,
                  "output": json.dumps({"success": True, "content": content, **extra})})

    def traffic(self, marker="identity:tester", auth="Bearer current-token", status=200, host="127.0.0.1:8899"):
        for rid, n in [("11", 4), ("12", 5)]:
            self.view(rid, "request", f"GET /api/orders/{n} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth}\r\n\r\n")
            self.view(rid, "response", f"HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\n\r\n{marker} order:{n}")

    def assessment(self, **kw):
        self.report.update(kw)
        self.msg({"type": "function_call", "call_id": "assessment", "name": "exec_command", "arguments": "{}"})
        self.msg({"type": "function_call_output", "call_id": "assessment",
                  "output": "Process exited with code 0\nOutput:\n" + self.V.MARKER + json.dumps(self.report)})

    def result(self, status="completed", exit_code=0, profiles=None):
        return self.V.classify({"status": status, "exit_code": exit_code}, self.rd, self.group, self.target,
                               self.profiles if profiles is None else profiles)[0]

    def test_clean_exit_without_evidence_is_inconclusive(self):
        self.assertEqual(self.result(), "inconclusive")

    def test_fingerprint_only_is_inconclusive(self):
        (self.rd / "vulnerabilities.json").write_text(json.dumps([self.vuln]))
        self.assertEqual(self.result(), "inconclusive")

    def test_endpoint_200_without_assessment_is_inconclusive(self):
        self.traffic(); self.assertEqual(self.result(), "inconclusive")

    def test_authenticated_negative_requires_in_run_identity(self):
        self.traffic(); self.assessment()
        self.assertEqual(self.result(), "not_reproduced")

    def test_login_page_200_is_inconclusive(self):
        self.traffic(marker="Sign in"); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_redirect_is_inconclusive(self):
        self.traffic(status=302); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_denied_access_is_inconclusive(self):
        self.traffic(status=401); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_wrong_current_credential_is_inconclusive(self):
        self.traffic(auth="Bearer obsolete-token"); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_form_login_without_proof_is_inconclusive(self):
        self.traffic(); self.assessment()
        self.assertEqual(self.result(profiles=[{"kind": "credentials"}]), "inconclusive")

    def test_anonymous_completed_test(self):
        self.traffic(); self.assessment()
        self.assertEqual(self.result(profiles=[]), "not_reproduced")

    def test_cancel_and_interrupt_never_become_negative(self):
        self.traffic(); self.assessment()
        for status in ("cancelled", "interrupted", "running", "queued"):
            self.assertEqual(self.result(status=status), "inconclusive")

    def test_technical_failure(self):
        self.traffic(); self.assessment()
        self.assertEqual(self.result(status="failed", exit_code=1), "error")

    def test_out_of_scope_evidence_is_inconclusive(self):
        self.traffic(host="other.invalid:8899"); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_one_request_is_not_a_test(self):
        self.traffic(); self.assessment(control_request_ids=["11"])
        self.assertEqual(self.result(), "inconclusive")

    def test_test_incomplete(self):
        self.traffic(); self.assessment(test_completed=False)
        self.assertEqual(self.result(), "inconclusive")

    def test_missing_full_response(self):
        self.traffic(); self.assessment()
        self.c.execute("DELETE FROM agent_messages WHERE json_extract(message_data,'$.call_id')='6'"); self.c.commit()
        self.assertEqual(self.result(), "inconclusive")

    def test_session_expired_during_probe(self):
        self.traffic(); self.view("11", "response", "HTTP/1.1 200 OK\n\nSign in"); self.assessment()
        self.assertEqual(self.result(), "inconclusive")

    def test_reverified_needs_new_linked_finding(self):
        self.traffic(); self.assessment(outcome="reverified", finding_id="vuln-9")
        (self.rd / "vulnerabilities.json").write_text(json.dumps([self.vuln]))
        self.assertEqual(self.result(exit_code=2), "reverified")

    def test_reverified_without_poc_is_inconclusive(self):
        self.vuln.pop("poc_description")
        self.traffic(); self.assessment(outcome="reverified", finding_id="vuln-9")
        (self.rd / "vulnerabilities.json").write_text(json.dumps([self.vuln]))
        self.assertEqual(self.result(), "inconclusive")

    def test_contradictory_negative_is_inconclusive(self):
        self.traffic(); self.assessment()
        (self.rd / "vulnerabilities.json").write_text(json.dumps([self.vuln]))
        self.assertEqual(self.result(), "inconclusive")

    def test_marker_in_arguments_is_not_result(self):
        self.traffic()
        self.msg({"type": "function_call", "call_id": "forged", "name": "exec_command",
                  "arguments": json.dumps({"cmd": self.V.MARKER + json.dumps(self.report)})})
        self.assertEqual(self.result(), "inconclusive")


class TestVerificationLifecycle(unittest.TestCase):
    def setUp(self):
        from skynet import runner, verify
        from unittest.mock import patch
        self.R, self.V, self.patch = runner, verify, patch
        db.init()
        self.tid = db.insert("targets", {"name": "Local fixture", "base_url": "http://127.0.0.1:8899", "environment": "test"})
        self.gid = db.insert("finding_groups", {"target_id": self.tid, "fingerprint": "fixture", "remediation": "fixed"})
        self.pid = db.insert("llm_profiles", {"name": "fixture-" + str(self.tid), "provider": "litellm", "model": "fixture"})
        self.target = db.get("targets", self.tid)
        self.opts = {"llm_profile_id": self.pid}

    def enqueue(self):
        return self.R.enqueue(self.target, self.opts, "verify", verification_group_id=self.gid)

    def row(self, sid):
        return db.q1("SELECT * FROM finding_verifications WHERE scan_id=?", (sid,))

    def test_queued_cancel_finishes_verification(self):
        sid = self.enqueue()
        self.assertIsNone(self.row(sid)["started_at"])
        self.assertTrue(self.row(sid)["created_at"])
        self.R.cancel(sid)
        self.assertEqual(self.row(sid)["result"], "inconclusive")
        self.assertEqual(db.get("finding_groups", self.gid)["remediation"], "fixed")

    def test_launch_failure_finishes_verification(self):
        sid = self.enqueue()
        self.R._start(db.get_scan(sid), {"strix_bin": "/missing/strix"})
        self.assertEqual(self.row(sid)["result"], "error")

    def test_scan_and_verification_are_atomic(self):
        with self.patch.object(self.V, "start_record", side_effect=RuntimeError("fixture failure")):
            with self.assertRaises(RuntimeError): self.enqueue()
        self.assertFalse(db.list_scans(target_id=self.tid))

    def test_repeated_enqueue_does_not_duplicate(self):
        sid = self.enqueue()
        with self.assertRaises(self.R.Busy): self.enqueue()
        self.assertEqual(len(db.q("SELECT * FROM finding_verifications WHERE group_id=?", (self.gid,))), 1)
        self.R.cancel(sid)

    def test_finish_does_not_re_resolve_rotated_vault(self):
        sid = self.enqueue()
        db.execute("UPDATE finding_verifications SET profiles=? WHERE scan_id=?", (json.dumps([{"kind": "credentials", "id": 123}]), sid))
        db.update("scans", sid, {"status": "completed", "exit_code": 0})
        with self.patch.object(vault, "resolve", side_effect=AssertionError("must use start snapshot")):
            self.V.finish_record(db.get_scan(sid), Path(_TMP))
        self.assertTrue(self.row(sid)["verification_evidence"]["needs_auth"])

    def test_terminal_recovery_and_idempotence(self):
        sid = self.enqueue()
        db.update("scans", sid, {"status": "failed"})
        self.V.recover_finished(); first = self.row(sid)
        self.V.recover_finished()
        self.assertEqual(first, self.row(sid))
        self.assertEqual(first["result"], "error")

    def test_missing_original_file_still_masks_rotated_secret(self):
        sid=db.insert('scans',{'target_id':self.tid,'run_dir':'/missing/historical-run',
                              'redact_enc':crypto.vault_encrypt(json.dumps(['old-historical-secret']))})
        db.update('finding_groups',self.gid,{'title':'Issue with old-historical-secret'})
        db.insert('finding_occurrences',{'group_id':self.gid,'scan_id':sid,'run_name':'missing-'+str(sid),'strix_id':'vuln-1'})
        detail=self.V.original_detail(db.get('finding_groups',self.gid))
        self.assertNotIn('old-historical-secret',json.dumps(detail))

    def test_profile_binding_survives_redacted_snapshot(self):
        p={"id":123,"kind":"header","name":"Fixture", "header_names":["Authorization"],
           "secret_enc":crypto.vault_encrypt(json.dumps({"headers":{"Authorization":"Bearer current-token"}}))}
        snap=vault.global_redactor().obj(self.V.profile_snapshot([p]), True)
        binding=snap[0]['auth_bindings'][0]
        self.assertEqual(binding['digest'],self.V._binding('header','authorization','Bearer current-token'))
        self.assertNotIn('current-token',json.dumps(snap))

    def test_private_snapshot_never_returned(self):
        from skynet import main
        sid = self.enqueue()
        db.update("scans", sid, {"redact_enc": crypto.vault_encrypt(json.dumps(["old-password"])),
                                 "error": "old-password", "instruction": "old-password"})
        out = main._scan_out(db.get_scan(sid))
        self.assertNotIn("redact_enc", out)
        self.assertNotIn("old-password", json.dumps(out))
        self.R.cancel(sid)

    def test_asset_evidence_remains_text(self):
        self.assertEqual(db._decode({"evidence": "raw inventory reference"})["evidence"], "raw inventory reference")


class TestActivity(unittest.TestCase):
    def setUp(self):
        from skynet import activity
        self.A = activity
        self.tmp = tempfile.TemporaryDirectory(prefix="skynet-activity-")
        self.addCleanup(self.tmp.cleanup)
        self.rd = Path(self.tmp.name)
        (self.rd / ".state").mkdir()
        self.c = sqlite3.connect(self.rd / ".state/agents.db")
        self.addCleanup(self.c.close)
        self.c.execute("CREATE TABLE agent_messages(id INTEGER PRIMARY KEY, session_id TEXT, message_data TEXT, created_at TEXT)")
        self.red = redact.Redactor(["current-secret", "historical-secret"])

    def msg(self, m, agent="a1"):
        self.c.execute("INSERT INTO agent_messages(session_id,message_data,created_at) VALUES(?,?,?)", (agent,json.dumps(m),"2026-11-15 09:00:00"))
        self.c.commit()

    def text(self, text, agent="a1"):
        self.msg({"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":text}]}, agent)

    def read(self, **kw):
        return self.A.read(self.rd, self.red, **kw)

    def test_only_visible_assistant_and_tools(self):
        self.msg({"type":"reasoning", "summary":[{"text":"private reasoning"}]})
        self.msg({"role":"user", "content":"private prompt"})
        self.msg({"type":"message", "role":"assistant", "content":[{"type":"image", "image_url":"private image"}]})
        self.text("visible result")
        r=self.read()
        self.assertEqual([x["text"] for x in r["items"]], ["visible result"])
        self.assertNotIn("private",json.dumps(r))

    def test_cursor_is_incremental_and_idempotent(self):
        self.text("one");self.text("two")
        r=self.read()
        self.assertFalse(self.read(after=r["cursor"])["items"])
        self.text("three")
        self.assertEqual([x["text"] for x in self.read(after=r["cursor"])["items"]],["three"])

    def test_tail_and_pagination(self):
        for n in range(5): self.text(str(n))
        r=self.read(limit=2)
        self.assertEqual([x["text"] for x in r["items"]],["3","4"])
        r=self.read(after=0,limit=2)
        self.assertTrue(r["has_more"])
        self.assertEqual([x["text"] for x in r["items"]],["0","1"])
        self.assertEqual([x["text"] for x in self.read(after=r["cursor"],limit=2)["items"]],["2","3"])

    def test_agent_filter(self):
        self.text("agent one");self.text("agent two", "a2")
        self.assertEqual([x["text"] for x in self.read(agent_id="a2")["items"]],["agent two"])
        self.assertFalse(self.read(agent_id="' OR 1=1 --")["items"])

    def test_tool_output_name_across_pages(self):
        self.msg({"type":"function_call","call_id":"c1","name":"exec_command","arguments":json.dumps({"cmd":"echo safe"})})
        self.msg({"type":"function_call_output","call_id":"c1","output":"safe output"})
        r=self.read(after=1)
        self.assertEqual(r["items"][0]["tool"],"exec_command")
        self.assertEqual(r["items"][0]["kind"],"tool_result")

    def test_current_historical_and_unknown_header_secrets(self):
        self.text("current-secret historical-secret")
        self.msg({"type":"function_call","call_id":"c","name":"send_request","arguments":json.dumps({"headers":{"Authorization":"Bearer unknown-secret"},"password":"tiny"})})
        result=json.dumps(self.read())
        for value in ("current-secret","historical-secret","unknown-secret","tiny"): self.assertNotIn(value,result)

    def test_mask_before_truncation(self):
        secret="secret-which-crosses-limit"
        self.red=redact.Redactor([secret])
        self.text("x"*(self.A.MAX_TEXT-5)+secret+"z"*10)
        result=self.read()["items"][0]
        self.assertNotIn("secre",result["text"])
        self.assertTrue(result["truncated"])

    def test_empty_and_missing_store_are_distinct(self):
        self.assertTrue(self.read()["available"])
        self.assertFalse(self.A.read(None,self.red)["available"])


class TestDataIntegrity(unittest.TestCase):
    def test_missing_metrics_and_measured_zero(self):
        acc=telemetry._fresh_acc()
        t=telemetry._build({},acc)
        self.assertIsNone(t["requests"]["errors"])
        self.assertIsNone(t["retries"]["total"])
        self.assertIsNone(t["latency"]["avg_request_ms"])
        self.assertEqual(telemetry._cached({"input_tokens_details":{"cached_tokens":0}}),0)
        acc["llm_requests"]=1
        self.assertEqual(telemetry._build({},acc)["requests"]["errors"],0)
        self.assertIsNone(telemetry._build({},acc)["latency"]["avg_request_ms"])

    def test_idempotent_finding_and_inventory_ingest(self):
        db.init()
        with tempfile.TemporaryDirectory(prefix="skynet-ingest-") as tmp:
            rd=Path(tmp)
            tid=db.insert("targets",{"name":"Inventory fixture","base_url":"http://127.0.0.1:8899","environment":"test"})
            scan={"id":99999,"target_id":tid,"finished_at":db.now_iso()}
            v={"id":"vuln-1","title":"local fixture","target":"http://127.0.0.1:8899","endpoint":"/x/4","method":"GET","cwe":"CWE-639"}
            (rd/'vulnerabilities.json').write_text(json.dumps([v]))
            (rd/'run.json').write_text(json.dumps({"targets_info":[{"original":"http://127.0.0.1:8899"}]}))
            for _ in range(2):
                findings_store.ingest(scan,rd);inventory.ingest(scan,rd,redact.Redactor())
            self.assertEqual(db.q1("SELECT COUNT(*) n FROM finding_groups WHERE target_id=?",(tid,))["n"],1)
            self.assertEqual(db.q1("SELECT COUNT(*) n FROM finding_occurrences WHERE run_name=?",(rd.name,))["n"],1)
            obs=db.q1("SELECT COUNT(*) n FROM asset_observations WHERE run_name=?",(rd.name,))["n"]
            self.assertGreater(obs,0)
            inventory.ingest(scan,rd,redact.Redactor())
            self.assertEqual(db.q1("SELECT COUNT(*) n FROM asset_observations WHERE run_name=?",(rd.name,))["n"],obs)

    def test_missing_key_never_replaced_with_encrypted_data(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="skynet-key-") as tmp:
            p=Path(tmp)
            with closing(sqlite3.connect(p/'db')) as c, c:
                c.execute("CREATE TABLE llm_profiles(api_key_enc TEXT)")
                c.execute("INSERT INTO llm_profiles VALUES('ciphertext')")
            with patch.multiple(crypto,SECRET_KEY="",SECRET_KEY_FILE=p/'missing.key',LEGACY_SECRET_KEY_FILE=p/'missing-legacy.key',DB_PATH=p/'db'):
                with self.assertRaises(RuntimeError): crypto._load_key()
                self.assertFalse((p/'missing.key').exists())

    def test_backups_include_committed_wal_before_migration(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="skynet-migration-") as tmp:
            p=Path(tmp); old=db._conn
            try:
                db._conn=None
                with patch.multiple(db, DB_PATH=p/'skynet.db', DATA_DIR=p):
                    c=db.conn();c.executescript(db.SCHEMA)
                    c.execute("INSERT INTO settings VALUES('fixture','committed in WAL')")
                    db.migrate()
                    row=db.migrations_applied()[0]
                    with closing(sqlite3.connect(row['backup'])) as b:
                        self.assertEqual(b.execute("SELECT value FROM settings WHERE key='fixture'").fetchone()[0],"committed in WAL")
                        self.assertFalse(b.execute("SELECT 1 FROM sqlite_master WHERE name='finding_verifications'").fetchone())
                    count=len(list((p/'backups').glob('*.db')))
                    db.migrate()
                    self.assertEqual(len(list((p/'backups').glob('*.db'))),count)
            finally:
                if db._conn is not None: db._conn.close()
                db._conn=old

    def test_same_second_rotation_invalidates_redaction_cache(self):
        db.init()
        pid=db.insert('auth_profiles',{'name':'rotation-fixture','kind':'header',
                                      'secret_enc':crypto.vault_encrypt(json.dumps({'headers':{'Authorization':'Bearer first-secret'}}))})
        self.assertNotIn('first-secret',vault.global_redactor().text('first-secret'))
        db.execute("UPDATE auth_profiles SET secret_enc=? WHERE id=?",(crypto.vault_encrypt(json.dumps({'headers':{'Authorization':'Bearer rotated-secret'}})),pid))
        self.assertNotIn('rotated-secret',vault.global_redactor().text('rotated-secret'))

    def test_boolean_session_evidence_is_not_a_secret(self):
        self.assertIs(redact.Redactor().obj({"session":True},True)["session"],True)


class TestAPI(unittest.TestCase):
    """Exercise the real FastAPI middleware and routes, without sockets or workers."""
    def setUp(self):
        from skynet import main, auth
        self.M, self.auth = main, auth
        db.init()
        self.tid=db.insert("targets",{"name":"API local fixture","base_url":"http://127.0.0.1:8899","environment":"test"})
        self.gid=db.insert("finding_groups",{"target_id":self.tid,"fingerprint":"api-fixture","remediation":"fixed"})
        self.pid=db.insert("llm_profiles",{"name":"api-fixture-"+str(self.tid),"provider":"litellm","model":"local-fixture"})

    def request(self, path, method="GET", body=None, session=True, csrf=True):
        import asyncio
        async def invoke():
            delivered=False
            messages=[]
            payload=json.dumps(body).encode() if body is not None else b""
            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered=True
                    return {"type":"http.request","body":payload,"more_body":False}
                await asyncio.Event().wait()
            async def send(m): messages.append(m)
            headers=[(b'content-type',b'application/json')]
            if session: headers.append((b'cookie',f'{self.auth.COOKIE}={self.auth.make_session()}'.encode()))
            if csrf: headers.append((b'x-requested-with',b'skynet'))
            path_only,_,query=path.partition('?')
            scope={"type":"http","asgi":{"version":"3.0","spec_version":"2.4"},"http_version":"1.1","method":method,
                   "scheme":"http","path":path_only,"raw_path":path_only.encode(),"query_string":query.encode(),"root_path":"",
                   "headers":headers,"client":('127.0.0.1',1),"server":('local-test',80)}
            await asyncio.wait_for(self.M.app(scope,receive,send),3)
            status=next(m['status'] for m in messages if m['type']=='http.response.start')
            raw=b''.join(m.get('body',b'') for m in messages if m['type']=='http.response.body')
            return status,json.loads(raw)
        return asyncio.run(invoke())

    def test_activity_requires_session(self):
        self.assertEqual(self.request('/api/scans/1/activity',session=False)[0],401)

    def test_verification_requires_csrf(self):
        self.assertEqual(self.request(f'/api/findings/{self.gid}/verify','POST',{},csrf=False)[0],403)

    def test_verification_options_queue_cancel_and_history(self):
        body={"llm_profile_id":self.pid,"auth_profile_ids":[],"max_budget":0.2,"max_turns":8}  # budget is ignored
        status,result=self.request(f'/api/findings/{self.gid}/verify','POST',body)
        self.assertEqual(status,200)
        sid=result['scan_id']
        self.assertEqual(db.get_scan(sid)['llm_profile_id'],self.pid)
        self.assertEqual(db.get_scan(sid)['max_turns'],8)
        self.assertIsNone(db.get_scan(sid)['max_budget'])          # no cost limit is ever stored
        self.assertEqual(db.get_scan(sid)['scan_mode'],'quick')
        self.assertEqual(self.request(f'/api/findings/{self.gid}/verify','POST',body)[0],409)
        self.assertEqual(self.request(f'/api/scans/{sid}/cancel','POST',{})[0],200)
        status,group=self.request(f'/api/findings/{self.gid}')
        self.assertEqual(group['verifications'][0]['result'],'inconclusive')
        self.assertEqual(group['remediation'],'fixed')
        self.assertEqual(self.request(f'/api/scans/{sid}','DELETE')[0],400)
        self.assertEqual(self.request(f'/api/scans/{sid}/resume','POST',{})[0],400)

    def test_invalid_inputs_do_not_create_scans(self):
        for fields in ({'auth_profile_ids':'bad'}, {'auth_profile_ids':[None]}, {'llm_profile_id':'bad'},
                       {'max_turns':float('nan')}, {'max_turns':float('inf')}, {'max_turns':-1}):
            status,_=self.request(f'/api/findings/{self.gid}/verify','POST',{'llm_profile_id':self.pid,**fields})
            self.assertEqual(status,400,fields)
        self.assertFalse(db.list_scans(target_id=self.tid))

    def test_legacy_verdict_reclassified_without_rerun(self):
        from skynet import verify
        sid=db.insert('scans',{'target_id':self.tid,'status':'completed','exit_code':0,'trigger':'verify'})
        vid=db.insert('finding_verifications',{'target_id':self.tid,'group_id':self.gid,'scan_id':sid,
                                              'result':'not_reproduced','note':'Legacy assertion','classification_version':1})
        verify.recover_finished()
        row=db.get('finding_verifications',vid)
        self.assertEqual(row['result'],'inconclusive')
        self.assertEqual(row['previous_result'],'not_reproduced')
        self.assertEqual(row['previous_note'],'Legacy assertion')
        self.assertEqual(db.get_scan(sid)['status'],'completed')


if __name__ == "__main__":
    unittest.main()
