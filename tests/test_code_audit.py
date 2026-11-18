"""Cross-module regressions found by the application source review; disposable data only."""
import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import mock

import test_users_audit as support
from skynet import control, crypto, db, evidence, inventory, llm, redact, runs, scope, vault, workspace


class TestCodeAudit(support.Base):
    def fixture(self):
        return support.TestReport.fixture(self)

    def scan_snapshot(self, tid, run, values):
        return db.insert("scans", {"target_id": tid, "run_name": run, "status": "completed",
                         "redact_enc": crypto.vault_encrypt(json.dumps(values))})

    def test_campaign_history_filters_before_limiting(self):
        tid, sid, *_ = self.fixture()
        cid = db.insert("campaigns", {"name": "Old campaign history"})
        db.update("scans", sid, {"campaign_id": cid})
        db.conn().executemany("INSERT INTO scans (target_id,status,started_at) VALUES (?,?,?)",
                             [(tid, "completed", "2099-01-01T00:00:00Z")] * 210)
        status, body = self.call(f"/api/campaigns/{cid}", user=self.user("viewer"))
        self.assertEqual(status, 200)
        self.assertEqual([s["id"] for s in body["scans"]], [sid])

    def test_resumed_run_keeps_old_and_new_secret_masks(self):
        tid, _, _, gid, _ = self.fixture()
        old, new = support._uniq("old-value-"), support._uniq("new-value-")
        run = support._uniq("shared-run-")
        self.scan_snapshot(tid, run, [old])
        sid = self.scan_snapshot(tid, run, [new])
        db.execute("UPDATE finding_occurrences SET scan_id=?,run_name=? WHERE group_id=?", (sid, run, gid))
        for red in (vault.scan_redactor(db.get_scan(sid)), vault.finding_redactor(gid)):
            self.assertEqual(red.text(old + " " + new), redact.MASK + " " + redact.MASK)

    def test_unreadable_snapshot_does_not_disable_masking_silently(self):
        tid, _, _, gid, _ = self.fixture()
        sid = db.q1("SELECT scan_id FROM finding_occurrences WHERE group_id=?", (gid,))["scan_id"]
        try:
            for invalid in ("broken-ciphertext", crypto.vault_encrypt('{"not": "a list"}')):
                db.update("scans", sid, {"redact_enc": invalid})
                with self.assertRaises(crypto.DecryptError):
                    vault.scan_redactor(db.get_scan(sid))
                with self.assertRaises(crypto.DecryptError):
                    vault.finding_redactor(gid)
                self.assertEqual(self.call(f"/api/scans/{sid}", user=self.user("viewer"))[0], 503)
        finally:
            db.update("scans", sid, {"redact_enc": ""})

    def test_corrupt_current_profile_is_not_ignored_by_global_masking(self):
        pid = db.insert("auth_profiles", {"name": support._uniq("unreadable"), "kind": "header", "secret_enc": "broken"})
        try:
            with self.assertRaises(crypto.DecryptError):
                vault.global_redactor()
        finally:
            db.delete("auth_profiles", pid)

    def test_log_preview_never_returns_fragments_at_byte_boundaries(self):
        tid, sid, *_ = self.fixture()
        secret = "credential-boundary-" + "z" * 40
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp)
            db.update("scans", sid, {"run_dir": str(rd), "redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
            viewer = self.user("viewer")
            # A caller can supply an offset inside a known secret.
            (rd / "strix.log").write_text("prefix " + secret + "\nnormal line\n")
            status, body = self.call(f"/api/scans/{sid}/log?offset=14", user=viewer)
            self.assertEqual(status, 200)
            self.assertNotIn(secret[7:], body["text"])
            self.assertIn("normal line", body["text"])
            # A single long line must not leak a secret prefix at the preview limit.
            (rd / "strix.log").write_text("x" * 255990 + secret + "\nnormal line\n")
            cursor = 0
            for _ in range(3):
                _, body = self.call(f"/api/scans/{sid}/log?offset={cursor}", user=viewer)
                self.assertNotIn(secret[:10], body["text"])
                self.assertNotIn(secret[10:], body["text"])
                cursor = body["offset"]
            # A short unfinished line is withheld until its newline arrives.
            (rd / "strix.log").write_text(secret[:12])
            _, body = self.call(f"/api/scans/{sid}/log?offset=0", user=viewer)
            self.assertEqual((body["text"], body["offset"]), ("", 0))

    def test_evidence_masks_before_preview_clipping(self):
        tid, sid, _, gid, _ = self.fixture()
        secret = support._uniq("boundary-value-")
        header = "HTTP/1.1 200 OK\n\n"
        raw = header + "x" * (evidence.MAX_BODY - len(header) - 8) + secret + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp)
            (rd / ".state").mkdir()
            c = sqlite3.connect(rd / ".state/agents.db")
            c.execute("CREATE TABLE agent_messages(id INTEGER PRIMARY KEY,session_id TEXT,message_data TEXT,created_at TEXT)")
            for m in ({"type": "function_call", "name": "view_request", "call_id": "call",
                       "arguments": json.dumps({"request_id": "1", "part": "response"})},
                      {"type": "function_call_output", "call_id": "call", "output": json.dumps({"content": raw, "has_more": False})}):
                c.execute("INSERT INTO agent_messages(session_id,message_data) VALUES (?,?)", ("a1", json.dumps(m)))
            c.commit()
            c.close()
            x = evidence.load(rd)["1"]
            text = evidence.public(x, redact.Redactor([secret]), "run")["response"]["text"]
            self.assertNotIn(secret[:6], text[-40:])
        self.assertIn(redact.MASK, text[-40:])

    def test_scope_urls_respect_effective_port_and_unknown_port(self):
        target = {"base_url": "https://example.test/api", "in_scope": [], "out_of_scope": []}
        self.assertEqual(scope.label(target, "example.test", 443, "/api/me"), "in")
        self.assertEqual(scope.label(target, "example.test", 8080, "/api/me"), "out")
        self.assertEqual(scope.label(target, "example.test", None, "/api/me"), "unknown")

    def test_normalization_does_not_merge_long_distinct_endpoints(self):
        prefix = "/api/" + "x" * 310
        self.assertNotEqual(scope.norm_path(prefix + "/first"), scope.norm_path(prefix + "/second"))

    def test_message_metadata_is_masked_together_with_content(self):
        secret = support._uniq("agent-secret-")
        row = {"id": 1, "agent_name": secret, "reason": "Agent " + secret,
               "created_by": "user " + secret, "content_enc": crypto.vault_encrypt(secret)}
        self.assertNotIn(secret, json.dumps(control.out_row(row, redact.Redactor([secret]))))

    def test_inventory_and_telemetry_are_masked_at_read_time(self):
        tid, sid, *_ = self.fixture()
        secret = support._uniq("stored-metadata-secret-")
        db.update("scans", sid, {"redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
        aid = db.insert("assets", {"target_id": tid, "kind": "endpoint", "key": "/" + secret,
                        "host": "example.test", "path": "/" + secret, "tier": "observed"})
        db.insert("asset_observations", {"asset_id": aid, "scan_id": sid, "run_name": "run", "source": "proxy",
                                         "tier": "observed", "ref": "ref", "evidence": secret})
        db.insert("scan_telemetry", {"scan_id": sid, "telemetry": {"available": True, "agents": [{"name": secret}]}})
        viewer = self.user("viewer")
        for path in (f"/api/targets/{tid}/inventory", f"/api/assets/{aid}/observations", f"/api/scans/{sid}/telemetry"):
            status, body = self.call(path, user=viewer)
            self.assertEqual(status, 200)
            self.assertNotIn(secret, json.dumps(body), path)

    def test_unreadable_llm_key_does_not_turn_into_anonymous_gateway_access(self):
        with self.assertRaises(crypto.DecryptError):
            llm.strix_env({"provider": "litellm", "model": "test", "api_key_enc": "broken"})

    def test_invalid_schedule_timezone_is_a_validation_error(self):
        status, body = self.call("/api/schedules/preview", "POST", {"kind": "interval", "interval_hours": 2,
                                "timezone": "Definitely/Not_A_Zone"}, user=self.user("viewer"))
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])

    def test_missing_or_malformed_findings_cannot_pass_ci_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp)
            (rd / "run.json").write_text('{"status":"completed"}')
            for content in (None, "not JSON", '{"wrong": "shape"}', '[{"severity":"low"},42]'):
                if content is not None:
                    (rd / "vulnerabilities.json").write_text(content)
                result = runs.summarize(rd, "high")
                self.assertIsNone(result["gate"], content)
                self.assertFalse(result["findings_available"])
            (rd / "vulnerabilities.json").write_text("[]")
            self.assertEqual(runs.summarize(rd, "high")["gate"], "pass")
            (rd / "run.json").write_text('{"status":"cancelled"}')
            self.assertIsNone(runs.summarize(rd, "high")["gate"])
            (rd / "vulnerabilities.json").write_text('[{"severity":"high","cvss":"invalid"}]')
            self.assertEqual(runs.summarize(rd, "high")["gate"], "fail")

    def test_malformed_metadata_and_nonfinite_scores_do_not_break_readers(self):
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp)
            for content in ('[]', '{"targets_info":[null,3,{}],"llm_usage":[],"scan_results":[]}'):
                (rd / "run.json").write_text(content)
                self.assertEqual(runs.run_meta(rd)["targets"], [])
            (rd / "vulnerabilities.json").write_text(json.dumps([
                {"id": str(i), "severity": "high", "cvss": score} for i, score in enumerate(("NaN", "bad", 11, "8.1"))]))
            rows = runs.findings(rd)
            self.assertEqual(rows[0]["cvss"], 8.1)
            self.assertTrue(all(r["cvss"] is None for r in rows[1:]))

    def test_clipped_evidence_is_not_exported_as_complete(self):
        x = {"request": {"text": "request", "complete": True, "clipped": True},
             "response": {"text": "response", "complete": True, "clipped": True}}
        with mock.patch.object(workspace, "exchange", return_value=x):
            self.assertFalse(workspace.diff(1, "run:1", "run:2")["complete"])
            self.assertIn("preview clipped", workspace.download_text(1, "run", "1"))

    def test_unmapped_coverage_masks_before_shortening_surface(self):
        from skynet import coverage_matrix
        tid, sid, *_ = self.fixture()
        secret = support._uniq("coverage-secret-")
        with tempfile.TemporaryDirectory() as tmp:
            rd = Path(tmp)
            db.update("scans", sid, {"redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
            (rd / "coverage.json").write_text(json.dumps({"entries": [{"surface": "x" * 115 + secret, "outcome": "reported"}]}))
            body = coverage_matrix.build(db.get_scan(sid), rd)
            self.assertNotIn(secret[:5], body["cells"][0]["endpoint"])

    def test_unreadable_profile_can_be_repaired_only_with_full_new_credentials(self):
        p = {"id": db.insert("auth_profiles", {"name": support._uniq("repair"), "kind": "header", "secret_enc": "broken"})}
        p = vault.get(p["id"])
        try:
            body = {"name": p["name"], "kind": "header", "headers": [{"name": "X-Test", "value": ""}]}
            with self.assertRaises(ValueError):
                vault.save(body, p)
            self.assertEqual(vault.get(p["id"])["secret_enc"], "broken")
            body["headers"][0]["value"] = "replacement-value"
            vault.save(body, p)
            self.assertEqual(vault.secrets_of(vault.get(p["id"])), {"headers": {"X-Test": "replacement-value"}})
        finally:
            db.delete("auth_profiles", p["id"])

    def test_spawned_process_is_stopped_if_registration_fails(self):
        from skynet import runner
        tid, sid, *_ = self.fixture()
        pid = db.insert("llm_profiles", {"name": support._uniq("launch"), "provider": "litellm", "model": "test"})
        db.update("scans", sid, {"llm_profile_id": pid, "targets": ["http://127.0.0.1:8899"]})
        scan = db.get_scan(sid)
        proc = mock.Mock(pid=99999999)
        original = db.update
        def fail_registration(table, key, data):
            if table == "scans" and data.get("status") == "running":
                raise OSError("simulated full disk")
            return original(table, key, data)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            binary = p / "strix"
            binary.touch()
            with mock.patch.object(runner, "docker_status", return_value={"ok": True}), \
                 mock.patch.object(runner, "strix_version", return_value={"version": "test"}), \
                 mock.patch.object(control, "bridge_status", return_value={"available": False, "reason": "test"}), \
                 mock.patch.object(runner.subprocess, "Popen", return_value=proc), \
                 mock.patch.object(runner.os, "killpg") as kill, mock.patch.object(db, "update", side_effect=fail_registration):
                try:
                    with self.assertRaises(OSError):
                        runner._launch(scan, {"strix_bin": str(binary), "strix_workdir": str(p)})
                    kill.assert_called_once_with(proc.pid, runner.signal.SIGTERM)
                    proc.wait.assert_called_once_with(timeout=5)
                    self.assertNotIn(sid, runner._procs)
                finally:
                    runner._cleanup_runtime(sid)

    def test_corrupt_ci_token_is_not_rotated_by_a_request(self):
        before = db.get_settings().get("api_token_enc", "")
        try:
            db.set_settings({"api_token_enc": "broken"})
            status, _ = self.call("/api/ci/scans/1", headers=[(b"x-api-token", b"candidate")])
            self.assertEqual(status, 503)
            self.assertEqual(db.get_settings()["api_token_enc"], "broken")
        finally:
            db.set_settings({"api_token_enc": before})

    def test_malformed_cookie_is_rejected_without_server_error(self):
        from skynet import auth
        self.assertIsNone(auth.valid_session("anything.\u00e5"))
        self.assertEqual(self.call("/api/me", cookie="anything.\u00e5")[0], 401)

    def test_ci_does_not_publish_legacy_pass_for_incomplete_engine_output(self):
        _, sid, *_ = self.fixture()
        before = db.get_settings().get("api_token_enc", "")
        try:
            db.set_settings({"api_token_enc": crypto.encrypt("ci-test-token")})
            db.update("scans", sid, {"summary": {"run_status": "cancelled", "gate": "pass", "counts": {}}})
            status, body = self.call(f"/api/ci/scans/{sid}", headers=[(b"x-api-token", b"ci-test-token")])
            self.assertEqual(status, 200)
            self.assertIsNone(body["gate"])
        finally:
            db.set_settings({"api_token_enc": before})

    def test_instruction_followup_cannot_page_before_its_marker(self):
        _, sid, *_ = self.fixture()
        mid = db.insert("agent_messages", {"scan_id": sid, "request_id": support._uniq("message-"), "agent_id": "a1",
                        "content_enc": crypto.vault_encrypt("QA instruction"), "state": "delivered"})
        with mock.patch.object(control, "marker_position", return_value=50), \
             mock.patch.object(self.M.activity, "read", return_value={"items": [], "cursor": 50}) as read:
            status, _ = self.call(f"/api/scans/{sid}/messages/{mid}/activity?after=-1", user=self.user("viewer"))
            self.assertEqual(status, 200)
            self.assertEqual(read.call_args.args[2], 50)
