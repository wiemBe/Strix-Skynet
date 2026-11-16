"""Multi-user accounts, role policy and audit log. Hermetic temp data dir (see test_features)."""
import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_features  # noqa: F401,E402  (sets SKYNET_DATA / key / password before skynet is imported)
from skynet import audit, auth, db  # noqa: E402


def _uniq(prefix):
    return f"{prefix}{os.urandom(3).hex()}"


class Base(unittest.TestCase):
    def setUp(self):
        from skynet import main
        self.M = main
        db.init()
        auth.bootstrap()

    def user(self, role, password="correct-horse-battery"):
        return auth.create_user(_uniq(role[:3]), role, password)

    def call(self, path, method="GET", body=None, user=None, cookie=None, headers=(), csrf=True):
        async def invoke():
            delivered, messages = False, []
            payload = json.dumps(body).encode() if body is not None else b""

            async def receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": payload, "more_body": False}
                await asyncio.Event().wait()

            async def send(m):
                messages.append(m)
            hs = [(b"content-type", b"application/json"), *headers]
            ck = cookie if cookie is not None else (auth.make_session(user) if user else None)
            if ck:
                hs.append((b"cookie", f"{auth.COOKIE}={ck}".encode()))
            if csrf:
                hs.append((b"x-requested-with", b"skynet"))
            p, _, query = path.partition("?")
            scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1",
                     "method": method, "scheme": "http", "path": p, "raw_path": p.encode(), "query_string": query.encode(),
                     "root_path": "", "headers": hs, "client": ("127.0.0.1", 1), "server": ("local-test", 80)}
            await asyncio.wait_for(self.M.app(scope, receive, send), 5)
            status = next(m["status"] for m in messages if m["type"] == "http.response.start")
            raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
            try:
                return status, json.loads(raw)
            except ValueError:
                return status, raw
        return asyncio.run(invoke())

    def last_audit(self, **where):
        cond = " AND ".join(f"{k}=?" for k in where)
        return db.q1(f"SELECT * FROM audit_log WHERE {cond} ORDER BY id DESC LIMIT 1", tuple(where.values()))

    def api_routes(self):
        from fastapi.routing import APIRoute
        for r in self.M.app.routes:
            if isinstance(r, APIRoute) and r.path.startswith("/api/") and not r.path.startswith("/api/ci/"):
                for m in r.methods:
                    yield m, r.path


class TestRolePolicy(Base):
    def concrete(self, path):
        import re
        return re.sub(r"\{[^}]+\}", "987654", path)

    def test_every_mutating_route_has_an_explicit_rule(self):
        missing = []
        for m, p in self.api_routes():
            if m in audit.MUTATING and p != "/api/login":
                rule, _ = audit.rule_for(m, self.concrete(p))
                if rule.action == "api.change":
                    missing.append(f"{m} {p}")
        self.assertEqual(missing, [], "add these routes to audit.RULES")

    def test_viewer_gets_403_on_every_mutating_route(self):
        viewer = self.user("viewer")
        for m, p in self.api_routes():
            if m not in audit.MUTATING or p == "/api/login":
                continue
            rule, _ = audit.rule_for(m, self.concrete(p))
            if rule.role == "viewer":
                continue
            status, _ = self.call(self.concrete(p), m, {}, user=viewer)
            self.assertEqual(status, 403, f"{m} {p}")

    def test_analyst_gets_403_on_admin_routes_and_admin_reads(self):
        analyst = self.user("analyst")
        for m, p in self.api_routes():
            rule, _ = audit.rule_for(m, self.concrete(p))
            if rule.role != "admin":
                continue
            status, body = self.call(self.concrete(p), m, {} if m in audit.MUTATING else None, user=analyst)
            self.assertEqual(status, 403, f"{m} {p}")
            self.assertEqual(body["need_role"], "admin")

    def test_reads_are_open_to_viewers_except_admin_pages(self):
        viewer = self.user("viewer")
        self.assertEqual(self.call("/api/targets", user=viewer)[0], 200)
        self.assertEqual(self.call("/api/me", user=viewer)[1]["role"], "viewer")
        for p in ("/api/settings", "/api/users", "/api/audit"):
            self.assertEqual(self.call(p, user=viewer)[0], 403, p)

    def test_denied_mutation_is_audited(self):
        viewer = self.user("viewer")
        self.call("/api/targets", "POST", {"name": "x"}, user=viewer)
        row = self.last_audit(actor=viewer["username"])
        self.assertEqual((row["action"], row["status"]), ("target.create", 403))


class TestSessions(Base):
    def test_login_sets_user_session_and_is_audited(self):
        u = self.user("analyst", "analyst-password-1")
        status, _ = self.call("/api/login", "POST", {"username": u["username"].upper(), "password": "analyst-password-1"})
        self.assertEqual(status, 200)
        row = self.last_audit(action="auth.login", actor=u["username"])
        self.assertEqual(row["actor_role"], "analyst")
        self.assertTrue(auth.get_user(u["id"])["last_login_at"])

    def test_failed_login_logs_only_existing_usernames(self):
        u = self.user("viewer")
        self.call("/api/login", "POST", {"username": u["username"], "password": "wrong-password"})
        self.assertEqual(self.last_audit(action="auth.login_failed")["actor"], u["username"])
        typo = "my-secret-password-typed-here"
        self.call("/api/login", "POST", {"username": typo, "password": "x"})
        self.assertEqual(self.last_audit(action="auth.login_failed")["actor"], "unknown user")
        self.assertFalse(db.q1("SELECT 1 FROM audit_log WHERE actor=? OR summary LIKE ?", (typo, f"%{typo}%")))
        auth.clear_failures("127.0.0.1")

    def test_password_reset_signs_out_existing_sessions(self):
        admin, u = self.user("admin"), self.user("analyst")
        old = auth.make_session(u)
        self.assertEqual(self.call("/api/me", cookie=old)[0], 200)
        self.assertEqual(self.call(f"/api/users/{u['id']}/password", "POST", {"password": "brand-new-password"}, user=admin)[0], 200)
        self.assertEqual(self.call("/api/me", cookie=old)[0], 401)
        self.assertTrue(auth.check_credentials(u["username"], "brand-new-password"))

    def test_disabled_user_loses_session_and_login(self):
        admin, u = self.user("admin"), self.user("analyst", "disabled-pass-1")
        ck = auth.make_session(u)
        self.call(f"/api/users/{u['id']}", "PUT", {"active": False}, user=admin)
        self.assertEqual(self.call("/api/me", cookie=ck)[0], 401)
        self.assertIsNone(auth.check_credentials(u["username"], "disabled-pass-1"))
        self.assertIn("disabled", self.last_audit(action="user.update")["summary"])

    def test_role_change_applies_to_an_existing_session(self):
        admin, u = self.user("admin"), self.user("analyst")
        ck = auth.make_session(u)
        self.call(f"/api/users/{u['id']}", "PUT", {"role": "viewer"}, user=admin)
        self.assertEqual(self.call("/api/targets", "POST", {"name": "x"}, cookie=ck)[0], 403)
        self.assertEqual(self.last_audit(action="user.update")["summary"], f"{u['username']}: role Analyst → Viewer")

    def test_own_password_change(self):
        u = self.user("viewer", "viewer-old-pass")
        st, _ = self.call("/api/settings/password", "POST", {"current": "viewer-old-pass", "new": "viewer-new-pass"}, user=u)
        self.assertEqual(st, 200)
        self.assertTrue(auth.check_credentials(u["username"], "viewer-new-pass"))
        row = self.last_audit(action="account.password_change", actor=u["username"])
        self.assertNotIn("viewer-new-pass", json.dumps(row))


class TestUserRules(Base):
    def test_builtin_admin_is_not_editable(self):
        admin, b = self.user("admin"), auth.builtin_user()
        for m, p, body in (("PUT", f"/api/users/{b['id']}", {"role": "viewer"}),
                           ("DELETE", f"/api/users/{b['id']}", None),
                           ("POST", f"/api/users/{b['id']}/password", {"password": "x" * 12})):
            self.assertEqual(self.call(p, m, body, user=admin)[0], 400, (m, p))
        self.assertEqual(auth.builtin_user()["role"], "admin")

    def test_admin_cannot_demote_disable_or_delete_self(self):
        admin = self.user("admin")
        self.assertEqual(self.call(f"/api/users/{admin['id']}", "PUT", {"role": "viewer"}, user=admin)[0], 400)
        self.assertEqual(self.call(f"/api/users/{admin['id']}", "PUT", {"active": False}, user=admin)[0], 400)
        self.assertEqual(self.call(f"/api/users/{admin['id']}", "DELETE", user=admin)[0], 400)

    def test_create_user_validation(self):
        admin = self.user("admin")
        self.assertEqual(self.call("/api/users", "POST", {"username": "a b", "role": "viewer", "password": "x" * 12}, user=admin)[0], 400)
        self.assertEqual(self.call("/api/users", "POST", {"username": _uniq("u"), "role": "root", "password": "x" * 12}, user=admin)[0], 400)
        self.assertEqual(self.call("/api/users", "POST", {"username": _uniq("u"), "role": "viewer", "password": "short"}, user=admin)[0], 400)
        self.assertEqual(self.call("/api/users", "POST", {"username": "scheduler", "role": "viewer", "password": "x" * 12}, user=admin)[0], 400)
        name = _uniq("new")
        st, body = self.call("/api/users", "POST", {"username": name, "role": "analyst", "password": "long-enough-pw"}, user=admin)
        self.assertEqual((st, body["role"]), (200, "analyst"))
        self.assertNotIn("password_hash", body)
        self.assertEqual(self.call("/api/users", "POST", {"username": name.upper(), "role": "viewer", "password": "x" * 12}, user=admin)[0], 400)


class TestAuditTrail(Base):
    def test_finding_status_change_records_actor_and_transition_not_body(self):
        u = self.user("analyst")
        tid = db.insert("targets", {"name": "Audit fixture", "base_url": "http://127.0.0.1:8899", "environment": "test"})
        gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("fp"), "title": "IDOR on orders",
                                           "remediation": "open"})
        note = "ticket SEC-1 secret-ish-note"
        st, _ = self.call(f"/api/findings/{gid}", "PATCH", {"remediation": "fixed", "remediation_note": note}, user=u)
        self.assertEqual(st, 200)
        row = self.last_audit(action="finding.status")
        self.assertEqual((row["actor"], row["object_type"], row["object_id"]), (u["username"], "finding", str(gid)))
        self.assertEqual(row["summary"], "open → fixed · IDOR on orders")
        self.assertNotIn(note, json.dumps(row))

    def test_notes_are_authored_by_the_signed_in_user(self):
        u = self.user("analyst")
        tid = db.insert("targets", {"name": "Note fixture", "base_url": "http://127.0.0.1:8899", "environment": "test"})
        gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("fp"), "remediation": "open"})
        st, body = self.call(f"/api/findings/{gid}/notes", "POST", {"body": "Reproduced manually"}, user=u)
        self.assertEqual(st, 200)
        self.assertEqual(body["notes"][0]["created_by"], u["username"])

    def test_ci_token_scan_start_is_audited(self):
        tid = db.insert("targets", {"name": "CI fixture", "base_url": "http://127.0.0.1:8899", "environment": "test"})
        pid = db.insert("llm_profiles", {"name": _uniq("ci-llm"), "provider": "litellm", "model": "local-fixture"})
        tok = auth.api_token()
        st, body = self.call(f"/api/ci/targets/{tid}/scan", "POST", {"llm_profile_id": pid},
                             headers=[(b"x-api-token", tok.encode())], csrf=False)
        self.assertEqual(st, 200)
        row = self.last_audit(actor="ci-token")
        self.assertEqual((row["action"], row["object_type"], row["object_id"]), ("scan.start", "scan", str(body["scan_id"])))
        from skynet import runner
        runner.cancel(body["scan_id"])

    def test_audit_feed_filters(self):
        admin, u = self.user("admin"), self.user("viewer")
        self.call("/api/targets", "POST", {"name": "x"}, user=u)
        st, body = self.call(f"/api/audit?actor={u['username']}", user=admin)
        self.assertEqual(st, 200)
        self.assertTrue(body["entries"])
        self.assertTrue(all(e["actor"] == u["username"] for e in body["entries"]))
        self.assertEqual(body["entries"][0]["action_label"], "Created target")


class TestMigration(unittest.TestCase):
    def test_v6_moves_the_generated_admin_password_into_the_users_table(self):
        with tempfile.TemporaryDirectory(prefix="skynet-migration6-") as tmp:
            p, old = Path(tmp), db._conn
            try:
                db._conn = None
                with mock.patch.multiple(db, DB_PATH=p / "skynet.db", DATA_DIR=p):
                    c = db.conn()
                    c.executescript(db.SCHEMA)
                    stored = auth._hash("legacy-admin-pass")
                    c.execute("INSERT INTO settings VALUES('admin_password_hash', ?)", (stored,))
                    db.migrate()
                    u = db.q1("SELECT * FROM users WHERE builtin=1")
                    self.assertEqual((u["role"], u["password_hash"], u["active"]), ("admin", stored, 1))
                    self.assertFalse(db.q1("SELECT 1 FROM settings WHERE key='admin_password_hash'"))
                    self.assertTrue(auth._verify_hash("legacy-admin-pass", u["password_hash"]))
                    with closing(sqlite3.connect(db.migrations_applied()[-1]["backup"])) as b:
                        self.assertTrue(b.execute("SELECT 1 FROM settings WHERE key='admin_password_hash'").fetchone())
            finally:
                if db._conn is not None:
                    db._conn.close()
                db._conn = old


if __name__ == "__main__":
    unittest.main()


class TestReport(Base):
    def fixture(self):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        iso = lambda d: d.isoformat(timespec="seconds")  # noqa: E731
        tid = db.insert("targets", {"name": _uniq("Report fixture "), "base_url": "http://127.0.0.1:8899", "environment": "test"})
        s1 = db.insert("scans", {"target_id": tid, "status": "completed", "trigger": "manual", "started_at": iso(now - timedelta(days=20)),
                                 "summary": {"counts": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}, "run_status": "completed"}})
        s2 = db.insert("scans", {"target_id": tid, "status": "cancelled", "trigger": "manual", "started_at": iso(now - timedelta(days=10)),
                                 "summary": {"counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "run_status": "cancelled"}})
        db.insert("scans", {"target_id": tid, "status": "completed", "trigger": "verify", "started_at": iso(now - timedelta(days=5))})
        secret = "Bearer sk-report-leak-123456"
        g_open = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("o"), "severity": "high", "remediation": "open",
                                              "title": "IDOR on invoices", "endpoint": "/api/invoices/{id}", "first_seen_at": iso(now - timedelta(days=20))})
        g_fixed = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("f"), "severity": "critical", "remediation": "fixed",
                                               "title": "SQLi", "first_seen_at": iso(now - timedelta(days=20)),
                                               "fixed_at": iso(now - timedelta(days=12)),
                                               "remediation_at": iso(now - timedelta(days=12))})
        for gid in (g_open, g_fixed):
            db.insert("finding_occurrences", {"group_id": gid, "scan_id": s1, "run_name": _uniq("r"), "strix_id": "v1",
                                              "severity": "high", "observed_at": iso(now - timedelta(days=20))})
        return tid, s1, s2, g_open, secret

    def test_report_content(self):
        from skynet import report
        tid, s1, s2, g_open, _ = self.fixture()
        r = report.for_target(tid)
        self.assertEqual([(t["scan_id"], t["complete"]) for t in r["trend"]], [(s1, True), (s2, False)])  # verify run excluded
        self.assertEqual((r["scans"]["completed"], r["scans"]["incomplete"], r["scans"]["verifications"]), (1, 1, 1))
        f = r["findings"]
        self.assertEqual(f["open_total"], 1)
        self.assertEqual(f["time_to_fix"]["critical"], {"n": 1, "median": 8.0, "max": 8.0})
        self.assertEqual(f["top_open"][0]["id"], g_open)
        self.assertGreaterEqual(f["open_age"]["high"]["max"], 19.9)
        self.assertTrue(any("SLA" in n for n in r["notes"]))

    def test_report_is_redacted(self):
        from skynet import report, vault
        tid, _, _, g_open, secret = self.fixture()
        db.execute("UPDATE finding_groups SET title=? WHERE id=?", (f"Token {secret} in URL", g_open))
        with mock.patch.object(vault, "finding_redactor", return_value=__import__("skynet.redact", fromlist=["Redactor"]).Redactor([secret])):
            out = json.dumps(report.for_target(tid))
        self.assertNotIn(secret, out)

    def test_viewer_can_open_report_and_it_is_audited(self):
        tid, *_ = self.fixture()
        viewer = self.user("viewer")
        st, body = self.call(f"/api/targets/{tid}/report", user=viewer)
        self.assertEqual((st, body["generated_by"]), (200, viewer["username"]))
        row = self.last_audit(action="report.view")
        self.assertEqual((row["actor"], row["object_type"], row["object_id"]), (viewer["username"], "target", str(tid)))

    def test_report_parses_every_stored_time_format(self):
        from skynet import report
        for v in ("2026-09-29T19:42:00.239955+00:00", "2026-11-15 09:10:00 UTC", "2026-11-14 07:00:00",
                  "2026-11-14T20:06:45+00:00", "2026-11-15T09:10:00Z"):
            self.assertIsNotNone(report._dt(v), v)
            self.assertIsNotNone(report._dt(v).tzinfo, v)
        self.assertIsNone(report._dt("not a date"))


class TestReviewRegressions(Base):
    def profile(self, secret):
        from skynet import vault
        return vault.save({"kind": "header", "name": _uniq("masking"),
                           "headers": [{"name": "Authorization", "value": "Bearer " + secret}]}, None)

    def test_audit_masks_known_and_historical_values_before_storage_and_truncation(self):
        from skynet import crypto, vault
        secret = _uniq("historical-credential-")
        pid = self.profile(secret)
        tid = db.insert("targets", {"name": "Masking fixture", "base_url": "http://127.0.0.1:8899"})
        db.insert("scans", {"target_id": tid, "redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
        # Even after the profile is removed, retained scan values protect new audit records.
        db.execute("DELETE FROM auth_profiles WHERE id=?", (pid,))
        text = "x" * 295 + secret
        audit.record("system", "agent.instruct", summary=text)
        row = self.last_audit(action="agent.instruct")
        self.assertNotIn(secret, row["summary"])
        self.assertNotIn(secret[:5], row["summary"])
        self.assertIn("••", row["summary"])
        self.assertNotIn(secret, json.dumps(audit.entries()))
        self.assertNotIn(secret, vault.stored_redactor().text(secret))

    def test_agent_instruction_audit_uses_redaction_on_the_real_route(self):
        from skynet import crypto
        secret = _uniq("agent-credential-")
        self.profile(secret)
        with tempfile.TemporaryDirectory(prefix="skynet-agent-mask-") as tmp:
            rd = Path(tmp)
            (rd / ".state").mkdir()
            (rd / ".state/agents.json").write_text(json.dumps({"statuses": {"a1": "running"},
                                                                  "names": {"a1": "Agent " + secret}}))
            tid = db.insert("targets", {"name": "Local fixture", "base_url": "http://127.0.0.1:8899"})
            sid = db.insert("scans", {"target_id": tid, "status": "running", "run_dir": str(rd)})
            mid = db.insert("agent_messages", {"scan_id": sid, "agent_id": "a1", "request_id": _uniq("msg"),
                                               "content_enc": crypto.vault_encrypt("fixture instruction")})
            with mock.patch.object(self.M.control, "send", return_value={"id": mid}):
                st, _ = self.call(f"/api/scans/{sid}/messages", "POST", {"agent_id": "a1", "content": "fixture instruction"},
                                  user=self.user("analyst"))
            self.assertEqual(st, 200)
            self.assertNotIn(secret, json.dumps(self.last_audit(action="agent.instruct")))

    def test_audit_read_masks_values_learned_after_the_event(self):
        secret = _uniq("newly-known-")
        db.insert("audit_log", {"at": db.now_iso(), "actor": "system", "action": "scan.import", "summary": secret})
        self.profile(secret)
        admin = self.user("admin")
        st, body = self.call("/api/audit", user=admin)
        self.assertEqual(st, 200)
        self.assertNotIn(secret, json.dumps(body))

    def test_unreadable_historical_masking_context_does_not_write_unsafe_audit(self):
        from skynet import crypto
        tid = db.insert("targets", {"name": "Unreadable masking fixture", "base_url": "http://127.0.0.1:8899"})
        sid = db.insert("scans", {"target_id": tid, "redact_enc": "not-a-valid-encrypted-snapshot"})
        marker = _uniq("must-not-store-")
        try:
            with self.assertRaises(crypto.DecryptError):
                audit.record("system", "scan.import", summary=marker)
            self.assertFalse(db.q1("SELECT id FROM audit_log WHERE summary=?", (marker,)))
        finally:
            db.execute("DELETE FROM scans WHERE id=?", (sid,))

    def test_disabling_permanently_revokes_cookie_after_reenable(self):
        admin, user = self.user("admin"), self.user("analyst")
        old = auth.make_session(user)
        for _ in range(2):
            self.assertEqual(self.call(f"/api/users/{user['id']}", "PUT", {"active": False}, user=admin)[0], 200)
            self.assertEqual(self.call("/api/me", cookie=old)[0], 401)
            self.assertEqual(self.call(f"/api/users/{user['id']}", "PUT", {"active": True}, user=admin)[0], 200)
            self.assertEqual(self.call("/api/me", cookie=old)[0], 401)
            fresh = auth.get_user(user["id"])
            self.assertEqual(self.call("/api/me", cookie=auth.make_session(fresh))[0], 200)
            old = auth.make_session(fresh)

    def test_fixed_transition_is_stable_on_notes_and_resets_on_reopen(self):
        from skynet import report
        user = self.user("analyst")
        tid = db.insert("targets", {"name": "Timing fixture", "base_url": "http://127.0.0.1:8899"})
        sid = db.insert("scans", {"target_id": tid, "status": "completed"})
        gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("timing"), "severity": "high",
                                           "remediation": "open", "first_seen_at": "2026-01-01T00:00:00+00:00"})
        db.insert("finding_occurrences", {"group_id": gid, "scan_id": sid, "run_name": _uniq("timing"), "strix_id": "v1"})
        def patch(day, rem, note):
            with mock.patch.object(db, "now_iso", return_value=f"2026-01-{day:02}T00:00:00+00:00"):
                self.assertEqual(self.call(f"/api/findings/{gid}", "PATCH", {"remediation": rem, "remediation_note": note}, user=user)[0], 200)
        patch(2, "fixed", "ticket opened")
        patch(10, "fixed", "ticket note updated")
        self.assertEqual(db.get("finding_groups", gid)["remediation_at"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(report.for_target(tid)["findings"]["time_to_fix"]["high"]["median"], 1.0)
        patch(11, "open", "reopened")
        self.assertIsNone(db.get("finding_groups", gid)["fixed_at"])
        patch(12, "fixed", "fixed again")
        self.assertEqual(report.for_target(tid)["findings"]["time_to_fix"]["high"]["median"], 11.0)

    def test_legacy_fixed_time_is_unknown_instead_of_using_last_note_time(self):
        from skynet import report
        tid, *_ = TestReport.fixture(self)
        db.execute("UPDATE finding_groups SET fixed_at=NULL WHERE target_id=? AND remediation='fixed'", (tid,))
        f = report.for_target(tid)["findings"]
        self.assertEqual(f["summary"]["remediation"]["fixed"], 1)
        self.assertEqual(f["time_to_fix"]["all"], {"n": 0, "median": None, "max": None})
        self.assertEqual(f["fixed_time_unknown"], 1)

    def test_all_report_metadata_and_generator_are_masked(self):
        from skynet import crypto, report
        secret = _uniq("report-credential-")
        pid = self.profile(secret)
        tid = db.insert("targets", {"name": "Target " + secret, "base_url": "http://127.0.0.1:8899/?password=" + secret})
        db.insert("scans", {"target_id": tid, "status": "completed", "redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
        cid = db.insert("campaigns", {"name": "Campaign " + secret, "description": "x" * 190 + secret})
        db.insert("campaign_targets", {"campaign_id": cid, "target_id": tid})
        db.execute("DELETE FROM auth_profiles WHERE id=?", (pid,))
        viewer = self.user("viewer")
        db.execute("UPDATE users SET display_name=? WHERE id=?", (secret, viewer["id"]))
        for path in (f"/api/targets/{tid}/report", f"/api/campaigns/{cid}/report"):
            st, data = self.call(path, user=viewer)
            self.assertEqual(st, 200)
            self.assertNotIn(secret, json.dumps(data))
            self.assertNotEqual(data["generated_by"], secret)
        campaign_report = report.for_campaign(cid)
        self.assertNotIn(secret, json.dumps(campaign_report))
        self.assertNotIn(secret[:10], campaign_report["subtitle"])

    def test_v7_backs_up_and_repairs_audit_without_inventing_fix_times(self):
        from skynet import crypto
        with tempfile.TemporaryDirectory(prefix="skynet-migration7-") as tmp:
            p, old = Path(tmp), db._conn
            try:
                db._conn = None
                with mock.patch.multiple(db, DB_PATH=p / "skynet.db", DATA_DIR=p):
                    c = db.conn()
                    c.executescript(db.SCHEMA)
                    with mock.patch.object(db, "MIGRATIONS", [m for m in db.MIGRATIONS if m[0] <= 6]):
                        db.migrate()
                    disabled = self.user("analyst")
                    old_cookie = auth.make_session(disabled)
                    db.execute("UPDATE users SET active=0 WHERE id=?", (disabled["id"],))
                    secret = _uniq("legacy-audit-")
                    db.insert("auth_profiles", {"name": "Legacy profile", "kind": "header", "secret_enc": crypto.vault_encrypt(json.dumps({"headers": {"Authorization": "Bearer " + secret}}))})
                    aid = db.insert("audit_log", {"at": "2026-01-01", "actor": "system", "action": "agent.instruct", "summary": secret, "status": 200})
                    tid = db.insert("targets", {"name": "Legacy fixture", "base_url": "http://127.0.0.1:8899"})
                    gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": _uniq("legacy"), "remediation": "fixed", "remediation_at": "2026-01-02"})
                    db.migrate()
                    migration = next(m for m in db.migrations_applied() if m["version"] == 7)
                    self.assertEqual(migration["version"], 7)
                    self.assertEqual(db.get("audit_log", aid)["summary"], "••••••")
                    self.assertEqual(db.get("audit_log", aid)["at"], "2026-01-01")
                    self.assertIsNone(db.get("finding_groups", gid)["fixed_at"])
                    self.assertEqual(db.q1("SELECT session_version FROM users LIMIT 1")["session_version"], 0)
                    self.assertEqual(auth.get_user(disabled["id"])["session_version"], 1)
                    db.execute("UPDATE users SET active=1 WHERE id=?", (disabled["id"],))
                    self.assertIsNone(auth.valid_session(old_cookie))
                    with closing(sqlite3.connect(migration["backup"])) as backup:
                        self.assertEqual(backup.execute("SELECT summary FROM audit_log WHERE id=?", (aid,)).fetchone()[0], secret)
                    self.assertEqual(Path(migration["backup"]).stat().st_mode & 0o777, 0o600)
                    before = len(list((p / "backups").glob("*.db")))
                    db.migrate()
                    self.assertEqual(len(list((p / "backups").glob("*.db"))), before)
            finally:
                if db._conn is not None:
                    db._conn.close()
                db._conn = old
