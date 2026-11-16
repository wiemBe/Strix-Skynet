"""SKY-01..SKY-07 (docs/FEATURE_BACKLOG.md) acceptance checks.

These are FIXTURE tests: Strix-shaped run folders (agents.db rows in the real Strix 1.7 / openai-agents format,
coverage.json, vulnerabilities.json) are written to temp dirs and read by the real Skynet code and API routes.
They do not start Strix, call an LLM or send traffic. Hermetic like test_features.py.
"""
import hashlib
import json
import os
import sqlite3
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

if "SKYNET_DATA" not in os.environ:
    _TMP = tempfile.mkdtemp(prefix="skynet-test-")
    os.environ["SKYNET_DATA"] = str(Path(_TMP) / "data")
    os.environ["SKYNET_SECRET_KEY_FILE"] = str(Path(_TMP) / "keys" / "secret.key")
    os.environ.setdefault("SKYNET_PASSWORD", "unit-test-password")

from skynet import (activity, browser, compare, control, coverage_matrix, crypto, db, findings_store,  # noqa: E402
                    inventory, session_health, timeline, verify, workspace)
from skynet.redact import Redactor  # noqa: E402

TOKEN = "Bearer sky-fixture-token-123"
OTHER = "Bearer someone-elses-token"
MARKER_TEXT = "identity:tester"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Run:
    """A Strix-shaped run folder."""
    n = 0

    def __del__(self):
        if getattr(self, "c", None):
            self.c.close()

    def __init__(self, root: Path, name: str | None = None):
        Run.n += 1
        self.name = name or f"fixture-run-{os.getpid()}-{Run.n}"
        self.dir = root / self.name
        (self.dir / ".state").mkdir(parents=True)
        self.c = sqlite3.connect(self.dir / ".state/agents.db")
        self.c.execute("CREATE TABLE agent_messages(id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, "
                       "message_data TEXT, created_at TEXT)")
        self.calls = 0
        self.at = "2026-11-15 09:00:00"
        (self.dir / "run.json").write_text(json.dumps({"targets_info": [], "status": "completed"}))
        (self.dir / ".state/agents.json").write_text(json.dumps({"statuses": {"a1": "completed", "a2": "completed"},
                                                                  "names": {"a1": "Recon", "a2": "Validator"}}))

    def msg(self, m, agent="a1", at=None):
        self.c.execute("INSERT INTO agent_messages(session_id,message_data,created_at) VALUES(?,?,?)",
                       (agent, json.dumps(m), at or self.at))
        self.c.commit()

    def tool(self, name, args, output, agent="a1", at=None):
        self.calls += 1
        cid = f"call-{self.calls}"
        self.msg({"type": "function_call", "call_id": cid, "name": name, "arguments": json.dumps(args)}, agent, at)
        self.msg({"type": "function_call_output", "call_id": cid, "output": output if not isinstance(output, dict)
                  else json.dumps(output)}, agent, at)
        return cid

    def exchange(self, rid, path="/api/orders/4", status=200, body=MARKER_TEXT, auth=TOKEN, method="GET",
                 agent="a1", caido_at="2026-11-15T09:00:01", list_it=True, location=None, has_more=False, zone_h=0, date=True):
        hdr = f"Authorization: {auth}\n" if auth else ""
        self.tool("view_request", {"request_id": rid, "part": "request"},
                  {"success": True, "content": f"{method} {path} HTTP/1.1\nHost: 127.0.0.1:8899\n{hdr}", "has_more": False}, agent)
        from datetime import datetime, timedelta
        from email.utils import format_datetime
        gmt = format_datetime(datetime.fromisoformat(caido_at).replace(tzinfo=__import__("datetime").timezone.utc), usegmt=True)
        local = (datetime.fromisoformat(caido_at) + timedelta(hours=zone_h)).isoformat()   # Caido: naive, sandbox zone
        loc = f"Location: {location}\n" if location else ""
        self.tool("view_request", {"request_id": rid, "part": "response"},
                  {"success": True, "content": f"HTTP/1.1 {status} X\n" + (f"Date: {gmt}\n" if date else "") + f"Content-Type: text/plain\n{loc}\n{body}", "has_more": has_more}, agent)
        if list_it:
            self.tool("list_requests", {}, {"success": True, "entries": [{"request": {
                "id": rid, "host": "127.0.0.1", "port": 8899, "method": method, "path": path, "is_tls": False,
                "created_at": local}, "response": {"status_code": status, "created_at": local}}]}, agent)

    def coverage(self, entries, complete=True):
        (self.dir / "coverage.json").write_text(json.dumps({"entries": entries, "completeness": {"complete": complete},
                                                             "gaps": []}))

    def vulns(self, items):
        (self.dir / "vulnerabilities.json").write_text(json.dumps(items))


class Base(unittest.TestCase):
    def setUp(self):
        db.init()
        self.tmp = tempfile.TemporaryDirectory(prefix="skynet-sky-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tid = db.insert("targets", {"name": f"SKY fixture {os.urandom(3).hex()}", "base_url": "http://127.0.0.1:8899",
                                         "environment": "test"})
        self.profile = {"id": 9001, "kind": "header", "name": "Tester token", "verify_expect_text": MARKER_TEXT,
                        "verify_expect_status": 200, "header_names": ["Authorization"],
                        "auth_bindings": [{"field": "authorization",
                                           "digest": verify._binding("header", "authorization", TOKEN)}]}

    def scan(self, run, status="completed", profiles=None, **kw):
        snap = [self.profile] if profiles is None else profiles
        return db.get_scan(db.insert("scans", {
            "target_id": self.tid, "status": status, "trigger": kw.pop("trigger", "manual"), "run_name": run.name,
            "run_dir": str(run.dir), "auth_snapshot": snap, "auth_profile_ids": [p["id"] for p in snap],
            "auth_profile_names": [p["name"] for p in snap], "started_at": kw.pop("started_at", "2026-11-15T08:59:00+00:00"),
            "redact_enc": crypto.vault_encrypt(json.dumps([TOKEN, TOKEN.split()[1]])), **kw}))

    def api(self):
        from test_features import TestAPI
        from skynet import auth, main
        self.M, self.auth = main, auth
        return TestAPI.request.__get__(self)

    def accepted_verification(self, scan, rids=("1", "2")):
        """Fixture for a settled classifier result, separate from an untrusted coverage claim."""
        gid = db.insert("finding_groups", {"target_id": self.tid, "fingerprint": f"accepted-fixture-{scan['id']}",
            "host": "127.0.0.1", "method": "GET", "endpoint": "/api/orders/{id}", "cwe": "CWE-639"})
        return db.insert("finding_verifications", {"scan_id": scan["id"], "group_id": gid, "target_id": self.tid,
            "classification_version": 2, "result": "not_reproduced",
            "verification_evidence": {"test_executed": True, "request_ids": list(rids)}})


# ======================================================================== SKY-02
class TestSessionHealth(Base):
    def test_precheck_success_then_loss_and_per_agent_states(self):
        r = Run(self.root)
        r.exchange("1", caido_at="2026-11-15T09:00:01", agent="a1")                         # verified (a1)
        r.exchange("2", status=401, body="unauthenticated", caido_at="2026-11-15T09:05:00", agent="a1")  # lost (a1)
        r.exchange("3", caido_at="2026-11-15T09:06:00", agent="a2")                         # verified (a2)
        s = self.scan(r, auth_checks=[{"profile_id": 9001, "result": "verified", "at": "2026-11-15T08:59:00+00:00",
                                       "kind": "header", "name": "Tester token"}])
        h = session_health.for_scan(s, r.dir)
        p = h["profiles"][0]
        self.assertEqual(p["state"], "unknown")                       # never one global verdict for the profile
        self.assertEqual(p["precheck"]["result"], "verified")
        self.assertIn("not evidence", p["precheck"]["label"])
        states = {a["agent_id"]: a["state"] for a in p["agents"]}
        self.assertEqual(states, {"a1": "lost", "a2": "verified"})
        a1 = next(a for a in p["agents"] if a["agent_id"] == "a1")
        self.assertEqual(a1["evidence"]["at"], "2026-11-15T09:05:00.000Z")
        self.assertEqual(a1["evidence"]["time_source"], "caido")
        self.assertEqual(a1["evidence"]["request_key"], f"{r.name}:2")
        raw = json.dumps(h)
        self.assertNotIn("sky-fixture-token-123", raw)
        self.assertNotIn("auth_bindings", raw)
        self.assertNotRegex(raw, r"[0-9a-f]{64}")                       # no keyed digests either

    def test_date_header_orders_signals_and_view_time_never_picks_a_winner(self):
        r = Run(self.root)
        r.exchange("1", caido_at="2026-11-15T09:00:01", list_it=False)                        # Date header only
        r.exchange("2", status=401, body="no", caido_at="2026-11-15T09:05:00", list_it=False)
        p = session_health.for_scan(self.scan(r), r.dir)["profiles"][0]
        self.assertEqual([s["time_source"] for s in p["signals"]], ["date_header", "date_header"])
        self.assertEqual(p["agents"][0]["state"], "lost")
        r2 = Run(self.root)
        r2.exchange("1", list_it=False, date=False)                                            # only view times
        r2.exchange("2", status=401, body="no", list_it=False, date=False)
        p2 = session_health.for_scan(self.scan(r2), r2.dir)["profiles"][0]
        self.assertEqual(p2["agents"][0]["state"], "unknown")
        self.assertIn("order cannot be established", p2["agents"][0]["reason"])

    def test_403_and_plain_200_are_not_session_evidence(self):
        r = Run(self.root)
        r.exchange("1", status=403, body="forbidden")
        r.exchange("2", status=200, body="no marker here")
        p = session_health.for_scan(self.scan(r), r.dir)["profiles"][0]
        self.assertEqual([s["signal"] for s in p["signals"]], ["denied", "none"])
        self.assertEqual(p["agents"][0]["state"], "unknown")

    def test_login_redirect_is_lost_and_other_credentials_ignored(self):
        r = Run(self.root)
        r.exchange("1", status=302, body="", location="/login?next=/x")
        r.exchange("2", auth=OTHER)                      # someone else's token: not this profile's evidence
        p = session_health.for_scan(self.scan(r), r.dir)["profiles"][0]
        self.assertEqual([s["request_id"] for s in p["signals"]], ["1"])
        self.assertEqual(p["agents"][0]["state"], "lost")

    def test_form_login_and_anonymous(self):
        r = Run(self.root)
        r.exchange("1")
        profs = [{"id": 1, "kind": "credentials", "name": "Form user"}, {"id": 2, "kind": "anonymous", "name": "Anon"}]
        out = {p["kind"]: p for p in session_health.for_scan(self.scan(r, profiles=profs), r.dir)["profiles"]}
        self.assertEqual(out["credentials"]["state"], "unknown")
        self.assertIn("Form login", out["credentials"]["reason"])
        self.assertEqual(out["anonymous"]["state"], "not_applicable")

    def test_incomplete_response_page_is_not_evidence(self):
        r = Run(self.root)
        r.exchange("1", has_more=True)
        p = session_health.for_scan(self.scan(r), r.dir)["profiles"][0]
        self.assertEqual(p["signals"], [])

    def test_form_login_negative_verification_stays_inconclusive(self):
        """Existing Verify contract, re-checked here as SKY-02 acceptance: a pre-check or form login never makes a
        negative verdict."""
        r = Run(self.root)
        r.exchange("11", path="/api/orders/4")
        r.exchange("12", path="/api/orders/5")
        r.tool("exec_command", {}, "Output:\n" + verify.MARKER + json.dumps({
            "group_id": 77, "outcome": "not_reproduced", "test_completed": True, "reason": "denied",
            "probe_request_ids": ["11"], "control_request_ids": ["12"]}))
        group = {"id": 77, "fingerprint": "x", "host": "127.0.0.1", "method": "GET", "endpoint": "/api/orders/{id}"}
        target = {"base_url": "http://127.0.0.1:8899", "in_scope": [], "out_of_scope": [], "extra_targets": []}
        res = verify.classify({"status": "completed", "exit_code": 0}, r.dir, group, target,
                              [{"kind": "credentials", "name": "Form user"}])
        self.assertEqual(res[0], "inconclusive")


# ======================================================================== SKY-03
class TestCoverageMatrix(Base):
    def entry(self, surface, risk="Broken object-level authorization (IDOR)", outcome="no_issue_found", ev="checked",
              by="Recon", at="2026-11-15 09:10:00 UTC"):
        return {"surface": surface, "risk_area": risk, "outcome": outcome, "outcome_label": outcome, "evidence": ev,
                "recorded_by": by, "recorded_at": at}

    def cells(self, r, verified=False, **kw):
        scan = self.scan(r, **kw)
        if verified:
            self.accepted_verification(scan)
        m = coverage_matrix.build(scan, r.dir)
        return m, {(c["endpoint"], c["role"], c["test_type"]): c for c in m["cells"]}

    def test_statuses_require_recorded_evidence(self):
        r = Run(self.root)
        r.exchange("1", path="/api/orders/1")
        r.exchange("2", path="/api/orders/2")                                   # linked to an accepted test below
        r.exchange("3", path="/api/me")                                          # single → partial
        r.exchange("4", path="/api/admin", status=403, body="no")                # all refused → blocked
        r.exchange("5", path="/api/admin", status=401, body="no")
        r.coverage([self.entry("GET /api/orders/{id}"), self.entry("GET /api/me"),
                    self.entry("GET /api/admin", outcome="ruled_out"),
                    self.entry("GET /api/products"),                             # claim only → unknown
                    self.entry("POST /api/upload", risk="SQL injection", outcome="not_applicable", ev="no upload route"),
                    self.entry("Login page and SSO", risk="Authentication")])  # unmappable surface
        cov_hash = sha(r.dir / "coverage.json")
        m, c = self.cells(r, verified=True)
        self.assertEqual(c[("GET /api/orders/{id}", "profile:9001", "WSTG-ATHZ")]["status"], "tested")
        self.assertEqual(c[("GET /api/me", "profile:9001", "WSTG-ATHZ")]["status"], "partial")
        self.assertEqual(c[("GET /api/admin", "profile:9001", "WSTG-ATHZ")]["status"], "blocked")
        self.assertEqual(c[("GET /api/products", "profile:9001", "WSTG-ATHZ")]["status"], "unknown")
        na = c[("POST /api/upload", "profile:9001", "WSTG-INPV")]
        self.assertEqual(na["status"], "not_applicable")
        self.assertIn("no upload route", na["reasons"][0])
        self.assertTrue(any(k[0].startswith("(unmapped surface)") for k in c))
        # every Tested cell links to verifiable full exchanges of this run
        ex = __import__("skynet.evidence", fromlist=["x"]).load(r.dir)
        for cell in m["cells"]:
            if cell["status"] == "tested":
                self.assertGreaterEqual(len(cell["evidence"]), 2)
                for e in cell["evidence"]:
                    self.assertTrue(e["key"].startswith(r.name + ":"))
                    self.assertTrue(__import__("skynet.evidence", fromlist=["x"]).full(ex[e["request_id"]]))
        # source claims are preserved verbatim and the file is not modified
        self.assertEqual(sha(r.dir / "coverage.json"), cov_hash)
        self.assertEqual(m["claims"][0]["outcome"], "no_issue_found")
        self.assertEqual(m["wstg_version"], "OWASP WSTG v4.2")

    def test_evidence_must_belong_to_the_coverage_record(self):
        r = Run(self.root)
        r.exchange("1", path="/api/orders/1", agent="a1")
        r.exchange("2", path="/api/orders/2", agent="a1")
        r.coverage([self.entry("GET /api/orders/{id}", by="Validator"),                         # a2 wrote it, a1 viewed
                    self.entry("GET /api/orders/{id}", risk="SQL injection", by="Recon",
                               at="2026-11-15 08:00:00 UTC")])                                    # written before viewing
        _, c = self.cells(r)
        a = c[("GET /api/orders/{id}", "profile:9001", "WSTG-ATHZ")]
        self.assertEqual(a["status"], "partial")
        self.assertIn("none belong to this record", a["reasons"][0])
        self.assertEqual(c[("GET /api/orders/{id}", "profile:9001", "WSTG-INPV")]["status"], "partial")

    def test_reported_record_uses_its_finding_links_and_merged_cells_keep_weaker_records(self):
        r = Run(self.root)
        r.exchange("1", path="/api/orders/1", agent="a1")
        r.exchange("2", path="/api/orders/2", agent="a1")
        r.vulns([{"id": "vuln-0001", "http_exchange_ids": ["1", "2"]}])
        r.coverage([self.entry("GET /api/orders/{id}", outcome="reported", by="Validator", ev="Reported (vuln-0001)."),
                    self.entry("GET /api/orders/{id} path aliases", outcome="ruled_out", by="Validator")])
        _, c = self.cells(r, verified=True)
        cell = c[("GET /api/orders/{id}", "profile:9001", "WSTG-ATHZ")]
        self.assertEqual(cell["status"], "tested")
        self.assertTrue(cell["mixed"])
        self.assertEqual(sorted(x["status"] for x in cell["claim_results"]), ["partial", "tested"])
        self.assertIn("1 of 2 records", cell["status_label"])

    def test_claim_alone_and_single_request_are_not_tested(self):
        r = Run(self.root)
        r.exchange("1", path="/api/orders/1")
        r.coverage([self.entry("GET /api/orders/{id}")])
        _, c = self.cells(r)
        self.assertEqual(c[("GET /api/orders/{id}", "profile:9001", "WSTG-ATHZ")]["status"], "partial")

    def test_traffic_without_record_and_anonymous_role(self):
        r = Run(self.root)
        r.exchange("1", path="/api/public", auth=None)
        r.coverage([])
        _, c = self.cells(r)
        self.assertEqual(c[("GET /api/public", "anonymous", "NONE")]["status"], "unknown")

    def test_missing_coverage_file(self):
        r = Run(self.root)
        m, _ = self.cells(r)
        self.assertIn("did not write coverage.json", m["gaps"][0])


# ======================================================================== SKY-07
class TestWorkspace(Base):
    def setUp(self):
        super().setUp()
        self.r = Run(self.root)
        self.r.exchange("802", path="/api/orders/2", status=401, body='{"error": "unauthenticated"}', auth=None)
        self.r.exchange("804", path="/api/orders/2", body='<script>alert(1)</script> owner admin ' + TOKEN)
        self.vuln = {"id": "vuln-0001", "title": "IDOR", "severity": "medium", "target": "http://127.0.0.1:8899",
                     "endpoint": "/api/orders/2", "method": "GET", "cwe": "CWE-639", "evidence": "e",
                     "http_exchange_ids": ["802", "804", "999"]}
        self.r.vulns([self.vuln])
        self.s = self.scan(self.r)
        findings_store.ingest(self.s, self.r.dir)
        self.gid = db.q1("SELECT group_id FROM finding_occurrences WHERE run_name=?", (self.r.name,))["group_id"]
        self.oid = db.q1("SELECT id FROM finding_occurrences WHERE run_name=?", (self.r.name,))["id"]

    def snapshot(self):
        return (db.q("SELECT * FROM finding_occurrences WHERE group_id=?", (self.gid,)),
                db.q("SELECT * FROM finding_groups WHERE id=?", (self.gid,)),
                db.q("SELECT * FROM finding_verifications WHERE group_id=?", (self.gid,)),
                sha(self.r.dir / "vulnerabilities.json"), sha(self.r.dir / ".state/agents.db"))

    def test_strix_links_are_not_paired_and_missing_is_explicit(self):
        w = workspace.build(self.gid, self.oid)
        ex = {x["request_id"]: x for x in w["context"]["exchanges"]}
        self.assertEqual({x["role"] for x in ex.values()}, {"unassigned"})
        self.assertEqual({x["role_source"] for x in ex.values()}, {"strix_link"})
        self.assertTrue(ex["999"]["missing"])
        self.assertTrue(ex["804"]["full"])
        self.assertIn("does not pair", w["context"]["pairing_note"])
        raw = json.dumps(w)
        self.assertNotIn("sky-fixture-token-123", raw)
        self.assertIn("<script>alert(1)</script>", ex["804"]["response"]["text"])   # plain text, rendered as text node
        self.assertFalse(any(k.endswith("_html") for k in ex["804"]))

    def test_notes_labels_reviews_never_touch_evidence(self):
        before = self.snapshot()
        workspace.add_note(self.gid, "First look " + TOKEN, "admin", self.oid)
        nid = db.q1("SELECT id FROM analyst_notes WHERE group_id=?", (self.gid,))["id"]
        workspace.edit_note(self.gid, nid, "Second look", "admin")
        workspace.set_label(self.gid, self.r.name, "804", "attack", "admin", self.oid)
        workspace.set_label(self.gid, self.r.name, "802", "control", "admin", self.oid)
        workspace.review(self.gid, self.oid, "confirmed", "same issue", "admin")
        self.assertEqual(self.snapshot(), before)
        n = workspace.notes(self.gid)[0]
        self.assertEqual(n["body"], "Second look")
        self.assertEqual(len(n["revisions"]), 2)
        self.assertNotIn("sky-fixture-token-123", json.dumps(n))
        stored = db.q1("SELECT body_enc FROM analyst_note_revisions WHERE note_id=? ORDER BY id", (nid,))["body_enc"]
        self.assertNotIn("First look", stored)                  # encrypted at rest
        ex = {x["request_id"]: x for x in workspace.build(self.gid, self.oid)["context"]["exchanges"]}
        self.assertEqual((ex["804"]["role"], ex["804"]["role_source"]), ("attack", "analyst"))
        self.assertEqual(workspace.build(self.gid)["occurrences"][0]["correlation"]["state"], "analyst_confirmed")
        with self.assertRaises(ValueError):
            workspace.set_label(self.gid, "unrelated-run", "1", "attack", "admin")

    def test_diff_and_download_are_masked(self):
        d = workspace.diff(self.gid, f"{self.r.name}:802", f"{self.r.name}:804")
        self.assertTrue(d["available"])
        self.assertIn("masked", d["note"])
        self.assertNotIn("sky-fixture-token-123", json.dumps(d))
        txt = workspace.download_text(self.gid, self.r.name, "804")
        self.assertNotIn("sky-fixture-token-123", txt)
        self.assertIn("owner admin", txt)
        with self.assertRaises(LookupError):
            workspace.download_text(self.gid, "other-run", "804")

    def test_reingest_keeps_notes_and_does_not_duplicate(self):
        workspace.add_note(self.gid, "kept", "admin", self.oid)
        findings_store.ingest(self.s, self.r.dir)
        findings_store.ingest(self.s, self.r.dir)
        self.assertEqual(db.q1("SELECT COUNT(*) n FROM finding_occurrences WHERE group_id=?", (self.gid,))["n"], 1)
        self.assertEqual(db.q1("SELECT id FROM finding_occurrences WHERE run_name=?", (self.r.name,))["id"], self.oid)
        self.assertEqual([n["body"] for n in workspace.notes(self.gid)], ["kept"])

    def test_new_verification_does_not_overwrite_older_evidence(self):
        v1 = Run(self.root)
        v1.exchange("11", path="/api/orders/2")
        v1.exchange("12", path="/api/orders/3")
        v1.tool("exec_command", {}, "Output:\n" + verify.MARKER + json.dumps({
            "group_id": self.gid, "outcome": "inconclusive", "test_completed": True, "reason": "r",
            "probe_request_ids": ["11"], "control_request_ids": ["12"]}))
        s1 = self.scan(v1, trigger="verify")
        f1 = db.insert("finding_verifications", {"group_id": self.gid, "target_id": self.tid, "scan_id": s1["id"],
                                                 "result": "inconclusive", "classification_version": 2})
        first = workspace.build(self.gid, verification_id=f1)["context"]
        v2 = Run(self.root)
        s2 = self.scan(v2, trigger="verify")
        f2 = db.insert("finding_verifications", {"group_id": self.gid, "target_id": self.tid, "scan_id": s2["id"],
                                                 "result": "pending", "classification_version": 2})
        self.assertEqual(workspace.build(self.gid, verification_id=f1)["context"], first)
        roles = {x["request_id"]: (x["role"], x["role_source"]) for x in first["exchanges"]}
        self.assertEqual(roles, {"11": ("attack", "assessment"), "12": ("control", "assessment")})
        self.assertTrue(workspace.build(self.gid, verification_id=f2)["context"]["gaps"])

    def test_missing_run_folder_is_a_gap(self):
        import shutil
        shutil.rmtree(self.r.dir)
        ctx = workspace.build(self.gid, self.oid)["context"]
        self.assertIn("missing", ctx["gaps"][0])

    def test_api_requires_csrf_and_writes_only_analyst_tables(self):
        request = self.api()
        st, _ = request(f"/api/findings/{self.gid}/notes", "POST", {"body": "x"}, csrf=False)
        self.assertEqual(st, 403)
        st, body = request(f"/api/findings/{self.gid}/notes", "POST", {"body": "via api", "occurrence_id": self.oid})
        self.assertEqual(st, 200)
        self.assertEqual(body["notes"][0]["body"], "via api")
        st, w = request(f"/api/findings/{self.gid}/workspace?occurrence_id={self.oid}")
        self.assertEqual(st, 200)
        self.assertNotIn("sky-fixture-token-123", json.dumps(w))


# ======================================================================== SKY-01
class TestCompare(Base):
    def make(self, rids, vulns, status="completed", profiles=None, mode="standard", complete=True):
        r = Run(self.root)
        for i, rid in enumerate(rids):
            r.exchange(rid, path=f"/api/orders/{i + 1}")
        r.coverage([{"surface": "GET /api/orders/{id}", "risk_area": "IDOR", "outcome": "no_issue_found",
                     "evidence": "x", "recorded_by": "Recon", "recorded_at": "2026-11-15 09:10:00 UTC"}], complete=complete)
        r.vulns(vulns)
        s = self.scan(r, status=status, profiles=profiles, scan_mode=mode)
        findings_store.ingest(s, r.dir)
        inventory.ingest(s, r.dir, Redactor())
        db.execute("INSERT OR REPLACE INTO run_ingest(run_name, scan_id, target_id, complete, scan_status) VALUES (?,?,?,?,?)",
                   (r.name, s["id"], self.tid, 1 if complete else 0, status))
        return s

    def vuln(self, vid, ep):
        return {"id": vid, "title": f"Issue {ep}", "severity": "high", "target": "http://127.0.0.1:8899",
                "endpoint": ep, "method": "GET", "cwe": "CWE-639"}

    def test_missing_finding_is_not_fixed_and_caveats(self):
        a = self.make(["1", "2"], [self.vuln("vuln-1", "/api/orders/1"), self.vuln("vuln-2", "/api/a")])
        b = self.make(["3"], [self.vuln("vuln-1", "/api/orders/1"), self.vuln("vuln-9", "/api/b")], status="cancelled",
                      profiles=[], mode="quick", complete=False)
        groups_before = db.q("SELECT id, remediation FROM finding_groups WHERE target_id=?", (self.tid,))
        out = compare.compare(a["id"], b["id"])
        self.assertEqual([f["title"] for f in out["findings"]["not_observed"]], ["Issue /api/a"])
        self.assertEqual(out["findings"]["not_observed"][0]["remediation"], "open")
        self.assertEqual([f["title"] for f in out["findings"]["new"]], ["Issue /api/b"])
        self.assertEqual(out["findings"]["seen_again"][0]["match"], "fingerprint_candidate")
        text = " ".join(c["text"] for c in out["caveats"])
        for s in ("cancelled", "coverage record incomplete", "Scan modes differ", "profiles differ"):
            self.assertIn(s, text)
        def keys(o):
            return [k for k, v in o.items() for k in [k, *keys(v)]] if isinstance(o, dict) else \
                [k for v in o for k in keys(v)] if isinstance(o, list) else []
        self.assertFalse([k for k in keys(out) if "score" in k.lower()])     # no improvement score
        self.assertIn("against_all_prior", out)                       # reuses inventory.run_diff
        self.assertEqual(out["label"], "Scan comparison (no release, build or commit recorded)")
        self.assertEqual(db.q("SELECT id, remediation FROM finding_groups WHERE target_id=?", (self.tid,)), groups_before)
        gone = {e["label"]: e for e in out["endpoints"]["not_observed"]}
        self.assertEqual(gone["GET /api/orders/{id}"]["state"] if "GET /api/orders/{id}" in gone else "both", "both")

    def test_reimport_is_idempotent(self):
        a = self.make(["1", "2"], [self.vuln("vuln-1", "/api/orders/1")])
        b = self.make(["3", "4"], [self.vuln("vuln-1", "/api/orders/1")])
        first = compare.compare(a["id"], b["id"])
        counts = [db.q1(f"SELECT COUNT(*) n FROM {t}")["n"] for t in ("finding_groups", "finding_occurrences", "assets",
                                                                      "asset_observations")]
        for s in (a, b):
            findings_store.ingest(s, Path(s["run_dir"]))
            inventory.ingest(s, Path(s["run_dir"]), Redactor())
        self.assertEqual(compare.compare(a["id"], b["id"]), first)
        self.assertEqual([db.q1(f"SELECT COUNT(*) n FROM {t}")["n"] for t in ("finding_groups", "finding_occurrences",
                                                                              "assets", "asset_observations")], counts)

    def test_analyst_confirmed_match_is_distinct(self):
        a = self.make(["1", "2"], [self.vuln("vuln-1", "/api/orders/1")])
        b = self.make(["3", "4"], [self.vuln("vuln-7", "/api/orders/1")])
        for s in (a, b):
            o = db.q1("SELECT id, group_id FROM finding_occurrences WHERE run_name=?", (s["run_name"],))
            workspace.review(o["group_id"], o["id"], "confirmed", "", "admin")
        self.assertEqual(compare.compare(a["id"], b["id"])["findings"]["seen_again"][0]["match"], "analyst_confirmed")

    def test_tested_endpoint_missing_is_not_tested_in_run(self):
        a = self.make(["1", "2"], [])
        self.accepted_verification(a)
        r = Run(self.root)
        r.coverage([])
        r.vulns([])
        b = self.scan(r)
        out = compare.compare(a["id"], b["id"])
        gone = {e["label"]: e for e in out["endpoints"]["not_observed"]}
        self.assertEqual(gone["GET /api/orders/{id}"]["state_label"], "Not tested in this run")
        self.assertTrue(any(c["reference_status"] == "tested" for c in out["coverage_changes"]))

    def test_coverage_lookup_is_per_method(self):
        c = compare._cell_index({"cells": [{"endpoint": "GET /api/x", "status": "partial"},
                                           {"endpoint": "* /api/y", "status": "tested"}]})
        self.assertIsNone(c.find("OPTIONS", "/api/x"))
        self.assertEqual(c.find("GET", "/api/x")["status"], "partial")
        self.assertEqual(c.find("POST", "/api/y")["status"], "tested")
        self.assertEqual(c.find("", "/api/x")["status"], "partial")

    def test_other_target_refused(self):
        a = self.make(["1"], [])
        other = db.insert("targets", {"name": "other", "base_url": "http://127.0.0.1:9", "environment": "test"})
        b = db.insert("scans", {"target_id": other, "status": "completed", "run_name": "x", "run_dir": "/nonexistent"})
        with self.assertRaises(ValueError):
            compare.compare(a["id"], b)


# ======================================================================== SKY-04
class TestInstructionCenter(Base):
    def test_marker_position_and_following_activity(self):
        r = Run(self.root)
        r.tool("exec_command", {"cmd": "before"}, "before-output", agent="a1")
        rid = "rid-" + os.urandom(6).hex()
        r.msg({"role": "user", "content": f"[Operator message via Skynet console | id={rid}]\nA human operator...\n\nfocus"}, "a1")
        r.tool("exec_command", {"cmd": "after-a1"}, "x", agent="a1")
        r.tool("exec_command", {"cmd": "after-a2"}, "y", agent="a2")
        s = self.scan(r, status="completed", control_mode="bridge")
        mid = db.insert("agent_messages", {"scan_id": s["id"], "request_id": rid, "agent_id": "a1", "agent_name": "Recon",
                                           "content_enc": crypto.vault_encrypt("focus " + TOKEN), "state": "delivered",
                                           "created_at": "2026-11-15T09:00:00+00:00", "accepted_at": "2026-11-15T09:00:01+00:00",
                                           "delivered_at": "2026-11-15T09:00:03+00:00"})
        self.assertIsNotNone(control.marker_position(r.dir, "a1", rid))
        self.assertIsNone(control.marker_position(r.dir, "a2", rid))
        request = self.api()
        st, out = request(f"/api/scans/{s['id']}/messages/{mid}/activity")
        self.assertEqual(st, 200)
        self.assertTrue(out["marker_found"])
        cmds = [i["text"] for i in out["items"] if i["kind"] == "tool_call"]
        self.assertTrue(any("after-a1" in c for c in cmds))
        self.assertFalse(any("after-a2" in c or "before" in c for c in cmds))
        self.assertEqual(out["application"]["state"], "not_confirmed")
        st, m = request(f"/api/scans/{s['id']}/messages?agent_id=a1")
        row = m["messages"][0]
        self.assertEqual(row["stage_label"], "In agent context")
        self.assertEqual(row["application"]["label"], "Application not confirmed")
        self.assertNotIn("sky-fixture-token-123", json.dumps(m))
        st, m2 = request(f"/api/scans/{s['id']}/messages?agent_id=a2")
        self.assertEqual(m2["messages"], [])

    def test_accepted_then_ended_is_distinct_from_in_context(self):
        base = {"id": 1, "state": "expired", "accepted_at": "2026-11-15T09:00:01+00:00", "created_at": "x"}
        v = control.instruction_view(base)
        self.assertTrue(v["accepted_then_ended"])
        self.assertEqual(v["stage_label"], "Accepted, ended before reaching context")
        self.assertIsNone(v["application"])
        self.assertFalse(control.instruction_view({**base, "accepted_at": None})["accepted_then_ended"])
        self.assertEqual(control.instruction_view({**base, "state": "delivered"})["stage_label"], "In agent context")

    def test_undelivered_message_has_no_following_activity(self):
        r = Run(self.root)
        s = self.scan(r, control_mode="bridge")
        mid = db.insert("agent_messages", {"scan_id": s["id"], "request_id": "rid-" + os.urandom(6).hex(), "agent_id": "a1",
                                           "content_enc": crypto.vault_encrypt("x"), "state": "expired",
                                           "accepted_at": "2026-11-15T09:00:01+00:00"})
        st, out = self.api()(f"/api/scans/{s['id']}/messages/{mid}/activity")
        self.assertFalse(out["marker_found"])
        self.assertEqual(out["items"], [])


# ======================================================================== SKY-06
class TestTimeline(Base):
    def test_stable_keys_survive_session_rewrite_and_no_duplicates(self):
        r = Run(self.root)
        r.exchange("5", caido_at="2026-11-15T09:00:05")
        for i in range(15):                                              # 30 session items
            r.tool("exec_command", {"cmd": f"id {i}"}, "uid=1", at=f"2026-11-15 09:00:{i:02d}")
        r.msg({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done " + TOKEN}]},
              at="2026-11-15 09:00:03")
        r.vulns([{"id": "vuln-1", "title": "x", "severity": "low", "timestamp": "2026-11-15 09:00:04 UTC"}])
        s = self.scan(r)
        first = timeline.page(s, r.dir, limit=500)["events"]
        keys = [e["key"] for e in first]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertNotIn("sky-fixture-token-123", json.dumps(first))
        # Strix rewrites the session: clear + re-insert, new row ids and one shared stored time.
        rows = r.c.execute("SELECT session_id, message_data FROM agent_messages ORDER BY id").fetchall()
        r.c.execute("DELETE FROM agent_messages")
        for sid, data in rows * 1:
            r.c.execute("INSERT INTO agent_messages(session_id,message_data,created_at) VALUES(?,?,?)",
                        (sid, data, "2026-11-15 10:00:00"))
        r.c.commit()
        second = timeline.page(s, r.dir, limit=500)
        self.assertEqual(sorted(e["key"] for e in second["events"]), sorted(keys))
        rewritten = [e for e in second["events"] if e["kind"] == "tool_call"]
        self.assertTrue(all(e["at"] is None for e in rewritten))           # rewrite time is not the event time
        self.assertTrue(all("rewritten" in e["time_note"] for e in rewritten))
        caido = next(e for e in second["events"] if e["kind"] == "http_request")
        self.assertEqual((caido["at"], caido["time_source"]), ("2026-11-15T09:00:05.000Z", "source"))
        self.assertEqual(timeline.page(s, r.dir, limit=500)["events"], second["events"])

    def test_live_follow_returns_late_events_wherever_they_sort(self):
        r = Run(self.root)
        r.exchange("1", caido_at="2026-11-15T09:00:01")
        s = self.scan(r, status="running")
        first = timeline.page(s, r.dir, limit=1)
        self.assertEqual(timeline.page(s, r.dir, seen_after=first["now"])["events"], [])
        r.msg({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "late"}]},
              at="2026-11-14 08:00:00")                                   # sorts before everything already seen
        new = timeline.page(s, r.dir, seen_after=first["now"])["events"]
        self.assertEqual([e["summary"] for e in new], ["late"])
        self.assertEqual(timeline.page(s, r.dir, limit=500)["events"][0]["summary"], "late")

    def test_session_event_keys_are_not_masked_into_collisions(self):
        r = Run(self.root)
        r.exchange("1032", path="/api/me")
        r.exchange("804", path="/api/orders/2")
        ev = timeline.page(self.scan(r), r.dir, kinds=["session"], limit=500)["events"]
        self.assertEqual(sorted(e["key"] for e in ev), sorted(f"{r.name}:auth:9001:{i}" for i in ("1032", "804")))

    def test_caido_zone_is_derived_from_gmt_date_headers(self):
        from skynet import evidence
        r = Run(self.root)
        r.exchange("1", caido_at="2026-11-14T21:41:41", zone_h=3)     # real run: Caido wrote 00:41:41 for 21:41:41 GMT
        r.exchange("2", caido_at="2026-11-14T21:42:00", zone_h=3, list_it=True)
        ex = evidence.load(r.dir)
        self.assertEqual(ex["1"]["listed"]["caido_offset_minutes"], 180)
        self.assertEqual(evidence.source_time(ex["1"]), "2026-11-14T21:41:41.000Z")
        r2 = Run(self.root)                                              # list metadata only: zone cannot be derived
        r2.tool("list_requests", {}, {"success": True, "entries": [{"request": {"id": "9", "host": "h", "port": 1,
                "method": "GET", "path": "/", "created_at": "2026-11-15T00:41:41"}, "response": {"status_code": 200}}]})
        self.assertIsNone(evidence.source_time(evidence.load(r2.dir)["9"]))

    def test_out_of_order_ties_untimed_filters_paging(self):
        r = Run(self.root)
        r.exchange("2", caido_at="2026-11-15T09:00:09")
        r.exchange("1", caido_at="2026-11-15T09:00:01")
        r.exchange("3", caido_at="2026-11-15T09:00:09")
        r.msg({"type": "function_call", "call_id": "nt", "name": "exec_command", "arguments": "{}"}, at=None)
        r.c.execute("UPDATE agent_messages SET created_at=NULL WHERE message_data LIKE '%\"nt\"%'")
        r.c.commit()
        s = self.scan(r)
        http = timeline.page(s, r.dir, kinds=["http_request"])["events"]
        self.assertEqual([e["request_id"] for e in http], ["1", "2", "3"])
        self.assertTrue(http[1]["same_time"] and http[2]["same_time"])
        allp = timeline.page(s, r.dir, limit=500)
        untimed = [e for e in allp["events"] if not e["at"]]
        self.assertTrue(untimed and all(e == allp["events"][-len(untimed):][i] for i, e in enumerate(untimed)))
        p1 = timeline.page(s, r.dir, offset=0, limit=3)
        p2 = timeline.page(s, r.dir, offset=3, limit=3)
        self.assertFalse({e["key"] for e in p1["events"]} & {e["key"] for e in p2["events"]})
        self.assertEqual(p1["total"], allp["total"])
        self.assertTrue(all(e.get("agent_id") == "a1" for e in timeline.page(s, r.dir, agent_id="a1")["events"]))

    def test_timeline_and_browser_never_run_anything(self):
        r = Run(self.root)
        r.exchange("1")
        s = self.scan(r, status="running")
        request = self.api()
        boom = mock.Mock(side_effect=AssertionError("must not be called"))
        with mock.patch.object(__import__("skynet.runner", fromlist=["x"]), "enqueue", boom), \
                mock.patch.object(control, "send", boom), mock.patch.object(control, "_call", boom), \
                mock.patch("urllib.request.urlopen", boom), mock.patch("http.client.HTTPConnection", boom):
            for path in (f"/api/scans/{s['id']}/timeline?limit=50", f"/api/scans/{s['id']}/timeline?offset=1",
                         f"/api/scans/{s['id']}/browser?agent_id=a1", f"/api/scans/{s['id']}/session-health",
                         f"/api/scans/{s['id']}/coverage-matrix"):
                st, _ = request(path)
                self.assertEqual(st, 200, path)
        self.assertEqual(db.get_scan(s["id"])["status"], "running")


# ======================================================================== SKY-05
class TestBrowser(Base):
    IMG = "data:image/png;base64," + "iVBORw0KGgo" + "A" * 4000

    def test_images_are_withheld_and_attributed_to_their_agent(self):
        r = Run(self.root)
        r.msg({"type": "function_call", "call_id": "v1", "name": "view_image",
               "arguments": json.dumps({"path": "/workspace/.agent-browser-screenshots/a.png"})}, "a1")
        r.msg({"type": "function_call_output", "call_id": "v1", "output": [{"type": "input_image", "image_url": self.IMG}]}, "a1")
        r.msg({"type": "function_call_output", "call_id": "v0",
               "output": [{"type": "input_text", "text": "[older screenshot elided to bound context memory]"}]}, "a1")
        s = self.scan(r, status="completed")
        v1 = browser.view(s, r.dir, "a1", Redactor())
        self.assertEqual(v1["freshness_label"], "Recorded")
        self.assertFalse(v1["capability"]["stream"])
        self.assertEqual([x["state"] for x in v1["screenshots"]], ["stored", "elided"])
        self.assertTrue(all(x["agent_id"] == "a1" for x in v1["screenshots"]))
        self.assertNotIn("iVBORw0KGgo", json.dumps(v1))
        v2 = browser.view(s, r.dir, "a2", Redactor())                  # another agent never inherits a1's image
        self.assertEqual((v2["screenshots"], v2["latest"], v2["freshness"]), ([], None, "unavailable"))
        feed = activity.read(r.dir, Redactor(), -1, "a1", 60)
        self.assertNotIn("iVBORw0KGgo", json.dumps(feed))
        self.assertTrue(any(activity.IMAGE_WITHHELD in i["text"] for i in feed["items"]))
        tl = timeline.page(s, r.dir, limit=500)
        self.assertNotIn("iVBORw0KGgo", json.dumps(tl))

    def test_freshness_thresholds(self):
        from datetime import datetime, timedelta, timezone
        r = Run(self.root)
        r.msg({"type": "function_call_output", "call_id": "v1", "output": [{"type": "input_image", "image_url": self.IMG}]},
              "a1", at="2026-11-15 09:00:00")
        s = self.scan(r, status="running")
        t0 = datetime(2026, 11, 15, 9, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(browser.view(s, r.dir, "a1", Redactor(), t0 + timedelta(seconds=30))["freshness"], "latest")
        self.assertEqual(browser.view(s, r.dir, "a1", Redactor(), t0 + timedelta(seconds=600))["freshness"], "stale")
        self.assertEqual(browser.view(s, None, "a1", Redactor())["freshness"], "unavailable")


if __name__ == "__main__":
    unittest.main()
