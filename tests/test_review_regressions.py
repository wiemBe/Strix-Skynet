"""Regression cases from the independent SKY review. Temp fixtures only; no scan or provider calls."""
import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_sky as fx
from skynet import compare, coverage_matrix, db, session_health, timeline, vault


class TestReviewRegressions(fx.Base):
    def run_fixture(self):
        r = fx.Run(self.root)
        self.addCleanup(r.c.close)
        return r
    def claim(self, surface="GET /api/orders/{id}", risk="SQL injection"):
        return {"surface": surface, "risk_area": risk, "outcome": "no_issue_found", "evidence": "tested",
                "recorded_by": "Recon", "recorded_at": "2026-11-15 09:10:00 UTC"}

    def event(self, run, text, at="2026-11-14 07:00:00"):
        run.msg({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}, at=at)

    def move_host(self, run, rid, host, port):
        for mid, raw in run.c.execute("SELECT id,message_data FROM agent_messages").fetchall():
            m = json.loads(raw)
            if m.get("type") == "function_call":
                continue
            # Each exchange has a unique numbered call prefix (three tools).
            first = (int(rid) - 1) * 3 + 1
            if m.get("call_id") not in [f"call-{i}" for i in range(first, first + 3)]:
                continue
            raw = raw.replace("127.0.0.1:8899", f"{host}:{port}")
            if '"list_requests"' not in raw:  # listed response metadata is JSON embedded in output
                raw = raw.replace('127.0.0.1', host).replace('8899', str(port))
            run.c.execute("UPDATE agent_messages SET message_data=? WHERE id=?", (raw, mid))
        run.c.commit()

    def test_r1_vault_addition_and_rotation_invalidate_masked_cache(self):
        r = self.run_fixture()
        first, second = "review-secret-added-498217", "review-secret-rotated-568723"
        self.event(r, f"observed literals {first} and {second}")
        s = self.scan(r)
        before = timeline.page(s, r.dir)
        pid = vault.save({"kind": "header", "name": "Review key", "headers": [{"name": "X-Key", "value": first}]}, None)
        added = timeline.page(s, r.dir)
        self.assertNotIn(first, json.dumps(added))
        self.assertNotEqual(before["masking_revision"], added["masking_revision"])
        # A costly live cache may throttle file rebuilds, but must never throttle new masking rules.
        cached = timeline._cache[s["id"]]
        timeline._cache[s["id"]] = (*cached[:3], 1000, *cached[4:])
        s["status"] = "running"
        vault.save({"kind": "header", "name": "Review key", "headers": [{"name": "X-Key", "value": second}]}, vault.get(pid))
        rotated = timeline.page(s, r.dir)
        self.assertNotIn(second, json.dumps(rotated))
        self.assertNotEqual(added["masking_revision"], rotated["masking_revision"])

    def test_r2_explicit_host_claim_never_uses_other_host(self):
        r = self.run_fixture()
        r.exchange("1", path="/api/orders/1")
        r.exchange("2", path="/api/orders/2")
        self.move_host(r, "1", "other.internal", 8899)
        self.move_host(r, "2", "other.internal", 8899)
        r.coverage([self.claim("GET http://127.0.0.1:8899/api/orders/{id}")])
        m = coverage_matrix.build(self.scan(r), r.dir)
        target = [c for c in m["cells"] if c.get("host") == "127.0.0.1"]
        self.assertTrue(target)
        self.assertTrue(all(not c["evidence"] for c in target))
        self.assertTrue(all(c["status"] != "tested" for c in target))
        other = [c for c in m["cells"] if c.get("host") == "other.internal"]
        self.assertTrue(other)

    def test_r2_ambiguous_path_retains_separate_origins(self):
        r = self.run_fixture()
        for rid in ("1", "2", "3"):
            r.exchange(rid, path=f"/api/orders/{rid}")
        self.move_host(r, "2", "other.internal", 8899)
        self.move_host(r, "3", "127.0.0.1", 9900)
        r.coverage([self.claim()])
        m = coverage_matrix.build(self.scan(r), r.dir)
        cells = [c for c in m["cells"] if c["role"] == "profile:9001"]
        self.assertEqual({(c["host"], c["port"]) for c in cells},
                         {("127.0.0.1", 8899), ("other.internal", 8899), ("127.0.0.1", 9900)})
        self.assertTrue(all(c["status"] != "tested" for c in cells))
        self.assertTrue(all(len(c["evidence"]) == 1 for c in cells))

    def test_r2_comparison_keeps_host_and_port(self):
        c = compare._cell_index({"cells": [
            {"endpoint": "GET /api/x", "host": "a.internal", "port": 80, "status": "tested"},
            {"endpoint": "GET /api/x", "host": "b.internal", "port": 80, "status": "partial"},
            {"endpoint": "GET /api/x", "host": "a.internal", "port": 81, "status": "blocked"}]})
        self.assertEqual(c.find("GET", "/api/x", "b.internal", 80)["status"], "partial")
        self.assertEqual(c.find("GET", "/api/x", "a.internal", 81)["status"], "blocked")
        self.assertIsNone(c.find("GET", "/api/x", "a.internal"))  # port is ambiguous
        self.assertIsNone(c.find("GET", "/api/x", "missing.internal", 80))

    def test_r3_two_ordinary_reads_are_not_a_security_test(self):
        r = self.run_fixture()
        r.exchange("1", path="/api/orders/1")
        r.exchange("2", path="/api/orders/2")
        r.coverage([self.claim()])
        c = next(c for c in coverage_matrix.build(self.scan(r), r.dir)["cells"] if c["role"] == "profile:9001")
        self.assertEqual(c["status"], "partial")
        self.assertIn("test execution", " ".join(c["reasons"]).lower())

    def test_r3_verified_test_binds_category_endpoint_and_requests(self):
        r = self.run_fixture()
        r.exchange("1", path="/api/orders/1")
        r.exchange("2", path="/api/orders/2")
        r.coverage([self.claim(risk="IDOR"), self.claim(risk="SQL injection")])
        s = self.scan(r, trigger="verify")
        gid = db.insert("finding_groups", {"target_id": self.tid, "fingerprint": "review-verified-test",
                                           "host": "127.0.0.1", "method": "GET", "endpoint": "/api/orders/{id}", "cwe": "CWE-639"})
        vid = db.insert("finding_verifications", {"scan_id": s["id"], "group_id": gid, "target_id": self.tid,
            "result": "not_reproduced", "classification_version": 2,
            "verification_evidence": {"test_executed": True, "request_ids": ["1", "2"]}})
        cells = coverage_matrix.build(s, r.dir)["cells"]
        auth = next(c for c in cells if c["role"] == "profile:9001" and c["test_type"] == "WSTG-ATHZ")
        injection = next(c for c in cells if c["role"] == "profile:9001" and c["test_type"] == "WSTG-INPV")
        self.assertEqual(auth["status"], "tested")
        self.assertEqual(auth["verification_id"], vid)
        self.assertEqual(injection["status"], "partial")
        db.update("finding_verifications", vid, {"result": "inconclusive"})
        self.assertFalse(any(c["status"] == "tested" for c in coverage_matrix.build(s, r.dir)["cells"]))

    def test_r4_created_event_never_inherits_updated_outcome(self):
        r = self.run_fixture()
        claim = self.claim()
        claim.update(recorded_at="2026-11-15 09:00:00 UTC", updated_at="2026-11-15 10:00:00 UTC",
                     outcome="reported", outcome_label="Reported")
        r.coverage([claim])
        events = [e for e in timeline.events(self.scan(r), r.dir) if e["kind"] == "coverage"]
        original = next(e for e in events if e["at"] == "2026-11-15T09:00:00Z")
        updated = next(e for e in events if e["at"] == "2026-11-15T10:00:00Z")
        self.assertNotIn("reported", original["summary"].lower())
        self.assertIn("created", original["summary"].lower())
        self.assertIn("reported", updated["summary"].lower())

    def test_r5_simultaneous_conflicts_are_unknown_for_both_id_orders(self):
        for statuses in ((200, 401), (401, 200)):
            r = self.run_fixture()
            for i, status in enumerate(statuses, 1):
                r.exchange(str(i), status=status, body=fx.MARKER_TEXT if status == 200 else "no")
            p = session_health.for_scan(self.scan(r), r.dir)["profiles"][0]
            self.assertEqual(p["agents"][0]["state"], "unknown")
            self.assertIn("order", p["agents"][0]["reason"])

    def test_r5_source_precision_and_timezones_determine_order(self):
        signals = [
            {"signal": "lost", "at": "2026-11-15T09:00:01Z", "time_source": "date_header"},
            {"signal": "verified", "at": "2026-11-15T12:00:01.500+03:00", "time_source": "caido"}]
        self.assertIsNone(session_health._last_decisive(signals)[0])  # Date's whole second overlaps Caido
        signals[1]["at"] = "2026-11-15T12:00:02.001+03:00"
        self.assertEqual(session_health._last_decisive(signals)[0]["signal"], "verified")

    def test_r2_https_default_port_and_scheme_are_retained(self):
        x = {"request": {"parsed": {"url": "/api/x", "method": "GET", "headers": {"host": "a.internal"}}},
             "listed": {"tls": True, "port": 443}}
        self.assertEqual(coverage_matrix._traffic_endpoint(x, {}, set())[:3], ("https", "a.internal", 443))

    def test_r3_wrong_role_missing_records_and_old_classification_stay_partial(self):
        r = self.run_fixture()
        r.exchange("1", path="/api/orders/1")
        r.exchange("2", path="/api/orders/2", auth=None)
        r.coverage([self.claim(risk="IDOR")])
        s = self.scan(r)
        vid = self.accepted_verification(s)
        self.assertFalse(any(c["status"] == "tested" for c in coverage_matrix.build(s, r.dir)["cells"]))
        db.update("finding_verifications", vid, {"classification_version": 1})
        self.assertIsNone(coverage_matrix._accepted_test(s))

    def test_r6_updates_to_existing_keys_and_process_restart_are_resynced(self):
        r = self.run_fixture()
        r.coverage([{**self.claim(), "updated_at": "2026-11-15 10:00:00 UTC"}])
        s = self.scan(r)
        first = timeline.page(s, r.dir)
        r.coverage([{**self.claim(), "outcome": "reported", "updated_at": "2026-11-15 10:00:00 UTC"}])
        changed = timeline.page(s, r.dir, seen_after=first["now"])
        self.assertEqual(len(changed["events"]), 1)
        self.assertIn("reported", changed["events"][0]["summary"])
        self.assertIn(changed["events"][0]["key"], {e["key"] for e in first["events"]})
        with mock.patch.object(timeline, "_epoch", "another-process"):
            self.assertTrue(timeline.page(s, r.dir, seen_after=changed["now"])["reset_required"])

    def test_r6_updated_records_that_leave_a_filter_are_removed(self):
        r = self.run_fixture()
        claim = {**self.claim(), "updated_at": "2026-11-15 10:00:00 UTC", "outcome": "needs_follow_up"}
        r.coverage([claim])
        s = self.scan(r)
        first = timeline.page(s, r.dir, q="needs_follow_up")
        self.assertEqual(len(first["events"]), 1)
        r.coverage([{**claim, "outcome": "reported"}])
        update = timeline.page(s, r.dir, q="needs_follow_up", seen_after=first["now"])
        self.assertEqual(update["events"], [])
        self.assertEqual(update["removed_keys"], [first["events"][0]["key"]])
        self.assertEqual(update["total"], 0)

    def test_r6_cursor_drains_large_late_batches_without_loss(self):
        r = self.run_fixture()
        s = self.scan(r, status="running")
        cursor = timeline.page(s, r.dir)["now"]
        for i in range(600):
            self.event(r, f"late-event-{i}")
        page = timeline.page(s, r.dir, seen_after=cursor, limit=500)
        self.assertEqual(len(page["events"]), 500)
        self.assertTrue(page["has_more"])
        # New events, including an older source time, can arrive while we drain the first batch.
        self.event(r, "arrived-during-paging", at="2026-11-13 00:00:00")
        next_page = timeline.page(s, r.dir, seen_after=page["now"], limit=500)
        self.assertEqual(len(next_page["events"]), 101)
        self.assertFalse(next_page["has_more"])
        self.assertEqual(len({e["key"] for e in page["events"] + next_page["events"]}), 601)
        self.assertEqual(timeline.page(s, r.dir, seen_after=next_page["now"])["events"], [])


class TestEndedScanAgentStatus(fx.Base):
    """A cancelled/killed Strix process never writes final agent states; the API must not keep showing 'running'."""

    def run_with(self, statuses):
        r = fx.Run(self.root)
        self.addCleanup(r.c.close)
        (r.dir / ".state/agents.json").write_text(json.dumps({
            "statuses": statuses, "names": {k: k.title() for k in statuses}, "parent_of": {"child": "root"}}))
        return r

    def test_cancelled_scan_settles_live_agents(self):
        from skynet import runs
        r = self.run_with({"root": "running", "child": "waiting", "done": "completed", "bad": "crashed"})
        out = runs.settle_agents(runs.agents(r.dir), "cancelled", active=False)
        st = {a["id"]: a["status"] for a in out["agents"]}
        self.assertEqual(st, {"root": "cancelled", "child": "cancelled", "done": "completed", "bad": "crashed"})
        self.assertEqual(next(a for a in out["agents"] if a["id"] == "root")["reported_status"], "running")
        self.assertEqual(out["counts"], {"cancelled": 2, "completed": 1, "crashed": 1})

    def test_completed_scan_marks_leftover_agents_stopped(self):
        from skynet import runs
        r = self.run_with({"root": "completed", "child": "budget_paused"})
        out = runs.settle_agents(runs.agents(r.dir), "completed", active=False)
        self.assertEqual({a["id"]: a["status"] for a in out["agents"]}, {"root": "completed", "child": "stopped"})

    def test_active_scan_is_untouched(self):
        from skynet import runs
        r = self.run_with({"root": "running", "child": "waiting"})
        data = runs.agents(r.dir)
        self.assertIs(runs.settle_agents(data, "running", active=True), data)
