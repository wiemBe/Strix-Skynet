"""Detailed report exports use real role, redaction and selection paths on a disposable DB."""
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import test_users_audit as support
from skynet import crypto, db, report


class TestReportGeneration(support.Base):
    def fixture(self):
        return support.TestReport.fixture(self)

    def test_register_includes_all_statuses_and_summary_stays_bounded(self):
        tid, sid, _, _, _ = self.fixture()
        for i in range(10):
            gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": support._uniq("register"),
                            "title": f"Register finding {i}", "severity": "medium", "remediation": "open" if i < 8 else "accepted"})
            db.insert("finding_occurrences", {"group_id": gid, "scan_id": sid, "run_name": support._uniq("register"), "strix_id": "v1"})
        f = report.for_target(tid)["findings"]
        self.assertEqual((len(f["top_open"]), f["open_more"], len(f["register"])), (6, 3, 12))
        self.assertEqual({g["remediation"] for g in f["register"]}, {"open", "fixed", "accepted"})
        self.assertEqual(sum(g["occurrences"] for g in f["register"]), f["summary"]["occurrences"])

    def test_campaign_occurrences_and_sources_stay_in_selection(self):
        tid, sid, _, gid, _ = self.fixture()
        cid = db.insert("campaigns", {"name": "Report selection fixture"})
        db.update("scans", sid, {"campaign_id": cid})
        outside = db.insert("scans", {"target_id": tid, "status": "completed"})
        db.insert("finding_occurrences", {"group_id": gid, "scan_id": outside, "run_name": support._uniq("outside"), "strix_id": "v1"})
        r = report.for_campaign(cid)
        g = next(g for g in r["findings"]["register"] if g["id"] == gid)
        self.assertEqual((g["occurrences"], g["scan_ids"]), (1, [sid]))
        # Even without current campaign membership the retained scan's target is accounted for.
        self.assertEqual([t["id"] for t in r["targets"]], [tid])
        self.assertEqual(r["targets"][0]["scans"]["total"], 1)

    def test_old_findings_are_not_silently_dropped_after_5000_scans(self):
        tid, _, _, gid, _ = self.fixture()
        db.conn().executemany("INSERT INTO scans (target_id,status,started_at) VALUES (?,?,?)",
                              [(tid, "completed", "2099-01-01T00:00:00+00:00")] * 5000)
        db.conn().commit()
        r = report.for_target(tid)
        self.assertEqual(r["scans"]["total"], 5002)  # verification excluded
        self.assertIn(gid, [g["id"] for g in r["findings"]["register"]])
        self.assertEqual(len(r["trend"]), 12)

    def test_scope_notes_and_exports_mask_historical_secrets(self):
        tid, sid, _, gid, _ = self.fixture()
        secret = support._uniq("historical-report-secret-")
        db.update("scans", sid, {"redact_enc": crypto.vault_encrypt(json.dumps([secret]))})
        db.update("targets", tid, {"in_scope": ["/api/" + secret], "out_of_scope": ["/admin/" + secret]})
        db.update("finding_groups", gid, {"remediation_note": "Ticket " + secret})
        viewer = self.user("viewer")
        for suffix in ("", "?format=markdown"):
            status, body = self.call(f"/api/targets/{tid}/report{suffix}", user=viewer)
            self.assertEqual(status, 200)
            self.assertNotIn(secret, body.decode() if isinstance(body, bytes) else json.dumps(body))

    def test_markdown_export_is_complete_audited_and_accessible_to_viewer(self):
        tid, sid, _, gid, _ = self.fixture()
        db.update("targets", tid, {"name": "Türkçe güvenlik değerlendirmesi", "out_of_scope": ["/admin"]})
        viewer = self.user("viewer")
        status, raw = self.call(f"/api/targets/{tid}/report?format=markdown", user=viewer)
        text = raw.decode()
        self.assertEqual(status, 200)
        self.assertIn("Türkçe güvenlik değerlendirmesi", text)
        self.assertIn("Complete finding register (2)", text)
        self.assertIn(f"Finding #{gid}", text)
        self.assertIn("Status: fixed", text)
        self.assertIn("/admin", text)
        self.assertIn(f"Source scans: \\#{sid}", text)
        self.assertEqual(self.last_audit(action="report.view")["actor"], viewer["username"])
        self.assertEqual(self.call(f"/api/targets/{tid}/report?format=markdown")[0], 401)
        self.assertEqual(self.call(f"/api/targets/{tid}/report?format=pdf", user=viewer)[0], 422)

    def test_campaign_markdown_with_no_targets_is_valid(self):
        cid = db.insert("campaigns", {"name": "Empty campaign", "scope": "Only explicitly approved systems"})
        status, raw = self.call(f"/api/campaigns/{cid}/report?format=markdown", user=self.user("viewer"))
        self.assertEqual(status, 200)
        self.assertIn(b"Assessment incomplete", raw)
        self.assertIn(b"Only explicitly approved systems", raw)
        self.assertIn(b"Complete finding register (0)", raw)

    def test_untrusted_markdown_stays_literal(self):
        tid, _, _, gid, _ = self.fixture()
        db.update("finding_groups", gid, {"title": "<script>alert(1)</script> | [click](https://example.test)",
                                         "remediation_note": "line one\n# Forged heading"})
        text = report.markdown(report.for_target(tid))
        self.assertNotIn("<script>", text)
        self.assertNotIn("[click](https://example.test)", text)
        self.assertIn("\\|", text)
        self.assertIn("line one<br>\\# Forged heading", text)

    def test_future_and_reversed_dates_are_unknown_and_sub_day_age_is_preserved(self):
        tid, _, _, gid, _ = self.fixture()
        now = datetime.now(timezone.utc)
        db.update("finding_groups", gid, {"first_seen_at": (now - timedelta(hours=2)).isoformat()})
        self.assertTrue(0 < report.for_target(tid)["findings"]["top_open"][0]["age_days"] < 1)
        db.update("finding_groups", gid, {"first_seen_at": (now + timedelta(days=1)).isoformat()})
        f = report.for_target(tid)["findings"]
        self.assertEqual(f["open_age_unknown"], 1)
        self.assertIsNone(f["top_open"][0]["age_days"])
        self.assertIsNone(report._days(now, now - timedelta(hours=1)))
        db.execute("UPDATE finding_groups SET fixed_at='2000-01-01T00:00:00+00:00' WHERE target_id=? AND remediation='fixed'", (tid,))
        f = report.for_target(tid)["findings"]
        self.assertEqual(f["fixed_time_unknown"], 1)
        self.assertEqual(f["time_to_fix"]["all"]["n"], 0)

    def test_scan_periods_and_coverage_use_instant_order_not_string_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            scans = [{"id": 1, "status": "completed", "started_at": "2026-11-17T00:30:00+03:00", "run_dir": tmp},
                     {"id": 2, "status": "completed", "started_at": "2026-11-16T23:00:00Z", "run_dir": tmp}]
            sc = report._scan_stats(scans)
            self.assertLess(report._dt(sc["first_at"]), report._dt(sc["last_at"]))
            self.assertEqual(report._dt(sc["last_completed_at"]), report._dt(scans[1]["started_at"]))
            with mock.patch.object(report.coverage_matrix, "build", return_value={"cells": []}) as build:
                self.assertEqual(report._coverage(scans)["scan_id"], 2)
                self.assertEqual(build.call_args.args, (scans[1], Path(tmp)))

    def test_executive_does_not_call_no_scans_or_incomplete_scans_secure(self):
        tid = db.insert("targets", {"name": "No assessment yet", "base_url": "http://127.0.0.1:8899"})
        r = report.for_target(tid)
        self.assertEqual(r["executive"]["headline"], "Assessment incomplete")
        self.assertIn("Complete a full assessment", r["executive"]["actions"][0])
        db.insert("scans", {"target_id": tid, "status": "running"})
        r = report.for_target(tid)
        self.assertTrue(any("Re-generate" in a for a in r["executive"]["actions"]))
