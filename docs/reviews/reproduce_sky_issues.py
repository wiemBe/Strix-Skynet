"""Read-only product review reproductions; all writes go to temporary fixture data."""
import json
import os
import sys
import tempfile
from pathlib import Path

root = tempfile.TemporaryDirectory(prefix="skynet-review-fixtures-")
os.environ["SKYNET_DATA"] = str(Path(root.name) / "data")
os.environ["SKYNET_SECRET_KEY_FILE"] = str(Path(root.name) / "key")
os.environ["SKYNET_PASSWORD"] = "review-fixture-password"
project = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project))
sys.path.insert(0, str(project / "tests"))
from test_sky import TestCoverageMatrix, Run
from skynet import coverage_matrix, timeline, vault, db, session_health

t = TestCoverageMatrix()
t.setUp()
out = {}
try:
    # Only normal authorized object reads; no injection payload, invalid input or control.
    r = Run(t.root)
    r.exchange("1", path="/api/orders/1")
    r.exchange("2", path="/api/orders/2")
    r.coverage([t.entry("GET /api/orders/{id}", risk="SQL injection", ev="tested")])
    s = t.scan(r)
    cell = next(c for c in coverage_matrix.build(s, r.dir)["cells"] if c["role"] == "profile:9001")
    out["ordinary_reads_marked_injection_tested"] = {"status": cell["status"], "type": cell["test_type"], "evidence_count": cell["evidence_count"]}

    # Same path, wholly different host; the full-URL coverage claim is still marked Tested.
    for mid, raw in r.c.execute("SELECT id,message_data FROM agent_messages").fetchall():
        r.c.execute("UPDATE agent_messages SET message_data=? WHERE id=?", (raw.replace("127.0.0.1", "other.internal"), mid))
    r.c.commit()
    r.coverage([t.entry("GET http://127.0.0.1:8899/api/orders/{id}")])
    cell = next(c for c in coverage_matrix.build(s, r.dir)["cells"] if c["role"] == "profile:9001")
    out["other_host_evidence_matches_target_claim"] = {"status": cell["status"], "endpoint": cell["endpoint"]}

    # A mutable coverage row's latest outcome is rendered at the original recorded_at.
    r2 = Run(t.root)
    e = t.entry("GET /api/me", outcome="reported", at="2026-11-15 09:00:00 UTC")
    e["updated_at"] = "2026-11-15 10:00:00 UTC"
    e["evidence"] = "This finding was first reported at 10:00"
    r2.coverage([e])
    s2 = t.scan(r2)
    out["latest_outcome_retroactively_at_recorded_time"] = [{"at":e["at"],"summary":e["summary"]} for e in timeline.events(s2,r2.dir) if e["kind"] == "coverage"]

    # Contradictory same-instant evidence is ordered by request-id, not resolved as Unknown.
    r3 = Run(t.root)
    r3.exchange("1", caido_at="2026-11-15T09:00:01")
    r3.exchange("2", status=401, body="no", caido_at="2026-11-15T09:00:01")
    s3=t.scan(r3)
    p=session_health.for_scan(s3,r3.dir)["profiles"][0]
    out["conflicting_same_timestamp_session_signals"] = {"state":p["agents"][0]["state"],"times":[x["at"] for x in p["signals"]]}

    r3b=Run(t.root)
    r3b.exchange("1", status=401, body="no", caido_at="2026-11-15T09:00:01")
    r3b.exchange("2", caido_at="2026-11-15T09:00:01")
    pb=session_health.for_scan(t.scan(r3b),r3b.dir)["profiles"][0]
    out["same_timestamp_reversed_ids_claim_verified"]={"state":pb["agents"][0]["state"]}

    # Timeline's masked-output cache survives changes in the Vault masking set.
    r4=Run(t.root)
    secret="fixture-secret-newly-added-45837295"
    r4.msg({"type":"message","role":"assistant","content":[{"type":"output_text","text":"Observed literal "+secret}]})
    s4=t.scan(r4)
    before=timeline.page(s4,r4.dir)
    vault.save({"kind":"header","name":"Review profile","headers":[{"name":"X-Review-Key","value":secret}]},None)
    fresh_masks_secret=secret not in vault.scan_redactor(s4).text("Observed literal "+secret,True)
    cached=timeline.page(s4,r4.dir)
    out["timeline_cache_ignores_changed_secret_masks"] = {"fresh_redactor_masks":fresh_masks_secret,"cached_response_leaks_fixture_secret":secret in json.dumps(cached)}

    # More than one live page is observed in a single poll; highwater leaps past the unseen tail.
    r5=Run(t.root)
    s5=t.scan(r5,status="running")
    first=timeline.page(s5,r5.dir)
    for i in range(600):
        r5.msg({"type":"message","role":"assistant","content":[{"type":"output_text","text":f"late-event-{i}"}]},at="2026-11-14 07:00:00")
    batch=timeline.page(s5,r5.dir,seen_after=first["now"],limit=500)
    after=timeline.page(s5,r5.dir,seen_after=batch["now"],limit=500)
    out["live_highwater_skips_unread_batch_tail"]={"matched":batch["matched"],"returned":len(batch["events"]),"next_poll_returns":len(after["events"])}
    print(json.dumps(out,indent=2))
finally:
    t.doCleanups()
