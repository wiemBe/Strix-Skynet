"""Disposable visual QA server; no normal lifespan/worker/scheduler/Strix/network calls.

Run from this repository with .venv/bin/python <this file>. Accounts below are
synthetic local-only test accounts. The printed temp root can be removed after exit.
"""
import json
import os
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TEMP = Path(tempfile.mkdtemp(prefix="skynet-users-fixes-qa-"))
os.environ.pop("SKYNET_SECRET_KEY", None)
os.environ.update(SKYNET_LOAD_DOTENV="0", SKYNET_DATA=str(TEMP / "data"),
                  SKYNET_SECRET_KEY_FILE=str(TEMP / "keys/secret.key"),
                  SKYNET_PASSWORD="qa-admin-password", SKYNET_STRIX_WORKDIR=str(TEMP / "work"))
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from skynet import auth, audit, crypto, db, findings_store, main, vault
from test_sky import Run


@asynccontextmanager
async def fixture(_):
    db.init()
    auth.bootstrap()
    auth.create_user("qa-viewer", "viewer", "qa-viewer-password", "QA Viewer")
    auth.create_user("qa-analyst", "analyst", "qa-analyst-password", "QA Analyst")
    secret = "qa-fixture-vault-secret-681a2"
    vault.save({"kind": "header", "name": "QA fixture credential", "headers": [
        {"name": "Authorization", "value": "Bearer " + secret}]}, None)
    tid = db.insert("targets", {"name": "QA fixture — " + secret,
                                "environment": "test", "base_url": "http://127.0.0.1:8899"})
    tid2 = db.insert("targets", {"name": "QA long target name / release-candidate / permissions-and-report-layout-check",
                                 "environment": "staging", "base_url": "http://127.0.0.1:8899"})
    run = Run(TEMP, name="qa-synthetic-records-no-engine-run")
    run.exchange("802", path="/api/orders/2", status=401, body='{"error":"unauthenticated"}', auth=None)
    run.exchange("804", path="/api/orders/2", status=200, body='{"owner":"qa-user","fixture":true}', auth="Bearer " + secret)
    run.vulns([{"id": "qa-open", "title": "QA fixture: access control evidence", "severity": "high",
                "target": "http://127.0.0.1:8899", "endpoint": "/api/orders/2", "method": "GET", "cwe": "CWE-639",
                "evidence": "Synthetic QA evidence only", "http_exchange_ids": ["802", "804"]}])
    sid = db.insert("scans", {"target_id": tid, "name": "QA fixture — no engine run", "status": "completed",
                              "trigger": "manual", "started_at": "2026-11-15T09:00:00+00:00",
                              "finished_at": "2026-11-15T09:10:00+00:00", "run_name": run.name, "run_dir": str(run.dir),
                              "redact_enc": crypto.vault_encrypt(json.dumps([secret])),
                              "summary": {"counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                                          "run_status": "completed"}})
    findings_store.ingest(db.get_scan(sid), run.dir)
    for severity, fp, fixed_at in [("medium", "qa-legacy-fixed", None), ("critical", "qa-recorded-fixed", "2026-11-05T00:00:00+00:00")]:
        gid = db.insert("finding_groups", {"target_id": tid, "fingerprint": fp, "title": "QA fixture: " + fp,
                                           "severity": severity, "remediation": "fixed", "first_seen_at": "2026-11-01T00:00:00+00:00",
                                           "remediation_at": "2026-11-05T00:00:00+00:00", "fixed_at": fixed_at})
        db.insert("finding_occurrences", {"group_id": gid, "scan_id": sid, "run_name": run.name,
                                          "strix_id": fp, "severity": severity, "observed_at": "2026-11-01T00:00:00+00:00"})
    cid = db.insert("campaigns", {"name": "QA campaign / release readiness", "description": "Synthetic local QA only · " + secret,
                                  "environment": "test", "status": "active"})
    for target in (tid, tid2):
        db.insert("campaign_targets", {"campaign_id": cid, "target_id": target})
    audit.record("system", "scan.import", summary="Synthetic QA fixture; no Strix/provider run · " + secret)
    run.c.close()
    run.c = None
    print("QA_TEMP_ROOT=" + str(TEMP), flush=True)
    yield


main.app.router.lifespan_context = fixture
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(main.app, host="127.0.0.1", port=8797, access_log=False)
