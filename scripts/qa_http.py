"""Explicit localhost-only management smoke test. Disposable QA instance only; never starts scans or providers."""
import argparse
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def run(base, mode, state_file):
    parsed = urllib.parse.urlparse(base)
    if parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.scheme != "http":
        raise ValueError("Use a disposable localhost HTTP QA instance only.")
    password = os.environ.get("SKYNET_QA_PASSWORD")
    if not password:
        raise ValueError("Set SKYNET_QA_PASSWORD; credentials are never accepted on the command line.")
    for attempt in range(60):
        try:
            with urllib.request.urlopen(base.rstrip("/") + "/login", timeout=2):
                break
        except urllib.error.URLError:
            if attempt == 59:
                raise
            time.sleep(0.25)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(path, body=None, method=None, csrf=True, expected=200):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-Requested-With"] = "skynet"
        req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None,
                                     method=method or ("POST" if body is not None else "GET"), headers=headers)
        try:
            response = opener.open(req, timeout=60)
        except urllib.error.HTTPError as e:
            response = e
        with response as r:
            assert r.code == expected, f"{req.method} {path}: HTTP {r.code}, expected {expected}"
            if expected == 200:
                assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")
                assert r.headers.get("X-Content-Type-Options") == "nosniff"
            raw = r.read()
            return json.loads(raw) if r.headers.get("Content-Type", "").startswith("application/json") else raw
    call("/api/targets", expected=401)
    call("/api/login", {"username": "admin", "password": password})
    settings = call("/api/settings")
    assert settings["schema_version"] >= 5
    assert settings["timezone"] == "Europe/Istanbul"
    call("/api/targets", {"name": "Must not exist"}, csrf=False, expected=403)
    if mode == "create":
        suffix = str(time.time_ns())[-8:]
        provider = call("/api/llm-profiles", {"name": f"QA LiteLLM (not contacted) {suffix}", "provider": "litellm",
                        "base_url": "http://127.0.0.1:9999/v1", "model": "qa-no-provider-call"})
        target = call("/api/targets", {"name": f"QA local target {suffix}", "base_url": "http://127.0.0.1:8899",
                      "environment": "test", "llm_profile_id": provider["id"]})
        auth = call("/api/auth-profiles", {"name": f"QA header profile {suffix}", "kind": "header",
                    "headers": [{"name": "X-QA-Key", "value": "qa-fixture-secret-never-a-real-credential"}],
                    "target_ids": [target["id"]]})
        campaign = call("/api/campaigns", {"name": f"QA campaign {suffix}", "target_ids": [target["id"]]})
        schedule = call("/api/schedules", {"name": "QA disabled schedule", "kind": "daily", "time_of_day": "03:00",
                        "target_id": target["id"], "enabled": False, "timezone": "Europe/Istanbul",
                        "llm_profile_id": provider["id"], "auth_profile_ids": [auth["id"]], "campaign_id": campaign["id"]})
        state = {"target": target["id"], "auth": auth["id"], "campaign": campaign["id"], "schedule": schedule["id"],
                 "provider": provider["id"]}
        state_file.write_text(json.dumps(state))
    else:
        state = json.loads(state_file.read_text())
    target = call(f"/api/targets/{state['target']}")
    profile = call(f"/api/auth-profiles/{state['auth']}")
    schedule = call(f"/api/schedules/{state['schedule']}")
    assert profile["has_secret"] and profile["secret_readable"]
    assert "qa-fixture-secret-never-a-real-credential" not in json.dumps(profile)
    assert "secret_enc" not in profile
    assert profile["id"] in [p["id"] for p in target["auth_profiles"]]
    assert not schedule["enabled"] and schedule["timezone"] == "Europe/Istanbul"
    assert call(f"/api/campaigns/{state['campaign']}")["id"] == state["campaign"]
    assert not call("/api/scans"), "This disposable QA instance must not start or contain any scans."
    call("/")
    return {"ok": True, "mode": mode, "ids": state, "schema_version": settings["schema_version"],
            "secret_readable": profile["secret_readable"], "secret_returned": False,
            "schedules_enabled": False, "scans_started": 0, "provider_calls": 0}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("create", "verify"))
    p.add_argument("--base-url", required=True)
    p.add_argument("--state", required=True, type=Path)
    p.add_argument("--disposable-qa", action="store_true", required=True)
    a = p.parse_args()
    print(json.dumps(run(a.base_url, a.mode, a.state), indent=2))
