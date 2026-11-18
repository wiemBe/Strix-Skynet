"""OpenCode Go profiles: hermetic API, launch, session and credential regressions."""
import io
import json
import os
import subprocess
import tempfile
import urllib.error
from pathlib import Path
from unittest import mock

import test_users_audit as support
from skynet import control, crypto, db, llm, redact, runner

KEY = "oc_sk_" + "synthetic-go-key-" * 3


class TestOpenCodeGo(support.Base):
    def profile(self, **extra):
        return {"name": support._uniq("go-"), "provider": "opencode_go", "model": "go-model",
                "api_key": KEY, **extra}

    def stored(self):
        data = self.M._llm_payload(self.profile())
        return llm.get(db.insert("llm_profiles", data))

    def test_api_encrypts_key_normalizes_model_and_never_returns_secret(self):
        admin = self.user("admin")
        status, body = self.call("/api/llm-profiles", "POST", self.profile(model="opencode-go/go-model"), user=admin)
        self.assertEqual(status, 200)
        self.assertEqual(body["base_url"], llm.OPENCODE_GO_BASE)
        self.assertEqual(body["strix_model"], "openai/go-model")
        self.assertEqual(body["provider_label"], "OpenCode Go")
        self.assertTrue(body["has_api_key"])
        self.assertNotIn("api_key_enc", body)
        self.assertNotIn(KEY, json.dumps(body))
        saved = llm.get(body["id"])
        self.assertNotEqual(saved["api_key_enc"], KEY)
        self.assertEqual(crypto.decrypt_strict(saved["api_key_enc"]), KEY)
        self.assertNotIn(KEY, json.dumps(self.call("/api/llm-profiles", user=self.user("viewer"))[1]))
        self.assertEqual(self.call("/api/llm-profiles", "POST", self.profile(), user=self.user("viewer"))[0], 403)

    def test_required_key_and_edit_keep_clear_and_provider_change(self):
        from fastapi import HTTPException
        for key in ("", "   "):
            with self.assertRaises(HTTPException):
                self.M._llm_payload(self.profile(api_key=key))
        p = self.stored()
        self.assertNotIn("api_key_enc", self.M._llm_payload(self.profile(api_key=""), p))
        with self.assertRaises(HTTPException):
            self.M._llm_payload(self.profile(api_key="", clear_api_key=True), p)
        changed = self.profile(provider="openrouter", api_key="")
        with self.assertRaises(HTTPException):
            self.M._llm_payload(changed, p)
        with mock.patch.object(llm, "test") as request:
            status, _ = self.call("/api/llm-profiles/test", "POST", {**changed, "id": p["id"]}, user=self.user("admin"))
            self.assertEqual(status, 400)
            request.assert_not_called()

    def test_environment_has_native_protocol_and_required_session_headers(self):
        p = self.stored()
        env = llm.strix_env(p, session_id="ses_skynet_fixture")
        self.assertEqual(env["LLM_API_BASE"], llm.OPENCODE_GO_BASE)
        self.assertEqual(env["STRIX_LLM"], "openai/go-model")
        self.assertEqual(env["STRIX_API_TYPE"], "chat_completions")
        self.assertEqual(json.loads(env["LLM_EXTRA_HEADERS"]), {
            "User-Agent": "Skynet-Strix/1.0", "x-opencode-session": "ses_skynet_fixture"})
        with self.assertRaises(ValueError):
            llm.strix_env(p)
        with self.assertRaises(ValueError):
            llm.strix_env({**p, "api_key_enc": ""}, session_id="session")
        self.assertEqual(llm.strix_env({**p, "api_type": "responses"}, session_id="session")["STRIX_API_TYPE"], "responses")
        self.assertNotIn("LLM_EXTRA_HEADERS", llm.strix_env({**p, "provider": "litellm"}))

    def test_sessions_are_distinct_and_resume_preserves_original(self):
        run = support._uniq("go-run-")
        sid = db.insert("scans", {"run_name": run})
        original = llm.scan_session_id({"id": sid})
        self.assertEqual(original, llm.scan_session_id({"id": sid}))
        self.assertNotEqual(original, llm.scan_session_id({"id": sid + 1}))
        self.assertEqual(original, llm.scan_session_id({"id": sid + 1, "resume_run": run}))
        self.assertNotIn(KEY, original)

    def test_inherited_credentials_and_headers_cannot_override_profile(self):
        env = llm.strix_env(self.stored(), session_id="session")
        with mock.patch.dict(os.environ, {"OPENCODE_API_KEY": "ambient", "OPENCODE_GO_API_KEY": "ambient",
                "OPENCODE_ZEN_API_KEY": "ambient", "DEDUPE_LLM_EXTRA_HEADERS": "ambient", "LLM_EXTRA_HEADERS": "ambient"}):
            child = runner._child_env(env, {})
        self.assertEqual(child["LLM_EXTRA_HEADERS"], env["LLM_EXTRA_HEADERS"])
        for name in ("OPENCODE_API_KEY", "OPENCODE_GO_API_KEY", "OPENCODE_ZEN_API_KEY", "DEDUPE_LLM_EXTRA_HEADERS"):
            self.assertNotIn(name, child)

    def test_catalogue_uses_go_endpoint_and_does_not_claim_key_verification(self):
        with mock.patch.object(llm, "_get", return_value={"data": [{"id": "go-model"}, {"id": None}]}) as get:
            result = llm.test(self.stored())
        self.assertTrue(result["ok"])
        self.assertTrue(result["model_found"])
        self.assertFalse(result["key_verified"])
        self.assertEqual(result["check_type"], "catalog")
        args = get.call_args.args
        self.assertEqual(args[:3], ("https://opencode.ai/inference/go/v1/models", KEY, None))
        self.assertEqual(args[3]["User-Agent"], llm.OPENCODE_USER_AGENT)
        self.assertTrue(args[3]["x-opencode-session"].startswith("ses_skynet_check_"))

    def test_custom_catalogue_never_redirects_to_default_or_payg(self):
        with mock.patch.object(llm, "_get", return_value={"data": []}) as get:
            llm.test({**self.stored(), "base_url": "https://gateway.example/go/openai/v1"})
        self.assertEqual(get.call_args.args[0], "https://gateway.example/go/v1/models")

    def test_catalogue_failure_no_fallback_and_scrubs_before_truncation(self):
        err = urllib.error.HTTPError(llm.OPENCODE_GO_BASE, 429, "rate limit", {}, io.BytesIO(("x" * 280 + KEY).encode()))
        with mock.patch.object(llm, "_get", side_effect=err) as get:
            result = llm.test(self.stored())
        self.assertFalse(result["ok"])
        self.assertIn("HTTP 429", result["message"])
        self.assertNotIn("oc_sk_", result["message"])
        self.assertEqual(get.call_count, 1)
        with mock.patch.object(llm, "_get", return_value={"data": "unexpected"}):
            self.assertFalse(llm.test(self.stored())["ok"])
        with mock.patch.object(llm, "_get") as get:
            self.assertFalse(llm.test({"provider": "opencode_go"}, key_override="")["ok"])
            get.assert_not_called()

    def test_go_key_is_pattern_redacted_without_profile_lookup(self):
        self.assertNotIn(KEY, redact.Redactor([]).text("provider error " + KEY, strict=True))

    def test_catalogue_request_carries_own_user_agent_and_session(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data": []}'
        with mock.patch.object(llm.urllib.request, "urlopen", return_value=response) as send:
            self.assertTrue(llm.test(self.stored())["ok"])
        request = send.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        self.assertEqual(headers["authorization"], "Bearer " + KEY)
        self.assertEqual(headers["user-agent"], llm.OPENCODE_USER_AGENT)
        self.assertTrue(headers["x-opencode-session"].startswith("ses_skynet_check_"))

    def test_runner_writes_headers_and_snapshots_key_before_process_start(self):
        p = self.stored()
        tid = db.insert("targets", {"name": support._uniq("go-target"), "base_url": "http://127.0.0.1:8899"})
        sid = db.insert("scans", {"target_id": tid, "llm_profile_id": p["id"], "model": "openai/previous-model",
            "targets": ["http://127.0.0.1:8899"]})
        def spawn(*args, **kwargs):
            cfg = json.loads((runner.RUNTIME_DIR / f"scan_{sid}.json").read_text())["env"]
            self.assertEqual(json.loads(cfg["LLM_EXTRA_HEADERS"])["x-opencode-session"], llm.scan_session_id({"id": sid}))
            self.assertEqual(cfg["LLM_API_KEY"], KEY)
            self.assertEqual(db.get_scan(sid)["model"], "openai/go-model")
            self.assertEqual(db.get_scan(sid)["llm_provider"], "opencode_go")
            self.assertIn(KEY, json.loads(crypto.vault_decrypt(db.get_scan(sid)["redact_enc"])))
            raise OSError("fixture: no real Strix process")
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "strix"
            binary.touch()
            with mock.patch.object(runner, "docker_status", return_value={"ok": True}), \
                 mock.patch.object(runner, "strix_version", return_value={"version": "test"}), \
                 mock.patch.object(control, "bridge_status", return_value={"available": False, "reason": "fixture"}), \
                 mock.patch.object(runner.subprocess, "Popen", side_effect=spawn) as popen:
                try:
                    runner._launch(db.get_scan(sid), {"strix_bin": str(binary), "strix_workdir": tmp})
                    popen.assert_called_once()
                finally:
                    runner._cleanup_runtime(sid)

    def test_installed_strix_parses_generated_settings_and_forwards_headers(self):
        runtime = Path(__file__).resolve().parents[1] / ".strix-runtime/bin/python"
        if not runtime.exists():
            self.skipTest("optional installed Strix runtime is not available")
        env = runner._child_env(llm.strix_env(self.stored(), session_id="ses_skynet_fixture"), {})
        script = '''from strix.config.settings import LlmSettings
from strix.core.inputs import _request_headers
s = LlmSettings()
assert s.model == "openai/go-model"
assert s.api_type == "chat_completions"
assert s.api_base == "https://opencode.ai/inference/go/openai/v1"
h = _request_headers(s.model, s.extra_headers)
assert h["User-Agent"] == "Skynet-Strix/1.0"
assert h["x-opencode-session"] == "ses_skynet_fixture"
'''
        r = subprocess.run([str(runtime), "-c", script], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr.replace(KEY, "[redacted]"))
