"""Automatic model discovery never generates tokens or reuses credentials across destinations."""
import io
import json
import urllib.error
from unittest import mock

import test_users_audit as support
from skynet import crypto, db, llm


class TestModelCatalogue(support.Base):
    def setUp(self):
        super().setUp()
        self.admin = self.user("admin")

    def saved(self, provider="opencode_go", base=""):
        return db.insert("llm_profiles", {"name": support._uniq("catalogue-"), "provider": provider,
            "base_url": base, "model": "chosen", "api_key_enc": crypto.encrypt("catalogue-fixture-key")})

    def test_openrouter_catalogue_is_public_and_never_calls_key_or_inference(self):
        with mock.patch.object(llm, "_get", return_value={"data": [{"id": "openai/gpt-fixture"}]}) as get:
            status, result = self.call("/api/llm-profiles/models", "POST", {"provider": "openrouter"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertFalse(result["key_verified"])
        self.assertEqual(result["models"], ["openai/gpt-fixture"])
        get.assert_called_once_with("https://openrouter.ai/api/v1/models", "", None)

    def test_saved_go_loads_without_model_input_or_exposing_credential(self):
        pid = self.saved()
        with mock.patch.object(llm, "_get", return_value={"data": [{"id": "go-fixture"}]}) as get:
            status, result = self.call("/api/llm-profiles/models", "POST", {"id": pid, "provider": "opencode_go"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(get.call_args.args[1], "catalogue-fixture-key")
        self.assertNotIn("catalogue-fixture-key", json.dumps(result))
        self.assertFalse(result["key_verified"])

    def test_automatic_fetch_never_sends_saved_key_to_changed_address(self):
        pid = self.saved()
        with mock.patch.object(llm, "_get") as get:
            status, result = self.call("/api/llm-profiles/models", "POST", {
                "id": pid, "provider": "opencode_go", "base_url": "https://new.example/openai/v1"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertFalse(result["ok"])
        get.assert_not_called()

    def test_provider_switch_can_load_public_catalogue_without_old_key(self):
        pid = self.saved()
        with mock.patch.object(llm, "_get", return_value={"data": []}) as get:
            status, result = self.call("/api/llm-profiles/models", "POST", {"id": pid, "provider": "openrouter"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(get.call_args.args[1], "")

    def test_litellm_keyless_gateway_and_v1_discovery(self):
        missing = urllib.error.HTTPError("http://localhost/models", 404, "missing", {}, io.BytesIO(b""))
        with mock.patch.object(llm, "_get", side_effect=[missing, {"data": [{"id": "deployment-alias"}]}]) as get:
            status, result = self.call("/api/llm-profiles/models", "POST", {
                "provider": "litellm", "base_url": "http://localhost:4000"}, user=self.admin)
        missing.close()
        self.assertEqual(status, 200)
        self.assertEqual(result["models"], ["deployment-alias"])
        self.assertEqual([c.args[0] for c in get.call_args_list], ["http://localhost:4000/models", "http://localhost:4000/v1/models"])
        self.assertTrue(all(c.args[1] == "" for c in get.call_args_list))

    def test_catalogue_permission_and_invalid_provider(self):
        for role in ("viewer", "analyst"):
            with mock.patch.object(llm, "_get") as get:
                status, _ = self.call("/api/llm-profiles/models", "POST", {"provider": "openrouter"}, user=self.user(role))
                self.assertEqual(status, 403)
                get.assert_not_called()
        self.assertEqual(self.call("/api/llm-profiles/models", "POST", {"provider": "unknown"}, user=self.admin)[0], 400)

    def test_public_catalogue_does_not_decrypt_unneeded_credentials(self):
        pid = self.saved("openrouter")
        db.update("llm_profiles", pid, {"api_key_enc": "unreadable-ciphertext"})
        with mock.patch.object(llm, "_get", return_value={"data": [{"id": "model"}]}):
            status, result = self.call("/api/llm-profiles/models", "POST", {"id": pid, "provider": "openrouter"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])

    def test_selected_model_changes_profile_without_rotating_key(self):
        pid = self.saved("openrouter")
        before = llm.get(pid)
        status, result = self.call(f"/api/llm-profiles/{pid}", "PUT", {
            "name": before["name"], "provider": "openrouter", "model": "openai/new-model"}, user=self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(result["strix_model"], "openrouter/openai/new-model")
        self.assertEqual(llm.get(pid)["api_key_enc"], before["api_key_enc"])
