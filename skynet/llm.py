"""LLM connection profiles mapped onto Strix's own env-var mechanism.

Strix uses LiteLLM internally and is configured with STRIX_LLM / LLM_API_KEY / LLM_API_BASE
(https://docs.strix.ai/advanced/configuration). This module only translates a stored profile into
those variables; it never proxies LLM traffic and never falls back to another profile.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import ssl
import urllib.error
import urllib.request
from typing import Any

from . import crypto, db, redact

OPENCODE_GO_BASE = "https://opencode.ai/inference/go/openai/v1"
OPENCODE_USER_AGENT = "Skynet-Strix/1.0"

PROVIDERS = {
    "openrouter": {"label": "OpenRouter", "prefix": "openrouter/", "default_base": "https://openrouter.ai/api/v1"},
    # Documented pattern for OpenAI-compatible gateways: openai/<model> + LLM_API_BASE.
    "litellm": {"label": "LiteLLM", "prefix": "openai/", "default_base": ""},
    "opencode_go": {"label": "OpenCode Go", "prefix": "openai/", "default_base": OPENCODE_GO_BASE,
                    "default_api_type": "chat_completions"},
}
API_TYPES = ("", "chat_completions", "responses")
EFFORTS = ("", "none", "minimal", "low", "medium", "high", "xhigh", "max")

# Inherited variables that could silently redirect Strix to another provider/key. Always stripped
# from the child environment so a scan only ever uses the profile it was started with.
LLM_ENV_DENYLIST = (
    "STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL",
    "OLLAMA_API_BASE", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "STRIX_API_TYPE",
    "STRIX_FORCE_API", "STRIX_REASONING_EFFORT", "LLM_EXTRA_HEADERS", "LLM_EXTRA_BODY",
    "STRIX_DEDUPE_MODEL", "DEDUPE_LLM_API_KEY", "DEDUPE_LLM_API_BASE",
    "DEDUPE_LLM_EXTRA_HEADERS", "OPENCODE_API_KEY", "OPENCODE_GO_API_KEY", "OPENCODE_ZEN_API_KEY",
)


def public(p: dict[str, Any]) -> dict[str, Any]:
    """Profile as sent to the browser: never includes the key."""
    out = {k: v for k, v in p.items() if k != "api_key_enc"}
    out["has_api_key"] = bool(p.get("api_key_enc"))
    out["strix_model"] = strix_model(p)
    out["provider_label"] = PROVIDERS.get(p["provider"], {}).get("label", p["provider"])
    return out


def list_profiles() -> list[dict[str, Any]]:
    return db.q("SELECT * FROM llm_profiles ORDER BY is_default DESC, name COLLATE NOCASE")


def get(pid: int | None) -> dict[str, Any] | None:
    return db.get("llm_profiles", pid) if pid else None


def default_profile() -> dict[str, Any] | None:
    return db.q1("SELECT * FROM llm_profiles WHERE is_default=1 LIMIT 1")


def set_default(pid: int) -> None:
    db.execute("UPDATE llm_profiles SET is_default = CASE WHEN id=? THEN 1 ELSE 0 END", (pid,))


def strix_model(p: dict[str, Any]) -> str:
    model = (p.get("model") or "").strip()
    if p.get("provider") == "opencode_go":
        model = model.removeprefix("opencode-go/")
    prefix = PROVIDERS.get(p.get("provider", ""), {}).get("prefix", "")
    return model if not prefix or model.startswith(prefix) else prefix + model


def scan_session_id(scan: dict[str, Any]) -> str:
    """Stable, installation-scoped routing id; a resumed run keeps its original session."""
    sid = scan["id"]
    if scan.get("resume_run"):
        first = db.q1("SELECT MIN(id) AS id FROM scans WHERE run_name=?", (scan["resume_run"],))
        if first and first["id"] is not None:
            sid = first["id"]
    digest = hmac.new(crypto.derive("opencode-go-session-v1"), str(sid).encode(), hashlib.sha256).hexdigest()
    return "ses_skynet_" + digest


def _go_headers(session_id: str) -> dict[str, str]:
    return {"User-Agent": OPENCODE_USER_AGENT, "x-opencode-session": session_id}


def strix_env(p: dict[str, Any], *, session_id: str | None = None) -> dict[str, str]:
    env = {"STRIX_LLM": strix_model(p)}
    key = crypto.decrypt_strict(p.get("api_key_enc"))
    if key:
        env["LLM_API_KEY"] = key
    elif p.get("provider") == "litellm":
        # Strix's OpenAI client refuses to start without a key even if the gateway needs none.
        env["LLM_API_KEY"] = "no-key"
    provider = PROVIDERS.get(p.get("provider"), {})
    base = (p.get("base_url") or provider.get("default_base") or "").strip().rstrip("/")
    if base:
        env["LLM_API_BASE"] = base
    api_type = p.get("api_type") or provider.get("default_api_type")
    if api_type:
        env["STRIX_API_TYPE"] = api_type
    if p.get("provider") == "opencode_go":
        if not key:
            raise ValueError("OpenCode Go requires an API key.")
        if not session_id:
            raise ValueError("OpenCode Go requires a scan session ID.")
        env["LLM_EXTRA_HEADERS"] = json.dumps(_go_headers(session_id))
    if p.get("reasoning_effort"):
        env["STRIX_REASONING_EFFORT"] = p["reasoning_effort"]
    if p.get("ca_cert_path"):
        env["SSL_CERT_FILE"] = p["ca_cert_path"]
    return env


def migrate_from_strix_cli_config(cfg: dict[str, Any]) -> None:
    """First start only: turn ~/.strix/cli-config.json into an OpenRouter profile."""
    if db.q1("SELECT id FROM llm_profiles LIMIT 1"):
        return
    env = cfg.get("env") or {}
    model = env.get("STRIX_LLM") or ""
    if not model.startswith("openrouter/"):
        return
    db.insert("llm_profiles", {
        "name": "OpenRouter", "provider": "openrouter", "base_url": env.get("LLM_API_BASE", ""),
        "api_key_enc": crypto.encrypt(env.get("LLM_API_KEY", "")), "model": model[len("openrouter/"):],
        "reasoning_effort": env.get("STRIX_REASONING_EFFORT", ""), "is_default": 1,
    })


# ---------------------------------------------------------------- connection test / model list
def _scrub(text: str, key: str) -> str:
    return redact.Redactor([key] if key else []).text(text, strict=True)


def _get(url: str, key: str, cafile: str | None, extra_headers: dict[str, str] | None = None) -> Any:
    headers = {"User-Agent": "skynet", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    headers.update(extra_headers or {})
    ctx = ssl.create_default_context(cafile=cafile) if cafile else None
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15, context=ctx) as r:
        return json.loads(r.read().decode() or "{}")


def test(p: dict[str, Any], key_override: str | None = None, *, catalog_only: bool = False) -> dict[str, Any]:
    key = key_override if key_override is not None else crypto.decrypt_strict(p.get("api_key_enc"))
    provider = p.get("provider")
    base = (p.get("base_url") or PROVIDERS.get(provider, {}).get("default_base") or "").rstrip("/")
    cafile = p.get("ca_cert_path") or None
    if not base:
        return {"ok": False, "message": "Base URL is required.", "models": []}
    result: dict[str, Any] = {"ok": False, "models": [], "message": ""}
    try:
        if provider == "openrouter" and not catalog_only:
            info = (_get(base + "/key", key, cafile) or {}).get("data") or {}
            usage, limit = info.get("usage"), info.get("limit")
            msg = "API key is valid."
            if isinstance(usage, (int, float)):
                msg += f" Usage: ${usage:.2f}" + (f" / limit ${limit}" if limit else "")
            result["message"] = msg
            data = _get(base + "/models", "", cafile)
        elif provider == "openrouter":
            data = _get(base + "/models", "", cafile)
            result.update(check_type="catalog", key_verified=False,
                          message="OpenRouter model catalogue loaded. Listed models do not verify your key or account access.")
        elif provider == "opencode_go":
            if not key:
                return {"ok": False, "models": [], "message": "OpenCode Go requires an API key."}
            # The model catalogue lives outside the OpenAI protocol path. Keep a custom origin rather
            # than silently sending its credential to a different host or the pay-as-you-go service.
            models = base[:-len("/openai/v1")] + "/v1/models" if base.endswith("/openai/v1") else base + "/models"
            data = _get(models, key, cafile, _go_headers("ses_skynet_check_" + secrets.token_hex(16)))
            result.update(check_type="catalog", key_verified=False,
                          message="OpenCode Go model catalogue is reachable. This check does not verify inference access, API key validity or Go allowance.")
        else:
            try:
                data = _get(base + "/models", key, cafile)
            except urllib.error.HTTPError as e:
                if e.code != 404 or base.endswith("/v1"):
                    raise
                data = _get(base + "/v1/models", key, cafile)
            result["message"] = "Gateway is reachable."
    except urllib.error.HTTPError as e:
        with e:
            body = _scrub(e.read().decode(errors="replace"), key)[:300]
        return {"ok": False, "message": f"HTTP {e.code}: {body}", "models": []}
    except urllib.error.URLError as e:
        return {"ok": False, "message": _scrub(f"Could not connect to server ({base}): {e.reason}", key), "models": []}
    except (TimeoutError, ValueError, ssl.SSLError, OSError) as e:
        return {"ok": False, "message": _scrub(f"Connection error: {e}", key), "models": []}
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return {"ok": False, "models": [], "message": "Provider returned an invalid model list."}
    ids = sorted({m["id"] for m in data["data"] if isinstance(m, dict) and isinstance(m.get("id"), str) and m["id"]})
    result["ok"] = True
    result["models"] = ids
    model = "" if catalog_only else (p.get("model") or "").strip()
    if provider == "opencode_go":
        model = model.removeprefix("opencode-go/")
    prefix = PROVIDERS.get(provider, {}).get("prefix", "")
    bare = model[len(prefix):] if prefix and model.startswith(prefix) else model
    if ids and bare:
        result["model_found"] = bare in ids
        result["message"] += f" {len(ids)} models listed; selected model " + (
            "is available." if bare in ids else f"'{bare}' was not found.")
    elif not ids:
        result["message"] += " Provider did not return a model list."
    return result
