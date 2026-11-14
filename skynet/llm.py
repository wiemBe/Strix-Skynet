"""LLM connection profiles (OpenRouter / LiteLLM) mapped onto Strix's own env-var mechanism.

Strix uses LiteLLM internally and is configured with STRIX_LLM / LLM_API_KEY / LLM_API_BASE
(https://docs.strix.ai/advanced/configuration). This module only translates a stored profile into
those variables; it never proxies LLM traffic and never falls back to another profile.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from . import crypto, db

PROVIDERS = {
    "openrouter": {"label": "OpenRouter", "prefix": "openrouter/", "default_base": "https://openrouter.ai/api/v1"},
    # Documented pattern for OpenAI-compatible gateways: openai/<model> + LLM_API_BASE.
    "litellm": {"label": "LiteLLM", "prefix": "openai/", "default_base": ""},
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
    prefix = PROVIDERS.get(p.get("provider", ""), {}).get("prefix", "")
    return model if not prefix or model.startswith(prefix) else prefix + model


def strix_env(p: dict[str, Any]) -> dict[str, str]:
    env = {"STRIX_LLM": strix_model(p)}
    key = crypto.decrypt(p.get("api_key_enc"))
    if key:
        env["LLM_API_KEY"] = key
    elif p.get("provider") == "litellm":
        # Strix's OpenAI client refuses to start without a key even if the gateway needs none.
        env["LLM_API_KEY"] = "no-key"
    if (p.get("base_url") or "").strip():
        env["LLM_API_BASE"] = p["base_url"].strip().rstrip("/")
    if p.get("api_type"):
        env["STRIX_API_TYPE"] = p["api_type"]
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
    return text.replace(key, "***") if key else text


def _get(url: str, key: str, cafile: str | None) -> Any:
    headers = {"User-Agent": "skynet", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    ctx = ssl.create_default_context(cafile=cafile) if cafile else None
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15, context=ctx) as r:
        return json.loads(r.read().decode() or "{}")


def test(p: dict[str, Any], key_override: str | None = None) -> dict[str, Any]:
    key = key_override if key_override is not None else crypto.decrypt(p.get("api_key_enc"))
    provider = p.get("provider")
    base = (p.get("base_url") or PROVIDERS.get(provider, {}).get("default_base") or "").rstrip("/")
    cafile = p.get("ca_cert_path") or None
    if not base:
        return {"ok": False, "message": "Base URL girilmemiş.", "models": []}
    result: dict[str, Any] = {"ok": False, "models": [], "message": ""}
    try:
        if provider == "openrouter":
            info = (_get(base + "/key", key, cafile) or {}).get("data") or {}
            usage, limit = info.get("usage"), info.get("limit")
            msg = "Anahtar geçerli."
            if isinstance(usage, (int, float)):
                msg += f" Kullanım: ${usage:.2f}" + (f" / limit ${limit}" if limit else "")
            result["message"] = msg
            data = _get(base + "/models", "", cafile)
        else:
            try:
                data = _get(base + "/models", key, cafile)
            except urllib.error.HTTPError as e:
                if e.code != 404 or base.endswith("/v1"):
                    raise
                data = _get(base + "/v1/models", key, cafile)
            result["message"] = "Gateway erişilebilir."
    except urllib.error.HTTPError as e:
        body = _scrub(e.read().decode(errors="replace")[:300], key)
        return {"ok": False, "message": f"HTTP {e.code}: {body}", "models": []}
    except urllib.error.URLError as e:
        return {"ok": False, "message": _scrub(f"Sunucuya bağlanılamadı ({base}): {e.reason}", key), "models": []}
    except (TimeoutError, ValueError, ssl.SSLError, OSError) as e:
        return {"ok": False, "message": _scrub(f"Bağlantı hatası: {e}", key), "models": []}
    ids = sorted({m.get("id") for m in (data or {}).get("data") or [] if isinstance(m, dict) and m.get("id")})
    result["ok"] = True
    result["models"] = ids
    model = (p.get("model") or "").strip()
    prefix = PROVIDERS.get(provider, {}).get("prefix", "")
    bare = model[len(prefix):] if prefix and model.startswith(prefix) else model
    if ids and bare:
        result["model_found"] = bare in ids
        result["message"] += f" {len(ids)} model listelendi; seçili model " + (
            "listede var." if bare in ids else f"'{bare}' listede YOK.")
    elif not ids:
        result["message"] += " Sağlayıcı model listesi döndürmedi."
    return result
