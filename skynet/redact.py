"""Masking of secrets in everything Skynet shows or stores from Strix output.

Two layers:
- value-based: exact secret values Skynet knows (auth-profile secrets, including those snapshotted per scan) and
  common encodings of them. This is what catches a password that Strix copied into run.json / coverage.json /
  agents.json / logs.
- pattern-based (strict mode, for telemetry and inventory evidence): Authorization/Cookie headers, key=value
  pairs that look like credentials, LLM API keys.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Iterable
from urllib.parse import quote, quote_plus

MASK = "••••••"
MIN_LEN = 1

_LLM_KEY = re.compile(r"\b(sk-or-v1-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{24,}|oc_sk_[A-Za-z0-9_-]{16,})")
_AUTH_HDR = re.compile(r"(?im)\b((?:proxy-)?authorization|x-api-key|api-key|x-auth-token)(\s*[:=]\s*)(bearer\s+|basic\s+|token\s+)?([^\s\"',;]+)")
_COOKIE_HDR = re.compile(r"(?im)\b(set-cookie|cookie)(\s*:\s*)([^\r\n]+)")
_KV = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|session|sid)(\"?\s*[:=]\s*\"?)([^\s\"'&,;}]{3,})")
_SECRET_KEYS = {"password", "passwd", "pwd", "secret", "token", "accesstoken", "refreshtoken", "apikey",
                "authorization", "proxyauthorization", "cookie", "setcookie", "session", "sid", "xauthtoken", "xapikey"}


def variants(secret: str) -> set[str]:
    out = {secret}
    for f in (quote, quote_plus):
        out.add(f(secret, safe=""))
    out.add(json.dumps(secret)[1:-1])
    out.add(base64.b64encode(secret.encode()).decode().rstrip("="))
    return {v for v in out if len(v) >= MIN_LEN}


class Redactor:
    def __init__(self, secrets: Iterable[str] = ()):
        vals: set[str] = set()
        for s in secrets:
            if s and len(s) >= MIN_LEN:
                vals |= variants(s)
        # longest first so a secret that contains another one is masked whole
        self._vals = sorted(vals, key=len, reverse=True)
        self._re = re.compile("|".join(re.escape(v) for v in self._vals)) if self._vals else None

    def __bool__(self) -> bool:
        return self._re is not None

    def text(self, s: str | None, strict: bool = False) -> str:
        if not s:
            return s or ""
        if self._re is not None:
            s = self._re.sub(MASK, s)
        s = _LLM_KEY.sub(MASK, s)
        if strict:
            s = _AUTH_HDR.sub(lambda m: f"{m[1]}{m[2]}{m[3] or ''}{MASK}", s)
            s = _COOKIE_HDR.sub(lambda m: m[1] + m[2] + re.sub(r"=([^;\s]+)", "=" + MASK, m[3]), s)
            s = _KV.sub(lambda m: f"{m[1]}{m[2]}{MASK}", s)
        return s

    def obj(self, o, strict: bool = False):
        """Recursively mask strings inside JSON-like data."""
        if isinstance(o, str):
            return self.text(o, strict)
        if isinstance(o, list):
            return [self.obj(x, strict) for x in o]
        if isinstance(o, dict):
            return {k: (MASK if strict and re.sub(r"[-_]", "", str(k).lower()) in _SECRET_KEYS
                        and isinstance(v, (str, list, dict)) and v
                        else self.obj(v, strict)) for k, v in o.items()}
        return o


def strict(s: str | None, secrets: Iterable[str] = ()) -> str:
    return Redactor(secrets).text(s, strict=True)
