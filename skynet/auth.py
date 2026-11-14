"""Single-admin login with an HMAC-signed session cookie, plus the CI API token."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

from . import crypto, db
from .config import ADMIN_PASSWORD, ADMIN_PASSWORD_FILE, ADMIN_USER, SESSION_HOURS

log = logging.getLogger("skynet.auth")
COOKIE = "skynet_session"
_SESSION_KEY = crypto.derive("session-cookie")
_failures: dict[str, list[float]] = {}


# ---------------------------------------------------------------- password
def _hash(pw: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def _verify_hash(pw: str, stored: str) -> bool:
    try:
        _, salt_b64, _ = stored.split("$")
        return hmac.compare_digest(_hash(pw, base64.b64decode(salt_b64)), stored)
    except ValueError:
        return False


def password_from_env() -> bool:
    return bool(ADMIN_PASSWORD)


def bootstrap() -> None:
    """If no password is configured, generate one and write it to data/admin_password.txt (0600)."""
    if ADMIN_PASSWORD or db.get_settings().get("admin_password_hash"):
        return
    pw = secrets.token_urlsafe(14)
    db.set_settings({"admin_password_hash": _hash(pw)})
    fd = os.open(ADMIN_PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"user: {ADMIN_USER}\npassword: {pw}\n")
    log.warning("No SKYNET_PASSWORD set; generated initial admin password in %s", ADMIN_PASSWORD_FILE)


def _fingerprint() -> str:
    src = ADMIN_PASSWORD or db.get_settings().get("admin_password_hash") or ""
    return hashlib.sha256(src.encode()).hexdigest()[:12]


def check_credentials(user: str, pw: str) -> bool:
    ok_user = hmac.compare_digest(user.encode(), ADMIN_USER.encode())
    if ADMIN_PASSWORD:
        ok_pw = hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())
    else:
        ok_pw = _verify_hash(pw, db.get_settings().get("admin_password_hash") or "")
    return ok_user and ok_pw


def change_password(current: str, new: str) -> None:
    if ADMIN_PASSWORD:
        raise ValueError("Şifre SKYNET_PASSWORD ortam değişkeninden geliyor; orada değiştirin.")
    if not check_credentials(ADMIN_USER, current):
        raise ValueError("Mevcut şifre yanlış.")
    if len(new) < 10:
        raise ValueError("Yeni şifre en az 10 karakter olmalı.")
    db.set_settings({"admin_password_hash": _hash(new)})
    ADMIN_PASSWORD_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------- brute-force throttle
def throttled(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _failures.get(ip, []) if now - t < 300]
    _failures[ip] = recent
    return len(recent) >= 5


def record_failure(ip: str) -> None:
    _failures.setdefault(ip, []).append(time.time())


def clear_failures(ip: str) -> None:
    _failures.pop(ip, None)


# ---------------------------------------------------------------- session cookie
def _sign(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(_SESSION_KEY, payload, hashlib.sha256).digest()).decode().rstrip("=")


def make_session() -> str:
    payload = base64.urlsafe_b64encode(json.dumps(
        {"u": ADMIN_USER, "exp": int(time.time()) + SESSION_HOURS * 3600, "v": _fingerprint()}).encode())
    return payload.decode() + "." + _sign(payload)


def valid_session(cookie: str | None) -> bool:
    if not cookie or "." not in cookie:
        return False
    payload, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload.encode())):
        return False
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except ValueError:
        return False
    return data.get("exp", 0) > time.time() and data.get("v") == _fingerprint() and data.get("u") == ADMIN_USER


# ---------------------------------------------------------------- CI token
def api_token() -> str:
    st = db.get_settings()
    tok = crypto.decrypt(st.get("api_token_enc"))
    if not tok:
        tok = rotate_api_token()
    return tok


def rotate_api_token() -> str:
    tok = secrets.token_urlsafe(32)
    db.set_settings({"api_token_enc": crypto.encrypt(tok)})
    return tok


def valid_api_token(tok: str) -> bool:
    return bool(tok) and hmac.compare_digest(tok.encode(), api_token().encode())
