"""Encryption at rest for secrets (LLM API keys, target credentials, CI token).

Key source, in order: SKYNET_SECRET_KEY env var, else data/secret.key (generated on first start, 0600).
Losing the key makes stored secrets unreadable; they then have to be re-entered in the UI.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from .config import SECRET_KEY, SECRET_KEY_FILE


def _load_key() -> bytes:
    if SECRET_KEY:
        return SECRET_KEY.encode()
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


_key = _load_key()
_fernet = Fernet(_key)


def derive(label: str) -> bytes:
    """Independent sub-key (e.g. for session-cookie HMAC) derived from the master key."""
    import hashlib
    import hmac
    return hmac.new(_key, label.encode(), hashlib.sha256).digest()


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode() if value else ""


def decrypt(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return ""
