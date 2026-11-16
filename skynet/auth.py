"""User accounts (admin / analyst / viewer) with an HMAC-signed session cookie, plus the CI API token.

The built-in account (SKYNET_USER, default "admin") always exists, is always an active admin and cannot be
edited in the UI. When SKYNET_PASSWORD is set its password comes from the environment; otherwise a random one is
generated on first start (data/admin_password.txt). Other accounts are managed under Settings > Users.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Any

from . import crypto, db
from .config import ADMIN_PASSWORD, ADMIN_PASSWORD_FILE, ADMIN_USER, SESSION_HOURS

log = logging.getLogger("skynet.auth")
COOKIE = "skynet_session"
_SESSION_KEY = crypto.derive("session-cookie")
_failures: dict[str, list[float]] = {}

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES, 1)}
ROLE_LABELS = {"viewer": "Viewer", "analyst": "Analyst", "admin": "Admin"}
MIN_PASSWORD = 10
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
# Reserved actor names used in the audit log for non-user actions.
RESERVED = {"scheduler", "ci-token", "system"}


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


_DUMMY_HASH = _hash(secrets.token_hex(8))   # equalises timing for unknown usernames


def password_from_env() -> bool:
    return bool(ADMIN_PASSWORD)


def env_managed(user: dict[str, Any] | None) -> bool:
    """The built-in account's password is controlled by SKYNET_PASSWORD when that is set."""
    return bool(user and user.get("builtin") and ADMIN_PASSWORD)


# ---------------------------------------------------------------- accounts
def builtin_user() -> dict[str, Any] | None:
    return db.q1("SELECT * FROM users WHERE builtin=1 ORDER BY id LIMIT 1")


def get_user(uid: int | None) -> dict[str, Any] | None:
    return db.q1("SELECT * FROM users WHERE id=?", (uid,)) if uid else None


def find_user(username: str) -> dict[str, Any] | None:
    return db.q1("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username.strip(),))


def bootstrap() -> None:
    """Make sure the built-in admin exists (and follows SKYNET_USER). Without SKYNET_PASSWORD and without a stored
    password, generate one and write it to data/admin_password.txt (0600)."""
    now = db.now_iso()
    u = builtin_user()
    if not u:
        db.execute("INSERT INTO users (username, role, active, builtin, created_at, updated_at) VALUES (?, 'admin', 1, 1, ?, ?)",
                   (ADMIN_USER, now, now))
        u = builtin_user()
    elif u["username"] != ADMIN_USER and not find_user(ADMIN_USER):
        db.execute("UPDATE users SET username=?, updated_at=? WHERE id=?", (ADMIN_USER, now, u["id"]))
    if u["role"] != "admin" or not u["active"]:   # never lose the break-glass account
        db.execute("UPDATE users SET role='admin', active=1 WHERE id=?", (u["id"],))
    if ADMIN_PASSWORD or u.get("password_hash"):
        return
    pw = secrets.token_urlsafe(14)
    db.execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?", (_hash(pw), now, u["id"]))
    fd = os.open(ADMIN_PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"user: {ADMIN_USER}\npassword: {pw}\n")
    log.warning("No SKYNET_PASSWORD set; generated initial admin password in %s", ADMIN_PASSWORD_FILE)


def _password_ok(user: dict[str, Any], pw: str) -> bool:
    if env_managed(user):
        return hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())
    return _verify_hash(pw, user.get("password_hash") or "")


def check_credentials(username: str, pw: str) -> dict[str, Any] | None:
    """The active user these credentials belong to, or None."""
    u = find_user(username) if username.strip() else None
    if not u:
        _verify_hash(pw, _DUMMY_HASH)
        return None
    return u if _password_ok(u, pw) and u["active"] else None


def public(u: dict[str, Any]) -> dict[str, Any]:
    """Account fields that are safe to send to the browser."""
    return {"id": u["id"], "username": u["username"], "display_name": u.get("display_name") or "",
            "role": u["role"], "role_label": ROLE_LABELS.get(u["role"], u["role"]), "active": bool(u["active"]),
            "builtin": bool(u["builtin"]), "password_from_env": env_managed(u),
            "created_at": u.get("created_at"), "last_login_at": u.get("last_login_at"),
            "password_changed_at": u.get("password_changed_at")}


def list_users() -> list[dict[str, Any]]:
    return [public(u) for u in db.q("SELECT * FROM users ORDER BY builtin DESC, username COLLATE NOCASE")]


def _check_password(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise ValueError(f"Password must contain at least {MIN_PASSWORD} characters.")


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError("Invalid role.")


def create_user(username: str, role: str, password: str, display_name: str = "") -> dict[str, Any]:
    username = username.strip()
    if not _USERNAME.match(username):
        raise ValueError("Username: 2–64 characters; letters, digits and . _ @ - (must start with a letter or digit).")
    if username.lower() in RESERVED or find_user(username):
        raise ValueError("This username is already taken.")
    _check_role(role)
    _check_password(password)
    now = db.now_iso()
    uid = db.execute("INSERT INTO users (username, display_name, role, password_hash, active, builtin, created_at, "
                     "updated_at, password_changed_at) VALUES (?,?,?,?,1,0,?,?,?)",
                     (username, display_name.strip()[:80], role, _hash(password), now, now, now))
    return get_user(uid)


def _editable(uid: int, acting: dict[str, Any]) -> dict[str, Any]:
    u = get_user(uid)
    if not u:
        raise LookupError("User not found.")
    if u["builtin"]:
        raise ValueError("The built-in admin account is managed in the server configuration (SKYNET_USER / SKYNET_PASSWORD).")
    return u


def _admins_left_without(uid: int) -> int:
    return db.q1("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1 AND id<>?", (uid,))["n"]


def update_user(uid: int, acting: dict[str, Any], role: str | None = None, active: bool | None = None,
                display_name: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (before, after)."""
    u = _editable(uid, acting)
    if uid == acting["id"] and ((role and role != u["role"]) or active is False):
        raise ValueError("You can't change the role of, or disable, your own account.")
    changes: dict[str, Any] = {}
    if role is not None and role != u["role"]:
        _check_role(role)
        changes["role"] = role
    if active is not None and bool(active) != bool(u["active"]):
        changes["active"] = 1 if active else 0
    if display_name is not None:
        changes["display_name"] = display_name.strip()[:80]
    demotes = changes.get("role", "admin") != "admin" or changes.get("active", 1) == 0
    if u["role"] == "admin" and demotes and not _admins_left_without(uid):
        raise ValueError("At least one active admin must remain.")
    if changes:
        changes["updated_at"] = db.now_iso()
        cols = ", ".join(f"{k}=?" for k in changes)
        db.execute(f"UPDATE users SET {cols} WHERE id=?", (*changes.values(), uid))
    return u, get_user(uid)


def reset_password(uid: int, acting: dict[str, Any], new: str) -> dict[str, Any]:
    u = _editable(uid, acting)
    _check_password(new)
    now = db.now_iso()
    db.execute("UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=?", (_hash(new), now, now, uid))
    return u


def delete_user(uid: int, acting: dict[str, Any]) -> dict[str, Any]:
    u = _editable(uid, acting)
    if uid == acting["id"]:
        raise ValueError("You can't delete your own account.")
    if u["role"] == "admin" and u["active"] and not _admins_left_without(uid):
        raise ValueError("At least one active admin must remain.")
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    return u


def change_password(user: dict[str, Any], current: str, new: str) -> None:
    """A signed-in user changing their own password. Existing sessions of that user are invalidated."""
    if env_managed(user):
        raise ValueError("The password comes from SKYNET_PASSWORD. Change it in the server configuration.")
    if not _password_ok(user, current):
        raise ValueError("Current password is incorrect.")
    _check_password(new)
    now = db.now_iso()
    db.execute("UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=?",
               (_hash(new), now, now, user["id"]))
    if user.get("builtin"):
        ADMIN_PASSWORD_FILE.unlink(missing_ok=True)


def touch_login(uid: int) -> None:
    db.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now_iso(), uid))


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


def _fingerprint(u: dict[str, Any]) -> str:
    """Changes when the user's password changes, so a password change/reset signs out old sessions."""
    src = f"{u['id']}:{u['username']}:" + (ADMIN_PASSWORD if env_managed(u) else (u.get("password_hash") or ""))
    return hashlib.sha256(src.encode()).hexdigest()[:16]


def make_session(user: dict[str, Any] | None = None) -> str:
    u = user or builtin_user()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"uid": u["id"], "exp": int(time.time()) + SESSION_HOURS * 3600, "v": _fingerprint(u)}).encode())
    return payload.decode() + "." + _sign(payload)


def valid_session(cookie: str | None) -> dict[str, Any] | None:
    """The signed-in user, re-read from the database on every request (role and active state are never trusted
    from the cookie), or None."""
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload.encode())):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("exp", 0) <= time.time():
        return None
    u = get_user(data.get("uid")) if isinstance(data.get("uid"), int) else None
    if not u or not u["active"] or not hmac.compare_digest(str(data.get("v", "")), _fingerprint(u)):
        return None
    return u


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
