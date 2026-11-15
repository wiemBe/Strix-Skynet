"""Reusable authentication profiles ("vault") for targets.

What the installed Strix (1.7) supports: it has no authentication option of its own. Credentials reach the agents
only through the instruction text or through files placed in the sandbox with `--workspace-file`. Skynet uses
the second channel for secret values: each selected profile is written to a 0600 file under data/runtime, copied
by Strix into /workspace/skynet_auth/ inside the sandbox, and removed from the host when the scan ends. The
instruction only names the profile, the method, non-secret metadata (username, header/cookie names) and the file
path, and asks the agents to use the file by reference (curl -H @file / -b file) instead of printing it.

Offered methods are the ones an agent can actually use with those primitives:
  anonymous    no credentials; an explicit unauthenticated role for access-control comparisons
  credentials  username + password for a login form (the agent has to read the password to type it)
  header       one or more request headers (Bearer token, API key)
  cookie       session cookie(s)
Not offered because nothing in Strix would make them work: OAuth flows/token refresh, MFA/TOTP, client
certificates (mTLS), NTLM/Kerberos.

Delivery is guidance to an LLM agent, not enforcement: Strix does not report whether a login succeeded. Skynet can
run its own pre-check (header/cookie profiles with a verification URL); that is shown separately.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import crypto, db, scope
from .redact import Redactor

KINDS = {
    "anonymous": "Anonim (oturumsuz)",
    "credentials": "Kullanıcı adı + şifre (form girişi)",
    "header": "HTTP başlığı (Bearer token / API anahtarı)",
    "cookie": "Oturum çerezi",
}
SANDBOX_DIR = "skynet_auth"
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
_COOKIE_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,200}$")


class AuthError(ValueError):
    """Profile cannot be used for this scan (missing, not assigned, unreadable). Never silently skipped."""


# ---------------------------------------------------------------- storage
def get(pid: int) -> dict[str, Any] | None:
    return db.get("auth_profiles", pid)


def secrets_of(p: dict[str, Any]) -> dict[str, Any]:
    raw = crypto.vault_decrypt(p.get("secret_enc"))
    return json.loads(raw) if raw else {}


def secret_values(p: dict[str, Any]) -> list[str]:
    """Every value that must be masked wherever it shows up."""
    try:
        s = secrets_of(p)
    except crypto.DecryptError:
        return []
    vals: list[str] = []
    if s.get("password"):
        vals.append(s["password"])
    for v in list((s.get("headers") or {}).values()) + list((s.get("cookies") or {}).values()):
        if not v:
            continue
        vals.append(v)
        m = re.match(r"(?i)^(bearer|basic|token)\s+(.+)$", v)
        if m:
            vals.append(m.group(2))
    return vals


def assigned_targets(pid: int) -> list[int]:
    return [r["target_id"] for r in db.q("SELECT target_id FROM auth_profile_targets WHERE profile_id=?", (pid,))]


def profiles_for_target(tid: int) -> list[dict[str, Any]]:
    return db.q("SELECT p.* FROM auth_profiles p JOIN auth_profile_targets a ON a.profile_id=p.id "
                "WHERE a.target_id=? ORDER BY p.name COLLATE NOCASE", (tid,))


def schedules_using(pid: int, target_ids: list[int] | None = None) -> list[dict[str, Any]]:
    rows = db.q("SELECT s.id, s.name, s.kind, s.enabled, s.target_id, s.auth_profile_ids, t.name AS target_name "
                "FROM schedules s JOIN targets t ON t.id=s.target_id")
    return [r for r in rows if pid in (r.get("auth_profile_ids") or [])
            and (target_ids is None or r["target_id"] in target_ids)]


_global_cache: dict[str, Any] = {"sig": None, "r": Redactor()}


def global_redactor(extra: list[str] | None = None) -> Redactor:
    """Masks the current secrets of every profile (cached until a profile changes) plus `extra`."""
    sig = db.q1("SELECT COUNT(*) AS n, MAX(updated_at) AS u, MAX(secret_updated_at) AS s FROM auth_profiles")
    key = (sig["n"], sig["u"], sig["s"]) if sig else None
    if _global_cache["sig"] != key:
        vals: list[str] = []
        for p in db.q("SELECT * FROM auth_profiles"):
            vals += secret_values(p)
        _global_cache.update(sig=key, vals=vals, r=Redactor(vals))
    if extra:
        return Redactor([*_global_cache.get("vals", []), *extra])
    return _global_cache["r"]


def scan_redactor(scan: dict[str, Any]) -> Redactor:
    """Current profile secrets + the encrypted snapshot of the values this scan was started with (so masking keeps
    working after a profile is rotated or deleted)."""
    snap: list[str] = []
    if scan.get("redact_enc"):
        try:
            snap = json.loads(crypto.vault_decrypt(scan["redact_enc"]) or "[]")
        except (crypto.DecryptError, ValueError):
            snap = []
    return global_redactor(snap)


# ---------------------------------------------------------------- public view
def public(p: dict[str, Any], with_usage: bool = True) -> dict[str, Any]:
    """As sent to the browser: no secret values, ever."""
    out = {k: v for k, v in p.items() if k != "secret_enc"}
    out["kind_label"] = KINDS.get(p["kind"], p["kind"])
    out["has_secret"] = bool(p.get("secret_enc"))
    out["secret_readable"] = True
    if p.get("secret_enc"):
        try:
            secrets_of(p)
        except crypto.DecryptError:
            out["secret_readable"] = False
    out["verifiable"] = p["kind"] in ("header", "cookie")
    if with_usage:
        tids = assigned_targets(p["id"])
        out["target_ids"] = tids
        out["targets"] = db.q(f"SELECT id, name, environment, base_url FROM targets WHERE id IN ({','.join('?' * len(tids))}) "
                              "ORDER BY name COLLATE NOCASE", tids) if tids else []
        out["schedules"] = schedules_using(p["id"])
    return out


# ---------------------------------------------------------------- validation
def payload(body: dict[str, Any], existing: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """-> (columns, new secret dict or None to keep the stored one)."""
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("Profil adı zorunlu")
    kind = body.get("kind")
    if kind not in KINDS:
        raise ValueError("Geçersiz yöntem")
    old = {}
    if existing and existing.get("secret_enc") and existing["kind"] == kind:
        old = secrets_of(existing)  # DecryptError propagates: user must re-enter
    cols: dict[str, Any] = {"name": name, "kind": kind, "description": (body.get("description") or "").strip(),
                            "notes": (body.get("notes") or "").strip(), "username": "", "login_url": "",
                            "header_names": [], "cookie_names": [], "cookie_domain": "",
                            "verify_url": "", "verify_expect_status": None, "verify_expect_text": ""}
    secret: dict[str, Any] | None = None
    if kind == "credentials":
        cols["username"] = (body.get("username") or "").strip()
        cols["login_url"] = (body.get("login_url") or "").strip()
        if not cols["username"]:
            raise ValueError("Kullanıcı adı zorunlu")
        if cols["login_url"] and scope.split(cols["login_url"])[0] not in ("http", "https"):
            raise ValueError("Giriş adresi http(s) olmalı")
        pw = body.get("password") or ""
        if pw:
            secret = {"password": pw}
        elif not old.get("password"):
            raise ValueError("Şifre zorunlu")
    elif kind in ("header", "cookie"):
        items = body.get("headers" if kind == "header" else "cookies") or []
        names, values = [], {}
        prev = old.get("headers" if kind == "header" else "cookies") or {}
        for it in items:
            n = (it.get("name") or "").strip()
            if not n:
                continue
            if not (_HEADER_NAME if kind == "header" else _COOKIE_NAME).match(n):
                raise ValueError(f"Geçersiz {'başlık' if kind == 'header' else 'çerez'} adı: {n}")
            if n.lower() in (x.lower() for x in names):
                raise ValueError(f"Aynı ad iki kez girildi: {n}")
            v = it.get("value") or ""
            if "\n" in v or "\r" in v:
                raise ValueError("Değer satır sonu içeremez")
            if not v and n not in prev:
                raise ValueError(f"“{n}” için değer girin")
            names.append(n)
            values[n] = v or prev[n]
        if not names:
            raise ValueError("En az bir " + ("başlık" if kind == "header" else "çerez") + " girin")
        cols["header_names" if kind == "header" else "cookie_names"] = names
        if kind == "cookie":
            cols["cookie_domain"] = (body.get("cookie_domain") or "").strip().lstrip(".").lower()
        if values != prev:
            secret = {"headers" if kind == "header" else "cookies": values}
        vurl = (body.get("verify_url") or "").strip()
        if vurl:
            if scope.split(vurl)[0] not in ("http", "https"):
                raise ValueError("Doğrulama adresi http(s) olmalı")
            cols["verify_url"] = vurl
            st = body.get("verify_expect_status")
            cols["verify_expect_status"] = int(st) if str(st or "").strip() else 200
            cols["verify_expect_text"] = (body.get("verify_expect_text") or "").strip()
    else:  # anonymous
        secret = {}
    if existing and existing["kind"] != kind and secret is None:
        raise ValueError("Yöntem değiştiğinde gizli değerleri yeniden girin")
    return cols, secret


def save(body: dict[str, Any], existing: dict[str, Any] | None) -> int:
    cols, secret = payload(body, existing)
    if secret is not None:
        cols["secret_enc"] = crypto.vault_encrypt(json.dumps(secret)) if secret else ""
        cols["secret_updated_at"] = db.now_iso()
    if existing and (cols.get("verify_url") != existing.get("verify_url") or secret is not None):
        cols.update(last_verify_at=None, last_verify_ok=None, last_verify_note=None)
    if existing:
        db.update("auth_profiles", existing["id"], cols)
        return existing["id"]
    return db.insert("auth_profiles", cols)


# ---------------------------------------------------------------- scan integration
def resolve(target_id: int, profile_ids: list[int]) -> list[dict[str, Any]]:
    """Profiles for a scan, enforcing assignment and readability. Raises AuthError."""
    out = []
    allowed = {p["id"] for p in profiles_for_target(target_id)}
    for pid in dict.fromkeys(int(x) for x in profile_ids or []):
        p = get(pid)
        if not p:
            raise AuthError(f"Kimlik profili #{pid} silinmiş.")
        if pid not in allowed:
            raise AuthError(f"“{p['name']}” profili bu hedefe atanmamış.")
        if p["kind"] != "anonymous":
            try:
                if not secrets_of(p):
                    raise AuthError(f"“{p['name']}” profilinde gizli değer yok.")
            except crypto.DecryptError as e:
                raise AuthError(f"“{p['name']}”: {e}") from e
        out.append(p)
    return out


def _slug(p: dict[str, Any]) -> str:
    s = unicodedata.normalize("NFKD", p["name"]).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40] or "profil"
    return f"{s}-{p['id']}"


def _write_private(path: Path, text: str) -> None:
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def render(profiles: list[dict[str, Any]], runtime_dir: Path, sid: int) -> tuple[str, list[tuple[Path, str]], list[str]]:
    """-> (instruction section without secrets, [(host file, sandbox dest)], secret values for masking)."""
    if not profiles:
        return "", [], []
    files: list[tuple[Path, str]] = []
    masks: list[str] = []
    lines = ["## Authentication profiles (provided by Skynet)",
             f"Secret values are NOT in this text. They are files in the sandbox under /workspace/{SANDBOX_DIR}/.",
             "Use these files by reference only (for example `curl -H @<file>` or `curl -b <file>`, or load them inside "
             "a script). Do not print, cat, echo, copy or paste their contents, and never write secret values into "
             "notes, coverage records, reports or messages. Refer to profiles by their name.", ""]
    for p in profiles:
        slug = _slug(p)
        base = f"/workspace/{SANDBOX_DIR}/{slug}"
        sec = secrets_of(p) if p["kind"] != "anonymous" else {}
        masks += secret_values(p)

        def put(ext: str, text: str) -> str:
            host = runtime_dir / f"scan_{sid}_auth_{slug}.{ext}"
            _write_private(host, text)
            files.append((host, f"{SANDBOX_DIR}/{slug}.{ext}"))
            return f"{base}.{ext}"

        if p["kind"] == "anonymous":
            lines.append(f"- Profile “{p['name']}” (anonymous): no credentials. Use it as the unauthenticated role "
                         "when comparing what each role can access.")
        elif p["kind"] == "credentials":
            f = put("json", json.dumps({"username": p.get("username"), "password": sec.get("password"),
                                        "login_url": p.get("login_url") or None}))
            lines.append(f"- Profile “{p['name']}” (form login): username `{p.get('username')}`"
                         + (f", login page {p['login_url']}" if p.get("login_url") else "")
                         + f". The password is the \"password\" key of {f}; read it only to submit the login form.")
        elif p["kind"] == "header":
            hdrs = sec.get("headers") or {}
            fh = put("headers", "".join(f"{k}: {v}\n" for k, v in hdrs.items()))
            put("json", json.dumps({"headers": hdrs}))
            lines.append(f"- Profile “{p['name']}” (HTTP header {', '.join(hdrs)}): `curl -H @{fh} <url>`; "
                         f"JSON form in {base}.json.")
        elif p["kind"] == "cookie":
            ck = sec.get("cookies") or {}
            dom = p.get("cookie_domain") or ""
            jar = "# Netscape HTTP Cookie File\n" + "".join(
                f"{('.' + dom) if dom else ''}\tTRUE\t/\tFALSE\t0\t{k}\t{v}\n" for k, v in ck.items()) if dom else ""
            fh = put("cookie-header", "Cookie: " + "; ".join(f"{k}={v}" for k, v in ck.items()) + "\n")
            if jar:
                put("cookies", jar)
            put("json", json.dumps({"cookies": ck, "domain": dom or None}))
            lines.append(f"- Profile “{p['name']}” (session cookie {', '.join(ck)}): `curl -H @{fh} <url>`"
                         + (f" or `curl -b {base}.cookies <url>`" if jar else "") + f"; JSON form in {base}.json.")
    if len(profiles) > 1:
        lines += ["", "Several roles are provided: use them to test authorization boundaries (horizontal and vertical "
                      "access control) between the profiles."]
    return "\n".join(lines) + "\n", files, masks


# ---------------------------------------------------------------- Skynet-side pre-check
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # report 3xx as-is instead of following it
        return None


def verify(p: dict[str, Any], target: dict[str, Any] | None = None) -> dict[str, Any]:
    """One request from the Skynet host to the profile's verification URL. Separate from the Strix scan."""
    now = db.now_iso()
    if p["kind"] == "anonymous":
        return {"result": "not_applicable", "note": "Anonim profilde doğrulanacak oturum yok.", "at": now}
    if p["kind"] == "credentials":
        return {"result": "not_verifiable", "at": now,
                "note": "Form girişini Strix ajanı yapar ve Strix girişin başarılı olup olmadığını bildirmez; Skynet doğrulayamaz."}
    if not p.get("verify_url"):
        return {"result": "not_configured", "at": now, "note": "Doğrulama adresi tanımlı değil; oturumun geçerliliği bilinmiyor."}
    sch, host, port, path = scope.split(p["verify_url"])
    targets = [target] if target else db.q("SELECT t.* FROM targets t JOIN auth_profile_targets a ON a.target_id=t.id "
                                           "WHERE a.profile_id=?", (p["id"],))
    if not targets or not any(scope.label(t, host, port, path) == "in" for t in targets):
        return {"result": "blocked", "at": now,
                "note": "Doğrulama adresi atanmış hedeflerin kapsamında değil; istek gönderilmedi."}
    try:
        sec = secrets_of(p)
    except crypto.DecryptError as e:
        return {"result": "failed", "at": now, "note": str(e)}
    headers = {"User-Agent": "skynet-auth-check"}
    headers.update(sec.get("headers") or {})
    if sec.get("cookies"):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sec["cookies"].items())
    expect = int(p.get("verify_expect_status") or 200)
    text = p.get("verify_expect_text") or ""
    red = Redactor(secret_values(p))
    t0 = time.time()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        try:
            r = opener.open(urllib.request.Request(p["verify_url"], headers=headers), timeout=10)
            code, body = r.status, r.read(200_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read(20_000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"result": "failed", "at": now, "note": red.text(f"İstek gönderilemedi: {getattr(e, 'reason', e)}", True)}
    ms = int((time.time() - t0) * 1000)
    ok = code == expect and (not text or text in body)
    why = f"HTTP {code} (beklenen {expect})" + (f", “{text}” {'bulundu' if text in body else 'bulunamadı'}" if text else "")
    return {"result": "verified" if ok else "failed", "status": code, "ms": ms, "at": now, "note": why}


def record_verify(p: dict[str, Any], r: dict[str, Any]) -> None:
    if r["result"] in ("verified", "failed"):
        db.execute("UPDATE auth_profiles SET last_verify_at=?, last_verify_ok=?, last_verify_note=? WHERE id=?",
                   (r["at"], 1 if r["result"] == "verified" else 0, r["note"], p["id"]))
