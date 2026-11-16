#!/usr/bin/env python3
"""Disposable same-container Nginx + Skynet integration test. No real scans.

Requires Linux, Nginx/OpenSSL, an installed app environment and --disposable-qa.
Only run in a dedicated QA container; it binds container ports 80/443/8787.
"""
import argparse
from contextlib import asynccontextmanager
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from install_nginx_rhel import render


def app_process(root, secure):
    os.environ.pop("SKYNET_SECRET_KEY", None)
    os.environ.update(SKYNET_LOAD_DOTENV="0", SKYNET_DATA=str(root/"data"), SKYNET_SECRET_KEY_FILE=str(root/"keys/key"),
                      SKYNET_COOKIE_SECURE="1" if secure else "0", SKYNET_PASSWORD="nginx-qa-fixture-password")
    from skynet import auth, db, main
    import uvicorn
    @asynccontextmanager
    async def fixture(_):
        db.init()
        auth.bootstrap()
        yield
    main.app.router.lifespan_context = fixture
    uvicorn.run(main.app, host="127.0.0.1", port=8787, access_log=False, workers=1,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1")


def request(ip, port, path, method="GET", body=None, headers=None, ca=None, source=None):
    opts = {"timeout": 5}
    if source:
        opts["source_address"] = (source, 0)
    conn = http.client.HTTPSConnection(ip, port, context=ssl.create_default_context(cafile=ca), **opts) if ca else http.client.HTTPConnection(ip, port, **opts)
    try:
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json", **(headers or {})})
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


def ready(ip, port, ca=None):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        try:
            if request(ip, port, "/login", ca=ca)[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.1)
    raise AssertionError(f"QA server not ready at {ip}:{port}")


def stop(process):
    process.terminate()
    try:
        process.wait(8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def check_mode(root, ip, secure):
    ca = None
    if secure:
        ca, key = str(root/"cert.pem"), str(root/"cert.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=Skynet disposable QA", "-addext", f"subjectAltName=IP:{ip}",
                        "-keyout", key, "-out", ca], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conf = root/("https.conf" if secure else "http.conf")
    conf.write_text(render(ip, [ip+"/32"], ca, key if secure else None))
    config = root/"nginx.conf"
    config.write_text(f'pid {root}/nginx.pid;\nerror_log {root}/nginx-error.log;\nevents {{}}\nhttp {{ include /etc/nginx/mime.types; include {conf}; }}\n')
    subprocess.run(["nginx", "-t", "-c", str(config)], check=True)
    app_log = open(root/("app-tls.log" if secure else "app-http.log"), "w")
    app = subprocess.Popen([sys.executable, __file__, "--app", str(root), str(int(secure))], stdout=app_log, stderr=subprocess.STDOUT)
    proxy = None
    try:
        ready("127.0.0.1", 8787)
        proxy = subprocess.Popen(["nginx", "-c", str(config), "-g", "daemon off;"], stdout=subprocess.DEVNULL)
        port = 443 if secure else 80
        ready(ip, port, ca)
        assert request(ip, port, "/api/me", ca=ca)[0] == 401
        assert request(ip, port, "/login", ca=ca, source="127.0.0.2")[0] == 403
        st, headers, _ = request(ip, port, "/api/login", "POST", {"username": "admin", "password": "nginx-qa-fixture-password"},
                                  {"X-Forwarded-For": "198.51.100.99", "X-Forwarded-Proto": "https"}, ca)
        assert st == 200
        cookies = SimpleCookie(headers["set-cookie"])
        cookie = next(iter(cookies.values()))
        assert cookie["httponly"] and cookie["samesite"].lower() == "strict"
        assert bool(cookie["secure"]) == secure
        credential = {"Cookie": f"{cookie.key}={cookie.value}"}
        st, _, me = request(ip, port, "/api/me", headers=credential, ca=ca)
        assert st == 200 and json.loads(me)["role"] == "admin"
        assert request(ip, port, "/static/app.js", headers=credential, ca=ca)[0] == 200
        payload = {"name": "Nginx disposable QA target", "environment": "test", "base_url": "http://127.0.0.1:8899"}
        assert request(ip, port, "/api/targets", "POST", payload, credential, ca)[0] == 403
        assert request(ip, port, "/api/targets", "POST", payload, {**credential, "X-Requested-With": "skynet"}, ca)[0] == 200
        with sqlite3.connect(root/"data/skynet.db") as db:
            client_ip = db.execute("SELECT ip FROM audit_log WHERE action='auth.login' ORDER BY id DESC LIMIT 1").fetchone()[0]
        assert client_ip == ip, (client_ip, ip)
        # A direct request from outside the single trusted loopback address cannot spoof IP.
        assert request("127.0.0.1", 8787, "/api/login", "POST", {"username": "admin", "password": "nginx-qa-fixture-password"},
                       {"X-Forwarded-For": "198.51.100.99"}, source="127.0.0.2")[0] == 200
        with sqlite3.connect(root/"data/skynet.db") as db:
            assert db.execute("SELECT ip FROM audit_log WHERE action='auth.login' ORDER BY id DESC LIMIT 1").fetchone()[0] == "127.0.0.2"
        try:
            with socket.create_connection((ip, 8787), timeout=1):
                raise AssertionError("Backend is exposed on the container network")
        except OSError:
            pass
        marker = "qa-query-must-not-be-logged-870ac"
        request(ip, port, "/login?token="+marker, ca=ca)
        assert marker not in Path("/var/log/nginx/skynet-access.log").read_text()
        if secure:
            st, h, _ = request(ip, 80, "/login?test=1", headers={"Host": "attacker.invalid"})
            assert st == 308 and h["location"] == f"https://{ip}/login?test=1"
        return {"transport": "https" if secure else "http", "nginx_config_test": True, "login_and_session": True,
                "secure_cookie": bool(cookie["secure"]), "csrf_enforced": True, "allowed_client_only": True,
                "static_assets": True, "real_client_ip": True, "spoofed_forwarding_header_rejected": True,
                "backend_not_network_exposed": True, "query_not_in_access_log": True,
                "tls_san_and_ca_verified": secure, "http_to_https_redirect": secure}
    finally:
        if proxy:
            stop(proxy)
        stop(app)
        app_log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-qa", action="store_true")
    args = parser.parse_args()
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if not args.disposable_qa or platform.system() != "Linux" or not container:
        parser.error("Use --disposable-qa inside a dedicated Linux QA container.")
    ip = socket.gethostbyname(socket.gethostname())
    with tempfile.TemporaryDirectory(prefix="skynet-nginx-qa-") as tmp:
        root = Path(tmp)
        result = {"platform": platform.machine(), "nginx": subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr.strip(),
                  "checks": [check_mode(root, ip, False), check_mode(root, ip, True)],
                  "scope": "Disposable UBI9 container; no production data, host keys, Docker socket, worker, scheduler, Strix or provider call"}
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--app":
        app_process(Path(sys.argv[2]), bool(int(sys.argv[3])))
    else:
        main()
