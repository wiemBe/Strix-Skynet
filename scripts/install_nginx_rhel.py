#!/usr/bin/env python3
"""Same-host Nginx deployment for RHEL 9.4+ x86_64. Dry-run unless --apply.

Never starts/restarts Skynet, edits its environment, opens its backend port, or
touches application data/keys. An existing healthy loopback service is required.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import tempfile

MANAGED = "# Managed by Skynet install_nginx_rhel.py"
CONFIG = Path("/etc/nginx/conf.d/skynet.conf")
BACKUPS = Path("/etc/skynet/nginx-backups")


def address(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("Use an IPv4 address assigned to the server's LAN interface.")
    return str(ip)


def network(value):
    cidr = ipaddress.IPv4Network(value, strict=True)
    if cidr.prefixlen == 0:
        raise ValueError("Specify the client network; 0.0.0.0/0 is not a LAN allowlist.")
    return str(cidr)


def cert_path(value):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in Path(value).parts:
        raise ValueError("Certificate paths must be absolute, without spaces or Nginx metacharacters.")
    return value


def render(ip, cidrs, cert=None, key=None):
    ip = address(ip)
    cidrs = list(dict.fromkeys(network(c) for c in cidrs))
    if not cidrs:
        raise ValueError("At least one --allow-cidr is required.")
    if bool(cert) != bool(key):
        raise ValueError("Supply both --tls-cert and --tls-key.")
    if cert:
        cert, key = cert_path(cert), cert_path(key)
    acl = "\n".join(f"    allow {c};" for c in ["127.0.0.1/32", *cidrs]) + "\n    deny all;"
    # Overwrite, never append, client-supplied forwarding headers. No retries of
    # state-changing operations; no response cache or buffered live feed.
    proxy = """    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header Forwarded "";
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_next_upstream off;
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_send_timeout 60s;
    }"""
    text = MANAGED + "\n# Backend stays private; all UI, API, reports and downloads use this proxy.\n"
    # Do not log bodies, credentials, URL queries, headers, or full request lines.
    text += "log_format skynet_safe '$remote_addr [$time_local] $request_method $status $body_bytes_sent $request_time';\n"
    if cert:
        text += f"""server {{
    listen {ip}:80 default_server;
    server_name {ip};
    access_log /var/log/nginx/skynet-access.log skynet_safe;
    return 308 https://{ip}$request_uri;
}}
"""
    text += f"""server {{
    listen {ip}:{'443 ssl' if cert else '80'} default_server;
    server_name {ip};
    server_tokens off;
    client_max_body_size 10m;
    access_log /var/log/nginx/skynet-access.log skynet_safe;
{acl}
"""
    if cert:
        text += f"    ssl_certificate {cert};\n    ssl_certificate_key {key};\n    ssl_protocols TLSv1.2 TLSv1.3;\n"
    return text + proxy + "\n}\n"


def firewall_rules(ip, cidrs, tls=False):
    return [f'rule family="ipv4" source address="{network(c)}" destination address="{address(ip)}" '
            f'port port="{p}" protocol="tcp" accept' for c in dict.fromkeys(cidrs) for p in ([80, 443] if tls else [80])]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE).stdout.strip()


def env_values(text):
    """Read only deployment flags; never execute/source the secret-bearing env file."""
    wanted = {"SKYNET_HOST", "SKYNET_PORT", "SKYNET_COOKIE_SECURE"}
    result = {}
    for line in text.splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name in wanted:
            words = shlex.split(value, comments=True)
            if len(words) != 1:
                raise ValueError(f"Set {name} explicitly in /etc/skynet/skynet.env.")
            result[name] = words[0]
    return result


def preflight(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() != 0:
        raise ValueError("Apply on the RHEL 9.4+ x86_64 server as root, not on a workstation.")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    version = tuple(int(n) for n in release.get("VERSION_ID", "0").strip('"').split(".")[:2])
    if release.get("ID", "").strip('"') != "rhel" or not (9, 4) <= version < (10, 0):
        raise ValueError("This installer targets RHEL 9.4+ (9.x).")
    assigned = json.loads(output("ip", "-j", "-4", "address", "show"))
    interface = next((i["ifname"] for i in assigned for a in i.get("addr_info", []) if a.get("local") == args.ip), None)
    if not interface:
        raise ValueError("--ip is not assigned to this server. This installer never assigns an IP.")
    flags = env_values(Path("/etc/skynet/skynet.env").read_text())
    expected = {"SKYNET_HOST": "127.0.0.1", "SKYNET_PORT": "8787", "SKYNET_COOKIE_SECURE": "1" if args.tls_cert else "0"}
    if any(flags.get(k) != v for k, v in expected.items()):
        raise ValueError(f"Set {expected} in /etc/skynet/skynet.env and apply to Skynet before installing this proxy. "
                         "The installer does not restart scans or edit the environment.")
    run("systemctl", "is-active", "--quiet", "skynet.service")
    listeners = output("ss", "-H", "-ltn", "sport = :8787").splitlines()
    if not listeners or any(line.split()[3] != "127.0.0.1:8787" for line in listeners):
        raise ValueError("Skynet must actually listen only on 127.0.0.1:8787.")
    run("curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "10",
        "--output", "/dev/null", "http://127.0.0.1:8787/login")
    run("systemctl", "is-active", "--quiet", "firewalld.service")
    result = subprocess.run(["firewall-cmd", "--get-zone-of-interface", interface], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    actual_zone = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() != "no zone" else output("firewall-cmd", "--get-default-zone")
    if args.zone != actual_zone:
        raise ValueError(f"--zone must be {actual_zone!r}, the firewalld zone of interface {interface!r}.")
    if args.tls_cert:
        run("openssl", "x509", "-in", args.tls_cert, "-noout", "-checkend", "0")
        san = output("openssl", "x509", "-in", args.tls_cert, "-noout", "-ext", "subjectAltName")
        if args.ip not in re.findall(r"IP Address:([0-9.]+)(?:,|\s|$)", san):
            raise ValueError("TLS certificate must include the server IPv4 in subjectAltName.")
        key = Path(args.tls_key)
        if key.stat().st_uid != 0 or key.stat().st_mode & 0o077:
            raise ValueError("TLS key must be root-owned and mode 0600 (or stricter).")
    if CONFIG.is_symlink() or CONFIG.exists() and not CONFIG.read_text().startswith(MANAGED):
        raise ValueError(f"Refusing to overwrite unmanaged {CONFIG}. Preserve/review it first.")


def install(args, text):
    preflight(args)
    run("dnf", "install", "-y", "nginx", "policycoreutils")
    # RHEL's documented reverse-proxy SELinux boolean; SELinux stays enforcing.
    if output("getenforce") != "Disabled":
        run("setsebool", "-P", "httpd_can_network_connect", "on")
    # Refuse custom global configs that do not load our vhost. Do not replace them.
    dump = run("nginx", "-T", stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    if not re.search(r"include\s+/etc/nginx/conf\.d/\*\.conf\s*;", dump):
        raise ValueError("Nginx must include /etc/nginx/conf.d/*.conf in its http block.")
    old = CONFIG.read_bytes() if CONFIG.exists() else None
    backup = None
    if old is not None and old != text.encode():
        bdir = BACKUPS
        bdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = bdir / ("skynet-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + ".conf")
        backup.write_bytes(old)
        backup.chmod(0o600)
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".skynet-", dir=CONFIG.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(temp, 0o644)
        os.replace(temp, CONFIG)
        run("restorecon", str(CONFIG))
        validation = run("nginx", "-t", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if f'conflicting server name "{args.ip}"' in validation.stderr:
            raise ValueError("Another Nginx vhost already claims this IP; previous config restored.")
        # Reload only Nginx; Skynet's queue owner remains untouched.
        active = subprocess.run(["systemctl", "is-active", "--quiet", "nginx.service"]).returncode == 0
        run("systemctl", "enable", "nginx.service")
        run("systemctl", "reload" if active else "start", "nginx.service")
    except Exception:
        if old is None:
            CONFIG.unlink(missing_ok=True)
        else:
            CONFIG.write_bytes(old)
            CONFIG.chmod(0o644)
            run("restorecon", str(CONFIG))
        raise
    finally:
        Path(temp).unlink(missing_ok=True)
    for rule in firewall_rules(args.ip, args.allow_cidr, bool(args.tls_cert)):
        # Do not reload the whole firewall or widen access with --add-service=http.
        for persistent in (False, True):
            flags = ["--permanent"] if persistent else []
            run("firewall-cmd", *flags, "--zone", args.zone, "--add-rich-rule", rule)
    print(f"Installed: {'https' if args.tls_cert else 'http'}://{args.ip}")
    print("Verify from an allowed client. Backend 8787 is not opened; Skynet was not restarted.")
    if backup:
        print(f"Previous proxy configuration: {backup}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, type=address, help="IPv4 already assigned to this RHEL server")
    parser.add_argument("--allow-cidr", action="append", required=True, type=network, help="Allowed client IPv4 CIDR; repeatable")
    parser.add_argument("--zone", required=True, help="Existing firewalld zone on the client-facing interface")
    parser.add_argument("--tls-cert", type=cert_path)
    parser.add_argument("--tls-key", type=cert_path)
    parser.add_argument("--apply", action="store_true", help="Install packages/config, enable Nginx and add scoped firewall rules")
    args = parser.parse_args(argv)
    try:
        text = render(args.ip, args.allow_cidr, args.tls_cert, args.tls_key)
        if args.apply:
            install(args, text)
        else:
            print(text)
            print("# Dry-run only; no packages, service, firewall, data or keys changed.")
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Nginx setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
