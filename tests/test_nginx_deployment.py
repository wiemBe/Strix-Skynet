"""Same-host reverse proxy safety checks; no real host configuration is changed."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_nginx_rhel", ROOT / "scripts/install_nginx_rhel.py")
nginx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nginx)


class TestNginxDeployment(unittest.TestCase):
    def test_invalid_addresses_networks_and_config_injection_are_rejected(self):
        for ip in ("0.0.0.0", "127.0.0.1", "::1", "224.0.0.1", "10.1.1.1; include /tmp/x;"):
            with self.assertRaises(ValueError):
                nginx.render(ip, ["10.0.0.0/8"])
        for cidr in ("0.0.0.0/0", "10.1.1.7/24", "::/0", "10.0.0.0/8; allow all;"):
            with self.assertRaises(ValueError):
                nginx.render("10.90.10.10", [cidr])
        for path in ("relative.crt", "/etc/a;include.conf", "/etc/a\nssl_certificate bad", "/etc/../tmp/a"):
            with self.assertRaises(ValueError):
                nginx.render("10.90.10.10", ["10.90.10.0/24"], path, "/etc/key.pem")
        with self.assertRaises(ValueError):
            nginx.render("10.90.10.10", [])
        with self.assertRaises(ValueError):
            nginx.render("10.90.10.10", ["10.90.10.0/24"], "/etc/cert.pem")

    def test_http_is_bound_to_the_selected_ip_and_replaces_forwarding_headers(self):
        config = nginx.render("10.90.10.10", ["10.90.10.0/24"])
        self.assertIn("listen 10.90.10.10:80 default_server;", config)
        self.assertIn("proxy_pass http://127.0.0.1:8787;", config)
        self.assertIn("allow 10.90.10.0/24;", config)
        self.assertIn("deny all;", config)
        self.assertNotIn("$proxy_add_x_forwarded_for", config)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertIn("proxy_buffering off;", config)
        self.assertIn("proxy_next_upstream off;", config)
        self.assertNotIn("$request_uri", config)
        self.assertNotIn("$request'", config)
        self.assertNotIn("root /", config)

    def test_tls_redirect_is_to_the_configured_address_not_client_host(self):
        config = nginx.render("10.90.10.10", ["10.90.10.0/24"], "/etc/cert.pem", "/etc/key.pem")
        self.assertIn("listen 10.90.10.10:443 ssl default_server;", config)
        self.assertIn("return 308 https://10.90.10.10$request_uri;", config)
        self.assertNotIn("https://$host", config)
        self.assertIn("ssl_certificate_key /etc/key.pem;", config)

    def test_firewall_rules_only_open_proxy_ports_for_selected_client_and_destination(self):
        rules = nginx.firewall_rules("10.90.10.10", ["10.90.10.0/24", "10.90.10.0/24"], True)
        self.assertEqual(len(rules), 2)
        for rule in rules:
            self.assertIn('source address="10.90.10.0/24"', rule)
            self.assertIn('destination address="10.90.10.10"', rule)
            self.assertNotIn("8787", rule)

    def test_dry_run_does_not_inspect_or_change_host(self):
        with mock.patch.object(nginx, "install") as install, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(nginx.main(["--ip", "10.90.10.10", "--allow-cidr", "10.90.10.0/24", "--zone", "internal"]), 0)
        install.assert_not_called()
        self.assertIn("Dry-run only", out.getvalue())

    def test_environment_is_parsed_as_data_without_expansion_or_printing_secrets(self):
        flags = nginx.env_values('SKYNET_HOST="127.0.0.1"\nSKYNET_PORT=8787\nSKYNET_PASSWORD=$(do-not-run)\nSKYNET_COOKIE_SECURE=1\n')
        self.assertEqual(flags, {"SKYNET_HOST": "127.0.0.1", "SKYNET_PORT": "8787", "SKYNET_COOKIE_SECURE": "1"})

    def test_invalid_nginx_config_restores_previous_managed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "skynet.conf"
            old = nginx.MANAGED + "\n# previous\n"
            conf.write_text(old)
            def invoke(*args, **kwargs):
                if args == ("nginx", "-T"):
                    return SimpleNamespace(stdout="include /etc/nginx/conf.d/*.conf;")
                if args == ("nginx", "-t"):
                    raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(stdout="")
            with mock.patch.object(nginx, "CONFIG", conf), mock.patch.object(nginx, "BACKUPS", Path(tmp)/"backups"), mock.patch.object(nginx, "preflight"), \
                    mock.patch.object(nginx, "output", return_value="Disabled"), mock.patch.object(nginx, "run", side_effect=invoke) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    nginx.install(SimpleNamespace(), nginx.MANAGED + "\ninvalid directive;\n")
            self.assertEqual(conf.read_text(), old)
            self.assertEqual(next((Path(tmp)/"backups").glob("*.conf")).read_text(), old)
            self.assertFalse(any(c.args[:2] == ("systemctl", "reload") or c.args[0] == "firewall-cmd" for c in run.call_args_list))

    def test_preflight_cannot_apply_to_a_workstation(self):
        with mock.patch.object(nginx.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "RHEL"):
                nginx.preflight(SimpleNamespace())


if __name__ == "__main__":
    unittest.main()
