"""Operator messages to running agents: bridge channel, control endpoint, Skynet API and audit, launcher choice.

Hermetic like test_features.py (temp SKYNET_DATA / key file set before skynet is imported). The checks that need
the real Strix coordinator, Strix agent session and openai-agents Runner run under the separate Strix runtime
(tests/runtime/*.py) and are skipped, visibly, when that runtime is not installed.
"""
import asyncio
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

if "SKYNET_DATA" not in os.environ:
    _TMP = tempfile.mkdtemp(prefix="skynet-test-")
    os.environ["SKYNET_DATA"] = str(Path(_TMP) / "data")
    os.environ["SKYNET_SECRET_KEY_FILE"] = str(Path(_TMP) / "keys" / "secret.key")
    os.environ.setdefault("SKYNET_PASSWORD", "unit-test-password")

from skynet import control, crypto, db, runner, strix_bridge as sb  # noqa: E402
from skynet.config import PROJECT_DIR, RUNTIME_DIR  # noqa: E402

RUNTIME_PY = PROJECT_DIR / ".strix-runtime" / "bin" / "python"


class FakeCoordinator:
    """The subset of strix.core.agents.AgentCoordinator the bridge reads (never writes)."""
    def __init__(self):
        self._lock = asyncio.Lock()
        self.statuses = {"root1": "running", "kid1": "waiting", "done1": "completed"}
        self.names = {"root1": "Root Agent", "kid1": "Recon", "done1": "Finished"}
        self.runtimes = {}
        self.budget_paused = False
        self.is_shutting_down = False

    async def reachability(self, aid):
        s = self.statuses.get(aid)
        return (s is not None and s not in sb.TERMINAL), s


class Bridge:
    """A real OperatorChannel + control HTTP server on a background event loop (as inside a Strix process)."""
    def __init__(self, state_path=None):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.coord = FakeCoordinator()
        self.channel = sb.OperatorChannel(state_path)
        self.loop.call_soon_threadsafe(self.channel.attach, self.coord, self.loop)
        self.token = "k" * 43
        self.server = sb.make_server(self.channel, self.token)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port

    def post(self, body, token=None, host="127.0.0.1", raw=None):
        data = raw if raw is not None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/messages", data=data, headers={
            "Authorization": f"Bearer {token or self.token}", "Host": host, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        _wait(lambda: not self.loop.is_running())
        self.loop.close()


class TestBridgeChannel(unittest.TestCase):
    def setUp(self):
        self.b = Bridge()

    def tearDown(self):
        self.b.close()

    def msg(self, rid="req-00000001", aid="root1", content="Focus on /api/orders"):
        return {"request_id": rid, "agent_id": aid, "content": content}

    def test_auth_and_host_checks(self):
        self.assertEqual(self.b.post(self.msg(), token="wrong")[0], 401)
        self.assertEqual(self.b.post(self.msg(), host="localhost")[0], 401)   # DNS-rebinding style Host
        self.assertEqual(self.b.post(None, raw=b"x" * (sb.MAX_BODY + 1))[0], 413)
        self.assertEqual(self.b.post(self.msg(rid="short"))[0], 400)
        self.assertEqual(self.b.post(self.msg(content="   "))[0], 400)
        self.assertEqual(self.b.post(self.msg(content="x" * (sb.MAX_CONTENT + 1)))[0], 400)

    def test_accept_dedupe_conflict(self):
        code, r = self.b.post(self.msg())
        self.assertEqual((code, r["ok"], r["state"], r["duplicate"]), (200, True, "queued", False))
        code, r = self.b.post(self.msg())
        self.assertTrue(r["duplicate"])
        self.assertEqual(len(self.b.channel.messages), 1)
        code, r = self.b.post(self.msg(content="different"))
        self.assertEqual((r["ok"], r["code"]), (False, "conflict"))

    def test_refusals(self):
        self.assertEqual(self.b.post(self.msg(aid="nobody"))[1]["code"], "unknown_agent")
        self.assertEqual(self.b.post(self.msg(aid="done1"))[1]["code"], "agent_not_active")
        self.b.coord.budget_paused = True
        self.assertEqual(self.b.post(self.msg(rid="req-00000002"))[1]["code"], "budget_paused")
        self.b.coord.budget_paused = False
        for i in range(sb.MAX_QUEUED_PER_AGENT):
            self.assertTrue(self.b.post(self.msg(rid=f"req-1000000{i}", aid="kid1", content=f"m{i}"))[1]["ok"])
        self.assertEqual(self.b.post(self.msg(rid="req-20000000", aid="kid1"))[1]["code"], "queue_full")
        self.b.coord.is_shutting_down = True
        self.assertEqual(self.b.post(self.msg(rid="req-30000000"))[1]["code"], "scan_ending")

    def test_expiry_when_agent_ends_and_on_close(self):
        self.b.post(self.msg())
        self.b.coord.statuses["root1"] = "completed"
        asyncio.run_coroutine_threadsafe(self.b.channel.agents(), self.b.loop).result(5)
        self.assertEqual(self.b.channel.messages["req-00000001"].state, "expired")
        self.b.coord.statuses["kid1"] = "waiting"
        self.b.post(self.msg(rid="req-00000005", aid="kid1"))
        self.b.loop.call_soon_threadsafe(self.b.channel.close)
        self.assertTrue(_wait(lambda: self.b.channel.messages["req-00000005"].state == "expired"))


def _wait(cond, timeout=5.0):
    import time
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class TestMessagingAPI(unittest.TestCase):
    def setUp(self):
        from skynet import main, auth
        from test_features import TestAPI
        self.M, self.auth = main, auth
        db.init()
        self.request = TestAPI.request.__get__(self)
        self.tid = db.insert("targets", {"name": "Msg fixture", "base_url": "http://127.0.0.1:8899", "environment": "test"})
        self.secret = "Sup3rSecretValue!"
        self.sid = db.insert("scans", {"target_id": self.tid, "name": "Msg fixture", "status": "running", "pid": os.getpid(),
                                       "control_mode": "bridge", "trigger": "manual",
                                       "redact_enc": crypto.vault_encrypt(json.dumps([self.secret]))})
        self.b = Bridge(str(control.state_path(self.sid)))
        self.rid = f"rid-{self.sid}-{os.urandom(4).hex()}"     # request IDs are unique across all scans
        self.write_manifest()

    def tearDown(self):
        self.b.close()
        runner._cleanup_runtime(self.sid)

    def write_manifest(self, **over):
        m = {"protocol": 1, "pid": os.getpid(), "port": self.b.port, "token": self.b.token, **over}
        sb._write_private_json(str(control.manifest_path(self.sid)), m)

    def send(self, content="Prioritise the order endpoints", rid=None, agent="root1", **kw):
        rid = rid or self.rid
        return self.request(f"/api/scans/{self.sid}/messages", "POST",
                            {"agent_id": agent, "content": content, "request_id": rid}, **kw)

    def test_auth_and_csrf(self):
        self.assertEqual(self.send(session=False)[0], 401)
        self.assertEqual(self.send(csrf=False)[0], 403)
        self.assertEqual(self.request(f"/api/scans/{self.sid}/messages", session=False)[0], 401)
        self.assertFalse(db.q("SELECT id FROM agent_messages WHERE scan_id=?", (self.sid,)))

    def test_send_is_encrypted_idempotent_and_conflicts(self):
        code, r = self.send()
        self.assertEqual((code, r["state"]), (200, "queued"))
        row = db.q1("SELECT * FROM agent_messages WHERE scan_id=?", (self.sid,))
        self.assertNotIn("order endpoints", row["content_enc"])
        self.assertEqual(crypto.vault_decrypt(row["content_enc"]), "Prioritise the order endpoints")
        self.assertEqual(self.send()[1]["id"], r["id"])                    # retry: same row
        self.assertEqual(len(self.b.channel.messages), 1)                   # and no second copy in Strix
        self.assertEqual(self.send(content="something else")[0], 409)
        code, m = self.request(f"/api/scans/{self.sid}/messages")
        self.assertTrue(m["available"])
        self.assertEqual({a["id"] for a in m["agents"] if a["accepting"]}, {"root1", "kid1"})
        self.assertEqual(m["messages"][0]["state"], "queued")

    def test_secrets_are_masked_in_history(self):
        self.send(content=f"use token {self.secret} for the API")
        _, m = self.request(f"/api/scans/{self.sid}/messages")
        self.assertNotIn(self.secret, json.dumps(m))

    def test_rejections_are_recorded(self):
        code, r = self.send(agent="done1")
        self.assertEqual((code, r["state"]), (200, "rejected"))
        self.assertIn("completed", r["reason"])
        self.assertEqual(self.send(content="", rid="22222222-bbbb")[0], 400)
        self.assertEqual(self.send(rid="bad id")[0], 400)

    def test_manifest_validation(self):
        self.write_manifest(pid=os.getpid() + 1)            # a manifest left by another process
        code, r = self.send()
        self.assertEqual(code, 409)
        self.assertFalse(db.q1("SELECT id FROM agent_messages WHERE request_id=?", (self.rid,)))
        self.write_manifest()
        os.chmod(control.manifest_path(self.sid), 0o644)    # unsafe permissions are not trusted
        self.assertEqual(self.send(rid="44444444-dddd")[0], 409)
        db.update("scans", self.sid, {"control_mode": ""})
        _, m = self.request(f"/api/scans/{self.sid}/messages")
        self.assertFalse(m["available"])
        db.update("scans", self.sid, {"control_mode": "bridge", "status": "completed"})
        self.assertEqual(self.send(rid="55555555-eeee")[0], 409)

    def test_timeout_is_unknown_and_recheck_never_duplicates(self):
        real = control._call
        def lost(m, method, path, body=None, timeout=10.0):
            real(m, method, path, body, timeout)       # the bridge accepts it...
            raise socket.timeout("timed out")           # ...but the answer never arrives
        control._call = lost
        try:
            code, r = self.send()
        finally:
            control._call = real
        self.assertEqual((code, r["state"]), (200, "unknown"))
        code, r = self.request(f"/api/scans/{self.sid}/messages/{r['id']}/recheck", "POST", {})
        self.assertEqual((code, r["state"]), (200, "queued"))
        self.assertEqual(len(self.b.channel.messages), 1)

    def test_retry_without_endpoint_keeps_unconfirmed(self):
        real = control._call
        def lost(*a, **k):
            raise socket.timeout("timed out")
        control._call = lost
        try:
            _, r = self.send()
        finally:
            control._call = real
        self.assertEqual(r["state"], "unknown")
        control.manifest_path(self.sid).unlink()                         # endpoint gone (e.g. scan ending)
        self.assertEqual(self.request(f"/api/scans/{self.sid}/messages/{r['id']}/recheck", "POST", {})[0], 409)
        self.assertEqual(db.get("agent_messages", r["id"])["state"], "unknown")   # not a false "rejected"

    def test_state_sync_and_finalize(self):
        _, a = self.send(rid=self.rid + "-a")
        _, b = self.send(rid=self.rid + "-b", content="second")
        rec = self.b.channel.messages[self.rid + "-a"]
        rec.state, rec.delivered_at = "delivered", db.now_iso()
        self.b.channel._persist()
        self.assertEqual(stat.S_IMODE(control.state_path(self.sid).stat().st_mode), 0o600)
        _, m = self.request(f"/api/scans/{self.sid}/messages")
        states = {x["request_id"]: x["state"] for x in m["messages"]}
        self.assertEqual(states, {self.rid + "-a": "delivered", self.rid + "-b": "queued"})
        control.finalize(db.get_scan(self.sid))
        self.assertEqual(db.get("agent_messages", b["id"])["state"], "expired")
        self.assertEqual(db.get("agent_messages", a["id"])["state"], "delivered")   # never moves backwards

    def test_scan_delete_removes_audit_rows(self):
        self.send()
        db.update("scans", self.sid, {"status": "completed"})
        self.assertEqual(self.request(f"/api/scans/{self.sid}", "DELETE")[0], 200)
        self.assertFalse(db.q("SELECT id FROM agent_messages WHERE scan_id=?", (self.sid,)))


class TestLauncherChoice(unittest.TestCase):
    def fake_runtime(self, version):
        d = Path(tempfile.mkdtemp())
        p = d / "python"
        p.write_text(f"#!/bin/sh\necho {version}\n")
        p.chmod(0o700)
        return p

    def status(self, version, binary="strix 1.7.0", messaging="1"):
        old = os.environ.get("SKYNET_STRIX_RUNTIME")
        os.environ["SKYNET_STRIX_RUNTIME"] = str(self.fake_runtime(version)) if version else "/nonexistent/python"
        try:
            return control.bridge_status({"agent_messaging": messaging}, binary)
        finally:
            if old is None:
                os.environ.pop("SKYNET_STRIX_RUNTIME")
            else:
                os.environ["SKYNET_STRIX_RUNTIME"] = old

    def test_scans_never_stop_on_budget_time_or_default_turns(self):
        self.assertEqual(runner.limit_args({}), [f"--max-turns={runner.UNLIMITED_TURNS}"])
        self.assertEqual(runner.limit_args({"max_turns": None, "max_budget": 0.4}),   # legacy budget ignored
                         [f"--max-turns={runner.UNLIMITED_TURNS}"])
        self.assertEqual(runner.limit_args({"max_turns": 40}), ["--max-turns=40"])  # an explicit limit is kept
        self.assertGreater(runner.UNLIMITED_TURNS, 500)                             # Strix's own default

    def test_messaging_is_opt_in(self):
        self.assertEqual(db.DEFAULT_SETTINGS["agent_messaging"], "0")

    def test_versions_must_match(self):
        self.assertTrue(self.status("1.7.0")["available"])
        r = self.status("1.8.0")
        self.assertFalse(r["available"])
        self.assertIn("does not match", r["reason"])
        self.assertFalse(self.status(None)["available"])
        self.assertFalse(self.status("1.7.0", messaging="0")["available"])

    def test_bridge_command_clears_stale_files(self):
        sid = 990001
        control.manifest_path(sid).write_text("{}")
        cmd, env = control.bridge_command(sid, ["--non-interactive", "--target=http://127.0.0.1:8899"])
        self.assertFalse(control.manifest_path(sid).exists())
        self.assertEqual(cmd[1:4], ["-I", "-u", str(control.BRIDGE)])
        self.assertEqual(cmd[-1], "--target=http://127.0.0.1:8899")
        self.assertEqual(env["SKYNET_CONTROL_MANIFEST"], str(control.manifest_path(sid)))

    def test_cleanup_does_not_touch_other_scans(self):
        keep = RUNTIME_DIR / "scan_12_instruction.md"
        gone = RUNTIME_DIR / "scan_1_instruction.md"
        secret = RUNTIME_DIR / "scan_1_auth_api-header.json"          # vault.render's naming
        for p in (keep, gone, secret, RUNTIME_DIR / "scan_1.json", RUNTIME_DIR / "scan_1_control.json"):
            p.write_text("x")
        runner._cleanup_runtime(1)
        self.assertTrue(keep.exists())
        self.assertFalse(any(p.exists() for p in (gone, secret, RUNTIME_DIR / "scan_1.json",
                                                    RUNTIME_DIR / "scan_1_control.json")))
        keep.unlink()

    def test_migration_4_applied(self):
        db.init()
        self.assertGreaterEqual(db.schema_version(), 4)
        cols = {r["name"] for r in db.q("PRAGMA table_info(scans)")}
        self.assertTrue({"control_mode", "control_note"} <= cols)


@unittest.skipUnless(RUNTIME_PY.is_file(), f"Strix runtime not installed at {RUNTIME_PY}; native bridge checks skipped")
class TestNativeStrixRuntime(unittest.TestCase):
    """Real AgentCoordinator, real Strix agent session, real openai-agents Runner (scripted model, no provider)."""
    def run_check(self, name):
        r = subprocess.run([str(RUNTIME_PY), "-I", str(Path(__file__).parent / "runtime" / name)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_delivery_through_real_coordinator_and_session(self):
        o = self.run_check("bridge_native_check.py")
        # status is never changed and the native mailbox is never used
        self.assertEqual((o["status_before"], o["status_after_run"], o["pending_native_mailbox"]), ("running", "running", 0))
        h = o["http"]
        self.assertEqual(h["unauth"][0], 401)
        self.assertEqual(h["first"][1]["state"], "queued")
        self.assertTrue(h["dup"][1]["duplicate"])
        self.assertEqual(h["conflict"][1]["code"], "conflict")
        self.assertEqual(h["terminal"][1]["code"], "agent_not_active")
        self.assertEqual(h["unknown"][1]["code"], "unknown_agent")
        marker = "[Operator message via Skynet console | id=req-00000001]"
        calls = o["first_run_calls"]
        self.assertFalse(any(marker in str(x) for x in calls[0]))
        for later in calls[1:]:                                           # every later call of the same run sees it,
            self.assertEqual(sum(marker in str(x) for x in later), 1)    # exactly once, right after the tool output
            self.assertEqual(later[2:4], ["function_call_output", later[3]])
        self.assertEqual(sum(marker in str(x) for x in o["session"]), 1)  # persisted once, in order
        self.assertEqual(o["session"][3][:len(marker)], marker)
        self.assertEqual(sum(marker in str(x) for x in o["second_run_calls"][0]), 1)   # resume: from history only
        self.assertEqual(o["state_file"]["messages"][0]["state"], "delivered")
        self.assertNotIn("Focus on", json.dumps(o["state_file"]))        # state file never holds content
        self.assertEqual(o["state_mode"], "0o600")
        self.assertEqual(o["late_state"], "expired")
        self.assertTrue(o["fault_input_unchanged"])                       # a session write fault never fails
        self.assertEqual(o["fault_state"], "queued")                       # the call and is never "delivered"
        self.assertTrue(o["noop_identity"])                                # no message: input passed through as-is

    def test_install_attaches_to_installed_strix(self):
        o = self.run_check("bridge_install_check.py")
        self.assertTrue(o["native_signature_has_coordinator"])
        self.assertTrue(o["installed"] and o["filter_attached"])
        self.assertEqual(o["seen"]["coordinator"], "AgentCoordinator")
        self.assertTrue(o["seen"]["pid_matches"])
        self.assertEqual(o["seen"]["manifest_mode"], "0o600")
        self.assertEqual(o["seen"]["manifest"]["strix_version"], "1.7.0")
        self.assertTrue(o["manifest_removed"] and o["channel_closed"])

    def test_cli_passthrough(self):
        r = subprocess.run([str(RUNTIME_PY), "-I", str(control.BRIDGE), "--version"], capture_output=True, text=True,
                           timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-1000:])
        self.assertIn("operator messaging attached", r.stdout)
        self.assertIn("strix 1.7.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
