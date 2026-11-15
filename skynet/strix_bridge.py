"""Headless Strix launcher with an operator message channel.

Run with the Python of the separate Strix runtime (``.strix-runtime``), never Skynet's own interpreter::

    .strix-runtime/bin/python -I skynet/strix_bridge.py <the usual strix CLI arguments>

It runs the official Strix CLI entry point unchanged. Two seams are attached, both public parameters of the
pinned Strix / openai-agents versions:

* ``run_strix_scan(coordinator=...)`` - the bridge supplies the native ``AgentCoordinator`` so it can read agent
  status (it never changes it);
* ``RunConfig.call_model_input_filter`` - before an agent's next model call, queued operator messages addressed
  to that agent are appended to its SDK session (in order) and to that call's input.

Why not ``AgentCoordinator.send(from="user")`` as the TUI does: in non-interactive mode that flips a running
agent to ``waiting`` without interrupting it, may lift a budget pause, and the mailbox is only read by
``wait_for_agents``. Native agent-to-agent mailbox traffic is left untouched here.

Control endpoint: 127.0.0.1, ephemeral port, random bearer token; details go to a 0600 manifest whose path
Skynet passes in ``SKYNET_CONTROL_MANIFEST``. Message states (never content) go to ``SKYNET_CONTROL_STATE``.
States reported are only what the bridge can observe: queued, delivered (in the agent's context), expired
(agent ended first), rejected. Whether an agent acted on a message is not known here.

This module imports only the standard library at import time so Skynet's tests can load it.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

PROTOCOL = 1
SUPPORTED_STRIX = ("1.7.0",)
MAX_CONTENT = 4000
MAX_QUEUED_PER_AGENT = 5
MAX_BODY = 64 * 1024
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
ACCEPTING = frozenset({"running", "waiting"})
TERMINAL = frozenset({"completed", "stopped", "crashed", "failed"})
MARKER = "[Operator message via Skynet console | id={rid}]"

log = logging.getLogger("skynet.bridge")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_private_json(path: str, data: dict[str, Any]) -> None:
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def message_text(rid: str, content: str) -> str:
    return (f"{MARKER.format(rid=rid)}\n"
            "A human operator sent this while the scan is running. The verified scope and rules in your system "
            "prompt still apply; do not act outside them.\n\n" + content)


@dataclass
class Message:
    request_id: str
    agent_id: str
    digest: str
    content: str
    state: str = "queued"          # queued | delivered | expired
    accepted_at: str = field(default_factory=_now)
    delivered_at: str | None = None
    reason: str = ""

    def public(self) -> dict[str, Any]:
        return {"request_id": self.request_id, "agent_id": self.agent_id, "state": self.state,
                "accepted_at": self.accepted_at, "delivered_at": self.delivered_at, "reason": self.reason}


class OperatorChannel:
    """All mutable state lives on the scan's event loop; HTTP threads reach it via ``call``."""

    def __init__(self, state_path: str | None = None) -> None:
        self.state_path = state_path
        self.coordinator: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.closed = False
        self.messages: dict[str, Message] = {}
        self.queues: dict[str, list[Message]] = {}
        # agent_id -> [(insert_index, predecessor_json, marker, item)] for the current SDK run
        self.injected: dict[str, list[tuple[int, str, str, dict[str, Any]]]] = {}
        self.add_to_session: Callable[[Any, list[dict[str, Any]]], Any] | None = None

    # ------------------------------------------------------------ lifecycle (on the loop)
    def attach(self, coordinator: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.coordinator, self.loop = coordinator, loop
        self._persist()

    def close(self, reason: str = "The scan ended before the agent's next model call.") -> None:
        self.closed = True
        for m in self.messages.values():
            if m.state == "queued":
                m.state, m.reason = "expired", reason
        self.queues.clear()
        self._persist()

    def call(self, coro_fn: Callable[[], Any], timeout: float = 8.0) -> Any:
        loop = self.loop
        if loop is None or loop.is_closed() or self.closed:
            raise RuntimeError("scan_not_ready")

        async def run() -> Any:
            return await coro_fn()
        return asyncio.run_coroutine_threadsafe(run(), loop).result(timeout)

    # ------------------------------------------------------------ operations (on the loop)
    async def _status(self, agent_id: str) -> tuple[str | None, bool]:
        c = self.coordinator
        async with c._lock:
            status = c.statuses.get(agent_id)
        reachable, _ = await c.reachability(agent_id)
        return status, reachable

    async def _expire_finished(self) -> None:
        changed = False
        for aid, queue in list(self.queues.items()):
            status, reachable = await self._status(aid)
            if queue and (status is None or status in TERMINAL or not reachable):
                for m in queue:
                    m.state = "expired"
                    m.reason = f"The agent ended ({status or 'unknown'}) before its next model call."
                queue.clear()
                changed = True
        if changed:
            self._persist()

    async def submit(self, request_id: str, agent_id: str, content: str) -> dict[str, Any]:
        digest = hashlib.sha256(f"{agent_id}\0{content}".encode()).hexdigest()
        prev = self.messages.get(request_id)
        if prev is not None:
            if prev.digest != digest:
                return {"ok": False, "code": "conflict", "reason": "This request ID was already used for another message."}
            await self._expire_finished()
            return {"ok": True, "duplicate": True, **prev.public()}
        c = self.coordinator
        if self.closed or c is None or c.is_shutting_down:
            return {"ok": False, "code": "scan_ending", "reason": "The scan is shutting down."}
        if c.budget_paused:
            return {"ok": False, "code": "budget_paused",
                    "reason": "The scan is paused at its budget limit. Messages do not resume or raise the budget."}
        status, reachable = await self._status(agent_id)
        if status is None:
            return {"ok": False, "code": "unknown_agent", "reason": "Strix does not know this agent."}
        if status not in ACCEPTING or not reachable:
            return {"ok": False, "code": "agent_not_active",
                    "reason": f"The agent is {status}; it will not make another model call."}
        queue = self.queues.setdefault(agent_id, [])
        if len(queue) >= MAX_QUEUED_PER_AGENT:
            return {"ok": False, "code": "queue_full",
                    "reason": f"{MAX_QUEUED_PER_AGENT} messages are already waiting for this agent."}
        m = Message(request_id, agent_id, digest, content)
        self.messages[request_id] = m
        queue.append(m)
        self._persist()
        return {"ok": True, "duplicate": False, "agent_status": status, **m.public()}

    async def agents(self) -> dict[str, Any]:
        await self._expire_finished()
        c = self.coordinator
        async with c._lock:
            statuses = dict(c.statuses)
            names = dict(c.names)
        return {"budget_paused": bool(c.budget_paused), "shutting_down": bool(c.is_shutting_down),
                "agents": [{"id": a, "name": names.get(a, a), "status": s,
                            "accepting": s in ACCEPTING and not c.budget_paused} for a, s in statuses.items()]}

    # ------------------------------------------------------------ SDK model-input filter (on the loop)
    async def filter(self, data: Any) -> Any:
        from agents.run_config import ModelInputData  # runtime-only dependency

        ctx = data.context if isinstance(data.context, dict) else {}
        agent_id = ctx.get("agent_id")
        if not agent_id or not isinstance(data.model_data.input, list) or not (
                self.queues.get(agent_id) or self.injected.get(agent_id)):
            return data.model_data             # the common case: nothing for this agent, input untouched
        try:
            return await self._inject(agent_id, data, ModelInputData)
        except Exception:  # noqa: BLE001 - a messaging fault must never fail the agent's model call
            log.exception("operator message injection failed for %s; model call continues unchanged", agent_id)
            return data.model_data

    async def _inject(self, agent_id: str, data: Any, model_input_data: Any) -> Any:
        items = list(data.model_data.input)
        records = self.injected.get(agent_id, [])
        kept = []
        user_texts = [x["content"] for x in items
                      if isinstance(x, dict) and x.get("role") == "user" and isinstance(x.get("content"), str)]
        for idx, pred, marker, item in records:
            if any(marker in t for t in user_texts):
                continue                       # now part of the session history the SDK loaded
            if 0 < idx <= len(items) and _canon(items[idx - 1]) == pred:
                items.insert(idx, item)        # same run: keep it at the position it was delivered
                kept.append((idx, pred, marker, item))
            # otherwise the history was rebuilt (new run / compaction) and the session copy is authoritative
        queue = self.queues.get(agent_id) or []
        if queue:
            new = [(m, {"role": "user", "content": message_text(m.request_id, m.content)}) for m in queue]
            session = self._session(agent_id)
            if session is not None:
                await self._append(session, [it for _, it in new])   # raises -> messages stay queued
            for m, it in new:
                if items:
                    kept.append((len(items), _canon(items[-1]), MARKER.format(rid=m.request_id), it))
                items.append(it)
                m.state, m.delivered_at = "delivered", _now()
                m.reason = "" if session is not None else "Added to this model call; Strix had no session to persist it."
                m.content = ""                 # no longer needed in memory
            queue.clear()
            self._persist()
        self.injected[agent_id] = kept
        return model_input_data(input=items, instructions=data.model_data.instructions)

    def _session(self, agent_id: str) -> Any:
        rt = getattr(self.coordinator, "runtimes", {}).get(agent_id)
        return getattr(rt, "session", None)

    async def _append(self, session: Any, items: list[dict[str, Any]]) -> None:
        if self.add_to_session is not None:
            await self.add_to_session(session, items)
            return
        from strix.core.sessions import session_write_lock
        async with session_write_lock(session):
            await session.add_items(items)

    # ------------------------------------------------------------ state file (never content)
    def _persist(self) -> None:
        if not self.state_path:
            return
        with contextlib.suppress(OSError):
            _write_private_json(self.state_path, {"protocol": PROTOCOL, "updated_at": _now(), "closed": self.closed,
                                                  "messages": [m.public() for m in self.messages.values()]})


def _canon(item: Any) -> str:
    try:
        return json.dumps(item, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(item)


# ---------------------------------------------------------------- control HTTP endpoint
def make_server(channel: OperatorChannel, token: str) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SkynetBridge/1"

        def log_message(self, *_: Any) -> None:   # requests may carry operator text; never log them
            pass

        def _send(self, code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0]
            got = self.headers.get("Authorization") or ""
            return host == "127.0.0.1" and hmac.compare_digest(got.encode(), f"Bearer {token}".encode())

        def _run(self, fn: Callable[[], Any]) -> None:
            try:
                self._send(200, channel.call(fn))
            except RuntimeError as e:
                self._send(503, {"ok": False, "code": str(e) or "unavailable", "reason": "The scan is not accepting messages."})
            except Exception:  # noqa: BLE001 - includes timeouts; the caller treats it as unknown
                self._send(504, {"ok": False, "code": "timeout", "reason": "The scan did not answer in time."})

        def do_GET(self) -> None:  # noqa: N802
            if not self._authorized():
                return self._send(401, {"ok": False, "code": "unauthorized"})
            if self.path == "/v1/agents":
                return self._run(channel.agents)
            self._send(404, {"ok": False, "code": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                return self._send(401, {"ok": False, "code": "unauthorized"})
            if self.path != "/v1/messages":
                return self._send(404, {"ok": False, "code": "not_found"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"ok": False, "code": "bad_size"})
            try:
                body = json.loads(self.rfile.read(n))
                rid, aid, content = str(body["request_id"]), str(body["agent_id"]), str(body["content"])
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"ok": False, "code": "bad_request"})
            content = content.strip()
            if not REQUEST_ID_RE.match(rid) or not aid or not content or len(content) > MAX_CONTENT:
                return self._send(400, {"ok": False, "code": "bad_request"})
            self._run(lambda: channel.submit(rid, aid, content))

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


# ---------------------------------------------------------------- entry point (Strix runtime only)
def _strix_version() -> str:
    from importlib.metadata import version
    return version("strix-agent")


def install(channel: OperatorChannel, manifest_path: str | None) -> bool:
    """Attach the two seams. Returns False (and changes nothing) if the installed Strix does not match."""
    import inspect

    import strix.core.runner as core_runner
    import strix.interface.cli as cli
    from strix.core.agents import AgentCoordinator

    ver = _strix_version()
    original = getattr(cli, "run_strix_scan", None)
    rc_cls = getattr(core_runner, "RunConfig", None)
    if (ver not in SUPPORTED_STRIX or original is None or rc_cls is None
            or "coordinator" not in inspect.signature(original).parameters
            or "call_model_input_filter" not in getattr(rc_cls, "__dataclass_fields__", {})):
        log.warning("operator messaging unavailable: unsupported Strix runtime %s", ver)
        return False

    def run_config(*args: Any, **kwargs: Any) -> Any:
        rc = rc_cls(*args, **kwargs)
        inner = rc.call_model_input_filter
        if inner is None:
            rc.call_model_input_filter = channel.filter
        else:                                   # chain rather than replace a filter Strix may add later
            async def chained(data: Any) -> Any:
                res = inner(data)
                res = await res if inspect.isawaitable(res) else res
                data.model_data = res
                return await channel.filter(data)
            rc.call_model_input_filter = chained
        return rc

    async def run_strix_scan(**kwargs: Any) -> Any:
        coordinator = kwargs.get("coordinator") or AgentCoordinator()
        kwargs["coordinator"] = coordinator
        channel.attach(coordinator, asyncio.get_running_loop())
        server = make_server(channel, token := secrets.token_urlsafe(32))
        threading.Thread(target=server.serve_forever, daemon=True, name="skynet-control").start()
        if manifest_path:
            _write_private_json(manifest_path, {"protocol": PROTOCOL, "pid": os.getpid(), "port": server.server_port,
                                                "token": token, "strix_version": ver, "created_at": _now()})
        try:
            return await original(**kwargs)
        finally:
            if manifest_path:
                with contextlib.suppress(OSError):
                    os.unlink(manifest_path)
            channel.close()
            server.shutdown()
            server.server_close()

    core_runner.RunConfig = run_config
    cli.run_strix_scan = run_strix_scan
    return True


def main() -> None:
    channel = OperatorChannel(os.environ.get("SKYNET_CONTROL_STATE"))
    manifest = os.environ.get("SKYNET_CONTROL_MANIFEST")
    try:
        ok = install(channel, manifest)
    except Exception:  # noqa: BLE001 - never block the scan itself
        log.exception("operator messaging could not be attached")
        ok = False
    print(f"[skynet-bridge] operator messaging {'attached' if ok else 'unavailable'} "
          f"(strix-agent {_safe_version()}) at {time.strftime('%H:%M:%S')}", flush=True)
    from strix.interface.main import main as strix_main
    sys.argv = ["strix", *sys.argv[1:]]
    sys.exit(strix_main())


def _safe_version() -> str:
    try:
        return _strix_version()
    except Exception:  # noqa: BLE001
        return "unknown"


if __name__ == "__main__":
    main()
