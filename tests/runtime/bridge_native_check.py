"""Runs under the Strix runtime (.strix-runtime/bin/python), not Skynet's .venv.

Drives the real openai-agents Runner, the real Strix AgentCoordinator and the real Strix agent session through the
bridge's model-input filter and control endpoint, with a scripted model (no provider call, no Docker). Prints one
JSON line with the observations; tests/test_bridge.py asserts on it.
"""
import asyncio
import json
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from skynet import strix_bridge as sb  # noqa: E402

from agents import Agent, RunConfig, Runner, function_tool  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from openai.types.responses import (Response, ResponseCompletedEvent, ResponseFunctionToolCall,  # noqa: E402
                                    ResponseOutputMessage, ResponseOutputText)
from strix.core.agents import AgentCoordinator  # noqa: E402
from strix.core.sessions import open_agent_session  # noqa: E402

out: dict = {"calls": []}
hooks: dict = {}


class Scripted(Model):
    def __init__(self, turns):
        self.turns, self.n = turns, 0

    async def get_response(self, *a, **k):
        raise NotImplementedError

    async def stream_response(self, system_instructions, input, *a, **k):
        self.n += 1
        out["calls"].append([str(i.get("content"))[:60] if i.get("role") == "user" else i.get("type")
                             for i in input])
        if self.n < self.turns:
            o = [ResponseFunctionToolCall(id=f"fc{self.n}", call_id=f"c{self.n}", name="probe", arguments="{}",
                                          type="function_call", status="completed")]
        else:
            o = [ResponseOutputMessage(id=f"m{self.n}", role="assistant", status="completed", type="message",
                                       content=[ResponseOutputText(text="done", type="output_text", annotations=[])])]
        yield ResponseCompletedEvent(type="response.completed", sequence_number=0, response=Response(
            id=f"r{self.n}", created_at=0, model="scripted", object="response", output=o,
            parallel_tool_calls=False, tool_choice="auto", tools=[]))


def post(port, token, body, auth=True):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/messages", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if auth else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@function_tool
async def probe() -> str:
    # Runs inside the agent's turn, i.e. while the agent is "running" mid-stream (as during a real scan).
    if hooks.get("fire") == len(out["calls"]):
        hooks["send"]()
    return "ok"


async def main():
    d = Path(tempfile.mkdtemp())
    state = d / "state.json"
    ch = sb.OperatorChannel(str(state))
    coord = AgentCoordinator()
    await coord.register("root1", "Root Agent", parent_id=None, task="t", skills=[])
    await coord.register("kid1", "Child", parent_id="root1", task="t", skills=[])
    session = open_agent_session("root1", d / "agents.db")
    await coord.attach_runtime("root1", session=session, interrupt_on_message=False, resumable=False)
    await coord.attach_runtime("kid1", session=open_agent_session("kid1", d / "agents.db"), resumable=False)
    await coord.set_status("kid1", "completed")
    await coord.mark_running("root1")
    ch.attach(coord, asyncio.get_running_loop())
    token = "t" * 40
    srv = sb.make_server(ch, token)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port
    loop = asyncio.get_running_loop()

    results = {}

    def send():
        def work():
            results["unauth"] = post(port, token, {"request_id": "req-00000001", "agent_id": "root1", "content": "x"}, auth=False)
            results["first"] = post(port, token, {"request_id": "req-00000001", "agent_id": "root1", "content": "Focus on /api/orders"})
            results["dup"] = post(port, token, {"request_id": "req-00000001", "agent_id": "root1", "content": "Focus on /api/orders"})
            results["conflict"] = post(port, token, {"request_id": "req-00000001", "agent_id": "root1", "content": "other"})
            results["terminal"] = post(port, token, {"request_id": "req-00000002", "agent_id": "kid1", "content": "hi"})
            results["unknown"] = post(port, token, {"request_id": "req-00000003", "agent_id": "nobody", "content": "hi"})
        t = threading.Thread(target=work)
        t.start()
        hooks["thread"] = t

    # The HTTP thread needs the loop free, so the tool only starts it; the next model call happens after it is done.
    async def wait_thread():
        while "thread" not in hooks or hooks["thread"].is_alive():
            await asyncio.sleep(0.02)

    hooks["fire"] = 1
    hooks["send"] = send
    orig_filter = ch.filter

    async def filt(data):
        if len(out["calls"]) >= 1:
            await wait_thread()
        return await orig_filter(data)

    status_before = coord.statuses["root1"]
    agent = Agent(name="root", instructions="x", tools=[probe], model=Scripted(4))
    ctx = {"agent_id": "root1", "coordinator": coord}
    s = Runner.run_streamed(agent, input="TASK", session=session, context=ctx,
                            run_config=RunConfig(call_model_input_filter=filt))
    async for _ in s.stream_events():
        pass
    out["status_before"] = status_before
    out["status_after_run"] = coord.statuses["root1"]
    out["pending_native_mailbox"] = coord.pending_counts.get("root1", 0)
    out["http"] = results
    out["session"] = [str(i.get("content"))[:60] if i.get("role") == "user" else i.get("type")
                      for i in await session.get_items()]
    out["state_file"] = json.loads(state.read_text())
    out["state_mode"] = oct(state.stat().st_mode & 0o777)

    out["first_run_calls"] = out["calls"]
    # A second run on the same session: the delivered message comes from history, not re-injected.
    out["calls"] = []
    agent2 = Agent(name="root", instructions="x", tools=[probe], model=Scripted(1))
    s2 = Runner.run_streamed(agent2, input="AGAIN", session=session, context=ctx,
                             run_config=RunConfig(call_model_input_filter=ch.filter))
    async for _ in s2.stream_events():
        pass
    out["second_run_calls"] = out.pop("calls")

    # A queued message for an agent that then ends is reported as expired, never delivered.
    await coord.mark_running("kid1")
    out["late"] = await ch.submit("req-00000009", "kid1", "too late")
    await coord.set_status("kid1", "completed")
    await ch.agents()
    out["late_state"] = ch.messages["req-00000009"].state
    # A failing session write never fails the model call: input goes through unchanged, the message stays queued.
    from agents.run_config import CallModelData, ModelInputData
    ch2 = sb.OperatorChannel(None)
    ch2.attach(coord, loop)

    async def boom(session, items):
        raise OSError("disk full")
    ch2.add_to_session = boom
    await ch2.submit("req-00000010", "root1", "x")
    inp = [{"role": "user", "content": "T"}]
    res = await ch2.filter(CallModelData(model_data=ModelInputData(input=list(inp), instructions="i"), agent=None,
                                         context={"agent_id": "root1"}))
    out["fault_input_unchanged"] = res.input == inp
    out["fault_state"] = ch2.messages["req-00000010"].state
    md = ModelInputData(input=list(inp), instructions="i")
    out["noop_identity"] = (await ch2.filter(CallModelData(model_data=md, agent=None, context={"agent_id": "kid1"}))) is md
    ch.close()
    srv.shutdown()
    print(json.dumps(out))


asyncio.run(main())
