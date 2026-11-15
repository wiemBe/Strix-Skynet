"""Strix runtime only: install() attaches to the real strix modules and the wrapper owns manifest lifecycle."""
import asyncio
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from skynet import strix_bridge as sb  # noqa: E402

import strix.core.runner as core_runner  # noqa: E402
import strix.interface.cli as cli  # noqa: E402

out = {"native_signature_has_coordinator": "coordinator" in inspect.signature(cli.run_strix_scan).parameters}
seen = {}


async def fake_original(*, scan_config, coordinator=None, **kw):   # same keyword shape as the native function
    seen["coordinator"] = type(coordinator).__name__
    m = json.loads(Path(manifest).read_text())
    seen["manifest"] = {k: m[k] for k in ("protocol", "pid", "strix_version")}
    seen["manifest_mode"] = oct(Path(manifest).stat().st_mode & 0o777)
    seen["pid_matches"] = m["pid"] == os.getpid()
    return "result"

d = tempfile.mkdtemp()
manifest = os.path.join(d, "m.json")
cli.run_strix_scan = fake_original
ch = sb.OperatorChannel(os.path.join(d, "s.json"))
out["installed"] = sb.install(ch, manifest)
rc = core_runner.RunConfig(model="x")
out["filter_attached"] = rc.call_model_input_filter == ch.filter
out["wrapper_result"] = asyncio.run(cli.run_strix_scan(scan_config={}))
out["seen"] = seen
out["manifest_removed"] = not os.path.exists(manifest)
out["channel_closed"] = ch.closed
print(json.dumps(out))
