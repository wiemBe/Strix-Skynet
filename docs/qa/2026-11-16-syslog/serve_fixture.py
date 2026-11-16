"""Temporary UI + real loopback UDP collector; no scheduler/scan/real SIEM calls."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
from contextlib import asynccontextmanager

ROOT = Path(__file__).resolve().parents[3]
TEMP = Path(tempfile.mkdtemp(prefix="skynet-syslog-ui-"))
os.environ.pop("SKYNET_SECRET_KEY", None)
os.environ.update(SKYNET_LOAD_DOTENV="0", SKYNET_DATA=str(TEMP/"data"), SKYNET_SECRET_KEY_FILE=str(TEMP/"keys/key"),
                  SKYNET_PASSWORD="syslog-qa-admin-password", SKYNET_STRIX_WORKDIR=str(TEMP/"work"))
sys.path.insert(0, str(ROOT))
from skynet import auth, db, main, siem

collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
collector.bind(("127.0.0.1", 0))
port = collector.getsockname()[1]


def collect():
    with (TEMP/"received.jsonl").open("a") as f:
        while True:
            try:
                packet, _ = collector.recvfrom(65535)
                event = json.loads(packet.decode("ascii").split(" - ", 1)[1])
                f.write(json.dumps(event)+"\n")
                f.flush()
            except OSError:
                return


@asynccontextmanager
async def fixture(_):
    db.init()
    auth.bootstrap()
    auth.create_user("syslog-viewer", "viewer", "syslog-qa-viewer-password", "QA Viewer")
    siem.start()
    threading.Thread(target=collect, daemon=True).start()
    print(json.dumps({"temp_root": str(TEMP), "collector_port": port, "url": "http://127.0.0.1:8798"}), flush=True)
    try:
        yield
    finally:
        siem.stop()
        collector.close()


main.app.router.lifespan_context = fixture
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(main.app, host="127.0.0.1", port=8798, access_log=False)
