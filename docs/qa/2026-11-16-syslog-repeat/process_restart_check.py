"""Real process exit/restart + real TCP receiver, using only disposable local data."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

if "--dispatch" in sys.argv:
    from skynet import db, siem
    db.init()
    siem.dispatch_once(time.time()+600 if "--advance-time" in sys.argv else None)
    raise SystemExit(0)

with tempfile.TemporaryDirectory(prefix="skynet-syslog-process-") as tmp:
    root = Path(tmp)
    os.environ.pop("SKYNET_SECRET_KEY", None)
    os.environ.update(SKYNET_LOAD_DOTENV="0", SKYNET_DATA=str(root/"data"), SKYNET_SECRET_KEY_FILE=str(root/"keys/key"))
    from skynet import audit, db, siem
    db.init()
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    siem.save({**siem.DEFAULTS, "enabled": True, "transport": "tcp", "host": "127.0.0.1", "port": port})
    audit.record("system", "target.update", summary="Disposable process restart QA", status=200)
    event = db.q1("SELECT * FROM syslog_outbox ORDER BY audit_id DESC LIMIT 1")
    expected = siem.configuration()["instance_id"]+":"+str(event["audit_id"])
    # Bound but not listening: first process encounters connection refusal.
    subprocess.run([sys.executable, __file__, "--dispatch"], check=True)
    first = db.q1("SELECT * FROM syslog_outbox WHERE audit_id=?", (event["audit_id"],))
    assert first["state"] == "pending" and first["attempts"] == 1
    reservation.close()
    captured = []
    with socket.socket() as receiver:
        receiver.bind(("127.0.0.1", port))
        receiver.listen(1)
        receiver.settimeout(5)
        def receive():
            with receiver.accept()[0] as connection:
                connection.settimeout(5)
                prefix = b""
                while not prefix.endswith(b" "):
                    prefix += connection.recv(1)
                size = int(prefix)
                packet = b""
                while len(packet) < size:
                    part = connection.recv(size-len(packet))
                    if not part:
                        raise AssertionError("Incomplete syslog frame")
                    packet += part
                captured.append(json.loads(packet.decode().split(" - ",1)[1]))
        thread = threading.Thread(target=receive, daemon=True)
        thread.start()
        subprocess.run([sys.executable, __file__, "--dispatch", "--advance-time"], check=True)
        thread.join(6)
    final = db.q1("SELECT * FROM syslog_outbox WHERE audit_id=?", (event["audit_id"],))
    assert len(captured) == 1 and captured[0]["event_id"] == expected
    assert final["attempts"] == 2 and final["state"] == "handed_off"
    print(json.dumps({"first_process_failure_persisted": True, "second_process_handoff_received": True,
                      "stable_event_id": True, "received_count": 1, "attempts": 2,
                      "scope": "Disposable DB/key; only 127.0.0.1 TCP; retry due time advanced for this test"}, indent=2))
    db._conn.close()
