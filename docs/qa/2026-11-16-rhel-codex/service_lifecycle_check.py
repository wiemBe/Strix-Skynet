"""Ephemeral UBI service lifecycle check; fixture data and localhost only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import sqlite3
import subprocess
import sys
import tempfile

if '--disposable-qa' not in sys.argv[1:] or platform.system() != 'Linux' or not any(
        p.exists() for p in (Path('/.dockerenv'), Path('/run/.containerenv'))):
    raise SystemExit('Use --disposable-qa inside a dedicated Linux QA container.')

ROOT = Path('/opt/skynet')
spec = importlib.util.spec_from_file_location('qa_http', ROOT / 'scripts/qa_http.py')
qa_http = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa_http)

with tempfile.TemporaryDirectory(prefix='skynet-service-qa-') as tmp:
    root = Path(tmp)
    work = root / 'work'
    work.mkdir()
    password = secrets.token_urlsafe(24)
    env = {k: v for k, v in os.environ.items() if not k.startswith('SKYNET_')}
    env.update(SKYNET_LOAD_DOTENV='0', SKYNET_DATA=str(root/'data'),
               SKYNET_SECRET_KEY_FILE=str(root/'keys/secret.key'),
               SKYNET_STRIX_BIN=str(ROOT/'.strix-runtime/bin/strix'),
               SKYNET_STRIX_RUNTIME=str(ROOT/'.strix-runtime/bin/python'),
               SKYNET_STRIX_WORKDIR=str(work), SKYNET_HOST='127.0.0.1', SKYNET_PORT='8787',
               SKYNET_TIMEZONE='Europe/Istanbul', SKYNET_COOKIE_SECURE='0', SKYNET_PASSWORD=password)
    os.environ['SKYNET_QA_PASSWORD'] = password
    checks = []
    snapshots = []
    for mode in ('create', 'verify'):
        with (root/(mode+'.log')).open('w') as log:
            proc = subprocess.Popen([sys.executable, '-m', 'skynet'], cwd=ROOT, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
            try:
                checks.append(qa_http.run('http://127.0.0.1:8787', mode, root/'state.json'))
            except BaseException:
                print((root/(mode+'.log')).read_text(), file=sys.stderr)
                raise
            finally:
                proc.terminate()
                try:
                    proc.wait(15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            assert proc.returncode in (0, -15), proc.returncode
        with sqlite3.connect(root/'data/skynet.db') as db:
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            snapshots.append((hashlib.sha256((root/'keys/secret.key').read_bytes()).hexdigest(),
                              db.execute('SELECT secret_enc FROM auth_profiles').fetchall()))
    assert snapshots[0] == snapshots[1], 'Restart changed the key or encrypted credentials'
    doctor = subprocess.run([sys.executable, str(ROOT/'scripts/doctor.py'), '--skip-docker'],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    result = json.loads(doctor.stdout)
    assert doctor.returncode == 0 and result['ok'], result
    for check in result['checks']:
        if check['check'] in ('encryption', 'sqlite_json', 'password_hash', 'messaging_runtime'):
            assert check['ok'], check
    print(json.dumps({'platform': platform.platform(), 'python': platform.python_version(),
                      'lifecycle': checks, 'key_and_ciphertext_preserved_after_restart': True,
                      'sqlite_integrity': 'ok', 'doctor': result,
                      'scope': 'Disposable UBI9; real application lifespan; no host volumes, Docker socket or external scan'}, indent=2))
