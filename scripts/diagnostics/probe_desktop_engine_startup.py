"""Bounded desktop-engine startup probe with empty data and no remote sockets."""
import json
import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'data/test-evidence/desktop-install-20260906'
EVIDENCE.mkdir(parents=True, exist_ok=True)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prepare-preview', action='store_true')
args = parser.parse_args()
LOGDIR = Path(tempfile.mkdtemp(prefix='startup-probe-', dir=EVIDENCE))
STATE = ROOT / '安装与维护/本机桌面体验版/用户数据/data' if args.prepare_preview else LOGDIR
STATE.mkdir(parents=True, exist_ok=True)
with socket.socket() as port_socket:
    port_socket.bind(('127.0.0.1', 0))
    port = port_socket.getsockname()[1]
allowed = {'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}
env = {k:v for k,v in os.environ.items() if k.upper() in allowed}
env.update({
    'NACHUAN_CONFIG_ENV_ONLY':'1', 'DATA_DIR':str(STATE),
    'USAGE_DB_PATH':str(STATE/'usage.db'),
    'NACHUAN_CONNECTIONS_PATH':str(STATE/'connections.json'),
    'NACHUAN_PROVIDER_CALL_LEDGER_PATH':str(STATE/'provider-calls.db'),
    'NACHUAN_PROVIDER_CALL_LEDGER_MODE':'required',
    'AGENT_EXEC_WORKDIR':str(STATE), 'NACHUAN_GUARD_HOME':str(STATE),
    'SEMCACHE_DB_DIR':str(STATE/'semcache'), 'GATEWAY_HOST':'127.0.0.1',
    'GATEWAY_PORT':str(port), 'NACHUAN_ENGINE_PORT':str(port),
    'NACHUAN_ENGINE_GENERATION':'1', 'NACHUAN_ENGINE_BOOT_TOKEN':secrets.token_hex(32),
    'GATEWAY_API_KEYS':secrets.token_hex(32), 'APPROVAL_ADMIN_KEY':secrets.token_hex(32),
    'NACHUAN_PAID_MEDIA_API_KEY':secrets.token_hex(32),
    'PYTHONUTF8':'1', 'PYTHONDONTWRITEBYTECODE':'1',
})
child_code = '''
import sys,faulthandler
sys.path.insert(0,sys.argv[1])
def audit(event,args):
    if event=='socket.connect':
        address=args[1]
        if not isinstance(address,tuple) or address[0] not in {'127.0.0.1','::1'}:
            raise RuntimeError('STARTUP_PROBE_REMOTE_SOCKET_DENIED')
sys.addaudithook(audit)
faulthandler.enable()
faulthandler.dump_traceback_later(20,repeat=True)
from gateway.app import main
main()
'''
started=time.monotonic()
out_path=LOGDIR/'stdout.log'
err_path=LOGDIR/'stderr.log'
with out_path.open('wb') as out, err_path.open('wb') as err:
    child=subprocess.Popen([str(ROOT/'.venv/Scripts/python.exe'),'-I','-B','-X','utf8','-c',child_code,str(ROOT)],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
    result={'ready':False,'probe_state':LOGDIR.name,'external_sockets_allowed':False,'prepare_preview':args.prepare_preview}
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while child.poll() is None and time.monotonic()-started < 120:
            try:
                with opener.open(f'http://127.0.0.1:{port}/health',timeout=0.5) as response:
                    health=json.load(response)
                    result.update(ready=response.status==200,status=health.get('status'),seconds=round(time.monotonic()-started,3))
                    break
            except Exception:
                time.sleep(0.5)
        if not result['ready']:
            result.update(seconds=round(time.monotonic()-started,3),exit_code=child.poll())
    finally:
        if child.poll() is None: child.terminate()
        child.wait(timeout=10)
result['stderr_file']=str(err_path.relative_to(ROOT))
(LOGDIR/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True),flush=True)
raise SystemExit(0 if result['ready'] else 1)
