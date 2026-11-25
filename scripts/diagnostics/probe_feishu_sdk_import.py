"""Bounded, credential-free diagnostic of the installed Feishu SDK import.

This does not connect an account or certify the SDK for production. It excludes
project/user startup hooks and reports only a marker, version and error class.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


CHILD = """
import importlib, json, sys, time
print(json.dumps({'phase': 'child_started'}), flush=True)
memory_sdk = None
owned_loopback_sockets = []
def loopback(address):
    return isinstance(address, tuple) and len(address) >= 2 and address[0] in {'127.0.0.1', '::1'}
def audit(event, args):
    if event == 'socket.bind' and len(args) >= 2 and loopback(args[1]) and args[1][1] == 0:
        owned_loopback_sockets.append(args[0])
        return
    if event == 'socket.connect' and len(args) >= 2 and loopback(args[1]):
        for server in owned_loopback_sockets:
            try:
                if server.getsockname()[:2] == args[1][:2]:
                    return
            except OSError:
                pass
    if event in {
        'socket.connect', 'socket.bind', 'subprocess.Popen', 'os.system',
        'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename',
    }:
        raise RuntimeError('SDK_IMPORT_SIDE_EFFECT_DENIED:' + event)
sys.addaudithook(audit)
sys.path.insert(0, sys.argv[1])
if sys.argv[3]:
    sys.path.insert(0, sys.argv[3])
if sys.argv[4] == 'bytecode':
    import hashlib
    from importlib.util import MAGIC_NUMBER
    if list(sys.version_info[:3]) != [3, 12, 9] or MAGIC_NUMBER.hex() != 'cb0d0d0a':
        raise RuntimeError('SDK_CACHE_INTERPRETER_MISMATCH')
    with open(sys.argv[3], 'rb') as source:
        if hashlib.sha256(source.read()).hexdigest() != sys.argv[5]:
            raise RuntimeError('SDK_CACHE_HASH_MISMATCH')
if sys.argv[4] == 'memory':
    import hashlib, io, zipfile
    from importlib.abc import Loader, MetaPathFinder
    from importlib.util import spec_from_loader
    with open(sys.argv[3], 'rb') as source:
        wheel_bytes = source.read()
    assert hashlib.sha256(wheel_bytes).hexdigest() == '9b443a5d47a7d204dd42dc40896c8b75087cc35788e45c48c140806d7df7e5e8'
    class MemorySdk(MetaPathFinder, Loader):
        def __init__(self, payload):
            self.archive = zipfile.ZipFile(io.BytesIO(payload))
            self.names = set(self.archive.namelist())
            self.read_seconds = 0.0
            self.compile_seconds = 0.0
            self.modules_loaded = 0
        def entry(self, fullname):
            prefix = fullname.replace('.', '/')
            package = prefix + '/__init__.py'
            return package if package in self.names else prefix + '.py'
        def find_spec(self, fullname, path=None, target=None):
            if fullname != 'lark_oapi' and not fullname.startswith('lark_oapi.'):
                return None
            entry = self.entry(fullname)
            if entry not in self.names:
                return None
            return spec_from_loader(fullname, self, is_package=entry.endswith('/__init__.py'))
        def create_module(self, spec):
            return None
        def exec_module(self, module):
            entry = self.entry(module.__name__)
            module.__file__ = 'nachuan-sdk-memory://1.6.8/' + entry
            if entry.endswith('/__init__.py'):
                module.__path__ = [module.__file__.rsplit('/', 1)[0]]
            read_started = time.monotonic()
            source = self.archive.read(entry)
            self.read_seconds += time.monotonic() - read_started
            compile_started = time.monotonic()
            code = compile(source, module.__file__, 'exec')
            self.compile_seconds += time.monotonic() - compile_started
            self.modules_loaded += 1
            exec(code, module.__dict__)
        def get_source(self, fullname):
            return self.archive.read(self.entry(fullname)).decode('utf-8-sig')
        def get_data(self, path):
            prefix = 'nachuan-sdk-memory://1.6.8/'
            if not path.startswith(prefix):
                raise OSError('SDK resource outside memory archive')
            return self.archive.read(path[len(prefix):])
    memory_sdk = MemorySdk(wheel_bytes)
    sys.meta_path.insert(0, memory_sdk)
started = time.monotonic()
target = sys.argv[2]
print(json.dumps({'phase': 'import_started', 'target': target}), flush=True)
if target == 'asyncio-loop':
    import asyncio
    loop = asyncio.new_event_loop()
    loop.close()
elif target == 'audit-selftest':
    import socket
    with socket.socket() as server, socket.socket() as client:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        client.connect(server.getsockname())
    denied = 0
    for kind, address in (
        ('connect', ('203.0.113.1', 9)),
        ('connect', ('127.0.0.1', 1)),
        ('bind', ('0.0.0.0', 0)),
    ):
        with socket.socket() as candidate:
            try:
                getattr(candidate, kind)(address)
            except RuntimeError as exc:
                assert 'SDK_IMPORT_SIDE_EFFECT_DENIED' in str(exc)
                denied += 1
    assert denied == 3
else:
    importlib.import_module('lark_oapi' if target in {'sdk-shutdown', 'sdk-owned-shutdown'} else target)
shutdown_receipt = None
if target == 'sdk-owned-shutdown':
    import asyncio, threading
    from pathlib import Path
    from lark_oapi.ws import client as ws_module
    from lark_oapi.core.enum import LogLevel
    location = Path(sys.argv[1]).parents[2] / 'gateway' / 'feishu_sdk_lifecycle.py'
    spec = importlib.util.spec_from_file_location('nachuan_sdk_lifecycle_probe', location)
    runtime = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runtime
    spec.loader.exec_module(runtime)
    stop = threading.Event()
    made = []
    class LocalSocket:
        closed = False
        async def close(self): self.closed = True
        async def send(self, data): pass
    connection = LocalSocket()
    def factory():
        client = ws_module.Client('diagnostic-only', 'not-a-credential', log_level=LogLevel.ERROR)
        owner_loop = asyncio.get_event_loop()
        async def connect_without_network():
            client._conn = connection
            client._service_id = '1'
            owner_loop.call_later(0.05, stop.set)
        client._connect = connect_without_network
        made.append((client, owner_loop))
        return client
    shutdown_started = time.monotonic()
    outcome = runtime.run_feishu_sdk(factory, stop)
    client, owner_loop = made[0]
    assert outcome.stop_requested and connection.closed and client._conn is None
    assert owner_loop.is_closed() and not runtime._FAILED_RUNS
    shutdown_receipt = {
        'mode': 'project-adapter-real-sdk-synthetic-transport',
        'sdk_start_exited': True, 'connection_closed': connection.closed,
        'pending_tasks': len(asyncio.all_tasks(owner_loop)),
        'loop_closed': owner_loop.is_closed(),
        'seconds': round(time.monotonic() - shutdown_started, 3),
        'production_integration': False,
    }
if target == 'sdk-shutdown':
    import asyncio
    from importlib.metadata import version
    if version('lark-oapi') != '1.6.8':
        raise RuntimeError('SDK_SHUTDOWN_VERSION_MISMATCH')
    from lark_oapi.ws import client as ws_module
    from lark_oapi.core.enum import LogLevel
    sdk_loop = ws_module.loop
    assert not sdk_loop.is_running() and not sdk_loop.is_closed()
    assert not asyncio.all_tasks(sdk_loop)
    class LocalSocket:
        closed = False
        async def close(self):
            self.closed = True
        async def send(self, data):
            pass
    connection = LocalSocket()
    client = ws_module.Client('diagnostic-only', 'not-a-credential', log_level=LogLevel.ERROR)
    async def connect_without_network():
        client._conn = connection
        client._service_id = '1'
    client._connect = connect_without_network
    stopped = False
    timed_out = False
    async def stop_owned_loop():
        await client._disconnect()
        for task in asyncio.all_tasks(sdk_loop):
            if task is not asyncio.current_task(sdk_loop):
                task.cancel()
    def deadline():
        global timed_out
        timed_out = True
        sdk_loop.stop()
    timer = sdk_loop.call_later(2, deadline)
    request = sdk_loop.call_later(0.05, lambda: sdk_loop.create_task(stop_owned_loop()))
    shutdown_started = time.monotonic()
    try:
        client.start()
    except asyncio.CancelledError:
        stopped = True
    finally:
        request.cancel()
        pending = asyncio.all_tasks(sdk_loop)
        for task in pending:
            task.cancel()
        if pending and not timed_out:
            sdk_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        timer.cancel()
    remaining = len(asyncio.all_tasks(sdk_loop))
    sdk_loop.close()
    assert stopped and not timed_out and connection.closed and client._conn is None and remaining == 0
    shutdown_receipt = {
        'mode': 'real-sdk-synthetic-transport',
        'sdk_start_exited': stopped, 'connection_closed': connection.closed,
        'pending_tasks': remaining, 'loop_closed': sdk_loop.is_closed(),
        'public_stop_available': callable(getattr(client, 'stop', None)),
        'seconds': round(time.monotonic() - shutdown_started, 3),
        'production_integration': False,
    }
sdk_version = None
if target in {'lark_oapi', 'sdk-shutdown', 'sdk-owned-shutdown'}:
    from importlib.metadata import version
    sdk_version = version('lark-oapi')
print(json.dumps({
    'phase': 'import_finished', 'marker': 'IMPORT_OK',
    'target': target, 'version': sdk_version,
    'python': list(sys.version_info[:3]),
    'seconds': round(time.monotonic() - started, 3),
    'shutdown_receipt': shutdown_receipt,
    'memory_metrics': {
        'modules_loaded': memory_sdk.modules_loaded,
        'archive_read_seconds': round(memory_sdk.read_seconds, 3),
        'compile_seconds': round(memory_sdk.compile_seconds, 3),
    } if memory_sdk is not None else None,
}), flush=True)
"""


def observation(stdout: bytes | None, stderr: bytes | None) -> dict:
    records = []
    for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("phase") in {
            "child_started", "import_started", "import_finished"
        }:
            records.append(record)
    error_text = (stderr or b"").decode("utf-8", errors="replace")
    imports = re.findall(r"(?m)^import time:\s+\d+\s+\|\s+\d+\s+\|\s+([\w.]+)", error_text)
    blocked = re.findall(r"SDK_IMPORT_SIDE_EFFECT_DENIED:([\w.]+)", error_text)
    exceptions = re.findall(r"(?m)^([A-Za-z_]\w*(?:Error|Exception))(?::|$)", error_text)
    frames = re.findall(r'File "([^"]+)", line (\d+), in ([\w<>]+)', error_text)
    return {
        "phases": [record["phase"] for record in records],
        "marker": next((r for r in reversed(records) if r.get("marker") == "IMPORT_OK"), None),
        "last_completed_import": imports[-1] if imports else None,
        "completed_import_count": len(imports),
        "blocked_event": blocked[-1] if blocked else None,
        "exception_type": exceptions[-1] if exceptions else None,
        "error_frames": [
            {"file": name.replace("\\", "/").rsplit("/", 1)[-1], "line": int(line), "function": function}
            for name, line, function in frames[-4:]
        ],
        "stderr_sha256": hashlib.sha256(stderr or b"").hexdigest(),
        "native_access_violation": "access violation" in error_text.lower(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("sdk", "sdk-shutdown", "sdk-owned-shutdown", "python", "asyncio", "asyncio-loop", "audit-selftest"), default="sdk")
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--sdk-layout", choices=("installed", "wheel", "memory", "bytecode"), default="installed")
    parser.add_argument("--cache-sha256", default="")
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 180:
        parser.error("timeout must be between 1 and 180 seconds")
    target = {"sdk": "lark_oapi", "sdk-shutdown": "sdk-shutdown", "sdk-owned-shutdown": "sdk-owned-shutdown", "python": "json", "asyncio": "asyncio", "asyncio-loop": "asyncio-loop", "audit-selftest": "audit-selftest"}[args.target]
    root = Path(__file__).resolve().parents[2]
    executable = root / ".venv" / "Scripts" / "python.exe"
    packages = root / ".venv" / "Lib" / "site-packages"
    if not executable.is_file() or not packages.is_dir():
        raise SystemExit("PROJECT_PYTHON_UNAVAILABLE")
    allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "TEMP", "TMP"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    wheel = ""
    if args.sdk_layout in {"wheel", "memory"}:
        candidate = root / "data" / "test-evidence" / "sdk-lifecycle-20260905" / "lark_oapi-1.6.8-py3-none-any.whl"
        expected = "9b443a5d47a7d204dd42dc40896c8b75087cc35788e45c48c140806d7df7e5e8"
        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != expected:
            raise SystemExit("LOCKED_SDK_WHEEL_UNAVAILABLE")
        wheel = str(candidate)
    if args.sdk_layout == "bytecode":
        if not re.fullmatch(r"[0-9a-f]{64}", args.cache_sha256):
            parser.error("bytecode requires an explicitly pinned --cache-sha256")
        candidate = root / "data" / "test-evidence" / "sdk-lifecycle-20260905" / ("lark_sdk_cpython-312_" + args.cache_sha256[:16] + ".zip")
        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != args.cache_sha256:
            raise SystemExit("SDK_CACHE_HASH_MISMATCH")
        wheel = str(candidate)
    started = time.monotonic()
    command = [str(executable), "-I", "-S", "-B", "-X", "utf8", "-X", "faulthandler"]
    if args.profile:
        command += ["-X", "importtime"]
    command += ["-c", CHILD, str(packages), target, wheel, args.sdk_layout, args.cache_sha256]
    try:
        process = subprocess.Popen(
            command,
            cwd=root, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + args.timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            try:
                stdout, stderr = process.communicate(timeout=max(0.01, min(10, remaining)))
                child = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                break
            except subprocess.TimeoutExpired as exc:
                if time.monotonic() >= deadline:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)
                    raise subprocess.TimeoutExpired(command, args.timeout_seconds, stdout, stderr)
                progress = observation(exc.stdout, exc.stderr)
                print(json.dumps({
                    "result": "running", "target": target,
                    "seconds": round(time.monotonic() - started, 1),
                    "last_completed_import": progress["last_completed_import"],
                    "completed_import_count": progress["completed_import_count"],
                    "phases": progress["phases"],
                }), flush=True)
    except subprocess.TimeoutExpired as exc:
        print(json.dumps({
            "result": "timeout", "target": target, "timeout_seconds": args.timeout_seconds,
            "sdk_layout": args.sdk_layout,
            **observation(exc.stdout, exc.stderr),
        }), flush=True)
        return 2
    stderr = child.stderr.decode("utf-8", errors="replace").lower()
    category = (
        "native_access_violation" if "access violation" in stderr
        else "import_side_effect_denied" if "sdk_import_side_effect_denied" in stderr
        else "import_failed" if child.returncode else "none"
    )
    observed = observation(child.stdout, child.stderr)
    marker = observed["marker"]
    valid = isinstance(marker, dict) and marker.get("target") == target
    result = {
        "result": "passed" if child.returncode == 0 and valid else "failed",
        "target": target,
        "sdk_layout": args.sdk_layout,
        "exit_code": child.returncode, "error_class": category,
        "seconds": round(time.monotonic() - started, 3),
        **observed,
        "sdk": marker if valid and target in {"lark_oapi", "sdk-shutdown", "sdk-owned-shutdown"} else None,
    }
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0 if result["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
