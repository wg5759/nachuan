from __future__ import annotations

import json
import hashlib
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.sqlite_backup import backup_databases


POWERSHELL = shutil.which("powershell")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
MANAGED_LAUNCHER = SCRIPT.parent / "managed_launcher.py"


def _run_supervisor(
    *args: str, timeout_seconds: float = 30.0
) -> subprocess.CompletedProcess[str]:
    if not POWERSHELL:
        pytest.skip("PowerShell is required for the Windows supervisor contract")
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )


def _run_supervisor_function(
    function_name: str, body: str
) -> subprocess.CompletedProcess[str]:
    """Load one production PowerShell function and mock every external boundary."""

    if not POWERSHELL:
        pytest.skip("PowerShell is required for the Windows supervisor contract")
    path = str(SCRIPT).replace("'", "''")
    name = function_name.replace("'", "''")
    command = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    '{path}', [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {{ throw 'supervisor source parse failed' }}
$target = @($ast.FindAll({{
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq '{name}'
}}, $true))
if ($target.Count -ne 1) {{ throw 'supervisor function not found or ambiguous: {name}' }}
Invoke-Expression ([string]$target[0].Extent.Text)
{body}
"""
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )


def _link_test_venv(root: Path) -> None:
    venv_root = Path(sys.executable).resolve().parents[1]
    link = root / ".venv"
    try:
        os.symlink(venv_root, link, target_is_directory=True)
    except OSError:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(venv_root)],
            capture_output=True,
            encoding="oem",
            errors="replace",
            check=False,
        )
        if result.returncode:
            pytest.skip(f"could not create isolated venv junction: {result.stderr}")


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _current_process_creation_filetime() -> int:
    if os.name != "nt":
        return max(1, time.time_ns() // 100)
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        kernel32.GetCurrentProcess(),
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
    return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)


def _start_attested_managed_engine(
    root: Path, *, port: int, token: str, financial_ready: bool = True
):
    scripts = root / "scripts"
    package = root / "gateway"
    data = root / "data"
    scripts.mkdir(parents=True, exist_ok=True)
    package.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        challenge = parse_qs(urlsplit(self.path).query).get("challenge", [""])[0]
        token = os.environ.get("NACHUAN_ENGINE_BOOT_TOKEN", "")
        proof = ""
        if len(challenge) == 64 and len(token) == 64:
            proof = hmac.new(bytes.fromhex(token), challenge.encode("ascii"), hashlib.sha256).hexdigest()
        body = json.dumps({
            "status": "ok",
            "readiness": "ok" if __FINANCIAL_READY__ else "degraded",
            "pid": os.getpid(),
            "boot_proof": proof,
            "checks": {
                "database": {"ready": True},
                "financial_ledger": {
                    "required": True,
                    "ready": __FINANCIAL_READY__,
                },
                "providers": {"ready": True},
            },
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        return

ThreadingHTTPServer(("127.0.0.1", int(os.environ["GATEWAY_PORT"])), Handler).serve_forever()
""".replace("__FINANCIAL_READY__", "True" if financial_ready else "False").strip(),
        encoding="utf-8",
    )
    (data / "engine_boot_token.txt").write_text(token, encoding="ascii")
    env = {
        **os.environ,
        "NACHUAN_ENGINE_BOOT_TOKEN": token,
        "NACHUAN_WEIXIN_BRIDGE_API_KEY": "sk-bridge-v2-weixin-" + "1" * 64,
        "NACHUAN_FEISHU_BRIDGE_API_KEY": "sk-bridge-v2-feishu-" + "2" * 64,
    }
    wrapper = subprocess.Popen(
        [
            str(root / ".venv" / "Scripts" / "python.exe"),
            "-X",
            "utf8",
            "-I",
            "-S",
            "-u",
            str(scripts / "managed_launcher.py"),
            "engine",
            "gateway.app",
            str(port),
            str(os.getpid()),
            str(_current_process_creation_filetime()),
        ],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if wrapper.poll() is not None:
            detail = wrapper.stderr.read() if wrapper.stderr else ""
            raise AssertionError(f"managed engine exited early: {detail}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5):
                return wrapper
        except OSError:
            time.sleep(0.1)
    wrapper.terminate()
    raise AssertionError("managed engine did not become reachable")


def _prepare_offline_managed_services(
    root: Path,
    *,
    providers_ready: bool,
    database_ready: bool = True,
) -> tuple[Path, Path]:
    """Install inert managed-service fixtures without touching real providers."""

    scripts = root / "scripts"
    package = root / "gateway"
    data = root / "data"
    scripts.mkdir(parents=True, exist_ok=True)
    package.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    shutil.copy2(SCRIPT.parent / "sqlite_backup.py", scripts / "sqlite_backup.py")
    _link_test_venv(root)

    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        challenge = parse_qs(urlsplit(self.path).query).get("challenge", [""])[0]
        token = os.environ.get("NACHUAN_ENGINE_BOOT_TOKEN", "")
        proof = ""
        if len(challenge) == 64 and len(token) == 64:
            proof = hmac.new(bytes.fromhex(token), challenge.encode("ascii"), hashlib.sha256).hexdigest()
        body = json.dumps({
            "status": "ok",
            "readiness": "ok" if __DATABASE_READY__ else "degraded",
            "pid": os.getpid(),
            "boot_proof": proof,
            "checks": {
                "database": {"ready": __DATABASE_READY__},
                "financial_ledger": {"required": True, "ready": True},
                "connection_store": {"ready": True},
                "providers": {"ready": __PROVIDERS_READY__},
            },
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        return

ThreadingHTTPServer(("127.0.0.1", int(os.environ["GATEWAY_PORT"])), Handler).serve_forever()
"""
        .replace("__DATABASE_READY__", "True" if database_ready else "False")
        .replace("__PROVIDERS_READY__", "True" if providers_ready else "False")
        .strip(),
        encoding="utf-8",
    )

    markers: list[Path] = []
    for service in ("weixin", "feishu"):
        marker = data / f"{service}.started"
        markers.append(marker)
        (scripts / f"run_{service}{'_ilink' if service == 'weixin' else ''}_bridge.py").write_text(
            f"""
from pathlib import Path
import time

Path({str(marker)!r}).write_text("started", encoding="ascii")
time.sleep(120)
""".strip(),
            encoding="utf-8",
        )

    (data / "ilink_token.json").write_text(
        json.dumps({"bot_token": "offline-saved-login"}), encoding="utf-8"
    )
    connection = sqlite3.connect(data / "proof.db")
    connection.execute("CREATE TABLE proof (value TEXT NOT NULL)")
    connection.execute("INSERT INTO proof VALUES ('offline')")
    connection.commit()
    connection.close()
    backup_databases(data, data / "backup" / "sqlite")
    return markers[0], markers[1]


def _start_offline_supervisor(root: Path, port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Action",
            "Run",
            "-Root",
            str(root),
            "-EnginePort",
            str(port),
            "-PollSeconds",
            "2",
            "-Json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _stop_offline_supervisor(
    supervisor: subprocess.Popen[str],
    root: Path,
    port: int,
    *,
    command_timeout_seconds: float = 30.0,
) -> None:
    if supervisor.poll() is None:
        supervisor.terminate()
        try:
            supervisor.wait(timeout=10)
        except subprocess.TimeoutExpired:
            supervisor.kill()
            supervisor.wait(timeout=5)
    _run_supervisor(
        "-Action",
        "Stop",
        "-Root",
        str(root),
        "-EnginePort",
        str(port),
        "-Json",
        timeout_seconds=command_timeout_seconds,
    )


def _wait_for_offline_supervisor_handshake(
    supervisor: subprocess.Popen[str],
    condition,
    *,
    description: str,
    timeout_seconds: float = 120.0,
) -> None:
    """Wait for an observable child-process handshake before querying Status."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if condition():
            return
        if supervisor.poll() is not None:
            stderr = supervisor.stderr.read() if supervisor.stderr else ""
            raise AssertionError(
                f"supervisor exited before {description}: {stderr}"
            )
        time.sleep(0.1)
    raise AssertionError(f"supervisor did not reach {description}")


def _wait_for_process_file_handshake(
    process,
    target: Path,
    *,
    description: str,
    timeout_seconds: float,
    clock=time.monotonic,
    sleeper=time.sleep,
) -> None:
    """Race an observable file against process exit with a test-only watchdog."""

    deadline = clock() + timeout_seconds
    while True:
        if target.is_file():
            return
        returncode = process.poll()
        if returncode is not None:
            # EOF is only safe after the process has exited.  Never synchronously
            # read a live long-running supervisor pipe while reporting timeout.
            detail = process.stderr.read() if process.stderr else ""
            raise AssertionError(
                f"{description} process exited code={returncode}: {detail}"
            )
        remaining = deadline - clock()
        if remaining <= 0:
            # Close the two final races before declaring the local watchdog:
            # the file may have committed or the process may have exited since
            # the checks at the top of the loop.
            if target.is_file():
                return
            returncode = process.poll()
            if returncode is not None:
                detail = process.stderr.read() if process.stderr else ""
                raise AssertionError(
                    f"{description} process exited code={returncode}: {detail}"
                )
            raise AssertionError(
                f"{description} watchdog expired while process was still running"
            )
        sleeper(min(0.1, remaining))


def test_process_file_handshake_accepts_pid_after_legacy_startup_window(
    tmp_path: Path,
):
    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    class BlockingStderr:
        read_calls = 0

        def read(self) -> str:
            self.read_calls += 1
            raise AssertionError("live stderr has no EOF")

    class RunningProcess:
        stderr = BlockingStderr()

        @staticmethod
        def poll():
            return None

    clock = Clock()
    process = RunningProcess()
    pid_file = tmp_path / "late.pid"

    def publish_after_legacy_window(_seconds: float) -> None:
        clock.value = 16.0
        pid_file.write_text("ready", encoding="ascii")

    _wait_for_process_file_handshake(
        process,
        pid_file,
        description="late test supervisor pid",
        timeout_seconds=45,
        clock=clock,
        sleeper=publish_after_legacy_window,
    )

    assert pid_file.is_file()
    assert process.stderr.read_calls == 0


def test_process_file_handshake_watchdog_never_reads_live_stderr(tmp_path: Path):
    class ExpiredClock:
        def __init__(self):
            self.calls = 0

        def __call__(self) -> float:
            self.calls += 1
            return 0.0 if self.calls == 1 else 46.0

    class BlockingStderr:
        read_calls = 0

        def read(self) -> str:
            self.read_calls += 1
            raise AssertionError("live stderr has no EOF")

    class RunningProcess:
        stderr = BlockingStderr()

        @staticmethod
        def poll():
            return None

    process = RunningProcess()
    with pytest.raises(AssertionError, match="watchdog.*still running"):
        _wait_for_process_file_handshake(
            process,
            tmp_path / "missing.pid",
            description="missing test supervisor pid",
            timeout_seconds=45,
            clock=ExpiredClock(),
            sleeper=lambda _seconds: None,
        )
    assert process.stderr.read_calls == 0


@pytest.mark.skipif(os.name != "nt", reason="supervisor process identity uses Windows CIM")
def test_provider_unavailable_still_starts_configured_durable_bridges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "provider-unavailable-cold-start"
    weixin_started, feishu_started = _prepare_offline_managed_services(
        root, providers_ready=False
    )
    port = _free_loopback_port()
    monkeypatch.setenv("FEISHU_APP_ID", "offline-app-id")
    monkeypatch.setenv("FEISHU_APP_SECRET", "offline-app-secret")
    supervisor = _start_offline_supervisor(root, port)
    status: subprocess.CompletedProcess[str] | None = None
    try:
        _wait_for_offline_supervisor_handshake(
            supervisor,
            lambda: weixin_started.is_file() and feishu_started.is_file(),
            description="both durable bridge start handshakes",
        )
        status = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(root),
            "-EnginePort",
            str(port),
            "-Json",
            # Status starts a fresh PowerShell process and performs Windows CIM
            # identity checks.  Under the full shard that can exceed 30s even
            # after both bridge children have handshaken.
            timeout_seconds=90,
        )
    finally:
        _stop_offline_supervisor(
            supervisor, root, port, command_timeout_seconds=90
        )

    assert status is not None and status.returncode == 0, (
        "" if status is None else status.stderr or status.stdout
    )
    payload = json.loads(status.stdout)
    assert payload["engine_health"]["state"] == "provider_unavailable"
    assert payload["engine_health"]["ready"] is False
    assert weixin_started.is_file()
    assert feishu_started.is_file()
    services = {service["name"]: service for service in payload["services"]}
    assert services["weixin"]["running"] is True
    assert services["weixin"]["ready"] is False
    assert services["feishu"]["running"] is True
    assert services["feishu"]["ready"] is False


@pytest.mark.skipif(os.name != "nt", reason="supervisor process identity uses Windows CIM")
def test_database_unready_keeps_configured_durable_bridges_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "database-unready-cold-start"
    weixin_started, feishu_started = _prepare_offline_managed_services(
        root, providers_ready=True, database_ready=False
    )
    port = _free_loopback_port()
    monkeypatch.setenv("FEISHU_APP_ID", "offline-app-id")
    monkeypatch.setenv("FEISHU_APP_SECRET", "offline-app-secret")
    supervisor = _start_offline_supervisor(root, port)
    status: subprocess.CompletedProcess[str] | None = None
    try:
        log_file = root / "data" / "logs" / "supervisor.log"

        def database_unready_logged() -> bool:
            log_text = (
                log_file.read_text(encoding="utf-8-sig", errors="replace")
                if log_file.is_file()
                else ""
            )
            return "database_unready" in log_text

        _wait_for_offline_supervisor_handshake(
            supervisor,
            database_unready_logged,
            description="database_unready health handshake",
        )
        status = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(root),
            "-EnginePort",
            str(port),
            "-Json",
            timeout_seconds=90,
        )
    finally:
        _stop_offline_supervisor(
            supervisor, root, port, command_timeout_seconds=90
        )

    assert status is not None and status.returncode == 0, (
        "" if status is None else status.stderr or status.stdout
    )
    payload = json.loads(status.stdout)
    assert payload["engine_health"]["state"] == "database_unready"
    assert payload["engine_health"]["ready"] is False
    assert not weixin_started.exists()
    assert not feishu_started.exists()
    services = {service["name"]: service for service in payload["services"]}
    assert services["weixin"]["running"] is False
    assert services["feishu"]["running"] is False


def test_dry_run_plans_weixin_when_saved_login_exists_without_leaking_token(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "ilink_token.json").write_text(
        json.dumps({"bot_token": "super-secret-bot-token"}), encoding="utf-8"
    )

    result = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Once",
        "-DryRun",
        "-Json",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    weixin = next(service for service in payload["services"] if service["name"] == "weixin")
    assert weixin == {
        "name": "weixin",
        "configured": True,
        "running": False,
        "ready": False,
        "action": "would-start",
    }
    assert "super-secret-bot-token" not in result.stdout


def test_dry_run_recognizes_dpapi_weixin_login_envelope(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "ilink_token.json").write_text(
        json.dumps(
            {
                "schema": "nachuan.protected-json.v1",
                "protection": "windows-dpapi-current-user",
                "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA==",
            }
        ),
        encoding="utf-8",
    )

    result = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Once",
        "-DryRun",
        "-Json",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    weixin = next(service for service in payload["services"] if service["name"] == "weixin")
    assert weixin["configured"] is True
    assert weixin["action"] == "would-start"


def test_dry_run_rejects_empty_weixin_login_and_unverified_backup_directory(
    tmp_path: Path,
):
    data = tmp_path / "data"
    (data / "backup" / "sqlite" / "not-a-snapshot").mkdir(parents=True)
    (data / "ilink_token.json").write_text("{}", encoding="utf-8")

    result = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Once",
        "-DryRun",
        "-Json",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    weixin = next(service for service in payload["services"] if service["name"] == "weixin")
    assert weixin["configured"] is False
    assert weixin["action"] == "none"
    assert payload["backup"]["available"] is False


def test_windows_powershell_script_has_utf8_bom() -> None:
    assert SCRIPT.read_bytes().startswith(b"\xef\xbb\xbf")


def test_managed_python_forces_utf8_before_isolated_mode_ignores_environment() -> None:
    source = SCRIPT.read_text(encoding="utf-8-sig")

    assert "$psi.Arguments = '-X utf8 -I -S {0}'" in source
    assert "\\s+-X\\s+utf8\\s+-I\\s+-S\\s+-u" in source
    assert "Modules\\CimCmdlets\\CimCmdlets.psd1" in source
    assert "Import-Module -Name $CimModuleManifest -ErrorAction Stop" in source


def test_media_validation_accepts_only_exact_closed_binary_directory(tmp_path: Path):
    data = tmp_path / "data"
    binaries = tmp_path / "static-media"
    data.mkdir()
    binaries.mkdir()
    ffmpeg = binaries / "ffmpeg.exe"
    ffprobe = binaries / "ffprobe.exe"
    ffmpeg.write_bytes(b"synthetic-ffmpeg")
    ffprobe.write_bytes(b"synthetic-ffprobe")
    config = {
        "schema": "nachuan.media-binaries.v1",
        "ffmpeg_bin": str(ffmpeg.resolve()),
        "ffmpeg_sha256": hashlib.sha256(ffmpeg.read_bytes()).hexdigest(),
        "ffprobe_bin": str(ffprobe.resolve()),
        "ffprobe_sha256": hashlib.sha256(ffprobe.read_bytes()).hexdigest(),
    }
    (data / "media-binaries.json").write_text(json.dumps(config), encoding="utf-8")

    valid = _run_supervisor("-Action", "Validate", "-Root", str(tmp_path), "-Json")
    assert valid.returncode == 0, valid.stderr or valid.stdout
    assert json.loads(valid.stdout)["media"] == {
        "configured": True,
        "ffmpeg_sha256": config["ffmpeg_sha256"],
        "ffprobe_sha256": config["ffprobe_sha256"],
    }

    (binaries / "version.dll").write_bytes(b"sidecar")
    rejected = _run_supervisor("-Action", "Validate", "-Root", str(tmp_path), "-Json")
    assert rejected.returncode != 0
    assert "sidecar" in (rejected.stderr + rejected.stdout).lower()


def test_backup_health_accepts_verified_snapshot_and_rejects_tampering(tmp_path: Path):
    data = tmp_path / "data"
    scripts = tmp_path / "scripts"
    data.mkdir()
    scripts.mkdir()
    shutil.copy2(SCRIPT.parent / "sqlite_backup.py", scripts / "sqlite_backup.py")
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    _link_test_venv(tmp_path)

    database = data / "memory.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE memory (value TEXT NOT NULL)")
    connection.execute("INSERT INTO memory VALUES ('verified')")
    connection.commit()
    connection.close()
    snapshot = backup_databases(data, data / "backup" / "sqlite")

    args = (
        "-Action",
        "Status",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Json",
    )
    valid = _run_supervisor(*args)

    assert valid.returncode == 0, valid.stderr or valid.stdout
    valid_health = json.loads(valid.stdout)["backup"]
    assert valid_health["available"] is True
    assert valid_health["verified"] is True
    assert valid_health["state"] == "verified"
    assert valid_health["database_count"] == 1
    assert valid_health["snapshot"] == snapshot.snapshot_dir.name

    with (snapshot.snapshot_dir / "memory.db").open("ab") as stream:
        stream.write(b"tampered")
    invalid = _run_supervisor(*args)

    assert invalid.returncode == 0, invalid.stderr or invalid.stdout
    invalid_health = json.loads(invalid.stdout)["backup"]
    assert invalid_health["available"] is False
    assert invalid_health["verified"] is False
    assert invalid_health["state"] == "invalid"


def test_one_shot_first_start_creates_and_reports_verified_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "纳川 root with spaces"
    data = root / "data"
    scripts = root / "scripts"
    data.mkdir(parents=True)
    scripts.mkdir()
    shutil.copy2(SCRIPT.parent / "sqlite_backup.py", scripts / "sqlite_backup.py")
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    _link_test_venv(root)
    connection = sqlite3.connect(data / "proof.db")
    connection.execute("CREATE TABLE proof (value TEXT NOT NULL)")
    connection.execute("INSERT INTO proof VALUES ('verified')")
    connection.commit()
    connection.close()
    old_weixin_key = "sk-bridge-weixin-" + "1" * 64
    old_feishu_key = "sk-bridge-feishu-" + "2" * 64
    (data / "weixin_bridge_api_key.txt").write_text(old_weixin_key, encoding="ascii")
    (data / "feishu_bridge_api_key.txt").write_text(old_feishu_key, encoding="ascii")

    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    monkeypatch.delenv("GATEWAY_API_KEYS", raising=False)
    monkeypatch.delenv("APPROVAL_ADMIN_KEY", raising=False)
    monkeypatch.delenv("FEISHU_APP_ID", raising=False)
    monkeypatch.delenv("FEISHU_APP_SECRET", raising=False)
    try:
        result = _run_supervisor(
            "-Action",
            "Run",
            "-Root",
            str(root),
            "-EnginePort",
            str(server.server_address[1]),
            "-Once",
            "-Json",
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    backup_debug = []
    for name in ("backup.err.log", "backup.out.log", "supervisor.log"):
        path = data / "logs" / name
        if path.is_file():
            backup_debug.append(
                f"{name}: {path.read_text(encoding='utf-8-sig', errors='replace')[-4000:]}"
            )
    assert result.returncode == 0, "\n".join(
        [result.stderr or result.stdout, *backup_debug]
    )
    payload = json.loads(result.stdout)
    assert payload["backup"]["available"] is True
    assert payload["backup"]["verified"] is True
    assert payload["backup"]["database_count"] == 1
    snapshot = data / "backup" / "sqlite" / payload["backup"]["snapshot"]
    assert (snapshot / "manifest.json").is_file()
    assert "sqlite backup completed and verified" in (data / "logs" / "supervisor.log").read_text(
        encoding="utf-8-sig"
    )
    gateway_key = (data / "gateway_api_key.txt").read_text(encoding="ascii")
    approval_key_path = data / "approval_admin_key.txt"
    approval_key = approval_key_path.read_text(encoding="ascii")
    weixin_bridge_key_path = data / "weixin_bridge_api_key.txt"
    feishu_bridge_key_path = data / "feishu_bridge_api_key.txt"
    boot_token_path = data / "engine_boot_token.txt"
    assert gateway_key.startswith("sk-local-")
    assert approval_key.startswith("sk-approval-")
    assert approval_key != gateway_key
    rotated_weixin_key = weixin_bridge_key_path.read_text("ascii")
    rotated_feishu_key = feishu_bridge_key_path.read_text("ascii")
    assert rotated_weixin_key.startswith("sk-bridge-v2-weixin-")
    assert rotated_feishu_key.startswith("sk-bridge-v2-feishu-")
    assert rotated_weixin_key != old_weixin_key
    assert rotated_feishu_key != old_feishu_key
    assert rotated_weixin_key != rotated_feishu_key
    assert len(boot_token_path.read_text("ascii")) == 64
    for secret_path in (
        data / "gateway_api_key.txt",
        approval_key_path,
        weixin_bridge_key_path,
        feishu_bridge_key_path,
        boot_token_path,
    ):
        acl_result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-Command",
                    "$item=[IO.FileInfo]::new($env:NACHUAN_TEST_SECRET_PATH); "
                    "$acl=$item.GetAccessControl(); "
                "[pscustomobject]@{protected=$acl.AreAccessRulesProtected; "
                "access_count=@($acl.Access).Count} | ConvertTo-Json -Compress",
            ],
            env={**os.environ, "NACHUAN_TEST_SECRET_PATH": str(secret_path)},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        assert acl_result.returncode == 0, acl_result.stderr or acl_result.stdout
        secret_acl = json.loads(acl_result.stdout)
        assert secret_acl == {"protected": True, "access_count": 1}
    assert not (data / "nachuan-supervisor.pid").exists()


def test_engine_health_is_not_ready_without_a_root_bound_process(tmp_path: Path):
    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            body = json.dumps({"status": "ok", "pid": os.getpid()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            str(server.server_address[1]),
            "-Json",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    engine = next(service for service in payload["services"] if service["name"] == "engine")
    assert engine["running"] is False
    assert engine["ready"] is False
    assert payload["engine_health"]["state"] == "process_missing"


def test_engine_health_rejects_marker_only_process_even_when_it_is_under_root(tmp_path: Path):
    _link_test_venv(tmp_path)
    helper = tmp_path / "bound_health.py"
    helper.write_text(
        """
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"status": "ok", "pid": os.getpid()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        return

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(f"{os.getpid()} {server.server_address[1]}", flush=True)
server.serve_forever()
""".strip(),
        encoding="utf-8",
    )
    bound = subprocess.Popen(
        [
            str(tmp_path / ".venv" / "Scripts" / "python.exe"),
            str(helper),
            "gateway.app",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        assert bound.stdout is not None
        identity_line = bound.stdout.readline().strip()
        assert identity_line, bound.stderr.read() if bound.stderr else ""
        _health_pid, port = (int(value) for value in identity_line.split())
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            str(port),
            "-Json",
        )
        assert result.returncode == 0, result.stderr or result.stdout
        payload = json.loads(result.stdout)
        engine = next(service for service in payload["services"] if service["name"] == "engine")
        assert engine["running"] is False
        assert engine["ready"] is False
        assert payload["engine_health"]["state"] == "process_missing"
    finally:
        bound.terminate()
        try:
            bound.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bound.kill()
            bound.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Windows venv launchers use a child base-Python process")
def test_engine_health_accepts_attested_descendant_of_exact_managed_launcher(tmp_path: Path):
    _link_test_venv(tmp_path)
    token = "a" * 64
    port = _free_loopback_port()
    launcher = _start_attested_managed_engine(tmp_path, port=port, token=token)
    try:
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            str(port),
            "-Json",
        )

        assert result.returncode == 0, result.stderr or result.stdout
        health = json.loads(result.stdout)["engine_health"]
        assert health["state"] == "ready"
        assert health["attested"] is True
        assert health["pid"] != launcher.pid
        assert launcher.pid in health["managed_pids"]
        assert health["pid"] in health["managed_pids"]
    finally:
        launcher.terminate()
        try:
            launcher.wait(timeout=5)
        except subprocess.TimeoutExpired:
            launcher.kill()
            launcher.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Windows venv launchers use a child base-Python process")
def test_engine_health_rejects_unready_required_financial_ledger(tmp_path: Path):
    _link_test_venv(tmp_path)
    port = _free_loopback_port()
    launcher = _start_attested_managed_engine(
        tmp_path,
        port=port,
        token="d" * 64,
        financial_ready=False,
    )
    try:
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            str(port),
            "-Json",
        )
        assert result.returncode == 0, result.stderr or result.stdout
        health = json.loads(result.stdout)["engine_health"]
        assert health["state"] == "financial_ledger_unready"
        assert health["ready"] is False
        assert health["restart_recommended"] is False
    finally:
        launcher.terminate()
        try:
            launcher.wait(timeout=5)
        except subprocess.TimeoutExpired:
            launcher.kill()
            launcher.wait(timeout=5)


def test_engine_health_rejects_exact_launcher_when_boot_proof_does_not_match(
    tmp_path: Path,
):
    _link_test_venv(tmp_path)
    port = _free_loopback_port()
    launcher = _start_attested_managed_engine(tmp_path, port=port, token="b" * 64)
    try:
        (tmp_path / "data" / "engine_boot_token.txt").write_text("c" * 64, "ascii")
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            str(port),
            "-Json",
        )
        assert result.returncode == 0, result.stderr or result.stdout
        health = json.loads(result.stdout)["engine_health"]
        assert health["state"] == "attestation_mismatch"
        assert health["attested"] is False
        assert health["ready"] is False
    finally:
        launcher.terminate()
        try:
            launcher.wait(timeout=5)
        except subprocess.TimeoutExpired:
            launcher.kill()
            launcher.wait(timeout=5)


def test_project_process_matching_rejects_sibling_prefix_paths(tmp_path: Path):
    root = tmp_path / "nachuan"
    sibling = tmp_path / "nachuan-copy"
    root.mkdir()
    sibling.mkdir()
    helper = sibling / "sleeper.py"
    helper.write_text("import time; time.sleep(60)\n", encoding="utf-8")
    process = subprocess.Popen([sys.executable, str(helper), "gateway.app"])
    try:
        result = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(root),
            "-EnginePort",
            "65431",
            "-Json",
        )

        assert result.returncode == 0, result.stderr or result.stdout
        payload = json.loads(result.stdout)
        assert payload["services"][0]["running"] is False
        assert payload["engine_health"]["state"] == "process_missing"
        assert process.poll() is None
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _weixin_health(pid: int, **overrides) -> dict:
    now = time.time()
    document = {
        "schema": "nachuan.weixin-bridge-health.v1",
        "state": "healthy",
        "ready": True,
        "connected": True,
        "fresh": True,
        "pid": pid,
        "updated_at": now,
        "heartbeat_at": now,
        "fresh_until": now + 30,
        "freshness_ttl_seconds": 30,
        "pending_inbound": 0,
        "pending_outbound": 0,
        "dead_inbound": 0,
        "dead_outbound": 0,
        "oldest_processing_age_seconds": 0.0,
        "consecutive_poll_failures": 0,
        "last_error_code": "",
        "access_configured": True,
        "bridge_key_configured": True,
        "engine_available": True,
        "readiness_reasons": [],
    }
    document.update(overrides)
    return document


def test_weixin_alive_stuck_processing_is_restarted_in_order_without_real_processes():
    result = _run_supervisor_function(
        "Invoke-WeixinWatchdog",
        r"""
$UnhealthyThreshold = 3
$script:Unhealthy = @{ weixin = 0 }
$script:StartAttempt = @{ weixin = 0 }
$script:NextStartAt = @{ weixin = [DateTimeOffset]::MinValue }
$script:Operations = @()
function Test-WeixinConfigured { return $true }
function Get-WeixinHealth {
    return [pscustomobject]@{
        pid = 4242
        fresh = $true
        ready = $false
        processing_stuck = $true
        oldest_processing_age_seconds = 361.0
        consecutive_poll_failures = 0
        state = 'healthy'
        reason = 'pending_inbound,processing_stuck'
    }
}
function Test-ManagedPythonPid { return $true }
function Stop-ProjectProcesses {
    param([string[]]$Markers, [string]$Service)
    $script:Operations += "stop:$Service"
}
function Start-ManagedProcess {
    param([string]$Name)
    $script:Operations += "start:$Name"
    return $true
}
function Write-SupervisorLog { param([string]$Message) }
Invoke-WeixinWatchdog @([pscustomobject]@{ ProcessId = 4242 })
[pscustomobject]@{
    operations = @($script:Operations)
    unhealthy = [int]$script:Unhealthy.weixin
} | ConvertTo-Json -Compress
""",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert json.loads(result.stdout) == {
        "operations": ["stop:weixin", "start:weixin"],
        "unhealthy": 0,
    }


def test_weixin_alive_normal_processing_is_not_restarted():
    result = _run_supervisor_function(
        "Invoke-WeixinWatchdog",
        r"""
$UnhealthyThreshold = 3
$script:Unhealthy = @{ weixin = 2 }
$script:StartAttempt = @{ weixin = 0 }
$script:NextStartAt = @{ weixin = [DateTimeOffset]::MinValue }
$script:Operations = @()
function Test-WeixinConfigured { return $true }
function Get-WeixinHealth {
    return [pscustomobject]@{
        pid = 4242
        fresh = $true
        ready = $false
        processing_stuck = $false
        oldest_processing_age_seconds = 360.0
        consecutive_poll_failures = 0
        state = 'healthy'
        reason = 'pending_inbound'
    }
}
function Test-ManagedPythonPid { return $true }
function Stop-ProjectProcesses {
    param([string[]]$Markers, [string]$Service)
    $script:Operations += "stop:$Service"
}
function Start-ManagedProcess {
    param([string]$Name)
    $script:Operations += "start:$Name"
    return $true
}
function Write-SupervisorLog { param([string]$Message) }
Invoke-WeixinWatchdog @([pscustomobject]@{ ProcessId = 4242 })
[pscustomobject]@{
    operations = @($script:Operations)
    unhealthy = [int]$script:Unhealthy.weixin
} | ConvertTo-Json -Compress
""",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert json.loads(result.stdout) == {"operations": [], "unhealthy": 0}


def test_weixin_pending_or_dead_work_is_fresh_but_not_ready(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "ilink_token.json").write_text(
        json.dumps({"bot_token": "configured-token"}), encoding="utf-8"
    )
    (data / "weixin_bridge_health.json").write_text(
        json.dumps(
            _weixin_health(
                424242,
                ready=False,
                pending_inbound=1,
                pending_outbound=2,
                dead_inbound=3,
                dead_outbound=4,
            )
        ),
        encoding="utf-8",
    )

    result = _run_supervisor(
        "-Action",
        "Status",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Json",
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    health = payload["weixin_health"]
    assert health["fresh"] is True
    assert health["ready"] is False
    assert health["pending_inbound"] == 1
    assert health["pending_outbound"] == 2
    assert health["dead_inbound"] == 3
    assert health["dead_outbound"] == 4
    assert "dead_inbound" in health["reason"]
    weixin = next(service for service in payload["services"] if service["name"] == "weixin")
    assert weixin["running"] is False
    assert weixin["ready"] is False


def test_weixin_processing_age_is_stuck_only_above_conservative_claim_threshold(
    tmp_path: Path,
):
    data = tmp_path / "data"
    data.mkdir()
    (data / "ilink_token.json").write_text(
        json.dumps({"bot_token": "configured-token"}), encoding="utf-8"
    )
    health_file = data / "weixin_bridge_health.json"

    health_file.write_text(
        json.dumps(
            _weixin_health(
                424242,
                ready=False,
                pending_inbound=1,
                oldest_processing_age_seconds=360.0,
            )
        ),
        encoding="utf-8",
    )
    normal = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )
    assert normal.returncode == 0, normal.stderr or normal.stdout
    normal_health = json.loads(normal.stdout)["weixin_health"]
    assert normal_health["oldest_processing_age_seconds"] == 360.0
    assert normal_health["processing_stuck"] is False
    assert "processing_stuck" not in normal_health["reason"]

    health_file.write_text(
        json.dumps(
            _weixin_health(
                424242,
                ready=False,
                pending_inbound=1,
                oldest_processing_age_seconds=360.001,
            )
        ),
        encoding="utf-8",
    )
    stuck = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )
    assert stuck.returncode == 0, stuck.stderr or stuck.stdout
    stuck_health = json.loads(stuck.stdout)["weixin_health"]
    assert stuck_health["processing_stuck"] is True
    assert "processing_stuck" in stuck_health["reason"]


def test_weixin_processing_age_must_be_a_finite_non_negative_json_number(
    tmp_path: Path,
):
    data = tmp_path / "data"
    data.mkdir()
    health_file = data / "weixin_bridge_health.json"

    for invalid_age in (-0.001, "NaN", "1.0", None):
        health_file.write_text(
            json.dumps(
                _weixin_health(
                    424242, oldest_processing_age_seconds=invalid_age
                )
            ),
            encoding="utf-8",
        )
        rejected = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            "65431",
            "-Json",
        )
        assert rejected.returncode == 0, rejected.stderr or rejected.stdout
        health = json.loads(rejected.stdout)["weixin_health"]
        assert health["state"] == "invalid"
        assert health["ready"] is False
        assert health["processing_stuck"] is False


def test_weixin_health_rejects_static_fresh_future_or_negative_fields(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    health_file = data / "weixin_bridge_health.json"
    expired = _weixin_health(
        1234,
        updated_at=time.time() - 120,
        fresh_until=time.time() - 60,
        freshness_ttl_seconds=60,
        fresh=True,
    )
    health_file.write_text(json.dumps(expired), encoding="utf-8")
    stale = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )
    assert stale.returncode == 0, stale.stderr or stale.stdout
    stale_health = json.loads(stale.stdout)["weixin_health"]
    assert stale_health["fresh"] is False
    assert stale_health["ready"] is False
    assert "stale" in stale_health["reason"]

    invalid = _weixin_health(1234, pending_inbound=-1)
    health_file.write_text(json.dumps(invalid), encoding="utf-8")
    rejected = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )
    assert rejected.returncode == 0, rejected.stderr or rejected.stdout
    assert json.loads(rejected.stdout)["weixin_health"]["state"] == "invalid"


def _feishu_health(pid: int, **overrides) -> dict:
    now = time.time()
    document = {
        "schema": "nachuan.feishu-bridge-health.v1",
        "state": "healthy",
        "ready": True,
        "connected": True,
        "fresh": True,
        "pid": pid,
        "updated_at": now,
        "heartbeat_at": now,
        "fresh_until": now + 10,
        "freshness_ttl_seconds": 10,
        "pending_inbound": 0,
        "pending_outbound": 0,
        "dead_inbound": 0,
        "dead_outbound": 0,
        "consecutive_reconnect_failures": 0,
        "last_connected_at": now,
        "last_event_received_at": 0,
        "last_message_finished_at": 0,
        "last_error_code": "",
        "access_configured": True,
        "bridge_key_configured": True,
        "engine_available": True,
        "readiness_reasons": [],
    }
    document.update(overrides)
    return document


@pytest.mark.parametrize(
    ("overrides", "expected_reason"),
    [
        ({"access_configured": False}, "access_locked"),
        ({"bridge_key_configured": False}, "bridge_key_missing"),
        ({"engine_available": False}, "engine_unavailable"),
    ],
)
def test_feishu_health_requires_access_key_and_authenticated_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict,
    expected_reason: str,
):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("FEISHU_APP_ID", "test-app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "test-secret")
    (data / "feishu_bridge_health.json").write_text(
        json.dumps(_feishu_health(424242, **overrides)), encoding="utf-8"
    )

    result = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )

    assert result.returncode == 0, result.stderr or result.stdout
    health = json.loads(result.stdout)["feishu_health"]
    assert health["ready"] is False
    assert health[next(iter(overrides))] is False
    assert expected_reason in health["reason"]


@pytest.mark.parametrize(
    "field",
    ["fresh", "access_configured", "bridge_key_configured", "engine_available"],
)
def test_feishu_health_security_flags_must_be_json_booleans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("FEISHU_APP_ID", "test-app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "test-secret")
    (data / "feishu_bridge_health.json").write_text(
        json.dumps(_feishu_health(424242, **{field: 1})), encoding="utf-8"
    )

    result = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )

    assert result.returncode == 0, result.stderr or result.stdout
    health = json.loads(result.stdout)["feishu_health"]
    assert health["state"] == "invalid"
    assert health["ready"] is False


def test_feishu_health_never_trusts_static_fresh_or_an_unbound_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("FEISHU_APP_ID", "test-app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "test-secret")
    expired = _feishu_health(
        424242,
        fresh=True,
        fresh_until=time.time() - 1,
    )
    (data / "feishu_bridge_health.json").write_text(
        json.dumps(expired), encoding="utf-8"
    )

    result = _run_supervisor(
        "-Action", "Status", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    health = payload["feishu_health"]
    assert health["fresh"] is False
    assert health["ready"] is False
    assert "stale" in health["reason"]
    assert "process_unbound" in health["reason"]
    feishu = next(service for service in payload["services"] if service["name"] == "feishu")
    assert feishu == {
        "name": "feishu",
        "configured": True,
        "running": False,
        "ready": False,
        "action": "none",
    }


@pytest.mark.skipif(os.name != "nt", reason="supervisor process identity uses Windows CIM")
def test_feishu_marker_only_process_cannot_bind_otherwise_fresh_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    data = tmp_path / "data"
    data.mkdir()
    _link_test_venv(tmp_path)
    helper = tmp_path / "feishu_health_holder.py"
    helper.write_text(
        "import os, time\nprint(os.getpid(), flush=True)\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [
            str(tmp_path / ".venv" / "Scripts" / "python.exe"),
            str(helper),
            "run_feishu_bridge.py",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        assert process.stdout is not None
        health_pid = int(process.stdout.readline().strip())
        (data / "feishu_bridge_health.json").write_text(
            json.dumps(_feishu_health(health_pid)), encoding="utf-8"
        )
        monkeypatch.setenv("FEISHU_APP_ID", "test-app")
        monkeypatch.setenv("FEISHU_APP_SECRET", "test-secret")

        ready = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            "65431",
            "-Json",
        )
        assert ready.returncode == 0, ready.stderr or ready.stdout
        payload = json.loads(ready.stdout)
        health = payload["feishu_health"]
        feishu = next(
            service for service in payload["services"] if service["name"] == "feishu"
        )
        assert health["fresh"] is True
        assert health["connected"] is True
        assert health["process_bound"] is False
        assert health["ready"] is False
        assert "process_unbound" in health["reason"]
        assert feishu["running"] is False
        assert feishu["ready"] is False

        queued = _feishu_health(health_pid, pending_outbound=1, ready=False)
        (data / "feishu_bridge_health.json").write_text(
            json.dumps(queued), encoding="utf-8"
        )
        degraded = _run_supervisor(
            "-Action",
            "Status",
            "-Root",
            str(tmp_path),
            "-EnginePort",
            "65431",
            "-Json",
        )
        assert degraded.returncode == 0, degraded.stderr or degraded.stdout
        degraded_health = json.loads(degraded.stdout)["feishu_health"]
        assert degraded_health["fresh"] is True
        assert degraded_health["process_bound"] is False
        assert degraded_health["ready"] is False
        assert "pending_outbound" in degraded_health["reason"]
        assert "reported_not_ready" in degraded_health["reason"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_stop_refuses_to_kill_pid_not_owned_by_this_root(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    sleeper = subprocess.Popen(
        [POWERSHELL, "-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        (data / "nachuan-supervisor.pid").write_text(str(sleeper.pid), encoding="ascii")
        result = _run_supervisor(
            "-Action", "Stop", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert sleeper.poll() is None
    finally:
        sleeper.terminate()
        try:
            sleeper.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sleeper.kill()
            sleeper.wait(timeout=5)


def test_stop_latch_blocks_restart_before_any_key_or_process_start(tmp_path: Path):
    stopped = _run_supervisor(
        "-Action", "Stop", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )
    assert stopped.returncode == 0, stopped.stderr or stopped.stdout
    latch = tmp_path / "data" / "nachuan-supervisor.stop.json"
    assert latch.is_file()

    restarted = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Once",
        "-Json",
    )
    assert restarted.returncode == 0, restarted.stderr or restarted.stdout
    payload = json.loads(restarted.stdout)
    assert payload["supervisor"]["suspended"] is True
    assert not (tmp_path / "data" / "gateway_api_key.txt").exists()


def test_scheduled_production_refuses_an_alternate_source_root(tmp_path: Path):
    result = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(tmp_path),
        "-EnginePort",
        "65431",
        "-Once",
        "-Scheduled",
        "-Json",
    )
    assert result.returncode != 0
    assert "refuses an alternate project root" in (result.stderr + result.stdout)


@pytest.mark.skipif(os.name != "nt", reason="junction validation is Windows-specific")
def test_supervisor_rejects_a_junction_project_root_before_touching_target(tmp_path: Path):
    target = tmp_path / "real-root"
    linked = tmp_path / "linked-root"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    made = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(target)],
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
    )
    if made.returncode:
        pytest.skip(f"could not create junction: {made.stderr}")

    result = _run_supervisor(
        "-Action", "Status", "-Root", str(linked), "-EnginePort", "65431", "-Json"
    )
    assert result.returncode != 0
    assert "reparse point" in (result.stderr + result.stdout).lower()
    assert sentinel.read_text("utf-8") == "untouched"
    assert not (target / "data").exists()


@pytest.mark.skipif(os.name != "nt", reason="junction validation is Windows-specific")
def test_supervisor_rejects_a_junction_data_root_before_creating_logs(tmp_path: Path):
    root = tmp_path / "project"
    target = tmp_path / "redirect-target"
    root.mkdir()
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    made = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(root / "data"), str(target)],
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
    )
    if made.returncode:
        pytest.skip(f"could not create junction: {made.stderr}")

    result = _run_supervisor(
        "-Action", "Stop", "-Root", str(root), "-EnginePort", "65431", "-Json"
    )
    assert result.returncode != 0
    assert "reparse point" in (result.stderr + result.stdout).lower()
    assert sentinel.read_text("utf-8") == "untouched"
    assert not (target / "logs").exists()
    assert not (target / "nachuan-supervisor.stop.json").exists()


def test_python_helpers_and_wrapper_ignore_ambient_pythonpath_before_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "clean-bootstrap"
    data = root / "data"
    scripts = root / "scripts"
    poison = tmp_path / "poison"
    data.mkdir(parents=True)
    scripts.mkdir()
    poison.mkdir()
    shutil.copy2(SCRIPT.parent / "sqlite_backup.py", scripts / "sqlite_backup.py")
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    _link_test_venv(root)
    with sqlite3.connect(data / "proof.db") as connection:
        connection.execute("CREATE TABLE proof(value TEXT NOT NULL)")
        connection.execute("INSERT INTO proof VALUES ('ok')")
    sentinel = tmp_path / "sitecustomize-ran.txt"
    (poison / "sitecustomize.py").write_text(
        "import os\nopen(os.environ['NACHUAN_TEST_SENTINEL'], 'w').write('executed')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(poison))
    monkeypatch.setenv("NACHUAN_TEST_SENTINEL", str(sentinel))

    result = _run_supervisor(
        "-Action",
        "Run",
        "-Root",
        str(root),
        "-EnginePort",
        str(_free_loopback_port()),
        "-Once",
        "-Json",
    )
    assert result.returncode == 0, result.stderr or result.stdout
    time.sleep(0.5)
    assert not sentinel.exists()


def test_stop_hardens_existing_runtime_tree_to_current_user_and_system(tmp_path: Path):
    data = tmp_path / "data"
    nested = data / "logs" / "nested"
    nested.mkdir(parents=True)
    sensitive = nested / "channel.log"
    sensitive.write_text("personal message", encoding="utf-8")

    result = _run_supervisor(
        "-Action", "Stop", "-Root", str(tmp_path), "-EnginePort", "65431", "-Json"
    )

    assert result.returncode == 0, result.stderr or result.stdout
    acl_result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-Command",
            "$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18'); "
            "$items=@(Get-Item -LiteralPath $env:NACHUAN_TEST_DATA -Force) + "
            "@(Get-ChildItem -LiteralPath $env:NACHUAN_TEST_DATA -Force -Recurse); "
            "$rows=@($items | ForEach-Object { $acl=$_.GetAccessControl(); "
            "[pscustomobject]@{container=[bool]$_.PSIsContainer; protected=$acl.AreAccessRulesProtected; "
            "unexpected=@($acl.Access | Where-Object { $allowed -notcontains $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }).Count} }); "
            "$rows | ConvertTo-Json -Compress",
        ],
        env={**os.environ, "NACHUAN_TEST_DATA": str(data)},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    assert acl_result.returncode == 0, acl_result.stderr or acl_result.stdout
    rows = json.loads(acl_result.stdout)
    if isinstance(rows, dict):
        rows = [rows]
    assert rows
    assert all(row["unexpected"] == 0 for row in rows)
    assert all(row["protected"] is True for row in rows if row["container"])
    assert next(row for row in rows if row["container"] is False and row["protected"])[
        "unexpected"
    ] == 0


def test_running_supervisor_writes_bound_identity_and_stops_gracefully(tmp_path: Path):
    root = tmp_path / "bound root"
    data = root / "data"
    scripts = root / "scripts"
    data.mkdir(parents=True)
    scripts.mkdir()
    shutil.copy2(SCRIPT.parent / "sqlite_backup.py", scripts / "sqlite_backup.py")
    shutil.copy2(MANAGED_LAUNCHER, scripts / "managed_launcher.py")
    _link_test_venv(root)
    connection = sqlite3.connect(data / "proof.db")
    connection.execute("CREATE TABLE proof(value TEXT NOT NULL)")
    connection.execute("INSERT INTO proof VALUES ('ok')")
    connection.commit()
    connection.close()

    supervisor = subprocess.Popen(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Action",
            "Run",
            "-Root",
            str(root),
            "-EnginePort",
            "65431",
            "-PollSeconds",
            "2",
            "-Json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    pid_file = data / "nachuan-supervisor.pid"
    try:
        # This is a cross-process identity handshake, not a 15-second startup
        # SLO.  The longer bound is only a local deadlock watchdog; under a
        # loaded Windows shard the valid pid commit has been observed at 19s.
        _wait_for_process_file_handshake(
            supervisor,
            pid_file,
            description="running supervisor pid handshake",
            timeout_seconds=45,
        )
        identity = json.loads(pid_file.read_text(encoding="utf-8-sig"))
        assert identity["schema"] == "nachuan.supervisor.v1"
        assert identity["pid"] == supervisor.pid
        assert Path(identity["root"]) == root
        assert identity["instance_id"]
        assert identity["command_line_sha256"]

        duplicate = _run_supervisor(
            "-Action",
            "Run",
            "-Root",
            str(root),
            "-EnginePort",
            "65431",
            "-Once",
            "-Json",
            timeout_seconds=90,
        )
        assert duplicate.returncode == 0, duplicate.stderr or duplicate.stdout
        assert supervisor.poll() is None
        after_duplicate = json.loads(pid_file.read_text(encoding="utf-8-sig"))
        assert after_duplicate["instance_id"] == identity["instance_id"]

        stopped = _run_supervisor(
            "-Action",
            "Stop",
            "-Root",
            str(root),
            "-EnginePort",
            "65431",
            "-Json",
            timeout_seconds=90,
        )
        assert stopped.returncode == 0, stopped.stderr or stopped.stdout
        supervisor_exit = supervisor.wait(timeout=45)
        supervisor_stdout = supervisor.stdout.read() if supervisor.stdout else ""
        supervisor_stderr = supervisor.stderr.read() if supervisor.stderr else ""
        assert supervisor_exit == 0, supervisor_stderr or supervisor_stdout
        assert not pid_file.exists()
        assert (data / "nachuan-supervisor.stop.json").is_file()
    finally:
        if supervisor.poll() is None:
            try:
                _run_supervisor(
                    "-Action",
                    "Stop",
                    "-Root",
                    str(root),
                    "-EnginePort",
                    "65431",
                    "-Json",
                    timeout_seconds=90,
                )
            except Exception:
                # Cleanup must still reach the verified Popen handle if the
                # production Stop probe itself cannot complete in this test.
                pass
        if supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait(timeout=10)
        for stream in (supervisor.stdout, supervisor.stderr):
            if stream is not None:
                stream.close()


def test_source_tree_cannot_register_a_persistent_logon_task(tmp_path: Path):
    result = _run_supervisor(
        "-Action",
        "InstallTask",
        "-Root",
        str(tmp_path),
        "-DryRun",
        "-Json",
    )

    assert result.returncode == 78
    assert "disabled for source-tree launches" in result.stderr

    script = SCRIPT.read_text("utf-8")
    launcher = (
        SCRIPT.parents[1] / "安装与维护" / "恢复并启动纳川.cmd"
    ).read_text("ascii")
    assert "Register-ScheduledTask" not in script
    assert "New-ScheduledTaskAction" not in script
    assert "-Action InstallTask" not in launcher


def test_supervisor_runs_verified_full_sqlite_backups() -> None:
    script = SCRIPT.read_text("utf-8")

    assert "scripts\\sqlite_backup.py" in script
    assert " backup --data-dir " in script
    assert " verify " in script
    assert "--keep 14" in script
    assert "WaitForExit(300000)" in script
    assert "sqlite backup failed during one-shot validation" in script
    assert "Global\\NachuanSupervisor-" in script
    assert "[IO.FileShare]::None" in script
    assert "if ($Scheduled)" in script
    assert "InstallTask is disabled for source-tree launches" in script


def test_supervisor_injects_a_nonpersistent_independent_paid_media_key() -> None:
    script = SCRIPT.read_text("utf-8")

    assert "function Ensure-PaidMediaApiKey" in script
    policy = script.split("function Ensure-PaidMediaApiKey", 1)[1].split(
        "function ", 1
    )[0]
    assert "New-CryptographicHex 32" in policy
    assert "NACHUAN_PAID_MEDIA_API_KEY" in policy
    assert "GATEWAY_API_KEYS" in policy
    assert "APPROVAL_ADMIN_KEY" in policy
    assert "Set-Content" not in policy
    assert "Add-Content" not in policy

    startup = script.split("# Key creation is inside the cross-session lock.", 1)[1]
    assert startup.index("Ensure-GatewayKey") < startup.index("Ensure-ApprovalAdminKey")
    assert startup.index("Ensure-ApprovalAdminKey") < startup.index(
        "Ensure-PaidMediaApiKey"
    )
    assert "'NACHUAN_PAID_MEDIA_API_KEY'" in script.split(
        "function Get-ManagedServiceEnvironment", 1
    )[1]
    assert "paid_media_api_key.txt" not in script.lower()
    assert "$PaidMediaKeyFile" not in script


def test_supervisor_injects_desktop_engine_session_authority_trio() -> None:
    """引擎的 Desktop Engine Session 启动门需要 supervisor 签发
    NACHUAN_ENGINE_GENERATION/NACHUAN_ENGINE_PORT/NACHUAN_ENGINE_BOOT_TOKEN。

    三元组必须由 supervisor 在引擎分支内直接赋值（继承值被 allowlist 排除），
    generation 在进程内单调递增，port 与监听端口一致。缺一时引擎拒启。
    """

    script = SCRIPT.read_text("utf-8")
    branch = script.split("function Get-ManagedServiceEnvironment", 1)[1].split(
        "function ", 1
    )[0]
    assert "$result['NACHUAN_ENGINE_GENERATION']" in branch
    assert "$result['NACHUAN_ENGINE_PORT']" in branch
    assert "$result['NACHUAN_ENGINE_BOOT_TOKEN']" in branch
    # 两个新值不得进入继承 allowlist：继承值被外层污染时绝不透传。
    allowlist = branch.split("$engineAllowed = @(", 1)[1].split(")", 1)[0]
    assert "NACHUAN_ENGINE_GENERATION" not in allowlist
    assert "NACHUAN_ENGINE_PORT" not in allowlist
    # 单调性守卫：同一 supervisor 进程内每次引擎启动签发新一代。
    assert "$script:EngineGenerationCounter + 1" in branch
    assert "'NACHUAN_ENGINE_GENERATION'" in branch
