from __future__ import annotations

import subprocess
import sys
import os
import re
import shutil
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from gateway.config import get_isolated_bridge_settings
from scripts.managed_launcher import build_child_environment


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "managed_launcher.py"


@pytest.mark.parametrize(
    ("service", "own_secret", "foreign_secret"),
    [
        ("weixin", "WEIXIN_MODEL", "FEISHU_APP_SECRET"),
        ("feishu", "FEISHU_APP_SECRET", "WEIXIN_OWNER"),
    ],
)
def test_channel_children_receive_only_their_own_channel_credentials(
    service: str, own_secret: str, foreign_secret: str
):
    source = {
        "SystemRoot": r"C:\Windows",
        "TEMP": r"C:\Temp",
        "GATEWAY_API_KEYS": "runtime-key",
        f"NACHUAN_{service.upper()}_BRIDGE_API_KEY": f"{service}-bridge-key",
        "APPROVAL_ADMIN_KEY": "approval-secret",
        "VOLCANO_API_KEY": "provider-secret",
        "FEISHU_APP_SECRET": "feishu-secret",
        "WEIXIN_MODEL": "agnes-flash",
        "WEIXIN_ALLOWED": "weixin-user",
        "WEIXIN_OWNER": "weixin-owner",
        "PYTHONPATH": r"C:\attacker",
        "PYTHONSTARTUP": r"C:\attacker\startup.py",
    }

    child = build_child_environment(service, source)

    assert own_secret in child
    assert foreign_secret not in child
    assert "WEIXIN_ALLOWED" not in child
    assert "WEIXIN_OWNER" not in child
    assert child["BRIDGE_API_KEY"] == f"{service}-bridge-key"
    assert "GATEWAY_API_KEYS" not in child
    assert "APPROVAL_ADMIN_KEY" not in child
    assert "VOLCANO_API_KEY" not in child
    assert "PYTHONPATH" not in child
    assert "PYTHONSTARTUP" not in child
    assert child["PYTHONUTF8"] == "1"


def test_engine_drops_channel_credentials_and_python_injection_hooks():
    child = build_child_environment(
        "engine",
        {
            "GATEWAY_API_KEYS": "runtime-key",
            "NACHUAN_WEIXIN_BRIDGE_API_KEY": "weixin-bridge-key",
            "NACHUAN_FEISHU_BRIDGE_API_KEY": "feishu-bridge-key",
            "APPROVAL_ADMIN_KEY": "approval-secret",
            "VOLCANO_API_KEY": "provider-secret",

            "NACHUAN_FAILOVER_STREAM_TOTAL_TIMEOUT": "900",
            "CLAUDE_CLI_PATH": r"C:\tools\claude.exe",
            "CLAUDE_CLI_SHA256": "c" * 64,
            "CLAUDE_CONFIG_DIR": r"C:\Users\developer\.claude",
            "FEISHU_APP_SECRET": "must-not-reach-engine",
            "WEIXIN_ALLOWED": "must-not-reach-engine",
            "TELEGRAM_BOT_TOKEN": "must-not-reach-engine",
            "PYTHONPATH": r"C:\attacker",
            "PYTHONINSPECT": "1",
            "PATH": r"C:\attacker",
            "COMSPEC": r"C:\attacker\cmd.exe",
            "HTTP_PROXY": "http://attacker.invalid:3128",
            "SSL_CERT_FILE": r"C:\attacker\root.pem",
        },
    )

    assert child["GATEWAY_API_KEYS"] == "runtime-key"
    assert child["APPROVAL_ADMIN_KEY"] == "approval-secret"
    assert child["VOLCANO_API_KEY"] == "provider-secret"
    assert child["NACHUAN_FAILOVER_STREAM_TOTAL_TIMEOUT"] == "900"
    assert "CLAUDE_CLI_PATH" not in child
    assert "CLAUDE_CLI_SHA256" not in child
    assert "CLAUDE_CONFIG_DIR" not in child
    assert child["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] == "required"
    assert Path(child["NACHUAN_PROVIDER_CALL_LEDGER_PATH"]) == (
        Path(__file__).resolve().parent.parent / "data" / "provider-calls.db"
    )
    assert child["NACHUAN_WEIXIN_BRIDGE_API_KEY"] == "weixin-bridge-key"
    assert child["NACHUAN_FEISHU_BRIDGE_API_KEY"] == "feishu-bridge-key"
    assert not any(name.startswith(("FEISHU_", "WEIXIN_", "TELEGRAM_")) for name in child)
    assert "PYTHONPATH" not in child
    assert "PYTHONINSPECT" not in child
    assert "attacker" not in child["PATH"].lower()
    assert "HTTP_PROXY" not in child
    assert "SSL_CERT_FILE" not in child
    if os.name == "nt":
        assert "attacker" not in child["COMSPEC"].lower()


def test_engine_launcher_passes_desktop_session_authority_trio():
    """Desktop Engine Session 启动门三元组必须能穿透 launcher 白名单。

    2026-08-18 红：supervisor 注入后引擎仍拒启，因为 launcher 的
    _ENGINE_ALLOWED_NAMES 漏掉 GENERATION/PORT，子进程环境被剥掉。
    """

    child = build_child_environment(
        "engine",
        {
            "GATEWAY_API_KEYS": "runtime-key",
            "NACHUAN_ENGINE_BOOT_TOKEN": "ab" * 32,
            "NACHUAN_ENGINE_GENERATION": "7",
            "NACHUAN_ENGINE_PORT": "8080",
        },
        engine_port=8080,
    )

    assert child["NACHUAN_ENGINE_BOOT_TOKEN"] == "ab" * 32
    assert child["NACHUAN_ENGINE_GENERATION"] == "7"
    assert child["NACHUAN_ENGINE_PORT"] == "8080"
    assert child["GATEWAY_PORT"] == "8080"


def test_engine_gets_an_independent_paid_media_capability_but_bridges_do_not():
    source = {
        "GATEWAY_API_KEYS": "runtime-key-a,runtime-key-b",
        "APPROVAL_ADMIN_KEY": "approval-secret",
        "NACHUAN_PAID_MEDIA_API_KEY": "sk-paid-media-" + "3" * 64,
        "NACHUAN_WEIXIN_BRIDGE_API_KEY": "weixin-bridge-key",
        "NACHUAN_FEISHU_BRIDGE_API_KEY": "feishu-bridge-key",
    }

    engine = build_child_environment("engine", source)
    paid_key = engine["NACHUAN_PAID_MEDIA_API_KEY"]

    assert re.fullmatch(r"sk-paid-media-[0-9a-f]{64}", paid_key)
    assert paid_key not in {"runtime-key-a", "runtime-key-b", "approval-secret"}
    for service in ("weixin", "feishu"):
        child = build_child_environment(service, source)
        assert "NACHUAN_PAID_MEDIA_API_KEY" not in child


def test_direct_engine_launcher_generates_a_paid_media_capability_when_absent():
    child = build_child_environment(
        "engine",
        {
            "GATEWAY_API_KEYS": "runtime-key",
            "APPROVAL_ADMIN_KEY": "approval-secret",
        },
    )

    paid_key = child["NACHUAN_PAID_MEDIA_API_KEY"]
    assert re.fullmatch(r"sk-paid-media-[0-9a-f]{64}", paid_key)
    assert paid_key not in {"runtime-key", "approval-secret"}


@pytest.mark.parametrize(
    ("paid_key", "runtime_keys", "approval_key"),
    [
        (
            "sk-paid-media-" + "4" * 64,
            "runtime-key,sk-paid-media-" + "4" * 64,
            "approval-secret",
        ),
        (
            "sk-paid-media-" + "5" * 64,
            "runtime-key",
            "sk-paid-media-" + "5" * 64,
        ),
        ("not-a-high-entropy-paid-key", "runtime-key", "approval-secret"),
    ],
)
def test_engine_launcher_rejects_overlapping_or_malformed_paid_media_capability(
    paid_key: str,
    runtime_keys: str,
    approval_key: str,
):
    with pytest.raises(ValueError, match="paid media capability"):
        build_child_environment(
            "engine",
            {
                "GATEWAY_API_KEYS": runtime_keys,
                "APPROVAL_ADMIN_KEY": approval_key,
                "NACHUAN_PAID_MEDIA_API_KEY": paid_key,
            },
        )


def test_launcher_rejects_arbitrary_service_or_marker_without_spawning():
    for arguments in (
        ("unknown", "gateway.app", "8080", "1", "1"),
        ("engine", "other.module", "8080", "1", "1"),
        ("engine", "gateway.app", "0", "1", "1"),
        ("engine", "gateway.app", "08080", "1", "1"),
    ):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        assert result.returncode == 64
        assert "rejected" in result.stderr


@pytest.mark.parametrize("service", ["weixin", "feishu"])
def test_managed_bridge_environment_forces_production_loopback_and_private_state(
    service: str,
):
    child = build_child_environment(
        service,
        {
            "BRIDGE_ENGINE_URL": "https://attacker.invalid/steal?token=1",
            "USAGE_DB_PATH": r"C:\Public\outside.db",
            "DATA_DIR": r"C:\Public",
            "NACHUAN_ENV": "development",
            f"{service.upper()}_ALLOW_ALL": "1",
            "HTTP_PROXY": "http://attacker.invalid:3128",
            "HTTPS_PROXY": "http://attacker.invalid:3128",
            "ALL_PROXY": "socks5://attacker.invalid:1080",
            f"NACHUAN_{service.upper()}_BRIDGE_API_KEY": "scoped-key",
        },
        engine_port=49152,
    )

    root = SCRIPT.parents[1]
    assert child["BRIDGE_ENGINE_URL"] == "http://127.0.0.1:49152"
    assert Path(child["USAGE_DB_PATH"]) == root / "data" / "usage.db"
    assert Path(child["DATA_DIR"]) == root / "data"
    assert child["NACHUAN_ENV"] == "production"
    assert child["BRIDGE_API_KEY"] == "scoped-key"
    assert f"{service.upper()}_ALLOW_ALL" not in child
    assert not {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} & set(child)


def test_isolated_bridge_settings_never_load_project_dotenv(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VOLCANO_API_KEY", raising=False)
    monkeypatch.delenv("APPROVAL_ADMIN_KEY", raising=False)
    # Settings has an absolute project env_file, so a cwd-local decoy alone is
    # not enough to prove the contract.  Override the class model config with a
    # temporary env file and verify the isolated constructor still disables it.
    from gateway.config import Settings

    env_file = tmp_path / ".env"
    env_file.write_text(
        "VOLCANO_API_KEY=must-not-load\nAPPROVAL_ADMIN_KEY=must-not-load\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
    get_isolated_bridge_settings.cache_clear()
    try:
        settings = get_isolated_bridge_settings()
        assert settings.volcano_api_key == ""
        assert settings.approval_admin_key == ""
    finally:
        get_isolated_bridge_settings.cache_clear()


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:8080/path",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080?key=leak",
        "http://127.0.0.1:8080#fragment",
        "http://127.0.0.1:70000",
    ],
)
def test_bridge_engine_url_rejects_every_non_exact_loopback_origin(url: str):
    from gateway.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None, bridge_engine_url=url)


def test_bridge_engine_url_normalizes_the_only_allowed_origin():
    from gateway.config import Settings

    settings = Settings(_env_file=None, bridge_engine_url="http://127.0.0.1:49152/")
    assert settings.bridge_engine_url == "http://127.0.0.1:49152"


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")
def test_managed_launcher_exits_and_kills_child_tree_when_supervisor_exits(
    tmp_path: Path,
):
    """A vanished supervisor cannot leave its wrapper or service tree behind."""

    import ctypes
    from ctypes import wintypes

    root = tmp_path / "managed parent exit"
    scripts = root / "scripts"
    gateway = root / "gateway"
    data = root / "data"
    scripts.mkdir(parents=True)
    gateway.mkdir()
    data.mkdir()
    launcher = scripts / "managed_launcher.py"
    shutil.copy2(SCRIPT, launcher)
    (gateway / "__init__.py").write_text("", encoding="utf-8")
    (gateway / "app.py").write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                "import sys",
                "import time",
                "from pathlib import Path",
                "",
                "sleeper = subprocess.Popen(",
                "    [sys.executable, '-I', '-S', '-c', 'import time; time.sleep(300)'],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                "    close_fds=True,",
                ")",
                "(Path.cwd() / 'data' / 'gateway-pids.txt').write_text(",
                "    f'{os.getpid()}\\n{sleeper.pid}\\n', encoding='ascii'",
                ")",
                "while True:",
                "    time.sleep(1)",
            ]
        ),
        encoding="utf-8",
    )

    wrapper_pid_file = data / "wrapper.pid"
    gateway_pids_file = data / "gateway-pids.txt"
    release_parent = data / "release-parent"
    wrapper_stderr = data / "wrapper.stderr.log"
    parent_code = "\n".join(
        [
            "import ctypes",
            "import os",
            "import subprocess",
            "import sys",
            "import time",
            "from ctypes import wintypes",
            "from pathlib import Path",
            "root = Path(sys.argv[1])",
            "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)",
            "kernel32.GetCurrentProcess.argtypes = []",
            "kernel32.GetCurrentProcess.restype = wintypes.HANDLE",
            "kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]",
            "kernel32.GetProcessTimes.restype = wintypes.BOOL",
            "created = wintypes.FILETIME()",
            "exited = wintypes.FILETIME()",
            "kernel_at = wintypes.FILETIME()",
            "user_at = wintypes.FILETIME()",
            "if not kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_at), ctypes.byref(user_at)):",
            "    raise ctypes.WinError(ctypes.get_last_error())",
            "parent_filetime = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)",
            "wrapper_stderr = (root / 'data' / 'wrapper.stderr.log').open('ab', buffering=0)",
            "wrapper = subprocess.Popen(",
            "    [sys.executable, '-I', '-S', '-u', str(root / 'scripts' / 'managed_launcher.py'), 'engine', 'gateway.app', '65431', str(os.getpid()), str(parent_filetime)],",
            "    cwd=root,",
            "    env=os.environ.copy(),",
            "    stdin=subprocess.DEVNULL,",
            "    stdout=subprocess.DEVNULL,",
            "    stderr=wrapper_stderr,",
            "    close_fds=True,",
            ")",
            "(root / 'data' / 'wrapper.pid').write_text(str(wrapper.pid), encoding='ascii')",
            "deadline = time.monotonic() + 15",
            "while not (root / 'data' / 'release-parent').exists():",
            "    if wrapper.poll() is not None:",
            "        raise SystemExit(70)",
            "    if time.monotonic() >= deadline:",
            "        raise SystemExit(71)",
            "    time.sleep(0.05)",
        ]
    )
    parent = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", parent_code, str(root)],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        close_fds=True,
    )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    wait_timeout = 0x00000102
    process_access = 0x00100000 | 0x0001  # SYNCHRONIZE | PROCESS_TERMINATE
    handles: list[tuple[str, int, object]] = []

    def open_process(name: str, pid: int) -> None:
        handle = kernel32.OpenProcess(process_access, False, pid)
        assert handle, f"could not open {name} pid {pid}: {ctypes.get_last_error()}"
        assert kernel32.WaitForSingleObject(handle, 0) == wait_timeout
        handles.append((name, pid, handle))

    try:
        deadline = time.monotonic() + 15
        gateway_pids: list[int] = []
        while True:
            if wrapper_pid_file.is_file() and gateway_pids_file.is_file():
                try:
                    gateway_pids = [
                        int(value)
                        for value in gateway_pids_file.read_text(
                            encoding="ascii"
                        ).splitlines()
                        if value.strip()
                    ]
                except (OSError, UnicodeError, ValueError):
                    gateway_pids = []
                if len(gateway_pids) == 2:
                    break
            if parent.poll() is not None:
                stdout, stderr = parent.communicate(timeout=1)
                pytest.fail(
                    f"short-lived parent exited before gateway start: "
                    f"code={parent.returncode}, stdout={stdout!r}, stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                pytest.fail("managed gateway process tree did not start")
            time.sleep(0.05)

        wrapper_pid = int(wrapper_pid_file.read_text(encoding="ascii").strip())
        open_process("wrapper", wrapper_pid)
        open_process("gateway", gateway_pids[0])
        open_process("gateway descendant", gateway_pids[1])

        started = time.monotonic()
        release_parent.write_text("exit", encoding="ascii")
        stdout, stderr = parent.communicate(timeout=5)
        assert parent.returncode == 0, stderr or stdout

        exit_deadline = started + 8
        for name, pid, handle in handles:
            remaining_ms = max(0, int((exit_deadline - time.monotonic()) * 1000))
            result = kernel32.WaitForSingleObject(handle, remaining_ms)
            detail = (
                wrapper_stderr.read_text(encoding="utf-8", errors="replace")
                if wrapper_stderr.is_file()
                else ""
            )
            assert result == 0, (
                f"{name} pid {pid} survived supervisor exit; wrapper stderr={detail!r}"
            )
        assert time.monotonic() < exit_deadline
    finally:
        if parent.poll() is None:
            release_parent.write_text("cleanup", encoding="ascii")
            try:
                parent.wait(timeout=2)
            except subprocess.TimeoutExpired:
                parent.kill()
                parent.wait(timeout=2)
        for _name, _pid, handle in handles:
            if kernel32.WaitForSingleObject(handle, 0) == wait_timeout:
                kernel32.TerminateProcess(handle, 1)
                kernel32.WaitForSingleObject(handle, 2000)
        for _name, _pid, handle in handles:
            kernel32.CloseHandle(handle)
