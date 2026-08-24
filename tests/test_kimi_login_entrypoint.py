from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

import cli.kimi_login_entrypoint as entrypoint
from gateway.kimi_subscription_login import KimiLoginRequest, KimiLoginResult
from gateway.kimi_subscription_worker import kimi_worker_environment


_DEVICE_CODE = "NACHUAN-DEVICE-CODE-MUST-STAY-ON-TERMINAL"
_TOKEN = "NACHUAN-TOKEN-MUST-NEVER-BE-RECORDED"


def _fake_pe(marker: bytes = b"kimi-login") -> bytes:
    payload = bytearray(512)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\0\0"
    payload[160 : 160 + len(marker)] = marker
    return bytes(payload)


def _source_environment(tmp_path: Path) -> dict[str, str]:
    kimi_home = (tmp_path / "data" / "kimi-code-home").resolve()
    temp_root = (tmp_path / "data" / "kimi-runtime").resolve()
    kimi_home.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    source = dict(os.environ)
    source.update(
        {
            "KIMI_CODE_HOME": str(kimi_home),
            "KIMI_CLI_TEMP_ROOT": str(temp_root),
            "KIMI_API_KEY": "ambient-api-secret",
            "KIMI_CODE_BASE_URL": "https://evil.invalid",
            "HTTPS_PROXY": "http://user:password@proxy.invalid",
            "BASH_ENV": str(tmp_path / "evil.sh"),
            "NODE_OPTIONS": "--require=C:\\evil.js",
            "NACHUAN_GATEWAY_KEY": "ambient-gateway-secret",
        }
    )
    return source


def _request(
    tmp_path: Path,
    *,
    executable: Path | None = None,
    timeout_seconds: float = 3.0,
) -> KimiLoginRequest:
    source = _source_environment(tmp_path)
    if executable is None:
        executable = (tmp_path / "official" / "kimi.exe").resolve()
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(_fake_pe())
    executable = executable.resolve(strict=True)
    return KimiLoginRequest(
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        executable_version="0.27.0",
        kimi_code_home=source["KIMI_CODE_HOME"],
        timeout_seconds=timeout_seconds,
    )


def _success() -> KimiLoginResult:
    return KimiLoginResult(
        returncode=0,
        timed_out=False,
        cancelled=False,
        process_tree_exit_verified=True,
    )


def _write_login_script(
    tmp_path: Path,
    request: KimiLoginRequest,
    source: str,
) -> None:
    for directory in {tmp_path.resolve(), Path(request.kimi_code_home)}:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "login").write_text(
            source,
            encoding="utf-8",
            newline="\n",
        )


def test_public_runner_uses_only_bound_login_argv_and_strict_child_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    environment = kimi_worker_environment(_source_environment(tmp_path))
    observed: dict[str, object] = {}

    def fake_transport(
        argv: tuple[str, ...],
        *,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> KimiLoginResult:
        observed.update(
            argv=argv,
            environment=dict(environment),
            timeout_seconds=timeout_seconds,
        )
        return _success()

    monkeypatch.setattr(
        entrypoint,
        "_contained_login_transport",
        fake_transport,
    )

    result = entrypoint.run_kimi_login_request(
        request,
        environment=environment,
    )

    assert result == _success()
    assert observed == {
        "argv": (request.executable_path, "login"),
        "environment": environment,
        "timeout_seconds": 3.0,
    }
    serialized = "\0".join(
        f"{key}={value}"
        for key, value in observed["environment"].items()  # type: ignore[union-attr]
    )
    for forbidden in (
        "ambient-api-secret",
        "ambient-gateway-secret",
        "evil.invalid",
        "proxy.invalid",
        "evil.sh",
        "evil.js",
    ):
        assert forbidden not in serialized


def test_real_login_inherits_terminal_and_never_returns_or_logs_auth_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _request(
        tmp_path,
        executable=Path(sys.executable),
        timeout_seconds=5.0,
    )
    environment = kimi_worker_environment(_source_environment(tmp_path))
    _write_login_script(
        tmp_path,
        request,
        "\n".join(
            [
                "import sys",
                f"print({_DEVICE_CODE!r}, flush=True)",
                f"print({_TOKEN!r}, file=sys.stderr, flush=True)",
            ]
        )
        + "\n",
    )
    monkeypatch.chdir(tmp_path)
    popen_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    real_popen = subprocess.Popen

    def recording_popen(
        *args: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        popen_calls.append((args, dict(kwargs)))
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(entrypoint.subprocess, "Popen", recording_popen)

    result = entrypoint.run_kimi_login_request(
        request,
        environment=environment,
    )

    captured = capfd.readouterr()
    assert result == _success()
    assert len(popen_calls) == 1
    args, kwargs = popen_calls[0]
    assert tuple(args[0]) == (request.executable_path, "login")
    assert kwargs.get("env") == environment
    assert kwargs.get("stdin") is None
    assert kwargs.get("stdout") is None
    assert kwargs.get("stderr") is None
    assert "capture_output" not in kwargs
    assert _DEVICE_CODE in captured.out
    assert _TOKEN in captured.err
    assert _DEVICE_CODE not in repr(result)
    assert _TOKEN not in repr(result)
    assert _DEVICE_CODE not in caplog.text
    assert _TOKEN not in caplog.text


def _pid_is_active(pid: int) -> bool:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            return bool(
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                and exit_code.value == 259
            )
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        if proc_stat.is_file() and proc_stat.read_text().split()[2] == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def _force_stop_test_pid(pid: int) -> None:
    if not _pid_is_active(pid):
        return
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, 1)
            kernel32.WaitForSingleObject(handle, 5000)
        finally:
            kernel32.CloseHandle(handle)
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _wait_for_pid_tree(pid_file: Path) -> dict[str, int]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            document = json.loads(pid_file.read_text(encoding="ascii"))
            return {
                "kimi": int(document["kimi"]),
                "grandchild": int(document["grandchild"]),
            }
        except (OSError, ValueError, KeyError, TypeError):
            time.sleep(0.01)
    raise AssertionError("fake Kimi login tree did not publish complete PIDs")


def _assert_tree_dead_with_test_cleanup(tree: dict[str, int]) -> None:
    pids = [tree["kimi"], tree["grandchild"]]
    try:
        assert {pid: _pid_is_active(pid) for pid in pids} == {
            pid: False for pid in pids
        }
    finally:
        for pid in reversed(pids):
            _force_stop_test_pid(pid)


def _write_nested_login_tree(
    tmp_path: Path,
    request: KimiLoginRequest,
) -> Path:
    pid_file = (tmp_path / "login-tree-pids.json").resolve()
    grandchild = (tmp_path / "login-grandchild.py").resolve()
    grandchild.write_text(
        "import time\ntime.sleep(60)\n",
        encoding="utf-8",
        newline="\n",
    )
    _write_login_script(
        tmp_path,
        request,
        "\n".join(
            [
                "import json, os, subprocess, sys, time",
                "proc = subprocess.Popen(",
                f"    [sys.executable, {str(grandchild)!r}],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                f"with open({str(pid_file)!r}, 'w', encoding='ascii') as handle:",
                "    json.dump(",
                "        {'kimi': os.getpid(), 'grandchild': proc.pid},",
                "        handle,",
                "    )",
                "time.sleep(60)",
            ]
        )
        + "\n",
    )
    return pid_file


def test_timeout_returns_only_after_login_and_grandchild_are_dead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(
        tmp_path,
        executable=Path(sys.executable),
        timeout_seconds=1.0,
    )
    environment = kimi_worker_environment(_source_environment(tmp_path))
    pid_file = _write_nested_login_tree(tmp_path, request)
    monkeypatch.chdir(tmp_path)

    result = entrypoint.run_kimi_login_request(
        request,
        environment=environment,
    )

    tree = _wait_for_pid_tree(pid_file)
    assert isinstance(result, KimiLoginResult)
    assert result.returncode != 0
    assert result.timed_out is True
    assert result.cancelled is False
    assert result.process_tree_exit_verified is True
    _assert_tree_dead_with_test_cleanup(tree)


class _CancelOnFirstBlockingWait:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        pid_file: Path,
    ) -> None:
        self._process = process
        self._pid_file = pid_file
        self._cancelled = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._process, name)

    def _cancel_once(self) -> None:
        if self._cancelled:
            return
        _wait_for_pid_tree(self._pid_file)
        self._cancelled = True
        raise KeyboardInterrupt

    def wait(self, timeout: float | None = None) -> int:
        self._cancel_once()
        return self._process.wait(timeout=timeout)

    def communicate(
        self,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes | None, bytes | None]:
        self._cancel_once()
        return self._process.communicate(input=input, timeout=timeout)


def test_keyboard_interrupt_returns_only_after_whole_login_tree_is_dead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(
        tmp_path,
        executable=Path(sys.executable),
        timeout_seconds=10.0,
    )
    environment = kimi_worker_environment(_source_environment(tmp_path))
    pid_file = _write_nested_login_tree(tmp_path, request)
    monkeypatch.chdir(tmp_path)
    real_popen = subprocess.Popen

    def cancelling_popen(
        *args: object,
        **kwargs: object,
    ) -> _CancelOnFirstBlockingWait:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        return _CancelOnFirstBlockingWait(process, pid_file)

    monkeypatch.setattr(entrypoint.subprocess, "Popen", cancelling_popen)

    result = entrypoint.run_kimi_login_request(
        request,
        environment=environment,
    )

    tree = _wait_for_pid_tree(pid_file)
    assert isinstance(result, KimiLoginResult)
    assert result.returncode != 0
    assert result.timed_out is False
    assert result.cancelled is True
    assert result.process_tree_exit_verified is True
    _assert_tree_dead_with_test_cleanup(tree)


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended Job contract")
def test_windows_login_is_suspended_until_job_assignment_then_resumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(
        tmp_path,
        executable=Path(sys.executable),
        timeout_seconds=5.0,
    )
    environment = kimi_worker_environment(_source_environment(tmp_path))
    sentinel = (tmp_path / "login-ran.txt").resolve()
    _write_login_script(
        tmp_path,
        request,
        "\n".join(
            [
                "from pathlib import Path",
                f"Path({str(sentinel)!r}).write_text('ran', encoding='ascii')",
            ]
        )
        + "\n",
    )
    monkeypatch.chdir(tmp_path)
    real_popen = subprocess.Popen
    real_assign = entrypoint._assign_and_resume_windows_process
    creation_flags: list[int] = []
    events: list[str] = []

    def recording_popen(
        *args: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        creation_flags.append(int(kwargs.get("creationflags", 0)))
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    def checked_assign_and_resume(job: int, pid: int) -> None:
        assert not sentinel.exists()
        events.append("assign-before-resume")
        real_assign(job, pid)

    monkeypatch.setattr(entrypoint.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(
        entrypoint,
        "_assign_and_resume_windows_process",
        checked_assign_and_resume,
    )

    result = entrypoint.run_kimi_login_request(
        request,
        environment=environment,
    )

    assert result == _success()
    assert creation_flags and creation_flags[0] & 0x00000004
    assert events == ["assign-before-resume"]
    assert sentinel.read_text(encoding="ascii") == "ran"
