from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import cli.codex_worker_entrypoint as entrypoint
from gateway.codex_subscription_worker import (
    CodexSubscriptionError,
    CodexWorkerRequest,
    CodexWorkerResult,
)


def _fake_pe(marker: bytes = b"codex") -> bytes:
    payload = bytearray(128)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[80 : 80 + len(marker)] = marker
    return bytes(payload)


def _request(tmp_path: Path, *, operation: str, prompt: str = "") -> CodexWorkerRequest:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(_fake_pe())
    return CodexWorkerRequest(
        operation=operation,  # type: ignore[arg-type]
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        prompt=prompt,
        timeout_seconds=3,
    )


def test_child_executes_in_an_empty_private_directory_and_cleans_it(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, operation="invoke", prompt="private prompt")
    captured: dict[str, object] = {}

    def fake_cli(
        argv: tuple[str, ...],
        *,
        stdin: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> entrypoint.CodexCliProcessResult:
        captured.update(
            argv=argv,
            stdin=stdin,
            cwd=cwd,
            entries=list(cwd.iterdir()),
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        return entrypoint.CodexCliProcessResult(
            returncode=0,
            stdout=b'{"type":"thread.started","thread_id":"t"}\n',
            stderr=b"",
            cleanup_verified=True,
        )

    result = entrypoint.execute_codex_cli_request(
        request,
        process_runner=fake_cli,
        source_environment={
            "USERPROFILE": str(tmp_path / "profile"),
            "CODEX_HOME": str(tmp_path / "profile" / ".codex"),
            "TEMP": str(tmp_path),
            "SYSTEMROOT": r"C:\Windows",
            "PATH": r"C:\safe",
            "OPENAI_API_KEY": "must-not-inherit",
            "NACHUAN_API_KEY": "must-not-inherit",
        },
    )

    assert isinstance(result, CodexWorkerResult)
    assert result.stdout.startswith('{"type":"thread.started"')
    assert captured["stdin"] == b"private prompt"
    assert captured["entries"] == []
    assert "private prompt" not in captured["argv"]
    assert "OPENAI_API_KEY" not in captured["environment"]
    assert "NACHUAN_API_KEY" not in captured["environment"]
    workdir = captured["cwd"]
    assert isinstance(workdir, Path)
    assert not workdir.exists()


def test_parent_starts_only_fixed_helper_and_sends_request_over_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "parent-pipe-only-prompt"
    request = _request(tmp_path, operation="invoke", prompt=prompt)
    captured: dict[str, object] = {}

    def fake_transport(
        command: tuple[str, ...],
        request_bytes: bytes,
        *,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> bytes:
        captured.update(
            command=command,
            request_bytes=request_bytes,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        return json.dumps(
            {
                "schema": "nachuan.codex-worker-response.v1",
                "returncode": 0,
                "stdout": "ok",
                "stderr": "",
                "process_tree_exit_verified": True,
            }
        ).encode("utf-8")

    monkeypatch.setattr(entrypoint, "_contained_helper_transport", fake_transport)

    result = entrypoint.run_codex_worker_request(
        request,
        source_environment={
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
            "USERPROFILE": str(tmp_path / "profile"),
            "OPENAI_API_KEY": "must-not-inherit",
        },
    )

    assert result == CodexWorkerResult(
        returncode=0,
        stdout="ok",
        stderr="",
        process_tree_exit_verified=True,
    )
    command = captured["command"]
    assert isinstance(command, tuple)
    assert prompt not in command
    assert request.executable_path not in command
    assert request.executable_sha256 not in command
    assert "--child" in command
    request_document = json.loads(captured["request_bytes"])
    assert request_document["prompt"] == prompt
    assert request_document["operation"] == "invoke"
    assert "OPENAI_API_KEY" not in captured["environment"]
    assert captured["environment"]["TEMP"] == str(tmp_path)
    assert captured["environment"]["TMP"] == str(tmp_path)


def test_child_rejects_replaced_executable_before_cli_start(tmp_path: Path) -> None:
    request = _request(tmp_path, operation="status")
    Path(request.executable_path).write_bytes(_fake_pe(b"replacement"))
    calls: list[object] = []

    with pytest.raises(CodexSubscriptionError) as caught:
        entrypoint.execute_codex_cli_request(
            request,
            process_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
            source_environment={"TEMP": str(tmp_path)},
        )

    assert caught.value.code == "binary_attestation_rejected"
    assert calls == []


def test_parent_rejects_duplicate_or_secret_bearing_helper_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path, operation="status")

    def duplicate(*_args, **_kwargs) -> bytes:
        return (
            b'{"schema":"nachuan.codex-worker-response.v1","returncode":0,'
            b'"returncode":0,"stdout":"","stderr":"",'
            b'"process_tree_exit_verified":true}'
        )

    monkeypatch.setattr(entrypoint, "_contained_helper_transport", duplicate)
    with pytest.raises(CodexSubscriptionError) as caught:
        entrypoint.run_codex_worker_request(request)
    assert caught.value.code == "helper_protocol_rejected"

    def extra(*_args, **_kwargs) -> bytes:
        return json.dumps(
            {
                "schema": "nachuan.codex-worker-response.v1",
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "process_tree_exit_verified": True,
                "token": "must-not-cross",
            }
        ).encode("utf-8")

    monkeypatch.setattr(entrypoint, "_contained_helper_transport", extra)
    with pytest.raises(CodexSubscriptionError) as caught:
        entrypoint.run_codex_worker_request(request)
    assert caught.value.code == "helper_protocol_rejected"


def test_child_timeout_is_redacted_and_reports_cleanup_truth(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, operation="invoke", prompt="secret")

    def timeout_cli(*_args, **_kwargs) -> entrypoint.CodexCliProcessResult:
        raise entrypoint.CodexCliProcessError(
            "timeout",
            cleanup_verified=False,
        )

    result = entrypoint.execute_codex_cli_request(
        request,
        process_runner=timeout_cli,
        source_environment={"TEMP": str(tmp_path)},
    )

    assert result.returncode == 124
    assert result.stdout == ""
    assert result.stderr == "worker_timeout"
    assert result.process_tree_exit_verified is False
    assert "secret" not in repr(result)


def test_child_decodes_cli_output_as_strict_bounded_utf8(tmp_path: Path) -> None:
    request = _request(tmp_path, operation="status")

    def invalid_utf8(*_args, **_kwargs) -> entrypoint.CodexCliProcessResult:
        return entrypoint.CodexCliProcessResult(
            returncode=0,
            stdout=b"\xff",
            stderr=b"",
            cleanup_verified=True,
        )

    with pytest.raises(CodexSubscriptionError) as caught:
        entrypoint.execute_codex_cli_request(
            request,
            process_runner=invalid_utf8,
            source_environment={"TEMP": str(tmp_path)},
        )

    assert caught.value.code == "cli_output_rejected"


def _pid_is_active(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

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
    return True


def _force_stop_test_pid(pid: int) -> None:
    if not _pid_is_active(pid):
        return
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
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


def test_helper_timeout_cleans_nested_child_and_grandchild(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "tree-pids.json"
    grandchild = tmp_path / "grandchild.py"
    child = tmp_path / "child.py"
    helper = tmp_path / "helper.py"
    grandchild.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    child.write_text(
        "\n".join(
            [
                "import json, os, subprocess, sys, time",
                "proc = subprocess.Popen([sys.executable, sys.argv[2]])",
                "with open(sys.argv[1], 'w', encoding='ascii') as handle:",
                "    json.dump({'child': os.getpid(), 'grandchild': proc.pid}, handle)",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    helper.write_text(
        "\n".join(
            [
                "import pathlib, subprocess, sys, time",
                "subprocess.Popen([sys.executable, sys.argv[2], sys.argv[1], sys.argv[3]])",
                "deadline = time.monotonic() + 5",
                "while not pathlib.Path(sys.argv[1]).exists() and time.monotonic() < deadline:",
                "    time.sleep(0.01)",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    environment = entrypoint.codex_worker_environment(
        {
            **os.environ,
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
        }
    )

    with pytest.raises(CodexSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            (
                str(Path(sys.executable).resolve(strict=True)),
                str(helper),
                str(pid_file),
                str(child),
                str(grandchild),
            ),
            b"{}",
            environment=environment,
            timeout_seconds=0.05,
        )

    assert caught.value.code == "helper_timeout"
    assert caught.value.process_exit_verified is True
    assert pid_file.exists()
    pids = json.loads(pid_file.read_text(encoding="ascii"))
    tree = [int(pids["child"]), int(pids["grandchild"])]
    try:
        assert {pid: _pid_is_active(pid) for pid in tree} == {
            pid: False for pid in tree
        }
    finally:
        for pid in reversed(tree):
            _force_stop_test_pid(pid)
