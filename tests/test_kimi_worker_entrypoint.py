from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

import cli.kimi_worker_entrypoint as entrypoint
from gateway.kimi_subscription_worker import (
    KimiSubscriptionError,
    KimiWorkerRequest,
    KimiWorkerResult,
    kimi_worker_environment,
)


_REQUEST_SCHEMA = "nachuan.kimi-worker-request.v1"
_RESPONSE_SCHEMA = "nachuan.kimi-worker-response.v2"
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
_MAX_RESPONSE_BYTES = 6 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024


def _fake_pe(marker: bytes = b"kimi") -> bytes:
    payload = bytearray(512)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\0\0"
    payload[160 : 160 + len(marker)] = marker
    return bytes(payload)


def _request(tmp_path: Path, *, prompt: str = "PRIVATE_KIMI_PROMPT") -> KimiWorkerRequest:
    executable = (tmp_path / "official" / "kimi.exe").resolve()
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(_fake_pe())
    return KimiWorkerRequest(
        operation="invoke",
        executable_path=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        bound_version="0.27.0",
        prompt=prompt,
        timeout_seconds=3.0,
    )


def _source_environment(tmp_path: Path) -> dict[str, str]:
    kimi_home = (tmp_path / "data" / "subscription-kimi-code-home").resolve()
    temp_root = (
        tmp_path / "data" / "subscription-cli-runtime" / "kimi-code"
    ).resolve()
    kimi_home.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    source = dict(os.environ)
    source.update(
        {
            "KIMI_CODE_HOME": str(kimi_home),
            "KIMI_CLI_TEMP_ROOT": str(temp_root),
            "KIMI_API_KEY": "must-not-reach-helper-or-kimi",
            "HTTPS_PROXY": "http://user:secret@proxy.invalid",
            "XREVIEW_SECRET": "must-not-reach-helper-or-kimi",
            "BASH_ENV": str(tmp_path / "evil.sh"),
            "NODE_OPTIONS": "--require=C:\\evil.js",
        }
    )
    return source


def _success_cli_result(
    *,
    text: str = "NACHUAN_KIMI_OK",
    stderr: bytes = b"",
    cleanup_verified: bool = True,
) -> entrypoint.KimiCliProcessResult:
    return entrypoint.KimiCliProcessResult(
        returncode=0,
        text=text,
        session_id="session-0123456789abcdef",
        stop_reason="end_turn",
        actual_served_model=None,
        tool_activity_observed=False,
        stderr=stderr,
        cleanup_verified=cleanup_verified,
    )


def _success_worker_result() -> KimiWorkerResult:
    return KimiWorkerResult(
        returncode=0,
        text="NACHUAN_KIMI_OK",
        session_id="session-0123456789abcdef",
        stop_reason="end_turn",
        actual_served_model=None,
        tool_activity_observed=False,
        process_tree_exit_verified=True,
    )


def _response_bytes(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema": _RESPONSE_SCHEMA,
        "returncode": 0,
        "text": "NACHUAN_KIMI_OK",
        "session_id": "session-0123456789abcdef",
        "stop_reason": "end_turn",
        "actual_served_model": None,
        "tool_activity_observed": False,
        "process_tree_exit_verified": True,
        "failure_code": None,
    }
    document.update(overrides)
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def test_parent_starts_only_fixed_helper_and_sends_sensitive_request_over_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "PARENT_PIPE_ONLY_父进程命令行不可见"
    request = _request(tmp_path, prompt=prompt)
    source_environment = _source_environment(tmp_path)
    captured: dict[str, object] = {}

    def fake_transport(
        command: tuple[str, ...],
        request_bytes: bytes,
        *,
        environment: dict[str, str],
        timeout_seconds: float,
        cancellation_event: threading.Event | None = None,
    ) -> bytes:
        captured.update(
            command=command,
            request_bytes=request_bytes,
            environment=environment,
            timeout_seconds=timeout_seconds,
            cancellation_event=cancellation_event,
        )
        return _response_bytes()

    monkeypatch.setattr(entrypoint, "_contained_helper_transport", fake_transport)

    result = entrypoint.run_kimi_worker_request(
        request,
        source_environment=source_environment,
    )

    assert result == _success_worker_result()
    assert captured["command"] == (
        str(Path(sys.executable).resolve(strict=True)),
        "-I",
        str(Path(entrypoint.__file__).resolve(strict=True)),
        "--child",
    )
    command_line = "\0".join(captured["command"])  # type: ignore[arg-type]
    assert prompt not in command_line
    assert request.executable_path not in command_line
    assert request.executable_sha256 not in command_line
    assert captured["cancellation_event"] is None

    request_document = json.loads(captured["request_bytes"])
    assert request_document == {
        "schema": _REQUEST_SCHEMA,
        "operation": "invoke",
        "executable_path": request.executable_path,
        "executable_sha256": request.executable_sha256,
        "bound_version": "0.27.0",
        "prompt": prompt,
        "timeout_seconds": 3.0,
    }
    assert captured["environment"] == kimi_worker_environment(source_environment)
    serialized_environment = "\0".join(
        f"{key}={value}"
        for key, value in captured["environment"].items()  # type: ignore[union-attr]
    )
    assert "must-not-reach-helper-or-kimi" not in serialized_environment
    assert "proxy.invalid" not in serialized_environment
    assert "XREVIEW" not in serialized_environment


def test_fixed_helper_response_carries_only_stable_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "PRIVATE_PROMPT_MUST_NOT_LEAK"
    remote_detail = "REMOTE_MESSAGE_AND_DATA_MUST_NOT_LEAK"
    request = _request(tmp_path, prompt=prompt)
    response = _response_bytes(
        returncode=70,
        text="",
        session_id="",
        stop_reason="",
        failure_code="auth_required",
    )
    assert remote_detail.encode("utf-8") not in response
    monkeypatch.setattr(
        entrypoint,
        "_contained_helper_transport",
        lambda *_args, **_kwargs: response,
    )

    result = entrypoint.run_kimi_worker_request(
        request,
        source_environment=_source_environment(tmp_path),
    )

    assert result.failure_code == "auth_required"
    assert prompt not in repr(result)
    assert remote_detail not in repr(result)


def test_child_repins_bound_cli_then_uses_exact_acp_argv_and_private_empty_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "SECOND_PIPE_ONLY_仅进入ACP标准输入"
    request = _request(tmp_path, prompt=prompt)
    source_environment = _source_environment(tmp_path)
    pin_events: list[tuple[str, str]] = []
    captured: dict[str, object] = {}

    @contextmanager
    def fake_pin(path: str | Path, digest: str) -> Iterator[Path]:
        pin_events.append((str(path), digest))
        yield Path(path).resolve(strict=True)

    def fake_cli(
        argv: tuple[str, ...],
        *,
        prompt_bytes: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> entrypoint.KimiCliProcessResult:
        captured.update(
            argv=argv,
            prompt_bytes=prompt_bytes,
            cwd=cwd,
            cwd_entries=tuple(cwd.iterdir()),
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        return _success_cli_result()

    monkeypatch.setattr(entrypoint, "pin_attested_cli", fake_pin)

    result = entrypoint.execute_kimi_cli_request(
        request,
        process_runner=fake_cli,
        source_environment=source_environment,
    )

    assert result == _success_worker_result()
    assert pin_events == [
        (request.executable_path, request.executable_sha256)
    ]
    assert captured["argv"] == (request.executable_path, "acp")
    assert captured["prompt_bytes"] == prompt.encode("utf-8")
    assert captured["cwd_entries"] == ()
    assert captured["environment"] == kimi_worker_environment(source_environment)
    assert prompt not in "\0".join(captured["argv"])  # type: ignore[arg-type]
    assert request.executable_sha256 not in "\0".join(
        captured["argv"]  # type: ignore[arg-type]
    )
    private_cwd = captured["cwd"]
    assert isinstance(private_cwd, Path)
    assert not private_cwd.exists()


def test_child_rejects_replaced_cli_before_process_runner(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    source_environment = _source_environment(tmp_path)
    Path(request.executable_path).write_bytes(_fake_pe(b"replacement"))
    calls: list[object] = []

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint.execute_kimi_cli_request(
            request,
            process_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
            source_environment=source_environment,
        )

    assert caught.value.code == "binary_attestation_rejected"
    assert caught.value.process_exit_verified is True
    assert calls == []


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        (
            b'{"schema":"nachuan.kimi-worker-request.v1",'
            b'"operation":"invoke","operation":"invoke",'
            b'"executable_path":"C:\\\\kimi.exe",'
            b'"executable_sha256":"'
            + b"0" * 64
            + b'","prompt":"x","timeout_seconds":3}'
        ),
        json.dumps(
            {
                "schema": _REQUEST_SCHEMA,
                "operation": "invoke",
                "executable_path": r"C:\kimi.exe",
                "executable_sha256": "0" * 64,
                "bound_version": "0.27.0",
                "prompt": "x",
                "timeout_seconds": 3,
                "extra": True,
            }
        ).encode("utf-8"),
        json.dumps(
            {
                "schema": "nachuan.kimi-worker-request.v0",
                "operation": "invoke",
                "executable_path": r"C:\kimi.exe",
                "executable_sha256": "0" * 64,
                "bound_version": "0.27.0",
                "prompt": "x",
                "timeout_seconds": 3,
            }
        ).encode("utf-8"),
        pytest.param(
            b"x" * (_MAX_REQUEST_BYTES + 1),
            id="oversize-request",
        ),
    ],
)
def test_child_request_is_strict_utf8_bounded_closed_schema(payload: bytes) -> None:
    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._decode_request(payload)

    assert caught.value.code == "helper_request_rejected"
    assert caught.value.process_exit_verified is True


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        (
            b'{"schema":"nachuan.kimi-worker-response.v1",'
            b'"returncode":0,"returncode":0,'
            b'"text":"ok","session_id":"s","stop_reason":"end_turn",'
            b'"actual_served_model":null,"tool_activity_observed":false,'
            b'"process_tree_exit_verified":true}'
        ),
        _response_bytes(extra=True),
        _response_bytes(schema="nachuan.kimi-worker-response.v0"),
        pytest.param(
            b"x" * (_MAX_RESPONSE_BYTES + 1),
            id="oversize-response",
        ),
    ],
)
def test_parent_response_is_strict_utf8_bounded_closed_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    request = _request(tmp_path)

    monkeypatch.setattr(
        entrypoint,
        "_contained_helper_transport",
        lambda *_args, **_kwargs: payload,
    )

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint.run_kimi_worker_request(
            request,
            source_environment=_source_environment(tmp_path),
        )

    assert caught.value.code == "helper_protocol_rejected"


@pytest.mark.parametrize("cleanup_verified", [True, False])
def test_child_timeout_is_redacted_and_preserves_cleanup_truth(
    tmp_path: Path,
    cleanup_verified: bool,
) -> None:
    prompt = "TIMEOUT_PROMPT_MUST_NOT_LEAK"
    request = _request(tmp_path, prompt=prompt)

    def timeout_cli(*_args, **_kwargs) -> entrypoint.KimiCliProcessResult:
        raise entrypoint.KimiCliProcessError(
            "timeout",
            cleanup_verified=cleanup_verified,
        )

    result = entrypoint.execute_kimi_cli_request(
        request,
        process_runner=timeout_cli,
        source_environment=_source_environment(tmp_path),
    )

    assert result == KimiWorkerResult(
        returncode=124,
        text="",
        session_id="",
        stop_reason="",
        actual_served_model=None,
        tool_activity_observed=False,
        process_tree_exit_verified=cleanup_verified,
    )
    assert prompt not in repr(result)


def test_child_carries_stable_protocol_failure_code_without_remote_details(
    tmp_path: Path,
) -> None:
    prompt = "PRIVATE_PROMPT_MUST_NOT_LEAK"
    remote_detail = "REMOTE_MESSAGE_AND_DATA_MUST_NOT_LEAK"
    request = _request(tmp_path, prompt=prompt)

    def rejected_cli(*_args, **_kwargs) -> entrypoint.KimiCliProcessResult:
        try:
            raise RuntimeError(remote_detail)
        except RuntimeError as cause:
            raise entrypoint.KimiCliProcessError(
                "protocol_rejected",
                cleanup_verified=True,
                failure_code="auth_required",
            ) from cause

    result = entrypoint.execute_kimi_cli_request(
        request,
        process_runner=rejected_cli,
        source_environment=_source_environment(tmp_path),
    )

    assert result.returncode == 70
    assert result.failure_code == "auth_required"
    assert prompt not in repr(result)
    assert remote_detail not in repr(result)


def test_process_tree_rejection_stays_distinct_from_generic_cli_failure(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    def rejected_tree(*_args, **_kwargs) -> entrypoint.KimiCliProcessResult:
        raise entrypoint.KimiCliProcessError(
            "process_tree_rejected",
            cleanup_verified=True,
        )

    result = entrypoint.execute_kimi_cli_request(
        request,
        process_runner=rejected_tree,
        source_environment=_source_environment(tmp_path),
    )

    assert result.returncode == 70
    assert result.failure_code == "process_tree_rejected"


def test_acp_product_error_becomes_prompt_free_cli_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "PRIVATE_PROMPT_MUST_NOT_LEAK"
    remote_detail = "REMOTE_MESSAGE_AND_DATA_MUST_NOT_LEAK"

    class FakeProcess:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.pid = 1234
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()

    def reject_protocol(*_args, **_kwargs):
        try:
            raise RuntimeError(remote_detail)
        except RuntimeError as cause:
            raise entrypoint.KimiAcpProductError("auth_required") from cause

    monkeypatch.setattr(
        entrypoint,
        "_spawn_contained_process",
        lambda *_args, **_kwargs: (process, None, process.pid),
    )
    monkeypatch.setattr(
        entrypoint,
        "run_kimi_acp_product_protocol",
        reject_protocol,
    )
    monkeypatch.setattr(
        entrypoint,
        "_kill_contained_process_tree",
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(entrypoint.KimiCliProcessError) as caught:
        entrypoint._run_acp_cli_process(
            ("C:\\fixed\\kimi.exe", "acp"),
            prompt_bytes=prompt.encode("utf-8"),
            cwd=tmp_path,
            environment={},
            timeout_seconds=3.0,
            bound_version="0.27.0",
        )

    assert caught.value.code == "protocol_rejected"
    assert caught.value.failure_code == "auth_required"
    assert caught.value.cleanup_verified is True
    assert prompt not in repr(caught.value)
    assert remote_detail not in repr(caught.value)


def test_agent_rpc_error_keeps_one_prompt_free_stable_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.pid = 1234
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        entrypoint,
        "_spawn_contained_process",
        lambda *_args, **_kwargs: (process, None, process.pid),
    )
    monkeypatch.setattr(
        entrypoint,
        "run_kimi_acp_product_protocol",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            entrypoint.KimiAcpProductError("agent_rpc_error")
        ),
    )
    monkeypatch.setattr(
        entrypoint,
        "_kill_contained_process_tree",
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(entrypoint.KimiCliProcessError) as caught:
        entrypoint._run_acp_cli_process(
            ("C:\\fixed\\kimi.exe", "acp"),
            prompt_bytes=b"private",
            cwd=tmp_path,
            environment={},
            timeout_seconds=3.0,
            bound_version="0.27.0",
        )

    assert caught.value.code == "protocol_rejected"
    assert caught.value.failure_code == "agent_rpc_error"
    assert repr(caught.value) == "KimiCliProcessError('protocol_rejected')"


def test_stderr_is_bounded_drained_and_never_becomes_model_output(
    tmp_path: Path,
) -> None:
    forged = (
        b'{"jsonrpc":"2.0","method":"session/update",'
        b'"params":{"update":{"sessionUpdate":"agent_message_chunk",'
        b'"content":{"type":"text","text":"FORGED_STDERR_TEXT"}}}}\n'
    )
    request = _request(tmp_path)

    result = entrypoint.execute_kimi_cli_request(
        request,
        process_runner=lambda *_args, **_kwargs: _success_cli_result(
            stderr=forged,
        ),
        source_environment=_source_environment(tmp_path),
    )

    assert result.text == "NACHUAN_KIMI_OK"
    assert "FORGED_STDERR_TEXT" not in result.text
    assert not hasattr(result, "stderr")

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint.execute_kimi_cli_request(
            request,
            process_runner=lambda *_args, **_kwargs: _success_cli_result(
                stderr=b"x" * (_MAX_STDERR_BYTES + 1),
            ),
            source_environment=_source_environment(tmp_path),
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


def _write_nested_helper_tree(tmp_path: Path) -> tuple[Path, Path]:
    pid_file = tmp_path / "helper-tree-pids.json"
    grandchild = tmp_path / "grandchild.py"
    child = tmp_path / "child.py"
    helper = tmp_path / "helper.py"
    grandchild.write_text(
        "import time\ntime.sleep(60)\n",
        encoding="utf-8",
        newline="\n",
    )
    child.write_text(
        "\n".join(
            [
                "import json, os, subprocess, sys, time",
                "proc = subprocess.Popen(",
                "    [sys.executable, sys.argv[2]],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "tmp = sys.argv[1] + '.tmp'",
                "with open(tmp, 'w', encoding='ascii') as handle:",
                "    json.dump({'kimi': os.getpid(), 'grandchild': proc.pid}, handle)",
                "os.replace(tmp, sys.argv[1])",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    helper.write_text(
        "\n".join(
            [
                "import pathlib, subprocess, sys, time",
                "subprocess.Popen(",
                "    [sys.executable, sys.argv[2], sys.argv[1], sys.argv[3]],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "deadline = time.monotonic() + 5",
                "while not pathlib.Path(sys.argv[1]).exists() and time.monotonic() < deadline:",
                "    time.sleep(0.01)",
                "if not pathlib.Path(sys.argv[1]).exists():",
                "    raise SystemExit(71)",
                "if sys.argv[4] == 'invalid-response':",
                "    sys.stdout.buffer.write(b'{not-json')",
                "    sys.stdout.buffer.flush()",
                "    raise SystemExit(0)",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return helper, pid_file


def _nested_helper_command(
    helper: Path,
    pid_file: Path,
    *,
    scenario: str,
) -> tuple[str, ...]:
    return (
        str(Path(sys.executable).resolve(strict=True)),
        str(helper.resolve(strict=True)),
        str(pid_file.resolve()),
        str((helper.parent / "child.py").resolve(strict=True)),
        str((helper.parent / "grandchild.py").resolve(strict=True)),
        scenario,
    )


def _assert_tree_dead_with_test_cleanup(pid_file: Path) -> None:
    tree = json.loads(pid_file.read_text(encoding="ascii"))
    pids = [int(tree["kimi"]), int(tree["grandchild"])]
    try:
        assert {pid: _pid_is_active(pid) for pid in pids} == {
            pid: False for pid in pids
        }
    finally:
        for pid in reversed(pids):
            _force_stop_test_pid(pid)


def test_helper_timeout_returns_only_after_kimi_and_grandchild_are_dead(
    tmp_path: Path,
) -> None:
    helper, pid_file = _write_nested_helper_tree(tmp_path)

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            _nested_helper_command(helper, pid_file, scenario="timeout"),
            b"{}",
            environment=kimi_worker_environment(_source_environment(tmp_path)),
            timeout_seconds=0.1,
        )

    assert caught.value.code == "helper_timeout"
    assert caught.value.process_exit_verified is True
    assert pid_file.exists()
    _assert_tree_dead_with_test_cleanup(pid_file)


def test_invalid_helper_protocol_cannot_leave_kimi_or_grandchild_running(
    tmp_path: Path,
) -> None:
    helper, pid_file = _write_nested_helper_tree(tmp_path)

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            _nested_helper_command(
                helper,
                pid_file,
                scenario="invalid-response",
            ),
            b"{}",
            environment=kimi_worker_environment(_source_environment(tmp_path)),
            timeout_seconds=2.0,
        )

    assert caught.value.code == "helper_process_tree_rejected"
    assert caught.value.process_exit_verified is True
    assert pid_file.exists()
    _assert_tree_dead_with_test_cleanup(pid_file)


class _CancelOnCommunicate:
    def __init__(self, process: subprocess.Popen[bytes], pid_file: Path) -> None:
        self._process = process
        self._pid_file = pid_file

    def __getattr__(self, name: str) -> object:
        return getattr(self._process, name)

    def communicate(
        self,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, bytes]:
        del input, timeout
        deadline = time.monotonic() + 5.0
        while not self._pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self._pid_file.exists():
            raise RuntimeError("fake Kimi tree did not become ready")
        raise KeyboardInterrupt


def test_external_cancellation_cleans_helper_kimi_and_grandchild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, pid_file = _write_nested_helper_tree(tmp_path)
    real_popen = subprocess.Popen

    def cancelling_popen(
        *args: object,
        **kwargs: object,
    ) -> _CancelOnCommunicate:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        return _CancelOnCommunicate(process, pid_file)

    monkeypatch.setattr(entrypoint.subprocess, "Popen", cancelling_popen)

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            _nested_helper_command(helper, pid_file, scenario="timeout"),
            b"{}",
            environment=kimi_worker_environment(_source_environment(tmp_path)),
            timeout_seconds=5.0,
        )

    assert caught.value.code == "helper_cancelled"
    assert caught.value.process_exit_verified is True
    assert pid_file.exists()
    _assert_tree_dead_with_test_cleanup(pid_file)


def test_cancellation_event_cleans_helper_kimi_and_grandchild(
    tmp_path: Path,
) -> None:
    helper, pid_file = _write_nested_helper_tree(tmp_path)
    cancellation_event = threading.Event()

    def cancel_when_tree_is_ready() -> None:
        deadline = time.monotonic() + 5.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancellation_event.set()

    canceller = threading.Thread(target=cancel_when_tree_is_ready, daemon=True)
    canceller.start()
    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            _nested_helper_command(helper, pid_file, scenario="timeout"),
            b"{}",
            environment=kimi_worker_environment(_source_environment(tmp_path)),
            timeout_seconds=5.0,
            cancellation_event=cancellation_event,
        )
    canceller.join(timeout=1.0)

    assert caught.value.code == "helper_cancelled"
    assert caught.value.process_exit_verified is True
    assert pid_file.exists()
    _assert_tree_dead_with_test_cleanup(pid_file)


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended Job contract")
def test_windows_helper_is_suspended_until_job_assignment_then_resumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "helper-ran.txt"
    helper = tmp_path / "ordered-helper.py"
    helper.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import sys",
                "Path(sys.argv[1]).write_text('ran', encoding='ascii')",
                "sys.stdout.buffer.write(b'{}')",
                "sys.stdout.buffer.flush()",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    real_assign = entrypoint._assign_and_resume_windows_process
    events: list[str] = []
    creation_flags: list[int] = []
    real_popen = subprocess.Popen

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

    response = entrypoint._contained_helper_transport(
        (
            str(Path(sys.executable).resolve(strict=True)),
            str(helper.resolve(strict=True)),
            str(sentinel.resolve()),
        ),
        b"{}",
        environment=kimi_worker_environment(_source_environment(tmp_path)),
        timeout_seconds=2.0,
    )

    assert response == b"{}"
    assert events == ["assign-before-resume"]
    assert creation_flags and creation_flags[0] & 0x00000004
    assert sentinel.read_text(encoding="ascii") == "ran"


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended Job contract")
def test_job_assignment_failure_never_runs_uncontained_helper_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "must-not-run.txt"
    helper = tmp_path / "suspended-helper.py"
    helper.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import sys, time",
                "Path(sys.argv[1]).write_text('unsafe', encoding='ascii')",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    spawned: list[subprocess.Popen[bytes]] = []
    creation_flags: list[int] = []
    real_popen = subprocess.Popen

    def recording_popen(
        *args: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        creation_flags.append(int(kwargs.get("creationflags", 0)))
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        spawned.append(process)
        return process

    def reject_assignment(_job: int, _pid: int) -> None:
        raise OSError("simulated AssignProcessToJobObject failure")

    monkeypatch.setattr(entrypoint.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(
        entrypoint,
        "_assign_and_resume_windows_process",
        reject_assignment,
    )

    with pytest.raises(KimiSubscriptionError) as caught:
        entrypoint._contained_helper_transport(
            (
                str(Path(sys.executable).resolve(strict=True)),
                str(helper.resolve(strict=True)),
                str(sentinel.resolve()),
            ),
            b"{}",
            environment=kimi_worker_environment(_source_environment(tmp_path)),
            timeout_seconds=2.0,
        )

    assert caught.value.code == "helper_process_tree_setup_failed"
    assert caught.value.process_exit_verified is True
    assert creation_flags and creation_flags[0] & 0x00000004
    assert not sentinel.exists()
    assert len(spawned) == 1
    process = spawned[0]
    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed


def test_product_entrypoint_does_not_import_or_call_review_helpers() -> None:
    source_path = (
        Path(__file__).resolve().parents[1] / "cli" / "kimi_worker_entrypoint.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)

    assert not any(
        name == "scripts.kimi_acp_private_client"
        or name.startswith("scripts.xreview")
        for name in imported
    )
    assert "run_private_kimi_acp_review" not in called_names
    assert "xreview" not in called_names
