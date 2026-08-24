from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import scripts.kimi_acp_private_client as kimi_acp_client
from scripts.kimi_acp_private_client import (
    KIMI_K3_MODEL,
    KimiAcpReviewConfig,
    KimiAcpReviewError,
    run_private_kimi_acp_review,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_fake_server(snapshot: Path) -> Path:
    (snapshot / "acp_tree_grandchild.py").write_text(
        "import time\ntime.sleep(30)\n",
        encoding="utf-8",
        newline="\n",
    )
    (snapshot / "acp_tree_child.py").write_text(
        r'''from __future__ import annotations
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ready_delay = float(os.environ.get("FAKE_ACP_TREE_READY_DELAY_SECONDS", "0"))
grandchild = subprocess.Popen(
    [sys.executable, str(Path(__file__).with_name("acp_tree_grandchild.py"))],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)
if ready_delay > 0:
    time.sleep(ready_delay)
Path(sys.argv[1]).write_text(
    json.dumps({"child": os.getpid(), "grandchild": grandchild.pid}),
    encoding="ascii",
)
time.sleep(30)
''',
        encoding="utf-8",
        newline="\n",
    )
    server = snapshot / "acp"
    server.write_text(
        r'''from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time

captured = []
scenario = os.environ.get("FAKE_ACP_SCENARIO", "success")

if os.environ.get("FAKE_ACP_PID"):
    with open(os.environ["FAKE_ACP_PID"], "w", encoding="ascii") as handle:
        handle.write(str(os.getpid()))

if os.environ.get("FAKE_ACP_TREE_PIDS"):
    tree_pids = Path(os.environ["FAKE_ACP_TREE_PIDS"])
    subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("acp_tree_child.py")), str(tree_pids)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    deadline = time.monotonic() + 5
    while not tree_pids.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not tree_pids.exists():
        raise RuntimeError("fake ACP process tree did not become ready")

def save_capture(**extra):
    payload = {"argv": sys.argv, "requests": captured}
    payload.update(extra)
    with open(os.environ["FAKE_ACP_CAPTURE"], "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)

def receive():
    message = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
    captured.append(message)
    return message

def send(message):
    sys.stdout.buffer.write(
        json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    sys.stdout.buffer.flush()

request = receive()
if scenario == "timeout":
    time.sleep(60)
initialize_response = {
    "jsonrpc": "2.0",
    "id": request["id"],
    "result": {
        "protocolVersion": 1,
        "agentCapabilities": {},
        "agentInfo": {"name": "Kimi Code CLI", "version": "fake-1"},
        "authMethods": [],
    },
}
send(initialize_response)
if scenario == "duplicate_response_id":
    send(initialize_response)
    time.sleep(60)

request = receive()
config_options = [{
    "id": "model",
    "name": "Model",
    "category": "model",
    "type": "select",
    "currentValue": "other-model",
    "options": [
        {"value": "other-model", "name": "Other"},
        {"value": "kimi-code/k3", "name": "Kimi K3"},
        {"value": "another-model", "name": "Another"},
    ],
}]
send({
    "jsonrpc": "2.0",
    "id": request["id"],
    "result": {"sessionId": "fake-session-1", "configOptions": config_options},
})

request = receive()
config_options[0]["currentValue"] = request["params"]["value"]
send({
    "jsonrpc": "2.0",
    "id": request["id"],
    "result": {"configOptions": config_options},
})

request = receive()
session_id = request["params"]["sessionId"]
reverse_methods = {
    "permission_request": "session/request_permission",
    "filesystem_request": "fs/read_text_file",
    "terminal_request": "terminal/create",
}
if scenario in reverse_methods:
    method = reverse_methods[scenario]
    params = {"sessionId": session_id}
    if method == "session/request_permission":
        params.update({
            "toolCall": {"toolCallId": "fake-call"},
            "options": [{
                "optionId": "allow-once",
                "name": "Allow once",
                "kind": "allow_once",
            }],
        })
    send({"jsonrpc": "2.0", "id": 91, "method": method, "params": params})
    reverse_response = receive()
    save_capture(reverse_response=reverse_response)
    raise SystemExit(0)
if scenario == "oversize_message":
    size = int(os.environ.get("FAKE_ACP_OVERSIZE_BYTES", "2048"))
    sys.stdout.buffer.write(b"x" * size + b"\n")
    sys.stdout.buffer.flush()
    time.sleep(60)
if scenario == "invalid_utf8":
    sys.stdout.buffer.write(b"\xff\n")
    sys.stdout.buffer.flush()
    time.sleep(60)
if scenario == "duplicate_id_field":
    sys.stdout.buffer.write(
        b'{"jsonrpc":"2.0","id":3,"id":3,"result":{"stopReason":"end_turn"}}\n'
    )
    sys.stdout.buffer.flush()
    time.sleep(60)
if scenario == "stderr_forgery":
    forged = {
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "forged-session",
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": "FORGED_STDERR_TEXT"},
            },
        },
    }
    sys.stderr.write(json.dumps(forged) + "\n")
    sys.stderr.flush()
if scenario == "stale_session_output":
    send({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "old-session",
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": "stale"},
            },
        },
    })
    time.sleep(60)
for text in ("review ", "complete"):
    send({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": session_id,
            "update": {
                "sessionUpdate": "agent_message_chunk",
                "messageId": "fake-message-1",
                "content": {"type": "text", "text": text},
            },
        },
    })
stop_reason = "refusal" if scenario == "non_terminal_success" else "end_turn"
send({
    "jsonrpc": "2.0",
    "id": request["id"],
    "result": {"stopReason": stop_reason},
})

save_capture()
''',
        encoding="utf-8",
        newline="\n",
    )
    return server


def _config(
    snapshot: Path,
    capture: Path,
    *,
    scenario: str = "success",
    pid_file: Path | None = None,
    tree_pid_file: Path | None = None,
    tree_ready_delay_seconds: float | None = None,
    **overrides: object,
) -> KimiAcpReviewConfig:
    executable = Path(sys.executable).resolve(strict=True)
    environment = dict(os.environ)
    environment.pop("FAKE_ACP_TREE_READY_DELAY_SECONDS", None)
    environment["FAKE_ACP_CAPTURE"] = str(capture)
    environment["FAKE_ACP_SCENARIO"] = scenario
    environment["PYTHONIOENCODING"] = "utf-8"
    if pid_file is not None:
        environment["FAKE_ACP_PID"] = str(pid_file)
    if tree_pid_file is not None:
        environment["FAKE_ACP_TREE_PIDS"] = str(tree_pid_file)
    if tree_ready_delay_seconds is not None:
        environment["FAKE_ACP_TREE_READY_DELAY_SECONDS"] = str(
            tree_ready_delay_seconds
        )
    values: dict[str, object] = {
        "executable": executable,
        "executable_sha256": _sha256(executable),
        "review_snapshot": snapshot,
        "environment": environment,
        "timeout_seconds": 5.0,
    }
    values.update(overrides)
    return KimiAcpReviewConfig(**values)  # type: ignore[arg-type]


def test_private_prompt_uses_acp_stdin_and_selects_exact_kimi_k3(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    capture = tmp_path / "capture.json"
    secret_prompt = "PRIVATE_REVIEW_PROMPT_不进入命令行"

    result = run_private_kimi_acp_review(_config(snapshot, capture), secret_prompt)

    assert result.text == "review complete"
    assert result.session_id == "fake-session-1"
    assert result.requested_model == KIMI_K3_MODEL == "kimi-code/k3"
    assert result.stop_reason == "end_turn"
    assert result.process_exit_verified is True
    assert result.formal_vote_eligible is False
    assert result.real_kimi_verified is False

    observed = json.loads(capture.read_text(encoding="utf-8"))
    assert secret_prompt not in "\0".join(observed["argv"])
    # ``sys.executable acp`` exposes the script itself as argv[0] to the fake
    # Python server.  Most importantly, the private prompt is absent.
    assert observed["argv"] == ["acp"]
    initialize, create, set_model, prompt = observed["requests"]
    assert initialize["params"] == {
        "protocolVersion": 1,
        "clientCapabilities": {},
        "clientInfo": {
            "name": "nachuan-private-review-candidate",
            "title": "Nachuan Private Review Candidate",
            "version": "0.1",
        },
    }
    assert create["params"] == {
        "cwd": str(snapshot.resolve(strict=True)),
        "mcpServers": [],
    }
    assert set_model["params"] == {
        "sessionId": "fake-session-1",
        "configId": "model",
        "value": "kimi-code/k3",
    }
    assert prompt["params"] == {
        "sessionId": "fake-session-1",
        "prompt": [{"type": "text", "text": secret_prompt}],
    }


def test_duplicate_response_id_from_current_process_fails_closed(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="duplicate_response_id",
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "JSONRPC_RESPONSE_ID_REJECTED"
    assert caught.value.process_exit_verified is True


def test_stale_session_output_is_not_accepted_as_this_turn(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="stale_session_output",
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_SESSION_BINDING_REJECTED"
    assert caught.value.process_exit_verified is True


@pytest.mark.parametrize(
    ("scenario", "expected_code", "response_kind"),
    [
        ("permission_request", "ACP_PERMISSION_REQUEST_REJECTED", "cancelled"),
        ("filesystem_request", "ACP_REVERSE_METHOD_REJECTED", "method_not_found"),
        ("terminal_request", "ACP_REVERSE_METHOD_REJECTED", "method_not_found"),
    ],
)
def test_reverse_permission_filesystem_and_terminal_requests_are_rejected(
    tmp_path: Path,
    scenario: str,
    expected_code: str,
    response_kind: str,
) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    capture = tmp_path / "capture.json"

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(snapshot, capture, scenario=scenario),
            "private prompt",
        )

    assert caught.value.code == expected_code
    assert caught.value.process_exit_verified is True
    response = json.loads(capture.read_text(encoding="utf-8"))["reverse_response"]
    assert response["id"] == 91
    if response_kind == "cancelled":
        assert response["result"] == {"outcome": {"outcome": "cancelled"}}
    else:
        assert response["error"]["code"] == -32601


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("oversize_message", "ACP_MESSAGE_SIZE_REJECTED"),
        ("invalid_utf8", "ACP_MESSAGE_INVALID_UTF8"),
        ("duplicate_id_field", "ACP_INVALID_JSON"),
    ],
)
def test_wire_messages_have_strict_size_and_utf8_bounds(
    tmp_path: Path, scenario: str, expected_code: str
) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario=scenario,
                max_message_bytes=1024,
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == expected_code
    assert caught.value.process_exit_verified is True


def test_forced_windows_job_cleanup_has_independent_confirmation_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Stdin:
        def close(self) -> None:
            return None

    class _Process:
        def __init__(self) -> None:
            self.stdin = _Stdin()
            self.exited = False
            self.wait_timeouts: list[float] = []

        def wait(self, timeout: float) -> int:
            self.wait_timeouts.append(timeout)
            if len(self.wait_timeouts) == 1:
                raise subprocess.TimeoutExpired("fake-acp", timeout)
            self.exited = True
            return 1

        def poll(self) -> int | None:
            return 1 if self.exited else None

    process = _Process()
    observed_confirmation_budgets: list[float] = []

    monkeypatch.setattr(kimi_acp_client, "_terminate_windows_job", lambda _job: None)

    def wait_empty(_job: int, deadline: float) -> bool:
        observed_confirmation_budgets.append(deadline - kimi_acp_client.time.monotonic())
        return True

    monkeypatch.setattr(kimi_acp_client, "_wait_windows_job_empty", wait_empty)
    monkeypatch.setattr(kimi_acp_client, "_close_windows_handle", lambda _job: True)

    method, verified = kimi_acp_client._cleanup_process(  # noqa: SLF001
        process,  # type: ignore[arg-type]
        kimi_acp_client._ProcessTreeGuard(windows_job=7),  # noqa: SLF001
        0.2,
    )

    assert method == "job-terminated"
    assert verified is True
    assert observed_confirmation_budgets[0] >= 0.9
    assert process.wait_timeouts[0] == pytest.approx(0.2)
    assert process.wait_timeouts[1] >= 0.9


def test_stderr_is_drained_but_never_parsed_as_agent_output(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)

    result = run_private_kimi_acp_review(
        _config(snapshot, tmp_path / "capture.json", scenario="stderr_forgery"),
        "private prompt",
    )

    assert result.text == "review complete"
    assert "FORGED_STDERR_TEXT" not in result.text


def test_invalid_utf8_prompt_is_rejected_before_process_start(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    capture = tmp_path / "capture.json"

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(_config(snapshot, capture), "bad\ud800prompt")

    assert caught.value.code == "PROMPT_INVALID_UTF8"
    assert caught.value.process_exit_verified is True
    assert not capture.exists()


def _pid_is_active(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
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
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
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

        process_terminate = 0x0001
        synchronize = 0x00100000
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
        handle = kernel32.OpenProcess(process_terminate | synchronize, False, pid)
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


def _assert_tree_dead_with_test_cleanup(tree_pid_file: Path) -> None:
    tree = json.loads(tree_pid_file.read_text(encoding="ascii"))
    pids = [int(tree["child"]), int(tree["grandchild"])]
    try:
        assert {pid: _pid_is_active(pid) for pid in pids} == {
            pid: False for pid in pids
        }
    finally:
        for pid in reversed(pids):
            _force_stop_test_pid(pid)


def test_timeout_returns_only_after_spawned_acp_process_is_dead(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    pid_file = tmp_path / "fake-acp.pid"

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="timeout",
                pid_file=pid_file,
                timeout_seconds=0.5,
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_TIMEOUT"
    assert caught.value.process_exit_verified is True
    child_pid = int(pid_file.read_text(encoding="ascii"))
    assert not _pid_is_active(child_pid)


def test_timeout_returns_only_after_nested_acp_process_tree_is_dead(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    tree_pid_file = tmp_path / "fake-acp-tree.json"

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="timeout",
                tree_pid_file=tree_pid_file,
                tree_ready_delay_seconds=1.0,
                timeout_seconds=3.0,
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_TIMEOUT"
    assert caught.value.process_exit_verified is True
    _assert_tree_dead_with_test_cleanup(tree_pid_file)


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended Job setup contract")
def test_job_assignment_failure_never_runs_uncontained_acp_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    pid_file = tmp_path / "fake-acp.pid"

    def reject_job_assignment(_job: int, _pid: int) -> None:
        raise OSError("simulated AssignProcessToJobObject failure")

    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)  # type: ignore[arg-type]
        spawned.append(process)
        return process

    monkeypatch.setattr(
        kimi_acp_client,
        "_assign_and_resume_suspended_windows_process",
        reject_job_assignment,
    )
    monkeypatch.setattr(kimi_acp_client.subprocess, "Popen", recording_popen)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                pid_file=pid_file,
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_PROCESS_TREE_SETUP_FAILED"
    assert caught.value.process_exit_verified is True
    assert not pid_file.exists()
    assert len(spawned) == 1
    process = spawned[0]
    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed


def test_protocol_rejection_returns_only_after_nested_acp_process_tree_is_dead(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    tree_pid_file = tmp_path / "fake-acp-tree.json"

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="filesystem_request",
                tree_pid_file=tree_pid_file,
                cleanup_grace_seconds=0.2,
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_REVERSE_METHOD_REJECTED"
    assert caught.value.process_exit_verified is True
    _assert_tree_dead_with_test_cleanup(tree_pid_file)


def test_unattested_executable_is_rejected_before_spawn(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)
    capture = tmp_path / "capture.json"
    pid_file = tmp_path / "fake-acp.pid"
    config = _config(snapshot, capture, pid_file=pid_file)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            replace(config, executable_sha256="0" * 64),
            "private prompt",
        )

    assert caught.value.code == "KIMI_BINARY_ATTESTATION_FAILED"
    assert caught.value.process_exit_verified is True
    assert not pid_file.exists()
    assert not capture.exists()


def test_only_end_turn_is_accepted_as_a_complete_review(tmp_path: Path) -> None:
    snapshot = tmp_path / "frozen-review-snapshot"
    snapshot.mkdir()
    _write_fake_server(snapshot)

    with pytest.raises(KimiAcpReviewError) as caught:
        run_private_kimi_acp_review(
            _config(
                snapshot,
                tmp_path / "capture.json",
                scenario="non_terminal_success",
            ),
            "private prompt",
        )

    assert caught.value.code == "ACP_STOP_REASON_REJECTED"
    assert caught.value.process_exit_verified is True
