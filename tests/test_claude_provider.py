"""Claude CLI provider tests with an asynchronous subprocess boundary."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from gateway.providers import claude_code as claude_module
from gateway.providers.base import ProviderError
from gateway.providers.claude_code import ClaudeCodeProvider
from gateway.schemas import ChatCompletionRequest
from orchestrator.identity import call_identity_known
from orchestrator.workflows.common import route_receipt


class _FakeProcess:
    def __init__(
        self,
        stdout: str = "",
        *,
        returncode: int = 0,
        stderr: str = "",
        block: bool = False,
    ) -> None:
        self._stdout = stdout.encode("utf-8")
        self._stderr = stderr.encode("utf-8")
        self._configured_returncode = returncode
        self.returncode: int | None = None
        self.pid = 4242
        self.block = block
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.terminate_calls = 0
        self.kill_calls = 0
        self.args: tuple[Any, ...] = ()
        self.kwargs: dict[str, Any] = {}
        self.communicated_input: bytes | None = None
        self.system_prompt_at_spawn: bytes | None = None

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        self.communicated_input = input
        self.started.set()
        if self.block:
            await self.release.wait()
        self.returncode = self._configured_returncode
        return self._stdout, self._stderr

    async def wait(self) -> int:
        if self.returncode is None:
            await self.release.wait()
            self.returncode = self._configured_returncode
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.returncode = -15
        self.release.set()

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9
        self.release.set()


def _req() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="claude-sonnet",
        messages=[
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
        ],
    )


def _provider(tmp_path: Path, *, timeout_s: float = 180.0) -> ClaudeCodeProvider:
    provider = ClaudeCodeProvider(timeout_s=timeout_s)
    attested = tmp_path / "claude.exe"
    attested.write_bytes(b"attested claude test executable")
    provider._cli = str(attested)
    provider._cli_sha256 = hashlib.sha256(attested.read_bytes()).hexdigest()
    provider.enabled = True
    return provider


def _install_process(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess) -> None:
    async def create(*args: Any, **kwargs: Any) -> _FakeProcess:
        process.args = args
        process.kwargs = kwargs
        if "--system-prompt-file" in args:
            prompt_index = args.index("--system-prompt-file") + 1
            process.system_prompt_at_spawn = Path(args[prompt_index]).read_bytes()
        return process

    monkeypatch.setattr(claude_module.asyncio, "create_subprocess_exec", create)


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share pin contract")
async def test_windows_cli_attestation_pin_blocks_post_hash_replacement(
    monkeypatch, tmp_path
):
    provider = _provider(tmp_path)
    executable = Path(provider._cli or "")
    attestations = 0
    real_matches = claude_module.matches_attestation

    def counted_matches(path: str, digest: str) -> bool:
        nonlocal attestations
        attestations += 1
        return real_matches(path, digest)

    monkeypatch.setattr(claude_module, "matches_attestation", counted_matches)

    assert provider._ensure_cli_attestation() is True
    assert provider._ensure_cli_attestation() is True
    assert attestations == 1
    with pytest.raises(OSError):
        executable.write_bytes(b"post-hash replacement")
    with pytest.raises(OSError):
        executable.unlink()

    await provider.aclose()
    executable.write_bytes(b"replacement after explicit release")


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share pin contract")
def test_windows_cli_attestation_failure_is_cached_until_reconfiguration(
    monkeypatch, tmp_path
):
    provider = _provider(tmp_path)
    attempts = 0

    def reject(_path: str, _digest: str) -> None:
        nonlocal attempts
        attempts += 1
        return None

    monkeypatch.setattr(claude_module, "_lock_attested_windows_executable", reject)

    assert provider._ensure_cli_attestation() is False
    assert provider._ensure_cli_attestation() is False
    assert attempts == 1

    provider._cli_sha256 = "f" * 64
    assert provider._ensure_cli_attestation() is False
    assert attempts == 2


async def test_claude_chat_uses_unique_primary_model_usage(monkeypatch, tmp_path):
    payload = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "hello from claude",
        "usage": {"input_tokens": 5, "output_tokens": 3},
        "modelUsage": {
            "claude-haiku-4-5-20251001": {"inputTokens": 1},
            "claude-sonnet-4-5-20250929": {"inputTokens": 5, "outputTokens": 3},
        },
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    provider = _provider(tmp_path)
    out = await provider.chat(_req(), "sonnet")

    assert out["choices"][0]["message"]["content"] == "hello from claude"
    assert out["usage"]["total_tokens"] == 8
    assert out["usage"]["cost_attribution_basis"] == (
        "cli_invocation_total_includes_provider_internal_models"
    )
    assert out["usage"]["provider_model_usage"] == {
        "claude-haiku-4-5-20251001": {"input_tokens": 1},
        "claude-sonnet-4-5-20250929": {
            "input_tokens": 5,
            "output_tokens": 3,
        },
    }
    assert out["model"] == "claude-sonnet-4-5-20250929"
    assert provider.expected_model_family("sonnet") == "anthropic"
    assert provider.verify_model_identity("sonnet", out["model"]) == (
        "claude-sonnet-4-5-20250929",
        "anthropic",
    )
    assert provider.verify_model_identity("opus", out["model"]) is None


async def test_claude_chat_keeps_prompt_content_out_of_process_argv(
    monkeypatch, tmp_path
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "safe",
        "usage": {},
    }
    process = _FakeProcess(json.dumps(payload))
    _install_process(monkeypatch, process)
    system_secret = "SYSTEM-SECRET-ARGUMENT-PROBE"
    conversation_secret = "USER-SECRET-ARGUMENT-PROBE"
    request = ChatCompletionRequest(
        model="claude-sonnet",
        messages=[
            {"role": "system", "content": system_secret},
            {"role": "user", "content": conversation_secret},
        ],
    )

    await _provider(tmp_path).chat(request, "sonnet")

    rendered_args = "\n".join(str(arg) for arg in process.args)
    assert system_secret not in rendered_args
    assert conversation_secret not in rendered_args
    assert "--system-prompt" not in process.args
    assert "--system-prompt-file" in process.args
    assert process.system_prompt_at_spawn == system_secret.encode("utf-8")
    assert process.kwargs["stdin"] is subprocess.PIPE
    assert process.communicated_input == f"User: {conversation_secret}".encode("utf-8")


async def test_claude_attestation_hash_does_not_block_the_event_loop(
    monkeypatch, tmp_path
):
    provider = _provider(tmp_path)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    watchdog_fired = threading.Event()

    def slow_attestation() -> bool:
        started.set()
        try:
            release.wait()
            return False
        finally:
            finished.set()

    def release_watchdog() -> None:
        watchdog_fired.set()
        release.set()

    monkeypatch.setattr(provider, "_ensure_cli_attestation", slow_attestation)
    # This timer is only a real deadlock guard.  The assertion below is causal:
    # a synchronous attestation call blocks the loop until this watchdog fires,
    # while asyncio.to_thread lets the loop sentinel run first regardless of
    # full-suite scheduler latency.
    timer = threading.Timer(2.0, release_watchdog)
    timer.start()
    task = asyncio.create_task(provider.chat(_req(), "sonnet"))
    try:
        async with asyncio.timeout(5.0):
            while not started.is_set():
                await asyncio.sleep(0)
            loop_progressed = asyncio.Event()
            asyncio.get_running_loop().call_soon(loop_progressed.set)
            await loop_progressed.wait()
            assert not watchdog_fired.is_set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    finally:
        release.set()
        timer.cancel()
        # Let the worker observe release before the provider fixture disappears.
        assert await asyncio.to_thread(finished.wait, 5.0)


async def test_maximum_cli_input_preparation_does_not_block_event_loop(
    monkeypatch, tmp_path
):
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    watchdog_fired = threading.Event()
    real_prepare = claude_module._prepare_prompt_workspace

    def release_watchdog() -> None:
        watchdog_fired.set()
        release.set()

    watchdog = threading.Timer(2.0, release_watchdog)

    def gated_prepare(system: str, conversation: str):  # noqa: ANN202
        watchdog.start()
        started.set()
        release.wait()
        try:
            return real_prepare(system, conversation)
        finally:
            finished.set()

    payload = {
        "type": "result",
        "is_error": False,
        "result": "bounded",
        "usage": {},
    }
    process = _FakeProcess(json.dumps(payload))
    _install_process(monkeypatch, process)
    provider = _provider(tmp_path)
    system = "s" * claude_module._MAX_CLAUDE_SYSTEM_PROMPT_BYTES
    conversation = "c" * claude_module._MAX_CLAUDE_CONVERSATION_BYTES
    monkeypatch.setattr(claude_module, "_prepare_prompt_workspace", gated_prepare)
    task = asyncio.create_task(provider._run("sonnet", system, conversation))
    try:
        async with asyncio.timeout(5.0):
            while not started.is_set():
                await asyncio.sleep(0)
            loop_progressed = asyncio.Event()
            asyncio.get_running_loop().call_soon(loop_progressed.set)
            await loop_progressed.wait()
            assert not watchdog_fired.is_set()
            watchdog.cancel()
            release.set()
            assert (await task)["result"] == "bounded"
    finally:
        release.set()
        watchdog.cancel()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if started.is_set():
            assert await asyncio.to_thread(finished.wait, 5.0)

    assert process.communicated_input == conversation.encode("utf-8")


async def test_double_cancel_during_prompt_preparation_still_removes_workspace(
    monkeypatch, tmp_path
):
    started = threading.Event()
    release = threading.Event()
    workspace_path: list[Path] = []

    def slow_prepare(
        _system: str,
        _conversation: str,
    ) -> tuple[claude_module._ProtectedPromptDirectory, bytes]:
        workspace = claude_module._ProtectedPromptDirectory(
            prefix="nachuan-double-cancel-",
            dir=tmp_path,
        )
        Path(workspace.name, "system-prompt.txt").write_text(
            "synthetic prompt",
            encoding="utf-8",
        )
        workspace_path.append(Path(workspace.name))
        started.set()
        release.wait(timeout=2.0)
        return workspace, b"conversation"

    monkeypatch.setattr(claude_module, "_prepare_prompt_workspace", slow_prepare)
    task = asyncio.create_task(
        claude_module._prepare_prompt_workspace_async("system", "conversation")
    )
    while not started.is_set():
        await asyncio.sleep(0.005)

    task.cancel()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    deadline = asyncio.get_running_loop().time() + 2.0
    while workspace_path[0].exists() and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)
    assert not workspace_path[0].exists()


async def test_claude_chat_without_model_usage_does_not_echo_request_alias(
    monkeypatch, tmp_path
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "answer without model evidence",
        "usage": {"input_tokens": 1, "output_tokens": 2},
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    out = await _provider(tmp_path).chat(_req(), "sonnet")

    assert out["model"] == ""
    assert out["model"] != _req().model
    domain = "sha256:" + "a" * 64
    receipt = route_receipt(
        requested_model="claude-alias",
        actual_model="claude-alias",
        route=SimpleNamespace(
            provider=SimpleNamespace(name="claude", independence_domain=domain),
            upstream_model="sonnet",
            independence_domain=domain,
            tier="premium",
        ),
        response=out,
    )
    assert receipt["observed_model"] is None
    assert call_identity_known(receipt) is False


async def test_claude_usage_includes_cache_read_and_creation_in_total_input(
    monkeypatch, tmp_path
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "cache-aware answer",
        "usage": {
            "input_tokens": 5,
            "cache_read_input_tokens": 2,
            "cache_creation_input_tokens": 3,
            "output_tokens": 4,
        },
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    out = await _provider(tmp_path).chat(_req(), "sonnet")

    assert out["usage"]["prompt_tokens"] == 10
    assert out["usage"]["completion_tokens"] == 4
    assert out["usage"]["total_tokens"] == 14
    assert out["usage"]["cached_tokens"] == 2
    assert out["usage"]["cache_read_tokens"] == 2
    assert out["usage"]["cache_creation_tokens"] == 3


async def test_claude_usage_rejects_fractional_token_counts(monkeypatch, tmp_path):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "invalid counts stay unknown",
        "usage": {"input_tokens": 1.9, "output_tokens": "2.0"},
        "modelUsage": {
            "claude-sonnet-4-5-20250929": {
                "inputTokens": 1.9,
                "outputTokens": "2.0",
            }
        },
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    out = await _provider(tmp_path).chat(_req(), "sonnet")

    assert out["usage"]["prompt_tokens"] is None
    assert out["usage"]["completion_tokens"] is None
    assert out["usage"]["total_tokens"] is None
    assert out["usage"]["provider_model_usage"] is None


async def test_claude_chat_with_ambiguous_primary_model_usage_is_unknown(
    monkeypatch, tmp_path
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "ambiguous",
        "usage": {},
        "modelUsage": {
            "claude-sonnet-4-5-20250929": {"inputTokens": 5},
            "claude-opus-4-1-20250805": {"inputTokens": 2},
            "claude-haiku-4-5-20251001": {"inputTokens": 1},
        },
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    out = await _provider(tmp_path).chat(_req(), "sonnet")

    assert out["model"] == ""


@pytest.mark.parametrize("requested_model", ["haiku", "claude-haiku-4-5-20251001"])
async def test_claude_explicit_haiku_accepts_unique_haiku_model_usage(
    monkeypatch, tmp_path, requested_model
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "fast answer",
        "usage": {"input_tokens": 1, "output_tokens": 2},
        "modelUsage": {
            "claude-haiku-4-5-20251001": {"inputTokens": 1},
        },
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    provider = _provider(tmp_path)
    out = await provider.chat(_req(), requested_model)

    assert out["model"] == "claude-haiku-4-5-20251001"
    assert provider.verify_model_identity(requested_model, out["model"]) == (
        "claude-haiku-4-5-20251001",
        "anthropic",
    )


async def test_claude_not_logged_in_raises(monkeypatch, tmp_path):
    upstream_secret = (
        r"Not logged in - Please run /login; token=sk-live-login "
        r"C:\Users\owner\.claude.json"
    )
    payload = {
        "type": "result",
        "is_error": True,
        "result": upstream_secret,
        "usage": {},
    }
    _install_process(
        monkeypatch,
        _FakeProcess(json.dumps(payload), returncode=1),
    )

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == (
        "Claude CLI 调用失败"
        "（error_type=authentication_required, exit_code=1）"
    )
    assert raised.value.status_code == 502
    assert "Not logged in" not in public
    assert "sk-live-login" not in public
    assert "C:\\Users" not in public


async def test_claude_json_error_uses_fixed_upstream_category_without_result(
    monkeypatch, tmp_path
):
    upstream_secret = r"provider failed token=sk-live-json D:\tenant\secret.json"
    payload = {
        "type": "result",
        "is_error": True,
        "result": upstream_secret,
        "usage": {},
    }
    _install_process(
        monkeypatch,
        _FakeProcess(json.dumps(payload), returncode=9, stderr="stderr-secret"),
    )

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == (
        "Claude CLI 调用失败"
        "（error_type=upstream_error, exit_code=9）"
    )
    assert raised.value.status_code == 502
    assert "sk-live-json" not in public
    assert "stderr-secret" not in public
    assert "D:\\tenant" not in public


async def test_claude_launch_error_does_not_expose_path_command_or_secret(
    monkeypatch, tmp_path
):
    leaked = r"C:\Users\owner\.claude\private.exe --token sk-live-secret"

    async def fail_launch(*_args, **_kwargs):
        raise PermissionError(f"access denied while launching {leaked}")

    monkeypatch.setattr(
        claude_module.asyncio,
        "create_subprocess_exec",
        fail_launch,
    )

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == "Claude CLI 无法启动（error_type=os_error）"
    assert raised.value.status_code == 502
    assert "C:\\Users" not in public
    assert "private.exe" not in public
    assert "sk-live-secret" not in public


async def test_claude_unparseable_raises(monkeypatch, tmp_path):
    stdout_secret = r"not-json stdout-secret C:\Users\owner\prompt.txt"
    stderr_secret = r"stderr-secret --api-key sk-live-secret D:\private"
    _install_process(
        monkeypatch,
        _FakeProcess(stdout_secret, returncode=23, stderr=stderr_secret),
    )

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == (
        "Claude CLI 输出无法解析"
        "（error_type=invalid_output, exit_code=23）"
    )
    assert raised.value.status_code == 502
    assert "stdout-secret" not in public
    assert "stderr-secret" not in public
    assert "sk-live-secret" not in public
    assert "C:\\Users" not in public
    assert "D:\\private" not in public


async def test_claude_nonzero_exit_cannot_return_or_echo_parseable_result(
    monkeypatch, tmp_path
):
    result_secret = r"answer-with-secret sk-live-result C:\private\answer.txt"
    payload = {
        "type": "result",
        "is_error": False,
        "result": result_secret,
        "usage": {},
    }
    _install_process(
        monkeypatch,
        _FakeProcess(json.dumps(payload), returncode=17, stderr="stderr-secret"),
    )

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == (
        "Claude CLI 进程异常退出"
        "（error_type=nonzero_exit, exit_code=17）"
    )
    assert raised.value.status_code == 502
    assert "answer-with-secret" not in public
    assert "sk-live-result" not in public
    assert "stderr-secret" not in public
    assert "C:\\private" not in public


async def test_claude_stream_uses_observed_model(monkeypatch, tmp_path):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "one two three",
        "usage": {"input_tokens": 1, "output_tokens": 3},
        "modelUsage": {"claude-sonnet-4-5-20250929": {"inputTokens": 1}},
    }
    _install_process(monkeypatch, _FakeProcess(json.dumps(payload)))

    chunks = [chunk async for chunk in _provider(tmp_path).stream(_req(), "sonnet")]
    text = "".join(
        chunk["choices"][0]["delta"].get("content", "")
        for chunk in chunks
        if chunk.get("choices")
    )

    assert text == "one two three"
    assert any(chunk.get("usage") for chunk in chunks)
    assert {chunk["model"] for chunk in chunks} == {"claude-sonnet-4-5-20250929"}


async def test_claude_cancellation_terminates_subprocess(monkeypatch, tmp_path):
    process = _FakeProcess(block=True)
    _install_process(monkeypatch, process)
    cleanup_calls: list[_FakeProcess] = []

    async def cleanup(proc: _FakeProcess, **_kwargs: Any) -> bool:
        cleanup_calls.append(proc)
        proc.terminate()
        return True

    monkeypatch.setattr(claude_module, "_terminate_process_tree", cleanup)
    task = asyncio.create_task(_provider(tmp_path).chat(_req(), "sonnet"))
    await asyncio.wait_for(process.started.wait(), timeout=3.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=0.2)

    assert cleanup_calls == [process]


async def test_claude_timeout_terminates_subprocess(monkeypatch, tmp_path):
    process = _FakeProcess(block=True)
    _install_process(monkeypatch, process)
    cleanup_calls: list[_FakeProcess] = []

    async def cleanup(proc: _FakeProcess, **_kwargs: Any) -> bool:
        cleanup_calls.append(proc)
        proc.terminate()
        return True

    monkeypatch.setattr(claude_module, "_terminate_process_tree", cleanup)

    with pytest.raises(ProviderError) as error:
        await _provider(tmp_path, timeout_s=0.01).chat(_req(), "sonnet")

    assert error.value.status_code == 504
    assert str(error.value) == "Claude CLI 请求超时（error_type=timeout）"
    assert "0.01" not in str(error.value)
    assert cleanup_calls == [process]


async def test_claude_process_io_error_is_sanitized_after_verified_cleanup(
    monkeypatch, tmp_path
):
    process = _FakeProcess()
    leaked = r"stderr pipe failed at C:\Users\owner\secret.log token=sk-live-io"

    async def fail_communicate(input: bytes | None = None):
        process.communicated_input = input
        process.started.set()
        raise OSError(leaked)

    process.communicate = fail_communicate  # type: ignore[method-assign]
    _install_process(monkeypatch, process)
    cleanup_calls: list[_FakeProcess] = []

    async def cleanup(proc: _FakeProcess, **_kwargs: Any) -> bool:
        cleanup_calls.append(proc)
        proc.terminate()
        return True

    monkeypatch.setattr(claude_module, "_terminate_process_tree", cleanup)

    with pytest.raises(ProviderError) as raised:
        await _provider(tmp_path).chat(_req(), "sonnet")

    public = str(raised.value)
    assert public == "Claude CLI 进程结果不可用（error_type=process_io）"
    assert raised.value.status_code == 502
    assert "C:\\Users" not in public
    assert "secret.log" not in public
    assert "sk-live-io" not in public
    assert cleanup_calls == [process]


@pytest.mark.skipif(os.name != "nt", reason="Windows file-share pin contract")
async def test_claude_aclose_drains_active_call_before_releasing_pin(
    monkeypatch, tmp_path
):
    payload = {
        "type": "result",
        "is_error": False,
        "result": "drained",
        "usage": {},
    }
    process = _FakeProcess(json.dumps(payload), block=True)
    _install_process(monkeypatch, process)
    provider = _provider(tmp_path)
    executable = Path(provider._cli or "")
    call = asyncio.create_task(provider.chat(_req(), "sonnet"))
    await asyncio.wait_for(process.started.wait(), timeout=3.0)

    closing = asyncio.create_task(provider.aclose())
    await asyncio.sleep(0.02)
    assert not closing.done()
    with pytest.raises(OSError):
        executable.write_bytes(b"replacement while request is active")

    process.release.set()
    assert (await call)["choices"][0]["message"]["content"] == "drained"
    await closing
    executable.write_bytes(b"replacement after drained close")
    with pytest.raises(ProviderError, match="provider is closing"):
        await provider.chat(_req(), "sonnet")


async def test_claude_unverified_process_cleanup_disables_runtime(
    monkeypatch, tmp_path
):
    process = _FakeProcess(block=True)
    _install_process(monkeypatch, process)

    async def cleanup_without_terminal_state(
        _proc: _FakeProcess, **_kwargs: Any
    ) -> None:
        return None

    monkeypatch.setattr(
        claude_module,
        "_terminate_process_tree",
        cleanup_without_terminal_state,
    )
    claude_module._CLAUDE_RUNTIME_COMPROMISED.clear()
    try:
        with pytest.raises(ProviderError) as error:
            await _provider(tmp_path, timeout_s=0.01).chat(_req(), "sonnet")

        assert error.value.status_code == 503
        assert str(error.value) == (
            "Claude CLI cleanup could not be verified; "
            "runtime disabled until restart"
        )
        assert "runtime disabled until restart" in str(error.value)
        assert process.returncode is None
        assert claude_module._CLAUDE_RUNTIME_COMPROMISED.is_set()
    finally:
        process.terminate()
        claude_module._CLAUDE_RUNTIME_COMPROMISED.clear()


def test_prompt_cleanup_failure_preserves_active_provider_error(tmp_path):
    claude_module._CLAUDE_RUNTIME_COMPROMISED.clear()
    workspace = claude_module._ProtectedPromptDirectory(
        prefix="nachuan-cleanup-test-",
        dir=tmp_path,
    )
    original_cleanup = workspace.cleanup

    def fail_cleanup() -> None:
        raise PermissionError("synthetic locked prompt")

    workspace.cleanup = fail_cleanup  # type: ignore[method-assign]
    original = ProviderError("original provider timeout", status_code=504)
    try:
        with pytest.raises(ProviderError) as error:
            with workspace:
                raise original

        assert error.value is original
        assert error.value.status_code == 504
        assert any("cleanup failed" in note for note in error.value.__notes__)
        assert claude_module._CLAUDE_RUNTIME_COMPROMISED.is_set()
    finally:
        workspace.cleanup = original_cleanup  # type: ignore[method-assign]
        workspace.cleanup()
        claude_module._CLAUDE_RUNTIME_COMPROMISED.clear()


async def test_interrupt_cleanup_rejects_terminal_parent_with_live_descendant(
    monkeypatch,
):
    class _TerminalParent:
        returncode = 0

    async def cleanup_with_live_descendant(_proc: Any) -> bool:
        # False is the tree-cleanup result: the direct parent exited, but a
        # captured descendant is still alive and therefore cleanup is unverified.
        return False

    monkeypatch.setattr(
        claude_module,
        "_terminate_process_tree",
        cleanup_with_live_descendant,
    )

    assert not await claude_module._cleanup_process_after_interrupt(_TerminalParent())


async def test_interrupt_cleanup_timeout_fails_closed_without_cancelling_drain(
    monkeypatch,
):
    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()
    cancelled = asyncio.Event()

    async def slow_verified_cleanup(_proc: Any) -> bool:
        started.set()
        try:
            await release.wait()
            return True
        except asyncio.CancelledError:
            cancelled.set()
            raise
        finally:
            finished.set()

    monkeypatch.setattr(claude_module, "_terminate_process_tree", slow_verified_cleanup)
    monkeypatch.setattr(
        claude_module,
        "_PROCESS_CLEANUP_TIMEOUT_SECONDS",
        -0.24,
    )

    async with asyncio.timeout(5.0):
        assert not await claude_module._cleanup_process_after_interrupt(object())
        assert started.is_set()
        await asyncio.sleep(0)
        assert not cancelled.is_set()
        release.set()
        await finished.wait()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Toolhelp semantics")
def test_windows_descendant_snapshot_rejects_partial_enumeration(monkeypatch):
    class _FakeFunction:
        def __init__(self, implementation):  # noqa: ANN001
            self._implementation = implementation
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):  # noqa: ANN002, ANN202
            return self._implementation(*args)

    def first_process(_snapshot, entry_pointer):  # noqa: ANN001, ANN202
        entry_pointer._obj.th32ProcessID = 4242
        entry_pointer._obj.th32ParentProcessID = 0
        return True

    def interrupted_enumeration(_snapshot, _entry_pointer):  # noqa: ANN001, ANN202
        ctypes.set_last_error(5)
        return False

    class _FakeKernel32:
        CreateToolhelp32Snapshot = _FakeFunction(lambda *_: 123)
        Process32FirstW = _FakeFunction(first_process)
        Process32NextW = _FakeFunction(interrupted_enumeration)
        OpenProcess = _FakeFunction(lambda *_: 0)

    monkeypatch.setattr(claude_module.ctypes, "WinDLL", lambda *_args, **_kwargs: _FakeKernel32())
    monkeypatch.setattr(claude_module, "_close_windows_handle", lambda _handle: None)

    handles, verified = claude_module._capture_windows_descendant_handles(4242)

    assert handles == []
    assert verified is False


@pytest.mark.skipif(os.name != "nt", reason="requires Windows tree-cleanup path")
@pytest.mark.parametrize(
    ("taskkill_returncode", "descendants_verified"),
    [(1, True), (0, False)],
)
async def test_windows_tree_cleanup_requires_killer_and_descendant_verification(
    monkeypatch,
    taskkill_returncode,
    descendants_verified,
):
    class _Parent:
        pid = 4242
        returncode = None

        def kill(self) -> None:
            self.returncode = -9

    class _Killer:
        def __init__(self) -> None:
            self.returncode = taskkill_returncode

        def kill(self) -> None:
            self.returncode = -9

    parent = _Parent()
    killer = _Killer()
    closed: list[int] = []
    real_close_windows_handle = claude_module._close_windows_handle

    def close_test_handle(handle: int) -> None:
        if handle == 909:
            closed.append(handle)
        else:
            real_close_windows_handle(handle)

    async def create_killer(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        return killer

    async def wait_process(process, _timeout):  # noqa: ANN001, ANN202
        if process is parent:
            parent.returncode = 0
        return process.returncode is not None

    monkeypatch.setattr(
        claude_module,
        "_capture_windows_descendant_handles",
        lambda _pid: ([909], True),
    )
    monkeypatch.setattr(
        claude_module,
        "_terminate_and_verify_windows_handles",
        lambda _handles, _timeout: descendants_verified,
    )
    monkeypatch.setattr(claude_module, "_close_windows_handle", close_test_handle)
    monkeypatch.setattr(claude_module, "_wait_process", wait_process)
    monkeypatch.setattr(
        claude_module,
        "trusted_windows_system_executable",
        lambda _name: r"C:\Windows\System32\taskkill.exe",
    )
    monkeypatch.setattr(
        claude_module.asyncio,
        "create_subprocess_exec",
        create_killer,
    )

    verified = await claude_module._terminate_process_tree(parent, cleanup_timeout=1.0)

    assert verified is False
    assert closed == [909]


@pytest.mark.skipif(os.name != "nt", reason="requires Windows tree-cleanup path")
async def test_windows_tree_cleanup_shares_full_deadline_with_trusted_killer(
    monkeypatch,
):
    class _Parent:
        pid = 4242
        returncode = None

        def kill(self) -> None:
            self.returncode = -9

    class _Killer:
        returncode = None

        def kill(self) -> None:
            self.returncode = -9

    parent = _Parent()
    killer = _Killer()
    killer_wait_budgets: list[float] = []
    real_close_windows_handle = claude_module._close_windows_handle

    async def create_killer(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        return killer

    async def wait_process(process, timeout):  # noqa: ANN001, ANN202
        if process is killer:
            killer_wait_budgets.append(timeout)
            if timeout >= 0.75:
                killer.returncode = 0
                return True
            return False
        parent.returncode = 0
        return True

    def close_test_handle(handle: int) -> None:
        if handle != 909:
            real_close_windows_handle(handle)

    monkeypatch.setattr(
        claude_module,
        "_capture_windows_descendant_handles",
        lambda _pid: ([909], True),
    )
    monkeypatch.setattr(
        claude_module,
        "_terminate_and_verify_windows_handles",
        lambda _handles, _timeout: True,
    )
    monkeypatch.setattr(claude_module, "_close_windows_handle", close_test_handle)
    monkeypatch.setattr(claude_module, "_wait_process", wait_process)
    monkeypatch.setattr(
        claude_module,
        "trusted_windows_system_executable",
        lambda _name: r"C:\Windows\System32\taskkill.exe",
    )
    monkeypatch.setattr(
        claude_module.asyncio,
        "create_subprocess_exec",
        create_killer,
    )

    verified = await claude_module._terminate_process_tree(parent, cleanup_timeout=1.0)

    assert verified is True
    assert killer_wait_budgets[0] >= 0.75


@pytest.mark.skipif(os.name != "nt", reason="requires the real Windows process tree")
async def test_windows_process_tree_cleanup_leaves_no_grandchild(tmp_path):
    """The real Windows cleanup path must reap both the CLI and its descendant."""

    from ctypes import wintypes

    process_terminate = 0x0001
    synchronize = 0x00100000
    wait_object_0 = 0x00000000
    wait_timeout = 0x00000102

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    def open_test_process(pid: int) -> Any:
        handle = kernel32.OpenProcess(process_terminate | synchronize, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def force_stop_test_process(handle: Any) -> None:
        if kernel32.WaitForSingleObject(handle, 0) == wait_timeout:
            kernel32.TerminateProcess(handle, 137)
            kernel32.WaitForSingleObject(handle, 2_000)

    grandchild_pid_file = tmp_path / "grandchild.pid"
    parent_script = """
import pathlib
import subprocess
import sys
import time

grandchild = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
pid_path = pathlib.Path(sys.argv[1])
ready_path = pid_path.with_suffix(".ready")
ready_path.write_text(str(grandchild.pid), encoding="ascii")
ready_path.replace(pid_path)
time.sleep(120)
"""
    proc: asyncio.subprocess.Process | None = None
    parent_handle: Any = None
    grandchild_handle: Any = None
    cleanup_verdicts: list[dict[str, bool | float | int]] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            parent_script,
            str(grandchild_pid_file),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            ),
        )
        parent_handle = open_test_process(proc.pid)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + 3.0
        while loop.time() < deadline and not grandchild_pid_file.exists():
            if proc.returncode is not None:
                pytest.fail(f"test parent exited before spawning: {proc.returncode}")
            await asyncio.sleep(0.02)
        assert grandchild_pid_file.exists(), "test grandchild did not report its PID"

        grandchild_pid = int(grandchild_pid_file.read_text(encoding="ascii"))
        grandchild_handle = open_test_process(grandchild_pid)
        assert kernel32.WaitForSingleObject(parent_handle, 0) == wait_timeout
        assert kernel32.WaitForSingleObject(grandchild_handle, 0) == wait_timeout

        verified = await asyncio.wait_for(
            claude_module._terminate_process_tree(
                proc,
                verdict_observer=cleanup_verdicts.append,
            ),
            timeout=4.0,
        )

        assert verified is True, cleanup_verdicts[-1] if cleanup_verdicts else {}
        await asyncio.wait_for(proc.wait(), timeout=1.0)
        assert kernel32.WaitForSingleObject(parent_handle, 0) == wait_object_0
        assert kernel32.WaitForSingleObject(grandchild_handle, 2_000) == wait_object_0
    finally:
        # Handles bind cleanup to these exact test-created process objects, so
        # PID reuse cannot cause an unrelated process to be terminated.
        if grandchild_handle:
            force_stop_test_process(grandchild_handle)
            kernel32.CloseHandle(grandchild_handle)
        if parent_handle:
            force_stop_test_process(parent_handle)
            kernel32.CloseHandle(parent_handle)
        if proc is not None and proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except TimeoutError:
                pass
