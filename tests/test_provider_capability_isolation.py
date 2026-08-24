"""普通聊天不得隐式升级为本机执行权限。"""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
from pathlib import Path

import pytest

from gateway.providers import codex as codex_module
from gateway.providers.base import ProviderError
from gateway.providers.claude_code import ClaudeCodeProvider
from gateway.providers.codex import CodexProvider
from gateway.schemas import ChatCompletionRequest


async def test_codex_plain_chat_is_rejected_without_attestation_or_spawning_cli() -> None:
    """An ambient or PATH Codex install is not authority to start a worker."""
    provider = CodexProvider()
    assert not hasattr(codex_module, "subprocess")
    assert not hasattr(provider, "_run")
    source = Path(codex_module.__file__).read_text(encoding="utf-8")
    for marker in ("tempfile", "subprocess.run", "output-last-message", "codex-out-"):
        assert marker not in source
    request = ChatCompletionRequest(
        model="codex-spark",
        messages=[{"role": "user", "content": "解释一个本地路径的含义"}],
    )

    with pytest.raises(ProviderError, match="not explicitly attested"):
        await provider.chat(request, "gpt-5.3-codex-spark")


async def test_claude_plain_chat_has_no_execution_or_full_disk_capability(
    monkeypatch, tmp_path: Path
) -> None:
    """普通聊天禁用工具；整机权限只能由显式 agent_exec 获得。"""
    calls: list[tuple[list[str], dict]] = []
    communicated: list[bytes | None] = []

    class _FakeProcess:
        returncode = 0
        pid = 12345

        async def communicate(self, input=None):  # noqa: ANN001, ANN201
            communicated.append(input)
            return (
                b'{"result":"\xe7\xba\xaf\xe8\x81\x8a\xe5\xa4\xa9\xe5\xae\x8c\xe6\x88\x90","usage":{"input_tokens":2,"output_tokens":3}}',
                b"",
            )

    async def fake_create(*args, **kwargs):  # noqa: ANN001, ANN202
        calls.append((list(args), kwargs))
        return _FakeProcess()

    monkeypatch.setattr(
        "gateway.providers.claude_code.asyncio.create_subprocess_exec",
        fake_create,
    )
    provider = ClaudeCodeProvider()
    attested = tmp_path / "claude.exe"
    attested.write_bytes(b"attested claude fixture")
    provider._cli = str(attested)
    provider._cli_sha256 = hashlib.sha256(attested.read_bytes()).hexdigest()
    provider.enabled = True
    request = ChatCompletionRequest(
        model="claude-opus",
        messages=[{"role": "user", "content": "你好，请简单介绍一下自己"}],
    )

    result = await provider.chat(request, "opus")

    assert result["choices"][0]["message"]["content"] == "纯聊天完成"
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[args.index("--tools") + 1] == ""
    assert {"--safe-mode", "--no-chrome", "--disable-slash-commands"} <= set(args)
    assert "bypassPermissions" not in args
    assert "--add-dir" not in args
    assert kwargs["cwd"]
    assert kwargs["stdin"] is subprocess.PIPE
    assert communicated and communicated[0]
    assert communicated[0] not in [str(arg).encode("utf-8") for arg in args]
    inherited = {str(k).upper() for k in kwargs["env"]}
    assert not inherited.intersection({"GATEWAY_API_KEYS", "VOLCANO_API_KEY", "TELEGRAM_BOT_TOKEN"})


async def test_codex_explicit_agent_exec_is_closed_without_os_worker(
    tmp_path: Path,
) -> None:
    """The closed method has no dormant subprocess implementation behind it."""
    provider = CodexProvider()
    assert not hasattr(provider, "_run")
    assert not hasattr(codex_module, "subprocess")

    with pytest.raises(ProviderError, match="text-only subscription worker"):
        await provider.agent_exec(
            "修改工作区文件", upstream_model="gpt-5.5", workdir=str(tmp_path)
        )


async def test_claude_explicit_agent_exec_is_closed_without_os_worker(
    monkeypatch, tmp_path: Path
) -> None:
    """Claude execution fails before its chat-only subprocess can run."""
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):  # noqa: ANN001
        calls.append(list(args))
        payload = '{"result":"执行完成","total_cost_usd":0.01}'
        return subprocess.CompletedProcess(args, 0, stdout=payload, stderr="")

    monkeypatch.setattr("gateway.providers.claude_code.subprocess.run", fake_run)
    provider = ClaudeCodeProvider()

    with pytest.raises(ProviderError, match="低权限 worker"):
        await provider.agent_exec(
            "修改工作区文件",
            upstream_model="opus",
            workdir=str(tmp_path),
            allowed_tools="Read Write Edit Bash",
            permission_mode="acceptEdits",
        )
    assert calls == []


def test_native_providers_have_no_embedded_execution_reference(tmp_path: Path) -> None:
    codex = CodexProvider()
    claude = ClaudeCodeProvider()
    assert not hasattr(codex, "_run")
    assert not hasattr(claude, "agent_args")
    assert not hasattr(claude, "_agent_exec_unreachable_reference")
    with pytest.raises(ProviderError, match="text-only subscription worker"):
        asyncio.run(
            codex.agent_exec(
                "x",
                upstream_model="gpt-5.5",
                workdir=str(tmp_path),
                sandbox="danger-full-access",
            )
        )
    with pytest.raises(ProviderError, match="低权限 worker"):
        asyncio.run(
            claude.agent_exec(
                "x",
                upstream_model="opus",
                workdir=str(tmp_path),
                allowed_tools="Read",
                permission_mode="bypassPermissions",
            )
        )
