from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gateway.codex_subscription_worker import CodexInvocation
from gateway.connections import normalize_connection_candidate
from gateway.providers.base import ProviderError
from gateway.providers.codex import CodexProvider
from gateway.router import Router
from gateway.schemas import ChatCompletionRequest


def _fake_pe(marker: bytes = b"codex") -> bytes:
    payload = bytearray(128)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[80 : 80 + len(marker)] = marker
    return bytes(payload)


def _environment(tmp_path: Path) -> dict[str, str]:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(_fake_pe())
    return {
        "CODEX_CLI_PATH": str(executable),
        "CODEX_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    }


class _Worker:
    def __init__(self, result: CodexInvocation | None = None) -> None:
        self.result = result or CodexInvocation(
            text="subscription reply",
            thread_id="thread_1",
            prompt_tokens=12,
            cached_tokens=3,
            completion_tokens=5,
        )
        self.prompts: list[str] = []

    def invoke(self, prompt: str) -> CodexInvocation:
        self.prompts.append(prompt)
        return self.result


@pytest.mark.asyncio
async def test_provider_turn_is_text_only_and_reports_subscription_usage(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    provider = CodexProvider(
        environment=_environment(tmp_path),
        worker=worker,
    )
    request = ChatCompletionRequest(
        model="codex-subscription",
        messages=[
            {"role": "system", "content": "Answer in Chinese."},
            {"role": "user", "content": "你好"},
        ],
    )

    response = await provider.chat(request, "codex-subscription-default")

    assert provider.enabled is True
    assert response["model"] == "codex-subscription"
    assert response["choices"][0]["message"] == {
        "role": "assistant",
        "content": "subscription reply",
        "name": None,
    }
    assert response["usage"] == {
        "prompt_tokens": 12,
        "completion_tokens": 5,
        "total_tokens": 17,
        "cached_tokens": 3,
        "cost_basis": "subscription_unallocated",
        "cost_attribution_basis": "codex_cli_turn",
    }
    assert len(worker.prompts) == 1
    assert "system: Answer in Chinese." in worker.prompts[0]
    assert "user: 你好" in worker.prompts[0]
    assert "codex-subscription-default" not in worker.prompts[0]
    assert provider.expected_model_family("codex-subscription-default") is None
    assert (
        provider.verify_model_identity(
            "codex-subscription-default",
            "gpt-unknown",
        )
        is None
    )


@pytest.mark.asyncio
async def test_provider_streams_only_the_verified_terminal_text(tmp_path: Path) -> None:
    worker = _Worker()
    provider = CodexProvider(
        environment=_environment(tmp_path),
        worker=worker,
    )
    request = ChatCompletionRequest(
        model="codex-subscription",
        messages=[{"role": "user", "content": "hello"}],
        stream=True,
    )

    chunks = [chunk async for chunk in provider.stream(request, "default")]

    assert chunks[0]["choices"][0]["delta"] == {
        "role": "assistant",
        "content": "subscription reply",
    }
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert chunks[-1]["usage"]["cost_basis"] == "subscription_unallocated"
    assert len(worker.prompts) == 1


@pytest.mark.asyncio
async def test_provider_rejects_images_and_tool_contracts_before_worker(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    provider = CodexProvider(
        environment=_environment(tmp_path),
        worker=worker,
    )
    image_request = ChatCompletionRequest(
        model="codex-subscription",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {"type": "image_url", "image_url": {"url": "https://example.test/x"}},
                ],
            }
        ],
    )
    tool_request = ChatCompletionRequest(
        model="codex-subscription",
        messages=[{"role": "user", "content": "run this"}],
        tools=[
            {
                "type": "function",
                "function": {"name": "run", "parameters": {"type": "object"}},
            }
        ],
    )

    with pytest.raises(ProviderError) as image_error:
        await provider.chat(image_request, "default")
    with pytest.raises(ProviderError) as tool_error:
        await provider.chat(tool_request, "default")

    assert image_error.value.status_code == 400
    assert tool_error.value.status_code == 400
    assert worker.prompts == []


def test_codex_connection_has_one_honest_default_model_and_no_api_key(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    connection = normalize_connection_candidate(
        "codex",
        {
            "type": "codex",
            "api_key": "",
            "base_url": "",
            "enabled_models": [
                {
                    "id": "codex-subscription",
                    "upstream_model": "codex-subscription-default",
                    "tier": "premium",
                    "description": "Codex subscription (account default)",
                    "modality": "chat",
                    "rank": 0,
                    "flagship": False,
                    "tool_capable": False,
                    "skills": ["code", "reasoning"],
                }
            ],
        },
    )
    router = Router(
        models_config={"providers": {}, "models": {}},
        codex_worker=worker,
        codex_environment=_environment(tmp_path),
    )

    routes = router.build_transient_routes("codex", connection)
    catalog = {item["name"]: item for item in router.catalog_view()}

    assert len(routes) == 1
    assert routes[0].virtual_model == "codex-subscription"
    assert routes[0].upstream_model == "codex-subscription-default"
    assert routes[0].tool_capable is False
    assert catalog["codex"]["connectable"] is True
    assert [model["id"] for model in catalog["codex"]["models"]] == [
        "codex-subscription"
    ]
