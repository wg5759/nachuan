from __future__ import annotations

import asyncio
import hashlib
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from gateway.kimi_subscription_worker import (
    KimiInvocation,
    KimiSubscriptionError,
)
from gateway.providers.base import ProviderError
from gateway.providers.kimi_subscription import (
    KimiSubscriptionProvider,
    KimiSubscriptionProviderError,
)
from gateway.schemas import ChatCompletionRequest


_PUBLIC_MODEL = "kimi-code-subscription"
_UPSTREAM_ALIAS = "kimi-code/k3"


def _fake_pe(marker: bytes = b"kimi") -> bytes:
    payload = bytearray(160)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[96 : 96 + len(marker)] = marker
    return bytes(payload)


def _environment(tmp_path: Path) -> dict[str, str]:
    executable = (tmp_path / "kimi.exe").resolve()
    executable.write_bytes(_fake_pe())
    return {
        "KIMI_CLI_PATH": str(executable),
        "KIMI_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "KIMI_CLI_VERSION": "0.27.0",
    }


class _Worker:
    def __init__(
        self,
        result: KimiInvocation | None = None,
        error: KimiSubscriptionError | None = None,
    ) -> None:
        self.result = result or KimiInvocation(
            text="subscription reply",
            session_id="session-0123456789abcdef",
            model_id=_PUBLIC_MODEL,
            actual_served_model=None,
        )
        self.error = error
        self.prompts: list[str] = []
        self.cancel_events: list[threading.Event] = []

    def invoke(
        self,
        prompt: str,
        *,
        cancellation_event: threading.Event,
    ) -> KimiInvocation:
        self.prompts.append(prompt)
        self.cancel_events.append(cancellation_event)
        if self.error is not None:
            raise self.error
        return self.result


class _CancellationWorker:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.cancel_seen = threading.Event()
        self.allow_cleanup = threading.Event()
        self.cleanup_finished = threading.Event()
        self.received_cancel_event: threading.Event | None = None

    def invoke(
        self,
        prompt: str,
        *,
        cancellation_event: threading.Event,
    ) -> KimiInvocation:
        assert "cancel this turn" in prompt
        self.received_cancel_event = cancellation_event
        self.started.set()
        if not cancellation_event.wait(5):
            raise AssertionError("provider did not propagate task cancellation")
        self.cancel_seen.set()
        if not self.allow_cleanup.wait(5):
            raise AssertionError("test did not release fake process-tree cleanup")
        self.cleanup_finished.set()
        raise KimiSubscriptionError(
            "turn_cancelled",
            process_exit_verified=True,
        )


async def _wait_event(event: threading.Event, timeout: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not event.is_set():
        if loop.time() >= deadline:
            raise AssertionError("thread event was not observed before timeout")
        await asyncio.sleep(0.005)


def _provider(tmp_path: Path, worker: object) -> KimiSubscriptionProvider:
    return KimiSubscriptionProvider(
        environment=_environment(tmp_path),
        worker=worker,
    )


@pytest.mark.asyncio
async def test_text_turn_uses_only_generic_model_and_unallocated_subscription_usage(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    provider = _provider(tmp_path, worker)
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[
            {"role": "system", "content": "Answer in Chinese."},
            {"role": "user", "content": "你好"},
        ],
    )

    response = await provider.chat(request, _UPSTREAM_ALIAS)

    assert provider.enabled is True
    assert response["model"] == _PUBLIC_MODEL
    assert response["choices"][0]["message"] == {
        "role": "assistant",
        "content": "subscription reply",
        "name": None,
    }
    assert response["usage"] == {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "cost_basis": "subscription_unallocated",
        "cost_attribution_basis": "kimi_code_cli_turn",
    }
    assert len(worker.prompts) == 1
    assert len(worker.cancel_events) == 1
    assert isinstance(worker.cancel_events[0], threading.Event)
    assert "system: Answer in Chinese." in worker.prompts[0]
    assert "user: 你好" in worker.prompts[0]
    assert _UPSTREAM_ALIAS not in worker.prompts[0]
    assert provider.expected_model_family(_UPSTREAM_ALIAS) is None
    assert provider.verify_model_identity(_UPSTREAM_ALIAS, "k3") is None


@pytest.mark.asyncio
async def test_images_tools_and_host_agent_execution_are_rejected_before_worker(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    provider = _provider(tmp_path, worker)
    image_request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.test/image.png"},
                    },
                ],
            }
        ],
    )
    tool_request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": "run this"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "run",
                    "parameters": {"type": "object"},
                },
            }
        ],
    )

    with pytest.raises(ProviderError) as image_error:
        await provider.chat(image_request, _UPSTREAM_ALIAS)
    with pytest.raises(ProviderError) as tool_error:
        await provider.chat(tool_request, _UPSTREAM_ALIAS)
    with pytest.raises(ProviderError) as agent_error:
        await provider.agent_exec(
            "inspect the host",
            upstream_model=_UPSTREAM_ALIAS,
            workdir=str(tmp_path),
        )

    assert image_error.value.status_code == 400
    assert tool_error.value.status_code == 400
    assert agent_error.value.status_code == 503
    assert worker.prompts == []
    assert worker.cancel_events == []


@pytest.mark.asyncio
async def test_worker_cannot_promote_requested_alias_to_actual_model_identity(
    tmp_path: Path,
) -> None:
    honest = KimiInvocation(
        text="reply",
        session_id="session-0123456789abcdef",
        model_id=_PUBLIC_MODEL,
        actual_served_model=None,
    )
    provider = _provider(
        tmp_path,
        _Worker(
            result=replace(
                honest,
                model_id=_UPSTREAM_ALIAS,
                actual_served_model="k3",
            )
        ),
    )
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": "hello"}],
    )

    with pytest.raises(ProviderError) as caught:
        await provider.chat(request, _UPSTREAM_ALIAS)

    assert caught.value.status_code == 503
    assert "k3" not in str(caught.value).casefold()


@pytest.mark.asyncio
async def test_worker_errors_are_stable_and_do_not_echo_sensitive_values(
    tmp_path: Path,
) -> None:
    secret = "PRIVATE_PROMPT_sk-live-local-path"
    worker = _Worker(
        error=KimiSubscriptionError(
            f"worker_failed:{secret}",
            process_exit_verified=True,
        )
    )
    provider = _provider(tmp_path, worker)
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": secret}],
    )

    with pytest.raises(ProviderError) as caught:
        await provider.chat(request, _UPSTREAM_ALIAS)

    assert caught.value.status_code == 503
    assert str(caught.value) == "Kimi Code subscription turn is unavailable"
    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    ("worker_code", "expected_reason"),
    [
        ("auth_required", "reauth_required"),
        ("agent_rpc_error", "connector_unavailable"),
        ("protocol_rejected", "text_contract_rejected"),
        ("unknown_PRIVATE_PROMPT_sk-live", "connector_unavailable"),
    ],
)
@pytest.mark.asyncio
async def test_worker_error_codes_map_to_a_closed_public_connection_reason(
    tmp_path: Path,
    worker_code: str,
    expected_reason: str,
) -> None:
    provider = _provider(
        tmp_path,
        _Worker(
            error=KimiSubscriptionError(
                worker_code,
                process_exit_verified=True,
            )
        ),
    )
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": "ping"}],
    )

    with pytest.raises(KimiSubscriptionProviderError) as caught:
        await provider.probe_chat(request, _PUBLIC_MODEL)

    assert caught.value.status_code == 503
    assert caught.value.reason_code == expected_reason
    assert str(caught.value) == "Kimi Code subscription turn is unavailable"
    assert worker_code not in str(caught.value)
    if worker_code == "agent_rpc_error":
        assert caught.value.diagnostic_code == "agent_rpc_error"
        assert (
            caught.value.ledger_error_type
            == "KimiSubscriptionProviderError.agent_rpc_error"
        )


@pytest.mark.asyncio
async def test_stream_has_one_text_chunk_and_one_closed_terminal_chunk(
    tmp_path: Path,
) -> None:
    worker = _Worker()
    provider = _provider(tmp_path, worker)
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": "hello"}],
        stream=True,
    )

    chunks = [chunk async for chunk in provider.stream(request, _UPSTREAM_ALIAS)]

    assert len(chunks) == 2
    assert chunks[0]["model"] == chunks[1]["model"] == _PUBLIC_MODEL
    assert chunks[0]["id"] == chunks[1]["id"]
    assert chunks[0]["choices"] == [
        {
            "index": 0,
            "delta": {
                "role": "assistant",
                "content": "subscription reply",
            },
            "finish_reason": None,
        }
    ]
    assert chunks[1]["choices"][0]["finish_reason"] == "stop"
    assert chunks[1]["usage"] == {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "cost_basis": "subscription_unallocated",
        "cost_attribution_basis": "kimi_code_cli_turn",
    }
    assert len(worker.prompts) == 1


@pytest.mark.asyncio
async def test_task_cancellation_waits_for_worker_process_tree_cleanup(
    tmp_path: Path,
) -> None:
    worker = _CancellationWorker()
    provider = _provider(tmp_path, worker)
    request = ChatCompletionRequest(
        model=_PUBLIC_MODEL,
        messages=[{"role": "user", "content": "cancel this turn"}],
    )
    task = asyncio.create_task(provider.chat(request, _UPSTREAM_ALIAS))

    try:
        await _wait_event(worker.started)
        assert worker.received_cancel_event is not None
        assert not worker.received_cancel_event.is_set()

        task.cancel()
        await _wait_event(worker.cancel_seen)
        await asyncio.sleep(0.02)

        assert not task.done()
        assert not worker.cleanup_finished.is_set()

        worker.allow_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)

        assert worker.cleanup_finished.is_set()
    finally:
        worker.allow_cleanup.set()
        if not task.done():
            task.cancel()


def test_provider_source_is_product_only_and_has_no_detached_to_thread_call() -> None:
    source = (
        Path(__file__).parents[1]
        / "gateway"
        / "providers"
        / "kimi_subscription.py"
    ).read_text(encoding="utf-8")
    assert "scripts.kimi_acp_private_client" not in source
    assert "xreview" not in source.casefold()
    assert "asyncio.to_thread" not in source
