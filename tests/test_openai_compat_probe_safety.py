"""Security regression tests for the bounded OpenAI-compatible probe path."""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

import gateway.providers.openai_compat as openai_compat
from gateway.providers.base import ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ChatCompletionRequest


UPSTREAM = "https://probe.example/v1"


def _request() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="virtual",
        messages=[{"role": "user", "content": "Reply OK"}],
        stream=False,
    )


class _ChunkedBody(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.yielded = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            await asyncio.sleep(0)
            self.yielded += 1
            yield chunk


def _valid_payload(content: str = "OK") -> dict[str, object]:
    return {
        "id": "probe-1",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


def test_loopback_clients_do_not_inherit_environment_proxies(monkeypatch):
    captured: list[dict[str, object]] = []

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            captured.append(kwargs)

    monkeypatch.setattr(openai_compat.httpx, "AsyncClient", _Client)

    for base_url in (
        "http://127.0.0.1:11434/v1",
        "http://127.9.8.7:11434/v1",
        "http://[::1]:11434/v1",
        "http://[::ffff:127.0.0.1]:11434/v1",
        "http://localhost:11434/v1",
        "http://localhost.:11434/v1",
        "http://model.localhost:11434/v1",
    ):
        OpenAICompatProvider("local", base_url, "")

    OpenAICompatProvider("remote", UPSTREAM, "key")

    assert all(call["trust_env"] is False for call in captured[:-1])
    assert captured[-1]["trust_env"] is True
    assert all(call["follow_redirects"] is False for call in captured)


@respx.mock
async def test_probe_chat_accepts_a_small_strict_response():
    route = respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(200, json=_valid_payload())
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        result = await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert result["choices"][0]["message"]["content"] == "OK"
    assert json.loads(route.calls.last.request.content)["stream"] is False


@respx.mock
async def test_probe_chat_rejects_oversized_content_length_before_reading():
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            content=b"{}",
            headers={"content-length": str(64 * 1024 + 1)},
        )
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        with pytest.raises(ProviderError, match="探测响应过大") as exc_info:
            await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502


async def test_probe_chat_rejects_actual_decompressed_chunked_body_over_limit():
    chunks = _ChunkedBody([b" " * (64 * 1024), b"x", b"must-not-be-read"])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=chunks,
            request=request,
        )

    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    await provider._client.aclose()
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    try:
        with pytest.raises(ProviderError, match="探测响应过大") as exc_info:
            await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502
    assert chunks.yielded == 2


@respx.mock
async def test_probe_chat_limits_the_decompressed_not_only_wire_body():
    compressed = gzip.compress(b" " * (64 * 1024 + 1))
    assert len(compressed) < 64 * 1024
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            content=compressed,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
        )
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        with pytest.raises(ProviderError, match="探测响应过大") as exc_info:
            await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502


@respx.mock
async def test_probe_chat_rejects_redirect_without_following_it():
    redirect = respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            307,
            headers={"location": "https://attacker.example/steal"},
        )
    )
    destination = respx.post("https://attacker.example/steal").mock(
        return_value=httpx.Response(200, json=_valid_payload())
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        with pytest.raises(ProviderError, match="拒绝重定向") as exc_info:
            await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502
    assert redirect.call_count == 1
    assert destination.call_count == 0


@respx.mock
@pytest.mark.parametrize(
    "body",
    [
        b"\xff",
        b"[]",
        b"{}",
        b'{"choices":[]}',
        b'{"choices":[{}]}',
    ],
)
async def test_probe_chat_rejects_invalid_utf8_json_or_choices(body: bytes):
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(200, content=body)
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        with pytest.raises(ProviderError, match="无效聊天响应") as exc_info:
            await provider.probe_chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502
    decoded = body.decode("utf-8", "ignore")
    if decoded:
        assert decoded not in str(exc_info.value)


@respx.mock
async def test_ordinary_chat_rejects_oversized_content_length_before_reading(
    monkeypatch,
):
    monkeypatch.setattr(openai_compat, "_CHAT_COMPLETION_BODY_BYTES", 64)
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            content=b"{}",
            headers={"content-length": "65"},
        )
    )
    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    try:
        with pytest.raises(ProviderError, match="超过安全大小限制") as exc_info:
            await provider.chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502


async def test_ordinary_chat_rejects_actual_streamed_body_over_limit(monkeypatch):
    monkeypatch.setattr(openai_compat, "_CHAT_COMPLETION_BODY_BYTES", 64)
    chunks = _ChunkedBody([b" " * 64, b"x", b"must-not-be-read"])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=chunks, request=request)

    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    await provider._client.aclose()
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    try:
        with pytest.raises(ProviderError, match="超过安全大小限制") as exc_info:
            await provider.chat(_request(), "actual-model")
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502
    assert chunks.yielded == 2


async def test_chat_stream_rejects_an_oversized_sse_line(monkeypatch):
    monkeypatch.setattr(openai_compat, "_CHAT_STREAM_LINE_BYTES", 64)
    monkeypatch.setattr(openai_compat, "_CHAT_STREAM_TOTAL_BYTES", 256)
    chunks = _ChunkedBody([b"data: " + b"x" * 64, b"must-not-be-read"])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=chunks,
            request=request,
        )

    provider = OpenAICompatProvider("remote", UPSTREAM, "key")
    await provider._client.aclose()
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    try:
        with pytest.raises(ProviderError, match="超过安全大小限制") as exc_info:
            _ = [item async for item in provider.stream(_request(), "actual-model")]
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 502
    assert chunks.yielded == 1
