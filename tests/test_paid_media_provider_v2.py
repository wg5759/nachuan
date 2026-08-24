"""Bounded URL-only provider adapter contract for paid-media v2."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import pytest

from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ImageGenerationRequest


class _SpyResponse:
    def __init__(self, payload: bytes, *, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        midpoint = max(1, len(self._payload) // 2)
        yield self._payload[:midpoint]
        yield self._payload[midpoint:]

    def json(self) -> object:
        raise AssertionError("protocol v2 must not call response.json()")

    @property
    def text(self) -> str:
        raise AssertionError("protocol v2 must not read response.text")

    @property
    def content(self) -> bytes:
        raise AssertionError("protocol v2 must not read response.content")


class _StreamContext:
    def __init__(self, response: _SpyResponse) -> None:
        self.response = response

    async def __aenter__(self) -> _SpyResponse:
        return self.response

    async def __aexit__(self, *_exc: object) -> None:
        return None


class _SpyClient:
    def __init__(self, response: _SpyResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def stream(self, method: str, url: str, **kwargs: Any) -> _StreamContext:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _StreamContext(self.response)


async def _provider_with(
    response: _SpyResponse,
    *,
    base_url: str = "https://provider.example/v1",
) -> tuple[OpenAICompatProvider, _SpyClient]:
    provider = OpenAICompatProvider("spy", base_url, "secret")
    await provider._client.aclose()  # noqa: SLF001 - replace transport at the seam
    client = _SpyClient(response)
    provider._client = client  # type: ignore[assignment]  # noqa: SLF001
    return provider, client


@pytest.mark.asyncio
async def test_v2_image_adapter_streams_bounded_url_metadata_without_buffer_helpers() -> None:
    wire = json.dumps(
        {
            "created": 1_784_200_000,
            "model": "upstream-image-v2",
            "data": [
                {"url": "https://cdn.example.test/a.png", "revised_prompt": "ignored"},
                {"url": "https://cdn.example.test/b.png"},
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            "provider_secret": "must-not-escape",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    provider, client = await _provider_with(_SpyResponse(wire))

    result = await provider.generate_image_asset_urls(
        ImageGenerationRequest(model="image", prompt="hello"),
        "upstream-image-v2",
    )

    assert result == {
        "created": 1_784_200_000,
        "model": "upstream-image-v2",
        "data": [
            {"url": "https://cdn.example.test/a.png"},
            {"url": "https://cdn.example.test/b.png"},
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
    }
    assert len(client.calls) == 1
    assert client.calls[0]["method"] == "POST"
    assert client.calls[0]["json"]["response_format"] == "url"


@pytest.mark.asyncio
async def test_agnes_v2_image_adapter_uses_the_official_request_shape() -> None:
    """Agnes rejects top-level response_format and requires a size."""

    wire = b'{"data":[{"url":"https://cdn.example.test/a.png"}]}'
    provider, client = await _provider_with(
        _SpyResponse(wire),
        base_url="https://apihub.agnes-ai.com/v1",
    )

    await provider.generate_image_asset_urls(
        ImageGenerationRequest(model="agnes-image", prompt="blue circle"),
        "agnes-image-2.1-flash",
    )

    assert len(client.calls) == 1
    payload = client.calls[0]["json"]
    assert payload == {
        "model": "agnes-image-2.1-flash",
        "prompt": "blue circle",
        "size": "1K",
        "extra_body": {"response_format": "url"},
    }


@pytest.mark.asyncio
async def test_agnes_v2_accepts_official_nullable_base64_sibling_in_url_response() -> None:
    """Agnes URL responses document nullable Base64/revised-prompt siblings."""

    wire = json.dumps(
        {
            "created": 1_785_400_000,
            "data": [
                {
                    "url": "https://cdn.example.test/a.png",
                    "b64_json": None,
                    "revised_prompt": None,
                }
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    provider, _client = await _provider_with(
        _SpyResponse(wire),
        base_url="https://apihub.agnes-ai.com/v1",
    )

    result = await provider.generate_image_asset_urls(
        ImageGenerationRequest(model="agnes-image", prompt="blue circle"),
        "agnes-image-2.1-flash",
    )

    assert result == {
        "created": 1_785_400_000,
        "data": [{"url": "https://cdn.example.test/a.png"}],
    }


@pytest.mark.asyncio
async def test_v2_image_adapter_rejects_b64_before_opening_stream() -> None:
    provider, client = await _provider_with(_SpyResponse(b"{}"))
    request = ImageGenerationRequest(
        model="image",
        prompt="hello",
        response_format="b64_json",
    )

    with pytest.raises(ProviderError, match="requires URL"):
        await provider.generate_image_asset_urls(request, "upstream-image-v2")
    assert client.calls == []


@pytest.mark.asyncio
async def test_v2_image_adapter_rejects_success_metadata_over_one_mib() -> None:
    provider, client = await _provider_with(
        _SpyResponse(b"{" + b"x" * (1024 * 1024) + b"}")
    )

    with pytest.raises(ProviderSubmissionOutcomeUnknown, match="oversized metadata"):
        await provider.generate_image_asset_urls(
            ImageGenerationRequest(model="image", prompt="hello"),
            "upstream-image-v2",
        )
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_v2_image_adapter_rejects_non_https_provider_url() -> None:
    wire = b'{"data":[{"url":"http://127.0.0.1/secret"}]}'
    provider, _client = await _provider_with(_SpyResponse(wire))

    with pytest.raises(ProviderSubmissionOutcomeUnknown, match="invalid URL metadata"):
        await provider.generate_image_asset_urls(
            ImageGenerationRequest(model="image", prompt="hello"),
            "upstream-image-v2",
        )


@pytest.mark.asyncio
async def test_v2_image_adapter_rejects_mixed_url_and_base64_metadata() -> None:
    wire = b'{"data":[{"url":"https://cdn.example.test/a.png","b64_json":"AA=="}]}'
    provider, _client = await _provider_with(_SpyResponse(wire))

    with pytest.raises(ProviderSubmissionOutcomeUnknown, match="invalid URL metadata"):
        await provider.generate_image_asset_urls(
            ImageGenerationRequest(model="image", prompt="hello"),
            "upstream-image-v2",
        )
