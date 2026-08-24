"""Remote image inputs must not become an SSRF or memory-amplification path."""

from __future__ import annotations

import base64

import pytest

from gateway.providers import claude_code
from gateway.providers.base import ProviderError
from gateway.providers.claude_code import ClaudeCodeProvider
from gateway.public_media import PublicBytesResult, PublicFetchSecurityError
from gateway.schemas import ChatCompletionRequest, ChatMessage


def _image_request(urls: list[str]) -> ChatCompletionRequest:
    # This unit exercises the provider's defence-in-depth count/type/byte
    # filter. Production requests with >4 images are rejected earlier by the
    # ChatCompletionRequest schema, so construct the outer model deliberately.
    return ChatCompletionRequest.model_construct(
        model="claude-sonnet",
        messages=[ChatMessage(
            role="user",
            content=[
                {"type": "text", "text": "describe"},
                *[{"type": "image_url", "image_url": {"url": url}} for url in urls],
            ],
        )],
    )


def test_private_image_url_is_rejected_before_network(monkeypatch) -> None:
    with pytest.raises(PublicFetchSecurityError):
        claude_code._fetch_public_image("http://127.0.0.1:8080/secrets")


def test_public_image_uses_pinned_bounded_helper(monkeypatch) -> None:
    captured = {}

    def fake_fetch(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return PublicBytesResult(
            data=b"image",
            content_type="image/png",
            final_url=url,
            size=5,
            headers={"content-type": "image/png"},
        )

    monkeypatch.setattr(claude_code, "fetch_public_bytes", fake_fetch)
    assert claude_code._fetch_public_image("https://images.example.test/start") == b"image"
    assert captured["kwargs"]["max_bytes"] == 10 * 1024 * 1024
    assert captured["kwargs"]["allowed_type_prefixes"] == ("image/",)
    assert captured["kwargs"]["total_timeout"] == 30.0


def test_data_images_are_type_size_and_count_limited(monkeypatch) -> None:
    monkeypatch.setattr(claude_code, "_MAX_IMAGE_BYTES", 8)
    monkeypatch.setattr(claude_code, "_MAX_IMAGE_TOTAL_BYTES", 20)
    good = "data:image/png;base64," + base64.b64encode(b"1234").decode()
    oversized = "data:image/png;base64," + base64.b64encode(b"x" * 100).decode()
    wrong_type = "data:text/plain;base64," + base64.b64encode(b"hello").decode()
    extracted = claude_code._extract_images(
        _image_request([wrong_type, oversized, good, good, good, good, good])
    )
    assert extracted == [b"1234"] * claude_code._MAX_IMAGES


async def test_claude_cli_image_path_is_closed_before_subprocess(monkeypatch) -> None:
    launched = False

    def fail_run(*_args, **_kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("Claude image request must not spawn a Read-capable CLI")

    monkeypatch.setattr(claude_code.subprocess, "run", fail_run)
    provider = ClaudeCodeProvider()
    request = _image_request([
        "data:image/png;base64," + base64.b64encode(b"image").decode()
    ])
    with pytest.raises(ProviderError, match="原生多模态 API"):
        await provider.chat(request, "opus")
    assert launched is False
