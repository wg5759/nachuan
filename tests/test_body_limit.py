from __future__ import annotations

import asyncio

import pytest

from gateway.body_limit import RequestBodyLimitMiddleware, _PayloadTooLarge


async def _invoke(
    *,
    path: str,
    chunks: list[bytes],
    content_length: bytes | None = None,
    method: str = "POST",
):
    called = False
    sent: list[dict] = []

    async def app(_scope, receive, send):
        nonlocal called
        called = True
        while True:
            msg = await receive()
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    headers = [] if content_length is None else [(b"content-length", content_length)]
    middleware = RequestBodyLimitMiddleware(app)
    await middleware(
        {"type": "http", "method": method, "path": path, "headers": headers},
        receive,
        send,
    )
    status = next(item["status"] for item in sent if item["type"] == "http.response.start")
    return called, status


def test_content_length_is_rejected_before_handler() -> None:
    called, status = asyncio.run(
        _invoke(path="/v1/intent", chunks=[], content_length=str(33 << 20).encode())
    )
    assert called is False and status == 413


def test_chunked_body_is_counted_and_route_limit_applies(monkeypatch) -> None:
    monkeypatch.setattr(RequestBodyLimitMiddleware, "DEFAULT_LIMIT", 5)
    called, status = asyncio.run(
        _invoke(path="/v1/intent", chunks=[b"123", b"456"], content_length=None)
    )
    assert called is True and status == 413


def test_small_body_reaches_handler(monkeypatch) -> None:
    monkeypatch.setattr(RequestBodyLimitMiddleware, "DEFAULT_LIMIT", 8)
    called, status = asyncio.run(
        _invoke(path="/v1/intent", chunks=[b"1234"], content_length=None)
    )
    assert called is True and status == 204


@pytest.mark.parametrize(
    "path",
    ["/v1/images/generations", "/v1/paid-media/assets/ack"],
)
def test_paid_media_small_json_paths_pre_reject_oversized_content_length(path) -> None:
    called, status = asyncio.run(
        _invoke(path=path, chunks=[], content_length=str((1 << 20) + 1).encode())
    )
    assert called is False and status == 413


@pytest.mark.parametrize(
    "path",
    ["/v1/images/generations", "/v1/paid-media/assets/ack"],
)
def test_paid_media_small_json_paths_abort_oversized_chunked_body(path) -> None:
    called, status = asyncio.run(
        _invoke(path=path, chunks=[b"x" * (1 << 20), b"x"], content_length=None)
    )
    assert called is True and status == 413


def test_paid_video_creation_retains_larger_keyframe_input_budget() -> None:
    called, status = asyncio.run(
        _invoke(
            path="/v1/videos/generations",
            chunks=[b"x" * ((1 << 20) + 1)],
            content_length=None,
        )
    )
    assert called is True and status == 204


@pytest.mark.parametrize("method", ["GET", "DELETE", "OPTIONS"])
def test_all_http_methods_enforce_chunked_body_limit(monkeypatch, method) -> None:
    monkeypatch.setattr(RequestBodyLimitMiddleware, "DEFAULT_LIMIT", 5)
    called, status = asyncio.run(
        _invoke(
            path="/future-route",
            method=method,
            chunks=[b"123", b"456"],
            content_length=None,
        )
    )
    assert called is True and status == 413


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_all_http_methods_pre_reject_oversized_content_length(monkeypatch, method) -> None:
    monkeypatch.setattr(RequestBodyLimitMiddleware, "DEFAULT_LIMIT", 5)
    called, status = asyncio.run(
        _invoke(
            path="/future-route",
            method=method,
            chunks=[],
            content_length=b"6",
        )
    )
    assert called is False and status == 413


def test_limit_exceeded_after_response_start_aborts_without_second_start(
    monkeypatch,
) -> None:
    monkeypatch.setattr(RequestBodyLimitMiddleware, "DEFAULT_LIMIT", 5)
    sent: list[dict] = []
    requests = [{"type": "http.request", "body": b"123456", "more_body": False}]

    async def app(_scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await receive()

    async def receive() -> dict:
        return requests.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    async def invoke() -> None:
        middleware = RequestBodyLimitMiddleware(app)
        await middleware(
            {"type": "http", "method": "POST", "path": "/v1/intent", "headers": []},
            receive,
            send,
        )

    with pytest.raises(_PayloadTooLarge):
        asyncio.run(invoke())
    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert [message["status"] for message in starts] == [200]
