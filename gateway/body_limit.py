"""ASGI request-body limits enforced before handlers allocate unbounded buffers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse


class _PayloadTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    DEFAULT_LIMIT = 32 * 1024 * 1024
    PATH_LIMITS = {
        # Paid-media metadata and ACK documents are intentionally tiny.  Keep
        # their JSON allocation ceiling independent from the global upload
        # allowance; video creation retains the larger keyframe-input budget.
        "/v1/images/generations": 1 * 1024 * 1024,
        "/v1/videos/generations": 32 * 1024 * 1024,
        "/v1/paid-media/assets/ack": 1 * 1024 * 1024,
        "/v1/audio/transcriptions": 50 * 1024 * 1024,
        "/v1/vision": 25 * 1024 * 1024,
        "/v1/lapian": 256 * 1024 * 1024,
        # The handler applies the stricter 24 MiB image / 512 MiB video
        # contract while streaming to a private spool.  The outer ASGI gate
        # still needs the largest legal raw video bound for chunked uploads.
        "/v1/paid-media/probe": 512 * 1024 * 1024,
    }

    def __init__(self, app: Any) -> None:
        self.app = app

    def _limit(self, path: str) -> int:
        return self.PATH_LIMITS.get(path, self.DEFAULT_LIMIT)

    async def __call__(self, scope: dict, receive: Callable[[], Awaitable[dict]], send) -> None:
        # HTTP permits request bodies on methods beyond POST/PUT/PATCH.  Future
        # handlers (and middleware that reads a body) must not silently bypass
        # the global bound merely because the method is GET/DELETE/OPTIONS.
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit(str(scope.get("path") or ""))
        headers = {bytes(k).lower(): bytes(v) for k, v in scope.get("headers") or []}
        # AES-GCM appends a fixed 16-byte authentication tag.  Preserve the
        # endpoint's plaintext limit while allowing exactly that transport
        # overhead; the bridge protocol middleware authenticates and decrypts
        # before the handler sees the request.
        transport_limit = limit + (
            16
            if headers.get(b"content-encoding", b"").lower()
            == b"nachuan-bridge-aesgcm-v1"
            else 0
        )
        raw_length = headers.get(b"content-length", b"")
        try:
            if raw_length and int(raw_length) > transport_limit:
                await JSONResponse(
                    {"detail": f"请求体超过 {limit // (1024 * 1024)}MB 安全上限"},
                    status_code=413,
                )(scope, receive, send)
                return
        except ValueError:
            await JSONResponse({"detail": "Content-Length 无效"}, status_code=400)(
                scope, receive, send
            )
            return

        total = 0
        response_started = False

        async def tracked_send(message: dict) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        async def limited_receive() -> dict:
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body") or b"")
                if total > transport_limit:
                    raise _PayloadTooLarge
            return message

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _PayloadTooLarge:
            # ASGI permits exactly one response start.  Once the downstream
            # application has started its response, abort the exchange and let
            # the server close it instead of attempting an invalid second 413.
            if response_started:
                raise
            await JSONResponse(
                {"detail": f"请求体超过 {limit // (1024 * 1024)}MB 安全上限"},
                status_code=413,
            )(scope, receive, tracked_send)
