from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Iterator

import pytest
from starlette.requests import ClientDisconnect

from gateway import paid_media_asset_delivery as delivery
from gateway.paid_media_asset_delivery import (
    archive_paid_media_document_for_web,
    pinned_asset_streaming_response,
)


class _FakePinnedAsset:
    media_type = "image/png"
    byte_length = 3
    sha256 = "a" * 64

    def __init__(self, *, fail_iterator: bool = False) -> None:
        self.fail_iterator = fail_iterator
        self.close_calls = 0

    def iter_chunks(self) -> Iterator[bytes]:
        yield b"abc"
        if self.fail_iterator:
            raise RuntimeError("stream failed")

    def close(self) -> None:
        self.close_calls += 1


def _scope() -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/asset",
        "raw_path": b"/asset",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
    }


async def _receive() -> dict[str, str]:
    return {"type": "http.disconnect"}


@pytest.mark.asyncio
async def test_pinned_asset_response_closes_on_client_disconnect() -> None:
    pinned = _FakePinnedAsset()
    response = pinned_asset_streaming_response(pinned, headers={})

    async def disconnect_on_body(message: dict[str, object]) -> None:
        if message["type"] == "http.response.body":
            raise OSError("client disconnected")

    with pytest.raises(ClientDisconnect):
        await response(_scope(), _receive, disconnect_on_body)

    assert pinned.close_calls == 1


@pytest.mark.asyncio
async def test_pinned_asset_response_closes_on_iterator_failure() -> None:
    pinned = _FakePinnedAsset(fail_iterator=True)
    response = pinned_asset_streaming_response(pinned, headers={})

    async def accept(_message: dict[str, object]) -> None:
        return None

    with pytest.raises(RuntimeError, match="stream failed"):
        await response(_scope(), _receive, accept)

    assert pinned.close_calls == 1


@pytest.mark.asyncio
async def test_web_archive_stores_each_complete_asset_before_pinning_the_next(
    monkeypatch,
) -> None:
    payloads = (b"first-private-asset", b"second-private-asset")
    tokens = ("nma1_" + "A" * 43, "nma1_" + "B" * 43)
    assets = [
        {
            "token": token,
            "mediaType": "image/png",
            "byteLength": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "validationReceiptSha256": str(index + 1) * 64,
        }
        for index, (token, payload) in enumerate(zip(tokens, payloads, strict=True))
    ]
    document = {
        "schema": "nachuan.paid-media-result.v2",
        "kind": "image",
        "created": 1,
        "turnId": "3" * 64,
        "assets": assets,
    }
    events: list[str] = []

    class FakeAssetStore:
        def ack(self, **_kwargs):
            events.append("ack-live-assets")
            return SimpleNamespace(cleanup_complete=True)

    class FakeRequestStore:
        def ack_asset_success(self, **_kwargs):
            events.append("ack-durable-result")
            return SimpleNamespace(token_set_digest="4" * 64)

        def complete_asset_ack_cleanup(self, **_kwargs):
            events.append("complete-cleanup")
            return True

    class FakeArchive:
        def receipt_for_document(self, **_kwargs):
            return None

        def store_asset(self, *, asset, **_kwargs):
            events.append(f"store:{asset.token}")

        def commit_document(self, **_kwargs):
            events.append("commit-document")
            return "5" * 64

        def store_document_payloads(self, **_kwargs):
            raise AssertionError("all asset payloads must not accumulate before storage")

        def document_batch(self, **_kwargs):
            from contextlib import contextmanager

            archive = self

            class Batch:
                def store_asset(self, *, asset, payload):
                    archive.store_asset(asset=asset, payload=payload)

                def commit(self):
                    return archive.commit_document()

            @contextmanager
            def opened():
                yield Batch()

            return opened()

    class FakePinned:
        media_type = "image/png"

        def __init__(self, token: str, payload: bytes) -> None:
            self.token = token
            self.payload = payload
            self.byte_length = len(payload)
            self.sha256 = hashlib.sha256(payload).hexdigest()

        def iter_chunks(self) -> Iterator[bytes]:
            yield self.payload[:3]
            yield self.payload[3:]

        def close(self) -> None:
            events.append(f"close:{self.token}")

    pinned_by_token = {
        token: FakePinned(token, payload)
        for token, payload in zip(tokens, payloads, strict=True)
    }

    def fake_pin(_state, *, token: str, principal_hash: str):
        assert principal_hash == "a" * 64
        events.append(f"pin:{token}")
        return pinned_by_token[token]

    monkeypatch.setattr(delivery, "PaidMediaAssetStore", FakeAssetStore)
    monkeypatch.setattr(delivery, "PaidMediaWebAssetArchive", FakeArchive)
    monkeypatch.setattr(delivery, "_pin_paid_media_asset_for_principal_sync", fake_pin, raising=False)
    state = SimpleNamespace(
        paid_media_assets=FakeAssetStore(),
        media_requests=FakeRequestStore(),
        paid_media_web_archive=FakeArchive(),
        paid_media_epoch=7,
        paid_media_installation_id="b" * 64,
    )

    receipt = await archive_paid_media_document_for_web(
        state,
        principal_hash="a" * 64,
        asset_document=document,
        now_ms=1,
    )

    assert receipt == "5" * 64
    assert events.index(f"store:{tokens[0]}") < events.index(f"pin:{tokens[1]}")
    assert events == [
        f"pin:{tokens[0]}",
        f"close:{tokens[0]}",
        f"store:{tokens[0]}",
        f"pin:{tokens[1]}",
        f"close:{tokens[1]}",
        f"store:{tokens[1]}",
        "commit-document",
        "ack-durable-result",
        "ack-live-assets",
        "complete-cleanup",
    ]
