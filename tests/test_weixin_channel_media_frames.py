from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest

from bridge.access import ChannelAccessPolicy
from gateway.channel_media_protocol import decode_channel_media_frame


def _load_bridge():
    path = Path(__file__).parents[1] / "scripts" / "run_weixin_ilink_bridge.py"
    spec = importlib.util.spec_from_file_location("run_weixin_media_frame_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_weixin_image_is_sent_as_identity_bound_sealed_frame(monkeypatch):
    bridge = _load_bridge()
    requests: list[dict[str, object]] = []

    def fake_request(_opener, **kwargs):
        requests.append(kwargs)
        return b'{"text":"sealed image accepted"}'

    monkeypatch.setattr(bridge, "request_bridge_bytes", fake_request)
    result = bridge._describe(
        b"real-image-bytes",
        user_id="wx_user",
        chat_id="wx_chat",
        message_key="wxmsg-v1:" + ("1" * 64),
    )

    assert result == "sealed image accepted"
    assert len(requests) == 1
    request = requests[0]
    assert request["url"] == f"{bridge.ENGINE}/v1/vision"
    assert request["headers"] == {"Content-Type": "application/octet-stream"}
    assert request["body"] != b"real-image-bytes"
    frame = decode_channel_media_frame(request["body"])
    assert frame.channel == "weixin"
    assert frame.user_id == "wx_user"
    assert frame.chat_id == "wx_chat"
    assert frame.message_key == "wxmsg-v1:" + ("1" * 64)
    assert frame.operation == "vision.describe"
    assert frame.pipeline_version == "vision.describe/v1"
    assert frame.params == {
        "model": "",
        "question": "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。",
    }
    assert frame.raw == b"real-image-bytes"


def test_weixin_same_message_retry_produces_byte_identical_frame(monkeypatch):
    bridge = _load_bridge()
    bodies: list[bytes] = []

    def fake_request(_opener, **kwargs):
        bodies.append(kwargs["body"])
        return b'{"text":"ok"}'

    monkeypatch.setattr(bridge, "request_bridge_bytes", fake_request)
    identity = {
        "user_id": "wx_retry",
        "chat_id": "wx_retry",
        "message_key": "wxmsg-v1:" + ("2" * 64),
    }

    assert bridge._describe(b"same-image", **identity) == "ok"
    assert bridge._describe(b"same-image", **identity) == "ok"
    assert bodies[0] == bodies[1]


def test_weixin_handler_forwards_principal_and_message_key(monkeypatch):
    bridge = _load_bridge()
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx_sender"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(bridge, "_cdn_download", lambda _media: b"image")
    monkeypatch.setattr(
        bridge,
        "_describe",
        lambda data, **kwargs: calls.append({"data": data, **kwargs}) or "seen",
    )
    monkeypatch.setattr(bridge, "_deliver_text", lambda *_args, **_kwargs: True)
    message = {
        "message_id": "wx_image_003",
        "from_user_id": "wx_sender",
        "context_token": "wx_context",
        "item_list": [{"type": 2, "image_item": {"media": {"url": "ignored"}}}],
    }

    bridge._handle(message, "bot-token")

    assert calls == [
        {
            "data": b"image",
            "user_id": "wx_sender",
            "chat_id": "wx_sender",
            "message_key": bridge._message_key(message),
        }
    ]


def test_weixin_gateway_transport_error_is_left_for_durable_inbox_retry(monkeypatch):
    bridge = _load_bridge()
    deliveries: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx_sender"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(bridge, "_cdn_download", lambda _media: b"image")
    monkeypatch.setattr(
        bridge,
        "_describe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            TimeoutError("gateway response lost")
        ),
    )
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: deliveries.append(text) or True,
    )
    message = {
        "message_id": "wx_image_retry",
        "from_user_id": "wx_sender",
        "context_token": "wx_context",
        "item_list": [{"type": 2, "image_item": {"media": {"url": "ignored"}}}],
    }

    with pytest.raises(TimeoutError, match="gateway response lost"):
        bridge._handle(message, "bot-token")
    assert deliveries == []


def test_weixin_vision_transport_loss_is_not_replayed_inside_one_handler(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "fixed-bridge-key"
    requests = 0

    def response_lost(_opener, **_kwargs):
        nonlocal requests
        requests += 1
        raise socket.timeout("response lost")

    monkeypatch.setattr(bridge, "request_bridge_bytes", response_lost)
    monkeypatch.setattr(
        bridge,
        "_resolve_engine_key",
        lambda: (_ for _ in ()).throw(
            AssertionError("paid media transport must not rediscover and replay inline")
        ),
    )

    with pytest.raises(socket.timeout, match="response lost"):
        bridge._describe(
            b"image",
            user_id="wx_sender",
            chat_id="wx_sender",
            message_key="wxmsg-v1:" + ("3" * 64),
        )
    assert requests == 1


@pytest.mark.parametrize(
    "response",
    (b"{}", b'{"text":""}', b'{"text":1}'),
    ids=("missing", "empty", "wrong-type"),
)
def test_weixin_vision_requires_nonempty_text_in_authenticated_2xx(
    monkeypatch,
    response: bytes,
):
    bridge = _load_bridge()
    monkeypatch.setattr(
        bridge,
        "request_bridge_bytes",
        lambda _opener, **_kwargs: response,
    )

    with pytest.raises(RuntimeError, match="vision_response_invalid"):
        bridge._describe(
            b"image",
            user_id="wx_sender",
            chat_id="wx_sender",
            message_key="wxmsg-v1:" + ("4" * 64),
        )


def test_weixin_media_principal_never_uses_mutable_owner_alias(monkeypatch):
    bridge = _load_bridge()
    calls: list[dict[str, object]] = []
    owners = iter(("wx_sender", "wx_sender"))
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx_sender"}), next(owners), ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(bridge, "_cdn_download", lambda _media: b"image")
    monkeypatch.setattr(
        bridge,
        "_describe",
        lambda data, **kwargs: calls.append({"data": data, **kwargs}) or "seen",
    )
    monkeypatch.setattr(bridge, "_deliver_text", lambda *_args, **_kwargs: True)
    message = {
        "message_id": "wx_owner_alias_media",
        "from_user_id": "wx_sender",
        "context_token": "wx_context",
        "item_list": [{"type": 2, "image_item": {"media": {"url": "ignored"}}}],
    }

    bridge._handle(message, "bot-token")

    assert calls[0]["user_id"] == "wx_sender"


def test_weixin_cdn_transport_failure_is_left_pending_for_durable_retry(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_is_official_cdn_url", lambda _url: True)
    monkeypatch.setattr(
        bridge,
        "fetch_public_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            socket.timeout("cdn response lost")
        ),
    )

    with pytest.raises(socket.timeout, match="cdn response lost"):
        bridge._cdn_download(
            {
                "url": "https://official-cdn.invalid/image",
                "aes_key": "",
            }
        )


def test_weixin_lost_inbound_lease_blocks_the_vision_provider_seam(monkeypatch):
    bridge = _load_bridge()
    calls = 0
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx_sender"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(bridge, "_cdn_download", lambda _media: b"image")

    def describe(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return "seen"

    monkeypatch.setattr(bridge, "_describe", describe)
    monkeypatch.setattr(bridge, "_deliver_text", lambda *_args, **_kwargs: True)
    bridge._HANDLE_CONTEXT.permits_provider = lambda: False
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost,
            match="inbound_provider_fence_lost",
        ):
            bridge._handle(
                {
                    "message_id": "wx_lost_lease_media",
                    "from_user_id": "wx_sender",
                    "context_token": "wx_context",
                    "item_list": [
                        {"type": 2, "image_item": {"media": {"url": "ignored"}}}
                    ],
                },
                "bot-token",
            )
    finally:
        del bridge._HANDLE_CONTEXT.permits_provider
    assert calls == 0


def test_weixin_download_budget_fits_the_sealed_vision_plaintext_limit():
    bridge = _load_bridge()
    worst_case_frame_overhead = 4 + 32 * 1024
    assert (
        bridge._MAX_INBOUND_MEDIA_BYTES + worst_case_frame_overhead
        <= 25 * 1024 * 1024
    )
