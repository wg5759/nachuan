from __future__ import annotations

import importlib.util
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.channel_media_protocol import decode_channel_media_frame


def _load_runner():
    path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
    spec = importlib.util.spec_from_file_location(
        "run_feishu_bridge_channel_media_test",
        path,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_feishu_image_is_sent_as_identity_bound_sealed_frame(monkeypatch) -> None:
    runner = _load_runner()
    raw_image = b"real-image-bytes"
    downloads: list[tuple[object, ...]] = []
    requests: list[dict[str, object]] = []

    def fake_download(*args, **kwargs):
        downloads.append((*args, kwargs))
        return raw_image

    def fake_request(_opener, **kwargs):
        requests.append(kwargs)
        return b'{"text":"sealed image accepted"}'

    monkeypatch.setattr(runner, "_download_resource", fake_download)
    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    monkeypatch.setattr(runner, "_reply", lambda *_args, **_kwargs: True)
    message = SimpleNamespace(
        message_type="image",
        content=json.dumps({"image_key": "img_key_1"}),
    )

    runner._handle_file(
        message,
        message_id="om_image_1",
        user_id="ou_sender_1",
        chat_id="oc_chat_1",
    )

    assert downloads == [
        ("om_image_1", "img_key_1", "image", {"media_kind": "image"})
    ]
    assert len(requests) == 1
    request = requests[0]
    assert request["url"] == f"{runner.ENGINE}/v1/vision"
    assert request["headers"] == {"Content-Type": "application/octet-stream"}
    assert request["body"] != raw_image

    frame = decode_channel_media_frame(request["body"])
    assert frame.channel == "feishu"
    assert frame.user_id == "ou_sender_1"
    assert frame.chat_id == "oc_chat_1"
    assert frame.message_key == (
        "fsmsg-v1:c713b7b84cab86201a23d0b708bc924d64ce8464691a42276caa0c696904dd51"
    )
    assert frame.operation == "vision.describe"
    assert frame.pipeline_version == "vision.describe/v1"
    assert frame.params == {
        "model": "",
        "question": "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。",
    }
    assert frame.raw == raw_image


def test_feishu_video_is_sent_as_identity_bound_sealed_frame(monkeypatch) -> None:
    runner = _load_runner()
    raw_video = b"real-video-bytes"
    requests: list[dict[str, object]] = []

    monkeypatch.setattr(
        runner,
        "_download_resource",
        lambda *_args, **_kwargs: raw_video,
    )

    def fake_request(_opener, **kwargs):
        requests.append(kwargs)
        return b'{"report":"sealed video accepted"}'

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    monkeypatch.setattr(runner, "_reply", lambda *_args, **_kwargs: True)
    message = SimpleNamespace(
        message_type="media",
        content=json.dumps({"file_key": "video_key_1"}),
    )

    runner._handle_file(
        message,
        message_id="om_video_1",
        user_id="ou_video_sender",
        chat_id="oc_video_chat",
    )

    assert len(requests) == 1
    request = requests[0]
    assert request["url"] == f"{runner.ENGINE}/v1/lapian"
    assert request["headers"] == {"Content-Type": "application/octet-stream"}
    assert request["body"] != raw_video

    frame = decode_channel_media_frame(request["body"])
    assert frame.channel == "feishu"
    assert frame.user_id == "ou_video_sender"
    assert frame.chat_id == "oc_video_chat"
    assert frame.message_key == (
        "fsmsg-v1:c934f9451dad411463ceb3ce61e460c30eb3aa39ec5ecc718d44907435648833"
    )
    assert frame.operation == "lapian.analyze"
    assert frame.pipeline_version == "lapian.analyze/v1"
    assert frame.params == {
        "vision_model": "agnes-flash",
        "synth_model": "",
        "max_frames": 40,
        "with_audio": True,
    }
    assert frame.raw == raw_video


def test_feishu_same_message_retry_produces_byte_identical_frame(monkeypatch) -> None:
    runner = _load_runner()
    bodies: list[bytes] = []

    def fake_request(_opener, **kwargs):
        bodies.append(kwargs["body"])
        return b'{"text":"ok"}'

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    identity = {
        "message_id": "om_retry_1",
        "user_id": "ou_retry_sender",
        "chat_id": "oc_retry_chat",
    }

    assert runner._describe(b"same-image", **identity) == "ok"
    assert runner._describe(b"same-image", **identity) == "ok"
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]


@pytest.mark.parametrize(
    "response",
    [
        b"[]",
        b"{}",
        b'{"text":null}',
        b'{"text":"   "}',
    ],
    ids=("not-an-object", "missing-text", "wrong-text-type", "blank-text"),
)
def test_feishu_vision_rejects_malformed_success_response(
    monkeypatch,
    response: bytes,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(
        runner,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(RuntimeError, match="vision_response_invalid"):
        runner._describe(
            b"image",
            message_id="om_invalid_vision",
            user_id="ou_invalid_vision",
            chat_id="oc_invalid_vision",
        )


@pytest.mark.parametrize(
    "response",
    [
        b"[]",
        b"{}",
        b'{"report":false}',
        b'{"report":"\\t"}',
    ],
    ids=("not-an-object", "missing-report", "wrong-report-type", "blank-report"),
)
def test_feishu_lapian_rejects_malformed_success_response(
    monkeypatch,
    response: bytes,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(
        runner,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(RuntimeError, match="lapian_response_invalid"):
        runner._lapian(
            b"video",
            message_id="om_invalid_lapian",
            user_id="ou_invalid_lapian",
            chat_id="oc_invalid_lapian",
        )


def test_feishu_video_download_budget_fits_sealed_bridge_plaintext_limit() -> None:
    runner = _load_runner()
    worst_case_frame_overhead = 4 + 32 * 1024

    assert runner._MAX_INBOUND_VIDEO_BYTES == (
        32 * 1024 * 1024 - worst_case_frame_overhead
    )
    assert (
        runner._MAX_INBOUND_VIDEO_BYTES + worst_case_frame_overhead
        <= 32 * 1024 * 1024
    )
    assert runner._media_policy("video")[0] == runner._MAX_INBOUND_VIDEO_BYTES


def test_feishu_image_transport_error_is_left_for_durable_inbox_retry(
    monkeypatch,
) -> None:
    runner = _load_runner()
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_download_resource",
        lambda *_args, **_kwargs: b"image",
    )
    monkeypatch.setattr(
        runner,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError("transport unavailable")
        ),
    )
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat_id, text, **_kwargs: replies.append(text) or True,
    )
    message = SimpleNamespace(
        message_type="image",
        content=json.dumps({"image_key": "img_key_retry"}),
    )

    with pytest.raises(urllib.error.URLError, match="transport unavailable"):
        runner._handle_file(
            message,
            message_id="om_image_retry",
            user_id="ou_sender_retry",
            chat_id="oc_chat_retry",
        )
    assert replies == []


def test_feishu_video_transport_error_is_left_for_durable_inbox_retry(
    monkeypatch,
) -> None:
    runner = _load_runner()
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_download_resource",
        lambda *_args, **_kwargs: b"video",
    )
    monkeypatch.setattr(
        runner,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError("transport unavailable")
        ),
    )
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat_id, text, **_kwargs: replies.append(text) or True,
    )
    message = SimpleNamespace(
        message_type="media",
        content=json.dumps({"file_key": "video_key_retry"}),
    )

    with pytest.raises(urllib.error.URLError, match="transport unavailable"):
        runner._handle_file(
            message,
            message_id="om_video_retry",
            user_id="ou_video_retry",
            chat_id="oc_video_retry",
        )
    assert replies and all("拉片失败" not in reply for reply in replies)


def test_feishu_message_handler_forwards_provider_identity_explicitly(
    monkeypatch,
) -> None:
    runner = _load_runner()
    captured: list[tuple[object, dict[str, object]]] = []
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset(), "ou_owner_sender"),
    )
    monkeypatch.setattr(runner, "_allow_inbound", lambda _open_id: True)

    def fake_handle_file(message, **kwargs):
        captured.append((message, kwargs))

    monkeypatch.setattr(runner, "_handle_file", fake_handle_file)
    message = SimpleNamespace(
        message_id="om_provider_message",
        chat_id="oc_provider_chat",
        message_type="image",
        content=json.dumps({"image_key": "provider_image"}),
    )
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=message,
            sender=SimpleNamespace(
                sender_id=SimpleNamespace(open_id="ou_owner_sender")
            ),
        )
    )

    runner._handle_message(event)

    assert captured == [
        (
            message,
            {
                "message_id": "om_provider_message",
                "user_id": "ou_owner_sender",
                "chat_id": "oc_provider_chat",
            },
        )
    ]
