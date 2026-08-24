from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

from gateway.channel_media_protocol import (
    ChannelMediaFrameError,
    decode_channel_media_frame,
    encode_channel_media_frame,
    recompute_channel_media_identity,
)


def test_channel_media_frame_has_canonical_wire_format_and_round_trips() -> None:
    message_key = "fsmsg-v1:" + "a" * 64
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key=message_key,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )

    metadata = (
        '{"channel":"feishu","chat_id":"oc_chat","message_key":"'
        + message_key
        + '","operation":"vision.describe","params":{"model":"","question":"what?"},'
        '"pipeline_version":"vision.describe/v1","raw_length":3,'
        '"raw_sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",'
        '"schema":"nachuan.channel-media-frame/v1","user_id":"ou_user"}'
    ).encode("utf-8")
    assert encoded == len(metadata).to_bytes(4, "big") + metadata + b"abc"

    decoded = decode_channel_media_frame(encoded)
    assert decoded.channel == "feishu"
    assert decoded.user_id == "ou_user"
    assert decoded.chat_id == "oc_chat"
    assert decoded.message_key == message_key
    assert decoded.operation == "vision.describe"
    assert decoded.pipeline_version == "vision.describe/v1"
    assert decoded.params == {"model": "", "question": "what?"}
    assert decoded.raw_sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert decoded.raw_length == 3
    assert decoded.raw == b"abc"


def test_weixin_lapian_frame_normalizes_closed_operation_parameters() -> None:
    encoded = encode_channel_media_frame(
        channel="weixin",
        user_id="wx_user",
        chat_id="wx_chat",
        message_key="wxmsg-v1:" + "b" * 64,
        operation="lapian.analyze",
        pipeline_version="lapian.analyze/v1",
        params={},
        raw=b"video",
    )

    decoded = decode_channel_media_frame(encoded)
    assert decoded.params == {
        "vision_model": "agnes-flash",
        "synth_model": "",
        "max_frames": 40,
        "with_audio": True,
    }
    identity = recompute_channel_media_identity(decoded)
    assert identity.operation_key.startswith("wxmsg-v1:")


def test_channel_media_frame_rejects_unknown_metadata_fields() -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )
    metadata_length = int.from_bytes(encoded[:4], "big")
    metadata = json.loads(encoded[4 : 4 + metadata_length])
    metadata["future_field"] = "open schema"
    tampered = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(ChannelMediaFrameError, match="metadata schema"):
        decode_channel_media_frame(
            len(tampered).to_bytes(4, "big") + tampered + b"abc"
        )


@pytest.mark.parametrize(
    "rewrite",
    (
        lambda value: b" " + value,
        lambda value: value.replace(
            b'"channel":"feishu",',
            b'"channel":"weixin","channel":"feishu",',
            1,
        ),
        lambda value: value.replace(b"ou_user", b"ou_\\u0075ser", 1),
    ),
    ids=("whitespace", "duplicate-key", "noncanonical-escape"),
)
def test_channel_media_frame_requires_exact_canonical_json_metadata(
    rewrite: Callable[[bytes], bytes],
) -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )
    metadata_length = int.from_bytes(encoded[:4], "big")
    rewritten = rewrite(encoded[4 : 4 + metadata_length])

    with pytest.raises(ChannelMediaFrameError, match="canonical JSON"):
        decode_channel_media_frame(
            len(rewritten).to_bytes(4, "big") + rewritten + b"abc"
        )


@pytest.mark.parametrize(
    ("metadata_change", "raw", "error"),
    (
        ({"raw_length": 4}, b"abc", "raw length"),
        ({"raw_sha256": "b" * 64}, b"abc", "raw SHA-256"),
        ({}, b"abd", "raw SHA-256"),
    ),
    ids=("declared-length", "declared-hash", "changed-body"),
)
def test_channel_media_frame_binds_exact_raw_length_and_sha256(
    metadata_change: dict[str, object], raw: bytes, error: str
) -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )
    metadata_length = int.from_bytes(encoded[:4], "big")
    metadata = json.loads(encoded[4 : 4 + metadata_length])
    metadata.update(metadata_change)
    rewritten = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(ChannelMediaFrameError, match=error):
        decode_channel_media_frame(
            len(rewritten).to_bytes(4, "big") + rewritten + raw
        )


def test_server_recomputes_principal_operation_key_and_request_hash() -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )

    identity = recompute_channel_media_identity(
        decode_channel_media_frame(encoded)
    )
    assert identity.principal_hash == (
        "2bf396673da1390f72d2b36d35ff8fe2fd2e2f039845b313a6940d9d56fbe80a"
    )
    assert identity.operation_key == (
        "fsmsg-v1:d4dd6d11ffbe925370ed7b41b759056b79f72fd97bc2fb1c8299aa4fcab516fe"
    )
    assert identity.request_sha256 == (
        "2843d74db22c0afd395a591f3e034da3fd1ece60b019bf9076ba54f24d6f6e4b"
    )


@pytest.mark.parametrize(
    "change",
    (
        {"channel": "telegram"},
        {"user_id": ""},
        {"user_id": " user"},
        {"chat_id": "\n"},
        {"message_key": "wxmsg-v1:" + "a" * 64},
        {"operation": "shell.execute"},
        {"pipeline_version": "vision.describe/v2"},
        {"params": {"question": "what?", "model": "", "extra": True}},
    ),
    ids=(
        "channel",
        "empty-user",
        "noncanonical-user",
        "empty-chat",
        "cross-channel-key",
        "operation",
        "pipeline-version",
        "open-params",
    ),
)
def test_channel_media_encoder_rejects_invalid_identity_and_semantics(
    change: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "channel": "feishu",
        "user_id": "ou_user",
        "chat_id": "oc_chat",
        "message_key": "fsmsg-v1:" + "a" * 64,
        "operation": "vision.describe",
        "pipeline_version": "vision.describe/v1",
        "params": {"question": "what?", "model": ""},
        "raw": b"abc",
    }
    values.update(change)

    with pytest.raises(ChannelMediaFrameError):
        encode_channel_media_frame(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    (
        {"schema": "nachuan.channel-media-frame/v2"},
        {"channel": "telegram"},
        {"user_id": ""},
        {"chat_id": "oc_chat\n"},
        {"message_key": "wxmsg-v1:" + "a" * 64},
        {"operation": "shell.execute"},
        {"pipeline_version": "vision.describe/v2"},
        {"params": {"question": "what?", "model": "", "extra": True}},
        {"params": {"question": "what?"}},
    ),
    ids=(
        "schema-value",
        "channel",
        "empty-user",
        "noncanonical-chat",
        "cross-channel-key",
        "operation",
        "pipeline-version",
        "open-params",
        "nonnormalized-params",
    ),
)
def test_channel_media_decoder_rejects_canonical_but_invalid_metadata(
    change: dict[str, object],
) -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )
    metadata_length = int.from_bytes(encoded[:4], "big")
    metadata = json.loads(encoded[4 : 4 + metadata_length])
    metadata.update(change)
    rewritten = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(ChannelMediaFrameError):
        decode_channel_media_frame(
            len(rewritten).to_bytes(4, "big") + rewritten + b"abc"
        )


@pytest.mark.parametrize(
    "raw_factory",
    (
        lambda: b"",
        lambda: 3,
        lambda: b"x" * (32 * 1024 * 1024 + 1),
    ),
    ids=("empty", "integer-coercion", "over-32-mib"),
)
def test_channel_media_encoder_rejects_unsafe_raw_payloads(
    raw_factory: Callable[[], object],
) -> None:
    with pytest.raises(ChannelMediaFrameError):
        encode_channel_media_frame(
            channel="feishu",
            user_id="ou_user",
            chat_id="oc_chat",
            message_key="fsmsg-v1:" + "a" * 64,
            operation="vision.describe",
            pipeline_version="vision.describe/v1",
            params={"question": "what?", "model": ""},
            raw=raw_factory(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "frame",
    (
        b"",
        b"\x00\x00\x00\x00",
        (32 * 1024 + 1).to_bytes(4, "big") + b" " * (32 * 1024 + 1),
        (1).to_bytes(4, "big") + b"\xff",
        (3).to_bytes(4, "big") + b"NaN",
        (2201).to_bytes(4, "big") + b"[" * 1100 + b"0" + b"]" * 1100,
    ),
    ids=(
        "missing-prefix",
        "empty-metadata",
        "oversized-metadata",
        "invalid-utf8",
        "nonfinite-json",
        "deeply-nested-json",
    ),
)
def test_channel_media_decoder_contains_malformed_input_and_parser_bombs(
    frame: bytes,
) -> None:
    with pytest.raises(ChannelMediaFrameError):
        decode_channel_media_frame(frame)


def test_channel_media_decoder_rejects_truncated_metadata_before_json() -> None:
    with pytest.raises(ChannelMediaFrameError, match="metadata length"):
        decode_channel_media_frame((10).to_bytes(4, "big") + b"{}")


def test_channel_media_decoder_rejects_empty_and_oversized_raw_payloads() -> None:
    encoded = encode_channel_media_frame(
        channel="feishu",
        user_id="ou_user",
        chat_id="oc_chat",
        message_key="fsmsg-v1:" + "a" * 64,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": "what?", "model": ""},
        raw=b"abc",
    )
    metadata_length = int.from_bytes(encoded[:4], "big")
    metadata = json.loads(encoded[4 : 4 + metadata_length])
    metadata["raw_length"] = 0
    metadata["raw_sha256"] = hashlib.sha256(b"").hexdigest()
    empty_metadata = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with pytest.raises(ChannelMediaFrameError, match="raw.*limit"):
        decode_channel_media_frame(
            len(empty_metadata).to_bytes(4, "big") + empty_metadata
        )

    metadata_prefix = encoded[: 4 + metadata_length]
    with pytest.raises(ChannelMediaFrameError, match="raw.*limit"):
        decode_channel_media_frame(
            metadata_prefix + b"x" * (32 * 1024 * 1024 + 1)
        )
