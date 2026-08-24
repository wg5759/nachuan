from __future__ import annotations

import hashlib

import pytest

from gateway.channel_media_idempotency import (
    derive_channel_media_key,
    hash_channel_media_request,
    validate_channel_principal_hash,
)


def _message_key(channel: str, seed: str) -> str:
    prefix = {"feishu": "fsmsg-v1:", "weixin": "wxmsg-v1:"}[channel]
    return prefix + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def test_channel_media_key_is_stable_operation_scoped_and_secret_free() -> None:
    source = _message_key("feishu", "provider-message-1")
    vision = derive_channel_media_key(
        channel="feishu", message_key=source, operation="vision.describe"
    )
    assert vision == derive_channel_media_key(
        channel="feishu", message_key=source, operation="vision.describe"
    )
    assert vision.startswith("fsmsg-v1:")
    assert len(vision) == len("fsmsg-v1:") + 64
    assert source not in vision
    assert vision != derive_channel_media_key(
        channel="feishu", message_key=source, operation="lapian.analyze"
    )
    assert vision != derive_channel_media_key(
        channel="feishu",
        message_key=_message_key("feishu", "provider-message-2"),
        operation="vision.describe",
    )


@pytest.mark.parametrize(
    ("channel", "message_key", "operation"),
    (
        ("telegram", _message_key("feishu", "one"), "vision.describe"),
        ("feishu", _message_key("weixin", "one"), "vision.describe"),
        ("feishu", _message_key("feishu", "one"), "unknown.operation"),
        ("feishu", "fsmsg-v1:" + "A" * 64, "vision.describe"),
    ),
)
def test_channel_media_key_rejects_cross_namespace_and_open_operations(
    channel: str, message_key: str, operation: str
) -> None:
    with pytest.raises(ValueError):
        derive_channel_media_key(
            channel=channel, message_key=message_key, operation=operation
        )


def test_channel_media_request_hash_binds_bytes_and_all_semantics() -> None:
    body_a = hashlib.sha256(b"image-a").hexdigest()
    body_b = hashlib.sha256(b"image-b").hexdigest()
    base = hash_channel_media_request(
        channel="feishu",
        operation="vision.describe",
        body_sha256=body_a,
        raw_length=7,
        pipeline_version="vision.describe/v1",
        semantics={"question": "what is here", "model": "vision-1"},
    )
    assert base == hash_channel_media_request(
        channel="feishu",
        operation="vision.describe",
        body_sha256=body_a,
        raw_length=7,
        pipeline_version="vision.describe/v1",
        semantics={"model": "vision-1", "question": "what is here"},
    )
    assert base != hash_channel_media_request(
        channel="feishu",
        operation="vision.describe",
        body_sha256=body_b,
        raw_length=7,
        pipeline_version="vision.describe/v1",
        semantics={"question": "what is here", "model": "vision-1"},
    )
    assert base != hash_channel_media_request(
        channel="feishu",
        operation="vision.describe",
        body_sha256=body_a,
        raw_length=7,
        pipeline_version="vision.describe/v1",
        semantics={"question": "read every word", "model": "vision-1"},
    )
    assert base != hash_channel_media_request(
        channel="weixin",
        operation="vision.describe",
        body_sha256=body_a,
        raw_length=7,
        pipeline_version="vision.describe/v1",
        semantics={"question": "what is here", "model": "vision-1"},
    )
    assert base != hash_channel_media_request(
        channel="feishu",
        operation="vision.describe",
        body_sha256=body_a,
        raw_length=8,
        pipeline_version="vision.describe/v1",
        semantics={"question": "what is here", "model": "vision-1"},
    )


def test_channel_media_request_hash_and_principal_are_closed_and_bounded() -> None:
    body_sha256 = hashlib.sha256(b"image").hexdigest()
    principal = hashlib.sha256(b"principal").hexdigest()
    assert validate_channel_principal_hash(principal) == principal
    for invalid in ("", "0" * 64, "A" * 64, "a" * 63, 123):
        with pytest.raises(ValueError):
            validate_channel_principal_hash(invalid)
    with pytest.raises(ValueError):
        hash_channel_media_request(
            channel="feishu",
            operation="vision.describe",
            body_sha256="0" * 64,
            raw_length=5,
            pipeline_version="vision.describe/v1",
            semantics={},
        )
    with pytest.raises(ValueError):
        hash_channel_media_request(
            channel="feishu",
            operation="vision.describe",
            body_sha256=body_sha256,
            raw_length=5,
            pipeline_version="vision.describe/v1",
            semantics={"value": float("nan")},
        )
    with pytest.raises(ValueError):
        hash_channel_media_request(
            channel="feishu",
            operation="vision.describe",
            body_sha256=body_sha256,
            raw_length=5,
            pipeline_version="vision.describe/v1",
            semantics={"question": "x" * (64 * 1024)},
        )
    for invalid_length in (0, 32 * 1024 * 1024 + 1):
        with pytest.raises(ValueError):
            hash_channel_media_request(
                channel="feishu",
                operation="vision.describe",
                body_sha256=body_sha256,
                raw_length=invalid_length,
                pipeline_version="vision.describe/v1",
                semantics={},
            )
    with pytest.raises(ValueError):
        hash_channel_media_request(
            channel="feishu",
            operation="vision.describe",
            body_sha256=body_sha256,
            raw_length=5,
            pipeline_version="vision.describe/v2",
            semantics={},
        )


def test_lapian_semantics_reject_unknown_fields_and_type_coercion() -> None:
    body_sha256 = hashlib.sha256(b"video").hexdigest()
    valid = {
        "vision_model": "agnes-flash",
        "synth_model": "",
        "max_frames": 40,
        "with_audio": True,
    }
    baseline = hash_channel_media_request(
        channel="feishu",
        operation="lapian.analyze",
        body_sha256=body_sha256,
        raw_length=5,
        pipeline_version="lapian.analyze/v1",
        semantics=valid,
    )
    assert baseline != hash_channel_media_request(
        channel="feishu",
        operation="lapian.analyze",
        body_sha256=body_sha256,
        raw_length=5,
        pipeline_version="lapian.analyze/v1",
        semantics={**valid, "max_frames": 41},
    )
    for drift in (
        {**valid, "max_frames": "40"},
        {**valid, "with_audio": 1},
        {**valid, "unknown": "value"},
        {**valid, "max_frames": 81},
    ):
        with pytest.raises(ValueError):
            hash_channel_media_request(
                channel="feishu",
                operation="lapian.analyze",
                body_sha256=body_sha256,
                raw_length=5,
                pipeline_version="lapian.analyze/v1",
                semantics=drift,
            )
