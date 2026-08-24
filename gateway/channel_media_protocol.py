"""Authenticated inner frame for message-channel media inference.

The returned bytes are intended to be used as the plaintext body of the
existing bridge AES-GCM envelope.  This module deliberately does not perform
transport encryption itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from gateway.channel_media_idempotency import (
    MAX_CHANNEL_MEDIA_RAW_BYTES,
    derive_channel_media_key,
    hash_channel_media_request,
    normalize_channel_media_params,
    validate_channel_media_channel,
    validate_channel_media_operation,
    validate_channel_media_pipeline_version,
)
from gateway.weixin_idempotency import (
    hash_channel_principal,
    validate_channel_idempotency_key,
)


CHANNEL_MEDIA_FRAME_SCHEMA = "nachuan.channel-media-frame/v1"
MAX_CHANNEL_MEDIA_METADATA_BYTES = 32 * 1024
_METADATA_FIELDS = frozenset(
    {
        "schema",
        "channel",
        "user_id",
        "chat_id",
        "message_key",
        "operation",
        "pipeline_version",
        "raw_sha256",
        "raw_length",
        "params",
    }
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_MAX_IDENTITY_BYTES = 512


class ChannelMediaFrameError(ValueError):
    """The inner channel-media frame is malformed or semantically invalid."""


@dataclass(frozen=True, slots=True)
class ChannelMediaFrame:
    channel: str
    user_id: str
    chat_id: str
    message_key: str
    operation: str
    pipeline_version: str
    params: dict[str, Any]
    raw_sha256: str
    raw_length: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class ChannelMediaIdentity:
    principal_hash: str
    operation_key: str
    request_sha256: str


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validated_raw_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("channel media raw payload must be bytes-like")
    payload = bytes(value)
    if not 1 <= len(payload) <= MAX_CHANNEL_MEDIA_RAW_BYTES:
        raise ValueError("channel media raw payload is outside its limit")
    return payload


def _validated_identity_text(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= _MAX_IDENTITY_BYTES:
        raise ValueError(f"{label} is outside its byte limit")
    if value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a canonical opaque identity")
    return value


def _validated_metadata_inputs(
    *,
    channel: object,
    user_id: object,
    chat_id: object,
    message_key: object,
    operation: object,
    pipeline_version: object,
    params: object,
) -> tuple[str, str, str, str, str, str, dict[str, Any]]:
    normalized_channel = validate_channel_media_channel(channel)
    normalized_operation = validate_channel_media_operation(operation)
    normalized_user_id = _validated_identity_text(user_id, label="user_id")
    normalized_chat_id = _validated_identity_text(chat_id, label="chat_id")
    normalized_message_key = validate_channel_idempotency_key(
        message_key,
        channel=normalized_channel,
    )
    normalized_pipeline = validate_channel_media_pipeline_version(
        operation=normalized_operation,
        pipeline_version=pipeline_version,
    )
    normalized_params = normalize_channel_media_params(
        operation=normalized_operation,
        params=params,
    )
    return (
        normalized_channel,
        normalized_user_id,
        normalized_chat_id,
        normalized_message_key,
        normalized_operation,
        normalized_pipeline,
        normalized_params,
    )


def encode_channel_media_frame(
    *,
    channel: str,
    user_id: str,
    chat_id: str,
    message_key: str,
    operation: str,
    pipeline_version: str,
    params: dict[str, Any],
    raw: bytes,
) -> bytes:
    try:
        (
            normalized_channel,
            normalized_user_id,
            normalized_chat_id,
            normalized_message_key,
            normalized_operation,
            normalized_pipeline,
            normalized_params,
        ) = _validated_metadata_inputs(
            channel=channel,
            user_id=user_id,
            chat_id=chat_id,
            message_key=message_key,
            operation=operation,
            pipeline_version=pipeline_version,
            params=params,
        )
        payload = _validated_raw_bytes(raw)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ChannelMediaFrameError("invalid channel media frame input") from exc
    metadata = _canonical_json(
        {
            "schema": CHANNEL_MEDIA_FRAME_SCHEMA,
            "channel": normalized_channel,
            "user_id": normalized_user_id,
            "chat_id": normalized_chat_id,
            "message_key": normalized_message_key,
            "operation": normalized_operation,
            "pipeline_version": normalized_pipeline,
            "raw_sha256": hashlib.sha256(payload).hexdigest(),
            "raw_length": len(payload),
            "params": normalized_params,
        }
    )
    if len(metadata) > MAX_CHANNEL_MEDIA_METADATA_BYTES:
        raise ChannelMediaFrameError("channel media metadata exceeds its limit")
    return len(metadata).to_bytes(4, "big") + metadata + payload


def decode_channel_media_frame(frame: bytes) -> ChannelMediaFrame:
    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise ChannelMediaFrameError("channel media frame must be bytes-like")
    encoded = bytes(frame)
    if len(encoded) < 4:
        raise ChannelMediaFrameError("channel media metadata length prefix is missing")
    metadata_length = int.from_bytes(encoded[:4], "big")
    if not 1 <= metadata_length <= MAX_CHANNEL_MEDIA_METADATA_BYTES:
        raise ChannelMediaFrameError("channel media metadata length exceeds its limit")
    raw_offset = 4 + metadata_length
    if raw_offset > len(encoded):
        raise ChannelMediaFrameError("channel media metadata length exceeds the frame")
    raw = encoded[raw_offset:]
    if not 1 <= len(raw) <= MAX_CHANNEL_MEDIA_RAW_BYTES:
        raise ChannelMediaFrameError("channel media raw payload is outside its limit")
    metadata_bytes = encoded[4:raw_offset]
    try:
        metadata = json.loads(
            metadata_bytes.decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        canonical_metadata = _canonical_json(metadata)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ChannelMediaFrameError(
            "channel media metadata must use exact canonical JSON"
        ) from exc
    if canonical_metadata != metadata_bytes:
        raise ChannelMediaFrameError(
            "channel media metadata must use exact canonical JSON"
        )
    if not isinstance(metadata, dict) or set(metadata) != _METADATA_FIELDS:
        raise ChannelMediaFrameError("channel media metadata schema is not closed")
    if metadata["schema"] != CHANNEL_MEDIA_FRAME_SCHEMA:
        raise ChannelMediaFrameError("unsupported channel media metadata schema")
    try:
        (
            normalized_channel,
            normalized_user_id,
            normalized_chat_id,
            normalized_message_key,
            normalized_operation,
            normalized_pipeline,
            normalized_params,
        ) = _validated_metadata_inputs(
            channel=metadata["channel"],
            user_id=metadata["user_id"],
            chat_id=metadata["chat_id"],
            message_key=metadata["message_key"],
            operation=metadata["operation"],
            pipeline_version=metadata["pipeline_version"],
            params=metadata["params"],
        )
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ChannelMediaFrameError(
            "channel media metadata is semantically invalid"
        ) from exc
    if normalized_params != metadata["params"]:
        raise ChannelMediaFrameError(
            "channel media parameters must use their normalized schema"
        )
    raw_length = metadata["raw_length"]
    if (
        type(raw_length) is not int
        or not 1 <= raw_length <= MAX_CHANNEL_MEDIA_RAW_BYTES
        or raw_length != len(raw)
    ):
        raise ChannelMediaFrameError("channel media raw length does not match")
    raw_sha256 = metadata["raw_sha256"]
    if (
        not isinstance(raw_sha256, str)
        or _DIGEST_RE.fullmatch(raw_sha256) is None
        or not hmac.compare_digest(raw_sha256, hashlib.sha256(raw).hexdigest())
    ):
        raise ChannelMediaFrameError("channel media raw SHA-256 does not match")
    return ChannelMediaFrame(
        channel=normalized_channel,
        user_id=normalized_user_id,
        chat_id=normalized_chat_id,
        message_key=normalized_message_key,
        operation=normalized_operation,
        pipeline_version=normalized_pipeline,
        params=normalized_params,
        raw_sha256=raw_sha256,
        raw_length=raw_length,
        raw=raw,
    )


def recompute_channel_media_identity(
    frame: ChannelMediaFrame,
) -> ChannelMediaIdentity:
    """Recompute every durable identity from authenticated frame fields."""

    principal_hash = hash_channel_principal(
        channel=frame.channel,
        user_id=frame.user_id,
        chat_id=frame.chat_id,
    )
    operation_key = derive_channel_media_key(
        channel=frame.channel,
        message_key=frame.message_key,
        operation=frame.operation,
    )
    request_sha256 = hash_channel_media_request(
        channel=frame.channel,
        operation=frame.operation,
        body_sha256=frame.raw_sha256,
        raw_length=frame.raw_length,
        pipeline_version=frame.pipeline_version,
        semantics=frame.params,
    )
    return ChannelMediaIdentity(
        principal_hash=principal_hash,
        operation_key=operation_key,
        request_sha256=request_sha256,
    )
