"""Stable, secret-free identities for durable message-channel media inference."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from gateway.weixin_idempotency import validate_channel_idempotency_key


_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_CHANNEL_PREFIXES = {"feishu": "fsmsg-v1:", "weixin": "wxmsg-v1:"}
_OPERATIONS = frozenset({"vision.describe", "lapian.analyze"})
_KEY_DOMAIN = b"nachuan-channel-media-key-v1\x00"
_REQUEST_DOMAIN = b"nachuan-channel-media-request-v2\x00"
_MAX_SEMANTICS_BYTES = 32 * 1024
MAX_CHANNEL_MEDIA_RAW_BYTES = 32 * 1024 * 1024
_PIPELINE_VERSIONS = {
    "vision.describe": "vision.describe/v1",
    "lapian.analyze": "lapian.analyze/v1",
}


def _validated_channel(value: object) -> str:
    channel = str(value or "")
    if channel not in _CHANNEL_PREFIXES:
        raise ValueError("unsupported durable media channel")
    return channel


def _validated_operation(value: object) -> str:
    operation = str(value or "")
    if operation not in _OPERATIONS:
        raise ValueError("unsupported durable channel media operation")
    return operation


def validate_channel_media_channel(value: object) -> str:
    return _validated_channel(value)


def validate_channel_media_operation(value: object) -> str:
    return _validated_operation(value)


def _validated_nonzero_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    if value == "0" * 64:
        raise ValueError(f"{label} must be a nonzero lowercase SHA-256 digest")
    return value


def validate_channel_principal_hash(value: object) -> str:
    return _validated_nonzero_digest(value, "channel principal hash")


def derive_channel_media_key(
    *, channel: object, message_key: object, operation: object
) -> str:
    """Domain-separate a provider message key without retaining raw identities."""

    normalized_channel = _validated_channel(channel)
    normalized_operation = _validated_operation(operation)
    normalized_key = validate_channel_idempotency_key(
        message_key, channel=normalized_channel
    )
    digest = hashlib.sha256(_KEY_DOMAIN)
    for value in (normalized_channel, normalized_operation, normalized_key):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return _CHANNEL_PREFIXES[normalized_channel] + digest.hexdigest()


def _validated_text(value: object, *, label: str, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds its byte limit")
    return value


def _normalized_semantics(operation: str, semantics: object) -> dict[str, Any]:
    if not isinstance(semantics, dict) or any(
        not isinstance(key, str) for key in semantics
    ):
        raise ValueError("channel media semantics must be an object")
    if operation == "vision.describe":
        allowed = frozenset({"question", "model"})
        if not set(semantics).issubset(allowed):
            raise ValueError("vision semantics contain unknown fields")
        return {
            "question": _validated_text(
                semantics.get("question", ""), label="vision question", max_bytes=8192
            ),
            "model": _validated_text(
                semantics.get("model", ""), label="vision model", max_bytes=512
            ),
        }
    allowed = frozenset(
        {"vision_model", "synth_model", "max_frames", "with_audio"}
    )
    if not set(semantics).issubset(allowed):
        raise ValueError("lapian semantics contain unknown fields")
    raw_frames = semantics.get("max_frames", 40)
    if isinstance(raw_frames, bool) or not isinstance(raw_frames, int):
        raise ValueError("lapian max_frames must be an integer")
    if not 1 <= raw_frames <= 80:
        raise ValueError("lapian max_frames is outside the supported range")
    raw_audio = semantics.get("with_audio", True)
    if type(raw_audio) is not bool:
        raise ValueError("lapian with_audio must be a boolean")
    return {
        "vision_model": _validated_text(
            semantics.get("vision_model", "agnes-flash"),
            label="lapian vision_model",
            max_bytes=512,
        ),
        "synth_model": _validated_text(
            semantics.get("synth_model", ""),
            label="lapian synth_model",
            max_bytes=512,
        ),
        "max_frames": raw_frames,
        "with_audio": raw_audio,
    }


def normalize_channel_media_params(
    *, operation: object, params: object
) -> dict[str, Any]:
    return _normalized_semantics(_validated_operation(operation), params)


def validate_channel_media_pipeline_version(
    *, operation: object, pipeline_version: object
) -> str:
    normalized_operation = _validated_operation(operation)
    expected = _PIPELINE_VERSIONS[normalized_operation]
    if pipeline_version != expected:
        raise ValueError("unsupported durable channel media pipeline version")
    return expected


def hash_channel_media_request(
    *,
    channel: object,
    operation: object,
    body_sha256: object,
    raw_length: object,
    pipeline_version: object,
    semantics: object,
) -> str:
    """Bind the exact media bytes and normalized provider-affecting parameters."""

    normalized_channel = _validated_channel(channel)
    normalized_operation = _validated_operation(operation)
    body_digest = _validated_nonzero_digest(body_sha256, "media body digest")
    if (
        type(raw_length) is not int
        or not 1 <= raw_length <= MAX_CHANNEL_MEDIA_RAW_BYTES
    ):
        raise ValueError("media raw length is outside the supported range")
    normalized_pipeline = validate_channel_media_pipeline_version(
        operation=normalized_operation,
        pipeline_version=pipeline_version,
    )
    normalized_semantics = _normalized_semantics(normalized_operation, semantics)
    try:
        encoded = json.dumps(
            {
                "version": 2,
                "channel": normalized_channel,
                "operation": normalized_operation,
                "pipeline_version": normalized_pipeline,
                "raw_length": raw_length,
                "raw_sha256": body_digest,
                "params": normalized_semantics,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("channel media semantics must be canonical JSON") from exc
    if len(encoded) > _MAX_SEMANTICS_BYTES:
        raise ValueError("channel media semantics exceed their digest budget")
    # Keep the finite-number guard explicit even if new scalar fields are added.
    if any(
        isinstance(value, float) and not math.isfinite(value)
        for value in normalized_semantics.values()
    ):
        raise ValueError("channel media semantics contain a non-finite number")
    return hashlib.sha256(_REQUEST_DOMAIN + encoded).hexdigest()
