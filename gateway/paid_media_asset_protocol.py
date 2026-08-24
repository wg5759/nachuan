"""Closed, bounded wire contract for paid-media asset streaming v2.

The public success document contains metadata and opaque bearer-like asset
tokens only.  Provider URLs, host paths, task credentials and base64 payloads
are deliberately outside this schema.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


PROTOCOL_HEADER = "X-Nachuan-Paid-Media-Protocol"
PROTOCOL_VERSION = "2"
RESULT_SCHEMA = "nachuan.paid-media-result.v2"
ACK_SCHEMA = "nachuan.paid-media-asset-ack.v1"
MAX_RESULT_BYTES = 1024 * 1024
MAX_ASSETS = 4
MAX_ASSET_BYTES = 24 * 1024 * 1024
SUPPORTED_MEDIA_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "video/mp4",
        "video/webm",
    }
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TURN_RE = _DIGEST_RE
_TOKEN_RE = re.compile(r"^nma1_[A-Za-z0-9_-]{43}$")
_TOKEN_SET_DOMAIN = b"nachuan-paid-media-token-set-v1\x00"
_RESULT_DOMAIN = b"nachuan-paid-media-result-document-v2\x00"
_TOKEN_HASH_DOMAIN = b"nachuan-paid-media-asset-token-v1\x00"


class PaidMediaAssetProtocolError(ValueError):
    """A protocol value is ambiguous, oversized, or outside the closed set."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code)


@dataclass(frozen=True, slots=True)
class PaidMediaAssetDescriptor:
    token: str
    media_type: str
    byte_length: int
    sha256: str
    validation_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class PaidMediaAssetResult:
    kind: str
    created: int
    turn_id: str
    assets: tuple[PaidMediaAssetDescriptor, ...]


@dataclass(frozen=True, slots=True)
class PaidMediaAssetAck:
    turn_id: str
    tokens: tuple[str, ...]
    archive_receipt_sha256: str


def _fail(code: str, message: str) -> PaidMediaAssetProtocolError:
    return PaidMediaAssetProtocolError(code, message)


def _exact_mapping(
    value: object,
    keys: frozenset[str],
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _fail("invalid_paid_media_asset_document", f"{label} must be an object")
    if frozenset(value) != keys:
        raise _fail(
            "invalid_paid_media_asset_document",
            f"{label} fields are outside the closed protocol",
        )
    return value


def _digest(value: object, *, label: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise _fail("invalid_paid_media_asset_document", f"{label} is invalid")
    if not allow_zero and value == "0" * 64:
        raise _fail("invalid_paid_media_asset_document", f"{label} is invalid")
    return value


def _token(value: object) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise _fail("invalid_paid_media_asset_token", "Paid media asset token is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _fail(
            "invalid_paid_media_asset_document",
            "Paid media asset document is not canonical JSON",
        ) from exc
    if len(encoded) > MAX_RESULT_BYTES:
        raise _fail(
            "paid_media_asset_document_too_large",
            "Paid media asset metadata exceeds its size limit",
        )
    return encoded


def create_asset_token() -> str:
    """Create a fixed-shape 256-bit opaque token with no encoded authority."""

    token = f"nma1_{secrets.token_urlsafe(32)}"
    if _TOKEN_RE.fullmatch(token) is None:  # defensive against runtime drift
        raise RuntimeError("opaque paid-media token generator returned an invalid token")
    return token


def asset_token_hash(token: object) -> str:
    normalized = _token(token)
    return hashlib.sha256(_TOKEN_HASH_DOMAIN + normalized.encode("ascii")).hexdigest()


def require_protocol_v2(scope: Mapping[str, Any]) -> None:
    """Require exactly one raw protocol header before claim/provider admission."""

    raw_headers = scope.get("headers")
    if not isinstance(raw_headers, (list, tuple)):
        raise _fail(
            "paid_media_protocol_required",
            "Paid media asset protocol v2 is required",
        )
    wanted = PROTOCOL_HEADER.lower().encode("ascii")
    values: list[bytes] = []
    for entry in raw_headers:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise _fail("invalid_paid_media_protocol", "Paid media protocol headers are invalid")
        try:
            name = bytes(entry[0]).lower()
            value = bytes(entry[1])
        except (TypeError, ValueError) as exc:
            raise _fail(
                "invalid_paid_media_protocol",
                "Paid media protocol headers are invalid",
            ) from exc
        if name == wanted:
            values.append(value)
    if len(values) != 1:
        raise _fail(
            "paid_media_protocol_required",
            "Exactly one paid media asset protocol v2 header is required",
        )
    try:
        value = values[0].decode("ascii", "strict")
    except UnicodeError as exc:
        raise _fail("invalid_paid_media_protocol", "Paid media protocol version is invalid") from exc
    if value != PROTOCOL_VERSION:
        raise _fail(
            "paid_media_protocol_unsupported",
            "Paid media asset protocol version is unsupported",
        )


def parse_asset_result(value: object) -> PaidMediaAssetResult:
    document = _exact_mapping(
        value,
        frozenset({"schema", "kind", "created", "turnId", "assets"}),
        label="Paid media result",
    )
    if document["schema"] != RESULT_SCHEMA or document["kind"] not in {"image", "video"}:
        raise _fail("invalid_paid_media_asset_document", "Paid media result schema is invalid")
    created = document["created"]
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or created < 0
        # This timestamp crosses the Python/JSON/TypeScript boundary and must
        # remain exactly representable by both runtimes.
        or created > (1 << 53) - 1
    ):
        raise _fail("invalid_paid_media_asset_document", "Paid media result timestamp is invalid")
    turn_id = _digest(document["turnId"], label="Paid media turn id")
    raw_assets = document["assets"]
    if not isinstance(raw_assets, Sequence) or isinstance(raw_assets, (str, bytes, bytearray)):
        raise _fail("invalid_paid_media_asset_document", "Paid media assets must be an array")
    if not 1 <= len(raw_assets) <= MAX_ASSETS:
        raise _fail("invalid_paid_media_asset_document", "Paid media asset count is invalid")
    parsed: list[PaidMediaAssetDescriptor] = []
    tokens: set[str] = set()
    for raw in raw_assets:
        asset = _exact_mapping(
            raw,
            frozenset(
                {"token", "mediaType", "byteLength", "sha256", "validationReceiptSha256"}
            ),
            label="Paid media asset",
        )
        token = _token(asset["token"])
        if token in tokens:
            raise _fail("invalid_paid_media_asset_document", "Paid media asset tokens are duplicated")
        tokens.add(token)
        media_type = asset["mediaType"]
        if not isinstance(media_type, str) or media_type not in SUPPORTED_MEDIA_TYPES:
            raise _fail("invalid_paid_media_asset_document", "Paid media asset type is invalid")
        if document["kind"] == "image" and not media_type.startswith("image/"):
            raise _fail("invalid_paid_media_asset_document", "Paid media image result contains non-image data")
        if document["kind"] == "video" and not media_type.startswith("video/"):
            raise _fail("invalid_paid_media_asset_document", "Paid media video result contains non-video data")
        byte_length = asset["byteLength"]
        if (
            isinstance(byte_length, bool)
            or not isinstance(byte_length, int)
            or not 1 <= byte_length <= MAX_ASSET_BYTES
        ):
            raise _fail("invalid_paid_media_asset_document", "Paid media asset length is invalid")
        parsed.append(
            PaidMediaAssetDescriptor(
                token=token,
                media_type=media_type,
                byte_length=byte_length,
                sha256=_digest(asset["sha256"], label="Paid media asset digest"),
                validation_receipt_sha256=_digest(
                    asset["validationReceiptSha256"],
                    label="Paid media validation receipt digest",
                ),
            )
        )
    result = PaidMediaAssetResult(
        kind=str(document["kind"]),
        created=created,
        turn_id=turn_id,
        assets=tuple(parsed),
    )
    _canonical_json(asset_result_document(result))
    return result


def asset_result_document(result: PaidMediaAssetResult) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "kind": result.kind,
        "created": result.created,
        "turnId": result.turn_id,
        "assets": [
            {
                "token": asset.token,
                "mediaType": asset.media_type,
                "byteLength": asset.byte_length,
                "sha256": asset.sha256,
                "validationReceiptSha256": asset.validation_receipt_sha256,
            }
            for asset in result.assets
        ],
    }


def canonical_asset_result(result: PaidMediaAssetResult | object) -> bytes:
    # Dataclasses are public Python objects, not an integrity brand. Re-parse a
    # caller-constructed instance so a forged ``PaidMediaAssetResult`` cannot
    # bypass the same closed schema and limits as JSON input.
    parsed = parse_asset_result(
        asset_result_document(result)
        if isinstance(result, PaidMediaAssetResult)
        else result
    )
    return _canonical_json(asset_result_document(parsed))


def asset_result_digest(result: PaidMediaAssetResult | object) -> str:
    return hashlib.sha256(_RESULT_DOMAIN + canonical_asset_result(result)).hexdigest()


def canonical_token_set_digest(tokens: Sequence[object]) -> str:
    if not isinstance(tokens, Sequence) or isinstance(tokens, (str, bytes, bytearray)):
        raise _fail("invalid_paid_media_asset_ack", "Paid media ACK tokens must be an array")
    normalized = [_token(token) for token in tokens]
    if not 1 <= len(normalized) <= MAX_ASSETS or len(set(normalized)) != len(normalized):
        raise _fail("invalid_paid_media_asset_ack", "Paid media ACK token set is invalid")
    canonical = b"\x00".join(token.encode("ascii") for token in sorted(normalized))
    return hashlib.sha256(_TOKEN_SET_DOMAIN + canonical).hexdigest()


def parse_asset_ack(value: object) -> PaidMediaAssetAck:
    document = _exact_mapping(
        value,
        frozenset({"schema", "turnId", "tokens", "archiveReceiptSha256"}),
        label="Paid media asset ACK",
    )
    if document["schema"] != ACK_SCHEMA:
        raise _fail("invalid_paid_media_asset_ack", "Paid media asset ACK schema is invalid")
    raw_tokens = document["tokens"]
    if not isinstance(raw_tokens, Sequence) or isinstance(raw_tokens, (str, bytes, bytearray)):
        raise _fail("invalid_paid_media_asset_ack", "Paid media ACK tokens must be an array")
    tokens = tuple(_token(token) for token in raw_tokens)
    canonical_token_set_digest(tokens)
    ack = PaidMediaAssetAck(
        turn_id=_digest(document["turnId"], label="Paid media ACK turn id"),
        tokens=tokens,
        archive_receipt_sha256=_digest(
            document["archiveReceiptSha256"],
            label="Paid media archive receipt digest",
        ),
    )
    _canonical_json(
        {
            "schema": ACK_SCHEMA,
            "turnId": ack.turn_id,
            "tokens": list(ack.tokens),
            "archiveReceiptSha256": ack.archive_receipt_sha256,
        }
    )
    return ack


__all__ = [
    "ACK_SCHEMA",
    "MAX_ASSETS",
    "MAX_ASSET_BYTES",
    "MAX_RESULT_BYTES",
    "PROTOCOL_HEADER",
    "PROTOCOL_VERSION",
    "RESULT_SCHEMA",
    "SUPPORTED_MEDIA_TYPES",
    "PaidMediaAssetAck",
    "PaidMediaAssetDescriptor",
    "PaidMediaAssetProtocolError",
    "PaidMediaAssetResult",
    "asset_result_digest",
    "asset_result_document",
    "asset_token_hash",
    "canonical_asset_result",
    "canonical_token_set_digest",
    "create_asset_token",
    "parse_asset_ack",
    "parse_asset_result",
    "require_protocol_v2",
]
