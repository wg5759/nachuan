from __future__ import annotations

import copy
import hashlib
import re

import pytest

from gateway.paid_media_asset_protocol import (
    ACK_SCHEMA,
    MAX_ASSET_BYTES,
    PROTOCOL_HEADER,
    RESULT_SCHEMA,
    PaidMediaAssetProtocolError,
    asset_result_digest,
    asset_token_hash,
    canonical_asset_result,
    canonical_token_set_digest,
    create_asset_token,
    parse_asset_ack,
    parse_asset_result,
    require_protocol_v2,
)


def _result(tokens: list[str] | None = None) -> dict[str, object]:
    values = tokens or [create_asset_token()]
    return {
        "schema": RESULT_SCHEMA,
        "kind": "image",
        "created": 1784200000,
        "turnId": "1" * 64,
        "assets": [
            {
                "token": token,
                "mediaType": "image/png",
                "byteLength": 123456,
                "sha256": f"{index + 2:x}" * 64,
                "validationReceiptSha256": f"{index + 6:x}" * 64,
            }
            for index, token in enumerate(values)
        ],
    }


def test_protocol_negotiation_requires_one_exact_v2_header() -> None:
    require_protocol_v2({"headers": [(PROTOCOL_HEADER.lower().encode(), b"2")]})
    for headers in (
        [],
        [(b"x-nachuan-paid-media-protocol", b"1")],
        [(b"x-nachuan-paid-media-protocol", b" 2")],
        [
            (b"x-nachuan-paid-media-protocol", b"2"),
            (b"X-Nachuan-Paid-Media-Protocol", b"2"),
        ],
    ):
        with pytest.raises(PaidMediaAssetProtocolError):
            require_protocol_v2({"headers": headers})


def test_tokens_are_fixed_shape_random_and_domain_hashed() -> None:
    first = create_asset_token()
    second = create_asset_token()
    assert first != second
    assert re.fullmatch(r"nma1_[A-Za-z0-9_-]{43}", first)
    assert asset_token_hash(first) != first.removeprefix("nma1_")
    assert asset_token_hash(first) != asset_token_hash(second)


def test_result_is_strict_bounded_and_deterministically_canonical() -> None:
    value = _result()
    parsed = parse_asset_result(value)
    assert parse_asset_result(copy.deepcopy(value)) == parsed
    assert canonical_asset_result(parsed) == canonical_asset_result(value)
    assert asset_result_digest(parsed) == asset_result_digest(value)

    extra = copy.deepcopy(value)
    extra["providerUrl"] = "https://provider.invalid/private"
    with pytest.raises(PaidMediaAssetProtocolError):
        parse_asset_result(extra)

    oversized = copy.deepcopy(value)
    oversized["assets"][0]["byteLength"] = MAX_ASSET_BYTES + 1  # type: ignore[index]
    with pytest.raises(PaidMediaAssetProtocolError):
        parse_asset_result(oversized)


def test_result_and_token_set_match_the_desktop_cross_runtime_fixture() -> None:
    def digest(label: str) -> str:
        return hashlib.sha256(label.encode()).hexdigest()

    value = {
        "schema": RESULT_SCHEMA,
        "kind": "image",
        "created": 1784200000,
        "turnId": digest("turn"),
        "assets": [
            {
                "token": f"nma1_{'A' * 43}",
                "mediaType": "image/png",
                "byteLength": 123456,
                "sha256": digest("asset"),
                "validationReceiptSha256": digest("validation"),
            }
        ],
    }
    assert asset_result_digest(value) == (
        "b12ba7445e0930220257c4489d8a204a28b72322473a13eb0fb8c8c4269dd315"
    )
    assert canonical_token_set_digest(
        [f"nma1_{'A' * 43}", f"nma1_{'B' * 43}"]
    ) == "7f801257d1e90a3d4292ca552375b225d42c1042a1a090b54567b99ee2e9d0b0"


def test_result_rejects_duplicate_tokens_cross_kind_and_zero_receipts() -> None:
    token = create_asset_token()
    duplicated = _result([token, token])
    with pytest.raises(PaidMediaAssetProtocolError):
        parse_asset_result(duplicated)

    cross_kind = _result()
    cross_kind["kind"] = "video"
    with pytest.raises(PaidMediaAssetProtocolError):
        parse_asset_result(cross_kind)

    zero = _result()
    zero["assets"][0]["validationReceiptSha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(PaidMediaAssetProtocolError):
        parse_asset_result(zero)


def test_ack_is_closed_and_token_set_digest_is_order_independent() -> None:
    tokens = [create_asset_token(), create_asset_token()]
    first = parse_asset_ack(
        {
            "schema": ACK_SCHEMA,
            "turnId": "1" * 64,
            "tokens": tokens,
            "archiveReceiptSha256": "2" * 64,
        }
    )
    assert first.tokens == tuple(tokens)
    assert canonical_token_set_digest(tokens) == canonical_token_set_digest(list(reversed(tokens)))

    for invalid in (
        {"schema": ACK_SCHEMA, "turnId": "1" * 64, "tokens": tokens},
        {
            "schema": ACK_SCHEMA,
            "turnId": "1" * 64,
            "tokens": [tokens[0], tokens[0]],
            "archiveReceiptSha256": "2" * 64,
        },
    ):
        with pytest.raises(PaidMediaAssetProtocolError):
            parse_asset_ack(invalid)
