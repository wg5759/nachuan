from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib

import pytest

from gateway.paid_media_engine_session_protocol import (
    CHALLENGE_BODY,
    DEFAULT_REPLAY_TTL_MS,
    HEADER_BODY_SHA256,
    HEADER_GENERATION,
    HEADER_NONCE,
    HEADER_PID,
    HEADER_PORT,
    HEADER_REQUEST_CONTRACT_SHA256,
    HEADER_RESPONSE_SIGNATURE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP_MS,
    NonceRegistry,
    PaidMediaEngineSessionAuthenticationError,
    PaidMediaEngineSessionCapacityError,
    PaidMediaEngineSessionHeaderError,
    PaidMediaEngineSessionProtocolError,
    PaidMediaEngineSessionReplayError,
    PaidMediaEngineSessionTimestampError,
    PaidMediaEngineSessionTransportError,
    derive_session_key,
    request_mac_input,
    request_contract_frame,
    request_contract_sha256,
    response_contract_frame,
    response_contract_sha256,
    response_mac_input,
    sign_request,
    sign_response,
    validate_asgi_loopback_scope,
    verify_request,
    verify_response,
)


BOOT_TOKEN = "0123456789abcdef" * 4
TIMESTAMP_MS = 1_784_200_123_456
NONCE = "00112233445566778899aabbccddeeff" * 2
GENERATION = 7
PID = 43_210
PORT = 43_111
METHOD = "POST"
TARGET = "/v1/images/generations"
REQUEST_BODY = b'{"model":"image-model","prompt":"hello"}'
REQUEST_BODY_SHA256 = (
    "d098eae8b6eed31982568318847fd7ca08be4394156a602fd806bc8e6af55ed2"
)
DERIVED_KEY = "2ab8e2271856f482a50273325c27d147e2c42b555e76cc353ebd754796738abd"
REQUEST_SIGNATURE = (
    "9bbf32b0bd7c65d3c5bae7fa75322b67257b78f36c0141d70e05e15e6807a852"
)
REQUEST_CONTRACT_SHA256 = (
    "f88ab2d8b299797c298fb4d226ad7ff388f5d10c7221a224ca23bd90f6de6a63"
)
CHALLENGE_SHA256 = (
    "e2e9bbab138d978ba7ecf5ebb734fb873e7416b7187dd35c039876a54046db26"
)
CONTRACT_SHA256 = (
    "2c1fc00755136e3b0a28400930edd033d6bc7f3018164d1132817af64fe60aa3"
)
RESPONSE_SIGNATURE = (
    "127c1f5f15125c7eae3a665c519ed15010dade3990310ee2fa403c62c9991260"
)


def _contract_headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"content-type", b"application/json"),
        (b"content-length", b"69"),
        (b"cache-control", b"no-store"),
    ]


def _request_headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"Content-Type", b"application/json"),
        (b"Content-Length", b"40"),
        (b"Accept", b"application/json"),
        (b"Accept-Encoding", b"identity"),
        (b"Cache-Control", b"no-store"),
        (b"X-Nachuan-Paid-Media-Protocol", b"2"),
        (b"Idempotency-Key", b"desktop-op-1234567890"),
        (b"Host", b"127.0.0.1:43111"),
        (b"Connection", b"keep-alive"),
    ]


def _signed_request(*, generation: int = GENERATION):
    return sign_request(
        boot_token=BOOT_TOKEN,
        generation=generation,
        pid=PID,
        port=PORT,
        method=METHOD,
        target=TARGET,
        contract_headers=_request_headers(),
        body=REQUEST_BODY,
        timestamp_ms=TIMESTAMP_MS,
        nonce=NONCE,
    )


def _wire_request(signed) -> list[tuple[object, object]]:
    return [*_request_headers(), *signed.headers.items()]


def _verify_request(headers, *, generation: int = GENERATION, registry=None):
    return verify_request(
        boot_token=BOOT_TOKEN,
        expected_generation=generation,
        expected_pid=PID,
        expected_port=PORT,
        method=METHOD,
        target=TARGET,
        headers=headers,
        body=REQUEST_BODY,
        nonce_registry=registry or NonceRegistry(),
        now_ms=TIMESTAMP_MS,
    )


def test_cross_language_fixed_vectors_lock_kdf_request_contract_and_response() -> None:
    signed = _signed_request()
    assert derive_session_key(BOOT_TOKEN).hex() == DERIVED_KEY
    assert signed.body_sha256 == REQUEST_BODY_SHA256
    assert request_contract_sha256(_request_headers()) == REQUEST_CONTRACT_SHA256
    assert signed.contract_sha256 == REQUEST_CONTRACT_SHA256
    assert (
        signed.headers[HEADER_REQUEST_CONTRACT_SHA256]
        == REQUEST_CONTRACT_SHA256
    )
    assert signed.headers[HEADER_SIGNATURE] == REQUEST_SIGNATURE
    assert len(CHALLENGE_BODY) == 69
    assert hashlib.sha256(CHALLENGE_BODY).hexdigest() == CHALLENGE_SHA256
    assert response_contract_sha256(_contract_headers()) == CONTRACT_SHA256
    response = sign_response(
        boot_token=BOOT_TOKEN,
        request_nonce=NONCE,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        status=200,
        contract_headers=_contract_headers(),
        body=CHALLENGE_BODY,
    )
    assert response.body_sha256 == CHALLENGE_SHA256
    assert response.contract_sha256 == CONTRACT_SHA256
    assert response.headers[HEADER_RESPONSE_SIGNATURE] == RESPONSE_SIGNATURE


def test_request_and_response_round_trip_exact_session() -> None:
    request = _signed_request()
    authenticated = _verify_request(_wire_request(request))
    assert authenticated.nonce == NONCE
    response_headers = _contract_headers()
    signed_response = sign_response(
        boot_token=BOOT_TOKEN,
        request_nonce=authenticated.nonce,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        status=200,
        contract_headers=response_headers,
        body=CHALLENGE_BODY,
    )
    response_headers.extend(signed_response.headers.items())
    verified = verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=NONCE,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=200,
        headers=response_headers,
        body=CHALLENGE_BODY,
    )
    assert verified.body_sha256 == CHALLENGE_SHA256
    assert verified.contract_sha256 == CONTRACT_SHA256


def test_invalid_hmac_or_wrong_exact_session_does_not_burn_nonce() -> None:
    signed = _signed_request(generation=GENERATION + 1)
    tampered = dict(signed.headers)
    tampered[HEADER_SIGNATURE] = "f" * 64
    registry = NonceRegistry()
    with pytest.raises(PaidMediaEngineSessionAuthenticationError):
        _verify_request(
            [*_request_headers(), *tampered.items()],
            generation=GENERATION + 1,
            registry=registry,
        )
    assert registry.size == 0
    with pytest.raises(PaidMediaEngineSessionAuthenticationError):
        _verify_request(_wire_request(signed), registry=registry)
    assert registry.size == 0
    assert _verify_request(
        _wire_request(signed), generation=GENERATION + 1, registry=registry
    ).nonce == NONCE


@pytest.mark.parametrize(
    "mutation",
    [
        lambda pairs: pairs + [("x-nachuan-paid-session-extension", "1")],
        lambda pairs: pairs
        + [("x-nachuan-paid-session-response-signature", "0" * 64)],
        lambda pairs: pairs + [(HEADER_NONCE, NONCE)],
        lambda pairs: [
            (name, value + "," + value if name == HEADER_NONCE else value)
            for name, value in pairs
        ],
    ],
)
def test_request_security_headers_are_closed_exact_and_not_combinable(mutation) -> None:
    with pytest.raises(PaidMediaEngineSessionHeaderError):
        _verify_request(mutation(_wire_request(_signed_request())))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda headers: headers + [(b"x-injected", b"1")],
        lambda headers: [
            (name, b"text/plain" if name.lower() == b"content-type" else value)
            for name, value in headers
        ],
        lambda headers: headers + [(b"CONTENT-TYPE", b"application/json")],
        lambda headers: [
            (name, b"a,b" if name.lower() == b"accept" else value)
            for name, value in headers
        ],
    ],
)
def test_request_contract_binds_all_ordinary_headers_and_rejects_ambiguity(
    mutation,
) -> None:
    signed = _signed_request()
    with pytest.raises(
        (PaidMediaEngineSessionAuthenticationError, PaidMediaEngineSessionHeaderError)
    ):
        _verify_request([*mutation(_request_headers()), *signed.headers.items()])


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (HEADER_TIMESTAMP_MS, "0784200123456"),
        (HEADER_GENERATION, "07"),
        (HEADER_PID, "0"),
        (HEADER_PORT, "08080"),
        (HEADER_BODY_SHA256, "A" * 64),
    ],
)
def test_numeric_and_hex_headers_require_canonical_wire_forms(header, value) -> None:
    headers = dict(_signed_request().headers)
    headers[header] = value
    with pytest.raises(PaidMediaEngineSessionProtocolError):
        _verify_request([*_request_headers(), *headers.items()])


def test_timestamp_window_and_concurrent_replay_are_bounded() -> None:
    signed = _signed_request()
    with pytest.raises(PaidMediaEngineSessionTimestampError):
        verify_request(
            boot_token=BOOT_TOKEN,
            expected_generation=GENERATION,
            expected_pid=PID,
            expected_port=PORT,
            method=METHOD,
            target=TARGET,
            headers=_wire_request(signed),
            body=REQUEST_BODY,
            nonce_registry=NonceRegistry(),
            now_ms=TIMESTAMP_MS + 30_001,
        )
    registry = NonceRegistry()

    def run_once() -> str:
        try:
            _verify_request(_wire_request(signed), registry=registry)
            return "ok"
        except PaidMediaEngineSessionReplayError:
            return "replay"

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(lambda _index: run_once(), range(24)))
    assert outcomes.count("ok") == 1
    assert outcomes.count("replay") == 23


def test_nonce_registry_capacity_and_expiry_are_bounded() -> None:
    registry = NonceRegistry(max_entries=1, max_ttl_ms=DEFAULT_REPLAY_TTL_MS)
    registry.consume("1" * 64, now_ms=TIMESTAMP_MS, expires_at_ms=TIMESTAMP_MS + 1)
    with pytest.raises(PaidMediaEngineSessionCapacityError):
        registry.consume("2" * 64, now_ms=TIMESTAMP_MS, expires_at_ms=TIMESTAMP_MS + 1)
    assert registry.prune(now_ms=TIMESTAMP_MS + 1) == 1
    registry.consume("2" * 64, now_ms=TIMESTAMP_MS + 1, expires_at_ms=TIMESTAMP_MS + 2)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-type", b"application/json"), (b"Content-Type", b"text/plain")],
        [(b"content-type", b" application/json")],
        [(b"location", b"https://a.invalid/x,y")],
        [(b"retry-after", b"1\r\nX-Evil: yes")],
        [(b"content-length", b"")],
    ],
)
def test_response_contract_rejects_duplicate_or_ambiguous_values(headers) -> None:
    with pytest.raises(PaidMediaEngineSessionHeaderError):
        response_contract_frame(headers)


def test_response_signature_binds_status_body_contract_and_direction() -> None:
    contract = _contract_headers()
    signed = sign_response(
        boot_token=BOOT_TOKEN,
        request_nonce=NONCE,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        status=200,
        contract_headers=contract,
        body=CHALLENGE_BODY,
    )
    headers = [*contract, *signed.headers.items()]
    with pytest.raises(PaidMediaEngineSessionAuthenticationError):
        verify_response(
            boot_token=BOOT_TOKEN,
            request_nonce=NONCE,
            expected_generation=GENERATION,
            expected_pid=PID,
            expected_port=PORT,
            status=201,
            headers=headers,
            body=CHALLENGE_BODY,
        )
    changed_contract = [
        (name, b"68" if name == b"content-length" else value)
        for name, value in contract
    ]
    with pytest.raises(PaidMediaEngineSessionAuthenticationError):
        verify_response(
            boot_token=BOOT_TOKEN,
            request_nonce=NONCE,
            expected_generation=GENERATION,
            expected_pid=PID,
            expected_port=PORT,
            status=200,
            headers=[*changed_contract, *signed.headers.items()],
            body=CHALLENGE_BODY,
        )
    with pytest.raises(PaidMediaEngineSessionHeaderError):
        verify_response(
            boot_token=BOOT_TOKEN,
            request_nonce=NONCE,
            expected_generation=GENERATION,
            expected_pid=PID,
            expected_port=PORT,
            status=200,
            headers=[*headers, (HEADER_NONCE, NONCE)],
            body=CHALLENGE_BODY,
        )


def test_streaming_response_can_sign_preverified_descriptor_digest() -> None:
    digest = "a" * 64
    contract = [
        ("content-type", "image/png"),
        ("content-length", "123"),
        ("cache-control", "no-store"),
        ("x-nachuan-paid-media-protocol", "2"),
        ("x-content-sha256", digest),
        ("x-content-type-options", "nosniff"),
    ]
    signed = sign_response(
        boot_token=BOOT_TOKEN,
        request_nonce=NONCE,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        status=200,
        contract_headers=contract,
        body_sha256=digest,
    )
    verified = verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=NONCE,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=200,
        headers=[*contract, *signed.headers.items()],
        body_sha256=digest,
    )
    assert verified.body_sha256 == digest


def test_mac_frames_are_length_delimited_and_domain_separated() -> None:
    request_contract = request_contract_frame(_request_headers())
    request_frame = request_mac_input(
        timestamp_ms=TIMESTAMP_MS,
        nonce=NONCE,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        method=METHOD,
        target=TARGET,
        body_sha256=REQUEST_BODY_SHA256,
        contract_sha256=REQUEST_CONTRACT_SHA256,
    )
    response_frame = response_mac_input(
        request_nonce=NONCE,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        status=200,
        body_sha256=CHALLENGE_SHA256,
        contract_sha256=CONTRACT_SHA256,
    )
    assert request_frame != response_frame
    assert len(request_contract) == 420
    assert len(request_frame) == 283
    assert b"nachuan.paid-media.engine-session.request-contract.v1" in request_contract
    assert b"nachuan.paid-media.engine-session.request.v1" in request_frame
    assert b"nachuan.paid-media.engine-session.response.v1" in response_frame
    assert b"nachuan.installation-root" not in request_frame + response_frame


def test_asgi_transport_requires_loopback_exact_port_and_query_free_raw_target() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "raw_path": b"/internal/v1/paid-media/session/challenge",
        "query_string": b"",
        "client": ("127.0.0.1", 55_000),
        "server": ("127.0.0.1", PORT),
    }
    assert validate_asgi_loopback_scope(scope, expected_port=PORT) == (
        "GET",
        "/internal/v1/paid-media/session/challenge",
    )
    for key, value in (
        ("client", ("192.0.2.1", 55_000)),
        ("server", ("127.0.0.1", PORT + 1)),
        ("query_string", b"x=1"),
        ("raw_path", b"/v1/images/generations?x=1"),
    ):
        rejected = dict(scope)
        rejected[key] = value
        with pytest.raises(PaidMediaEngineSessionTransportError):
            validate_asgi_loopback_scope(rejected, expected_port=PORT)


def test_signed_object_never_exposes_boot_token_or_derived_key() -> None:
    signed = _signed_request()
    assert BOOT_TOKEN not in repr(signed)
    assert DERIVED_KEY not in repr(signed)
    assert signed.headers[HEADER_GENERATION] == str(GENERATION)
    assert signed.headers[HEADER_PID] == str(PID)
    assert signed.headers[HEADER_PORT] == str(PORT)
    assert signed.headers[HEADER_TIMESTAMP_MS] == str(TIMESTAMP_MS)
    assert signed.headers[HEADER_BODY_SHA256] == REQUEST_BODY_SHA256
    assert signed.headers[HEADER_NONCE] == NONCE
