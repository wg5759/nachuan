from __future__ import annotations

import pytest

from gateway.desktop_engine_session_protocol import (
    HEADER_CAPABILITY,
    NonceRegistry,
    DesktopEngineSessionReplayError,
    derive_session_key,
    sign_request,
    sign_response,
    verify_request,
    verify_response,
)


BOOT_TOKEN = "11" * 32
NOW = 1_800_000_000_000
PORT = 43_111
REQUEST_HEADERS = [
    (b"Host", b"127.0.0.1:43111"),
    (b"Connection", b"close"),
    (b"Content-Length", b"2"),
    (b"Accept", b"application/json"),
    (b"Accept-Encoding", b"identity"),
    (b"Cache-Control", b"no-store"),
    (b"Content-Type", b"application/json"),
]


def test_cross_language_capability_request_vector_and_replay_fence() -> None:
    assert derive_session_key(BOOT_TOKEN).hex() == (
        "44455a72ce95d106649f0e305f5c1e123996a7be51587dc9fd4a334a92abfec6"
    )
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=7,
        pid=4242,
        port=PORT,
        capability="sync.run",
        method="POST",
        target="/v1/sync/run",
        contract_headers=REQUEST_HEADERS,
        body=b"{}",
        timestamp_ms=NOW,
        nonce="22" * 32,
        channel_nonce="33" * 32,
    )
    assert signed.contract_sha256 == (
        "48df1e1f6691e8f9647a7bc1be24457a98e0b11d3fc4341c26c36c8b14e78926"
    )
    assert signed.headers["X-Nachuan-Engine-Session-Signature"] == (
        "708a022463984085bd1adcaee63bbe771913847587ec4202ff7ffe59fca9ac30"
    )
    assert signed.headers[HEADER_CAPABILITY] == "sync.run"

    wire = [*REQUEST_HEADERS, *signed.headers.items()]
    nonces = NonceRegistry()
    verified = verify_request(
        boot_token=BOOT_TOKEN,
        expected_generation=7,
        expected_pid=4242,
        expected_port=PORT,
        expected_capability="sync.run",
        method="POST",
        target="/v1/sync/run",
        headers=wire,
        body=b"{}",
        nonce_registry=nonces,
        now_ms=NOW + 100,
    )
    assert verified.capability == "sync.run"
    assert verified.channel_nonce == "33" * 32

    with pytest.raises(DesktopEngineSessionReplayError):
        verify_request(
            boot_token=BOOT_TOKEN,
            expected_generation=7,
            expected_pid=4242,
            expected_port=PORT,
            expected_capability="sync.run",
            method="POST",
            target="/v1/sync/run",
            headers=wire,
            body=b"{}",
            nonce_registry=nonces,
            now_ms=NOW + 101,
        )


def test_cross_language_response_envelope_binds_capability_status_body_and_headers() -> None:
    headers = [
        (b"Content-Type", b"application/json"),
        (b"Content-Length", b"11"),
        (b"Cache-Control", b"no-store"),
        (b"Connection", b"close"),
    ]
    signed = sign_response(
        boot_token=BOOT_TOKEN,
        request_nonce="22" * 32,
        generation=7,
        pid=4242,
        port=PORT,
        capability="sync.run",
        status=200,
        contract_headers=headers,
        body=b'{"ok":true}',
    )
    assert signed.contract_sha256 == (
        "b292f18cd442dfeff7333ff5d30aaf56fde3cfbef81b6f84e54d59e0006e30a3"
    )
    assert signed.headers["X-Nachuan-Engine-Session-Response-Signature"] == (
        "1de2ac7f407d6747997d76fb2f77575e428c5f2f9fcbc2e77bbbdc1730847655"
    )

    verified = verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce="22" * 32,
        expected_generation=7,
        expected_pid=4242,
        expected_port=PORT,
        expected_capability="sync.run",
        status=200,
        headers=[
            *headers,
            *signed.headers.items(),
            (b"Date", b"Fri, 17 Jul 2026 00:00:00 GMT"),
            (b"Server", b"uvicorn"),
        ],
        body=b'{"ok":true}',
    )
    assert verified.capability == "sync.run"
    assert verified.body_sha256 == signed.body_sha256
