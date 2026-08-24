from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from gateway.installation_root_protocol import (
    DEFAULT_MAX_FUTURE_MS,
    DEFAULT_MAX_PAST_MS,
    DuplicateHeaderError,
    HEADER_BODY_SHA256,
    HEADER_NONCE,
    HEADER_RESPONSE_REQUEST_NONCE,
    HEADER_RESPONSE_SIGNATURE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP_MS,
    InstallationRootAuthenticationError,
    InstallationRootProtocolError,
    InstallationRootTimestampError,
    LoopbackPolicyError,
    NonceCapacityError,
    NonceRegistry,
    NonceReplayError,
    REQUEST_HEADER_NAMES,
    extract_single_headers,
    generate_boot_token,
    sign_request,
    sign_response,
    validate_asgi_loopback_scope,
    verify_request,
    verify_response,
)


TOKEN = "0123456789abcdef" * 4
NOW_MS = 1_720_000_000_123
NONCE = "11" * 32
METHOD = "POST"
PATH = "/internal/installation-root/component/advance"
BODY = b'{"component":"desktop","sequence":7}'


def _verify_request(
    signed,
    *,
    registry: NonceRegistry | None = None,
    method: str = METHOD,
    path: str = PATH,
    headers=None,
    body: bytes = BODY,
    now_ms: int = NOW_MS,
):
    return verify_request(
        boot_token=TOKEN,
        method=method,
        path=path,
        headers=signed.headers if headers is None else headers,
        body=body,
        nonce_registry=registry or NonceRegistry(),
        now_ms=now_ms,
    )


def test_fixed_request_and_response_vectors_are_cross_language_stable() -> None:
    request = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce=NONCE,
    )
    assert request.body_sha256 == (
        "c4b40a3c7f3e201c7d569ad3bb8843f34e03df348fe6370fecc23449685e950a"
    )
    assert request.headers[HEADER_SIGNATURE] == (
        "f6560bd9f2a516796fca9762742e69210c8a2fc375817df63831812f31c80bf4"
    )
    authenticated = _verify_request(request)
    assert authenticated.timestamp_ms == NOW_MS
    assert authenticated.nonce == NONCE
    assert authenticated.body_sha256 == request.body_sha256

    response_body = b'{"error":"fenced"}'
    response = sign_response(
        boot_token=TOKEN,
        request_nonce=NONCE,
        status=409,
        body=response_body,
    )
    assert response.body_sha256 == (
        "cc7566fcc1963e31bfe59eb56d9d3c68589fbb9d12ce9ae21e98bdc489920541"
    )
    assert response.headers[HEADER_RESPONSE_SIGNATURE] == (
        "07601f6202fff71bb1448497aa6615c972ed1de5652eb297153afd935351e9ec"
    )
    assert verify_response(
        boot_token=TOKEN,
        request_nonce=NONCE,
        status=409,
        headers=response.headers,
        body=response_body,
    ).body_sha256 == response.body_sha256


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ("body", InstallationRootAuthenticationError),
        ("method", InstallationRootAuthenticationError),
        ("path", InstallationRootAuthenticationError),
        ("timestamp", InstallationRootAuthenticationError),
        ("nonce", InstallationRootAuthenticationError),
        ("signature", InstallationRootAuthenticationError),
    ],
)
def test_every_single_bit_request_tamper_is_rejected(change: str, error: type) -> None:
    signed = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce=NONCE,
    )
    method = METHOD
    path = PATH
    body = BODY
    headers = dict(signed.headers)
    if change == "body":
        body = BODY[:-1] + bytes([BODY[-1] ^ 1])
    elif change == "method":
        method = "PUT"
    elif change == "path":
        path = PATH[:-1] + chr(ord(PATH[-1]) ^ 1)
    elif change == "timestamp":
        headers[HEADER_TIMESTAMP_MS] = str(NOW_MS ^ 1)
    elif change == "nonce":
        headers[HEADER_NONCE] = ("10" if NONCE.startswith("11") else "11") + NONCE[2:]
    elif change == "signature":
        value = headers[HEADER_SIGNATURE]
        headers[HEADER_SIGNATURE] = ("0" if value[0] != "0" else "1") + value[1:]
    with pytest.raises(error):
        _verify_request(
            signed, method=method, path=path, headers=headers, body=body
        )


def test_header_names_are_case_insensitive_but_duplicates_and_format_drift_fail() -> None:
    signed = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce=NONCE,
    )
    lower_raw = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in signed.headers.items()
    ]
    assert _verify_request(signed, headers=lower_raw).nonce == NONCE

    duplicate_raw = list(lower_raw)
    duplicate_raw.append((HEADER_SIGNATURE.upper(), signed.headers[HEADER_SIGNATURE]))
    with pytest.raises(DuplicateHeaderError, match="duplicate"):
        extract_single_headers(duplicate_raw, REQUEST_HEADER_NAMES)

    uppercase_digest = dict(signed.headers)
    uppercase_digest[HEADER_BODY_SHA256] = uppercase_digest[
        HEADER_BODY_SHA256
    ].upper()
    with pytest.raises(InstallationRootProtocolError, match="digest"):
        _verify_request(signed, headers=uppercase_digest)

    comma_signature = dict(signed.headers)
    comma_signature[HEADER_SIGNATURE] += "," + signed.headers[HEADER_SIGNATURE]
    with pytest.raises(InstallationRootProtocolError, match="signature"):
        _verify_request(signed, headers=comma_signature)

    unknown_root_header = dict(signed.headers)
    unknown_root_header["X-Nachuan-Root-Authorization"] = TOKEN
    with pytest.raises(InstallationRootProtocolError, match="unknown"):
        _verify_request(signed, headers=unknown_root_header)


def test_expired_future_and_noncanonical_timestamps_are_rejected() -> None:
    expired = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS - DEFAULT_MAX_PAST_MS - 1,
        nonce="21" * 32,
    )
    with pytest.raises(InstallationRootTimestampError, match="expired"):
        _verify_request(expired)

    future = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS + DEFAULT_MAX_FUTURE_MS + 1,
        nonce="22" * 32,
    )
    with pytest.raises(InstallationRootTimestampError, match="future"):
        _verify_request(future)

    malformed = dict(future.headers)
    malformed[HEADER_TIMESTAMP_MS] = "0" + malformed[HEADER_TIMESTAMP_MS]
    with pytest.raises(InstallationRootProtocolError, match="timestamp"):
        _verify_request(future, headers=malformed)

    past_boundary = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS - DEFAULT_MAX_PAST_MS,
        nonce="23" * 32,
    )
    assert _verify_request(past_boundary).nonce == "23" * 32

    future_boundary = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS + DEFAULT_MAX_FUTURE_MS,
        nonce="24" * 32,
    )
    assert _verify_request(future_boundary).nonce == "24" * 32


def test_only_one_concurrent_request_can_consume_an_authenticated_nonce() -> None:
    signed = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce="31" * 32,
    )
    registry = NonceRegistry()
    barrier = threading.Barrier(8)

    def attempt(_: int) -> str:
        barrier.wait(timeout=5)
        try:
            _verify_request(signed, registry=registry)
            return "accepted"
        except NonceReplayError:
            return "replayed"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("accepted") == 1
    assert results.count("replayed") == 7
    assert registry.size == 1


def test_nonce_registry_has_fail_closed_capacity_and_ttl_bounds() -> None:
    registry = NonceRegistry(max_entries=2, max_ttl_ms=100)
    registry.consume("41" * 32, now_ms=1_000, expires_at_ms=1_050)
    registry.consume("42" * 32, now_ms=1_000, expires_at_ms=1_050)
    with pytest.raises(NonceCapacityError, match="full"):
        registry.consume("43" * 32, now_ms=1_001, expires_at_ms=1_051)
    with pytest.raises(InstallationRootProtocolError, match="TTL"):
        registry.consume("43" * 32, now_ms=1_000, expires_at_ms=1_101)

    assert registry.prune(now_ms=1_049) == 0
    assert registry.prune(now_ms=1_050) == 2
    registry.consume("43" * 32, now_ms=1_050, expires_at_ms=1_150)
    assert registry.size == 1

    with pytest.raises(ValueError, match="bounded"):
        NonceRegistry(max_ttl_ms=300_002)


def test_failed_authentication_does_not_consume_nonce() -> None:
    signed = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce="51" * 32,
    )
    registry = NonceRegistry()
    bad_headers = dict(signed.headers)
    bad_headers[HEADER_SIGNATURE] = "00" * 32
    with pytest.raises(InstallationRootAuthenticationError):
        _verify_request(signed, registry=registry, headers=bad_headers)
    assert registry.size == 0
    assert _verify_request(signed, registry=registry).nonce == "51" * 32
    assert registry.size == 1


def test_response_is_bound_to_request_nonce_status_body_and_separate_domain() -> None:
    body = b'{"status":"active"}'
    signed = sign_response(
        boot_token=TOKEN,
        request_nonce=NONCE,
        status=200,
        body=body,
    )
    assert verify_response(
        boot_token=TOKEN,
        request_nonce=NONCE,
        status=200,
        headers=signed.headers,
        body=body,
    ).request_nonce == NONCE

    with pytest.raises(InstallationRootAuthenticationError):
        verify_response(
            boot_token=TOKEN,
            request_nonce=NONCE,
            status=201,
            headers=signed.headers,
            body=body,
        )
    with pytest.raises(InstallationRootAuthenticationError):
        verify_response(
            boot_token=TOKEN,
            request_nonce=NONCE,
            status=200,
            headers=signed.headers,
            body=body + b" ",
        )
    wrong_nonce_headers = dict(signed.headers)
    wrong_nonce_headers[HEADER_RESPONSE_REQUEST_NONCE] = "12" * 32
    with pytest.raises(InstallationRootAuthenticationError):
        verify_response(
            boot_token=TOKEN,
            request_nonce=NONCE,
            status=200,
            headers=wrong_nonce_headers,
            body=body,
        )


def test_asgi_helper_rejects_query_remote_peer_and_reconstructed_path() -> None:
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 49152),
        "method": "POST",
        "raw_path": PATH.encode("ascii"),
        "query_string": b"",
    }
    assert validate_asgi_loopback_scope(scope, allowed_paths={PATH}) == (METHOD, PATH)

    query = dict(scope, query_string=b"admin=true")
    with pytest.raises(LoopbackPolicyError, match="query"):
        validate_asgi_loopback_scope(query)
    remote = dict(scope, client=("192.0.2.10", 49152))
    with pytest.raises(LoopbackPolicyError, match="loopback"):
        validate_asgi_loopback_scope(remote)
    no_raw_path = dict(scope)
    del no_raw_path["raw_path"]
    with pytest.raises(LoopbackPolicyError, match="raw path"):
        validate_asgi_loopback_scope(no_raw_path)
    wrong_allowed_path = dict(scope, raw_path=b"/internal/installation-root/other")
    with pytest.raises(LoopbackPolicyError, match="not allowed"):
        validate_asgi_loopback_scope(wrong_allowed_path, allowed_paths={PATH})


def test_boot_token_is_strict_lower_hex_never_a_bearer_and_never_leaks() -> None:
    generated = generate_boot_token()
    assert len(generated) == 64
    assert generated == generated.lower()
    int(generated, 16)

    signed = sign_request(
        boot_token=TOKEN,
        method=METHOD,
        path=PATH,
        body=BODY,
        timestamp_ms=NOW_MS,
        nonce=NONCE,
    )
    wire = repr(signed)
    assert TOKEN not in wire
    assert all(name.lower() != "authorization" for name in signed.headers)
    assert TOKEN not in "\n".join(signed.headers.values())

    with pytest.raises(InstallationRootProtocolError) as raised:
        sign_request(
            boot_token=TOKEN.upper(),
            method=METHOD,
            path=PATH,
            body=BODY,
            timestamp_ms=NOW_MS,
            nonce=NONCE,
        )
    assert TOKEN.upper() not in str(raised.value)

    with pytest.raises(InstallationRootProtocolError, match="upper-case"):
        sign_request(
            boot_token=TOKEN,
            method="post",
            path=PATH,
            body=BODY,
            timestamp_ms=NOW_MS,
            nonce=NONCE,
        )
    with pytest.raises(InstallationRootProtocolError, match="query-free"):
        sign_request(
            boot_token=TOKEN,
            method=METHOD,
            path=PATH + "?x=1",
            body=BODY,
            timestamp_ms=NOW_MS,
            nonce=NONCE,
        )
