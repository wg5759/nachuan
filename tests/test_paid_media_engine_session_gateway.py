from __future__ import annotations

import hashlib
import json
import os
import time

import pytest

from gateway.paid_media_engine_session_gateway import (
    PaidMediaEngineSessionGatewayApp,
    SESSION_STATE_KEY,
    STAGE_READY_PATH,
)
from gateway.paid_media_engine_session_protocol import (
    CHALLENGE_BODY,
    CHALLENGE_PATH,
    HEADER_RESPONSE_SIGNATURE,
    sign_request,
    verify_response,
)


BOOT_TOKEN = "0123456789abcdef" * 4
GENERATION = 7
PID = 43_210
PORT = 43_111
INSTALLATION_PRINCIPAL = "a" * 64
VAULT_EVIDENCE_SHA256 = "b" * 64


def _environment() -> dict[str, str]:
    return {
        "NACHUAN_ENGINE_BOOT_TOKEN": BOOT_TOKEN,
        "NACHUAN_ENGINE_GENERATION": str(GENERATION),
        "NACHUAN_ENGINE_PORT": str(PORT),
    }


def _ordinary_headers(
    *, body: bytes, content_type: str | None = None, paid: bool = False
) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"host", f"127.0.0.1:{PORT}".encode("ascii")),
        (b"connection", b"keep-alive"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"accept", b"application/json"),
        (b"accept-encoding", b"identity"),
        (b"cache-control", b"no-store"),
    ]
    if content_type is not None:
        headers.append((b"content-type", content_type.encode("ascii")))
    if paid:
        headers.append((b"x-nachuan-paid-media-protocol", b"2"))
    return headers


def _stage_body(
    *,
    principal: str = INSTALLATION_PRINCIPAL,
    vault_evidence_sha256: str = VAULT_EVIDENCE_SHA256,
) -> bytes:
    return json.dumps(
        {
            "schema": "nachuan.paid-media.engine-session.stage-ready.v1",
            "generation": GENERATION,
            "pid": PID,
            "port": PORT,
            "installationPrincipal": principal,
            "vaultEvidenceSha256": vault_evidence_sha256,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _signed_headers(
    *,
    method: str,
    target: str,
    body: bytes,
    nonce: str,
    ordinary: list[tuple[bytes, bytes]],
) -> tuple[list[tuple[bytes, bytes]], object]:
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        method=method,
        target=target,
        contract_headers=ordinary,
        body=body,
        timestamp_ms=time.time_ns() // 1_000_000,
        nonce=nonce,
    )
    security = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in signed.headers.items()
    ]
    return [*ordinary, *security], signed


def _request_scope(
    *,
    method: str,
    target: str,
    headers: list[tuple[bytes, bytes]],
    server_port: int = PORT,
    decoded_path: str | None = None,
) -> dict:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "raw_path": target.encode("ascii"),
        "path": target if decoded_path is None else decoded_path,
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 55_000),
        "server": ("127.0.0.1", server_port),
        "state": {},
    }


async def _invoke(
    app,
    *,
    method: str,
    target: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes = b"",
    server_port: int = PORT,
    decoded_path: str | None = None,
) -> list[dict]:
    messages = [
        {"type": "http.request", "body": body, "more_body": False}
    ]

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    sent: list[dict] = []

    async def send(message):
        sent.append(dict(message))

    await app(
        _request_scope(
            method=method,
            target=target,
            headers=headers,
            server_port=server_port,
            decoded_path=decoded_path,
        ),
        receive,
        send,
    )
    return sent


def _response(sent: list[dict]) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    assert sent and sent[0]["type"] == "http.response.start"
    body = b"".join(
        message.get("body", b"")
        for message in sent[1:]
        if message.get("type") == "http.response.body"
    )
    return sent[0]["status"], list(sent[0]["headers"]), body


def _verify_signed_response(
    sent: list[dict], *, nonce: str, expected_status: int
) -> bytes:
    status, headers, body = _response(sent)
    assert status == expected_status
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=status,
        headers=headers,
        body=body,
    )
    return body


async def _activate_stage(
    app: PaidMediaEngineSessionGatewayApp,
    *,
    nonce: str,
    body: bytes | None = None,
) -> list[dict]:
    payload = _stage_body() if body is None else body
    ordinary = _ordinary_headers(
        body=payload,
        content_type="application/json",
        paid=True,
    )
    headers, _ = _signed_headers(
        method="POST",
        target=STAGE_READY_PATH,
        body=payload,
        nonce=nonce,
        ordinary=ordinary,
    )
    return await _invoke(
        app,
        method="POST",
        target=STAGE_READY_PATH,
        headers=headers,
        body=payload,
    )


@pytest.mark.asyncio
async def test_stage_ready_is_boot_local_signed_latch_and_never_enters_downstream() -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )

    first = await _activate_stage(app, nonce="8" * 64)
    receipt = _verify_signed_response(first, nonce="8" * 64, expected_status=200)
    assert json.loads(receipt) == {
        "schema": "nachuan.paid-media.engine-session.stage-ready.receipt.v1",
        "ok": True,
        "vaultEvidenceSha256": VAULT_EVIDENCE_SHA256,
    }
    assert app.stage_ready is True
    assert app.stage_vault_evidence_sha256 == VAULT_EVIDENCE_SHA256
    assert app.new_operations_ready is True

    repeated = await _activate_stage(app, nonce="9" * 64)
    assert _verify_signed_response(repeated, nonce="9" * 64, expected_status=200) == receipt
    assert calls == 0


@pytest.mark.asyncio
async def test_stage_ready_rejects_noncanonical_body_wrong_principal_and_binding_change() -> None:
    principal = INSTALLATION_PRINCIPAL
    app = PaidMediaEngineSessionGatewayApp(
        lambda *_args: None,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: principal,
    )

    noncanonical = _stage_body().replace(b'","generation"', b'", "generation"')
    malformed = await _activate_stage(app, nonce="a" * 64, body=noncanonical)
    assert json.loads(
        _verify_signed_response(malformed, nonce="a" * 64, expected_status=400)
    )["code"] == "invalid_request"
    assert app.stage_ready is False

    wrong = await _activate_stage(
        app,
        nonce="b" * 64,
        body=_stage_body(principal="c" * 64),
    )
    assert json.loads(
        _verify_signed_response(wrong, nonce="b" * 64, expected_status=503)
    )["code"] == "installation_authority_unavailable"
    assert app.stage_ready is False

    accepted = await _activate_stage(app, nonce="c" * 64)
    _verify_signed_response(accepted, nonce="c" * 64, expected_status=200)
    conflict = await _activate_stage(
        app,
        nonce="d" * 64,
        body=_stage_body(vault_evidence_sha256="d" * 64),
    )
    assert json.loads(
        _verify_signed_response(conflict, nonce="d" * 64, expected_status=409)
    )["code"] == "stage_binding_conflict"
    assert app.stage_vault_evidence_sha256 == VAULT_EVIDENCE_SHA256


@pytest.mark.asyncio
async def test_stage_ready_authority_drift_fuses_boot_latch_closed() -> None:
    current = {"principal": INSTALLATION_PRINCIPAL}
    app = PaidMediaEngineSessionGatewayApp(
        lambda *_args: None,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: current["principal"],
    )
    accepted = await _activate_stage(app, nonce="e" * 64)
    _verify_signed_response(accepted, nonce="e" * 64, expected_status=200)
    assert app.stage_ready is True

    current["principal"] = "e" * 64
    assert app.stage_ready is False
    current["principal"] = INSTALLATION_PRINCIPAL
    assert app.stage_ready is False
    assert app.stage_vault_evidence_sha256 is None


@pytest.mark.asyncio
async def test_stage_ready_authenticated_replay_after_wrong_principal_never_activates() -> None:
    current = {"principal": INSTALLATION_PRINCIPAL}
    body = _stage_body(principal="f" * 64)
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST",
        target=STAGE_READY_PATH,
        body=body,
        nonce="f" * 64,
        ordinary=ordinary,
    )
    app = PaidMediaEngineSessionGatewayApp(
        lambda *_args: None,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: current["principal"],
        hide_auth_failures=True,
    )
    first = await _invoke(
        app,
        method="POST",
        target=STAGE_READY_PATH,
        headers=headers,
        body=body,
    )
    _verify_signed_response(first, nonce="f" * 64, expected_status=503)
    current["principal"] = "f" * 64
    replay = await _invoke(
        app,
        method="POST",
        target=STAGE_READY_PATH,
        headers=headers,
        body=body,
    )
    assert _response(replay)[0] == 503
    assert not any(
        name == HEADER_RESPONSE_SIGNATURE.lower().encode("ascii")
        for name, _value in _response(replay)[1]
    )
    assert app.stage_ready is False


@pytest.mark.asyncio
async def test_challenge_is_authenticated_and_returns_exact_signed_keepalive_body() -> None:
    called = False

    async def downstream(_scope, _receive, _send):
        nonlocal called
        called = True

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    nonce = "1" * 64
    ordinary = _ordinary_headers(body=b"")
    headers, _signed = _signed_headers(
        method="GET",
        target=CHALLENGE_PATH,
        body=b"",
        nonce=nonce,
        ordinary=ordinary,
    )
    sent = await _invoke(
        app,
        method="GET",
        target=CHALLENGE_PATH,
        headers=headers,
    )

    body = _verify_signed_response(sent, nonce=nonce, expected_status=200)
    assert body == CHALLENGE_BODY
    assert called is False
    assert app.ready is True
    _status, response_headers, _body = _response(sent)
    normalized = {name.lower(): value for name, value in response_headers}
    assert normalized[b"connection"] == b"keep-alive"
    assert b"x-nachuan-paid-media-protocol" not in normalized
    assert b"idempotency-replayed" not in normalized


@pytest.mark.asyncio
async def test_missing_or_inconsistent_boot_authority_never_delegates() -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    for environment, server_port in (
        ({}, PORT),
        ({**_environment(), "NACHUAN_ENGINE_GENERATION": "07"}, PORT),
        (_environment(), PORT + 1),
    ):
        app = PaidMediaEngineSessionGatewayApp(
            downstream,
            configured_port=PORT,
            environ=environment,
            pid_provider=lambda: PID,
        )
        ordinary = _ordinary_headers(body=b"")
        headers, _ = _signed_headers(
            method="GET",
            target=CHALLENGE_PATH,
            body=b"",
            nonce=os.urandom(32).hex(),
            ordinary=ordinary,
        )
        sent = await _invoke(
            app,
            method="GET",
            target=CHALLENGE_PATH,
            headers=headers,
            server_port=server_port,
        )
        status, response_headers, _body = _response(sent)
        assert status == 503
        assert not any(
            name.lower() == HEADER_RESPONSE_SIGNATURE.lower().encode("ascii")
            for name, _value in response_headers
        )
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "decoded_path", "expected_status"),
    [
        (
            "/v1/%70aid-media/assets/npa1_alias",
            "/v1/paid-media/assets/npa1_alias",
            400,
        ),
        ("/v1/images/%67enerations", "/v1/images/generations", 400),
        ("/v1/videos/%74ask-1", "/v1/videos/task-1", 401),
        (
            "/internal/v1/paid-media/%73ession/challenge",
            CHALLENGE_PATH,
            400,
        ),
    ],
)
async def test_decoded_paid_path_alias_cannot_bypass_raw_session_boundary(
    target: str, decoded_path: str, expected_status: int
) -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    sent = await _invoke(
        app,
        method="GET",
        target=target,
        decoded_path=decoded_path,
        headers=[],
    )
    assert _response(sent)[0] == expected_status
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "/v1/images/generations/extra",
        "/v1/videos/task-1/extra",
        "/v1/paid-media/assets/npa1_alias/extra",
    ],
)
async def test_paid_route_trailing_aliases_remain_inside_session_boundary(
    target: str,
) -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    sent = await _invoke(app, method="GET", target=target, headers=[])

    assert _response(sent)[0] == 401
    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["host", "connection", "length", "protocol"])
async def test_authenticated_request_transport_headers_are_semantically_exact(
    mutation: str,
) -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    target = "/v1/images/generations"
    body = b'{"model":"m","prompt":"p"}'
    ordinary = _ordinary_headers(
        body=body, content_type="application/json", paid=True
    )
    replacements = {
        "host": (b"host", b"127.0.0.1:43112"),
        "connection": (b"connection", b"close"),
        "length": (b"content-length", b"999"),
        "protocol": (b"x-nachuan-paid-media-protocol", b"1"),
    }
    replacement = replacements[mutation]
    target_header = replacement[0]
    ordinary = [
        replacement if name == target_header else (name, value)
        for name, value in ordinary
    ]
    nonce = {
        "host": "8",
        "connection": "9",
        "length": "a",
        "protocol": "b",
    }[mutation] * 64
    headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce=nonce,
        ordinary=ordinary,
    )
    sent = await _invoke(
        app, method="POST", target=target, headers=headers, body=body
    )
    response = _verify_signed_response(sent, nonce=nonce, expected_status=400)
    assert json.loads(response)["code"] == "invalid_request"
    assert calls == 0


@pytest.mark.asyncio
async def test_legacy_long_lived_keys_are_rejected_before_delegation() -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    body = b'{"model":"m","prompt":"p"}'
    ordinary = [
        *_ordinary_headers(body=body, content_type="application/json", paid=True),
        (b"authorization", b"Bearer forbidden-long-runtime-key"),
    ]
    headers, _ = _signed_headers(
        method="POST",
        target="/v1/images/generations",
        body=body,
        nonce="2" * 64,
        ordinary=ordinary,
    )
    sent = await _invoke(
        app,
        method="POST",
        target="/v1/images/generations",
        headers=headers,
        body=body,
    )
    status, _headers, response_body = _response(sent)
    assert status == 400
    assert b"forbidden-long" not in response_body
    assert calls == 0


@pytest.mark.asyncio
async def test_authenticated_actual_request_is_signed_closed_until_stage_ready() -> None:
    calls = 0

    async def downstream(_scope, _receive, _send):
        nonlocal calls
        calls += 1

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    target = "/v1/images/generations"
    body = b'{"model":"m","prompt":"p"}'
    nonce = "f" * 64
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce=nonce,
        ordinary=ordinary,
    )

    sent = await _invoke(
        app,
        method="POST",
        target=target,
        headers=headers,
        body=body,
    )

    closed = _verify_signed_response(sent, nonce=nonce, expected_status=503)
    assert json.loads(closed)["code"] == (
        "desktop-v2-stage-authority-unavailable"
    )
    assert app.ready is True
    assert app.stage_ready is False
    assert app.new_operations_ready is False
    assert calls == 0


@pytest.mark.asyncio
async def test_tampered_ordinary_header_fails_without_burning_nonce_then_replay_closes() -> None:
    calls = 0

    async def downstream(scope, receive, send):
        nonlocal calls
        calls += 1
        assert scope["state"][SESSION_STATE_KEY]["authenticated"] is True
        request = await receive()
        assert request["body"] == body
        response = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(response)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": response})

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    body = b'{"model":"m","prompt":"p"}'
    nonce = "3" * 64
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST",
        target="/v1/images/generations",
        body=body,
        nonce=nonce,
        ordinary=ordinary,
    )
    tampered = [
        (name, b"text/plain" if name == b"content-type" else value)
        for name, value in headers
    ]
    rejected = await _invoke(
        app,
        method="POST",
        target="/v1/images/generations",
        headers=tampered,
        body=body,
    )
    assert _response(rejected)[0] == 401
    accepted = await _invoke(
        app,
        method="POST",
        target="/v1/images/generations",
        headers=headers,
        body=body,
    )
    assert _verify_signed_response(accepted, nonce=nonce, expected_status=200) == (
        b'{"ok":true}'
    )
    replayed = await _invoke(
        app,
        method="POST",
        target="/v1/images/generations",
        headers=headers,
        body=body,
    )
    assert _response(replayed)[0] == 401
    assert calls == 1


@pytest.mark.asyncio
async def test_downstream_business_error_and_invalid_response_are_signed_closed() -> None:
    invalid = False

    async def downstream(_scope, _receive, send):
        body = b'{"detail":"closed"}'
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if invalid:
            headers.append((b"Content-Type", b"text/plain"))
        await send(
            {"type": "http.response.start", "status": 422, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/paid-media/assets/ack"
    body = b"{}"
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    first_nonce = "4" * 64
    first_headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce=first_nonce,
        ordinary=ordinary,
    )
    first = await _invoke(
        app, method="POST", target=target, headers=first_headers, body=body
    )
    assert json.loads(
        _verify_signed_response(first, nonce=first_nonce, expected_status=422)
    ) == {"detail": "closed"}

    invalid = True
    second_nonce = "5" * 64
    second_headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce=second_nonce,
        ordinary=ordinary,
    )
    second = await _invoke(
        app, method="POST", target=target, headers=second_headers, body=body
    )
    replacement = _verify_signed_response(
        second, nonce=second_nonce, expected_status=503
    )
    assert json.loads(replacement)["code"] == "downstream_response_invalid"


@pytest.mark.asyncio
async def test_asset_stream_signs_descriptor_sha_without_buffering_whole_body() -> None:
    payload = b"verified-private-asset"
    digest = hashlib.sha256(payload).hexdigest()

    async def downstream(scope, _receive, send):
        assert scope["state"][SESSION_STATE_KEY]["authenticated"] is True
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"image/png"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-nachuan-paid-media-protocol", b"2"),
                    (b"x-content-sha256", digest.encode("ascii")),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload[:8], "more_body": True}
        )
        await send(
            {"type": "http.response.body", "body": payload[8:], "more_body": False}
        )

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/paid-media/assets/npa1_" + ("a" * 64)
    nonce = "6" * 64
    ordinary = _ordinary_headers(body=b"", paid=True)
    headers, _ = _signed_headers(
        method="GET", target=target, body=b"", nonce=nonce, ordinary=ordinary
    )
    sent = await _invoke(app, method="GET", target=target, headers=headers)
    status, response_headers, response_body = _response(sent)
    assert status == 200
    assert response_body == payload
    assert len(sent) == 3
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=200,
        headers=response_headers,
        body=response_body,
    )


@pytest.mark.asyncio
async def test_buffered_send_failure_never_attempts_a_second_response_start() -> None:
    response = b'{"ok":true}'

    async def downstream(_scope, _receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(response)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": response})

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/images/generations"
    body = b'{"model":"m","prompt":"p"}'
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce="c" * 64,
        ordinary=ordinary,
    )
    requests = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return requests.pop(0) if requests else {"type": "http.disconnect"}

    sent: list[dict] = []

    async def failing_send(message):
        sent.append(dict(message))
        if message.get("type") == "http.response.start":
            raise RuntimeError("simulated socket write failure")

    with pytest.raises(RuntimeError, match="simulated socket write failure"):
        await app(
            _request_scope(method="POST", target=target, headers=headers),
            receive,
            failing_send,
        )

    assert [item["type"] for item in sent].count("http.response.start") == 1


@pytest.mark.asyncio
async def test_incomplete_buffered_downstream_response_is_replaced_before_commit() -> None:
    async def downstream(_scope, _receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"partial":',
                "more_body": True,
            }
        )

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/paid-media/assets/ack"
    body = b"{}"
    nonce = "d" * 64
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST",
        target=target,
        body=body,
        nonce=nonce,
        ordinary=ordinary,
    )

    sent = await _invoke(
        app,
        method="POST",
        target=target,
        headers=headers,
        body=body,
    )

    replacement = _verify_signed_response(sent, nonce=nonce, expected_status=503)
    assert json.loads(replacement)["code"] == "downstream_response_invalid"


@pytest.mark.asyncio
async def test_stream_length_mismatch_aborts_before_forwarding_final_chunk() -> None:
    payload = b"verified-private-asset"
    digest = hashlib.sha256(payload).hexdigest()

    async def downstream(_scope, _receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"image/png"),
                    (b"content-length", str(len(payload) + 1).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-nachuan-paid-media-protocol", b"2"),
                    (b"x-content-sha256", digest.encode("ascii")),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload[:8], "more_body": True}
        )
        await send(
            {"type": "http.response.body", "body": payload[8:], "more_body": False}
        )

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/paid-media/assets/npa1_" + ("b" * 64)
    body = b""
    ordinary = _ordinary_headers(body=body, paid=True)
    headers, _ = _signed_headers(
        method="GET",
        target=target,
        body=body,
        nonce="e" * 64,
        ordinary=ordinary,
    )
    requests = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return requests.pop(0) if requests else {"type": "http.disconnect"}

    sent: list[dict] = []

    async def send(message):
        sent.append(dict(message))

    with pytest.raises(ValueError, match="content length mismatch"):
        await app(
            _request_scope(method="GET", target=target, headers=headers),
            receive,
            send,
        )

    bodies = [item for item in sent if item.get("type") == "http.response.body"]
    assert len(bodies) == 1
    assert bodies[0]["more_body"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "cache-control",
        "paid-protocol",
        "nosniff",
        "content-encoding",
        "transfer-encoding",
        "content-type",
        "content-length",
    ],
)
async def test_stream_contract_semantics_are_closed_before_response_commit(
    mutation: str,
) -> None:
    payload = b"asset"
    digest = hashlib.sha256(payload).hexdigest()
    response_headers = [
        (b"content-type", b"image/png"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-nachuan-paid-media-protocol", b"2"),
        (b"x-content-sha256", digest.encode("ascii")),
        (b"x-content-type-options", b"nosniff"),
    ]
    if mutation == "cache-control":
        response_headers[2] = (b"cache-control", b"public")
    elif mutation == "paid-protocol":
        response_headers[3] = (b"x-nachuan-paid-media-protocol", b"1")
    elif mutation == "nosniff":
        response_headers.pop()
    elif mutation == "content-encoding":
        response_headers.append((b"content-encoding", b"gzip"))
    elif mutation == "transfer-encoding":
        response_headers.append((b"transfer-encoding", b"chunked"))
    elif mutation == "content-type":
        response_headers = [
            item for item in response_headers if item[0] != b"content-type"
        ]
    elif mutation == "content-length":
        response_headers[1] = (b"content-length", b"05")

    async def downstream(_scope, _receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": payload})

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/paid-media/assets/npa1_" + ("c" * 64)
    ordinary = _ordinary_headers(body=b"", paid=True)
    headers, _ = _signed_headers(
        method="GET",
        target=target,
        body=b"",
        nonce={
            "cache-control": "0",
            "paid-protocol": "1",
            "nosniff": "2",
            "content-encoding": "3",
            "transfer-encoding": "4",
            "content-type": "5",
            "content-length": "6",
        }[mutation]
        * 64,
        ordinary=ordinary,
    )
    requests = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        return requests.pop(0) if requests else {"type": "http.disconnect"}

    sent: list[dict] = []

    async def send(message):
        sent.append(dict(message))

    with pytest.raises(ValueError):
        await app(
            _request_scope(method="GET", target=target, headers=headers),
            receive,
            send,
        )

    assert sent == []


@pytest.mark.asyncio
async def test_authority_drift_after_authenticated_request_replaces_json_response() -> None:
    environment = _environment()

    async def downstream(_scope, _receive, send):
        body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
        environment["NACHUAN_ENGINE_GENERATION"] = str(GENERATION + 1)

    app = PaidMediaEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=environment,
        pid_provider=lambda: PID,
        installation_principal_supplier=lambda: INSTALLATION_PRINCIPAL,
    )
    await _activate_stage(app, nonce=os.urandom(32).hex())
    target = "/v1/images/generations"
    body = b'{"model":"m","prompt":"p"}'
    nonce = "7" * 64
    ordinary = _ordinary_headers(body=body, content_type="application/json", paid=True)
    headers, _ = _signed_headers(
        method="POST", target=target, body=body, nonce=nonce, ordinary=ordinary
    )
    sent = await _invoke(
        app, method="POST", target=target, headers=headers, body=body
    )
    replacement = _verify_signed_response(sent, nonce=nonce, expected_status=503)
    assert json.loads(replacement)["code"] == "session_changed"
    assert app.ready is False
