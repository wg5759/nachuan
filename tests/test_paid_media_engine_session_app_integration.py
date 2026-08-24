from __future__ import annotations

import json
import time

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from starlette.requests import Request

from gateway import app as appmod
from gateway import auth as authmod
from gateway.paid_media_engine_session_gateway import (
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
INSTALLATION_ID = "c" * 64
INSTALLATION_EPOCH = 3
INSTALLATION_PRINCIPAL = appmod.installation_principal(
    INSTALLATION_ID, INSTALLATION_EPOCH
)
VAULT_EVIDENCE_SHA256 = "d" * 64


def _environment() -> dict[str, str]:
    return {
        "NACHUAN_ENGINE_BOOT_TOKEN": BOOT_TOKEN,
        "NACHUAN_ENGINE_GENERATION": str(GENERATION),
        "NACHUAN_ENGINE_PORT": str(PORT),
    }


def _ordinary_headers(*, body: bytes, actual: bool) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"host", f"127.0.0.1:{PORT}".encode("ascii")),
        (b"connection", b"keep-alive"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"accept", b"application/json"),
        (b"accept-encoding", b"identity"),
        (b"cache-control", b"no-store"),
    ]
    if actual:
        headers.extend(
            [
                (b"content-type", b"application/json"),
                (b"x-nachuan-paid-media-protocol", b"2"),
                (b"idempotency-key", b"desktop-shadow-1234567890"),
            ]
        )
    return headers


def _configure_installation_root_state(public: FastAPI) -> None:
    public.state.paid_media_authority_mode = "installation-root"
    public.state.paid_media_installation_id = INSTALLATION_ID
    public.state.paid_media_epoch = INSTALLATION_EPOCH
    public.state.paid_media_root_principal = INSTALLATION_PRINCIPAL
    public.state.paid_media_principal = appmod.stable_paid_principal(
        INSTALLATION_PRINCIPAL
    )


def _stage_body() -> bytes:
    return json.dumps(
        {
            "schema": "nachuan.paid-media.engine-session.stage-ready.v1",
            "generation": GENERATION,
            "pid": PID,
            "port": PORT,
            "installationPrincipal": INSTALLATION_PRINCIPAL,
            "vaultEvidenceSha256": VAULT_EVIDENCE_SHA256,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


async def _activate_stage(composed) -> None:
    body = _stage_body()
    ordinary = [
        item
        for item in _ordinary_headers(body=body, actual=True)
        if item[0] != b"idempotency-key"
    ]
    sent = await _invoke(
        composed,
        method="POST",
        target=STAGE_READY_PATH,
        headers=_signed_headers(
            method="POST",
            target=STAGE_READY_PATH,
            body=body,
            nonce="5" * 64,
            ordinary=ordinary,
        ),
        body=body,
    )
    status, headers, receipt = _response(sent)
    assert status == 200
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce="5" * 64,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=status,
        headers=headers,
        body=receipt,
    )


def _signed_headers(
    *,
    method: str,
    target: str,
    body: bytes,
    nonce: str,
    ordinary: list[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
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
    return [
        *ordinary,
        *[
            (name.lower().encode("ascii"), value.encode("ascii"))
            for name, value in signed.headers.items()
        ],
    ]


async def _invoke(
    app,
    *,
    method: str,
    target: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
) -> list[dict]:
    requests = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return requests.pop(0) if requests else {"type": "http.disconnect"}

    sent: list[dict] = []

    async def send(message):
        sent.append(dict(message))

    await app(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "raw_path": target.encode("ascii"),
            "path": target,
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 55_000),
            "server": ("127.0.0.1", PORT),
            "state": {},
        },
        receive,
        send,
    )
    return sent


def _response(sent: list[dict]) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    assert sent and sent[0]["type"] == "http.response.start"
    body = b"".join(
        item.get("body", b"")
        for item in sent[1:]
        if item.get("type") == "http.response.body"
    )
    return sent[0]["status"], list(sent[0]["headers"]), body


@pytest.mark.asyncio
async def test_packaged_composition_challenges_then_signed_closes_actual_before_hooks() -> None:
    hooks = {"ledger": 0, "reservation": 0, "provider": 0}
    public = FastAPI()

    @public.post("/v1/images/generations")
    async def forbidden_business_path() -> dict[str, bool]:
        for name in hooks:
            hooks[name] += 1
        return {"ok": True}

    composed = appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    verifier = public.state.paid_media_engine_session_verifier
    assert verifier.ready is True
    assert verifier.stage_ready is False
    assert verifier.new_operations_ready is False

    challenge_nonce = "1" * 64
    challenge_ordinary = _ordinary_headers(body=b"", actual=False)
    challenge = await _invoke(
        composed,
        method="GET",
        target=CHALLENGE_PATH,
        headers=_signed_headers(
            method="GET",
            target=CHALLENGE_PATH,
            body=b"",
            nonce=challenge_nonce,
            ordinary=challenge_ordinary,
        ),
        body=b"",
    )
    status, response_headers, response_body = _response(challenge)
    assert status == 200
    assert response_body == CHALLENGE_BODY
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=challenge_nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=status,
        headers=response_headers,
        body=response_body,
    )

    target = "/v1/images/generations"
    body = b'{"model":"image-model","prompt":"hello"}'
    actual_nonce = "2" * 64
    actual_ordinary = _ordinary_headers(body=body, actual=True)
    actual = await _invoke(
        composed,
        method="POST",
        target=target,
        headers=_signed_headers(
            method="POST",
            target=target,
            body=body,
            nonce=actual_nonce,
            ordinary=actual_ordinary,
        ),
        body=body,
    )
    status, response_headers, response_body = _response(actual)
    assert status == 503
    assert json.loads(response_body)["code"] == (
        "desktop-v2-stage-authority-unavailable"
    )
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=actual_nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=status,
        headers=response_headers,
        body=response_body,
    )
    assert hooks == {"ledger": 0, "reservation": 0, "provider": 0}


@pytest.mark.asyncio
async def test_probe_success_and_error_are_inside_the_signed_paid_boundary() -> None:
    public = FastAPI()
    _configure_installation_root_state(public)

    @public.get("/v1/paid-media/probe/readiness")
    async def readiness() -> JSONResponse:
        return JSONResponse(
            {"ready": True},
            headers={
                "Cache-Control": "no-store",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
        )

    @public.post("/v1/paid-media/probe")
    async def rejected_probe() -> JSONResponse:
        return JSONResponse(
            {"detail": {"code": "media_probe_rejected"}},
            status_code=422,
            headers={"Cache-Control": "no-store"},
        )

    composed = appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    await _activate_stage(composed)
    assert public.state.paid_media_engine_session_verifier.stage_ready is True

    cases = (
        ("GET", "/v1/paid-media/probe/readiness", b"", "6" * 64, 200),
        ("POST", "/v1/paid-media/probe", b"probe", "7" * 64, 422),
    )
    for method, target, body, nonce, expected_status in cases:
        ordinary = _ordinary_headers(body=body, actual=True)
        sent = await _invoke(
            composed,
            method=method,
            target=target,
            headers=_signed_headers(
                method=method,
                target=target,
                body=body,
                nonce=nonce,
                ordinary=ordinary,
            ),
            body=body,
        )
        status, response_headers, response_body = _response(sent)
        assert status == expected_status
        normalized = {name.lower(): value for name, value in response_headers}
        assert normalized[b"cache-control"] == b"no-store"
        assert int(normalized[b"content-length"]) == len(response_body)
        if status == 200:
            assert normalized[b"x-nachuan-paid-media-protocol"] == b"2"
        verify_response(
            boot_token=BOOT_TOKEN,
            request_nonce=nonce,
            expected_generation=GENERATION,
            expected_pid=PID,
            expected_port=PORT,
            status=status,
            headers=response_headers,
            body=response_body,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation", ["unsigned", "header", "body", "long-lived-key"]
)
async def test_packaged_composition_rejects_tamper_and_long_keys_before_hooks(
    mutation: str,
) -> None:
    calls = 0
    public = FastAPI()

    @public.post("/v1/images/generations")
    async def forbidden_business_path() -> dict[str, bool]:
        nonlocal calls
        calls += 1
        return {"ok": True}

    composed = appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    target = "/v1/images/generations"
    signed_body = b'{"model":"image-model","prompt":"hello"}'
    sent_body = signed_body
    ordinary = _ordinary_headers(body=signed_body, actual=True)
    if mutation == "long-lived-key":
        ordinary.append((b"authorization", b"Bearer forbidden-runtime-key"))
    if mutation == "unsigned":
        headers = ordinary
    else:
        headers = _signed_headers(
            method="POST",
            target=target,
            body=signed_body,
            nonce={"header": "3", "body": "4", "long-lived-key": "5"}[
                mutation
            ]
            * 64,
            ordinary=ordinary,
        )
    if mutation == "header":
        headers = [
            (name, b"text/plain" if name == b"content-type" else value)
            for name, value in headers
        ]
    elif mutation == "body":
        sent_body = b'{"model":"image-model","prompt":"HELLO"}'

    rejected = await _invoke(
        composed,
        method="POST",
        target=target,
        headers=headers,
        body=sent_body,
    )
    status, response_headers, response_body = _response(rejected)

    assert status == 503
    assert json.loads(response_body)["code"] == "session_unavailable"
    assert not any(
        name.lower() == HEADER_RESPONSE_SIGNATURE.lower().encode("ascii")
        for name, _value in response_headers
    )
    assert calls == 0


@pytest.mark.asyncio
async def test_packaged_dependency_uses_session_state_without_reading_long_keys(
    monkeypatch,
) -> None:
    public = FastAPI()
    _configure_installation_root_state(public)
    calls = 0

    @public.post("/v1/images/generations")
    async def protected(
        request: Request,
        credential: str = Depends(authmod.require_paid_media_api_key),
    ) -> JSONResponse:
        nonlocal calls
        calls += 1
        return JSONResponse(
            {
                "credential": credential,
                "principal": request.state.nachuan_paid_media_principal_hash,
            },
            headers={
                "Cache-Control": "no-store",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
        )

    composed = appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    await _activate_stage(composed)
    monkeypatch.setattr(authmod.sys, "frozen", True, raising=False)

    def forbidden_settings_read():
        raise AssertionError("packaged session path compared a long-lived key")

    monkeypatch.setattr(authmod, "get_settings", forbidden_settings_read)
    body = b'{"model":"image-model","prompt":"live-state"}'
    target = "/v1/images/generations"
    nonce = "8" * 64
    ordinary = _ordinary_headers(body=body, actual=True)
    status, response_headers, response_body = _response(
        await _invoke(
            composed,
            method="POST",
            target=target,
            headers=_signed_headers(
                method="POST",
                target=target,
                body=body,
                nonce=nonce,
                ordinary=ordinary,
            ),
            body=body,
        )
    )

    assert status == 200
    assert calls == 1
    assert json.loads(response_body) == {
        "credential": "paid-engine-session",
        "principal": appmod.stable_paid_principal(INSTALLATION_PRINCIPAL),
    }
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        status=status,
        headers=response_headers,
        body=response_body,
    )


@pytest.mark.asyncio
async def test_packaged_dependency_rejects_an_equal_but_inactive_session_state(
    monkeypatch,
) -> None:
    public = FastAPI()
    _configure_installation_root_state(public)
    appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )
    session = {
        "authenticated": True,
        "nonce": "b" * 64,
        "generation": GENERATION,
        "pid": PID,
        "port": PORT,
    }
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/images/generations",
            "raw_path": b"/v1/images/generations",
            "query_string": b"",
            "headers": [],
            "app": public,
            "state": {SESSION_STATE_KEY: session},
        }
    )
    monkeypatch.setattr(authmod.sys, "frozen", True, raising=False)

    def forbidden_settings_read():
        raise AssertionError("packaged session path compared a long-lived key")

    monkeypatch.setattr(authmod, "get_settings", forbidden_settings_read)
    with pytest.raises(HTTPException) as exc_info:
        await authmod.require_paid_media_api_key(
            request,
            authorization=None,
            x_nachuan_paid_media_key=None,
        )
    assert exc_info.value.status_code == 503
