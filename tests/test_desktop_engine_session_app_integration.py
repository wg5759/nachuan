from __future__ import annotations

import json
import time
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from gateway import app as appmod
from gateway import auth as authmod
from gateway.desktop_engine_session_protocol import (
    CHALLENGE_BODY,
    CHALLENGE_PATH,
    HEADER_SIGNATURE,
    sign_request,
    verify_response,
)

BOOT_TOKEN = "cd" * 32
GENERATION = 17
PID = 54_321
PORT = 43_211
CLIENT = ("127.0.0.1", 55_321)
_MISSING_STATE = object()


@pytest.fixture(autouse=True)
def _restore_composed_gateway_verifiers():
    """Keep wrapper composition tests from mutating the process-global app."""

    state = appmod._public_fastapi_app.state
    names = (
        "desktop_engine_session_verifier",
        "paid_media_engine_session_verifier",
    )
    before = {name: getattr(state, name, _MISSING_STATE) for name in names}
    yield
    for name, value in before.items():
        if value is _MISSING_STATE:
            try:
                delattr(state, name)
            except AttributeError:
                pass
        else:
            setattr(state, name, value)


def _environment() -> dict[str, str]:
    return {
        "NACHUAN_ENGINE_BOOT_TOKEN": BOOT_TOKEN,
        "NACHUAN_ENGINE_GENERATION": str(GENERATION),
        "NACHUAN_ENGINE_PORT": str(PORT),
    }


def _base_headers(
    body: bytes, *, connection: str, json_body: bool
) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"host", f"127.0.0.1:{PORT}".encode("ascii")),
        (b"connection", connection.encode("ascii")),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"accept", b"application/json"),
        (b"accept-encoding", b"identity"),
        (b"cache-control", b"no-store"),
    ]
    if json_body:
        headers.append((b"content-type", b"application/json"))
    return headers


def _wire_headers(headers: Mapping[str, str]) -> list[tuple[bytes, bytes]]:
    return [
        (name.encode("ascii"), value.encode("ascii"))
        for name, value in headers.items()
    ]


def _scope(
    *,
    method: str,
    raw_path: bytes,
    query: bytes,
    headers: list[tuple[bytes, bytes]],
    client: tuple[str, int] = CLIENT,
) -> dict[str, Any]:
    return {
        "type": "http",
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": raw_path.decode("ascii"),
        "raw_path": raw_path,
        "query_string": query,
        "client": client,
        "server": ("127.0.0.1", PORT),
        "headers": headers,
        "state": {},
    }


async def _invoke(
    target: Any, scope: Mapping[str, Any], body: bytes
) -> list[dict[str, Any]]:
    received = False
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: Mapping[str, Any]) -> None:
        messages.append(dict(message))

    await target(dict(scope), receive, send)
    return messages


def _response(
    messages: list[dict[str, Any]],
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    starts = [message for message in messages if message["type"] == "http.response.start"]
    assert len(starts) == 1
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return starts[0]["status"], list(starts[0].get("headers") or []), body


async def _challenge(
    target: Any, *, nonce: str, client: tuple[str, int] = CLIENT
) -> str:
    base = _base_headers(b"", connection="keep-alive", json_body=False)
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability="session.challenge",
        method="GET",
        target=CHALLENGE_PATH,
        contract_headers=base,
        body=b"",
        timestamp_ms=time.time_ns() // 1_000_000,
        nonce=nonce,
        channel_nonce="0" * 64,
    )
    status, headers, body = _response(
        await _invoke(
            target,
            _scope(
                method="GET",
                raw_path=CHALLENGE_PATH.encode("ascii"),
                query=b"",
                headers=[*base, *_wire_headers(signed.headers)],
                client=client,
            ),
            b"",
        )
    )
    assert (status, body) == (200, CHALLENGE_BODY)
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="session.challenge",
        status=status,
        headers=headers,
        body=body,
    )
    return signed.nonce


async def _signed_request(
    target: Any,
    *,
    capability: str,
    method: str,
    raw_path: bytes,
    challenge_nonce: str,
    request_nonce: str,
    query: bytes = b"",
    body: bytes = b"",
    mutate_signature: bool = False,
    client: tuple[str, int] = CLIENT,
) -> tuple[Any, list[dict[str, Any]]]:
    base = _base_headers(body, connection="close", json_body=method == "POST")
    exact_target = raw_path.decode("ascii") + (
        "?" + query.decode("ascii") if query else ""
    )
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability=capability,
        method=method,
        target=exact_target,
        contract_headers=base,
        body=body,
        timestamp_ms=time.time_ns() // 1_000_000,
        nonce=request_nonce,
        channel_nonce=challenge_nonce,
    )
    security_headers = dict(signed.headers)
    if mutate_signature:
        security_headers[HEADER_SIGNATURE] = "0" * 64
    messages = await _invoke(
        target,
        _scope(
            method=method,
            raw_path=raw_path,
            query=query,
            headers=[*base, *_wire_headers(security_headers)],
            client=client,
        ),
        body,
    )
    return signed, messages


def _compose(public: FastAPI, environment: dict[str, str] | None = None) -> Any:
    return appmod._compose_gateway_asgi_app(
        public,
        packaged=True,
        configured_port=PORT,
        environ=_environment() if environment is None else environment,
        pid_provider=lambda: PID,
    )


def test_electron_development_boot_environment_installs_only_desktop_wrapper() -> None:
    public = FastAPI()

    appmod._compose_gateway_asgi_app(
        public,
        packaged=False,
        configured_port=PORT,
        environ=_environment(),
        pid_provider=lambda: PID,
    )

    desktop = public.state.desktop_engine_session_verifier
    assert isinstance(desktop, appmod.DesktopEngineSessionGatewayApp)
    assert desktop.ready is True
    assert public.state.paid_media_engine_session_verifier is None


def test_plain_source_gateway_without_electron_boot_environment_installs_no_session_wrapper() -> None:
    public = FastAPI()

    appmod._compose_gateway_asgi_app(
        public,
        packaged=False,
        configured_port=PORT,
        environ={},
        pid_provider=lambda: PID,
    )

    assert public.state.desktop_engine_session_verifier is None
    assert public.state.paid_media_engine_session_verifier is None


def test_partial_development_boot_environment_fails_closed_without_enabling_paid() -> None:
    public = FastAPI()

    appmod._compose_gateway_asgi_app(
        public,
        packaged=False,
        configured_port=PORT,
        environ={"NACHUAN_ENGINE_BOOT_TOKEN": BOOT_TOKEN},
        pid_provider=lambda: PID,
    )

    desktop = public.state.desktop_engine_session_verifier
    assert isinstance(desktop, appmod.DesktopEngineSessionGatewayApp)
    assert desktop.ready is False
    assert public.state.paid_media_engine_session_verifier is None


def test_source_gateway_refuses_start_when_electron_requested_session_is_unready(
    monkeypatch,
) -> None:
    monkeypatch.setattr(appmod, "_is_packaged_runtime", lambda: False)
    monkeypatch.setenv("NACHUAN_ENGINE_BOOT_TOKEN", BOOT_TOKEN)
    monkeypatch.delenv("NACHUAN_ENGINE_GENERATION", raising=False)
    monkeypatch.delenv("NACHUAN_ENGINE_PORT", raising=False)
    monkeypatch.setattr(
        appmod._public_fastapi_app.state,
        "desktop_engine_session_verifier",
        None,
        raising=False,
    )
    monkeypatch.setattr(
        appmod,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "gateway_host": "127.0.0.1",
                "gateway_port": PORT,
                "api_keys": frozenset({"test-key"}),
            },
        )(),
    )

    with pytest.raises(SystemExit, match="Desktop Engine Session"):
        appmod.main()


def test_packaged_gateway_refuses_start_when_shared_session_authority_is_unready(
    monkeypatch,
) -> None:
    monkeypatch.setattr(appmod, "_is_packaged_runtime", lambda: True)
    monkeypatch.setattr(
        appmod._public_fastapi_app.state,
        "desktop_engine_session_verifier",
        None,
        raising=False,
    )
    monkeypatch.setattr(
        appmod,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "gateway_host": "127.0.0.1",
                "gateway_port": PORT,
                "api_keys": frozenset({"test-key"}),
            },
        )(),
    )

    with pytest.raises(SystemExit, match="Desktop Engine Session"):
        appmod.main()


@pytest.mark.asyncio
async def test_main_equivalent_session_reaches_real_gateway_approval_route_without_long_keys(
    monkeypatch,
) -> None:
    class _Approvals:
        def __init__(self) -> None:
            self.users: list[str] = []

        def list_pending(self, user_id: str) -> list[dict[str, object]]:
            self.users.append(user_id)
            return [{"id": 7, "kind": "action", "status": "pending"}]

    approvals = _Approvals()
    public = appmod._public_fastapi_app
    monkeypatch.setattr(public.state, "approvals", approvals, raising=False)

    def forbidden_long_key_lookup() -> object:
        raise AssertionError("Desktop session path read a long-lived credential")

    monkeypatch.setattr(authmod, "get_settings", forbidden_long_key_lookup)
    composed = _compose(public)
    challenge = await _challenge(composed, nonce="11" * 32)
    signed, messages = await _signed_request(
        composed,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce=challenge,
        request_nonce="12" * 32,
    )
    status, headers, body = _response(messages)

    assert status == 200
    assert approvals.users == ["owner"]
    assert json.loads(body) == {
        "user_id": "owner",
        "pending": [{"id": 7, "kind": "action", "status": "pending"}],
    }
    normalized = {name.lower(): value for name, value in headers}
    assert b"x-trace-id" not in normalized
    assert b"server-timing" not in normalized
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="approval.list",
        status=status,
        headers=headers,
        body=body,
    )


@pytest.mark.asyncio
async def test_main_plugin_ui_capability_reaches_real_snapshot_without_long_keys(
    monkeypatch,
) -> None:
    slots = (
        {
            "slot_id": "workspace.orchestration",
            "surface": "workspace.menu",
            "component": "orchestrate",
            "order": 600,
            "plugin_id": "com.nachuan.ui.orchestration",
            "plugin_version": "1.0.0",
            "artifact_sha256": "a" * 64,
        },
    )
    public = appmod._public_fastapi_app
    monkeypatch.setattr(
        public.state,
        "router",
        SimpleNamespace(
            plugin_kernel=SimpleNamespace(ui_slot_snapshot=lambda: slots)
        ),
        raising=False,
    )

    def forbidden_long_key_lookup() -> object:
        raise AssertionError("plugin UI session path read a long-lived credential")

    monkeypatch.setattr(authmod, "get_settings", forbidden_long_key_lookup)
    composed = _compose(public)
    challenge = await _challenge(composed, nonce="51" * 32)
    signed, messages = await _signed_request(
        composed,
        capability="plugin.ui.snapshot",
        method="GET",
        raw_path=b"/internal/v1/desktop/session/plugin-ui-snapshot",
        challenge_nonce=challenge,
        request_nonce="52" * 32,
    )
    status, headers, body = _response(messages)

    assert status == 200
    assert json.loads(body) == {
        "schema": "nachuan.plugin-ui.snapshot.v1",
        "slots": [dict(slots[0])],
    }
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="plugin.ui.snapshot",
        status=status,
        headers=headers,
        body=body,
    )


@pytest.mark.parametrize(
    ("capability", "method", "raw_path", "query", "body"),
    [
        ("approval.list", "GET", b"/v1/approvals", b"user_id=owner", b""),
        (
            "approval.resolve",
            "POST",
            b"/v1/approvals/7/resolve",
            b"",
            b'{"decision":"approve","note":""}',
        ),
        (
            "connection.save",
            "POST",
            b"/admin/connections/openai",
            b"",
            b'{"type":"openai","api_key":"key","base_url":"https://api.example/v1","enabled_models":[],"preserve_existing_credential":false}',
        ),
        (
            "connection.delete",
            "DELETE",
            b"/admin/connections/openai",
            b"",
            b"",
        ),
        (
            "sync.config",
            "POST",
            b"/v1/sync/config",
            b"",
            b'{"url":"https://sync.example","anon_key":"anon"}',
        ),
        (
            "sync.auth",
            "POST",
            b"/v1/sync/login",
            b"",
            b'{"email":"owner@example.com","password":"secret"}',
        ),
        (
            "sync.auth",
            "POST",
            b"/v1/sync/signup",
            b"",
            b'{"email":"owner@example.com","password":"secret"}',
        ),
        (
            "sync.toggle",
            "POST",
            b"/v1/sync/toggle",
            b"",
            b'{"enabled":false}',
        ),
        ("sync.run", "POST", b"/v1/sync/run", b"", b"{}"),
        (
            "channel-recovery.inspect",
            "POST",
            b"/admin/channel-recovery/feishu/inspect",
            b"",
            b'{"target_kind":"video","target_key":"task-1"}',
        ),
        (
            "channel-recovery.close",
            "POST",
            b"/admin/channel-recovery/weixin/close-without-replay",
            b"",
            b'{"target_kind":"inbound","target_key":"message-1","expected_before_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decided_at_ms":1000,"reason":"operator confirmed no replay","user_confirmed":true,"confirm_final":true}',
        ),
    ],
)
@pytest.mark.asyncio
async def test_every_closed_capability_reaches_inner_auth_without_persistent_keys(
    capability: str,
    method: str,
    raw_path: bytes,
    query: bytes,
    body: bytes,
) -> None:
    calls: list[str] = []
    public = FastAPI()

    async def target(
        request: Request,
        _: str = Depends(authmod.require_api_key),
        __: str = Depends(authmod.require_approval_admin_key),
    ) -> dict[str, bool]:
        calls.append(request.url.path)
        return {"ok": True}

    route_path = raw_path.decode("ascii")
    if capability == "approval.resolve":
        route_path = "/v1/approvals/{approval_id}/resolve"
    elif capability.startswith("connection."):
        route_path = "/admin/connections/{provider}"
    public.add_api_route(route_path, target, methods=[method])
    composed = _compose(public)
    challenge = await _challenge(composed, nonce="13" * 32)
    signed, messages = await _signed_request(
        composed,
        capability=capability,
        method=method,
        raw_path=raw_path,
        query=query,
        body=body,
        challenge_nonce=challenge,
        request_nonce="14" * 32,
    )
    status, headers, response_body = _response(messages)

    assert status == 200
    assert calls == [raw_path.decode("ascii")]
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability=capability,
        status=status,
        headers=headers,
        body=response_body,
    )


@pytest.mark.asyncio
async def test_bad_signature_channel_nonce_capability_and_replay_never_reach_route() -> None:
    calls = 0
    public = FastAPI()

    @public.get("/v1/approvals")
    async def approvals(
        user_id: str,
        _: str = Depends(authmod.require_api_key),
        __: str = Depends(authmod.require_approval_admin_key),
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"user_id": user_id, "pending": []}

    composed = _compose(public)

    bad_signature_challenge = await _challenge(composed, nonce="21" * 32)
    _, bad_signature = await _signed_request(
        composed,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce=bad_signature_challenge,
        request_nonce="22" * 32,
        mutate_signature=True,
    )
    assert _response(bad_signature)[0] == 401

    wrong_channel_challenge = await _challenge(composed, nonce="23" * 32)
    wrong_channel_signed, wrong_channel = await _signed_request(
        composed,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce="ff" * 32,
        request_nonce="24" * 32,
    )
    status, headers, body = _response(wrong_channel)
    assert status == 400
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=wrong_channel_signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="approval.list",
        status=status,
        headers=headers,
        body=body,
    )
    assert wrong_channel_challenge != "ff" * 32

    wrong_capability_challenge = await _challenge(composed, nonce="25" * 32)
    _, wrong_capability = await _signed_request(
        composed,
        capability="sync.run",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce=wrong_capability_challenge,
        request_nonce="26" * 32,
    )
    assert _response(wrong_capability)[0] == 401

    first_challenge = await _challenge(composed, nonce="27" * 32)
    first_signed, first = await _signed_request(
        composed,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce=first_challenge,
        request_nonce="28" * 32,
    )
    first_status, first_headers, first_body = _response(first)
    assert first_status == 200
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=first_signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="approval.list",
        status=first_status,
        headers=first_headers,
        body=first_body,
    )
    second_challenge = await _challenge(composed, nonce="29" * 32)
    _, replay = await _signed_request(
        composed,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        challenge_nonce=second_challenge,
        request_nonce="28" * 32,
    )
    assert _response(replay)[0] == 401
    assert calls == 1


@pytest.mark.asyncio
async def test_closed_manifest_bad_status_and_generation_rotation_fail_closed() -> None:
    calls = {"run": 0, "outside": 0}
    public = FastAPI()

    @public.post("/v1/sync/run")
    async def sync_run(
        _: str = Depends(authmod.require_api_key),
        __: str = Depends(authmod.require_approval_admin_key),
    ) -> JSONResponse:
        calls["run"] += 1
        return JSONResponse({"ok": True}, status_code=204)

    @public.post("/v1/sync/status")
    async def outside_manifest() -> dict[str, bool]:
        calls["outside"] += 1
        return {"ok": True}

    environment = _environment()
    composed = _compose(public, environment)

    status_challenge = await _challenge(composed, nonce="31" * 32)
    status_signed, status_messages = await _signed_request(
        composed,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=status_challenge,
        request_nonce="32" * 32,
    )
    status, headers, body = _response(status_messages)
    assert status == 503
    assert json.loads(body)["code"] == "downstream_response_invalid"
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=status_signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="sync.run",
        status=status,
        headers=headers,
        body=body,
    )

    outside_challenge = await _challenge(composed, nonce="33" * 32)
    _, outside = await _signed_request(
        composed,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/status",
        body=b"{}",
        challenge_nonce=outside_challenge,
        request_nonce="34" * 32,
    )
    assert _response(outside)[0] == 400

    rotation_challenge = await _challenge(composed, nonce="35" * 32)
    environment["NACHUAN_ENGINE_GENERATION"] = str(GENERATION + 1)
    _, rotated = await _signed_request(
        composed,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=rotation_challenge,
        request_nonce="36" * 32,
    )
    assert _response(rotated)[0] == 503
    assert calls == {"run": 1, "outside": 0}


@pytest.mark.asyncio
async def test_packaged_composition_preserves_unrelated_non_session_traffic() -> None:
    public = FastAPI()

    @public.get("/plain")
    async def plain() -> dict[str, str]:
        return {"mode": "ordinary"}

    composed = _compose(public)
    status, _headers, body = _response(
        await _invoke(
            composed,
            _scope(
                method="GET",
                raw_path=b"/plain",
                query=b"",
                # ASGI permits opaque header bytes outside this private
                # protocol.  The wrapper must not normalize unrelated traffic.
                headers=[(b"x-user-label", b"\xff")],
            ),
            b"",
        )
    )
    assert status == 200
    assert json.loads(body) == {"mode": "ordinary"}


@pytest.mark.asyncio
async def test_equal_nonsecret_state_cannot_bypass_wrapper_by_calling_inner_fastapi() -> None:
    calls = 0
    public = FastAPI()

    @public.get("/v1/approvals")
    async def approvals(
        user_id: str,
        _: str = Depends(authmod.require_api_key),
        __: str = Depends(authmod.require_approval_admin_key),
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"user_id": user_id, "pending": []}

    _compose(public)
    forged = {
        "schema": "nachuan.desktop.engine-session.state.v1",
        "authenticated": True,
        "principal": "desktop-main",
        "capability": "approval.list",
        "nonce": "41" * 32,
        "generation": GENERATION,
        "pid": PID,
        "port": PORT,
    }
    scope = _scope(
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=owner",
        headers=[],
    )
    scope["state"] = {"nachuan_desktop_engine_session": forged}
    status, headers, body = _response(await _invoke(public, scope, b""))

    assert status == 503
    assert json.loads(body)["detail"] == (
        "Desktop engine-session capability is unavailable."
    )
    assert dict(headers)[b"cache-control"] == b"no-store"
    assert calls == 0
