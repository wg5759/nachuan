from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from gateway.desktop_engine_session_gateway import (
    SESSION_STATE_KEY,
    DesktopEngineSessionGatewayApp,
)
from gateway.desktop_engine_session_protocol import (
    CHALLENGE_BODY,
    CHALLENGE_PATH,
    sign_request,
    verify_response,
)


BOOT_TOKEN = "ab" * 32
GENERATION = 9
PID = 4242
PORT = 43_111
NOW = 1_800_000_000_000
CLIENT = ("127.0.0.1", 55_123)
ENV = {
    "NACHUAN_ENGINE_BOOT_TOKEN": BOOT_TOKEN,
    "NACHUAN_ENGINE_GENERATION": str(GENERATION),
    "NACHUAN_ENGINE_PORT": str(PORT),
}


def _base_headers(body: bytes, *, connection: str, json_body: bool) -> list[tuple[bytes, bytes]]:
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
    headers: list[tuple[Any, Any]],
    client=CLIENT,
    decoded_path: str | None = None,
) -> dict[str, Any]:
    return {
        "type": "http",
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": raw_path.decode("ascii") if decoded_path is None else decoded_path,
        "raw_path": raw_path,
        "query_string": query,
        "client": client,
        "server": ("127.0.0.1", PORT),
        "headers": headers,
        "state": {},
    }


async def _invoke(app: Any, scope: Mapping[str, Any], body: bytes) -> list[dict[str, Any]]:
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

    await app(dict(scope), receive, send)
    return messages


async def _challenge(
    app: Any,
    *,
    client: tuple[str, int] = CLIENT,
    nonce: str = "33" * 32,
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
        timestamp_ms=NOW,
        nonce=nonce,
        channel_nonce="0" * 64,
    )
    status, response_headers, response_body = _response(
        await _invoke(
            app,
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
    assert (status, response_body) == (200, CHALLENGE_BODY)
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="session.challenge",
        status=status,
        headers=response_headers,
        body=response_body,
    )
    return signed.nonce


async def _signed_request(
    app: Any,
    *,
    capability: str,
    method: str,
    raw_path: bytes,
    query: bytes = b"",
    body: bytes = b"",
    challenge_nonce: str,
    request_nonce: str = "44" * 32,
    client: tuple[str, int] = CLIENT,
    decoded_path: str | None = None,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    base = _base_headers(body, connection="close", json_body=method == "POST")
    target = raw_path.decode("ascii") + (
        "?" + query.decode("ascii") if query else ""
    )
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability=capability,
        method=method,
        target=target,
        contract_headers=[*base, *(extra_headers or [])],
        body=body,
        timestamp_ms=NOW,
        nonce=request_nonce,
        channel_nonce=challenge_nonce,
    )
    messages = await _invoke(
        app,
        _scope(
            method=method,
            raw_path=raw_path,
            query=query,
            headers=[
                *base,
                *(extra_headers or []),
                *_wire_headers(signed.headers),
            ],
            client=client,
            decoded_path=decoded_path,
        ),
        body,
    )
    return signed, messages


def _response(messages: list[dict[str, Any]]) -> tuple[int, list[Any], bytes]:
    assert [message["type"] for message in messages] == [
        "http.response.start",
        "http.response.body",
    ]
    return messages[0]["status"], messages[0]["headers"], messages[1]["body"]


@pytest.mark.asyncio
async def test_challenge_then_privileged_json_uses_same_connection_and_injects_nonsecret_state() -> None:
    delegated: list[tuple[dict[str, Any], bytes]] = []

    async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
        request = await receive()
        delegated.append((scope, request["body"]))
        body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    app = DesktopEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )

    challenge_headers = _base_headers(b"", connection="keep-alive", json_body=False)
    challenge = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability="session.challenge",
        method="GET",
        target=CHALLENGE_PATH,
        contract_headers=challenge_headers,
        body=b"",
        timestamp_ms=NOW,
        nonce="11" * 32,
        channel_nonce="0" * 64,
    )
    status, headers, body = _response(
        await _invoke(
            app,
            _scope(
                method="GET",
                raw_path=CHALLENGE_PATH.encode("ascii"),
                query=b"",
                headers=[
                    *challenge_headers,
                    *_wire_headers(challenge.headers),
                ],
            ),
            b"",
        )
    )
    assert (status, body) == (200, CHALLENGE_BODY)
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=challenge.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="session.challenge",
        status=status,
        headers=headers,
        body=body,
    )

    request_body = b"{}"
    request_headers = _base_headers(request_body, connection="close", json_body=True)
    request = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability="sync.run",
        method="POST",
        target="/v1/sync/run",
        contract_headers=request_headers,
        body=request_body,
        timestamp_ms=NOW,
        nonce="22" * 32,
        channel_nonce=challenge.nonce,
    )
    status, headers, body = _response(
        await _invoke(
            app,
            _scope(
                method="POST",
                raw_path=b"/v1/sync/run",
                query=b"",
                headers=[
                    *request_headers,
                    *_wire_headers(request.headers),
                ],
            ),
            request_body,
        )
    )
    assert (status, body) == (200, b'{"ok":true}')
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=request.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="sync.run",
        status=status,
        headers=headers,
        body=body,
    )
    assert delegated[0][1] == b"{}"
    state = delegated[0][0]["state"][SESSION_STATE_KEY]
    assert state == {
        "schema": "nachuan.desktop.engine-session.state.v1",
        "authenticated": True,
        "principal": "desktop-main",
        "capability": "sync.run",
        "nonce": request.nonce,
        "generation": GENERATION,
        "pid": PID,
        "port": PORT,
    }
    assert BOOT_TOKEN not in repr(state)
    assert not app.accepts_authenticated_state(
        state, expected_capability="sync.run"
    )


@pytest.mark.parametrize(
    ("capability", "method", "raw_path", "query", "body"),
    [
        (
            "plugin.ui.snapshot",
            "GET",
            b"/internal/v1/desktop/session/plugin-ui-snapshot",
            b"",
            b"",
        ),
        ("approval.list", "GET", b"/v1/approvals", b"user_id=a%20b", b""),
        (
            "approval.resolve",
            "POST",
            b"/v1/approvals/7/resolve",
            b"",
            b'{"decision":"approve","note":"ok"}',
        ),
        (
            "connection.save",
            "POST",
            b"/admin/connections/openai-compatible",
            b"",
            b'{"type":"openai","api_key":"secret","base_url":"https://example.test/v1","enabled_models":[{"id":"m"}],"preserve_existing_credential":false}',
        ),
        (
            "connection.delete",
            "DELETE",
            b"/admin/connections/openai-compatible",
            b"",
            b"",
        ),
        (
            "sync.config",
            "POST",
            b"/v1/sync/config",
            b"",
            b'{"url":"https://demo.supabase.co","anon_key":"anon"}',
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
        ("sync.toggle", "POST", b"/v1/sync/toggle", b"", b'{"enabled":true}'),
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
async def test_closed_manifest_delegates_every_exact_privileged_route(
    capability: str,
    method: str,
    raw_path: bytes,
    query: bytes,
    body: bytes,
) -> None:
    delegated: list[dict[str, Any]] = []

    async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
        delegated.append(scope)
        request = await receive()
        assert request["body"] == body
        response_body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": response_body})

    app = DesktopEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    channel = await _challenge(app)
    signed, messages = await _signed_request(
        app,
        capability=capability,
        method=method,
        raw_path=raw_path,
        query=query,
        body=body,
        challenge_nonce=channel,
    )
    status, response_headers, response_body = _response(messages)
    assert (status, response_body) == (200, b'{"ok":true}')
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability=capability,
        status=status,
        headers=response_headers,
        body=response_body,
    )
    assert len(delegated) == 1
    state = delegated[0]["state"][SESSION_STATE_KEY]
    assert state["capability"] == capability
    assert all(
        not name.lower().startswith(b"x-nachuan-engine-session-")
        for name, _ in delegated[0]["headers"]
    )


@pytest.mark.parametrize(
    ("capability", "raw_path", "body"),
    [
        (
            "approval.resolve",
            b"/v1/approvals/7/resolve",
            b'{"decision":"approve","note":"","extra":true}',
        ),
        (
            "connection.save",
            b"/admin/connections/openai",
            b'{"type":"openai","api_key":"","base_url":"","enabled_models":[],"preserve_existing_credential":false,"extra":true}',
        ),
        (
            "connection.save",
            b"/admin/connections/openai",
            b'{"type":"openai","api_key":"","base_url":"","enabled_models":[{"weight":1e400}],"preserve_existing_credential":false}',
        ),
        (
            "sync.config",
            b"/v1/sync/config",
            b'{"url":"https://demo.supabase.co","anon_key":"anon","extra":true}',
        ),
        (
            "sync.auth",
            b"/v1/sync/login",
            b'{"email":"owner@example.com","password":"secret","extra":true}',
        ),
        ("sync.toggle", b"/v1/sync/toggle", b'{"enabled":true,"extra":true}'),
        ("sync.run", b"/v1/sync/run", b'{"extra":true}'),
        (
            "channel-recovery.close",
            b"/admin/channel-recovery/feishu/close-without-replay",
            b'{"target_kind":"video","target_key":"task-1","expected_before_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decided_at_ms":1000,"reason":"operator confirmed no replay","user_confirmed":true,"confirm_final":false}',
        ),
    ],
)
@pytest.mark.asyncio
async def test_closed_json_schemas_reject_invalid_bodies(
    capability: str, raw_path: bytes, body: bytes
) -> None:
    delegated = False

    async def downstream(_scope: Any, _receive: Any, _send: Any) -> None:
        nonlocal delegated
        delegated = True

    app = DesktopEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    channel = await _challenge(app)
    signed, messages = await _signed_request(
        app,
        capability=capability,
        method="POST",
        raw_path=raw_path,
        body=body,
        challenge_nonce=channel,
    )
    status, headers, response_body = _response(messages)
    assert status == 400
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
    assert delegated is False


@pytest.mark.asyncio
async def test_request_and_response_message_counts_are_bounded() -> None:
    delegated = False

    async def unused_downstream(_scope: Any, _receive: Any, _send: Any) -> None:
        nonlocal delegated
        delegated = True

    request_app = DesktopEngineSessionGatewayApp(
        unused_downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    channel = await _challenge(request_app, nonce="71" * 32)
    body = b"{}"
    base = _base_headers(body, connection="close", json_body=True)
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability="sync.run",
        method="POST",
        target="/v1/sync/run",
        contract_headers=base,
        body=body,
        timestamp_ms=NOW,
        nonce="72" * 32,
        channel_nonce=channel,
    )
    request_messages = 0
    output: list[dict[str, Any]] = []

    async def endless_receive() -> dict[str, Any]:
        nonlocal request_messages
        request_messages += 1
        return {"type": "http.request", "body": b"", "more_body": True}

    async def collect(message: Mapping[str, Any]) -> None:
        output.append(dict(message))

    await request_app(
        _scope(
            method="POST",
            raw_path=b"/v1/sync/run",
            query=b"",
            headers=[*base, *_wire_headers(signed.headers)],
        ),
        endless_receive,
        collect,
    )
    assert _response(output)[0] == 400
    assert request_messages == 4097
    assert delegated is False

    async def fragmented_downstream(_scope: Any, _receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        for _ in range(4100):
            await send(
                {
                    "type": "http.response.body",
                    "body": b"",
                    "more_body": True,
                }
            )

    response_app = DesktopEngineSessionGatewayApp(
        fragmented_downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    response_channel = await _challenge(response_app, nonce="73" * 32)
    actual, messages = await _signed_request(
        response_app,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=response_channel,
        request_nonce="74" * 32,
    )
    status, headers, response_body = _response(messages)
    assert status == 503
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=actual.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="sync.run",
        status=status,
        headers=headers,
        body=response_body,
    )


@pytest.mark.asyncio
async def test_capability_mixing_query_alias_path_alias_and_replay_fail_closed() -> None:
    delegated = 0

    async def downstream(_scope: Any, _receive: Any, send: Any) -> None:
        nonlocal delegated
        delegated += 1
        body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def make_app() -> DesktopEngineSessionGatewayApp:
        return DesktopEngineSessionGatewayApp(
            downstream,
            configured_port=PORT,
            environ=ENV,
            pid_provider=lambda: PID,
            now_ms_provider=lambda: NOW,
        )

    mixed = make_app()
    channel = await _challenge(mixed, nonce="51" * 32)
    _, messages = await _signed_request(
        mixed,
        capability="approval.resolve",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=channel,
        request_nonce="52" * 32,
    )
    assert _response(messages)[0] == 401

    query_alias = make_app()
    channel = await _challenge(query_alias, nonce="53" * 32)
    _, messages = await _signed_request(
        query_alias,
        capability="approval.list",
        method="GET",
        raw_path=b"/v1/approvals",
        query=b"user_id=a%62",
        challenge_nonce=channel,
        request_nonce="54" * 32,
    )
    assert _response(messages)[0] == 400

    path_alias = make_app()
    channel = await _challenge(path_alias, nonce="55" * 32)
    _, messages = await _signed_request(
        path_alias,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/%72un",
        decoded_path="/v1/sync/run",
        body=b"{}",
        challenge_nonce=channel,
        request_nonce="56" * 32,
    )
    assert _response(messages)[0] == 400

    replay = make_app()
    channel = await _challenge(replay, nonce="57" * 32)
    _, first = await _signed_request(
        replay,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=channel,
        request_nonce="58" * 32,
    )
    assert _response(first)[0] == 200
    _, second = await _signed_request(
        replay,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=channel,
        request_nonce="58" * 32,
    )
    assert _response(second)[0] == 401
    assert delegated == 1


@pytest.mark.parametrize(
    "bad_headers",
    [
        [(b"content-length", b"12")],
        [(b"content-encoding", b"gzip")],
        [(b"x-injected", b"yes")],
        [(b"content-type", b"application/json")],
    ],
)
@pytest.mark.asyncio
async def test_downstream_response_header_injection_becomes_one_signed_503(
    bad_headers: list[tuple[bytes, bytes]],
) -> None:
    async def downstream(_scope: Any, _receive: Any, send: Any) -> None:
        body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json"), *bad_headers],
            }
        )
        await send({"type": "http.response.body", "body": body})

    app = DesktopEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    channel = await _challenge(app)
    signed, messages = await _signed_request(
        app,
        capability="sync.run",
        method="POST",
        raw_path=b"/v1/sync/run",
        body=b"{}",
        challenge_nonce=channel,
    )
    status, headers, body = _response(messages)
    assert status == 503
    assert len([message for message in messages if message["type"] == "http.response.start"]) == 1
    verify_response(
        boot_token=BOOT_TOKEN,
        request_nonce=signed.nonce,
        expected_generation=GENERATION,
        expected_pid=PID,
        expected_port=PORT,
        expected_capability="sync.run",
        status=status,
        headers=headers,
        body=body,
    )


@pytest.mark.parametrize(
    "legacy_name",
    [b"authorization", b"x-nachuan-approval-key", b"x-nachuan-paid-media-key"],
)
@pytest.mark.asyncio
async def test_long_lived_secret_headers_are_rejected_before_body_release(
    legacy_name: bytes,
) -> None:
    reads = 0
    delegated = False

    async def downstream(_scope: Any, _receive: Any, _send: Any) -> None:
        nonlocal delegated
        delegated = True

    app = DesktopEngineSessionGatewayApp(
        downstream,
        configured_port=PORT,
        environ=ENV,
        pid_provider=lambda: PID,
        now_ms_provider=lambda: NOW,
    )
    body = b"{}"
    base = _base_headers(body, connection="close", json_body=True)
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        generation=GENERATION,
        pid=PID,
        port=PORT,
        capability="sync.run",
        method="POST",
        target="/v1/sync/run",
        contract_headers=[*base, (legacy_name, b"long-lived-secret")],
        body=body,
        timestamp_ms=NOW,
        nonce="61" * 32,
        channel_nonce="62" * 32,
    )
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal reads
        reads += 1
        return {"type": "http.request", "body": body}

    async def send(message: Mapping[str, Any]) -> None:
        messages.append(dict(message))

    await app(
        _scope(
            method="POST",
            raw_path=b"/v1/sync/run",
            query=b"",
            headers=[
                *base,
                (legacy_name, b"long-lived-secret"),
                *_wire_headers(signed.headers),
            ],
        ),
        receive,
        send,
    )
    assert _response(messages)[0] == 400
    assert (reads, delegated) == (0, False)
