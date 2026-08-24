from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.body_limit import RequestBodyLimitMiddleware
from gateway.bridge_protocol import open_response, seal_request
from gateway.config import get_settings
from gateway.trusted_media_probe import TrustedMediaProbeResult
from gateway.weixin_idempotency import WeixinIdempotencyStore


AUTH = {"Authorization": "Bearer test-key"}
ORIGIN = "http://127.0.0.1:5173"


def _verified_test_image_probe(
    path,
    *,
    expected_media_type: str,
    expected_byte_length: int,
    expected_sha256: str,
    **_kwargs,
) -> TrustedMediaProbeResult:
    payload = Path(path).read_bytes()
    assert len(payload) == expected_byte_length
    assert hashlib.sha256(payload).hexdigest() == expected_sha256
    return TrustedMediaProbeResult(
        media_type=expected_media_type,
        detected_kind="image",
        byte_length=expected_byte_length,
        sha256=expected_sha256,
        codec_name="png",
        audio_codec_name=None,
        video_stream_count=1,
        audio_stream_count=0,
        format_name="png",
        width=1,
        height=1,
        duration_ms=None,
        decoded_frames=1,
        ffmpeg_sha256="a" * 64,
        ffprobe_sha256="b" * 64,
    )


def _reset_gateway_stack() -> None:
    # Starlette caches the assembled ASGI middleware stack after first use.
    appmod._public_fastapi_app.middleware_stack = None


def test_cors_is_outermost_and_covers_body_limit_and_bridge_rejections() -> None:
    assert appmod.app.user_middleware[0].cls is CORSMiddleware
    assert any(item.cls is RequestBodyLimitMiddleware for item in appmod.app.user_middleware)

    with TestClient(appmod.app) as client:
        too_large = client.post(
            "/v1/intent",
            headers={
                **AUTH,
                "Origin": ORIGIN,
                "Content-Type": "application/json",
                "Content-Length": str(33 * 1024 * 1024),
            },
            content=b"",
        )
        malformed_bridge = client.post(
            "/v1/agent/chat",
            headers={
                "Origin": ORIGIN,
                "Content-Encoding": "nachuan-bridge-aesgcm-v1",
                "X-Nachuan-Bridge-Version": "1",
            },
            content=b"",
        )

    assert too_large.status_code == 413
    assert too_large.headers["access-control-allow-origin"] == ORIGIN
    assert malformed_bridge.status_code == 401
    assert malformed_bridge.headers["access-control-allow-origin"] == ORIGIN


def test_cors_covers_admission_short_circuit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("ADMISSION_ROLLING_MINUTE_PER_KEY", "1")
    monkeypatch.setenv("ADMISSION_DAILY_EXPENSIVE_PER_KEY", "0")
    get_settings.cache_clear()
    _reset_gateway_stack()
    try:
        with TestClient(appmod.app) as client:
            first = client.post(
                "/v1/intent", headers={**AUTH, "Origin": ORIGIN}, json={}
            )
            limited = client.post(
                "/v1/intent", headers={**AUTH, "Origin": ORIGIN}, json={}
            )
        assert first.status_code == 200
        assert limited.status_code == 429
        assert limited.headers["access-control-allow-origin"] == ORIGIN
    finally:
        get_settings.cache_clear()
        _reset_gateway_stack()


def test_outer_cors_preserves_sealed_bridge_response(monkeypatch, tmp_path) -> None:
    secret = "sk-bridge-v2-weixin-" + ("7" * 64)
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("NACHUAN_WEIXIN_BRIDGE_API_KEY", secret)
    get_settings.cache_clear()
    _reset_gateway_stack()
    try:
        sealed = seal_request(
            secret=secret,
            channel="weixin",
            method="GET",
            url_or_target="/v1/bridge/health",
        )
        with TestClient(appmod.app) as client:
            response = client.request(
                "GET",
                "/v1/bridge/health",
                headers={**sealed.headers, "Origin": ORIGIN},
                content=sealed.body,
            )
        plaintext = open_response(
            secret=secret,
            channel="weixin",
            request_nonce=sealed.request_nonce,
            status=response.status_code,
            headers=response.headers,
            body=response.content,
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == ORIGIN
        health = json.loads(plaintext)
        assert set(health) == {"status", "channel", "chat_ready", "reason"}
        assert health["status"] == "ok"
        assert health["channel"] == "weixin"
        assert type(health["chat_ready"]) is bool
        if health["chat_ready"]:
            assert health["reason"] == "ready"
        else:
            assert health["reason"] in {
                "ready_no_model",
                "provider_call_ledger_not_ready",
            }
    finally:
        get_settings.cache_clear()
        _reset_gateway_stack()


def test_health_reports_quarantined_connection_names_without_details(monkeypatch) -> None:
    with TestClient(appmod.app) as client:
        monkeypatch.setattr(
            client.app.state.store,
            "invalid",
            lambda: {"unsafe-provider": "secret validation detail"},
        )
        response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["readiness"] == "degraded"
    assert body["checks"]["connection_store"] == {
        "ready": False,
        "quarantined": ["unsafe-provider"],
    }
    assert "secret validation detail" not in response.text


def test_health_degrades_when_required_financial_ledger_is_unavailable(monkeypatch) -> None:
    class BrokenLedger:
        required = True

        def operational_snapshot(self):  # noqa: ANN201
            raise OSError("private-ledger-path-and-secret")

    with TestClient(appmod.app) as client:
        monkeypatch.setattr(
            client.app.state,
            "provider_call_ledger",
            BrokenLedger(),
        )
        response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["readiness"] == "degraded"
    assert body["checks"]["financial_ledger"] == {
        "required": True,
        "ready": False,
        "status": "unavailable",
        "capacity_status": "unknown",
        "database_bytes": 0,
        "wal_bytes": 0,
        "max_database_bytes": 0,
        "disk_free_bytes": 0,
        "last_write_error_type": "OSError",
        "last_write_error_at": None,
    }
    assert "private-ledger-path-and-secret" not in response.text


def test_health_degrades_when_financial_ledger_is_not_required(monkeypatch) -> None:
    ledger = SimpleNamespace(
        operational_snapshot=lambda: {
            "required": False,
            # Even a permissive or older ledger implementation must not be
            # projected as production-ready when durable accounting is optional.
            "ready": True,
            "status": "best_effort",
            "capacity_status": "ok",
        }
    )
    with TestClient(appmod.app) as client:
        monkeypatch.setattr(client.app.state, "provider_call_ledger", ledger)
        response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["readiness"] == "degraded"
    assert body["checks"]["financial_ledger"]["required"] is False
    assert body["checks"]["financial_ledger"]["ready"] is False
    assert body["checks"]["financial_ledger"]["status"] == "best_effort"


def test_legacy_channel_replay_drops_untrusted_nested_private_material() -> None:
    secret = "legacy-nested-private-receipt"
    projected = appmod._project_durable_channel_replay(
        {
            "reply": "legacy reply remains usable",
            "model": "unattested-model",
            "outcome": "partial",
            "usage": {
                "prompt_tokens": 1,
                "private_receipt": {"hmac": secret},
            },
            "images": [{"url": "https://private.invalid/image", "receipt": secret}],
            "trace_id": secret,
        }
    )

    assert projected["reply"] == "legacy reply remains usable"
    assert projected["model"] == "nachuan-engine"
    assert projected["channel_result_version"] == 2
    assert projected["attribution_state"] == "local_engine"
    assert secret not in json.dumps(projected, ensure_ascii=False)
    assert projected.get("usage") == {}
    assert "images" not in projected
    assert "trace_id" not in projected


@pytest.mark.asyncio
async def test_usage_logging_is_best_effort_and_does_not_block_the_event_loop() -> None:
    loop = asyncio.get_running_loop()
    loop_thread = threading.get_ident()
    started = asyncio.Event()
    release = threading.Event()
    logger_threads: list[int] = []

    class SlowLogger:
        def log(self, **_kwargs) -> None:
            logger_threads.append(threading.get_ident())
            loop.call_soon_threadsafe(started.set)
            release.wait(timeout=2)

    timer = threading.Timer(2, release.set)
    timer.start()
    task = asyncio.create_task(
        appmod._log_usage_best_effort(SlowLogger(), status="ok")
    )
    try:
        await asyncio.wait_for(started.wait(), timeout=2)
        marker = asyncio.Event()
        loop.call_soon(marker.set)
        await asyncio.wait_for(marker.wait(), timeout=1)
        assert task.done() is False
        assert logger_threads == [logger_threads[0]]
        assert logger_threads[0] != loop_thread
        release.set()
        assert await task is True
    finally:
        release.set()
        timer.cancel()

    class BrokenLogger:
        def log(self, **_kwargs) -> None:
            raise RuntimeError("usage database unavailable")

    assert await appmod._log_usage_best_effort(BrokenLogger(), status="ok") is False


@pytest.mark.asyncio
async def test_usage_logging_cancellation_is_never_replaced_by_cleanup_name_errors() -> None:
    started = threading.Event()
    release = threading.Event()

    class SlowLogger:
        def log(self, **_kwargs) -> None:
            started.set()
            release.wait(timeout=1)

    task = asyncio.create_task(
        appmod._log_usage_best_effort(SlowLogger(), status="cancelled")
    )
    while not started.is_set():
        await asyncio.sleep(0.005)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


class _EndpointRouter:
    def __init__(self, route) -> None:
        self.route = route

    def resolve(self, model: str):  # noqa: ANN201
        return self.route if model in {"model-a", "agnes-flash"} else None

    async def aclose(self) -> None:
        return None


class _SchedulableEndpointRouter(_EndpointRouter):
    def __init__(self, route, *, routes: list[dict[str, object]]) -> None:
        super().__init__(route)
        self._route_rows = routes

    def routes_info(self) -> list[dict[str, object]]:
        return list(self._route_rows)


def test_bridge_health_fails_closed_without_verified_chat_route() -> None:
    with TestClient(appmod.app) as client:
        client.app.state.router = _SchedulableEndpointRouter(None, routes=[])
        response = client.get("/v1/bridge/health", headers=AUTH)

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "channel": "runtime",
        "chat_ready": False,
        "reason": "ready_no_model",
    }


def test_bridge_health_fails_closed_for_unavailable_explicit_model() -> None:
    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
    )
    router = _SchedulableEndpointRouter(
        route,
        routes=[{"model": "model-a", "tier": "cheap", "modality": "chat"}],
    )
    with TestClient(appmod.app) as client:
        client.app.state.router = router
        response = client.get(
            "/v1/bridge/health?model=retired-model",
            headers=AUTH,
        )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "channel": "runtime",
        "chat_ready": False,
        "reason": "requested_model_unavailable",
    }


def test_bridge_health_reports_chat_ready_without_route_secrets() -> None:
    private_url = "https://private-provider.invalid/v1"
    private_key = "provider-secret-must-not-leak"
    route = SimpleNamespace(
        provider=SimpleNamespace(
            name="provider-a",
            base_url=private_url,
            api_key=private_key,
        ),
        upstream_model="upstream-secret-name",
        tier="cheap",
        modality="chat",
    )
    router = _SchedulableEndpointRouter(
        route,
        routes=[{"model": "model-a", "tier": "cheap", "modality": "chat"}],
    )
    with TestClient(appmod.app) as client:
        client.app.state.router = router
        client.app.state.provider_call_ledger = SimpleNamespace(
            operational_snapshot=lambda: {
                "required": True,
                "ready": True,
                "status": "ready",
                "capacity_status": "ok",
            }
        )
        response = client.get("/v1/bridge/health", headers=AUTH)

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "channel": "runtime",
        "chat_ready": True,
        "reason": "ready",
    }
    assert private_url not in response.text
    assert private_key not in response.text
    assert "upstream-secret-name" not in response.text


def test_bridge_health_fails_closed_when_financial_ledger_is_not_required() -> None:
    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
    )
    router = _SchedulableEndpointRouter(
        route,
        routes=[{"model": "model-a", "tier": "cheap", "modality": "chat"}],
    )
    with TestClient(appmod.app) as client:
        client.app.state.router = router
        client.app.state.provider_call_ledger = SimpleNamespace(
            operational_snapshot=lambda: {
                "required": False,
                "ready": True,
                "status": "best_effort",
                "capacity_status": "ok",
            }
        )
        response = client.get("/v1/bridge/health", headers=AUTH)

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "channel": "runtime",
        "chat_ready": False,
        "reason": "provider_call_ledger_not_ready",
    }


def _broken_usage_log(loop_thread: dict[str, int], log_thread: dict[str, int]):
    def boom(**_kwargs) -> None:
        log_thread["id"] = threading.get_ident()
        raise RuntimeError("usage database unavailable")

    def assert_off_loop() -> None:
        assert loop_thread["id"] != log_thread["id"]

    return boom, assert_off_loop


def test_agent_usage_failure_cannot_replace_success(monkeypatch) -> None:
    loop_thread: dict[str, int] = {}
    log_thread: dict[str, int] = {}
    boom, assert_off_loop = _broken_usage_log(loop_thread, log_thread)

    async def fake_agent_chat(*_args, **_kwargs):
        loop_thread["id"] = threading.get_ident()
        return {
            "reply": "ok",
            "model": "model-a",
            "turns": 1,
            "usage": {},
            "outcome": "blocked",
            "blocked": True,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
        }

    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
        exec_backend="",
    )
    monkeypatch.setattr(appmod, "agent_chat", fake_agent_chat)
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        monkeypatch.setattr(client.app.state.usage, "log", boom)
        response = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={"message": "hello", "channel": "api", "model": "model-a"},
        )
    assert response.status_code == 200
    assert response.json()["reply"] == "ok"
    assert_off_loop()


def test_agent_chat_without_model_selects_a_verified_chat_route(monkeypatch) -> None:
    selected: dict[str, str] = {}

    async def fake_agent_chat(*_args, **kwargs):
        selected["model"] = str(kwargs["model"])
        return {
            "reply": "ok",
            "model": str(kwargs["model"]),
            "turns": 1,
            "usage": {},
            "outcome": "completed_unverified",
            "blocked": False,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
        }

    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
    )
    router = _SchedulableEndpointRouter(
        route,
        routes=[
            {
                "model": "model-a",
                "tier": "cheap",
                "modality": "chat",
                "rank": 1,
                "flagship": False,
            }
        ],
    )
    monkeypatch.setenv("BRIDGE_MODEL", "")
    get_settings.cache_clear()
    monkeypatch.setattr(appmod, "agent_chat", fake_agent_chat)
    try:
        with TestClient(appmod.app) as client:
            client.app.state.router = router
            response = client.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={"message": "hello", "channel": "api"},
            )
        assert response.status_code == 200
        assert selected == {"model": "model-a"}
    finally:
        get_settings.cache_clear()


def test_agent_chat_without_any_verified_chat_route_is_ready_no_model(
    monkeypatch,
) -> None:
    async def must_not_call_model(*_args, **_kwargs):
        raise AssertionError("an unconfigured gateway called a model")

    router = _SchedulableEndpointRouter(None, routes=[])
    monkeypatch.setenv("BRIDGE_MODEL", "")
    get_settings.cache_clear()
    monkeypatch.setattr(appmod, "agent_chat", must_not_call_model)
    try:
        with TestClient(appmod.app, raise_server_exceptions=False) as client:
            client.app.state.router = router
            response = client.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={"message": "hello", "channel": "api"},
            )
        assert response.status_code == 503
        assert response.json()["detail"] == {
            "code": "ready_no_model",
            "retryable": False,
        }
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize(
    "idempotency_key",
    ["api-must-not-be-durable", None],
    ids=["string", "null"],
)
def test_agent_chat_rejects_api_idempotency_key_before_model_readiness(
    monkeypatch,
    idempotency_key: object,
) -> None:
    async def must_not_call_model(*_args, **_kwargs):
        raise AssertionError("an invalid API envelope called a model")

    monkeypatch.setattr(appmod, "agent_chat", must_not_call_model)
    with TestClient(appmod.app, raise_server_exceptions=False) as client:
        client.app.state.router = _SchedulableEndpointRouter(None, routes=[])
        response = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={
                "message": "hello",
                "channel": "api",
                "idempotency_key": idempotency_key,
            },
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "idempotency_key 仅允许用于持久消息渠道"
    }


class _StructureValidationSentinel:
    def resolve(self, _model: str):  # noqa: ANN201
        raise AssertionError("invalid structure reached model resolution")

    def routes_info(self):  # noqa: ANN201
        raise AssertionError("invalid structure reached model discovery")

    def claim(self, *_args, **_kwargs):  # noqa: ANN201
        raise AssertionError("invalid structure reached idempotency storage")


def _post_structurally_invalid_agent_chat(payload: object):
    sentinel = _StructureValidationSentinel()
    with TestClient(appmod.app, raise_server_exceptions=False) as client:
        original_router = client.app.state.router
        original_idempotency = client.app.state.weixin_idempotency
        client.app.state.router = sentinel
        client.app.state.weixin_idempotency = sentinel
        try:
            return client.post("/v1/agent/chat", headers=AUTH, json=payload)
        finally:
            client.app.state.router = original_router
            client.app.state.weixin_idempotency = original_idempotency


def test_agent_chat_rejects_unknown_fields_before_model_readiness() -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": "hello", "channel": "api", "unexpected": True}
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "agent chat 请求包含未知字段"}


@pytest.mark.parametrize(
    "channel",
    [None, 7, False, "", "API", " api", "telegram"],
)
def test_agent_chat_rejects_invalid_channel_before_model_readiness(
    channel: object,
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": "hello", "channel": channel}
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "message",
    [None, 7, " \t\r\n", "你" * ((2 * 1024 * 1024) // 3 + 1)],
    ids=["none", "integer", "whitespace", "utf8-oversize"],
)
def test_agent_chat_rejects_invalid_message_before_model_readiness(
    message: object,
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": message, "channel": "api"}
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "identity_fields",
    [
        {"chat_id": 7},
        {"user_id": None},
        {"chat_id": "bad\nchat"},
        {"user_id": "用" * 171},
    ],
    ids=["chat-type", "user-type", "chat-control", "user-utf8-oversize"],
)
def test_agent_chat_rejects_invalid_identity_before_model_readiness(
    identity_fields: dict[str, object],
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": "hello", "channel": "api", **identity_fields}
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "optional_fields",
    [
        {"model": 7},
        {"model": "模" * 171},
        {"system": 7},
        {"system": "规" * ((32 * 1024) // 3 + 1)},
    ],
    ids=["model-type", "model-utf8-oversize", "system-type", "system-utf8-oversize"],
)
def test_agent_chat_rejects_invalid_model_or_system_before_model_readiness(
    optional_fields: dict[str, object],
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": "hello", "channel": "api", **optional_fields}
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "boolean_fields",
    [
        {"video_async": "false"},
        {"video_async": 0},
        {"video_async": None},
        {"video_async_capacity_available": "false"},
        {"video_async_capacity_available": 1},
        {"video_async_capacity_available": None},
    ],
)
def test_agent_chat_rejects_non_boolean_flags_before_model_readiness(
    boolean_fields: dict[str, object],
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {"message": "hello", "channel": "api", **boolean_fields}
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("channel", "idempotency_key"),
    [
        ("weixin", "fsmsg-v1:" + "a" * 64),
        ("feishu", "wxmsg-v1:" + "b" * 64),
    ],
)
def test_agent_chat_rejects_cross_domain_durable_key_before_side_effects(
    channel: str,
    idempotency_key: str,
) -> None:
    response = _post_structurally_invalid_agent_chat(
        {
            "message": "hello",
            "channel": channel,
            "chat_id": "chat-1",
            "user_id": "user-1",
            "idempotency_key": idempotency_key,
        }
    )

    assert response.status_code == 422
    assert response.json() == {"detail": f"{channel} idempotency_key 格式无效"}


def test_image_usage_failure_cannot_replace_success(
    monkeypatch, paid_media_auth_headers
) -> None:
    loop_thread: dict[str, int] = {}
    log_thread: dict[str, int] = {}
    boom, assert_off_loop = _broken_usage_log(loop_thread, log_thread)

    class Provider:
        name = "image-provider"
        paid_media_asset_protocol_versions = frozenset({"2"})

        async def generate_image_asset_urls(self, _request, _model):
            loop_thread["id"] = threading.get_ident()
            return {"data": [{"url": "https://example.invalid/image.png"}]}

    route = SimpleNamespace(
        provider=Provider(), upstream_model="image-upstream", tier="premium"
    )
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        asset_store = client.app.state.paid_media_assets
        payload = b"verified-test-image"

        def local_stage_url(*, turn_id: str, ordinal: int, url: str):
            assert url == "https://example.invalid/image.png"
            return asset_store.stage_base64_chunks(
                turn_id=turn_id,
                ordinal=ordinal,
                media_type="image/png",
                chunks=(base64.b64encode(payload).decode("ascii"),),
                probe=_verified_test_image_probe,
            )

        monkeypatch.setattr(asset_store, "stage_url", local_stage_url)
        monkeypatch.setattr(client.app.state.usage, "log", boom)
        response = client.post(
            "/v1/images/generations",
            headers={
                **paid_media_auth_headers,
                "Idempotency-Key": f"usage-image-{uuid4()}",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
            json={"model": "model-a", "prompt": "draw"},
        )
    assert response.status_code == 200
    assert response.json()["schema"].endswith("result.v2")
    assert response.json()["kind"] == "image"
    assert len(response.json()["assets"]) == 1
    assert_off_loop()


def test_mode_usage_failure_cannot_replace_success(monkeypatch) -> None:
    loop_thread: dict[str, int] = {}
    log_thread: dict[str, int] = {}
    boom, assert_off_loop = _broken_usage_log(loop_thread, log_thread)

    async def fake_mode(_router, _messages):
        loop_thread["id"] = threading.get_ident()
        return {
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {},
            "_route": {"model": "model-a"},
        }

    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
    )
    monkeypatch.setitem(appmod.SINGLE_ANSWER_MODES, "smart", fake_mode)
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        monkeypatch.setattr(client.app.state.usage, "log", boom)
        response = client.post(
            "/v1/route",
            headers=AUTH,
            json={
                "mode": "smart",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["choices"]
    assert_off_loop()


def test_fleet_usage_failure_is_off_loop_and_cannot_replace_success(monkeypatch) -> None:
    loop_thread: dict[str, int] = {}
    log_thread: dict[str, int] = {}
    boom, assert_off_loop = _broken_usage_log(loop_thread, log_thread)

    async def fake_fleet(_router, _task, **_kwargs):
        loop_thread["id"] = threading.get_ident()
        return {
            "reply": "fleet ok",
            "model": "model-a",
            "usage": {},
            "media": [],
            "mode": "trinity",
            "verified": True,
        }

    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
    )
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_fleet)
    monkeypatch.setattr(appmod, "_grow_memory", lambda *_args: None)
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        monkeypatch.setattr(client.app.state.usage, "log", boom)
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "nachuan",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "fleet ok"
    assert_off_loop()


def test_direct_chat_usage_failure_cannot_replace_success(monkeypatch) -> None:
    loop_thread: dict[str, int] = {}
    log_thread: dict[str, int] = {}
    boom, assert_off_loop = _broken_usage_log(loop_thread, log_thread)
    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
    )

    async def fake_chat(_router, _request):
        loop_thread["id"] = threading.get_ident()
        return (
            {
                "choices": [
                    {"message": {"role": "assistant", "content": "chat ok"}}
                ],
                "usage": {},
            },
            "model-a",
            route,
        )

    monkeypatch.setattr(appmod, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(appmod, "_grow_memory", lambda *_args: None)
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        monkeypatch.setattr(client.app.state.usage, "log", boom)
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "model-a",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "chat ok"
    assert_off_loop()


def test_direct_stream_usage_uses_invocation_receipt_after_hot_reload(monkeypatch) -> None:
    usage_rows: list[dict] = []
    reloaded_route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-after-reload"),
        upstream_model="upstream-after-reload",
        tier="cheap",
    )

    class HotReloadedRouter:
        def __init__(self) -> None:
            self.resolve_calls: list[str] = []

        def resolve(self, model: str):  # noqa: ANN201
            self.resolve_calls.append(model)
            return reloaded_route

        async def aclose(self) -> None:
            return None

    async def fake_stream(_router, request):  # noqa: ANN001
        yield {
            "choices": [
                {"index": 0, "delta": {"content": "stream ok"}, "finish_reason": None}
            ],
            "usage": {"total_tokens": 7},
            "_served_by": {
                "route_receipt_version": 1,
                "requested": request.model,
                "actual": "model-before-reload",
                "provider": "provider-before-reload",
                "upstream_model": "upstream-before-reload",
                "tier": "premium",
            },
        }

    router = HotReloadedRouter()
    monkeypatch.setattr(appmod, "stream_with_fallback", fake_stream)
    monkeypatch.setattr(appmod, "_grow_memory", lambda *_args: None)
    with TestClient(appmod.app) as client:
        client.app.state.router = router
        monkeypatch.setattr(
            client.app.state.usage, "log", lambda **values: usage_rows.append(values)
        )
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "model-a",
                "stream": True,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    assert "stream ok" in response.text
    assert router.resolve_calls == []
    row = [item for item in usage_rows if item["stream"] == 1][-1]
    assert row["virtual_model"] == "model-before-reload"
    assert row["provider"] == "provider-before-reload"
    assert row["upstream_model"] == "upstream-before-reload"
    assert row["tier"] == "premium"
    assert row["total_tokens"] == 7


def test_direct_stream_unserved_usage_never_guesses_from_router(monkeypatch) -> None:
    usage_rows: list[dict] = []

    class PoisonRouter:
        def __init__(self) -> None:
            self.resolve_calls: list[str] = []

        def resolve(self, model: str):  # noqa: ANN201
            self.resolve_calls.append(model)
            return SimpleNamespace(
                provider=SimpleNamespace(name="must-not-be-used"),
                upstream_model="must-not-be-used",
                tier="must-not-be-used",
            )

        async def aclose(self) -> None:
            return None

    async def fake_stream(_router, _request):  # noqa: ANN001
        yield {
            "error": {
                "message": "all routes failed",
                "type": "provider_error",
                "status_code": 502,
            }
        }

    router = PoisonRouter()
    monkeypatch.setattr(appmod, "stream_with_fallback", fake_stream)
    monkeypatch.setattr(appmod, "_grow_memory", lambda *_args: None)
    with TestClient(appmod.app) as client:
        client.app.state.router = router
        monkeypatch.setattr(
            client.app.state.usage, "log", lambda **values: usage_rows.append(values)
        )
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "model-a",
                "stream": True,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    assert "all routes failed" in response.text
    assert router.resolve_calls == []
    row = [item for item in usage_rows if item["stream"] == 1][-1]
    assert row["virtual_model"] == "model-a"
    assert row["provider"] == "direct-unserved"
    assert row["upstream_model"] == ""
    assert row["tier"] == "unserved"
    assert row["status"] == "error"


@pytest.mark.asyncio
async def test_grow_memory_task_has_strong_reference_until_completion(monkeypatch) -> None:
    release = asyncio.Event()
    started = asyncio.Event()

    async def fake_extract(*_args, **_kwargs):
        started.set()
        await release.wait()

    class Router:
        def resolve(self, model: str):  # noqa: ANN201
            return object() if model == "agnes-flash" else None

    monkeypatch.setattr(appmod, "extract_and_store", fake_extract)
    appmod.app.state.background_tasks = set()
    task = appmod._grow_memory(Router(), "user", "assistant")
    await asyncio.wait_for(started.wait(), timeout=0.5)
    assert task is not None
    assert task in appmod.app.state.background_tasks
    release.set()
    await task
    await asyncio.sleep(0)
    assert task not in appmod.app.state.background_tasks


def test_short_lease_bounds_sqlite_wait_and_heartbeat_interval(tmp_path) -> None:
    store = WeixinIdempotencyStore(
        tmp_path / "idempotency.db",
        lease_seconds=10,
        busy_timeout_ms=30_000,
    )
    interval = appmod._durable_heartbeat_interval(store)
    assert interval == pytest.approx(3.0)
    assert store.busy_timeout_ms <= store.lease_seconds * 250
    assert interval + (store.busy_timeout_ms / 1000) < store.lease_seconds


def test_heartbeat_stop_failure_preserves_business_root_cause(monkeypatch) -> None:
    async def business_failure(*_args, **_kwargs):
        raise HTTPException(status_code=502, detail="provider root cause")

    async def stop_failure(*_args, **_kwargs):
        raise appmod._DurableTurnLeaseLost(
            reason="heartbeat_stop_timeout", storage_unavailable=True
        )

    monkeypatch.setattr(appmod, "agent_chat", business_failure)
    monkeypatch.setattr(appmod, "_stop_durable_heartbeat", stop_failure)
    response_key = "wxmsg-v1:" + ("c" * 64)
    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
    )
    with TestClient(appmod.app) as client:
        client.app.state.router = _EndpointRouter(route)
        response = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={
                "message": "business failure",
                "channel": "weixin",
                "chat_id": "root-cause-chat",
                "user_id": "root-cause-user",
                "model": "model-a",
                "idempotency_key": response_key,
            },
        )
    assert response.status_code == 502
    assert response.json()["detail"] == "provider root cause"
