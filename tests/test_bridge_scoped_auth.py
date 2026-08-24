from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.bridge_protocol import open_response, seal_request
from gateway.config import get_settings


def _sealed_call(
    client: TestClient,
    *,
    key: str,
    channel: str,
    method: str,
    path: str,
    document: object | None = None,
    body: bytes | None = None,
) -> tuple[int, object]:
    plaintext = (
        body
        if body is not None
        else json.dumps(document, separators=(",", ":")).encode("utf-8")
    )
    sealed = seal_request(
        secret=key,
        channel=channel,
        method=method,
        url_or_target=path,
        body=plaintext,
    )
    headers = dict(sealed.headers)
    if document is not None:
        headers["Content-Type"] = "application/json"
    response = client.request(method, path, headers=headers, content=sealed.body)
    opened = open_response(
        secret=key,
        channel=channel,
        request_nonce=sealed.request_nonce,
        status=response.status_code,
        headers=response.headers,
        body=response.content,
    )
    return response.status_code, json.loads(opened.decode("utf-8"))


def test_channel_bridge_keys_are_endpoint_scoped_and_channel_bound(monkeypatch):
    weixin_key = "sk-bridge-v2-weixin-" + "1" * 64
    feishu_key = "sk-bridge-v2-feishu-" + "2" * 64
    monkeypatch.setenv("NACHUAN_WEIXIN_BRIDGE_API_KEY", weixin_key)
    monkeypatch.setenv("NACHUAN_FEISHU_BRIDGE_API_KEY", feishu_key)
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            wx = {"Authorization": f"Bearer {weixin_key}"}
            fs = {"Authorization": f"Bearer {feishu_key}"}

            # A bridge capability is not a general gateway/runtime credential.
            assert client.get("/v1/models", headers=wx).status_code == 401
            assert client.get("/v1/bridge/health", headers=wx).status_code == 401
            assert client.get("/v1/bridge/health", headers=fs).status_code == 401
            runtime_health = client.get(
                "/v1/bridge/health",
                headers={"Authorization": "Bearer test-key"},
            ).json()
            assert set(runtime_health) == {
                "status",
                "channel",
                "chat_ready",
                "reason",
            }
            assert runtime_health["status"] == "ok"
            assert runtime_health["channel"] == "runtime"
            assert type(runtime_health["chat_ready"]) is bool
            if runtime_health["chat_ready"]:
                assert runtime_health["reason"] == "ready"
            else:
                assert runtime_health["reason"] in {
                    "ready_no_model",
                    "provider_call_ledger_not_ready",
                }

            old = seal_request(
                secret="sk-bridge-weixin-" + "9" * 64,
                channel="weixin",
                method="GET",
                url_or_target="/v1/bridge/health",
                body=b"",
            )
            assert client.request(
                "GET",
                "/v1/bridge/health",
                headers=old.headers,
                content=old.body,
            ).status_code == 401

            wrong_channel_key = seal_request(
                secret=weixin_key,
                channel="feishu",
                method="GET",
                url_or_target="/v1/bridge/health",
                body=b"",
            )
            assert client.request(
                "GET",
                "/v1/bridge/health",
                headers=wrong_channel_key.headers,
                content=wrong_channel_key.body,
            ).status_code == 401

            health_status, weixin_health = _sealed_call(
                client,
                key=weixin_key,
                channel="weixin",
                method="GET",
                path="/v1/bridge/health",
                body=b"",
            )
            assert health_status == 200
            assert isinstance(weixin_health, dict)
            assert set(weixin_health) == {
                "status",
                "channel",
                "chat_ready",
                "reason",
            }
            assert weixin_health["status"] == "ok"
            assert weixin_health["channel"] == "weixin"
            assert type(weixin_health["chat_ready"]) is bool
            if weixin_health["chat_ready"]:
                assert weixin_health["reason"] == "ready"
            else:
                assert weixin_health["reason"] in {
                    "ready_no_model",
                    "provider_call_ledger_not_ready",
                }

            # It is accepted by an explicitly bridge-scoped media endpoint.
            assert _sealed_call(
                client,
                key=weixin_key,
                channel="weixin",
                method="POST",
                path="/v1/vision",
                body=b"",
            )[0] == 422

            # A channel capability cannot forge another channel's durable Turn.
            mismatched = _sealed_call(
                client,
                key=weixin_key,
                channel="weixin",
                method="POST",
                path="/v1/agent/chat",
                document={
                    "message": "hello",
                    "user_id": "user-1",
                    "chat_id": "chat-1",
                    "channel": "feishu",
                    "model": "echo",
                    "idempotency_key": "fsmsg-v1:" + "a" * 64,
                },
            )
            assert mismatched[0] == 403

            # Channel normalization must not become a durable-Turn bypass.
            mixed_case = _sealed_call(
                client,
                key=weixin_key,
                channel="weixin",
                method="POST",
                path="/v1/agent/chat",
                document={
                    "message": "hello",
                    "user_id": "user-1",
                    "chat_id": "chat-1",
                    "channel": "WeIxIn",
                    "model": "echo",
                },
            )
            assert mixed_case[0] == 422
            assert _sealed_call(
                client,
                key=feishu_key,
                channel="feishu",
                method="POST",
                path="/v1/agent/feedback",
                document={
                    "user_id": "user-1",
                    "chat_id": "chat-1",
                    "channel": "weixin",
                    "rating": "up",
                },
            )[0] == 403
            assert _sealed_call(
                client,
                key=feishu_key,
                channel="feishu",
                method="POST",
                path="/v1/agent/feedback",
                document=[],
            )[0] == 422
    finally:
        get_settings.cache_clear()


def test_gateway_refuses_pre_v2_bridge_keys_at_startup(monkeypatch):
    monkeypatch.setenv(
        "NACHUAN_WEIXIN_BRIDGE_API_KEY",
        "sk-bridge-weixin-" + "1" * 64,
    )
    monkeypatch.setenv(
        "NACHUAN_FEISHU_BRIDGE_API_KEY",
        "sk-bridge-feishu-" + "2" * 64,
    )
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="weixin bridge key format is invalid"):
            with TestClient(app):
                pass
    finally:
        get_settings.cache_clear()
