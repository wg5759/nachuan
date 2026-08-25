"""管理 API 测试：目录 / 保存连接 / 路由生效 / 掩码 / 删除（不触发真实网络）。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway import admin, connections, local_model
from gateway.app import app
from gateway.auth import require_api_key, require_approval_admin_key
from gateway.connections import ConnectionStore
from gateway.providers.base import ProviderError
from gateway.providers.kimi_subscription import KimiSubscriptionProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.router import Router


@pytest.fixture(autouse=True)
def _adapt_admin_provider_doubles_to_the_bounded_probe(monkeypatch):
    """Admin unit doubles implement post(); transport bounds have dedicated tests."""

    async def probe_chat(self, req, upstream_model):
        response = await self._client.post(
            self._endpoint,
            headers=self._headers,
            json=req.to_upstream_payload(upstream_model, stream=False),
        )
        if response.status_code >= 400:
            raise RuntimeError("synthetic provider probe failed")
        return response.json()

    monkeypatch.setattr(OpenAICompatProvider, "probe_chat", probe_chat)

AUTH = {"Authorization": "Bearer test-key"}


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderError("private", status_code=401), "invalid_credentials"),
        (ProviderError("private", status_code=403), "invalid_credentials"),
        (ProviderError("private", status_code=429), "quota_or_rate_limited"),
        (
            ProviderError("private", status_code=404),
            "model_or_endpoint_not_found",
        ),
        (ProviderError("private", status_code=400), "invalid_request"),
        (ProviderError("private", status_code=503), "upstream_unavailable"),
        (ProviderError("private", status_code=504), "network_or_timeout"),
        (asyncio.TimeoutError(), "network_or_timeout"),
    ],
)
def test_connection_failure_reason_is_closed_and_actionable(
    error: BaseException,
    expected: str,
) -> None:
    assert admin._connection_failure_reason("provider", error) == expected
    response = admin._connection_validation_failure("provider", expected)
    assert response["reason_code"] == expected
    assert "private" not in json.dumps(response)


def test_unknown_connection_failure_does_not_echo_private_details() -> None:
    assert admin._connection_failure_reason(
        "provider", RuntimeError("PRIVATE_REMOTE_FAILURE_DETAIL")
    ) is None
    response = admin._connection_validation_failure("provider")
    assert "reason_code" not in response
    assert "PRIVATE" not in json.dumps(response)


def test_subscription_cli_connection_probe_uses_its_declared_bounded_deadline():
    class SubscriptionCliProvider:
        connection_probe_timeout_s = 180.0

    class OrdinaryProvider:
        pass

    assert admin._connection_probe_deadlines(SubscriptionCliProvider()) == (
        180.0,
        195.0,
    )
    assert admin._connection_probe_deadlines(OrdinaryProvider()) == (
        admin._CONNECTION_TEST_ATTEMPT_TIMEOUT_SEC,
        admin._CONNECTION_TEST_TOTAL_TIMEOUT_SEC,
    )
    for invalid in (0, -1, float("inf"), 301, "180"):
        provider = SubscriptionCliProvider()
        provider.connection_probe_timeout_s = invalid
        assert admin._connection_probe_deadlines(provider) == (
            admin._CONNECTION_TEST_ATTEMPT_TIMEOUT_SEC,
            admin._CONNECTION_TEST_TOTAL_TIMEOUT_SEC,
        )


@pytest.mark.parametrize(
    ("probe_error", "cleanup_fails", "expected_reason"),
    [
        (
            KimiSubscriptionProviderError(reason_code="reauth_required"),
            False,
            "reauth_required",
        ),
        (
            KimiSubscriptionProviderError(reason_code="text_contract_rejected"),
            False,
            "text_contract_rejected",
        ),
        (
            RuntimeError("PRIVATE_REMOTE_FAILURE_DETAIL"),
            False,
            "connector_unavailable",
        ),
        (
            KimiSubscriptionProviderError(reason_code="reauth_required"),
            True,
            "connector_unavailable",
        ),
    ],
)
def test_kimi_connect_failure_returns_only_a_closed_reason_code(
    monkeypatch,
    probe_error: Exception,
    cleanup_fails: bool,
    expected_reason: str,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")

    class _Provider:
        connection_probe_timeout_s = 180.0

        async def probe_chat(self, _req, _upstream_model):
            raise probe_error

        async def aclose(self):
            if cleanup_fails:
                raise RuntimeError("PRIVATE_CLEANUP_FAILURE_DETAIL")

    class _Route:
        virtual_model = "kimi-code-subscription"
        upstream_model = "kimi-code-subscription"
        provider = _Provider()

    class _Router:
        @staticmethod
        def assign_available_model_ids(_provider, conn):
            return conn

        @staticmethod
        def build_transient_routes(_provider, _conn):
            return [_Route()]

    async def call_probe(provider, req, upstream_model, **_kwargs):
        return await provider.probe_chat(req, upstream_model)

    monkeypatch.setattr(admin, "chat_once_with_deadline", call_probe)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = object()
    test_app.state.router = _Router()

    with TestClient(test_app) as client:
        response = client.post(
            "/admin/connections/kimi-code",
            json={
                "type": "kimi_code",
                "api_key": "",
                "base_url": "",
                "enabled_models": [
                    {
                        "id": "kimi-code-subscription",
                        "upstream_model": "kimi-code-subscription",
                        "tier": "premium",
                        "description": "contained text subscription",
                        "modality": "chat",
                        "rank": 0,
                        "flagship": False,
                        "tool_capable": False,
                        "skills": ["code", "reasoning"],
                    }
                ],
                "preserve_existing_credential": False,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error": "连接验证失败，请检查凭据、模型与服务状态",
        "reason_code": expected_reason,
    }
    assert "PRIVATE_" not in response.text


def test_catalog_lists_volcano_without_disabled_claude_providers():
    with TestClient(app) as c:
        r = c.get("/admin/catalog", headers=AUTH)
        assert r.status_code == 200
        providers = {p["name"]: p for p in r.json()["providers"]}
        assert "volcano" in providers
        assert providers["volcano"]["auth"] == "api_key"
        assert providers["volcano"]["type"] == "volcano"
        # 本月停用的 Claude/Anthropic 不得再作为连接卡片出现。
        assert "claude_code" not in providers
        assert "anthropic" not in providers
        assert providers["codex"]["connectable"] is True
        assert providers["codex"]["auth"] == "login"
        assert [model["id"] for model in providers["codex"]["models"]] == [
            "codex-subscription"
        ]
        for local_name in ("ollama", "lmstudio", "llamacpp", "jan", "vllm"):
            assert providers[local_name]["region"] == "local"
            assert providers[local_name]["auth"] == "none"
            assert providers[local_name]["connectable"] is True
        assert providers["moonshot_intl"]["default_base_url"] == (
            "https://api.moonshot.ai/v1"
        )
        assert providers["moonshot_intl"]["auto_discover_models"] is True
        assert providers["qwen_intl"]["default_base_url"] == (
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        )
        assert providers["qwen_us"]["default_base_url"] == (
            "https://dashscope-us.aliyuncs.com/compatible-mode/v1"
        )
        assert providers["zai_intl"]["default_base_url"] == (
            "https://api.z.ai/api/paas/v4"
        )


def test_catalog_requires_auth():
    with TestClient(app) as c:
        assert c.get("/admin/catalog").status_code == 401


def test_save_route_mask_and_delete(approval_auth_headers, monkeypatch):
    provider_calls: list[dict] = []

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "up-1",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, url, *, headers, json):
            provider_calls.append({"url": url, "headers": dict(headers), "json": dict(json)})
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    with TestClient(app) as c:
        # Connect 是一个事务：先用候选配置做一次有界验证，再持久化并上路由。
        r = c.post(
            "/admin/connections/myprov",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "secret-key-123456",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [
                    {"id": "m1", "upstream_model": "up-1", "tier": "cheap", "description": "x"}
                ],
            },
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert "m1" in r.json()["models"]
        assert len(provider_calls) == 1
        assert provider_calls[0]["url"] == "https://api.openai.com/v1/chat/completions"
        assert provider_calls[0]["headers"]["Authorization"] == "Bearer secret-key-123456"
        assert provider_calls[0]["json"]["model"] == "up-1"
        assert provider_calls[0]["json"]["max_tokens"] == 1

        # 模型应已可路由
        models = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
        assert "m1" in models

        # 掩码视图不含明文 key
        conns = c.get("/admin/connections", headers=AUTH).json()
        assert "myprov" in conns
        assert "api_key" not in conns["myprov"]
        assert "api_key_masked" not in conns["myprov"]
        assert conns["myprov"]["credential_present"] is True
        assert conns["myprov"]["state"] == "verified"
        assert conns["myprov"]["verified_at"].endswith("Z")
        assert "verification" not in conns["myprov"]

        # 删除后模型消失
        assert c.delete(
            "/admin/connections/myprov", headers=approval_auth_headers
        ).status_code == 200
        models2 = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
        assert "m1" not in models2


def test_runtime_key_alone_cannot_change_connections(approval_auth_headers):
    with TestClient(app) as c:
        denied = c.post(
            "/admin/connections/blocked",
            headers=AUTH,
            json={
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [],
            },
        )
        assert denied.status_code == 401
        assert c.delete("/admin/connections/blocked", headers=AUTH).status_code == 401
        assert (
            c.post("/admin/connections/blocked/test", headers=AUTH).status_code == 401
        )


@pytest.mark.parametrize(
    ("provider", "body"),
    [
        (
            "anthropic",
            {
                "type": "anthropic",
                "api_key": "secret",
                "base_url": "https://api.anthropic.com",
                "enabled_models": [{"id": "claude-api-model"}],
            },
        ),
    ],
)
def test_connect_rejects_unavailable_protocols(
    approval_auth_headers, provider, body
):
    with TestClient(app) as c:
        response = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json=body,
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "连接配置不符合接入策略"}
        assert provider not in c.get("/admin/connections", headers=AUTH).json()


def test_connect_rejects_reserved_virtual_model_ids_before_any_probe(
    approval_auth_headers, monkeypatch
):
    probed = False

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, *args, **kwargs):
            nonlocal probed
            del args, kwargs
            probed = True
            raise AssertionError("reserved model id reached the provider")

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    with TestClient(app) as c:
        response = c.post(
            "/admin/connections/reserved-model-provider",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "echo", "upstream_model": "gpt-4o"}],
            },
        )
    assert response.status_code == 422
    assert probed is False


def test_connect_probes_every_model_and_promotes_only_successes(
    approval_auth_headers, monkeypatch
):
    probed: list[str] = []

    class _ProviderResponse:
        text = ""

        def __init__(self, model: str):
            self.model = model
            self.status_code = 404 if model == "broken-upstream" else 200

        def json(self) -> dict:
            return {
                "id": "connect-check",
                "model": self.model,
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers
            probed.append(json["model"])
            return _ProviderResponse(json["model"])

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "partial-model-verification"
    with TestClient(app) as c:
        response = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [
                    {"id": "working-model", "upstream_model": "working-upstream"},
                    {"id": "broken-model", "upstream_model": "broken-upstream"},
                    {
                        "id": "unadapted-image-model",
                        "upstream_model": "image-upstream",
                        "modality": "image",
                    },
                ],
            },
        )
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert response.json()["models"] == ["working-model"]
        assert set(response.json()["rejected_models"]) == {
            "broken-model",
            "unadapted-image-model",
        }
        masked = c.get("/admin/connections", headers=AUTH).json()[provider]
        assert [model["id"] for model in masked["enabled_models"]] == [
            "working-model"
        ]
        routed = {model["id"] for model in c.get("/v1/models", headers=AUTH).json()["data"]}
        assert "working-model" in routed
        assert "broken-model" not in routed
        assert c.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200
    assert set(probed) == {"working-upstream", "broken-upstream"}


def test_connect_namespaces_cross_provider_virtual_model_collision_automatically(
    approval_auth_headers, monkeypatch
):
    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers, json
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    first_provider = "collision-first"
    second_provider = "collision-second"
    payload = {
        "type": "openai_compat",
        "api_key": "secret",
        "base_url": "https://api.openai.com/v1",
        "enabled_models": [{"id": "shared-virtual-id", "upstream_model": "upstream"}],
    }
    with TestClient(app) as c:
        first = c.post(
            f"/admin/connections/{first_provider}",
            headers=approval_auth_headers,
            json=payload,
        )
        assert first.status_code == 200 and first.json()["ok"] is True
        second = c.post(
            f"/admin/connections/{second_provider}",
            headers=approval_auth_headers,
            json=payload,
        )
        assert second.status_code == 200 and second.json()["ok"] is True
        assert second.json()["models"] == [
            f"{second_provider}::shared-virtual-id"
        ]
        connections_view = c.get("/admin/connections", headers=AUTH).json()
        assert connections_view[first_provider]["enabled_models"][0]["id"] == (
            "shared-virtual-id"
        )
        assert connections_view[second_provider]["enabled_models"][0]["id"] == (
            f"{second_provider}::shared-virtual-id"
        )
        routed = {
            model["id"] for model in c.get("/v1/models", headers=AUTH).json()["data"]
        }
        assert {"shared-virtual-id", f"{second_provider}::shared-virtual-id"} <= routed
        assert c.delete(
            f"/admin/connections/{second_provider}", headers=approval_auth_headers
        ).status_code == 200
        assert c.delete(
            f"/admin/connections/{first_provider}", headers=approval_auth_headers
        ).status_code == 200


def test_connect_discovers_and_selects_chat_model_when_manifest_is_empty(
    approval_auth_headers, monkeypatch
):
    requested: list[tuple[str, str, str]] = []

    class _CatalogResponse:
        status_code = 200
        headers = {"content-length": "123"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield json.dumps(
                {
                    "data": [
                        {"id": "text-embedding-3-small"},
                        {"id": "gpt-chat-recommended"},
                        {"id": "gpt-image-1"},
                    ]
                }
            ).encode("utf-8")

    class _ProbeResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "choices": [
                    {"message": {"role": "assistant", "content": "ok"}}
                ]
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, *, headers):
            requested.append((method, url, headers.get("Authorization", "")))
            return _CatalogResponse()

        async def post(self, _url, *, headers, json):
            del headers
            requested.append(("POST", json["model"], ""))
            return _ProbeResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "zero-config-discovery"
    with TestClient(app) as client:
        response = client.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [],
            },
        )
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert response.json()["models"] == ["gpt-chat-recommended"]
        assert client.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200
    assert requested == [
        (
            "GET",
            "https://api.openai.com/v1/models",
            "Bearer secret",
        ),
        ("POST", "gpt-chat-recommended", ""),
    ]


def test_connection_test_reports_every_verified_chat_model(
    approval_auth_headers, monkeypatch
):
    failing_upstream = ""

    class _ProviderResponse:
        text = ""

        def __init__(self, model: str):
            self.model = model
            self.status_code = 503 if model == failing_upstream else 200

        def json(self):
            return {
                "choices": [
                    {"message": {"role": "assistant", "content": "ok"}}
                ]
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers
            return _ProviderResponse(json["model"])

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "multi-model-health"
    with TestClient(app) as client:
        connected = client.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [
                    {"id": "health-a", "upstream_model": "up-a"},
                    {"id": "health-b", "upstream_model": "up-b"},
                ],
            },
        )
        assert connected.status_code == 200 and connected.json()["ok"] is True
        failing_upstream = "up-b"
        tested = client.post(
            f"/admin/connections/{provider}/test", headers=approval_auth_headers
        )
        assert tested.status_code == 200
        assert tested.json() == {
            "ok": False,
            "tested_models": [
                {"model": "health-a", "ok": True},
                {"model": "health-b", "ok": False},
            ],
            "tested_count": 2,
            "failed_count": 1,
            "error": "部分模型当前不可达，请检查服务状态与凭据",
        }
        assert client.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200


def test_reconnect_can_explicitly_preserve_the_verified_credential(
    approval_auth_headers, monkeypatch
):
    authorization_headers: list[str] = []

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del json
            authorization_headers.append(headers.get("Authorization", ""))
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "preserveprov"
    with TestClient(app) as c:
        first = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "old-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "old-model", "upstream_model": "old-up"}],
            },
        )
        assert first.status_code == 200 and first.json()["ok"] is True

        reconnect = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "new-model", "upstream_model": "new-up"}],
                "preserve_existing_credential": True,
            },
        )
        assert reconnect.status_code == 200
        assert reconnect.json()["ok"] is True
        assert authorization_headers == [
            "Bearer old-secret-credential",
            "Bearer old-secret-credential",
        ]

        models = {m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]}
        assert "new-model" in models
        assert "old-model" not in models
        masked = c.get("/admin/connections", headers=AUTH).json()[provider]
        assert "api_key_masked" not in masked
        assert masked["credential_present"] is True
        assert masked["state"] == "verified"

        assert c.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200


def test_reconnect_never_forwards_preserved_credential_to_changed_target(
    approval_auth_headers, monkeypatch
):
    authorization_headers: list[str] = []

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del json
            authorization_headers.append(headers.get("Authorization", ""))
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "preserve-target-bound"
    with TestClient(app) as client:
        first = client.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "old-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "old-model", "upstream_model": "old-up"}],
            },
        )
        assert first.status_code == 200 and first.json()["ok"] is True

        changed_target = client.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "",
                "base_url": "https://api.moonshot.cn/v1",
                "enabled_models": [{"id": "new-model", "upstream_model": "new-up"}],
                "preserve_existing_credential": True,
            },
        )
        assert changed_target.status_code == 422
        assert authorization_headers == ["Bearer old-secret-credential"]

        saved = client.get("/admin/connections", headers=AUTH).json()[provider]
        assert saved["base_url"] == "https://api.openai.com/v1"
        assert [model["id"] for model in saved["enabled_models"]] == ["old-model"]
        assert client.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200


def test_failed_reconnect_keeps_the_old_route_and_credential(
    approval_auth_headers, monkeypatch
):
    authorization_headers: list[str] = []

    class _ProviderResponse:
        text = "upstream leaked bad-secret-credential"

        def __init__(self, status_code: int):
            self.status_code = status_code

        def json(self) -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del json
            authorization = headers.get("Authorization", "")
            authorization_headers.append(authorization)
            return _ProviderResponse(401 if "bad-secret" in authorization else 200)

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    provider = "failedreconnect"
    with TestClient(app) as c:
        first = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "old-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "working-model", "upstream_model": "old-up"}],
            },
        )
        assert first.status_code == 200 and first.json()["ok"] is True

        failed = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "bad-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "broken-model", "upstream_model": "bad-up"}],
            },
        )
        assert failed.status_code == 200
        assert failed.json() == {
            "ok": False,
            "error": "连接验证失败，请检查凭据、模型与服务状态",
        }
        assert "bad-secret" not in failed.text
        models = {m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]}
        assert "working-model" in models and "broken-model" not in models

        preserved = c.post(
            f"/admin/connections/{provider}",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "final-model", "upstream_model": "final-up"}],
                "preserve_existing_credential": True,
            },
        )
        assert preserved.status_code == 200 and preserved.json()["ok"] is True
        assert authorization_headers == [
            "Bearer old-secret-credential",
            "Bearer bad-secret-credential",
            "Bearer old-secret-credential",
        ]
        assert c.delete(
            f"/admin/connections/{provider}", headers=approval_auth_headers
        ).status_code == 200


def test_local_model_catalog_rejects_private_or_metadata_target():
    with TestClient(app) as c:
        for target in (
            "http://192.168.1.5:8000/v1",
            "https://169.254.169.254/latest/meta-data",
        ):
            response = c.get(
                "/admin/local/models", params={"base_url": target}, headers=AUTH
            )
            assert response.status_code == 422


def test_local_model_discovery_is_bounded_and_bypasses_environment_proxies(
    monkeypatch
):
    client_options: list[dict] = []
    requests: list[tuple[str, str]] = []
    body = json.dumps(
        {"data": [{"id": "local-a"}, {"id": "local-b"}]}
    ).encode("utf-8")

    class _StreamResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield body[:7]
            yield body[7:]

    class _ProviderClient:
        def __init__(self, **kwargs):
            client_options.append(dict(kwargs))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, **_kwargs):
            requests.append((method, url))
            return _StreamResponse()

    monkeypatch.setattr(admin.httpx, "AsyncClient", _ProviderClient)
    with TestClient(app) as c:
        response = c.get(
            "/admin/local/models",
            params={"base_url": "http://127.0.0.1:11434/v1"},
            headers=AUTH,
        )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "models": ["local-a", "local-b"]}
    assert client_options == [
        {"timeout": 5.0, "follow_redirects": False, "trust_env": False}
    ]
    assert requests == [("GET", "http://127.0.0.1:11434/v1/models")]


def test_local_model_discovery_rejects_oversize_and_public_targets(monkeypatch):
    oversized = b"x" * (256 * 1024 + 1)

    class _StreamResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield oversized

    class _ProviderClient:
        def __init__(self, **_kwargs):
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return _StreamResponse()

    monkeypatch.setattr(admin.httpx, "AsyncClient", _ProviderClient)
    with TestClient(app) as c:
        too_large = c.get(
            "/admin/local/models",
            params={"base_url": "http://127.0.0.1:11434/v1"},
            headers=AUTH,
        )
        public = c.get(
            "/admin/local/models",
            params={"base_url": "https://openrouter.ai/api/v1"},
            headers=AUTH,
        )
    assert too_large.status_code == 200
    assert too_large.json() == {"ok": False, "error": "无法读取模型目录"}
    assert public.status_code == 422
    assert public.json() == {"detail": "模型服务地址不符合安全策略"}


@pytest.mark.asyncio
async def test_connect_candidates_for_one_provider_are_serialized(
    tmp_path, monkeypatch
):
    asgi_client_type = httpx.AsyncClient
    active = 0
    maximum_active = 0

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            nonlocal active, maximum_active
            del headers, json
            active += 1
            maximum_active = max(maximum_active, active)
            try:
                await asyncio.sleep(0.15)
                return _ProviderResponse()
            finally:
                active -= 1

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)

    def write(path, payload, *, purpose):
        del purpose
        Path(path).write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "write_protected_json", write)
    store = ConnectionStore(tmp_path / "connections.json")
    live_router = Router(models_config={}, store=store)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    provider = "serializedprov"

    def payload(suffix: str) -> dict:
        return {
            "type": "openai_compat",
            "api_key": f"secret-{suffix}",
            "base_url": "https://api.openai.com/v1",
            "enabled_models": [
                {"id": f"model-{suffix}", "upstream_model": f"up-{suffix}"}
            ],
        }

    transport = httpx.ASGITransport(app=test_app)
    async with asgi_client_type(transport=transport, base_url="http://test") as client:
        first, second = await asyncio.gather(
            client.post(
            f"/admin/connections/{provider}",
            json=payload("first"),
            ),
            client.post(
            f"/admin/connections/{provider}",
            json=payload("second"),
            ),
        )
        assert all(
            r.status_code == 200 and r.json()["ok"] is True
            for r in (first, second)
        )
        assert maximum_active == 1
    await live_router.aclose()


@pytest.mark.asyncio
async def test_failed_live_promotion_rolls_back_the_durable_connection(
    tmp_path, monkeypatch
):
    asgi_client_type = httpx.AsyncClient

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers, json
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)

    def write(path, payload, *, purpose):
        del purpose
        Path(path).write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "write_protected_json", write)
    store = ConnectionStore(tmp_path / "connections.json")
    provider = "rollbackprov"
    old_record = store.mark_verified(
        provider,
        {
            "type": "openai_compat",
            "api_key": "old-secret-credential",
            "base_url": "https://api.openai.com/v1",
            "enabled_models": [{"id": "old-model", "upstream_model": "old-up"}],
        },
        verified_at_value="2026-07-16T12:34:56Z",
    )
    store.set(provider, old_record)
    live_router = Router(models_config={}, store=store)
    old_route = live_router.resolve("old-model")
    assert old_route is not None

    original_get = store.get
    fail_next_reload = True

    def fail_once(name):
        nonlocal fail_next_reload
        if fail_next_reload:
            fail_next_reload = False
            raise OSError("synthetic reload failure with new-secret-credential")
        return original_get(name)

    monkeypatch.setattr(store, "get", fail_once)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)

    async with asgi_client_type(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/admin/connections/{provider}",
            json={
                "type": "openai_compat",
                "api_key": "new-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "new-model", "upstream_model": "new-up"}],
            },
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "连接切换失败，旧连接已保留"}
    assert "new-secret" not in response.text
    assert store.get(provider) == old_record
    assert live_router.resolve("old-model") is old_route
    assert live_router.resolve("new-model") is None
    await live_router.aclose()


@pytest.mark.asyncio
async def test_failed_delete_reload_restores_the_durable_and_live_connection(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)

    def write(path, payload, *, purpose):
        del purpose
        Path(path).write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "write_protected_json", write)
    provider = "delete-rollback"
    store = ConnectionStore(tmp_path / "connections.json")
    old_record = store.mark_verified(
        provider,
        {
            "type": "openai_compat",
            "api_key": "old-secret-credential",
            "base_url": "https://api.openai.com/v1",
            "enabled_models": [{"id": "old-model", "upstream_model": "old-up"}],
        },
        verified_at_value="2026-07-16T12:34:56Z",
    )
    store.set(provider, old_record)
    live_router = Router(models_config={}, store=store)
    old_route = live_router.resolve("old-model")
    assert old_route is not None

    original_get = store.get
    fail_next_reload = True

    def fail_once(name):
        nonlocal fail_next_reload
        if fail_next_reload:
            fail_next_reload = False
            raise OSError("synthetic delete reload failure")
        return original_get(name)

    monkeypatch.setattr(store, "get", fail_once)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        response = await client.delete(f"/admin/connections/{provider}")

    assert response.status_code == 503
    assert response.json() == {"detail": "连接删除失败，旧连接已保留"}
    assert store.get(provider) == old_record
    assert live_router.resolve("old-model") is old_route
    await live_router.aclose()


@pytest.mark.asyncio
async def test_approval_can_remove_an_opaque_quarantined_connection(
    tmp_path, monkeypatch
):
    def read(path, *, purpose, migrate_plaintext=False):
        del purpose, migrate_plaintext
        return json.loads(Path(path).read_text("utf-8"))

    def write(path, payload, *, purpose):
        del purpose
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "read_protected_json", read)
    monkeypatch.setattr(connections, "write_protected_json", write)
    path = tmp_path / "connections.json"
    path.write_text(
        json.dumps(
            {
                "../invalid-provider": {
                    "type": "openai_compat",
                    "api_key": "quarantined-secret",
                    "base_url": "https://api.openai.com/v1",
                    "enabled_models": [{"id": "legacy-model"}],
                }
            }
        ),
        encoding="utf-8",
    )
    store = ConnectionStore(path)
    handle = next(iter(store.masked()))
    live_router = Router(models_config={}, store=store)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    transport = httpx.ASGITransport(app=test_app)

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        response = await client.delete(f"/admin/connections/{handle}")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert store.masked() == {}
    assert json.loads(path.read_text("utf-8")) == {}
    await live_router.aclose()


@pytest.mark.asyncio
async def test_transient_provider_cleanup_failure_is_redacted_and_never_promoted(
    tmp_path, monkeypatch
):
    asgi_client_type = httpx.AsyncClient

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers, json
            return _ProviderResponse()

        async def aclose(self):
            raise RuntimeError("cleanup contained new-secret-credential")

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)

    def write(path, payload, *, purpose):
        del purpose
        Path(path).write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "write_protected_json", write)
    store = ConnectionStore(tmp_path / "connections.json")
    live_router = Router(models_config={}, store=store)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)

    async with asgi_client_type(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/admin/connections/cleanupfail",
            json={
                "type": "openai_compat",
                "api_key": "new-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "new-model", "upstream_model": "new-up"}],
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error": "连接验证失败，请检查凭据、模型与服务状态",
        "reason_code": "connector_unavailable",
    }
    assert "new-secret" not in response.text
    assert store.get("cleanupfail") is None
    assert live_router.resolve("new-model") is None
    await live_router.aclose()


@pytest.mark.asyncio
async def test_persistence_failure_keeps_the_old_credential_and_live_route(
    tmp_path, monkeypatch
):
    asgi_client_type = httpx.AsyncClient

    class _ProviderResponse:
        status_code = 200
        text = ""

        @staticmethod
        def json() -> dict:
            return {
                "id": "connect-check",
                "model": "upstream",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def post(self, _url, *, headers, json):
            del headers, json
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)

    def write(path, payload, *, purpose):
        del purpose
        Path(path).write_text(json.dumps(dict(payload)), encoding="utf-8")

    monkeypatch.setattr(connections, "write_protected_json", write)
    provider = "persistfail"
    store = ConnectionStore(tmp_path / "connections.json")
    old_record = store.mark_verified(
        provider,
        {
            "type": "openai_compat",
            "api_key": "old-secret-credential",
            "base_url": "https://api.openai.com/v1",
            "enabled_models": [{"id": "old-model", "upstream_model": "old-up"}],
        },
        verified_at_value="2026-07-16T12:34:56Z",
    )
    store.set(provider, old_record)
    live_router = Router(models_config={}, store=store)
    old_route = live_router.resolve("old-model")
    assert old_route is not None

    def fail_write(*_args, **_kwargs):
        raise OSError("persistence failure contained new-secret-credential")

    monkeypatch.setattr(connections, "write_protected_json", fail_write)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)

    async with asgi_client_type(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/admin/connections/{provider}",
            json={
                "type": "openai_compat",
                "api_key": "new-secret-credential",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "new-model", "upstream_model": "new-up"}],
            },
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "连接配置未能安全持久化"}
    assert "new-secret" not in response.text
    assert store.get(provider) == old_record
    assert live_router.resolve("old-model") is old_route
    assert live_router.resolve("new-model") is None
    await live_router.aclose()
