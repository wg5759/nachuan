"""Host CLI execution stays fail-closed until a separate OS worker exists."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app
from gateway.providers.base import ProviderError
from gateway.router import ModelRoute, Router

AUTH = {"Authorization": "Bearer test-key"}


class _NeverCalledProvider:
    name = "custom-codex"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def agent_exec(self, task: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"task": task, **kwargs})
        raise AssertionError("host CLI provider must not be called")


class _ExecRouter:
    def __init__(self, route: ModelRoute) -> None:
        self.route = route
        self.resolve_calls: list[str] = []

    def resolve(self, model: str) -> ModelRoute | None:
        self.resolve_calls.append(model)
        return self.route

    def first_route_for(self, provider: str) -> ModelRoute | None:
        raise AssertionError(f"must not discover a host provider: {provider}")


def _route(provider: Any) -> ModelRoute:
    return ModelRoute(
        virtual_model="codex-spark",
        provider=provider,
        upstream_model="gpt-5.3-codex-spark",
        tier="premium",
        exec_backend="codex",
    )


def test_agent_exec_endpoint_fails_closed_before_parsing_or_approval() -> None:
    assert not hasattr(appmod, "_run_agent_exec_unreachable_reference")
    with TestClient(app) as client:
        for payload in (
            {},
            {"task": "只读规划", "mode": "plan"},
            {"task": "已审批写入", "mode": "full", "approval_id": 1},
        ):
            response = client.post("/v1/agent/exec", headers=AUTH, json=payload)
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]


async def test_internal_agent_exec_fails_before_model_resolution(tmp_path) -> None:
    provider = _NeverCalledProvider()
    router = _ExecRouter(_route(provider))

    with pytest.raises(ProviderError, match="低权限执行 worker") as exc:
        await appmod._run_agent_exec(
            router,
            "修改文件",
            backend="auto",
            mode="plan",
            workdir=str(tmp_path),
            model_override="codex-spark",
        )

    assert exc.value.status_code == 503
    assert router.resolve_calls == []
    assert provider.calls == []


def test_router_model_list_does_not_claim_native_execution_is_available() -> None:
    provider = _NeverCalledProvider()
    router = object.__new__(Router)
    router._routes = {"codex-spark": _route(provider)}

    assert "exec_backend" not in router.list_models()[0]
