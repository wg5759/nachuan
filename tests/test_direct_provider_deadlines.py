from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from gateway import admin
from orchestrator import vision
from orchestrator.workflows import coding_team, panel_judge


class _BlockingProvider:
    name = "blocking"

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def chat(self, _req, _upstream):  # noqa: ANN001
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.cancelled.set()

    async def probe_chat(self, req, upstream):  # noqa: ANN001
        return await self.chat(req, upstream)


class _Route:
    def __init__(self, provider: _BlockingProvider, model: str = "slow") -> None:
        self.provider = provider
        self.virtual_model = model
        self.upstream_model = model


class _Router:
    def __init__(self, provider: _BlockingProvider) -> None:
        self.route = _Route(provider)

    def resolve(self, _model: str):  # noqa: ANN201
        return self.route

    def first_route_for(self, _provider: str):  # noqa: ANN201
        return self.route

    def routes_for_provider(self, provider: str):  # noqa: ANN201
        return [self.route] if provider == self.route.provider.name else []


async def test_admin_connection_test_has_a_hard_deadline_and_cancels_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(admin, "_CONNECTION_TEST_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False)
    monkeypatch.setattr(admin, "_CONNECTION_TEST_TOTAL_TIMEOUT_SEC", 0.3, raising=False)
    provider = _BlockingProvider()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(router=_Router(provider)))
    )

    result = await asyncio.wait_for(admin.test_connection("blocking", request), timeout=2.0)

    assert result == {
        "ok": False,
        "tested_models": [{"model": "slow", "ok": False}],
        "tested_count": 1,
        "failed_count": 1,
        "model": "slow",
        "error": "部分模型当前不可达，请检查服务状态与凭据",
    }
    assert provider.cancelled.is_set()


async def test_vision_call_has_a_hard_deadline_and_cancels_provider(monkeypatch) -> None:
    monkeypatch.setattr(vision, "_VISION_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False)
    monkeypatch.setattr(vision, "_VISION_TOTAL_TIMEOUT_SEC", 0.3, raising=False)
    provider = _BlockingProvider()
    started = time.monotonic()

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            vision.describe_image(_Router(provider), b"image", model="slow"),
            timeout=2.0,
        )

    assert time.monotonic() - started < 1.5
    assert provider.cancelled.is_set()


async def test_coding_team_chat_has_a_hard_deadline_and_cancels_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(coding_team, "_CHAT_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False)
    monkeypatch.setattr(coding_team, "_CHAT_TOTAL_TIMEOUT_SEC", 0.3, raising=False)
    provider = _BlockingProvider()

    result = await asyncio.wait_for(
        coding_team._chat(_Router(provider), "slow", "plan"), timeout=2.0
    )

    assert "超时" in result
    assert provider.cancelled.is_set()


async def test_panel_call_has_a_hard_deadline_and_cancels_provider(monkeypatch) -> None:
    monkeypatch.setattr(panel_judge, "_ASK_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False)
    monkeypatch.setattr(panel_judge, "_ASK_TOTAL_TIMEOUT_SEC", 0.3, raising=False)
    provider = _BlockingProvider()

    result = await asyncio.wait_for(
        panel_judge._ask(
            _Router(provider), "slow", [{"role": "user", "content": "question"}]
        ),
        timeout=2.0,
    )

    assert result["answer"] is None
    assert "超时" in result["error"]
    assert provider.cancelled.is_set()


async def test_external_cancellation_is_never_converted_to_a_workflow_error(
    monkeypatch,
) -> None:
    monkeypatch.setattr(coding_team, "_CHAT_ATTEMPT_TIMEOUT_SEC", 10.0, raising=False)
    monkeypatch.setattr(coding_team, "_CHAT_TOTAL_TIMEOUT_SEC", 10.0, raising=False)
    provider = _BlockingProvider()
    task = asyncio.create_task(coding_team._chat(_Router(provider), "slow", "plan"))
    await asyncio.wait_for(provider.started.wait(), timeout=2.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.cancelled.is_set()
