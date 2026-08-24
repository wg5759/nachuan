from __future__ import annotations

import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import gateway.app as appmod
from gateway.app import app
from gateway.streaming import sse_encode


AUTH = {"Authorization": "Bearer test-key"}


def _sse_events(body: str) -> list[dict]:
    events: list[dict] = []
    for line in body.splitlines():
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        events.append(json.loads(line.removeprefix("data: ")))
    return events


def test_agent_run_normalizes_legacy_unverified_result(monkeypatch):
    async def fake_orchestrated(*_args, **_kwargs):
        return {"reply": "done", "model": "glm", "usage": {}}

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "只读分析", "orchestrate": True},
        )

    assert response.status_code == 200
    assert response.json()["outcome"] == "completed_unverified"
    assert response.json()["model"] == "nachuan-engine"
    assert "glm" not in response.text
    assert response.json()["blocked"] is False
    assert response.json()["reviewed"] is False
    assert response.json()["verified"] is False
    assert response.json()["machine_verified"] is False


def test_agent_run_rejects_contradictory_completed_result(monkeypatch):
    raw_secret = r"C:\Users\owner\private\provider-token.txt"

    async def fake_orchestrated(*_args, **_kwargs):
        return {
            "reply": raw_secret,
            "model": "glm",
            "outcome": "completed",
            "blocked": False,
            "verified": False,
            "machine_verified": False,
        }

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "只读分析", "orchestrate": True},
        )

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "code": "invalid_agent_result",
        "retryable": False,
    }
    assert raw_secret not in response.text


def test_agent_run_stream_rejects_invalid_result_without_leaking(monkeypatch):
    raw_secret = "provider returned secret-internal-result"

    async def fake_orchestrated(*_args, **_kwargs):
        return {
            "reply": raw_secret,
            "model": "glm",
            "outcome": "completed",
            "blocked": False,
            "verified": False,
            "machine_verified": False,
        }

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "只读分析", "orchestrate": True, "stream": True},
        )

    assert response.status_code == 200
    events = _sse_events(response.text)
    assert events[-1] == {
        "type": "error",
        "code": "invalid_agent_result",
        "message": "Agent 返回了无效的终态结果",
    }
    assert raw_secret not in response.text


def test_agent_run_stream_hides_internal_exception(monkeypatch):
    raw_secret = r"upstream failed at C:\private\model with sk-live-secret"

    async def fake_orchestrated(*_args, **_kwargs):
        raise RuntimeError(raw_secret)

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "只读分析", "orchestrate": True, "stream": True},
        )

    assert response.status_code == 200
    events = _sse_events(response.text)
    assert events[-1] == {
        "type": "error",
        "code": "agent_execution_failed",
        "message": "Agent 执行失败，请稍后重试",
    }
    assert raw_secret not in response.text


def test_agent_run_does_not_learn_from_failed_result(monkeypatch):
    growth_calls: list[tuple[str, str]] = []

    async def fake_orchestrated(*_args, **_kwargs):
        return {
            "reply": "deterministic failure summary must not become memory",
            "model": "nachuan-engine",
            "outcome": "failed",
            "blocked": False,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
            "stopped_reason": "empty_response",
        }

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    monkeypatch.setattr(
        appmod,
        "_grow_memory",
        lambda _router, task, reply: growth_calls.append((task, reply)),
    )
    with TestClient(app) as client:
        plain = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "read-only failure probe", "orchestrate": True},
        )
        streamed = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={
                "task": "read-only failure probe",
                "orchestrate": True,
                "stream": True,
            },
        )

    assert plain.status_code == 200 and plain.json()["outcome"] == "failed"
    assert streamed.status_code == 200
    assert _sse_events(streamed.text)[-1]["result"]["outcome"] == "failed"
    assert growth_calls == []


def test_agent_run_stream_filters_untrusted_progress_payload(monkeypatch):
    raw_secret = r"provider failed at C:\private\model with sk-live-secret"

    async def fake_orchestrated(*_args, **kwargs):
        await kwargs["on_event"](
            {"type": "node", "status": "done", "digest": raw_secret}
        )
        await kwargs["on_event"]({"type": "step", "log": raw_secret})
        await kwargs["on_event"]({"type": "route", "model": raw_secret})
        await kwargs["on_event"](
            {"type": "escalate", "from": raw_secret, "to": raw_secret}
        )
        await kwargs["on_event"]({"type": "done", "model": raw_secret})
        await kwargs["on_event"](
            {"type": "pending_video", "task_id": raw_secret, "model": raw_secret}
        )
        return {
            "reply": "safe result",
            "model": "nachuan-engine",
            "outcome": "completed_unverified",
            "blocked": False,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
        }

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "只读分析", "orchestrate": True, "stream": True},
        )

    events = _sse_events(response.text)
    assert raw_secret not in response.text
    assert not any(event.get("type") == "node" for event in events)
    assert {"type": "step", "log": "已完成一个受控步骤"} in events
    assert not any(event.get("type") == "pending_video" for event in events)
    for event in events:
        for field in ("model", "from", "to"):
            if field in event:
                assert event[field] == "unknown"


def test_public_agent_stream_event_uses_model_allowlist_and_strict_task_id() -> None:
    allowed = frozenset({"glm", "strong-model"})

    assert appmod._public_agent_stream_event(
        {"type": "route", "model": "glm"}, allowed_models=allowed
    ) == {"type": "route", "model": "glm", "complex": False, "difficulty": ""}
    assert appmod._public_agent_stream_event(
        {"type": "escalate", "from": "glm", "to": "strong-model"},
        allowed_models=allowed,
    ) == {"type": "escalate", "from": "glm", "to": "strong-model"}
    assert appmod._public_agent_stream_event(
        {
            "type": "pending_video",
            "task_id": "studio:0123456789ab",
            "model": "glm",
        },
        allowed_models=allowed,
    ) == {
        "type": "pending_video",
        "task_id": "studio:0123456789ab",
        "model": "glm",
    }
    assert appmod._public_agent_stream_event(
        {"type": "pending_video", "task_id": r"C:\private\task", "model": "glm"},
        allowed_models=allowed,
    ) is None


@pytest.mark.asyncio
async def test_sse_encode_aclose_propagates_to_inner_iterator() -> None:
    cleaned = asyncio.Event()

    async def source():
        try:
            yield {"type": "step"}
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            cleaned.set()

    encoded = sse_encode(source())
    assert await anext(encoded) == b'data: {"type": "step"}\n\n'
    await encoded.aclose()

    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_agent_run_stream_body_close_drains_real_producer(monkeypatch) -> None:
    cancelled = asyncio.Event()
    cleaned = asyncio.Event()
    release = asyncio.Event()

    class Router:
        def list_models(self):
            return []

    async def fake_capability(**_kwargs):
        return None, None

    async def fake_compress(_router, _conversation_id, history):
        return history

    async def fake_orchestrated(*_args, **kwargs):
        await kwargs["on_event"]({"type": "step", "log": "provider raw"})
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            await asyncio.sleep(0.15)
            cleaned.set()
            raise

    monkeypatch.setattr(appmod, "_action_capability", fake_capability)
    monkeypatch.setattr(appmod.conv_summary, "rolling_compress", fake_compress)
    monkeypatch.setattr(appmod, "memory_system_note", lambda *_a, **_k: ("", None))
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    monkeypatch.setattr(appmod.steer, "register", lambda *_a, **_k: None)
    monkeypatch.setattr(appmod.steer, "unregister", lambda *_a, **_k: None)
    monkeypatch.setattr(appmod.app.state, "router", Router(), raising=False)
    monkeypatch.setattr(appmod.app.state, "background_tasks", set(), raising=False)
    monkeypatch.setattr(appmod.app.state, "memory", object(), raising=False)

    body = json.dumps(
        {
            "task": "只读取消探针",
            "workdir": str(appmod.workspace_root()),
            "mode": "plan",
            "allow": [],
            "orchestrate": True,
            "stream": True,
            "conversation_id": "cancel-probe",
        }
    ).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/agent/run",
            "headers": [(b"content-type", b"application/json")],
            "query_string": b"",
            "server": ("test", 80),
            "client": ("test", 123),
            "scheme": "http",
        },
        receive=receive,
    )
    response = await appmod.agent_run_endpoint(request, api_key="test-key")
    first = await response.body_iterator.__anext__()
    first_bytes = first if isinstance(first, bytes) else first.encode()
    assert b'"type": "step"' in first_bytes

    started = time.monotonic()
    try:
        await response.body_iterator.aclose()
        assert cancelled.is_set()
        assert cleaned.is_set()
        assert time.monotonic() - started >= 0.10
    finally:
        release.set()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_agent_stream_cancel_waits_for_producer_cleanup() -> None:
    started = asyncio.Event()
    cleaned = asyncio.Event()

    async def producer() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            cleaned.set()

    task = asyncio.create_task(producer())
    await started.wait()
    await appmod._cancel_and_drain_agent_stream_task(task)

    assert task.done()
    assert cleaned.is_set()
