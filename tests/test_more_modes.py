"""辩论 / 拆解 / 流水线 工作流（用 echo 实测）。"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import app
from orchestrator.durable_event_log import (
    DurableWorkflowEventLog,
    DurableWorkflowEventUnavailable,
)

AUTH = {"Authorization": "Bearer test-key"}


def test_debate_rejects_duplicate_and_self_judge_routes():
    with TestClient(app) as c:
        r = c.post(
            "/v1/orchestrate/debate",
            headers=AUTH,
            json={"prompt": "x", "debaters": ["echo", "echo"], "judge": "echo", "rounds": 2},
        )
        assert r.status_code == 422


def test_decompose_echo():
    with TestClient(app) as c:
        r = c.post(
            "/v1/orchestrate/decompose",
            headers=AUTH,
            json={"task": "写一篇短文", "planner": "echo", "aggregator": "echo"},
        )
        assert r.status_code == 200
        d = r.json()
        assert d["final"]
        assert isinstance(d["subtasks"], list)


def test_pipeline_echo():
    with TestClient(app) as c:
        r = c.post(
            "/v1/orchestrate/pipeline",
            headers=AUTH,
            json={
                "prompt": "hi",
                "steps": [
                    {"model": "echo", "instruction": "起草"},
                    {"model": "echo", "instruction": "润色"},
                ],
            },
        )
        assert r.status_code == 200
        d = r.json()
        assert len(d["trace"]) == 2
        assert d["final"]
        workflow_id = d["workflow_id"]
    log = DurableWorkflowEventLog(
        Path(str(os.environ["USAGE_DB_PATH"])).parent / "workflow-events.db"
    )
    try:
        events = log.list_events(workflow_id)
    finally:
        log.close()
    assert len(events) == 11
    assert events[0]["event_name"] == "fact/workflow/pipeline/turn"
    assert events[-1]["event_name"] == "fact/workflow/pipeline/turn"


def test_pipeline_validation():
    with TestClient(app) as c:
        r = c.post("/v1/orchestrate/pipeline", headers=AUTH, json={"prompt": "hi"})
        assert r.status_code == 422


def test_pipeline_durable_event_failure_is_explicitly_retry_unsafe():
    async def broken_sink(_name: str, _payload: object) -> None:
        raise DurableWorkflowEventUnavailable("simulated durable outage")

    with TestClient(app) as c:
        registry = app.state.router.plugin_kernel.events
        original_sink = registry._durable_sink
        registry._durable_sink = broken_sink
        try:
            response = c.post(
                "/v1/orchestrate/pipeline",
                headers=AUTH,
                json={
                    "prompt": "must not reach a model",
                    "steps": [{"model": "echo", "instruction": "draft"}],
                },
            )
        finally:
            registry._durable_sink = original_sink
    assert response.status_code == 503
    assert response.headers["X-Nachuan-Retry-Safe"] == "false"
    assert response.json()["detail"] == "流水线持久事件日志当前不可用"
