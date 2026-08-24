"""辩论 / 拆解 / 流水线 工作流（用 echo 实测）。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app

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


def test_pipeline_validation():
    with TestClient(app) as c:
        r = c.post("/v1/orchestrate/pipeline", headers=AUTH, json={"prompt": "hi"})
        assert r.status_code == 422
