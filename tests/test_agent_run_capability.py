from __future__ import annotations

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app


AUTH = {"Authorization": "Bearer test-key"}


def _result() -> dict:
    return {
        "reply": "done",
        "steps": 1,
        "model": "glm",
        "usage": {},
        "tool_log": [],
        "file_changes": [],
        "media": [],
    }


def test_agent_run_defaults_to_server_enforced_read_only_tools(monkeypatch):
    seen: dict = {}

    async def fake_orchestrated(_router, _task, **kwargs):
        seen["allow"] = kwargs.get("allow")
        return _result()

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "分析这个目录", "orchestrate": True},
        )

    assert response.status_code == 200
    assert seen["allow"]
    assert {"write_file", "run_command", "browser_type", "browser_eval"}.isdisjoint(
        seen["allow"]
    )


def test_high_risk_agent_run_uses_exact_scoped_one_time_capability(
    monkeypatch, approval_auth_headers
):
    calls: list[dict] = []

    async def fake_orchestrated(_router, task, **kwargs):
        calls.append({"task": task, **kwargs})
        return _result()

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    payload = {
        "task": "删除生产目录",
        "mode": "auto",
        "user_id": "agent-run-scope-user",
        "conversation_id": "approved-conversation",
        "history": [{"role": "user", "content": "approved history"}],
    }
    with TestClient(app) as client:
        held = client.post("/v1/agent/run", headers=AUTH, json=payload).json()
        assert held.get("needs_approval") is True
        aid = held["approval_id"]
        client.post(
            f"/v1/approvals/{aid}/resolve",
            headers=approval_auth_headers,
            json={"decision": "approve"},
        )

        # Native CLI is disabled before approval parsing, so an agent_run token
        # can never be replayed into that trust domain.
        wrong_scope = client.post(
            "/v1/agent/exec",
            headers=AUTH,
            json={**payload, "approval_id": aid},
        )
        assert wrong_scope.status_code == 503

        tampered_replay = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={
                **payload,
                "task": "删除另一目录",
                "allow": ["read_file"],
                "history": [{"role": "user", "content": "attacker history"}],
                "conversation_id": "attacker-conversation",
                "workdir": "Z:/attacker",
                "approval_id": aid,
            },
        )
        replay = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={**payload, "approval_id": aid},
        )

    assert tampered_replay.status_code == 200 and tampered_replay.json()["reply"] == "done"
    assert replay.status_code == 403
    assert len(calls) == 1
    assert calls[0]["task"] == "删除生产目录"
    assert calls[0]["history"][-1]["content"] == "approved history"


def test_low_risk_workspace_write_still_requires_capability(monkeypatch):
    async def fake_orchestrated(*_args, **_kwargs):
        raise AssertionError("must not execute before the capability is approved")

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orchestrated)
    with TestClient(app) as client:
        held = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={"task": "创建一个说明文件", "mode": "auto", "user_id": "low-risk-cap"},
        ).json()

    assert held.get("needs_approval") is True
    assert held.get("by") == "capability"


def test_native_agent_job_create_and_resume_are_fail_closed(monkeypatch):
    async def fail_plan(*_args, **_kwargs):
        raise AssertionError("disabled job endpoint must not plan")

    def fail_spawn(*_args, **_kwargs):
        raise AssertionError("disabled job endpoint must not spawn")

    monkeypatch.setattr(appmod, "plan_job", fail_plan)
    monkeypatch.setattr(appmod, "_spawn_job", fail_spawn)
    with TestClient(app) as client:
        for payload in (
            {"goal": "分析目录", "mode": "plan"},
            {"goal": "修改目录", "mode": "auto", "approval_id": 1},
        ):
            response = client.post("/v1/agent/job", headers=AUTH, json=payload)
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]

        resumed = client.post(
            "/v1/agent/job/attacker-chosen/resume",
            headers=AUTH,
            json={"mode": "plan", "approval_id": 1},
        )
        assert resumed.status_code == 503
