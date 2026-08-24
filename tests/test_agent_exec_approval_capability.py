from __future__ import annotations

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app


AUTH = {"Authorization": "Bearer test-key"}


def _assert_native_exec_closed(monkeypatch, payload: dict) -> None:
    calls: list[str] = []

    async def fake_exec(_router, task, **_kwargs):
        calls.append(task)
        return {"result": "must never run", "backend": "codex"}

    monkeypatch.setattr(appmod, "_run_agent_exec", fake_exec)
    with TestClient(app) as client:
        response = client.post("/v1/agent/exec", headers=AUTH, json=payload)

    assert response.status_code == 503
    assert "低权限" in response.json()["detail"]
    assert calls == []


def test_approved_boolean_cannot_reopen_native_exec(monkeypatch):
    _assert_native_exec_closed(
        monkeypatch,
        {"task": "删除生产数据库", "user_id": "cap-user", "approved": True},
    )


def test_approval_id_cannot_reopen_native_exec(monkeypatch):
    _assert_native_exec_closed(
        monkeypatch,
        {
            "task": "删除生产数据库",
            "user_id": "cap-user-2",
            "approval_id": "forged-or-stale-approval",
        },
    )


def test_full_permission_mode_cannot_reopen_native_exec(monkeypatch):
    _assert_native_exec_closed(
        monkeypatch,
        {"task": "整理文件", "user_id": "cap-user-3", "mode": "full"},
    )
