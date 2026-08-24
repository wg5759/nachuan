"""M4 协作编排：panel_judge（用 echo 实测，无需外部模型）。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app

AUTH = {"Authorization": "Bearer test-key"}


def test_panel_rejects_duplicate_and_self_judge_routes():
    with TestClient(app) as c:
        r = c.post(
            "/v1/orchestrate/panel",
            headers=AUTH,
            json={"prompt": "你好", "panelists": ["echo", "echo"], "judge": "echo"},
        )
        assert r.status_code == 422


def test_panel_unknown_panelist():
    with TestClient(app) as c:
        r = c.post(
            "/v1/orchestrate/panel",
            headers=AUTH,
            json={"prompt": "x", "panelists": ["does-not-exist"], "judge": "echo"},
        )
        assert r.status_code == 200
        d = r.json()
        assert d["panelists"][0]["error"]  # 未知模型记录错误
        assert d.get("error")  # 全失败 → 顶层 error


def test_panel_validation():
    with TestClient(app) as c:
        r = c.post("/v1/orchestrate/panel", headers=AUTH, json={"prompt": "x"})
        assert r.status_code == 422  # 缺 panelists/judge
