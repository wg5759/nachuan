from __future__ import annotations

from fastapi.testclient import TestClient

import gateway.app as app_mod
from gateway.app import _inject_followup_context
from gateway.schemas import ChatMessage

AUTH = {"Authorization": "Bearer test-key"}


def test_short_followup_gets_context_hint_for_route_messages():
    messages = [
        {"role": "user", "content": "按流程去生成今天的视频"},
        {
            "role": "assistant",
            "content": "已启动今日视频渲染。任务：ep_render_0706_143658。日志：D:\\AI视频制作\\日更\\2026-07-06\\duo_run.log",
        },
        {"role": "user", "content": "然后呢？"},
    ]

    assert _inject_followup_context(messages) is True

    assert messages[-2]["role"] == "system"
    assert "不是让你解释这个短语本身" in messages[-2]["content"]
    assert "duo_run.log" in messages[-2]["content"]
    assert messages[-1] == {"role": "user", "content": "然后呢？"}


def test_short_followup_gets_context_hint_for_chat_messages():
    messages = [
        ChatMessage(role="user", content="按流程去生成今天的视频"),
        ChatMessage(role="assistant", content="已启动今日视频渲染。完成标志：PIPELINE_DONE。"),
        ChatMessage(role="user", content="下一步呢"),
    ]

    assert _inject_followup_context(messages) is True

    assert isinstance(messages[-2], ChatMessage)
    assert messages[-2].role == "system"
    assert "PIPELINE_DONE" in str(messages[-2].content)


def test_non_followup_is_left_unchanged():
    messages = [
        {"role": "assistant", "content": "已启动今日视频渲染。"},
        {"role": "user", "content": "解释一下视频工作流的原理"},
    ]

    assert _inject_followup_context(messages) is False
    assert len(messages) == 2


def test_route_short_followup_skips_web_search(monkeypatch):
    calls = {"n": 0}

    async def fake_search(req):  # noqa: ANN001
        calls["n"] += 1
        return 0

    monkeypatch.setattr(app_mod.websearch, "maybe_augment_request", fake_search)

    with TestClient(app_mod.app) as c:
        original_routes = dict(app_mod.app.state.router._routes)
        app_mod.app.state.router._routes = {
            k: v for k, v in original_routes.items() if k == "echo"
        }
        try:
            r = c.post(
                "/v1/route",
                headers=AUTH,
                json={
                    "mode": "economy",
                    "web_search": True,
                    "messages": [
                        {"role": "assistant", "content": "已启动今日视频渲染。日志：duo_run.log"},
                        {"role": "user", "content": "然后呢？"},
                    ],
                },
            )
        finally:
            app_mod.app.state.router._routes = original_routes

    assert r.status_code == 200
    assert calls["n"] == 0
