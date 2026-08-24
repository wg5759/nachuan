from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from bridge.access import ChannelAccessPolicy, explicit_development_allow_all
from bridge.telegram import TelegramBridge


def _load_weixin_bridge():
    path = Path(__file__).parents[1] / "scripts" / "run_weixin_ilink_bridge.py"
    spec = importlib.util.spec_from_file_location("run_weixin_access_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_allow_all_requires_both_development_mode_and_explicit_channel_opt_in():
    assert not explicit_development_allow_all(
        "WEIXIN", {"NACHUAN_ENV": "production", "WEIXIN_ALLOW_ALL": "1"}
    )
    assert not explicit_development_allow_all("WEIXIN", {"NACHUAN_ENV": "development"})
    assert explicit_development_allow_all(
        "WEIXIN", {"NACHUAN_ENV": "development", "WEIXIN_ALLOW_ALL": "true"}
    )


@pytest.mark.asyncio
async def test_telegram_is_fail_closed_but_whoami_remains_available_for_onboarding():
    bridge = TelegramBridge("synthetic-bot-token", access=ChannelAccessPolicy(set()))
    bridge._engine_chat = AsyncMock(return_value="should not run")
    bridge._send = AsyncMock()
    client = object()

    await bridge.handle_update(
        client,
        {"message": {"text": "你好", "chat": {"id": 11}, "from": {"id": 22}}},
    )
    bridge._engine_chat.assert_not_awaited()
    bridge._send.assert_not_awaited()

    await bridge.handle_update(
        client,
        {"message": {"text": "/whoami", "chat": {"id": 11}, "from": {"id": 22}}},
    )
    bridge._send.assert_awaited_once_with(client, 11, "你的 Telegram 标识：22")


@pytest.mark.asyncio
async def test_telegram_allowlist_routes_only_the_authorized_sender_to_engine():
    bridge = TelegramBridge(
        "synthetic-bot-token", access=ChannelAccessPolicy({"22"})
    )
    bridge._engine_chat = AsyncMock(return_value="ok")
    bridge._send = AsyncMock()

    await bridge.handle_update(
        object(),
        {"message": {"text": "你好", "chat": {"id": 11}, "from": {"id": 22}}},
    )

    bridge._engine_chat.assert_awaited_once()


def test_weixin_is_fail_closed_but_whoami_remains_available(monkeypatch):
    bridge = _load_weixin_bridge()
    monkeypatch.setattr(bridge, "ACCESS", ChannelAccessPolicy(set()))
    monkeypatch.setattr(bridge, "_extract_items", lambda _msg: ("你好", None, False))
    engine = AsyncMock()
    delivered: list[str] = []
    monkeypatch.setattr(bridge, "_agent_chat", engine)
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: delivered.append(text),
    )

    bridge._handle({"from_user_id": "wx-22", "context_token": "ctx"}, "token")
    assert delivered == [
        "纳川微信当前处于安全锁定状态，本消息没有调用模型。"
        "请先发送 /whoami 获取微信标识，再由管理员加入白名单。"
    ]
    assert engine.call_count == 0

    delivered.clear()
    monkeypatch.setattr(bridge, "_extract_items", lambda _msg: ("/whoami", None, False))
    bridge._handle({"from_user_id": "wx-22", "context_token": "ctx"}, "token")
    assert delivered == ["你的微信标识：wx-22"]
