"""Telegram 桥接：消息处理逻辑（mock 引擎 + Telegram API）。"""

from __future__ import annotations

import json

import httpx
import respx

from bridge.telegram import TelegramBridge
from bridge.access import ChannelAccessPolicy


@respx.mock
async def test_handle_update_chats_and_replies():
    engine = respx.post("http://127.0.0.1:8080/v1/agent/chat").mock(
        return_value=httpx.Response(200, json={"reply": "hi back"})
    )
    send = respx.post("https://api.telegram.org/botTOK/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bridge = TelegramBridge("TOK", model="glm", access=ChannelAccessPolicy({"123"}))
    async with httpx.AsyncClient() as client:
        await bridge.handle_update(
            client,
            {"message": {"text": "hello", "chat": {"id": 123}, "from": {"id": 123}}},
        )
    assert send.called
    request = json.loads(engine.calls.last.request.content)
    assert request == {
        "message": "hello",
        "chat_id": "123",
        "user_id": "123",
        "channel": "telegram",
        "model": "glm",
    }
    sent = json.loads(send.calls.last.request.content)
    assert sent["chat_id"] == 123
    assert "hi back" in sent["text"]


@respx.mock
async def test_model_command_switches_model():
    respx.get("http://127.0.0.1:8080/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "claude-sonnet"}]})
    )
    send = respx.post("https://api.telegram.org/botTOK/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bridge = TelegramBridge("TOK", model="glm", access=ChannelAccessPolicy({"1"}))
    async with httpx.AsyncClient() as client:
        await bridge.handle_update(
            client,
            {"message": {"text": "/model claude-sonnet", "chat": {"id": 1}, "from": {"id": 1}}},
        )
    assert bridge.model == "glm"  # 默认值不再被某个会话全局改写
    assert bridge._model_for(1, 1) == "claude-sonnet"
    assert bridge._model_for(2, 1) == "glm"
    assert bridge._model_for(1, 2) == "glm"
    assert send.called


@respx.mock
async def test_model_command_rejects_unknown_model_without_changing_session():
    respx.get("http://127.0.0.1:8080/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "glm"}]})
    )
    send = respx.post("https://api.telegram.org/botTOK/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bridge = TelegramBridge("TOK", model="glm", access=ChannelAccessPolicy({"1"}))

    async with httpx.AsyncClient() as client:
        await bridge.handle_update(
            client,
            {"message": {"text": "/model attacker-model", "chat": {"id": 1}, "from": {"id": 1}}},
        )

    assert bridge._model_for(1, 1) == "glm"
    sent = json.loads(send.calls.last.request.content)
    assert sent["text"] == "模型不可用：attacker-model"


@respx.mock
async def test_session_model_is_used_only_for_the_matching_chat_and_sender():
    respx.get("http://127.0.0.1:8080/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "glm"}, {"id": "claude-sonnet"}]})
    )
    engine = respx.post("http://127.0.0.1:8080/v1/agent/chat").mock(
        return_value=httpx.Response(200, json={"reply": "ok"})
    )
    respx.post("https://api.telegram.org/botTOK/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bridge = TelegramBridge("TOK", model="glm", access=ChannelAccessPolicy({"1", "2"}))

    async with httpx.AsyncClient() as client:
        await bridge.handle_update(
            client,
            {"message": {"text": "/model claude-sonnet", "chat": {"id": 10}, "from": {"id": 1}}},
        )
        await bridge.handle_update(
            client,
            {"message": {"text": "one", "chat": {"id": 10}, "from": {"id": 1}}},
        )
        await bridge.handle_update(
            client,
            {"message": {"text": "two", "chat": {"id": 10}, "from": {"id": 2}}},
        )
        await bridge.handle_update(
            client,
            {"message": {"text": "three", "chat": {"id": 11}, "from": {"id": 1}}},
        )

    payloads = [json.loads(call.request.content) for call in engine.calls]
    assert [payload["model"] for payload in payloads] == ["claude-sonnet", "glm", "glm"]


@respx.mock
async def test_session_model_cache_is_bounded_lru_via_real_handlers():
    respx.get("http://127.0.0.1:8080/v1/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "model-a"}, {"id": "model-b"}, {"id": "model-c"}]},
        )
    )
    engine = respx.post("http://127.0.0.1:8080/v1/agent/chat").mock(
        return_value=httpx.Response(200, json={"reply": "ok"})
    )
    respx.post("https://api.telegram.org/botTOK/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    bridge = TelegramBridge(
        "TOK",
        model="default",
        access=ChannelAccessPolicy({"1", "2", "3"}),
        max_session_models=2,
    )

    async with httpx.AsyncClient() as client:
        await bridge.handle_update(
            client,
            {"message": {"text": "/model model-a", "chat": {"id": 10}, "from": {"id": 1}}},
        )
        await bridge.handle_update(
            client,
            {"message": {"text": "/model model-b", "chat": {"id": 20}, "from": {"id": 2}}},
        )
        # A real chat hits session 10, making it newer than session 20.
        await bridge.handle_update(
            client,
            {"message": {"text": "touch", "chat": {"id": 10}, "from": {"id": 1}}},
        )
        await bridge.handle_update(
            client,
            {"message": {"text": "/model model-c", "chat": {"id": 30}, "from": {"id": 3}}},
        )

    touch_payload = json.loads(engine.calls.last.request.content)
    assert touch_payload["model"] == "model-a"
    assert bridge._model_for(10, 1) == "model-a"
    assert bridge._model_for(20, 2) == "default"
    assert bridge._model_for(30, 3) == "model-c"
    assert len(bridge._session_models) == 2


async def test_ignores_non_text_update():
    bridge = TelegramBridge("TOK")
    async with httpx.AsyncClient() as client:
        # 无 text 不应抛错、不发送
        await bridge.handle_update(client, {"message": {"chat": {"id": 1}}})
