"""飞书桥接核心：url 校验 + 消息→超级体 + 命令/白名单（mock 飞书 API + 引擎）。"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx

from bridge.feishu import FeishuBridge

TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
SEND_URL = "https://open.feishu.cn/open-apis/im/v1/messages"
AGENT_URL = "http://127.0.0.1:8080/v1/agent/chat"


@pytest.fixture(autouse=True)
def _explicit_legacy_webhook_development_opt_in(monkeypatch):
    monkeypatch.setenv("NACHUAN_ENV", "development")
    monkeypatch.setenv(
        "NACHUAN_ENABLE_LEGACY_FEISHU_WEBHOOK",
        "I_ACCEPT_PLAINTEXT_DEVELOPMENT_LOOPBACK",
    )


def test_legacy_feishu_webhook_is_fail_closed_in_production(monkeypatch):
    monkeypatch.setenv("NACHUAN_ENV", "production")
    with pytest.raises(RuntimeError, match="legacy Feishu webhook is disabled"):
        FeishuBridge("app", "sec")


def _sent_text(send) -> str:  # noqa: ANN001
    """从最后一次发消息调用里解出真正的文本（content 是被转义的 JSON 字符串）。"""
    outer = json.loads(send.calls.last.request.content)
    return json.loads(outer["content"])["text"]


def _msg_event(
    text: str,
    open_id: str = "ou_user",
    chat_id: str = "oc_1",
    message_id: str = "m-text-1",
) -> dict:
    return {
        "schema": "2.0",
        "event": {
            "sender": {"sender_id": {"open_id": open_id}},
            "message": {
                "message_type": "text",
                "message_id": message_id,
                "chat_id": chat_id,
                "content": json.dumps({"text": text}),
            },
        },
    }


async def test_feishu_url_verification():
    bridge = FeishuBridge("app", "sec", allowed_users={"ou_a"})
    async with httpx.AsyncClient() as client:
        r = await bridge.handle_event(client, {"type": "url_verification", "challenge": "abc123"})
    assert r == {"challenge": "abc123"}


@respx.mock
async def test_feishu_message_routes_to_agent():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"code": 0, "tenant_access_token": "t-xxx"})
    )
    agent = respx.post(AGENT_URL).mock(
        return_value=httpx.Response(200, json={"reply": "hi back", "model": "glm"})
    )
    send = respx.post(SEND_URL).mock(return_value=httpx.Response(200, json={"code": 0}))
    bridge = FeishuBridge("app", "sec", model="glm", allowed_users={"ou_a"})
    async with httpx.AsyncClient() as client:
        await bridge.handle_event(client, _msg_event("hello", open_id="ou_a"))
    assert agent.called
    body = json.loads(agent.calls.last.request.content)
    assert body["user_id"] == "ou_a" and body["channel"] == "feishu" and body["message"] == "hello"
    assert body["idempotency_key"].startswith("fsmsg-v1:")
    assert len(body["idempotency_key"]) == len("fsmsg-v1:") + 64
    assert "hi back" in _sent_text(send)


@respx.mock
async def test_feishu_whoami_returns_open_id():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"tenant_access_token": "t"}))
    agent = respx.post(AGENT_URL).mock(return_value=httpx.Response(200, json={"reply": "x"}))
    send = respx.post(SEND_URL).mock(return_value=httpx.Response(200, json={"code": 0}))
    bridge = FeishuBridge("app", "sec", allowed_users={"ou_a"})
    async with httpx.AsyncClient() as client:
        await bridge.handle_event(client, _msg_event("/whoami", open_id="ou_zhang"))
    assert not agent.called
    assert "ou_zhang" in _sent_text(send)


@respx.mock
async def test_feishu_whitelist_declines_stranger():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"tenant_access_token": "t"}))
    agent = respx.post(AGENT_URL).mock(return_value=httpx.Response(200, json={"reply": "x"}))
    send = respx.post(SEND_URL).mock(return_value=httpx.Response(200, json={"code": 0}))
    bridge = FeishuBridge("app", "sec", allowed_users={"ou_owner"})
    async with httpx.AsyncClient() as client:
        await bridge.handle_event(client, _msg_event("hi", open_id="ou_stranger"))
    assert not agent.called  # 未授权 → 不消耗模型额度
    assert "未被授权" in _sent_text(send)


@respx.mock
async def test_feishu_audio_transcribes_and_replies():
    """D4：语音消息 → 下载 → 转写 → 喂给超级体 → 回复（含转写文本）。"""
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"tenant_access_token": "t"}))
    dl = respx.get(url__regex=r".+/messages/m1/resources/fk1.*").mock(
        return_value=httpx.Response(200, content=b"audio-bytes")
    )
    tr = respx.post("http://127.0.0.1:8080/v1/audio/transcriptions").mock(
        return_value=httpx.Response(200, json={"text": "你好机器人"})
    )
    agent = respx.post(AGENT_URL).mock(
        return_value=httpx.Response(200, json={"reply": "在的，有什么可以帮你"})
    )
    send = respx.post(SEND_URL).mock(return_value=httpx.Response(200, json={"code": 0}))
    evt = {
        "schema": "2.0",
        "event": {
            "sender": {"sender_id": {"open_id": "ou_a"}},
            "message": {
                "message_type": "audio",
                "chat_id": "oc_1",
                "message_id": "m1",
                "content": json.dumps({"file_key": "fk1"}),
            },
        },
    }
    bridge = FeishuBridge("app", "sec", allowed_users={"ou_a"})
    async with httpx.AsyncClient() as client:
        await bridge.handle_event(client, evt)
    assert dl.called and tr.called and agent.called
    agent_body = json.loads(agent.calls.last.request.content)
    assert agent_body["message"] == "你好机器人"  # 转写后喂入
    assert agent_body["idempotency_key"].startswith("fsmsg-v1:")
    out = _sent_text(send)
    assert "你好机器人" in out and "在的" in out


@respx.mock
async def test_feishu_image_acknowledged():
    """D4：图片消息 → 确认收到（不调模型）。"""
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"tenant_access_token": "t"}))
    agent = respx.post(AGENT_URL).mock(return_value=httpx.Response(200, json={"reply": "x"}))
    send = respx.post(SEND_URL).mock(return_value=httpx.Response(200, json={"code": 0}))
    evt = {
        "schema": "2.0",
        "event": {
            "sender": {"sender_id": {"open_id": "ou_a"}},
            "message": {
                "message_type": "image",
                "chat_id": "oc_1",
                "message_id": "m2",
                "content": json.dumps({"image_key": "ik1"}),
            },
        },
    }
    bridge = FeishuBridge("app", "sec", allowed_users={"ou_a"})
    async with httpx.AsyncClient() as client:
        await bridge.handle_event(client, evt)
    assert not agent.called
    assert "收到文件/图片" in _sent_text(send)


def _load_feishu_runner():
    path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
    spec = importlib.util.spec_from_file_location("run_feishu_bridge_media_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_feishu_runner_generated_media_uses_pinned_helper_and_data_cap(monkeypatch):
    runner = _load_feishu_runner()
    captured = {}

    def fake_fetch(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return SimpleNamespace(data=b"image")

    monkeypatch.setattr(runner, "fetch_public_bytes", fake_fetch)
    assert runner._download_url("https://media.example/image.png", "image") == b"image"
    assert captured["kwargs"]["max_bytes"] == 20 * 1024 * 1024
    assert captured["kwargs"]["allowed_type_prefixes"] == ("image/",)
    assert captured["kwargs"]["total_timeout"] == 120.0

    monkeypatch.setattr(runner, "_MAX_GENERATED_IMAGE_BYTES", 8)
    decoded = False

    def fail_decode(*_args, **_kwargs):
        nonlocal decoded
        decoded = True
        raise AssertionError("oversized base64 must be rejected before decode")

    monkeypatch.setattr(runner.base64, "b64decode", fail_decode)
    oversized = "data:image/png;base64," + base64.b64encode(b"x" * 100).decode()
    with pytest.raises(ValueError, match="大小上限"):
        runner._download_url(oversized, "image")
    assert decoded is False


def test_feishu_runner_resource_stream_is_bounded_and_raw_content_fails_closed(monkeypatch):
    runner = _load_feishu_runner()
    monkeypatch.setattr(runner, "_MAX_INBOUND_IMAGE_BYTES", 8)

    class ResourceAPI:
        response = None

        def get(self, _request):
            return self.response

    api = ResourceAPI()
    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(v1=SimpleNamespace(message_resource=api))
    )

    class OversizedStream:
        headers = {"Content-Type": "image/png"}

        def __init__(self):
            self.remaining = 9

        def read(self, size):
            count = min(size, self.remaining)
            self.remaining -= count
            return b"x" * count

    api.response = SimpleNamespace(file=OversizedStream(), raw=None, headers=None)
    with pytest.raises(ValueError, match="大小上限"):
        runner._download_resource("m1", "k1", "image", media_kind="image")

    api.response = SimpleNamespace(
        file=None,
        raw=SimpleNamespace(content=b"already-buffered", headers={"content-type": "image/png"}),
        headers=None,
    )
    with pytest.raises(ValueError, match="可限量读取"):
        runner._download_resource("m1", "k1", "image", media_kind="image")


@respx.mock
async def test_feishu_webhook_audio_download_rejects_declared_oversize(monkeypatch):
    import bridge.feishu as feishu_module

    monkeypatch.setattr(feishu_module, "_MAX_AUDIO_BYTES", 8)
    route = respx.get(url__regex=r".+/messages/m1/resources/fk1.*").mock(
        return_value=httpx.Response(
            200,
            content=b"123456789",
            headers={"content-type": "audio/ogg", "content-length": "9"},
        )
    )
    bridge = FeishuBridge("app", "sec")
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="大小上限"):
            await bridge._download(client, "m1", "fk1", "file", "token")
    assert route.called
