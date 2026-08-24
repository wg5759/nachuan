"""多模态编排（#3）：意图识别 + 生图/生视频 + agent 直接产出媒体。"""

from __future__ import annotations

import asyncio

import pytest

import orchestrator.agent as agent_module
from gateway.media_call_metering import bind_paid_media_authority
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.agent import ConversationStore, agent_chat
from orchestrator.media import detect_media_intent, gen_image


@pytest.fixture
def paid_media_authority():
    """Explicit durable authority for lower-level media behavior unit tests."""

    with bind_paid_media_authority(
        principal_hash="a" * 64,
        operation="images.create",
    ):
        with bind_paid_media_authority(
            principal_hash="a" * 64,
            operation="videos.create",
        ):
            yield


def test_detect_media_intent():
    assert detect_media_intent("你能做视频吗?") is None  # 能力提问→交给对话
    assert detect_media_intent("做个猫在沙滩的视频") == "video"
    assert detect_media_intent("帮我画只猫") == "image"
    assert detect_media_intent("今天天气怎么样") is None


class _MediaProvider:
    name = "m"

    async def generate_image(self, req, upstream):  # noqa: ANN001
        return {"data": [{"url": "http://x/img.png"}]}

    async def chat(self, req, upstream):  # noqa: ANN001  (用于 polish_prompt)
        return ChatCompletionResponse.from_text(
            model=req.model, text="一只可爱的猫", usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        ).model_dump()


class _Route:
    def __init__(self, p):  # noqa: ANN001
        self.provider = p
        self.upstream_model = "x"
        self.tier = "free"


class _Router:
    def __init__(self, p):  # noqa: ANN001
        self._p = p

    def resolve(self, m):  # noqa: ANN001
        return _Route(self._p)

    def routes_info(self):
        return [{"model": "agnes-flash", "tier": "free", "provider": "a"}]


def test_gen_image(paid_media_authority):
    imgs = asyncio.run(gen_image(_Router(_MediaProvider()), "a cat"))
    assert imgs == ["http://x/img.png"]


def test_agent_generates_image_on_intent(paid_media_authority):
    res = asyncio.run(
        agent_chat(
            _Router(_MediaProvider()), ConversationStore(), message="帮我画只猫", chat_id="c", user_id="u",
            model="glm",
        )
    )
    assert res.get("images") == ["http://x/img.png"]
    assert res["agent_route"]["label"] == "image"
    assert res["outcome"] == "completed_unverified"
    assert res["blocked"] is False
    assert "img.png" in res["reply"]  # 链接也进了文字回复（飞书可点）


class _VideoProvider:
    name = "v"

    async def generate_video(self, req, upstream):  # noqa: ANN001
        return {"task_id": "vt-123"}  # 上游创建即返回任务 id，未直接给 URL

    async def chat(self, req, upstream):  # noqa: ANN001  (polish_prompt 用)
        return ChatCompletionResponse.from_text(
            model=req.model, text="一只猫在跳舞",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


def test_agent_video_async_returns_task(paid_media_authority):
    # 飞书桥用 video_async=True：只拿任务 id 立即回执，不卡几分钟、也不超时丢结果
    res = asyncio.run(
        agent_chat(
            _Router(_VideoProvider()), ConversationStore(), message="做个猫跳舞的视频", chat_id="c",
            user_id="u", model="glm", video_async=True,
        )
    )
    assert res["agent_route"]["label"] == "video"
    assert res.get("video_task") == "vt-123"  # 桥据此异步轮询
    assert res["outcome"] == "accepted_async"
    assert res["blocked"] is False
    assert "生成" in res["reply"]  # 立即回执（不阻塞）


def test_agent_rejects_async_video_before_polish_or_provider_job_when_capacity_closed(
    monkeypatch,
):
    class ForbiddenProvider:
        name = "forbidden"

        def __init__(self):
            self.chat_calls = 0
            self.video_calls = 0

        async def chat(self, req, upstream):  # noqa: ANN001
            self.chat_calls += 1
            raise AssertionError("容量关闭时不应润色视频提示词")

        async def generate_video(self, req, upstream):  # noqa: ANN001
            self.video_calls += 1
            raise AssertionError("容量关闭时不应创建上游视频任务")

    async def explicit_video_intent(*_args, **_kwargs):
        return "video"

    monkeypatch.setattr(agent_module, "classify_intent", explicit_video_intent)
    provider = ForbiddenProvider()
    store = ConversationStore()
    res = asyncio.run(
        agent_chat(
            _Router(provider),
            store,
            message="生成一段视频",
            chat_id="capacity-chat",
            user_id="capacity-user",
            model="glm",
            video_async=True,
            video_async_capacity_available=False,
        )
    )

    assert res["agent_route"]["label"] == "video_capacity"
    assert res["video_rejected"] == "capacity"
    assert res["outcome"] == "rejected_capacity"
    assert res["blocked"] is True
    assert "video_task" not in res
    assert provider.chat_calls == 0
    assert provider.video_calls == 0
    assert store.get("api:capacity-chat") == [
        {"role": "user", "content": "生成一段视频"},
        {"role": "assistant", "content": res["reply"]},
    ]
