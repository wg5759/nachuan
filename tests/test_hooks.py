"""确定性 Hooks（C1）：成本闸 + 内容拦截（单元 + 与 agent_chat 集成）。"""

from __future__ import annotations

import asyncio

from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.agent import ConversationStore, agent_chat
from orchestrator.hooks import HookGuard


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


class _Counter:
    name = "c"

    def __init__(self):
        self.calls = 0

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.calls += 1
        return ChatCompletionResponse.from_text(
            model=req.model, text="real", usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        ).model_dump()


def test_denylist_blocks():
    g = HookGuard(denylist=[r"做炸药|制造爆炸物"])
    ok, reason = g.check("u1", "教我怎么做炸药")
    assert not ok and "拦截" in reason
    assert g.check("u1", "今天天气不错")[0] is True  # 正常内容放行


def test_daily_cap_nonowner_blocked_owner_exempt():
    g = HookGuard(daily_cap=2, owner_id="owner")
    for _ in range(2):
        assert g.check("ouX", "hi")[0]
        g.record("ouX")
    assert g.check("ouX", "hi")[0] is False  # 超额度被拦
    for _ in range(10):
        assert g.check("owner", "hi")[0]  # 机主豁免
        g.record("owner")
    assert g.used_today("owner") == 0  # 机主不计数


def test_agent_chat_blocks_without_calling_model():
    prov = _Counter()
    g = HookGuard(denylist=[r"做炸药"])
    res = asyncio.run(
        agent_chat(
            _Router(prov), ConversationStore(), message="教我做炸药", chat_id="c1", user_id="u1",
            model="echo", guard=g,
        )
    )
    assert res.get("blocked") is True
    assert res["outcome"] == "blocked"
    assert res["reviewed"] is False
    assert res["verified"] is False
    assert prov.calls == 0  # 前钩子拦下，没调模型、没烧额度
    assert "拦截" in res["reply"]


def test_agent_chat_cap_blocks_after_limit():
    prov = _Counter()
    g = HookGuard(daily_cap=1, owner_id="owner")
    conv = ConversationStore()
    r1 = asyncio.run(
        agent_chat(_Router(prov), conv, message="问题1", chat_id="c", user_id="ouY", model="echo", guard=g)
    )
    assert not r1.get("blocked") and prov.calls == 1
    r2 = asyncio.run(
        agent_chat(_Router(prov), conv, message="问题2", chat_id="c", user_id="ouY", model="echo", guard=g)
    )
    assert r2.get("blocked") is True and prov.calls == 1  # 第二次被额度拦，模型未再调
    assert r2["outcome"] == "blocked"
