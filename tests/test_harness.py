"""厚 Harness 模式（B1）：规划→实现→评估→重试→升级（自适应弱模型增强）。"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.modes import run_harness

AUTH = {"Authorization": "Bearer test-key"}
HARD = "请设计一个高并发短链系统并给出关键取舍"


class _Route:
    def __init__(self, p):  # noqa: ANN001
        self.provider = p
        self.upstream_model = "x"
        self.tier = "free"


class _Router:
    def __init__(self, p):  # noqa: ANN001
        self._p = p

    def resolve(self, m):  # noqa: ANN001
        return _Route(self._p) if m else None

    def routes_info(self):
        return [
            {"model": "gpt-5.5", "tier": "premium", "provider": "p"},
            {"model": "agnes-flash", "tier": "free", "provider": "a"},
        ]


class _Scripted:
    """按提示词角色返回 planner / generator / evaluator；verdict 控制评估判定。"""

    name = "s"

    def __init__(self, verdict):  # noqa: ANN001
        self.verdict = verdict
        self.calls = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        last = req.messages[-1].content
        self.calls.append(req.model)
        if "找茬" in last:
            out = self.verdict
        elif "解题计划" in last:
            out = "1. 拆分\n2. 实现\n3. 验证"
        else:
            out = f"答案by{req.model}"
        return ChatCompletionResponse.from_text(
            model=req.model, text=out, usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        ).model_dump()


def test_harness_weak_succeeds():
    prov = _Scripted("OK")
    r = asyncio.run(run_harness(_Router(prov), [{"role": "user", "content": HARD}]))
    assert r["_route"]["mode"] == "harness"
    assert r["_route"]["escalated"] is False
    assert r["_route"]["model"] == "agnes-flash"  # 弱模型搞定
    assert r["_route"]["rounds"] == 1
    assert "gpt-5.5" not in prov.calls  # 没烧强模型


def test_harness_escalates_to_strong():
    prov = _Scripted("NEEDS_WORK: 漏了限流与热点 key")
    r = asyncio.run(run_harness(_Router(prov), [{"role": "user", "content": HARD}]))
    assert r["_route"]["escalated"] is True
    assert r["_route"]["model"] == "gpt-5.5"  # 弱模型两轮不过 → 升级强模型
    assert "gpt-5.5" in prov.calls


def test_harness_http_route_is_isolated_from_persisted_connections():
    with TestClient(app) as c:
        real_router = c.app.state.router
        try:
            c.app.state.router = _Router(_Scripted("OK"))
            r = c.post(
                "/v1/route",
                headers=AUTH,
                json={"mode": "harness", "messages": [{"role": "user", "content": "你好"}]},
            )
        finally:
            # Lifespan shutdown must close the real Router it created.
            c.app.state.router = real_router
        assert r.status_code == 200
        d = r.json()
        assert d["_route"]["mode"] == "harness"
        assert d["choices"][0]["message"]["content"]
