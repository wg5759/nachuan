"""消息渠道的复杂纯文本应进入无副作用的多模型 advisory 编排。"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from gateway.schemas import ChatCompletionResponse, Usage
from gateway.model_identity import exact_verified_model_identity
from gateway.provider_call_ledger import configured_provider_call_ledger
import orchestrator.agent as agent_module
from orchestrator import modes as orchestration_modes
from orchestrator import scoreboard
from orchestrator.agent import ConversationStore, agent_chat, session_key
from tests.review_fixtures import trusted_chat_result


class _CallLog:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.review_calls = 0
        self.review_failures_before_pass = 0


class _AdvisoryProvider:
    def __init__(self, name: str, log: _CallLog, domain: str) -> None:
        self.name = name
        self.log = log
        self.independence_domain = domain

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return exact_verified_model_identity(upstream_model, observed_model)

    async def chat(self, req, _upstream_model):  # noqa: ANN001
        messages = [m.model_dump(exclude_none=True) for m in req.messages]
        self.log.calls.append(
            {"model": req.model, "messages": messages, "tools": req.model_dump().get("tools") or []}
        )
        text = "\n".join(str(m.get("content") or "") for m in messages)
        if "模型舰队的调度器" in text:
            if "worker(channel-worker)" in text:
                answer = json.dumps(
                    {"model": "channel-reviewer", "role": "verifier", "instruction": "独立验收"}
                )
            else:
                answer = json.dumps(
                    {"model": "channel-worker", "role": "worker", "instruction": "综合分析并提出方案"}
                )
        elif "你是独立审核官" in text or "请独立严格评分" in text:
            self.log.review_calls += 1
            if self.log.review_calls <= self.log.review_failures_before_pass:
                answer = "FAIL:还缺少关键验收证据"
            else:
                answer = "论证完整且满足要求。\nPASS"
        else:
            answer = "这是经过多模型协作形成的复杂架构分析。"
        return ChatCompletionResponse.from_text(
            model=_upstream_model,
            text=answer,
            usage=Usage(prompt_tokens=5, completion_tokens=3, total_tokens=8),
        ).model_dump()


class _Route:
    def __init__(
        self,
        virtual_model: str,
        provider: _AdvisoryProvider,
        upstream_model: str,
        model_family: str,
        tier: str,
    ) -> None:
        self.virtual_model = virtual_model
        self.provider = provider
        self.upstream_model = upstream_model
        self.model_family = model_family
        self.independence_domain = provider.independence_domain
        self.tier = tier
        self.flagship = False


class _AdvisoryRouter:
    def __init__(self) -> None:
        self.log = _CallLog()
        specs = [
            ("channel-cheap", "cheap-vendor", "qwen-turbo", "alibaba-qwen", "cheap"),
            ("channel-worker", "worker-vendor", "gpt-4o", "openai", "premium"),
            ("channel-reviewer", "review-vendor", "claude-sonnet-4-6", "anthropic", "premium"),
            ("channel-reviewer-2", "review-vendor-2", "gemini-2.5-pro", "google-gemini", "premium"),
            ("channel-reviewer-3", "review-vendor-3", "deepseek-v3", "deepseek", "premium"),
        ]
        self._routes = {}
        for model, provider_name, upstream, family, tier in specs:
            domain = "sha256:" + hashlib.sha256(provider_name.encode()).hexdigest()
            provider = _AdvisoryProvider(provider_name, self.log, domain)
            self._routes[model] = _Route(
                model, provider, upstream, family, tier
            )

    def resolve(self, model):  # noqa: ANN001
        return self._routes.get(model)

    def routes_info(self) -> list[dict[str, Any]]:
        rows = []
        for rank, (model, route) in enumerate(self._routes.items(), start=1):
            rows.append({
                "model": model,
                "provider": route.provider.name,
                "upstream_model": route.upstream_model,
                "model_family": route.model_family,
                "independence_domain": route.independence_domain,
                "tier": route.tier,
                "rank": rank,
                "flagship": route.flagship,
            })
        return rows

    def list_models(self) -> list[dict[str, Any]]:
        return [
            {"id": row["model"], "owned_by": row["provider"], "tier": row["tier"],
             "modality": "chat", "description": "测试模型"}
            for row in self.routes_info()
        ]


class _Memory:
    def search(self, _user_id: str, _query: str) -> list[dict[str, str]]:
        return [{"text": "用户偏好中文回答"}]


@pytest.fixture(autouse=True)
def _isolated_scoreboard(monkeypatch, tmp_path: Path):  # noqa: ANN001
    monkeypatch.setattr(scoreboard, "_db_path", lambda: str(tmp_path / "scoreboard.db"))
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv(
        "NACHUAN_PROVIDER_CALL_LEDGER_PATH",
        str(tmp_path / "provider-calls.db"),
    )
    provider_ledger = configured_provider_call_ledger()
    scoreboard.reset()
    yield
    scoreboard.reset()
    provider_ledger.close()


async def test_complex_channel_chat_uses_reviewed_multi_model_advisory_without_write_tools() -> None:
    router = _AdvisoryRouter()
    store = ConversationStore()
    key = session_key("weixin", "chat-1")
    store.append(key, "user", "上一轮我在讨论缓存一致性")
    store.append(key, "assistant", "我们已经确认需要比较一致性模型")

    result = await agent_chat(
        router,
        store,
        message="请分析这个复杂系统架构为什么会出现一致性问题，并给出严谨的权衡方案",
        chat_id="chat-1",
        channel="weixin",
        user_id="owner",
        model="channel-cheap",
        persona="你是纳川，不得暴露内部模型身份",
        memory=_Memory(),
    )

    called_models = [c["model"] for c in router.log.calls]
    assert "channel-worker" in called_models
    assert "channel-reviewer" in called_models
    assert result["orchestration_mode"] == "org"
    assert result["reviewed"] is True
    assert result["verified"] is False
    assert result["outcome"] == "completed_unverified"

    execution_call = next(
        c
        for c in router.log.calls
        if c["model"] == "channel-cheap"
        and any("执行规格" in str(m.get("content") or "") for m in c["messages"])
    )
    context = "\n".join(str(m.get("content") or "") for m in execution_call["messages"])
    assert "你是纳川，不得暴露内部模型身份" in context
    assert "上一轮我在讨论缓存一致性" in context
    assert "用户偏好中文回答" in context
    tool_names = {
        tool.get("function", {}).get("name")
        for tool in execution_call["tools"]
        if isinstance(tool, dict)
    }
    assert not tool_names & {"write_file", "run_command", "browser_click", "browser_type", "browser_upload"}


async def test_simple_channel_greeting_stays_on_single_model_fast_path() -> None:
    router = _AdvisoryRouter()

    result = await agent_chat(
        router,
        ConversationStore(),
        message="你好",
        chat_id="chat-fast",
        channel="weixin",
        user_id="owner",
        model="channel-cheap",
        persona="你是纳川，简洁回答。",
    )

    assert [call["model"] for call in router.log.calls] == ["channel-cheap"]
    assert router.log.calls[0]["tools"] == []
    assert result["orchestration_mode"] == "single"
    assert result["verified"] is None
    assert result["outcome"] == "completed_unverified"


async def test_escalated_advisory_final_answer_is_still_independently_reviewed() -> None:
    router = _AdvisoryRouter()
    router.log.review_failures_before_pass = 2

    result = await agent_chat(
        router,
        ConversationStore(),
        message="请完整分析跨地域多活架构的一致性、容灾和成本取舍，并给出验收标准",
        chat_id="chat-escalated-review",
        channel="weixin",
        user_id="owner",
        model="channel-cheap",
        persona="你是纳川，不得暴露内部模型身份。",
    )

    assert router.log.review_calls == 3
    assert result["agent_route"]["orchestration"]["escalated"] is True
    assert result["agent_route"]["orchestration"]["reviewed"] is True
    assert result["agent_route"]["orchestration"]["verified"] is False
    assert result["reviewed"] is True
    assert result["verified"] is False
    assert result["outcome"] == "completed_unverified"


async def test_review_pass_from_initiator_fallback_has_zero_vote(monkeypatch) -> None:  # noqa: ANN001
    router = _AdvisoryRouter()
    review_served_by: list[str] = []

    async def fake_chat_with_fallback(_router, req, **_kwargs):  # noqa: ANN001
        text = "\n".join(str(message.content or "") for message in req.messages)
        if "你是独立审核官" in text or "请独立严格评分" in text:
            # Simulate the requested reviewer failing over to the initiating
            # planner. A textual PASS from that route must carry zero vote.
            served = "channel-worker"
            answer = "PASS"
            review_served_by.append(served)
        elif "执行规格（要点 + 验收标准），不要作答" in text:
            served = "channel-worker"
            answer = "1. 分析\n2. 验收"
        elif req.model == "channel-cheap":
            served = "channel-cheap"
            answer = "执行员草稿"
        else:
            served = "channel-worker"
            answer = "规划模型升级答案"
        response = ChatCompletionResponse.from_text(
            model=router.resolve(served).upstream_model,
            text=answer,
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()
        route = router.resolve(served)
        return trusted_chat_result(
            request_payload=req.model_dump(exclude_none=True),
            response=response,
            requested_model=req.model,
            actual_model=served,
            route=route,
        )

    monkeypatch.setattr(orchestration_modes, "chat_with_fallback", fake_chat_with_fallback)

    result = await orchestration_modes.run_org(
        router,
        [{"role": "user", "content": "分析一个复杂多活系统"}],
    )

    assert len(review_served_by) == 3
    assert set(review_served_by) == {"channel-worker"}
    assert result["_route"]["reviewer_independent"] is False
    assert result["_route"]["initiator_vote_weight"] == 0
    assert result["_route"]["reviewer_vote_weight"] == 0
    assert result["_route"]["verified"] is False


async def test_advisory_shared_deadline_returns_honest_partial(monkeypatch) -> None:  # noqa: ANN001
    seen = {"deadline": None}

    async def fake_org(router, messages, *, wall_deadline=None):  # noqa: ANN001
        seen["deadline"] = wall_deadline
        raise asyncio.TimeoutError

    monkeypatch.setattr(agent_module, "run_org", fake_org)

    result = await agent_module.run_advisory_chat(
        _AdvisoryRouter(),
        [{"role": "user", "content": "复杂任务"}],
        total_timeout=1,
    )

    assert seen["deadline"] is not None
    assert result["reviewed"] is False
    assert result["verified"] is False
    assert result["machine_verified"] is False
    assert result["outcome"] == "partial"
    assert result["route"]["timed_out"] is True
