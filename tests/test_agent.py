"""超级智能体 M1：多轮对话记忆（单元实测 + HTTP 实测）。"""

from __future__ import annotations

import asyncio
import hashlib
import threading

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.model_identity import exact_verified_model_identity
from gateway.schemas import ChatCompletionResponse, Usage
import orchestrator.agent as agent_module
from orchestrator.agent import ConversationStore, agent_chat

AUTH = {"Authorization": "Bearer test-key"}


class _RecordingProvider:
    """记录每次收到的 messages，用于断言“历史确实带给了模型”。"""

    name = "rec"

    def __init__(self) -> None:
        self.seen: list[list[dict[str, str]]] = []
        self.seen_models: list[str] = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.seen_models.append(req.model)
        self.seen.append([{"role": m.role, "content": m.content} for m in req.messages])
        last = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
        return ChatCompletionResponse.from_text(
            model=req.model,
            text=f"got:{last}",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


class _FakeRoute:
    def __init__(self, provider) -> None:  # noqa: ANN001
        self.provider = provider
        self.upstream_model = "x"
        self.tier = "cheap"
        self.modality = "chat"
        self.exec_backend = ""


class _FakeRouter:
    def __init__(self, provider) -> None:  # noqa: ANN001
        self._p = provider

    def resolve(self, model):  # noqa: ANN001
        return _FakeRoute(self._p)

    def routes_info(self):
        return [
            {
                "model": "test-chat",
                "provider": self._p.name,
                "tier": "cheap",
                "modality": "chat",
                "rank": 1,
            }
        ]


class _AttributedProvider(_RecordingProvider):
    name = "attributed-provider"

    def __init__(self) -> None:
        super().__init__()
        self.independence_domain = (
            "sha256:" + hashlib.sha256(self.name.encode()).hexdigest()
        )

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.seen.append([{"role": m.role, "content": m.content} for m in req.messages])
        last = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
        return ChatCompletionResponse.from_text(
            model=upstream_model,
            text=f"got:{last}",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return exact_verified_model_identity(upstream_model, observed_model)


class _AttributedRouter:
    def __init__(self) -> None:
        self.provider = _AttributedProvider()

    def resolve(self, model):  # noqa: ANN001, ANN201
        if model != "attributed-chat":
            return None
        return type("AttributedRoute", (), {
            "virtual_model": "attributed-chat",
            "provider": self.provider,
            "upstream_model": "gpt-4o",
            "model_family": "openai",
            "independence_domain": self.provider.independence_domain,
            "tier": "cheap",
            "flagship": False,
            "modality": "chat",
            "exec_backend": "",
        })()

    def routes_info(self):  # noqa: ANN201
        route = self.resolve("attributed-chat")
        return [{
            "model": "attributed-chat",
            "provider": route.provider.name,
            "upstream_model": route.upstream_model,
            "model_family": route.model_family,
            "independence_domain": route.independence_domain,
            "tier": route.tier,
            "flagship": route.flagship,
            "modality": route.modality,
            "rank": 1,
        }]


def test_agent_multi_turn_passes_history():
    """第二轮调用里，模型应能看到第一轮的用户问题与助手回复。"""
    prov = _RecordingProvider()
    router = _FakeRouter(prov)
    store = ConversationStore()

    async def run():
        await agent_chat(router, store, message="我叫小明，记住", chat_id="t", model="echo")
        return await agent_chat(router, store, message="我叫什么名字？", chat_id="t", model="echo")

    r2 = asyncio.run(run())

    second = prov.seen[1]
    contents = [m["content"] for m in second]
    assert "我叫小明，记住" in contents  # 第一轮用户消息在场
    assert any(c.startswith("got:") for c in contents)  # 第一轮助手回复在场
    assert second[-1]["content"] == "我叫什么名字？"  # 末尾是本轮问题
    assert r2["turns"] == 2


def test_agent_sessions_are_isolated():
    """不同 chat_id 的历史互不串台。"""
    prov = _RecordingProvider()
    router = _FakeRouter(prov)
    store = ConversationStore()

    async def run():
        await agent_chat(router, store, message="A 的秘密", chat_id="a", model="echo")
        await agent_chat(router, store, message="B 在说话", chat_id="b", model="echo")

    asyncio.run(run())
    b_msgs = [m["content"] for m in prov.seen[1]]
    assert "A 的秘密" not in b_msgs  # b 会话看不到 a 的内容
    assert b_msgs[-1] == "B 在说话"


def test_agent_chat_model_lock_keeps_the_operator_selected_model(monkeypatch):
    provider = _RecordingProvider()

    def prefer_cheap_model(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        return {
            "model": "case-router-cheap",
            "label": "cheap",
            "case": None,
            "store": False,
        }

    monkeypatch.setattr(agent_module, "decide_route", prefer_cheap_model)
    result = asyncio.run(
        agent_chat(
            _FakeRouter(provider),
            ConversationStore(),
            message="必须使用我在界面选中的模型",
            chat_id="explicit-model-unit",
            user_id="owner",
            model="operator-selected",
            model_locked=True,
            cases=object(),
        )
    )

    assert result["model"] == "operator-selected"


def test_agent_read_only_dependencies_never_block_the_event_loop():
    """Slow local reads must remain cancellable by the channel wall deadline."""

    async def assert_off_loop(kind: str) -> None:
        started = threading.Event()
        release = threading.Event()

        def block_once() -> None:
            started.set()
            release.wait(timeout=1.0)

        class SlowMemory:
            def search(self, _user_id, _query):  # noqa: ANN001, ANN201
                block_once()
                return []

        class SlowCases:
            def search(self, _user_id, _query, *, k):  # noqa: ANN001, ANN201
                assert k == 1
                block_once()
                return []

        class SlowConversation(ConversationStore):
            blocked = False

            def get(self, key):  # noqa: ANN001, ANN201
                if not self.blocked:
                    self.blocked = True
                    block_once()
                return super().get(key)

        store = SlowConversation() if kind == "conversation" else ConversationStore()
        kwargs = {
            "memory": SlowMemory() if kind == "memory" else None,
            "cases": SlowCases() if kind == "cases" else None,
        }
        timer = threading.Timer(0.8, release.set)
        timer.start()
        loop = asyncio.get_running_loop()
        before = loop.time()
        task = asyncio.create_task(
            agent_chat(
                _FakeRouter(_RecordingProvider()),
                store,
                message="你好",
                chat_id=f"off-loop-{kind}",
                user_id="owner",
                model="echo",
                **kwargs,
            )
        )
        try:
            while not started.is_set():
                await asyncio.sleep(0.005)
            await asyncio.sleep(0.02)
            assert loop.time() - before < 0.4
        finally:
            release.set()
            timer.cancel()
        await asyncio.wait_for(task, timeout=2.0)

    async def run() -> None:
        for kind in ("memory", "cases", "conversation"):
            await assert_off_loop(kind)

    asyncio.run(run())


def test_agent_endpoint_verified_chat_route_accumulates():
    provider = _RecordingProvider()
    with TestClient(app) as c:
        original_router = c.app.state.router
        try:
            c.app.state.router = _FakeRouter(provider)
            r1 = c.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={"message": "你好", "chat_id": "e1", "channel": "api", "model": "test-chat"},
            )
            assert r1.status_code == 200
            d1 = r1.json()
            assert d1["reply"] == "got:你好"
            assert d1["session"] == "api:e1"
            assert d1["turns"] == 1

            r2 = c.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={"message": "再说一次", "chat_id": "e1", "channel": "api", "model": "test-chat"},
            )
            assert r2.status_code == 200
            assert r2.json()["turns"] == 2  # 跨请求累计上下文
        finally:
            c.app.state.router = original_router


def test_agent_endpoint_honors_an_explicit_model_over_case_routing(monkeypatch):
    provider = _RecordingProvider()

    def prefer_cheap_model(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        return {
            "model": "case-router-cheap",
            "label": "cheap",
            "case": None,
            "store": False,
        }

    monkeypatch.setattr(agent_module, "decide_route", prefer_cheap_model)
    with TestClient(app) as client:
        original_router = client.app.state.router
        original_cases = client.app.state.cases
        try:
            client.app.state.router = _FakeRouter(provider)
            client.app.state.cases = object()
            response = client.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={
                    "message": "必须使用我在界面选中的模型",
                    "chat_id": "explicit-model",
                    "channel": "desktop",
                    "user_id": "owner",
                    "model": "operator-selected",
                },
            )
        finally:
            client.app.state.router = original_router
            client.app.state.cases = original_cases

    assert response.status_code == 200
    assert response.json()["reply"] == "got:必须使用我在界面选中的模型"
    answer_models = [
        model
        for model, messages in zip(provider.seen_models, provider.seen, strict=True)
        if messages
        and messages[-1]
        == {"role": "user", "content": "必须使用我在界面选中的模型"}
    ]
    assert answer_models == ["operator-selected"]
    assert "case-router-cheap" not in provider.seen_models


def test_agent_endpoint_binds_each_provider_reply_to_a_fresh_private_author_context(
    monkeypatch,
):
    router = _AttributedRouter()
    captured: list[dict] = []
    original_bind = agent_module.bind_agent_author_receipt

    def recording_bind(receipt, *, reply):  # noqa: ANN001, ANN202
        bound = original_bind(receipt, reply=reply)
        captured.append(bound)
        return bound

    monkeypatch.setattr(agent_module, "bind_agent_author_receipt", recording_bind)
    with TestClient(app) as client:
        original_router = client.app.state.router
        try:
            client.app.state.router = router
            first = client.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={
                    "message": "你好",
                    "chat_id": "attribution-a",
                    "channel": "api",
                    "model": "attributed-chat",
                },
            )
            second = client.post(
                "/v1/agent/chat",
                headers=AUTH,
                json={
                    "message": "再见",
                    "chat_id": "attribution-b",
                    "channel": "api",
                    "model": "attributed-chat",
                },
            )
        finally:
            client.app.state.router = original_router

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["model"] == "attributed-chat"
    assert second.json()["model"] == "attributed-chat"
    assert "final_route_receipt" not in first.json()
    assert "final_route_receipt" not in second.json()
    assert len(captured) == 2
    assert (
        captured[0]["_nachuan_attestation_context_sha256"]
        != captured[1]["_nachuan_attestation_context_sha256"]
    )


def test_agent_endpoint_requires_message():
    with TestClient(app) as c:
        r = c.post("/v1/agent/chat", headers=AUTH, json={"chat_id": "x", "model": "echo"})
        assert r.status_code == 422


def test_translate_failure_is_partial_and_never_leaks_provider_error(monkeypatch):
    async def translate_intent(*_args, **_kwargs):
        return "translate"

    async def failed_translate(*_args, **_kwargs):
        raise RuntimeError("sk-live-secret https://internal-provider.example")

    monkeypatch.setattr(agent_module, "classify_intent", translate_intent)
    monkeypatch.setattr(agent_module, "translate", failed_translate)
    result = asyncio.run(
        agent_chat(
            _FakeRouter(_RecordingProvider()),
            ConversationStore(),
            message="翻译成英文：你好",
            chat_id="translate-failure",
            model="test-chat",
        )
    )

    assert result["outcome"] == "partial"
    assert result["blocked"] is False
    assert "sk-live-secret" not in result["reply"]
    assert "internal-provider" not in result["reply"]
    assert result["reply"] == "翻译暂时失败，本轮没有产出译文，请稍后重试。"
    assert result["model"] == "nachuan-engine"


def test_translate_success_binds_the_exact_provider_reply_author(monkeypatch):
    async def translate_intent(*_args, **_kwargs):
        return "translate"

    response = {
        "choices": [{"message": {"role": "assistant", "content": "Hello"}}],
        "usage": {},
        "model": "upstream-private-id",
    }

    async def translated(*_args, **kwargs):
        assert kwargs["include_author_evidence"] is True
        return {
            "translated": "Hello",
            "model": "actual-translate-model",
            "target": "en",
            "_response": response,
            "_route": {"actual_model": "actual-translate-model"},
            "_requested_model": "requested-translate-model",
        }

    captured: dict = {}

    def fake_route_receipt(**kwargs):
        captured.update(kwargs)
        return {"route-bound": True}

    def fake_author_bind(receipt, *, reply):
        assert receipt == {"route-bound": True}
        assert reply == "Hello"
        return {"author-bound": True}

    monkeypatch.setattr(agent_module, "classify_intent", translate_intent)
    monkeypatch.setattr(agent_module, "translate", translated)
    monkeypatch.setattr(agent_module, "route_receipt", fake_route_receipt)
    monkeypatch.setattr(agent_module, "bind_agent_author_receipt", fake_author_bind)
    result = asyncio.run(
        agent_chat(
            _FakeRouter(_RecordingProvider()),
            ConversationStore(),
            message="翻译成英文：你好",
            chat_id="translate-success",
            model="test-chat",
        )
    )

    assert result["model"] == "actual-translate-model"
    assert result["final_route_receipt"] == {"author-bound": True}
    assert captured["requested_model"] == "requested-translate-model"
    assert captured["actual_model"] == "actual-translate-model"
    assert captured["response"] is response


def test_kb_failure_is_partial_and_never_leaks_provider_error(monkeypatch):
    class FailingProvider:
        name = "failing-kb"

        async def chat(self, _req, _upstream):
            raise RuntimeError("Bearer sk-live-kb-secret internal-kb-host")

    class OneHitKnowledgeBase:
        def search(self, _user_id, _message, *, k):
            assert k == 5
            return [{"title": "手册", "text": "已验证内容"}]

    async def kb_intent(*_args, **_kwargs):
        return "kb"

    monkeypatch.setattr(agent_module, "classify_intent", kb_intent)
    result = asyncio.run(
        agent_chat(
            _FakeRouter(FailingProvider()),
            ConversationStore(),
            message="查询知识库",
            chat_id="kb-failure",
            user_id="owner",
            model="test-chat",
            kb=OneHitKnowledgeBase(),
        )
    )

    assert result["outcome"] == "partial"
    assert result["blocked"] is False
    assert "sk-live-kb-secret" not in result["reply"]
    assert "internal-kb-host" not in result["reply"]
    assert result["reply"] == "知识库回答暂时失败，本轮没有形成答案，请稍后重试。"
    assert result["model"] == "nachuan-engine"


def test_kb_success_binds_the_exact_provider_reply_author(monkeypatch):
    class OneHitKnowledgeBase:
        def search(self, _user_id, _message, *, k):
            assert k == 5
            return [{"title": "手册", "text": "已验证内容"}]

    async def kb_intent(*_args, **_kwargs):
        return "kb"

    response = {
        "choices": [{"message": {"role": "assistant", "content": "资料答案[1]"}}],
        "usage": {},
        "model": "upstream-private-id",
    }

    async def fallback(*_args, **_kwargs):
        return response, "actual-kb-model", {"actual_model": "actual-kb-model"}

    captured: dict = {}

    def fake_route_receipt(**kwargs):
        captured.update(kwargs)
        return {"route-bound": True}

    monkeypatch.setattr(agent_module, "classify_intent", kb_intent)
    monkeypatch.setattr(agent_module, "chat_with_fallback", fallback)
    monkeypatch.setattr(agent_module, "route_receipt", fake_route_receipt)
    monkeypatch.setattr(
        agent_module,
        "bind_agent_author_receipt",
        lambda receipt, *, reply: {"receipt": receipt, "reply": reply},
    )
    result = asyncio.run(
        agent_chat(
            _FakeRouter(_RecordingProvider()),
            ConversationStore(),
            message="查询知识库",
            chat_id="kb-success",
            user_id="owner",
            model="test-chat",
            kb=OneHitKnowledgeBase(),
        )
    )

    assert result["reply"] == "资料答案[1]"
    assert result["model"] == "actual-kb-model"
    assert result["final_route_receipt"]["reply"] == "资料答案[1]"
    assert captured["actual_model"] == "actual-kb-model"
    assert captured["response"] is response


def test_agent_persona_is_stable_prefix():
    """C2：人设作为稳定前缀，排在 system 最前。"""
    prov = _RecordingProvider()
    asyncio.run(
        agent_chat(
            _FakeRouter(prov), ConversationStore(), message="hi", chat_id="p", model="echo",
            persona="我是稳定人设",
        )
    )
    sysmsg = prov.seen[0][0]
    assert sysmsg["role"] == "system" and sysmsg["content"].startswith("我是稳定人设")
