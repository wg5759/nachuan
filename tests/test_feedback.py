"""超级智能体 M4：反馈与反思（Reflexion）。"""

from __future__ import annotations

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.agent import (
    ConversationReceiptUnavailable,
    ConversationStore,
    agent_chat,
    record_feedback,
    record_feedback_once,
    session_key,
)
from orchestrator.cases import CaseLibrary
from orchestrator.memory import MemoryStore, reflect

AUTH = {"Authorization": "Bearer test-key"}


class _Route:
    def __init__(self, p):  # noqa: ANN001
        self.provider = p
        self.upstream_model = "x"
        self.tier = "free"


class _Router:
    def __init__(self, p):  # noqa: ANN001
        self._p = p

    def resolve(self, model):  # noqa: ANN001
        return _Route(self._p)


class _InsightProvider:
    name = "ins"

    async def chat(self, req, upstream_model):  # noqa: ANN001
        return ChatCompletionResponse.from_text(
            model=req.model,
            text='["用户偏好简洁直接", "用户是后端工程师且主用 Python"]',
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


def test_feedback_down_adds_lesson(tmp_path):
    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    r = record_feedback(memory=mem, cases=lib, conv=conv, user_id="u1", rating="down", note="回答要更简短")
    assert "lesson_added" in r["applied"]
    assert any("教训" in m["text"] and "简短" in m["text"] for m in mem.all_for("u1"))
    mem.close()
    lib.close()


def test_feedback_up_promotes_case(tmp_path):
    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    key = session_key("api", "c1")
    conv.append(key, "user", "怎么实现快速排序？")
    conv.append(key, "assistant", "可以这样实现……")
    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1", rating="up", channel="api", chat_id="c1"
    )
    assert any(x.startswith("case_promoted") for x in r["applied"])
    assert lib.count("u1") == 1
    assert lib.all_for("u1")[0]["model"] == "user_approved"
    mem.close()
    lib.close()


def test_reflect_adds_insights(tmp_path):
    mem = MemoryStore(str(tmp_path / "m.db"))
    for t in ["我用 Python", "我喜欢简洁", "我是后端工程师"]:
        mem.add("u1", t)
    added = asyncio.run(reflect(_Router(_InsightProvider()), mem, user_id="u1", model="echo"))
    assert added
    assert any(m["kind"] == "insight" for m in mem.all_for("u1"))
    mem.close()


# ════════════════════ 反馈记账钩子（批6③：👍/👎 → scoreboard.record）════════════════════
def test_feedback_records_scoreboard_when_model_known(tmp_path, monkeypatch):
    """会话里存了本轮 served model → 👍 给该模型按用户原话的 task_kind 记一场 win。"""
    import orchestrator.scoreboard as sb

    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    key = session_key("api", "c1")
    conv.append(key, "user", "帮我分析并重构这段复杂算法")   # 含"分析/重构/算法"→ reason
    conv.append(key, "assistant", "可以这样重构……")
    conv.set_last_model(key, "premC")                        # 本轮 served model

    recorded: list[tuple] = []
    monkeypatch.setattr(sb, "record", lambda m, k, win: recorded.append((m, k, win)))

    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1",
        rating="up", channel="api", chat_id="c1",
    )
    assert "scoreboard_recorded" in r["applied"]
    assert len(recorded) == 1
    m, kind, win = recorded[0]
    assert m == "premC" and win is True and kind == "reason"  # task_kind 来自 classify(用户原话)
    mem.close()
    lib.close()


def test_feedback_records_loss_on_down(tmp_path, monkeypatch):
    """👎 → 给该模型记一场 loss（win=False），且教训照旧存入 memory。"""
    import orchestrator.scoreboard as sb

    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    key = session_key("api", "c2")
    conv.append(key, "user", "写个 def foo(): 的函数")   # 含 "def " → classify code
    conv.append(key, "assistant", "def foo(): ...")
    conv.set_last_model(key, "glm")

    recorded: list[tuple] = []
    monkeypatch.setattr(sb, "record", lambda m, k, win: recorded.append((m, k, win)))

    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1",
        rating="down", channel="api", chat_id="c2", note="太啰嗦",
    )
    assert "lesson_added" in r["applied"]        # 👎 教训照旧
    assert "scoreboard_recorded" in r["applied"]
    assert recorded == [("glm", "code", False)]  # 用户原话含 "def " → classify code；loss
    mem.close()
    lib.close()


def test_feedback_skips_scoreboard_when_model_unknown(tmp_path, monkeypatch):
    """定位不到模型（会话里没存 served model）→ 跳过记账，绝不瞎猜模型。"""
    import orchestrator.scoreboard as sb

    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    key = session_key("api", "c3")
    conv.append(key, "user", "问题")
    conv.append(key, "assistant", "答案")
    # 故意不 set_last_model → 拿不到模型名

    recorded: list[tuple] = []
    monkeypatch.setattr(sb, "record", lambda m, k, win: recorded.append((m, k, win)))

    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1",
        rating="up", channel="api", chat_id="c3",
    )
    assert recorded == []                             # 没记账
    assert "scoreboard_recorded" not in r["applied"]
    mem.close()
    lib.close()


def test_local_blocked_turn_clears_previous_provider_feedback_attribution(
    tmp_path, monkeypatch
):
    from orchestrator import scoreboard as sb

    class RejectingGuard:
        def check(self, _user_id, _message):  # noqa: ANN001, ANN201
            return False, "本轮由本地安全策略拦截"

    conv = ConversationStore()
    key = session_key("api", "blocked-attribution")
    conv.append(key, "user", "上一轮问题")
    conv.append(key, "assistant", "上一轮供应商回答")
    conv.set_last_model(key, "previous-provider")

    asyncio.run(
        agent_chat(
            _Router(_InsightProvider()),
            conv,
            message="本轮本地拦截",
            chat_id="blocked-attribution",
            channel="api",
            user_id="u1",
            model="glm",
            guard=RejectingGuard(),
        )
    )
    assert conv.last_model(key) is None

    recorded: list[tuple] = []
    monkeypatch.setattr(sb, "record", lambda *args: recorded.append(args))
    result = record_feedback(
        memory=None,
        cases=None,
        conv=conv,
        user_id="u1",
        rating="down",
        channel="api",
        chat_id="blocked-attribution",
    )
    assert recorded == []
    assert "scoreboard_recorded" not in result["applied"]


def test_feedback_skips_scoreboard_without_chat_id(tmp_path, monkeypatch):
    """无 chat_id（无法定位会话）→ 跳过记账（👎 教训仍照常）。"""
    import orchestrator.scoreboard as sb

    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()

    recorded: list[tuple] = []
    monkeypatch.setattr(sb, "record", lambda m, k, win: recorded.append((m, k, win)))

    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1", rating="down", note="改进",
    )
    assert recorded == []
    assert "lesson_added" in r["applied"]  # 教训不受影响
    mem.close()
    lib.close()


def test_feedback_scoreboard_hook_swallows_exception(tmp_path, monkeypatch):
    """记账钩子抛异常 → 全吞，反馈主流程（教训/案例）不受影响。"""
    import orchestrator.scoreboard as sb

    mem = MemoryStore(str(tmp_path / "m.db"))
    lib = CaseLibrary(str(tmp_path / "c.db"))
    conv = ConversationStore()
    key = session_key("api", "c4")
    conv.append(key, "user", "问")
    conv.append(key, "assistant", "答")
    conv.set_last_model(key, "premC")

    def boom(m, k, win):
        raise RuntimeError("scoreboard down")

    monkeypatch.setattr(sb, "record", boom)

    r = record_feedback(
        memory=mem, cases=lib, conv=conv, user_id="u1", rating="down", chat_id="c4", note="x",
    )
    assert "lesson_added" in r["applied"]                 # 主流程不受钩子异常影响
    assert "scoreboard_recorded" not in r["applied"]      # 钩子失败→没记成
    mem.close()
    lib.close()


def test_agent_chat_stores_served_model(tmp_path):
    """agent_chat 走标准聊天路径后，把本轮 served model 记进 conv（供反馈钩子定位）。"""
    import asyncio

    from gateway.schemas import ChatCompletionResponse, Usage

    class _P:
        name = "vX"

        async def chat(self, req, upstream_model):  # noqa: ANN001
            return ChatCompletionResponse.from_text(
                model="served-XYZ", text="你好呀",
                usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            ).model_dump()

    class _Route:
        def __init__(self, p):
            self.provider = p
            self.upstream_model = "u"
            self.tier = "cheap"

    class _R:
        def resolve(self, m):  # noqa: ANN001
            return _Route(_P())

    conv = ConversationStore()
    out = asyncio.run(agent_chat(
        _R(), conv, message="你好", chat_id="cc", channel="api", model="glm",
    ))
    key = session_key("api", "cc")
    # served model 被记下（来自 failover 返回的 served），供 👍/👎 定位
    assert conv.last_model(key) == out["model"]


def test_feedback_endpoints_http():
    with TestClient(app) as c:
        r = c.post(
            "/v1/agent/feedback",
            headers=AUTH,
            json={"user_id": "fbu", "rating": "down", "note": "别太啰嗦"},
        )
        assert r.status_code == 200 and "lesson_added" in r.json()["applied"]
        mems = c.get("/v1/agent/memory", params={"user_id": "fbu"}, headers=AUTH).json()["memories"]
        assert any("啰嗦" in m["text"] for m in mems)
        # 缺 rating → 422
        assert c.post("/v1/agent/feedback", headers=AUTH, json={"user_id": "fbu"}).status_code == 422
        # reflect 端点连通（少于 3 条记忆时返回空列表，但端点应 200）
        rr = c.post("/v1/agent/reflect", headers=AUTH, json={"user_id": "fbu2"})
        assert rr.status_code == 200 and "insights_added" in rr.json()
        app.state.memory.clear("fbu")


def test_feedback_once_replays_persisted_result_after_restart(tmp_path, monkeypatch):
    """A lost HTTP response must not promote the same feedback twice."""
    import orchestrator.scoreboard as sb

    memory = MemoryStore(str(tmp_path / "memory.db"))
    cases = CaseLibrary(str(tmp_path / "cases.db"))
    db_path = tmp_path / "conversations.db"
    conversations = ConversationStore(db_path=str(db_path))
    key = session_key("feishu", "oc_feedback")
    conversations.append(key, "user", "How should this be implemented?")
    conversations.append(key, "assistant", "Use one durable receipt.")
    conversations.set_last_model(key, "review-model")
    recorded: list[tuple[str, str, bool]] = []
    monkeypatch.setattr(
        sb,
        "record",
        lambda model, kind, win: recorded.append((model, kind, win)),
    )
    request = {
        "memory": memory,
        "cases": cases,
        "user_id": "ou_feedback",
        "rating": "up",
        "channel": "feishu",
        "chat_id": "oc_feedback",
        "note": "",
        "idempotency_key": "om_feedback_001",
    }

    try:
        first = record_feedback_once(conv=conversations, **request)
        replay = record_feedback_once(conv=conversations, **request)
        conversations.close()
        conversations = ConversationStore(db_path=str(db_path))
        after_restart = record_feedback_once(conv=conversations, **request)

        assert replay == first == after_restart
        assert cases.count("ou_feedback") == 1
        assert len(recorded) == 1
        assert recorded[0][0] == "review-model"
        assert recorded[0][2] is True
    finally:
        conversations.close()
        memory.close()
        cases.close()


def test_feishu_feedback_endpoint_rejects_same_key_with_different_body(tmp_path):
    """A Feishu message id cannot be rebound to different feedback semantics."""
    with TestClient(app) as client:
        original = app.state.conversations
        isolated = ConversationStore(db_path=str(tmp_path / "endpoint-conversations.db"))
        app.state.conversations = isolated
        first_body = {
            "user_id": "ou_conflict",
            "chat_id": "oc_conflict",
            "channel": "feishu",
            "rating": "down",
            "note": "first correction",
            "idempotency_key": "om_conflict_001",
        }
        try:
            first = client.post("/v1/agent/feedback", headers=AUTH, json=first_body)
            conflict = client.post(
                "/v1/agent/feedback",
                headers=AUTH,
                json={**first_body, "note": "different correction"},
            )

            assert first.status_code == 200
            assert conflict.status_code == 409
        finally:
            app.state.memory.clear("ou_conflict")
            app.state.conversations = original
            isolated.close()


def test_feedback_once_serializes_concurrent_sqlite_claims(tmp_path, monkeypatch):
    """Two gateway workers sharing SQLite cannot execute one effect twice."""

    class BlockingCases:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()
            self.calls = 0
            self.lock = threading.Lock()

        def add(self, *_args):  # noqa: ANN002, ANN201
            with self.lock:
                self.calls += 1
            self.started.set()
            if not self.release.wait(10):
                raise RuntimeError("test did not release feedback effect")
            return "case-once"

    db_path = tmp_path / "concurrent-conversations.db"
    first_store = ConversationStore(db_path=str(db_path))
    key = session_key("feishu", "oc_concurrent")
    first_store.append(key, "user", "Please review this answer")
    first_store.append(key, "assistant", "Reviewed answer")
    second_store = ConversationStore(db_path=str(db_path))
    cases = BlockingCases()
    second_claimed = threading.Event()
    original_claim = second_store.claim_idempotent_effect

    def observed_claim(**kwargs):  # noqa: ANN003, ANN201
        outcome = original_claim(**kwargs)
        second_claimed.set()
        return outcome

    monkeypatch.setattr(second_store, "claim_idempotent_effect", observed_claim)
    request = {
        "memory": None,
        "cases": cases,
        "user_id": "ou_concurrent",
        "rating": "up",
        "channel": "feishu",
        "chat_id": "oc_concurrent",
        "note": "",
        "idempotency_key": "om_concurrent_001",
    }
    results: list[dict] = []
    failures: list[BaseException] = []

    def run(store):  # noqa: ANN001, ANN202
        try:
            results.append(record_feedback_once(conv=store, **request))
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    first_thread = threading.Thread(target=run, args=(first_store,))
    second_thread = threading.Thread(target=run, args=(second_store,))
    try:
        first_thread.start()
        assert cases.started.wait(10)
        second_thread.start()
        assert second_claimed.wait(10)
        cases.release.set()
        first_thread.join(10)
        second_thread.join(10)

        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        assert failures == []
        assert len(results) == 2 and results[0] == results[1]
        assert cases.calls == 1
    finally:
        cases.release.set()
        first_thread.join(10)
        second_thread.join(10)
        first_store.close()
        second_store.close()


def test_feedback_once_does_not_repeat_an_indeterminate_effect(tmp_path):
    """A crash after effect start leaves a fail-closed durable marker."""

    class IndeterminateCases:
        def __init__(self) -> None:
            self.calls = 0

        def add(self, *_args):  # noqa: ANN002, ANN201
            self.calls += 1
            raise RuntimeError("effect outcome lost")

    store = ConversationStore(db_path=str(tmp_path / "indeterminate.db"))
    key = session_key("feishu", "oc_indeterminate")
    store.append(key, "user", "Question")
    store.append(key, "assistant", "Answer")
    cases = IndeterminateCases()
    request = {
        "memory": None,
        "cases": cases,
        "conv": store,
        "user_id": "ou_indeterminate",
        "rating": "up",
        "channel": "feishu",
        "chat_id": "oc_indeterminate",
        "note": "",
        "idempotency_key": "om_indeterminate_001",
        "wait_seconds": 0,
    }
    try:
        with pytest.raises(RuntimeError, match="effect outcome lost"):
            record_feedback_once(**request)
        with pytest.raises(
            ConversationReceiptUnavailable,
            match="outcome is still in progress",
        ):
            record_feedback_once(**request)
        assert cases.calls == 1
    finally:
        store.close()


def test_feedback_once_scopes_same_transport_key_to_principal(tmp_path, monkeypatch):
    """One channel message key cannot make a different principal conflict or replay."""
    import orchestrator.agent as agent_module

    store = ConversationStore(db_path=str(tmp_path / "principal-scope.db"))
    applied: list[tuple[str, str]] = []

    def fake_record_feedback(**kwargs):  # noqa: ANN003, ANN202
        principal = (kwargs["user_id"], kwargs["chat_id"])
        applied.append(principal)
        return {"principal": list(principal)}

    monkeypatch.setattr(agent_module, "record_feedback", fake_record_feedback)
    common = {
        "memory": None,
        "cases": None,
        "conv": store,
        "rating": "up",
        "channel": "weixin",
        "note": "",
        "idempotency_key": "wxmsg-v1:same-upstream-key",
    }
    try:
        first = record_feedback_once(
            **common,
            user_id="wx_user_a",
            chat_id="wx_chat_a",
        )
        second = record_feedback_once(
            **common,
            user_id="wx_user_b",
            chat_id="wx_chat_b",
        )
        first_replay = record_feedback_once(
            **common,
            user_id="wx_user_a",
            chat_id="wx_chat_a",
        )

        assert first == first_replay == {"principal": ["wx_user_a", "wx_chat_a"]}
        assert second == {"principal": ["wx_user_b", "wx_chat_b"]}
        assert applied == [
            ("wx_user_a", "wx_chat_a"),
            ("wx_user_b", "wx_chat_b"),
        ]
    finally:
        store.close()


def test_weixin_feedback_endpoint_requires_idempotency_key():
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/feedback",
            headers=AUTH,
            json={
                "user_id": "wx_feedback",
                "chat_id": "wx_chat",
                "channel": "weixin",
                "rating": "up",
            },
        )

    assert response.status_code == 422
    assert "idempotency_key" in str(response.json().get("detail"))
