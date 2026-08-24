"""超级智能体 M3：案例库 + 师生进化（Voyager/Memento）。"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.agent import ConversationStore, agent_chat
from orchestrator.cases import CaseLibrary, decide_route

AUTH = {"Authorization": "Bearer test-key"}

HARD = "请证明快速排序平均时间复杂度为 O(n log n)，并给出三种工程上的优化方案与权衡"
EASY = "你好呀"


class _Route:
    def __init__(self, p):  # noqa: ANN001
        self.provider = p
        self.upstream_model = "x"
        self.tier = "free"


class _Router:
    """假路由：premium=gpt-5.5、free=agnes-flash，均解析到记录型 provider。"""

    def __init__(self, p):  # noqa: ANN001
        self._p = p

    def resolve(self, model):  # noqa: ANN001
        if model in ("echo", "gpt-5.5", "agnes-flash", "glm", "claude-opus", "gpt-5.4"):
            return _Route(self._p)
        return None

    def routes_info(self):
        return [
            {"model": "gpt-5.5", "tier": "premium", "provider": "p"},
            {"model": "agnes-flash", "tier": "free", "provider": "a"},
        ]


class _Recorder:
    name = "rec"

    def __init__(self):
        self.seen = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.seen.append(
            {"model": req.model, "msgs": [{"role": m.role, "content": m.content} for m in req.messages]}
        )
        return ChatCompletionResponse.from_text(
            model=req.model,
            text=f"解法[{req.model}]",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


def test_case_library_add_search_count(tmp_path):
    lib = CaseLibrary(str(tmp_path / "c.db"))
    assert lib.add("u1", HARD, "答案……", "gpt-5.5") > 0
    assert lib.count("u1") == 1
    hits = lib.search("u1", HARD)
    assert hits and hits[0]["score"] >= 0.4  # 同题高分
    far = lib.search("u1", "今天天气怎么样")
    assert far == [] or far[0]["score"] < 0.4  # 无关低分/无命中
    assert lib.count("u2") == 0  # 跨用户隔离
    lib.close()


def test_case_library_dedup(tmp_path):
    lib = CaseLibrary(str(tmp_path / "c.db"))
    id1 = lib.add("u", "如何修复登录超时的问题", "加重试与超时配置", "gpt")
    id2 = lib.add("u", "如何修复登录超时的问题", "换个解法也行", "claude")  # 近重复 → 复用、不新增
    assert id2 == id1 and lib.count("u") == 1
    id3 = lib.add("u", "怎样优化数据库查询性能", "加索引", "gpt")  # 不同题 → 新增
    assert id3 != id1 and lib.count("u") == 2
    lib.close()


def test_case_library_export_import_merge(tmp_path):
    # 跨机同步/备份地基：导出 → 合并导入(去重+幂等)
    a = CaseLibrary(str(tmp_path / "a.db"))
    a.add("u", "问题甲怎么解决呢", "解法甲", "gpt")
    a.add("u", "问题乙又该如何搞定", "解法乙", "claude")
    bundle = a.export_all("u")
    assert len(bundle) == 2
    b = CaseLibrary(str(tmp_path / "b.db"))
    b.add("u", "问题丙要怎么处理才好", "解法丙", "gpt")
    assert b.import_merge("u", bundle) == 2 and b.count("u") == 3  # 甲乙并入 b
    assert b.import_merge("u", bundle) == 0 and b.count("u") == 3  # 再导=幂等、不重复
    a.close()
    b.close()


def test_decide_route_teacher_then_reuse(tmp_path):
    lib = CaseLibrary(str(tmp_path / "c.db"))
    router = _Router(_Recorder())
    d1 = decide_route(router, "u1", HARD, lib)  # 无案例+难题 → 老师
    assert d1["label"] == "teacher" and d1["model"] == "gpt-5.5" and d1["store"]
    d2 = decide_route(router, "u1", EASY, lib)  # 易题 → 便宜/免费
    assert d2["label"] == "cheap" and d2["model"] == "agnes-flash"
    lib.add("u1", HARD, "老师的解法", "gpt-5.5")
    d3 = decide_route(router, "u1", HARD, lib)  # 有相似案例 → 复用
    assert d3["label"] == "case_reuse" and d3["model"] == "agnes-flash" and d3["case"]
    lib.close()


def test_agent_teacher_does_not_train_student_from_review_only_output(tmp_path, monkeypatch):
    lib = CaseLibrary(str(tmp_path / "c.db"))
    rec = _Recorder()
    conv = ConversationStore()

    async def reviewed_but_not_machine_verified(_router, _messages, **_kwargs):
        return {
            "reply": "reviewed answer",
            "model": "agnes-flash",
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "orchestration_mode": "org",
            "reviewed": True,
            "verified": False,
            "machine_verified": False,
            "outcome": "completed_unverified",
            "route": {"mode": "org", "reviewed": True, "machine_verified": False},
        }

    monkeypatch.setattr(
        "orchestrator.agent.run_advisory_chat", reviewed_but_not_machine_verified
    )

    async def turn(msg):
        return await agent_chat(
            _Router(rec), conv, message=msg, chat_id="c1", user_id="u1", model="glm", cases=lib
        )

    r1 = asyncio.run(turn(HARD))
    assert r1["agent_route"]["label"] == "teacher"
    assert r1["orchestration_mode"] == "org"  # 难题由强模型规划、便宜模型执行并审核
    assert r1["reviewed"] is True
    assert r1["verified"] is False
    assert r1["machine_verified"] is False
    assert r1["outcome"] == "completed_unverified"
    assert r1["model"] == "agnes-flash"  # 返回实际产出答案的执行模型，不伪装成规划模型
    assert r1["agent_route"]["store_blocked_reason"] == "machine_verification_required"
    assert lib.count("u1") == 0

    r2 = asyncio.run(turn(HARD))
    assert r2["agent_route"]["label"] == "teacher"
    assert r2["model"] == "agnes-flash"  # 免费学生作答
    assert r2["orchestration_mode"] == "org"
    assert lib.count("u1") == 0
    lib.close()


def test_sync_cases_push_pull_idempotent():
    with TestClient(app) as c:
        app.state.cases.clear("synct")
        items = [
            {"problem": "同步题甲怎么办呢", "solution": "甲解", "model": "gpt"},
            {"problem": "同步题乙又如何弄", "solution": "乙解", "model": "claude"},
        ]
        r = c.post("/v1/sync/cases/push", json={"user_id": "synct", "items": items}, headers=AUTH)
        assert r.json()["added"] == 2
        pulled = c.get("/v1/sync/cases/pull", params={"user_id": "synct"}, headers=AUTH).json()["items"]
        assert len(pulled) == 2
        # 再 push 同一批 → 去重幂等、不重复堆
        r2 = c.post("/v1/sync/cases/push", json={"user_id": "synct", "items": pulled}, headers=AUTH)
        assert r2.json()["added"] == 0
        app.state.cases.clear("synct")


def test_cases_http_list():
    with TestClient(app) as c:
        app.state.cases.add("httpc", HARD, "解法内容", "gpt-5.5")
        r = c.get("/v1/agent/cases", params={"user_id": "httpc"}, headers=AUTH)
        assert r.status_code == 200
        assert any("快速排序" in x["problem"] for x in r.json()["cases"])
        app.state.cases.clear("httpc")
