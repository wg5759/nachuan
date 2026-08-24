"""超级智能体 M2：长期用户记忆（存储/去重/检索 + 抽取 + 注入 + HTTP）。"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.agent import ConversationStore, agent_chat
from orchestrator.memory import MemoryStore, extract_and_store

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


class _FactProvider:
    """假模型：返回带 evidence 的抽取结果——一条有用户原话支撑、一条脑补无支撑。"""

    name = "fact"

    async def chat(self, req, upstream_model):  # noqa: ANN001
        return ChatCompletionResponse.from_text(
            model=req.model,
            text=(
                '抽取结果：[{"fact":"用户是后端工程师","evidence":"用 python 写个登录接口"},'
                '{"fact":"用户常年住在火星基地","evidence":"我常年住在火星基地"}]'
            ),
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


class _RecordingProvider:
    name = "rec"

    def __init__(self):
        self.seen = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.seen.append([{"role": m.role, "content": m.content} for m in req.messages])
        return ChatCompletionResponse.from_text(
            model=req.model,
            text="ok",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


def test_memory_store_add_dedup_search(tmp_path):
    store = MemoryStore(str(tmp_path / "mem.db"))
    assert store.add("u1", "我是后端工程师，主用 Python")
    assert store.add("u1", "我喜欢简洁、直接的回答")
    assert store.add("u1", "我是后端工程师，主用 Python") is False  # 近重复跳过
    assert len(store.all_for("u1")) == 2
    assert store.all_for("u2") == []  # 跨用户隔离
    hits = store.search("u1", "用 python 写个脚本")
    assert any("Python" in h["text"] for h in hits)  # 关键词命中
    store.clear("u1")
    assert store.all_for("u1") == []
    store.close()


def test_extract_and_store_grounding(tmp_path):
    """防投毒：有用户原话支撑的事实入库；模型脑补、无依据的被拦下（抗失智闸①）。"""
    store = MemoryStore(str(tmp_path / "mem.db"))
    router = _Router(_FactProvider())

    async def run():
        return await extract_and_store(
            router,
            store,
            user_id="u1",
            user_msg="帮我用 python 写个登录接口",  # 没提"火星"
            assistant_msg="好的……",
            model="echo",
        )

    added = asyncio.run(run())
    assert "用户是后端工程师" in added  # evidence 出自用户原话 → 入库
    texts = [m["text"] for m in store.all_for("u1")]
    assert texts == ["用户是后端工程师"]
    assert "用户常年住在火星基地" not in texts  # evidence 不在用户话里 → 被防投毒拦下
    asyncio.run(run())  # 再抽一次相同事实 → 去重，不新增
    assert len(store.all_for("u1")) == 1
    store.close()


def test_supersede_on_fact_update(tmp_path):
    """事实更新：新值作废同结构旧值，旧的下线但可回溯，检索不再注入旧值（抗失智闸②）。"""
    store = MemoryStore(str(tmp_path / "mem.db"))
    assert store.add("u1", "用户在北京工作")
    assert store.add("u1", "用户在上海工作")  # 同结构、局部值替换 → 判为更新
    active = [m["text"] for m in store.all_for("u1")]
    assert "用户在上海工作" in active
    assert "用户在北京工作" not in active  # 旧值被 superseded，默认不返回
    allm = [m["text"] for m in store.all_for("u1", include_superseded=True)]
    assert "用户在北京工作" in allm  # 未删除，可回溯/恢复
    hits = store.search("u1", "用户现在在哪里工作")
    assert all(h["text"] != "用户在北京工作" for h in hits)  # 检索不再注入过期值
    # 独立事实不被误消解
    assert store.add("u1", "用户喜欢喝美式咖啡")
    assert "用户喜欢喝美式咖啡" in [m["text"] for m in store.all_for("u1")]
    assert "用户在上海工作" in [m["text"] for m in store.all_for("u1")]
    store.close()


def test_schema_migration_from_legacy(tmp_path):
    """老库（无 status/source 列）应平滑迁移：旧记忆默认 active、可读可写。"""
    import sqlite3

    p = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(p)
    conn.execute(
        "CREATE TABLE user_memory (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id TEXT NOT NULL, text TEXT NOT NULL, kind TEXT DEFAULT 'fact', "
        "created_at REAL, updated_at REAL)"
    )
    conn.execute(
        "INSERT INTO user_memory (user_id, text, kind, created_at, updated_at) "
        "VALUES ('u1','用户主用 Python','fact',1.0,1.0)"
    )
    conn.commit()
    conn.close()
    store = MemoryStore(p)  # 触发 _init 迁移
    mems = store.all_for("u1")
    assert len(mems) == 1  # 老记忆默认 active、可读
    assert mems[0]["status"] == "active"
    assert mems[0]["text"] == "用户主用 Python"
    assert store.add("u1", "用户还在用 Rust")  # 迁移后仍可写
    store.close()


def test_agent_injects_memory(tmp_path):
    mem = MemoryStore(str(tmp_path / "mem.db"))
    mem.add("u1", "用户是后端工程师，主用 Python")
    prov = _RecordingProvider()
    conv = ConversationStore()

    async def run():
        return await agent_chat(
            _Router(prov),
            conv,
            message="帮我写个 python 脚本",
            chat_id="c1",
            user_id="u1",
            model="echo",
            memory=mem,
        )

    res = asyncio.run(run())
    first = prov.seen[0][0]
    assert first["role"] == "system"
    assert "后端工程师" in first["content"]  # 记忆被注入 system
    assert res["memories_used"]
    mem.close()


def test_memory_http_list_and_clear(approval_auth_headers):
    with TestClient(app) as c:
        app.state.memory.add("httpu", "用户在做大模型聚合器项目")
        r = c.get("/v1/agent/memory", params={"user_id": "httpu"}, headers=AUTH)
        assert r.status_code == 200
        assert any("聚合器" in m["text"] for m in r.json()["memories"])
        legacy = c.delete("/v1/agent/memory", params={"user_id": "httpu"}, headers=AUTH)
        assert legacy.status_code == 410
        held = c.post(
            "/v1/agent/memory/clear", json={"user_id": "httpu"}, headers=AUTH
        ).json()
        approved = c.post(
            f"/v1/approvals/{held['approval_id']}/resolve",
            json={"decision": "approve"},
            headers=approval_auth_headers,
        )
        assert approved.status_code == 200
        d = c.post(
            "/v1/agent/memory/clear",
            json={"user_id": "httpu", "approval_id": held["approval_id"]},
            headers=AUTH,
        )
        assert d.status_code == 200
        r2 = c.get("/v1/agent/memory", params={"user_id": "httpu"}, headers=AUTH)
        assert r2.json()["memories"] == []


def test_search_vector_recall(tmp_path, monkeypatch):
    """向量混合：与目标关键词零重叠、但语义相关的记忆也能被召回到第一（向量半边真生效）。"""
    np = pytest.importorskip(
        "numpy", reason="向量记忆实验测试需 `uv sync --locked --extra savers`"
    )

    import orchestrator.embedder as emb

    def fake(texts, is_query=False):  # noqa: ANN001, ARG001
        def vv(t):
            a = np.zeros(emb.EMBED_DIM, dtype="float32")
            if any(w in t for w in ("城", "住", "居", "上海", "沪")):
                a[0] = 1.0
            elif any(w in t.lower() for w in ("python", "后端", "代码")):
                a[1] = 1.0
            else:
                a[2] = 1.0
            return a

        arr = [texts] if isinstance(texts, str) else list(texts)
        return np.stack([vv(t) for t in arr]).astype("float32")

    monkeypatch.setattr(emb._INSTANCE, "encode", fake)
    store = MemoryStore(str(tmp_path / "mem.db"))
    store.add("u1", "我在上海生活")
    store.add("u1", "我用 Python 写后端")
    store.add("u1", "我爱喝奶茶")
    # 查询与"上海生活"零关键词重叠（无共同字），纯关键词召回不到，只有向量能顶到第一
    hits = store.search("u1", "目前居所位于哪座城")
    assert hits[0]["text"] == "我在上海生活"
    assert "vec" not in hits[0]  # 对外不暴露 BLOB
    store.close()
