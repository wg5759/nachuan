"""知识库（IMA）：分块 + 导入 + token 重叠检索 + 引用上下文。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from orchestrator.knowledge import KnowledgeBase, build_context, chunk_text

AUTH = {"Authorization": "Bearer test-key"}


def test_chunk_text_short_and_long():
    assert chunk_text("") == []
    assert chunk_text("一句话") == ["一句话"]
    long = "段落甲。" * 200  # 单段约 800 字 → 硬切
    parts = chunk_text(long, size=300)
    assert len(parts) >= 2 and all(len(p) <= 300 for p in parts)


def test_add_and_search(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    r = kb.add_document("u", "Python手册", "Python 是解释型语言，支持面向对象。列表是可变序列。")
    assert r["chunks"] >= 1 and kb.count("u") == 1
    kb.add_document("u", "Go手册", "Go 是编译型语言，goroutine 实现并发。切片是动态数组。")
    hits = kb.search("u", "Python 列表是什么")
    assert hits and hits[0]["title"] == "Python手册" and hits[0]["score"] > 0
    assert kb.search("other", "Python") == []  # 跨用户隔离
    kb.close()


def test_delete(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    d = kb.add_document("u", "甲", "知识库测试内容关于猫：猫是夜行动物，这些是平日的观察记录。")
    assert kb.delete_document("u", d["doc_id"]) is True
    assert kb.count("u") == 0 and kb.search("u", "猫") == []
    kb.close()


def test_build_context():
    assert build_context([]) == ""
    ctx = build_context([{"title": "手册", "text": "重要内容"}])
    assert "[1]" in ctx and "手册" in ctx and "重要内容" in ctx


def test_kb_http_flow(approval_auth_headers):
    with TestClient(app) as c:
        r = c.post(
            "/v1/kb/docs",
            json={"user_id": "kbt", "title": "测试文档", "text": "海豚是哺乳动物，生活在海里，以鱼类为食，智商很高。"},
            headers=AUTH,
        )
        assert r.status_code == 200 and r.json()["chunks"] >= 1
        docs = c.get("/v1/kb/docs", params={"user_id": "kbt"}, headers=AUTH).json()["docs"]
        assert docs and docs[0]["title"] == "测试文档"
        # 空用户查询 → 无命中、不调模型、返回结构正确
        q = c.post("/v1/kb/query", json={"user_id": "emptyu", "query": "随便"}, headers=AUTH).json()
        assert q["answer"] and q["sources"] == []
        legacy = c.delete(
            f"/v1/kb/docs/{docs[0]['id']}", params={"user_id": "kbt"}, headers=AUTH
        )
        assert legacy.status_code == 410
        held = c.post(
            f"/v1/kb/docs/{docs[0]['id']}/delete",
            json={"user_id": "kbt"},
            headers=AUTH,
        ).json()
        approved = c.post(
            f"/v1/approvals/{held['approval_id']}/resolve",
            json={"decision": "approve"},
            headers=approval_auth_headers,
        )
        assert approved.status_code == 200
        ok = c.post(
            f"/v1/kb/docs/{docs[0]['id']}/delete",
            json={"user_id": "kbt", "approval_id": held["approval_id"]},
            headers=AUTH,
        ).json()
        assert ok["ok"] is True


def test_hybrid_search_vector_recall(tmp_path, monkeypatch):
    """混合检索：与分块关键词零重叠、语义相关的分块也能被召回（向量半边真生效）。"""
    np = pytest.importorskip(
        "numpy", reason="向量知识库实验测试需 `uv sync --locked --extra savers`"
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
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    kb.add_document("u", "居住地", "我在上海生活，这里气候湿润，离江边很近，日子过得舒心。")
    kb.add_document("u", "技术栈", "平时用 Python 写后端，偶尔写些脚本工具，代码都放进仓库。")
    # 查询与"上海生活"零关键词重叠，纯关键词命中不到，靠向量召回
    hits = kb.search("u", "目前居所位于哪座城")
    assert hits and hits[0]["title"] == "居住地"
    kb.close()
