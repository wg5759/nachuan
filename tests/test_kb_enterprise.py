"""企业级知识库四柱子：写入闸 / 生命周期分层 / FTS5+BM25 / 体检与评测。"""

from __future__ import annotations

import sqlite3

import pytest

from orchestrator.knowledge import KnowledgeBase, build_context
from scripts import kb_doctor

_DOC_A = "海豚是哺乳动物，生活在海里，以鱼类为食。"  # ≥20 字符
_DOC_B = "海豚是齿鲸，靠回声定位捕食，群体协作围猎鱼群。"


def test_gate_noop_same_title_same_text(tmp_path):
    """同题同文再导入 → 不重复写入，返回既有 doc_id，dedup=noop。"""
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    r1 = kb.add_document("u", "手册", _DOC_A)
    r2 = kb.add_document("u", "手册", _DOC_A)
    assert r2["dedup"] == "noop" and r2["doc_id"] == r1["doc_id"]
    assert kb.count("u") == 1
    kb.close()


def test_gate_supersede_same_title_new_text(tmp_path):
    """同题异文 → 新文档写入、旧文档 superseded（不删除、可审计），检索只见新文。"""
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    r1 = kb.add_document("u", "手册", _DOC_A)
    r2 = kb.add_document("u", "手册", _DOC_B)
    assert r2["dedup"] == "supersede" and r2["doc_id"] != r1["doc_id"]
    assert kb.count("u") == 2  # 旧文档保留可审计
    status = {d["id"]: d["status"] for d in kb.list_documents("u")}  # list 全量可见
    assert status[r1["doc_id"]] == "superseded" and status[r2["doc_id"]] == "active"
    hits = kb.search("u", "回声定位")
    assert hits and all(h["doc_id"] == r2["doc_id"] for h in hits)
    assert kb.search("u", "哺乳动物") == []  # 旧文档已下线，检索不到
    kb.close()


def test_gate_reject_empty_title_and_short_text(tmp_path):
    """空 title / 正文 <20 字符 → ValueError，一个字都不写。"""
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    with pytest.raises(ValueError):
        kb.add_document("u", "", _DOC_A)
    with pytest.raises(ValueError):
        kb.add_document("u", "   ", _DOC_A)
    with pytest.raises(ValueError):
        kb.add_document("u", "短文", "太短了")  # 3 字符 < 20
    assert kb.count("u") == 0
    kb.close()


def test_lifecycle_set_status_archived(tmp_path):
    """archived 同样退出检索；set_status 校验非法状态。"""
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    r = kb.add_document("u", "手册", _DOC_A)
    assert kb.search("u", "海豚")
    assert kb.set_status("u", r["doc_id"], "archived") is True
    assert kb.search("u", "海豚") == []
    with pytest.raises(ValueError):
        kb.set_status("u", r["doc_id"], "deleted")
    kb.close()


# 先插"总则"（长文档、覆盖率更高但非答案），再插"退款政策"（短而聚焦、标题命中）
_DOC_WRONG = (
    "本总则收录售后相关的一般性说明。怎么办理、如何退款、什么流程之类的问题，这里一概不展开，"
    "全部另见对应专项文档。其余条目从略，占位文字用来把篇幅拉长，冲淡关键词密度，"
    "排序时长文档天然吃亏，这正是本用例要验证的行为。"
)
_DOC_RIGHT = "退款流程说明：退款申请提交后三个工作日内审核，退款原路退回。"
_QUERY = "退款流程怎么走"


def _pure_vs_fts_ranking(tmp_path):
    """同一语料分别用纯覆盖率与 FTS5+BM25 排序，返回 (纯覆盖率榜首, BM25 榜首)。"""
    kb_pure = KnowledgeBase(str(tmp_path / "pure.db"))
    kb_pure._fts = False  # 模拟 FTS5 不可用 → 纯覆盖率  # noqa: SLF001
    kb_pure.add_document("u", "总则", _DOC_WRONG)
    kb_pure.add_document("u", "退款政策", _DOC_RIGHT)
    pure_hits = kb_pure.search("u", _QUERY)
    kb_pure.close()

    kb = KnowledgeBase(str(tmp_path / "fts.db"))
    fts_ok = kb._fts  # noqa: SLF001
    if fts_ok:
        kb.add_document("u", "总则", _DOC_WRONG)
        kb.add_document("u", "退款政策", _DOC_RIGHT)
        fts_hits = kb.search("u", _QUERY)
    else:
        fts_hits = []
    kb.close()
    return (
        pure_hits[0]["title"] if pure_hits else None,
        fts_hits[0]["title"] if fts_hits else None,
        fts_ok,
    )


def test_fts_bm25_outranks_pure_coverage(tmp_path):
    """FTS5 召回优于纯覆盖率（关键词半边，embedder 在测试环境全局禁用）：
    "总则"字面覆盖 query token 更多（0.692 vs 0.538），纯覆盖率排它第一；
    BM25 靠长度惩罚 + title 加权 + "退款"高频，把"退款政策"顶到第一
    （归一化 BM25 实测 1.000 vs 0.667）。"""
    pure_top, fts_top, fts_ok = _pure_vs_fts_ranking(tmp_path)
    if not fts_ok:
        pytest.skip("本机 sqlite3 无 FTS5")
    assert pure_top == "总则"  # 纯覆盖率排错
    assert fts_top == "退款政策"  # BM25 纠正排序


def test_fts_bm25_outranks_with_neutral_vectors(tmp_path, monkeypatch):
    """同一排序用例叠加 fake 向量（人人相同的单位向量 → 向量半边无区分度，
    给所有命中加同一常数），验证 FTS 排序不被向量半边扰动。"""
    np = pytest.importorskip(
        "numpy", reason="向量知识库实验测试需 `uv sync --locked --extra savers`"
    )
    import orchestrator.embedder as emb

    def fake(texts, is_query=False):  # noqa: ANN001, ARG001
        arr = [texts] if isinstance(texts, str) else list(texts)
        one = np.zeros(emb.EMBED_DIM, dtype="float32")
        one[0] = 1.0
        return np.stack([one.copy() for _ in arr])

    monkeypatch.setattr(emb._INSTANCE, "encode", fake)
    pure_top, fts_top, fts_ok = _pure_vs_fts_ranking(tmp_path)
    if not fts_ok:
        pytest.skip("本机 sqlite3 无 FTS5")
    assert pure_top == "总则"
    assert fts_top == "退款政策"


def test_fts_unavailable_degrades_to_coverage(tmp_path):
    """FTS5 不可用（同名普通表占位 → 建虚表探针失败）→ 永久降级，写入检索照常。"""
    db = tmp_path / "kb.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE kb_fts(x TEXT)")  # 占位同名普通表 → FTS 探针必败
    con.commit()
    con.close()
    kb = KnowledgeBase(str(db))
    assert kb._fts is False
    r = kb.add_document("u", "手册", _DOC_A)
    assert r["dedup"] == "add" and r["chunks"] >= 1
    hits = kb.search("u", "海豚")
    assert hits and hits[0]["title"] == "手册"
    assert kb.rebuild_fts() is None  # 降级期重建是安全 no-op
    kb.close()


def test_migration_old_db(tmp_path):
    """老库（无 status/text_hash/vec、无 kb_fts）打开即平滑迁移，老数据照常可检索。"""
    db = tmp_path / "kb.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE kb_docs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,"
        "title TEXT NOT NULL,source TEXT,chunks INTEGER DEFAULT 0,created_at REAL)"
    )
    con.execute(
        "CREATE TABLE kb_chunks(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,"
        "doc_id INTEGER NOT NULL,title TEXT,text TEXT NOT NULL)"
    )
    con.execute(
        "INSERT INTO kb_docs(user_id,title,source,chunks,created_at) VALUES('u','手册','',1,1.0)"
    )
    con.execute(
        "INSERT INTO kb_chunks(user_id,doc_id,title,text) VALUES('u',1,'手册',?)", (_DOC_A,)
    )
    con.commit()
    con.close()

    kb = KnowledgeBase(str(db))
    doc_cols = {r[1] for r in kb._conn.execute("PRAGMA table_info(kb_docs)")}  # noqa: SLF001
    assert {"status", "text_hash"} <= doc_cols
    chunk_cols = {r[1] for r in kb._conn.execute("PRAGMA table_info(kb_chunks)")}  # noqa: SLF001
    assert "vec" in chunk_cols
    doc = kb.list_documents("u")[0]
    assert doc["status"] == "active"  # 迁移默认 active，老文档不丢
    hits = kb.search("u", "海豚")  # 老块不在 FTS → 覆盖率兜底，照常命中
    assert hits and hits[0]["title"] == "手册"
    # 老行 text_hash 为 NULL（正文未知）→ 同题再导入判异文、走 supersede，绝不误判 noop
    r = kb.add_document("u", "手册", _DOC_A)
    assert r["dedup"] == "supersede"
    kb.close()


def test_rebuild_fts(tmp_path):
    """rebuild_fts 全量重建：删空索引后恢复行数，检索不受影响。"""
    kb = KnowledgeBase(str(tmp_path / "kb.db"))
    if not kb._fts:
        pytest.skip("本机 sqlite3 无 FTS5")
    kb.add_document("u", "手册", _DOC_A)
    kb._conn.execute("DELETE FROM kb_fts")  # noqa: SLF001
    kb._conn.commit()  # noqa: SLF001
    assert kb.rebuild_fts() == 1  # 1 个分块
    n = kb._conn.execute("SELECT COUNT(*) FROM kb_fts").fetchone()[0]  # noqa: SLF001
    assert n == 1
    assert kb.search("u", "海豚")
    kb.close()


def test_doctor_smoke_clean_and_orphan(tmp_path):
    """体检冒烟：干净库 exit 0；注入孤儿 chunk 后 exit 1。"""
    db = str(tmp_path / "kb.db")
    kb = KnowledgeBase(db)
    kb.add_document("u", "手册", _DOC_A)
    kb.close()
    assert kb_doctor.main(["--db", db, "--quiet"]) == 0

    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO kb_chunks(user_id,doc_id,title,text) VALUES('u',999,'孤儿','无对应文档的分块')"
    )
    con.commit()
    con.close()
    assert kb_doctor.main(["--db", db, "--quiet"]) == 1


def test_eval_recall_smoke():
    """评测冒烟：临时库自建语料，recall@5 达标（≥0.8）即 exit 0。"""
    recall = kb_doctor.run_eval(kb_doctor.EVAL_FILE, quiet=True)
    assert recall >= kb_doctor.RECALL_THRESHOLD
    assert kb_doctor.main(["--eval", "--quiet"]) == 0


def test_build_context_unchanged():
    """build_context 输出格式不变（接口钉死）。"""
    assert build_context([]) == ""
    ctx = build_context([{"title": "手册", "text": "重要内容"}])
    assert ctx.startswith("[知识库参考资料]") and "[1]" in ctx and "手册" in ctx
