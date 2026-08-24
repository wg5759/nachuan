"""知识库（IMA 内核）：导入文档 → 分块 → 检索 → 带引用回答。

企业级四根柱子（详见项目根 AGENTS.md「知识库架构约定」）：
① 写入闸门：add_document 先查重裁决——同 user 同 title 且正文完全相同 → 不重复写入
   （dedup="noop"，返回既有 doc_id）；同 title 异正文 → 新文档写入、旧文档置
   superseded（dedup="supersede"，不删除、可审计）；空 title / 正文 <20 字符 ValueError 拒收。
② 分层生命周期：kb_docs.status ∈ active/superseded/archived（缺省 active，
   老库 PRAGMA table_info + ALTER TABLE 平滑迁移），search 只查 active，list 全量可见。
③ 检索升级：关键词分 = max(语言无关 token 覆盖率, 归一化 FTS5 BM25)，再与 bge 向量
   余弦 0.5/0.5 融合；FTS5 / embedder 任一不可用都静默退回纯覆盖率全扫（降级哲学）。
④ 评测+体检：scripts/kb_doctor.py（FAIL/WARN 分级）+ scripts/kb_eval.jsonl 回归集。

检索沿用案例库同一套**语言无关 token 重叠**打分（零新依赖，中文友好）；按 user_id 隔离。
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from orchestrator.embedder import cosine_blobs, encode_query, fuse  # 混合检索：向量编码+融合
from orchestrator.memory import _tokens  # 复用语言无关的粗分词

_CHUNK = 600  # 每块约多少字符
_OVERLAP = 80  # 块间重叠，避免把语义切断
_MIN_TEXT = 20  # 写入闸门：正文最小字符数（防垃圾碎片入库）
_STATUSES = ("active", "superseded", "archived")


def chunk_text(text: str, size: int = _CHUNK, overlap: int = _OVERLAP) -> list[str]:
    """按段落聚合到 ~size，过长段落硬切（带重叠）。"""
    text = (text or "").replace("\r", "").strip()
    if not text:
        return []
    paras = [p.strip() for p in text.split("\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paras:
        if buf and len(buf) + len(p) + 1 > size:
            chunks.append(buf)
            buf = ""
        while len(p) > size:  # 单段超长 → 硬切
            chunks.append(p[:size])
            p = p[size - overlap :]
        buf = (buf + "\n" + p) if buf else p
    if buf:
        chunks.append(buf)
    return chunks


def _encode_blobs(texts: list[str]) -> list[Any]:
    """批量把分块编码成 BLOB（对齐输入）；embedder 不可用则全 None → 纯关键词。"""
    if not texts:
        return []
    from orchestrator.embedder import encode, to_blob

    mat = encode(texts, is_query=False)
    if mat is None:
        return [None] * len(texts)
    return [to_blob(mat[i]) for i in range(len(texts))]


def _text_hash(text: str) -> str:
    """正文归一化（去 \\r、去首尾空白）后的 SHA-256——写入闸"正文完全相同"的判据。"""
    return hashlib.sha256((text or "").replace("\r", "").strip().encode("utf-8")).hexdigest()


def _fts_terms(text: str) -> str:
    """把文本预分词成空格分隔的 token 串供 FTS5 索引（unicode61 不切中文，预分词后中西文通吃）。"""
    return " ".join(sorted(_tokens(text)))


class KnowledgeBase:
    """按 user_id 存文档与分块；FTS5 BM25 + token 覆盖率 + 向量混合检索。SQLite，进程内加锁。"""

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._fts = False  # FTS5 是否可用（不可用时检索退回纯覆盖率，行为与升级前一致）
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS kb_docs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL, title TEXT NOT NULL, source TEXT,
                    chunks INTEGER DEFAULT 0, created_at REAL,
                    status TEXT DEFAULT 'active', text_hash TEXT);
                CREATE TABLE IF NOT EXISTS kb_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL, doc_id INTEGER NOT NULL,
                    title TEXT, text TEXT NOT NULL, vec BLOB);
                CREATE INDEX IF NOT EXISTS idx_kbchunks_user ON kb_chunks(user_id);
                CREATE INDEX IF NOT EXISTS idx_kbdocs_user ON kb_docs(user_id);
                """
            )
            # 老库平滑迁移（对齐 memory.py 的 PRAGMA + ALTER 范式）：
            # kb_chunks 早期无 vec 列 → 补（首次 search 懒回填向量）；
            # kb_docs 早期无 status/text_hash 列 → 补，老文档默认 active、hash 置 NULL
            # （NULL 视为"正文未知"，同 title 再导入走 supersede，不会误判 noop）。
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(kb_chunks)")}
            if "vec" not in cols:
                self._conn.execute("ALTER TABLE kb_chunks ADD COLUMN vec BLOB")
            doc_cols = {r[1] for r in self._conn.execute("PRAGMA table_info(kb_docs)")}
            if "status" not in doc_cols:
                self._conn.execute(
                    "ALTER TABLE kb_docs ADD COLUMN status TEXT DEFAULT 'active'"
                )
            if "text_hash" not in doc_cols:
                self._conn.execute("ALTER TABLE kb_docs ADD COLUMN text_hash TEXT")
            # FTS5 虚表（存预分词 token，rowid 对齐 kb_chunks.id）。建表 + 探针写删：
            # 老库若已存在同名普通表 / 本机 sqlite3 无 FTS5 → 抛错 → 永久降级纯覆盖率。
            try:
                self._conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(title, text)"
                )
                self._conn.execute("INSERT INTO kb_fts(rowid,title,text) VALUES(-1,'','')")
                self._conn.execute("DELETE FROM kb_fts WHERE rowid=-1")
                self._fts = True
            except sqlite3.Error:
                self._fts = False
            self._conn.commit()

    def _fts_insert(self, chunk_id: int, title: str, text: str) -> None:
        """分块同步进 FTS（调用方须持锁）。失败静默降级——绝不影响文档写入。"""
        if not self._fts:
            return
        try:
            self._conn.execute(
                "INSERT INTO kb_fts(rowid,title,text) VALUES(?,?,?)",
                (chunk_id, _fts_terms(title), _fts_terms(text)),
            )
        except sqlite3.Error:
            self._fts = False  # 索引损坏 → 退回纯覆盖率；doctor 会报行数不一致

    def add_document(self, user_id: str, title: str, text: str, source: str = "") -> dict[str, Any]:
        """导入一篇文档，带写入闸门。返回 {doc_id, title, chunks, dedup}。

        闸门裁决（同 user 下、仅看 active 文档）：
        - 拒收：title 空白 / 正文 <20 字符 → ValueError（不入门，垃圾不污染检索）；
        - noop：title 相同且正文完全相同 → 不重复写入，返回既有 doc_id；
        - supersede：title 相同正文不同 → 新文档写入，旧文档置 superseded（不删除）；
        - add：其余正常导入。
        """
        title = (title or "").strip()
        if not title:
            raise ValueError("知识库文档 title 不能为空")
        body = (text or "").replace("\r", "").strip()
        if len(body) < _MIN_TEXT:
            raise ValueError(f"知识库文档正文过短（<{_MIN_TEXT} 字符），拒绝写入")
        digest = _text_hash(body)
        with self._lock:
            same_title = self._conn.execute(
                "SELECT id,chunks,text_hash FROM kb_docs "
                "WHERE user_id=? AND title=? AND status='active'",
                (user_id, title),
            ).fetchall()
            for did, nchunks, old_hash in same_title:
                if old_hash == digest:  # (a) 同题同文 → 不重复写入
                    return {
                        "doc_id": did, "title": title, "chunks": nchunks, "dedup": "noop",
                    }
            parts = chunk_text(body)
            vecs = _encode_blobs(parts)  # 对齐 parts；embedder 不可用则全 None（纯关键词）
            cur = self._conn.execute(
                "INSERT INTO kb_docs(user_id,title,source,chunks,created_at,status,text_hash) "
                "VALUES(?,?,?,?,?,'active',?)",
                (user_id, title, source, len(parts), time.time(), digest),
            )
            doc_id = cur.lastrowid
            for c, v in zip(parts, vecs):
                ccur = self._conn.execute(
                    "INSERT INTO kb_chunks(user_id,doc_id,title,text,vec) VALUES(?,?,?,?,?)",
                    (user_id, doc_id, title, c, v),
                )
                self._fts_insert(int(ccur.lastrowid), title, c)
            if same_title:  # (b) 同题异文 → 旧文档下线（superseded，不删除、可审计）
                self._conn.execute(
                    "UPDATE kb_docs SET status='superseded' "
                    "WHERE user_id=? AND title=? AND status='active' AND id<>?",
                    (user_id, title, doc_id),
                )
            self._conn.commit()
        return {
            "doc_id": doc_id, "title": title, "chunks": len(parts),
            "dedup": "supersede" if same_title else "add",
        }

    def _bm25_scores(self, q: set[str]) -> dict[int, float]:
        """FTS5 BM25 关键词分（按本query最大值归一化到 0..1，chunk_id→分）。

        FTS5 不可用 / 空 query / 无命中 → {}，调用方退回纯覆盖率（降级哲学）。
        title 列权重 5（标题命中比正文偶然命中更说明问题）。
        """
        if not self._fts or not q:
            return {}
        match = " OR ".join(f'"{t}"' for t in sorted(q))  # _tokens 产出无引号，安全
        try:
            rows = self._conn.execute(
                "SELECT rowid, bm25(kb_fts, 5.0, 1.0) FROM kb_fts WHERE kb_fts MATCH ?",
                (match,),
            ).fetchall()
        except sqlite3.Error:
            self._fts = False  # 索引损坏 → 永久降级，绝不拖垮检索
            return {}
        raw = {int(rid): -score for rid, score in rows}  # bm25 越小越好且通常为负 → 取反
        top = max(raw.values(), default=0.0)
        if top <= 0:
            return {}
        return {cid: v / top for cid, v in raw.items()}

    def search(self, user_id: str, query: str, k: int = 5) -> list[dict[str, Any]]:
        """混合检索：max(覆盖率, 归一化 BM25) 关键词分 + 本地向量余弦，加权融合（各 0..1 同量纲）。

        只查 active 文档（分层生命周期）；superseded/archived 可经 list_documents 审计。
        embedder 不可用（未下模型/降级）或 FTS5 不可用 → 自动退化为纯关键词覆盖率，
        与升级前完全一致。老库缺向量的分块会在首次检索时懒回填，本次仍靠关键词。
        score 字段仅用于排序展示。
        """
        q = _tokens(query)
        with self._lock:
            rows = self._conn.execute(
                "SELECT c.id, c.doc_id, c.title, c.text, c.vec FROM kb_chunks c "
                "JOIN kb_docs d ON d.id=c.doc_id AND d.user_id=c.user_id "
                "WHERE c.user_id=? AND d.status='active'",
                (user_id,),
            ).fetchall()
            bm = self._bm25_scores(q)
        if not rows:
            return []
        qvec = encode_query(query)
        refill: list[tuple[int, str]] = []
        out: list[dict[str, Any]] = []
        for cid, doc_id, title, text, vec in rows:
            coverage = (len(q & _tokens(text)) / len(q)) if q else 0.0
            kw = max(coverage, bm.get(int(cid), 0.0))  # FTS 分只在更高时接管
            vs = cosine_blobs(qvec, vec)  # qvec/vec 任一为空→None（降级或该块缺向量）
            if qvec is not None and vs is None:
                refill.append((int(cid), text))  # 老块缺向量 → 记下懒回填
            score = fuse(kw, vs)
            if score > 0:
                out.append(
                    {"doc_id": doc_id, "title": title, "text": text, "score": round(score, 3)}
                )
        if qvec is not None and refill:
            self._refill_vecs(refill)  # 一次性补向量，不影响本次结果
        out.sort(key=lambda c: c["score"], reverse=True)
        return out[:k]

    def _refill_vecs(self, items: list[tuple[int, str]]) -> None:
        """给缺向量的老分块补编码（一次性）。失败静默——绝不影响检索。"""
        try:
            from orchestrator.embedder import encode, to_blob

            mat = encode([t for _i, t in items], is_query=False)
            if mat is None:
                return
            with self._lock:
                for j, (cid, _t) in enumerate(items):
                    self._conn.execute(
                        "UPDATE kb_chunks SET vec=? WHERE id=?", (to_blob(mat[j]), cid)
                    )
                self._conn.commit()
        except Exception:  # noqa: BLE001
            pass

    def rebuild_fts(self) -> Optional[int]:
        """全量重建 FTS 索引（doctor --rebuild 用）。返回索引行数；FTS5 不可用返回 None。"""
        if not self._fts:
            return None
        with self._lock:
            try:
                self._conn.execute("DELETE FROM kb_fts")
                rows = self._conn.execute("SELECT id,title,text FROM kb_chunks").fetchall()
                for cid, title, text in rows:
                    self._conn.execute(
                        "INSERT INTO kb_fts(rowid,title,text) VALUES(?,?,?)",
                        (cid, _fts_terms(title or ""), _fts_terms(text)),
                    )
                self._conn.commit()
            except sqlite3.Error:
                self._conn.rollback()
                self._fts = False
                return None
        return len(rows)

    def set_status(self, user_id: str, doc_id: int, status: str) -> bool:
        """手工调整文档生命周期状态（active/superseded/archived），供审计/归档操作。"""
        if status not in _STATUSES:
            raise ValueError(f"非法知识库文档状态 {status!r}（可选：{_STATUSES}）")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE kb_docs SET status=? WHERE user_id=? AND id=?",
                (status, user_id, doc_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def list_documents(self, user_id: str) -> list[dict[str, Any]]:
        """全量列出（含 superseded/archived，供审计）；检索只取 active。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id,title,source,chunks,created_at,status FROM kb_docs WHERE user_id=? "
                "ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [
            {
                "id": r[0], "title": r[1], "source": r[2], "chunks": r[3],
                "created_at": r[4], "status": r[5],
            }
            for r in rows
        ]

    def delete_document(self, user_id: str, doc_id: int) -> bool:
        with self._lock:
            chunk_ids = [
                r[0]
                for r in self._conn.execute(
                    "SELECT id FROM kb_chunks WHERE user_id=? AND doc_id=?", (user_id, doc_id)
                ).fetchall()
            ]
            self._conn.execute(
                "DELETE FROM kb_chunks WHERE user_id=? AND doc_id=?", (user_id, doc_id)
            )
            if self._fts and chunk_ids:
                try:
                    self._conn.executemany(
                        "DELETE FROM kb_fts WHERE rowid=?", [(i,) for i in chunk_ids]
                    )
                except sqlite3.Error:
                    self._fts = False  # 降级；doctor 会报行数不一致
            cur = self._conn.execute(
                "DELETE FROM kb_docs WHERE user_id=? AND id=?", (user_id, doc_id)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def count(self, user_id: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM kb_docs WHERE user_id=?", (user_id,)
            ).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def build_context(hits: list[dict[str, Any]]) -> str:
    """把检索到的分块拼成带编号的"参考资料"块，供模型据实回答 + 标引用。"""
    if not hits:
        return ""
    lines = ["[知识库参考资料]"]
    for i, h in enumerate(hits, 1):
        lines.append(f"[{i}] (来源:{h.get('title') or '?'}) {h['text']}")
    return "\n".join(lines)
