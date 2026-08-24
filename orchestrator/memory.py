"""长期用户记忆（M2）：把“关于用户的持久事实/习惯”落到本地 SQLite —— 越用越懂你。

打法借鉴 mem0（抽取偏好）/ Letta·MemGPT（自管理记忆）/ Memento（无需微调、靠检索复用）。
每轮对话：① 检索相关记忆注入 system；② 回复后用便宜/免费模型抽取新事实、去重入库。
不引入向量库等重依赖：用 IDF 加权的关键词重叠做轻量检索，用项目自家免费模型做抽取。

抗失智三闸（对所有接入模型统一生效——逻辑在网关/编排层，不靠模型自管记忆，弱模型也被保护）：
① 防投毒：抽取的事实必须有用户原话(evidence)支撑，模型脑补的丢弃；
② 时效/矛盾消解：新事实作废同结构的旧事实(status=superseded)，只注入当前有效的；
③ 检索去噪：IDF 加权让稀有区分词得分高、高频虚词得分低，少召回无关记忆。
"""

from __future__ import annotations

import difflib
import json
import math
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.schemas import ChatCompletionRequest
from orchestrator.embedder import cosine_blobs, encode, encode_query, fuse, to_blob

_MAX_INJECT = 12  # 注入 system 的记忆条数上限


def _tokens(text: str) -> set[str]:
    """语言无关的粗分词：英数单词 + 中文单字与相邻双字。用于关键词重叠打分。"""
    t = (text or "").lower()
    words = set(re.findall(r"[a-z0-9]+", t))
    cjk = re.findall(r"[一-鿿]", t)
    grams = {cjk[i] + cjk[i + 1] for i in range(len(cjk) - 1)}
    return words | grams | set(cjk)


def _vec_blob(text: str) -> Any:
    """编码单条记忆为向量 BLOB；embedder 未就绪/降级则 None（search 时懒回填）。"""
    v = encode(text, is_query=False)
    return to_blob(v) if v is not None else None


def _strip_vec(m: dict[str, Any]) -> dict[str, Any]:
    """去掉 vec 键的浅拷贝——对外（system 注入 / HTTP）不暴露 BLOB。"""
    return {k: v for k, v in m.items() if k != "vec"}


class MemoryStore:
    """按 user_id 存取“用户长期事实”。SQLite，进程内加锁（仿 UsageLogger）。"""

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS user_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    text TEXT NOT NULL,
                    kind TEXT DEFAULT 'fact',
                    status TEXT DEFAULT 'active',
                    source TEXT DEFAULT '',
                    vec BLOB,
                    created_at REAL,
                    updated_at REAL
                )"""
            )
            # 老库平滑迁移：早期表没有 status/source/vec 列，缺则补。ADD COLUMN 带默认值，
            # 现有行自动取默认（active/''/NULL），老记忆不丢、默认仍可注入，向量首检索时懒回填。
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(user_memory)")}
            if "status" not in cols:
                self._conn.execute(
                    "ALTER TABLE user_memory ADD COLUMN status TEXT DEFAULT 'active'"
                )
            if "source" not in cols:
                self._conn.execute(
                    "ALTER TABLE user_memory ADD COLUMN source TEXT DEFAULT ''"
                )
            if "vec" not in cols:
                self._conn.execute("ALTER TABLE user_memory ADD COLUMN vec BLOB")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_memory_user ON user_memory(user_id)"
            )
            self._conn.commit()

    def all_for(
        self, user_id: str, limit: int = 200, include_superseded: bool = False,
        with_vec: bool = False,
    ) -> list[dict[str, Any]]:
        """默认只返回 active（当前有效）记忆；include_superseded=True 连同已下线的一起返回（审计/回溯）。

        with_vec=True 时 dict 附带 vec（BLOB，仅检索内部用）；默认不带，
        保证对外 dict（HTTP 响应/system 注入）干净，不混入无法 JSON 序列化的 bytes。
        """
        cols = "id, text, kind, status, source, created_at, updated_at"
        if with_vec:
            cols += ", vec"
        sql = f"SELECT {cols} FROM user_memory WHERE user_id=?"  # noqa: S608 (列名固定，非用户输入)
        params: list[Any] = [user_id]
        if not include_superseded:
            sql += " AND status='active'"
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = {
                "id": r[0], "text": r[1], "kind": r[2], "status": r[3],
                "source": r[4], "created_at": r[5], "updated_at": r[6],
            }
            if with_vec:
                d["vec"] = r[7]
            out.append(d)
        return out

    def add(self, user_id: str, text: str, kind: str = "fact", source: str = "") -> bool:
        """新增一条。返回是否真正写入。source 记来源依据（用户原话片段）。

        去重与时效消解（抗失智闸②），对每条旧 active 记忆按文本相似度 ratio 分档：
        - ratio>0.82 且**一侧无独占实词**（一方是另一方超集/纯近重复）→ 跳过，不写；
        - ratio≥0.6 且**双方各有独占实词**且同 kind（如「在北京」vs「在上海」这类局部值替换）
          → 判为事实更新：旧记忆标 superseded、只留新的（顺带修掉「事实更新被当近重复丢弃」的老坑）；
        - 其余 → 视为独立新事实，保守起见不动旧的。
        判据是「局部值替换」，对并列事实可能偏激进；但被降级的旧记忆不删除
        （status=superseded，可经 include_superseded 回溯/恢复），代价可控。
        """
        text = (text or "").strip()
        if not text or not user_id:
            return False
        new_tok = _tokens(text)
        supersede_ids: list[int] = []
        for m in self.all_for(user_id):
            ratio = difflib.SequenceMatcher(None, m["text"], text).ratio()
            only_old = _tokens(m["text"]) - new_tok
            only_new = new_tok - _tokens(m["text"])
            if ratio > 0.82 and (not only_old or not only_new):
                return False  # 近重复/一方为超集 → 跳过
            if ratio >= 0.6 and only_old and only_new and m["kind"] == kind:
                supersede_ids.append(int(m["id"]))  # 同结构、局部值不同 → 事实更新
        now = time.time()
        with self._lock:
            for sid in supersede_ids:
                self._conn.execute(
                    "UPDATE user_memory SET status='superseded', updated_at=? WHERE id=?",
                    (now, sid),
                )
            self._conn.execute(
                "INSERT INTO user_memory "
                "(user_id, text, kind, status, source, vec, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (user_id, text, kind, "active", source, _vec_blob(text), now, now),
            )
            self._conn.commit()
        return True

    def search(self, user_id: str, query: str, k: int = _MAX_INJECT) -> list[dict[str, Any]]:
        """混合检索：IDF 加权关键词分（抗失智闸③）+ 本地向量余弦，加权融合。

        - IDF 分 = Σ idf(命中 token) / Σ idf(query token)，归一化到 0..1：稀有区分词
          （Python/上海）权重高、高频虚词（用户/的）权重低，避免高频词主导而召回无关记忆。
        - 向量分：query 向量与各记忆向量余弦；embedder 未就绪/降级 → 自动退化为纯 IDF。
        - 老记忆缺向量者首次检索懒回填。无重叠且无向量则回退最近 k 条（用户画像）。
        """
        mems = self.all_for(user_id, with_vec=True)
        if not mems:
            return []
        q = _tokens(query)
        if not q:
            return [_strip_vec(m) for m in mems[:k]]
        mem_toks = [_tokens(m["text"]) for m in mems]
        n = len(mems)
        df: dict[str, int] = {}
        for tk in mem_toks:
            for t in tk:
                df[t] = df.get(t, 0) + 1

        # 平滑 IDF：出现越少权重越高；+1 防除零，log(1+·) 保正。
        def _idf(t: str) -> float:
            return math.log(1 + n / (1 + df.get(t, 0)))

        q_full = sum(_idf(t) for t in q) or 1.0  # query 全命中的满分，用于把关键词分归一化到 0..1
        qvec = encode_query(query)
        refill: list[tuple[int, str]] = []
        scored: list[tuple[float, dict[str, Any]]] = []
        for m, tk in zip(mems, mem_toks):
            kw = sum(_idf(t) for t in (q & tk)) / q_full
            vs = cosine_blobs(qvec, m.get("vec"))
            if qvec is not None and vs is None:
                refill.append((int(m["id"]), m["text"]))  # 缺向量的老记忆 → 记下懒回填
            scored.append((fuse(kw, vs), m))
        if qvec is not None and refill:
            self._refill_vecs(refill)  # 一次性补向量，不影响本次结果
        scored.sort(key=lambda s: s[0], reverse=True)
        hits = [m for sc, m in scored if sc > 0][:k]
        return [_strip_vec(m) for m in (hits or mems[:k])]

    def _refill_vecs(self, items: list[tuple[int, str]]) -> None:
        """给缺向量的老记忆补编码（一次性）。失败静默——绝不影响检索。"""
        mat = encode([t for _i, t in items], is_query=False)
        if mat is None:
            return
        with self._lock:
            for j, (mid, _t) in enumerate(items):
                self._conn.execute(
                    "UPDATE user_memory SET vec=? WHERE id=?", (to_blob(mat[j]), mid)
                )
            self._conn.commit()

    def delete(self, mem_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM user_memory WHERE id=?", (mem_id,))
            self._conn.commit()

    def clear(self, user_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM user_memory WHERE user_id=?", (user_id,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def format_memories(mems: list[dict[str, Any]]) -> str:
    if not mems:
        return ""
    lines = "\n".join(f"- {m['text']}" for m in mems)
    # 注入的长期记忆属“冗余上下文”，可有损压缩省 token（不动用户当前问题）。
    # compress_text 安全降级：短/不可用/异常都原样返回，不影响行为。
    try:
        from orchestrator.compress import compress_text

        lines = compress_text(lines, rate=0.6)
    except Exception:  # noqa: BLE001
        pass
    return f"【关于当前用户你已了解（回答时自然利用，不要生硬复述）】\n{lines}"


_EXTRACT_PROMPT = (
    "你是记忆抽取器。从下面这轮对话中，抽取关于【用户本人】的、长期有用的事实"
    "（如身份/职业、稳定偏好、习惯、长期目标、重要约束）。\n"
    "铁律（防止记忆失智）：事实必须以【用户自己说过的话】为依据；不得臆测推断、"
    "不得把助手说的内容当成用户事实、不得脑补用户没表达过的信息。\n"
    "只抽取持久的个人事实；忽略一次性/临时内容、闲聊、对你的称呼。\n"
    "严格只输出一个 JSON 数组，每项形如 "
    '{{"fact":"简短中文事实","evidence":"用户原话中的依据片段"}}；'
    "evidence 必须逐字摘自上面【用户】的话。没有可抽取的就输出 []。\n\n"
    "用户：{user}\n助手：{assistant}\n\nJSON："
)


def _parse_facts(text: str) -> list[tuple[str, str]]:
    """解析抽取结果为 [(fact, evidence)]。新格式为 [{"fact","evidence"}]；
    兼容旧的纯字符串数组（evidence 置空 → 走弱校验）。"""
    m = re.search(r"\[.*\]", text or "", re.S)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for x in arr:
        if isinstance(x, str) and x.strip():
            out.append((x.strip()[:200], ""))
        elif isinstance(x, dict):
            fact = str(x.get("fact") or "").strip()[:200]
            evidence = str(x.get("evidence") or "").strip()[:300]
            if fact:
                out.append((fact, evidence))
    return out[:8]


def _grounded(fact: str, evidence: str, user_msg: str) -> bool:
    """防投毒校验（抗失智闸①）：事实须有用户原话支撑，否则判为脑补、丢弃。

    evidence 逐字命中用户消息 → 强通过；否则回退看 evidence/fact 的 token 是否大部分
    (≥0.6) 出现在用户消息里。**只用【用户消息】做锚，绝不拿助手内容当依据**——
    否则模型会把自己上一轮说的话反哺成"用户事实"，正是失智的源头。
    """
    um_flat = re.sub(r"\s+", "", (user_msg or "").lower())
    ev = re.sub(r"\s+", "", (evidence or "").lower())
    if len(ev) >= 2 and ev in um_flat:
        return True
    ut = _tokens(user_msg)
    if not ut:
        return False
    probe = _tokens(evidence) or _tokens(fact)
    if not probe:
        return False
    return len(probe & ut) / len(probe) >= 0.6


async def extract_and_store(
    router: Any,
    store: MemoryStore,
    *,
    user_id: str,
    user_msg: str,
    assistant_msg: str,
    model: str,
) -> list[str]:
    """用便宜/免费模型从一轮对话抽取用户事实并入库。返回新写入的事实。

    防投毒（抗失智闸①）：每条抽取的事实须过 _grounded 校验——有用户原话支撑才入库，
    模型脑补/臆断的直接丢弃，避免脏记忆污染之后每一轮的注入。
    """
    if not user_id or len((user_msg or "").strip()) < 4:
        return []
    prompt = _EXTRACT_PROMPT.format(user=user_msg[:1500], assistant=(assistant_msg or "")[:1500])
    req = ChatCompletionRequest(model=model, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
    try:
        with bind_provider_call_scope(role="memory.extract"):
            res, _served, _route = await chat_with_fallback(router, req)
    except Exception:  # noqa: BLE001
        return []
    text = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    stored: list[str] = []
    for fact, evidence in _parse_facts(text):
        if not _grounded(fact, evidence, user_msg):
            continue  # 无用户原话支撑 → 判为脑补，拦截不入库
        if store.add(user_id, fact, source=evidence[:200]):
            stored.append(fact)
    return stored


_REFLECT_PROMPT = (
    "下面是关于某用户的一些零散记忆。请归纳成更概括、更有用的几条高层洞察"
    "（合并重复、提炼稳定习惯与偏好）。\n"
    "严格只输出一个 JSON 数组，每项一句简短中文；最多 5 条。\n\n记忆：\n{mems}\n\nJSON："
)


async def reflect(router: Any, store: MemoryStore, *, user_id: str, model: str) -> list[str]:
    """反思（Generative Agents）：把零散记忆归纳为高层洞察(kind=insight)并入库。"""
    mems = store.all_for(user_id)
    if len(mems) < 3:
        return []
    text = "\n".join(f"- {m['text']}" for m in mems)
    req = ChatCompletionRequest(  # type: ignore[arg-type]
        model=model, messages=[{"role": "user", "content": _REFLECT_PROMPT.format(mems=text)}]
    )
    try:
        with bind_provider_call_scope(role="memory.reflect"):
            res, _served, _route = await chat_with_fallback(router, req)
    except Exception:  # noqa: BLE001
        return []
    out = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    # 反思是对已过滤记忆的归纳，无需二次 grounding；insight 无单一 evidence，source 留空。
    return [f for f, _ev in _parse_facts(out) if store.add(user_id, f, kind="insight")]
