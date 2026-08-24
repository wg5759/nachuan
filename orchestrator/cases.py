"""案例库 + 师生进化（M3）：强模型解过的难题存为“案例/技能”，下次免费模型照着答。

打法：Voyager（技能库越攒越强）+ Memento（无需微调、靠案例检索复用）+ DSPy（老师给学生示范）。
每轮决策：
  · 命中足够相似的历史案例 → 用免费模型(学生)带着“老师解法”作答（不再烧强模型）。
  · 否则按难度：难题 → 强模型(老师)解，并把解法存入案例库；易题 → 免费/便宜模型。
案例默认按用户隔离（隐私安全；群聊多用户也不串台）。
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from orchestrator.classify import classify
from orchestrator.memory import _tokens  # 复用语言无关的粗分词
from orchestrator.modes import pick_model

# 查询关键词被某历史案例“问题”覆盖到的比例阈值；达到即视为“解过的同类题”。
CASE_REUSE_THRESHOLD = 0.4
_PREFER_FREE = "agnes-flash"  # 学生模型优先用免费 Agnes，省额度
_MAX_SOLUTION = 4000
_DEDUP_THRESHOLD = 0.85  # 新案例与已有"问题"相似度≥此值=近重复 → 复用不新增(治技能/案例膨胀)


class CaseLibrary:
    """按 user_id 存“难题→强模型解法”的案例。SQLite，进程内加锁。"""

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    problem TEXT NOT NULL,
                    solution TEXT NOT NULL,
                    model TEXT,
                    created_at REAL
                )"""
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id)")
            self._conn.commit()

    def add(self, user_id: str, problem: str, solution: str, model: str = "") -> int:
        problem = (problem or "").strip()
        solution = (solution or "").strip()[:_MAX_SOLUTION]
        if not user_id or not problem or not solution:
            return 0
        # 去重(自研技能进化第一步·治膨胀)：与已有案例高度相似就复用、不重复堆
        hits = self.search(user_id, problem, k=1)
        if hits and hits[0]["score"] >= _DEDUP_THRESHOLD:
            return int(hits[0]["id"])
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO cases (user_id, problem, solution, model, created_at) "
                "VALUES (?,?,?,?,?)",
                (user_id, problem, solution, model, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def all_for(self, user_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, problem, solution, model, created_at FROM cases "
                "WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [
            {"id": r[0], "problem": r[1], "solution": r[2], "model": r[3], "created_at": r[4]}
            for r in rows
        ]

    def export_all(self, user_id: str) -> list[dict[str, Any]]:
        """导出某用户全部案例（跨机同步/备份用的便携包）。"""
        return self.all_for(user_id, limit=1_000_000)

    def import_merge(self, user_id: str, items: list[dict[str, Any]]) -> int:
        """合并导入（跨机同步 push/pull、或从备份还原）：逐条 add，去重已内置→幂等。返回净新增条数。"""
        n0 = self.count(user_id)
        for it in items or []:
            self.add(
                user_id, str(it.get("problem", "")), str(it.get("solution", "")), str(it.get("model", ""))
            )
        return self.count(user_id) - n0

    def count(self, user_id: str) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM cases WHERE user_id=?", (user_id,)
                ).fetchone()[0]
            )

    def search(self, user_id: str, query: str, k: int = 3) -> list[dict[str, Any]]:
        """返回最相似的案例，带 score(0..1=查询关键词被问题覆盖的比例)。"""
        q = _tokens(query)
        if not q:
            return []
        out = []
        for c in self.all_for(user_id):
            score = len(q & _tokens(c["problem"])) / len(q)
            if score > 0:
                out.append({**c, "score": round(score, 3)})
        out.sort(key=lambda c: c["score"], reverse=True)
        return out[:k]

    def clear(self, user_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM cases WHERE user_id=?", (user_id,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def format_case(case: dict[str, Any]) -> str:
    # 案例“解法”常是强模型的长篇输出（冗余上下文）→ 可有损压缩省 token。
    # 只压解法，不压“问题”（问题短、且要保留以便对照）。安全降级：异常原样返回。
    solution = case["solution"]
    try:
        from orchestrator.compress import compress_text

        solution = compress_text(solution, rate=0.5)
    except Exception:  # noqa: BLE001
        pass
    return (
        "【你过去解决过类似问题，参考当时的思路作答（按需改进，不要照抄）】\n"
        f"问题：{case['problem']}\n解法：{solution}"
    )


def _free_or_cheap(router: Any) -> str | None:
    return _PREFER_FREE if router.resolve(_PREFER_FREE) else pick_model(router, "cheap")


def decide_route(router: Any, user_id: str, message: str, cases: CaseLibrary | None) -> dict[str, Any]:
    """决定：用哪个模型、是否注入案例、是否把本轮存为新案例。

    返回 {model, label(case_reuse/teacher/cheap), case, store}。
    """
    if cases is not None and user_id:
        hits = cases.search(user_id, message, k=1)
        if hits and hits[0]["score"] >= CASE_REUSE_THRESHOLD:
            return {"model": _free_or_cheap(router), "label": "case_reuse", "case": hits[0], "store": False}
    c = classify(message)
    if c.get("difficulty") == "hard":
        return {"model": pick_model(router, "premium"), "label": "teacher", "case": None, "store": True}
    return {"model": _free_or_cheap(router), "label": "cheap", "case": None, "store": False}
