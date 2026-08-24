"""服务端持久化「滚动摘要」——真正无限长的对话上下文（跨请求累积，不丢主线）。

机主要的终极形态：不是每次请求重新压一遍，而是**把摘要存下来、跨请求累积滚动**：
- 每个对话（conv_id）在 SQLite 里存一份「主线摘要」+ 已折叠进摘要的消息数（covered）。
- 每次请求：已在摘要里的老消息跳过；新产生的、且不在"最近若干条"里的中段消息，**增量折叠**进
  已有摘要（把旧摘要 + 新几轮 → 更新后的摘要）；最近 keep_recent 条永远原样精确保留。
- 于是对话再长，喂给模型的永远是「主线摘要（不断累积）＋最近细节」，token 有界、主线不丢。

与 `history_compress.py`（无 conv_id 时的无状态兜底）、`compress.py`（单条超长文本逐 token 压）互补。

降级第一：摘要用便宜模型 + 硬超时；任何失败（无模型/超时/DB 异常）→ 退回无状态压缩或原样历史，
绝不因摘要挡任务。存储异常全吞。
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from orchestrator.history_compress import _history_chars, compress_history

_REPO = Path(__file__).resolve().parent.parent
_DATA = Path(os.getenv("DATA_DIR") or (_REPO / "data"))

# 最近这么多条永远原样保留（精确不失真）。
_KEEP_RECENT = 8
# 待折叠中段累计超过此字符数才触发一次增量折叠（省摘要调用；短对话零开销）。
_FOLD_THRESHOLD_CHARS = 6000
_SUMMARY_TIMEOUT = 60.0


def _db_path() -> str:
    return str(_DATA / "conv_summary.db")


class _Store:
    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS conv_summary (
                    conv_id TEXT PRIMARY KEY,
                    summary TEXT NOT NULL DEFAULT '',
                    covered INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT
                )"""
            )
            self._conn.commit()

    def get(self, conv_id: str) -> tuple[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT summary, covered FROM conv_summary WHERE conv_id=?", (conv_id,)
            ).fetchone()
        return (str(row[0] or ""), int(row[1] or 0)) if row else ("", 0)

    def put(self, conv_id: str, summary: str, covered: int) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO conv_summary (conv_id, summary, covered, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(conv_id) DO UPDATE SET
                       summary=excluded.summary, covered=excluded.covered, updated_at=excluded.updated_at""",
                (conv_id, summary, covered, time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            self._conn.commit()

    def clear(self, conv_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM conv_summary WHERE conv_id=?", (conv_id,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_instance: _Store | None = None
_inst_lock = threading.Lock()


def _get_store() -> _Store | None:
    global _instance
    if _instance is not None:
        return _instance
    with _inst_lock:
        if _instance is None:
            try:
                _instance = _Store(_db_path())
            except Exception:  # noqa: BLE001 建库失败 → 上层退回无状态
                return None
    return _instance


def reset() -> None:
    """测试隔离：丢弃当前实例（换 _db_path 后调它）。"""
    global _instance
    with _inst_lock:
        if _instance is not None:
            try:
                _instance.close()
            except Exception:  # noqa: BLE001
                pass
        _instance = None


def clear(conv_id: str) -> None:
    """清一个对话的滚动摘要（新对话/用户清空时调）。异常全吞。"""
    try:
        st = _get_store()
        if st and conv_id:
            st.clear(conv_id)
    except Exception:  # noqa: BLE001
        pass


async def _merge_summarize(router: Any, prev_summary: str, fold_msgs: list[dict[str, Any]]) -> str:
    """把「已有主线摘要 + 新增几轮对话」增量合并成更新后的主线摘要（便宜模型，硬超时）。

    失败 → 返回 prev_summary（不推进，等下次再折叠；绝不丢已有摘要）。
    """
    convo = "\n".join(
        f"{m.get('role', '?')}: {str(m.get('content') or '')[:1500]}" for m in fold_msgs
    )[:16000]
    prompt = (
        "你在维护一份『对话主线摘要』，随对话进行不断更新。下面给你【已有摘要】和【新增的几轮对话】，"
        "请输出【更新后的摘要】——把新增内容并入，只保留对后续继续工作有用的信息：关键事实、已做的决定、"
        "产出的文件/路径/任务号、当前未完成任务及进度、用户偏好约束。丢掉寒暄与跑偏支线，用简洁要点，"
        "**总长度控制住（老信息可进一步概括），不要无限膨胀**。\n\n"
        f"【已有摘要】\n{prev_summary or '(暂无)'}\n\n【新增的几轮对话】\n{convo}\n\n【更新后的摘要】："
    )
    try:
        from gateway.failover import chat_with_fallback
        from gateway.provider_call_ledger import bind_provider_call_scope
        from gateway.schemas import ChatCompletionRequest
        from orchestrator.modes import pick_model

        cheap = "agnes-flash" if router.resolve("agnes-flash") else pick_model(router, "cheap")
        if not cheap:
            return prev_summary
        req = ChatCompletionRequest(model=cheap, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
        with bind_provider_call_scope(role="conversation_summary.merge"):
            res, _s, _r = await asyncio.wait_for(
                chat_with_fallback(router, req), timeout=_SUMMARY_TIMEOUT
            )
        out = ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        return out or prev_summary
    except Exception:  # noqa: BLE001
        return prev_summary


async def rolling_compress(
    router: Any,
    conv_id: str | None,
    messages: list[dict[str, Any]] | None,
    *,
    keep_recent: int = _KEEP_RECENT,
) -> list[dict[str, Any]] | None:
    """对话历史累积滚动摘要压缩。返回喂给模型的干净历史（[主线摘要 system] + 最近若干条）。

    - 无 conv_id → 退回无状态 `compress_history`（仍能压，只是不跨请求累积）。
    - 有 conv_id：读持久化摘要 + covered；把"新增且非最近"的中段增量折叠进摘要；最近 keep_recent 原样。
    - 任何失败 → 退回无状态压缩或原样（降级第一）。
    """
    if not messages:
        return messages
    if not conv_id:
        return await compress_history(router, messages, keep_recent=keep_recent)

    st = _get_store()
    if st is None:
        return await compress_history(router, messages, keep_recent=keep_recent)

    try:
        summary, covered = st.get(conv_id)
    except Exception:  # noqa: BLE001
        return await compress_history(router, messages, keep_recent=keep_recent)

    n = len(messages)
    # 前端把历史裁短了/用户编辑过 → covered 失效，重置成无状态重新压（安全）。
    if covered > n:
        summary, covered = "", 0

    recent_start = max(0, n - keep_recent)
    fold = messages[covered:recent_start]  # 新增(未折叠) 且 不在最近 keep_recent 里的中段
    # 触发折叠：有中段可折 且 (已有摘要 或 中段够长)。短对话且无摘要 → 原样返回，零开销。
    if fold and (summary or _history_chars(fold) >= _FOLD_THRESHOLD_CHARS):
        new_summary = await _merge_summarize(router, summary, fold)
        if new_summary and new_summary != summary:
            summary = new_summary
            covered = recent_start
            try:
                st.put(conv_id, summary, covered)
            except Exception:  # noqa: BLE001 存失败不影响本次返回
                pass

    if not summary:
        return messages  # 还没攒够摘要 → 原样

    note = {
        "role": "system",
        "content": (
            "【本对话主线摘要（引擎跨请求累积维护，长对话也不丢主线；最近几轮在下方原样保留）】\n"
            + summary
        ),
    }
    return [note] + messages[recent_start:]
