"""非财务用量看板：把端点聚合结果落到本地 SQLite 供 UI 展示。

此旧表可能只覆盖外层 endpoint，且 token 缺失时沿用历史 ``0`` 语义；它
不是 provider attempt 财务真相源，也不得与 ``provider_calls`` 表相加计费。
逐上游调用的商业核算只使用 :mod:`gateway.provider_call_ledger`。

api_key **绝不明文落库**：入口即单向哈希成 key_id（数据库泄露≠执行凭据泄露，gpt5.6 审 P1-13）；
旧库历史明文行在启动迁移时一次性清洗。看板只按 key 区分调用来源，不需要可逆。
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


def _key_id(key: str) -> str:
    """完整 Bearer key → 不可逆短标识（固定域前缀做盐；仅用于聚合区分，不可还原）。"""
    if not key:
        return ""
    if key.startswith("k_"):  # 已是 key_id（迁移后的历史行再进来）
        return key
    return "k_" + hashlib.sha256(("nachuan-usage:" + key).encode("utf-8")).hexdigest()[:12]

# 仅允许写入这些列（列名来自本项目代码，非用户输入；白名单再加一层防护）
_COLUMNS = {
    "ts", "api_key", "virtual_model", "provider", "upstream_model", "tier",
    "prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens", "cost_usd",
    "stream", "status", "latency_ms",
}


class UsageLogger:
    financial_source = False

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    api_key TEXT,
                    virtual_model TEXT,
                    provider TEXT,
                    upstream_model TEXT,
                    tier TEXT,
                    prompt_tokens INTEGER DEFAULT 0,
                    completion_tokens INTEGER DEFAULT 0,
                    total_tokens INTEGER DEFAULT 0,
                    cached_tokens INTEGER DEFAULT 0,
                    stream INTEGER DEFAULT 0,
                    status TEXT,
                    latency_ms INTEGER,
                    cost_usd REAL DEFAULT 0
                )
                """
            )
            # 迁移：给旧库补 cost_usd 列
            try:
                self._conn.execute("ALTER TABLE usage ADD COLUMN cost_usd REAL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:  # 迁移：旧库补 cached_tokens（原生 prompt 缓存命中量）
                self._conn.execute("ALTER TABLE usage ADD COLUMN cached_tokens INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            # 迁移：清洗历史明文 key → key_id（一次性；已是 k_ 前缀的跳过）
            try:
                rows = self._conn.execute(
                    "SELECT DISTINCT api_key FROM usage WHERE api_key IS NOT NULL AND api_key != '' AND api_key NOT LIKE 'k\\_%' ESCAPE '\\'"
                ).fetchall()
                for (old,) in rows:
                    self._conn.execute("UPDATE usage SET api_key = ? WHERE api_key = ?", (_key_id(str(old)), old))
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    def log(self, **fields: Any) -> None:
        fields.setdefault("ts", time.time())
        if "api_key" in fields:  # 单点治理：任何调用方传进来的完整 key 都在此哈希，绝不明文落库
            fields["api_key"] = _key_id(str(fields.get("api_key") or ""))
        clean = {k: v for k, v in fields.items() if k in _COLUMNS}
        cols = ", ".join(clean.keys())
        placeholders = ", ".join(["?"] * len(clean))
        with self._lock:
            self._conn.execute(
                f"INSERT INTO usage ({cols}) VALUES ({placeholders})",
                list(clean.values()),
            )
            self._conn.commit()

    def summary(self) -> list[dict[str, Any]]:
        """按虚拟模型聚合：调用次数、各类 token 总量、自报实际成本之和。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT virtual_model, provider, COUNT(*), "
                "SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens), "
                "SUM(COALESCE(cost_usd, 0)), SUM(COALESCE(cached_tokens, 0)) "
                "FROM usage GROUP BY virtual_model ORDER BY SUM(total_tokens) DESC"
            ).fetchall()
        return [
            {
                "model": r[0],
                "provider": r[1],
                "calls": r[2],
                "prompt_tokens": int(r[3] or 0),
                "completion_tokens": int(r[4] or 0),
                "total_tokens": int(r[5] or 0),
                "actual_cost_usd": float(r[6] or 0),
                "cached_tokens": int(r[7] or 0),
            }
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
