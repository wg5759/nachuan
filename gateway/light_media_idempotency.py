"""轻量媒体幂等键存储（P1-1：替代默认关闭的重型 paid-media 保险库冷启动开销）。

在统一核心库（``nachuan_core.db``）中维护单表 ``media_idempotency_keys``，提供：
1. 防重复提交（processing 占位，含超时接管）；
2. 同键同参直接返回缓存结果（succeeded -> cached）；
3. 同键不同参数/模态冲突检测（返回 conflict 或抛出 409 ``LightMediaIdempotencyConflict``）。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from storage.unified_db import ensure_unified_wal, resolve_db_path

ClaimState = Literal["claimed", "cached", "in_progress", "conflict"]


class LightMediaIdempotencyConflict(Exception):
    """同一幂等键被用于不同参数或模态时抛出（对应 HTTP 409）。"""

    status_code: int = 409

    def __init__(
        self,
        message: str = "idempotency key already bound to a different request",
        *,
        idempotency_key: str = "",
        modality: str = "",
    ) -> None:
        super().__init__(message)
        self.idempotency_key = idempotency_key
        self.modality = modality


@dataclass(frozen=True, slots=True)
class LightMediaClaimResult:
    state: ClaimState
    idempotency_key: str
    modality: str
    request_hash: str
    result: dict[str, Any] | None = None
    status_code: int = 200


def compute_request_hash(payload: Any) -> str:
    """对媒体请求参数计算稳定的 SHA-256 摘要。"""

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class LightMediaIdempotencyStore:
    """单表轻量媒体幂等存储，默认落于统一核心库 ``nachuan_core.db``。"""

    OWNED_TABLES: frozenset[str] = frozenset({"media_idempotency_keys"})

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        data_dir: str | Path | None = None,
        db_mode: str | None = None,
        stale_after_sec: float = 300.0,
    ) -> None:
        resolved = resolve_db_path(
            "light_media_idempotency",
            data_dir=data_dir,
            explicit_path=db_path,
            db_mode=db_mode,
        )
        self.path = resolved
        self._stale_after_sec = max(1.0, float(stale_after_sec))
        self._lock = threading.RLock()
        is_memory = str(resolved) == ":memory:"
        if not is_memory:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(resolved),
            check_same_thread=False,
            timeout=5.0,
            isolation_level=None,
        )
        if not is_memory:
            ensure_unified_wal(self._conn, busy_timeout_ms=5000)
        else:
            self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS media_idempotency_keys (
                        idempotency_key TEXT PRIMARY KEY,
                        modality TEXT NOT NULL,
                        status TEXT NOT NULL,
                        request_hash TEXT NOT NULL,
                        result_json TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_media_idempotency_updated "
                    "ON media_idempotency_keys(updated_at)"
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def claim(
        self,
        idempotency_key: str,
        modality: str,
        request_hash: str,
        *,
        now: float | None = None,
        raise_on_conflict: bool = False,
    ) -> LightMediaClaimResult:
        """原子声明一个幂等键：首次占位、同键同参命中缓存/处理中、同键异参报 409 冲突。"""

        key = str(idempotency_key or "").strip()
        mod = str(modality or "").strip()
        req_hash = str(request_hash or "").strip()
        if not key or not mod or not req_hash:
            raise ValueError("idempotency_key, modality, and request_hash must be non-empty")
        ts = time.time() if now is None else float(now)

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT modality, status, request_hash, result_json, updated_at "
                    "FROM media_idempotency_keys WHERE idempotency_key=?",
                    (key,),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO media_idempotency_keys("
                        "idempotency_key, modality, status, request_hash, result_json, created_at, updated_at"
                        ") VALUES (?, ?, 'processing', ?, '', ?, ?)",
                        (key, mod, req_hash, ts, ts),
                    )
                    self._conn.execute("COMMIT")
                    return LightMediaClaimResult(
                        state="claimed",
                        idempotency_key=key,
                        modality=mod,
                        request_hash=req_hash,
                        result=None,
                        status_code=200,
                    )

                existing_mod, existing_status, existing_hash, result_json, updated_at = row
                if str(existing_hash) != req_hash or str(existing_mod) != mod:
                    self._conn.execute("COMMIT")
                    if raise_on_conflict:
                        raise LightMediaIdempotencyConflict(
                            "idempotency key conflicts with an existing request",
                            idempotency_key=key,
                            modality=mod,
                        )
                    return LightMediaClaimResult(
                        state="conflict",
                        idempotency_key=key,
                        modality=mod,
                        request_hash=req_hash,
                        result=None,
                        status_code=409,
                    )

                if str(existing_status) == "succeeded":
                    self._conn.execute("COMMIT")
                    decoded = json.loads(result_json) if result_json else {}
                    return LightMediaClaimResult(
                        state="cached",
                        idempotency_key=key,
                        modality=mod,
                        request_hash=req_hash,
                        result=decoded if isinstance(decoded, dict) else {"result": decoded},
                        status_code=200,
                    )

                if str(existing_status) == "processing" and (ts - float(updated_at)) < self._stale_after_sec:
                    self._conn.execute("COMMIT")
                    return LightMediaClaimResult(
                        state="in_progress",
                        idempotency_key=key,
                        modality=mod,
                        request_hash=req_hash,
                        result=None,
                        status_code=409,
                    )

                # failed 或已超时的 processing 允许同键同参接管重试
                self._conn.execute(
                    "UPDATE media_idempotency_keys SET status='processing', result_json='', updated_at=? "
                    "WHERE idempotency_key=?",
                    (ts, key),
                )
                self._conn.execute("COMMIT")
                return LightMediaClaimResult(
                    state="claimed",
                    idempotency_key=key,
                    modality=mod,
                    request_hash=req_hash,
                    result=None,
                    status_code=200,
                )
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def complete(
        self,
        idempotency_key: str,
        result: dict[str, Any],
        *,
        now: float | None = None,
    ) -> bool:
        """提交成功结果并缓存，供后续同键请求直接命中。"""

        key = str(idempotency_key or "").strip()
        ts = time.time() if now is None else float(now)
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE media_idempotency_keys SET status='succeeded', result_json=?, updated_at=? "
                    "WHERE idempotency_key=?",
                    (encoded, ts, key),
                )
                self._conn.execute("COMMIT")
                return cur.rowcount > 0
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def fail(
        self,
        idempotency_key: str,
        error: str = "",
        *,
        now: float | None = None,
    ) -> bool:
        """标记本次执行失败，允许调用方以同键同参安全重试。"""

        key = str(idempotency_key or "").strip()
        ts = time.time() if now is None else float(now)
        encoded = json.dumps({"error": str(error or "")}, ensure_ascii=False) if error else ""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE media_idempotency_keys SET status='failed', result_json=?, updated_at=? "
                    "WHERE idempotency_key=?",
                    (encoded, ts, key),
                )
                self._conn.execute("COMMIT")
                return cur.rowcount > 0
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        key = str(idempotency_key or "").strip()
        with self._lock:
            row = self._conn.execute(
                "SELECT idempotency_key, modality, status, request_hash, result_json, created_at, updated_at "
                "FROM media_idempotency_keys WHERE idempotency_key=?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return {
            "idempotency_key": str(row[0]),
            "modality": str(row[1]),
            "status": str(row[2]),
            "request_hash": str(row[3]),
            "result": json.loads(row[4]) if row[4] else None,
            "created_at": float(row[5]),
            "updated_at": float(row[6]),
        }

    def prune_expired(self, *, max_age_sec: float = 86_400.0, now: float | None = None) -> int:
        cutoff = (time.time() if now is None else float(now)) - max(1.0, float(max_age_sec))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "DELETE FROM media_idempotency_keys WHERE updated_at < ?",
                    (cutoff,),
                )
                self._conn.execute("COMMIT")
                return max(0, int(cur.rowcount))
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()
