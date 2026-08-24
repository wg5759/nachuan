"""Server-issued, one-time receipts for reverting agent file writes.

The browser is not trusted to choose an arbitrary path or replacement content.
It may only return the exact pre-image that the server hashed into a signed
receipt when the write occurred.  A tiny SQLite ledger makes receipts one-shot
and survives gateway restarts without storing the file contents themselves.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


_MAX_TEXT_BYTES = 2 * 1024 * 1024
_TTL_SECONDS = 24 * 60 * 60
_EXECUTING_LEASE_SECONDS = 60
_MAX_RECEIPT_ROWS = 50_000
_MAX_DB_BYTES = 64 * 1024 * 1024


class UndoReceiptError(RuntimeError):
    """Receipt is invalid, expired, replayed, or no longer safe to apply."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _norm(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _read_current(path: str) -> bytes:
    with open(path, "rb") as handle:
        raw = handle.read(_MAX_TEXT_BYTES + 1)
    if len(raw) > _MAX_TEXT_BYTES:
        raise UndoReceiptError("撤销目标超过安全大小上限")
    return raw


class UndoReceiptStore:
    def __init__(self, db_path: str | Path, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("undo receipt secret must be at least 32 bytes")
        self._secret = bytes(secret)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout=5000")
        mode = str(self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0])
        if mode.casefold() != "wal":
            self._conn.close()
            raise RuntimeError("undo receipt database requires SQLite WAL mode")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA journal_size_limit=8388608")
        self._conn.execute("PRAGMA wal_autocheckpoint=1000")
        page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
        max_pages = max(1, _MAX_DB_BYTES // page_size)
        actual_pages = int(
            self._conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        )
        if actual_pages * page_size > _MAX_DB_BYTES:
            self._conn.close()
            raise RuntimeError("undo receipt database exceeds its hard size limit")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS undo_receipts (
                jti TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                started_at REAL,
                finished_at REAL
            )"""
        )
        columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(undo_receipts)").fetchall()
        }
        if "started_at" not in columns:
            self._conn.execute("ALTER TABLE undo_receipts ADD COLUMN started_at REAL")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_undo_expiry ON undo_receipts(expires_at)"
        )
        self._conn.commit()

    def issue(
        self,
        *,
        workdir: str,
        path: str,
        before: str,
        after: str,
        existed: bool,
    ) -> str:
        before_raw = before.encode("utf-8")
        after_raw = after.encode("utf-8")
        if len(before_raw) > _MAX_TEXT_BYTES or len(after_raw) > _MAX_TEXT_BYTES:
            return ""
        root = _norm(workdir)
        requested = path if os.path.isabs(path) else os.path.join(root, path)
        target = _norm(requested)
        try:
            if os.path.commonpath([root, target]) != root:
                return ""
        except ValueError:
            return ""
        now = time.time()
        payload = {
            "v": 1,
            "jti": secrets.token_urlsafe(18),
            "wd": root,
            "target": target,
            "path": str(path),
            "before_sha256": _sha(before_raw),
            "after_sha256": _sha(after_raw),
            "existed": bool(existed),
            "exp": int(now + _TTL_SECONDS),
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        sig = hmac.new(self._secret, raw, hashlib.sha256).digest()
        token = f"{_b64e(raw)}.{_b64e(sig)}"
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "DELETE FROM undo_receipts WHERE expires_at<? "
                    "AND (status!='executing' OR COALESCE(started_at,created_at)<=?)",
                    (now, now - _EXECUTING_LEASE_SECONDS),
                )
                count = int(
                    self._conn.execute("SELECT COUNT(*) FROM undo_receipts").fetchone()[0]
                )
                if count >= _MAX_RECEIPT_ROWS:
                    self._conn.rollback()
                    return ""
                self._conn.execute(
                    "INSERT INTO undo_receipts(jti,status,created_at,expires_at) VALUES(?,?,?,?)",
                    (payload["jti"], "pending", now, float(payload["exp"])),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return token

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            encoded, encoded_sig = token.split(".", 1)
            raw = _b64d(encoded)
            sig = _b64d(encoded_sig)
            expected = hmac.new(self._secret, raw, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise UndoReceiptError("撤销凭证签名无效")
            payload = json.loads(raw)
        except UndoReceiptError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise UndoReceiptError("撤销凭证格式无效") from exc
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise UndoReceiptError("撤销凭证版本无效")
        if float(payload.get("exp") or 0) < time.time():
            raise UndoReceiptError("撤销凭证已过期")
        return payload

    def verify_projection(
        self,
        token: str,
        *,
        path: str,
        before: str,
        after: str,
    ) -> bool:
        """Verify a UI file-change projection without consuming its receipt."""

        try:
            payload = self._decode(token)
            before_raw = before.encode("utf-8")
            after_raw = after.encode("utf-8")
            if len(before_raw) > _MAX_TEXT_BYTES or len(after_raw) > _MAX_TEXT_BYTES:
                return False
            if not (
                hmac.compare_digest(str(payload.get("path") or ""), path)
                and hmac.compare_digest(
                    str(payload.get("before_sha256") or ""), _sha(before_raw)
                )
                and hmac.compare_digest(
                    str(payload.get("after_sha256") or ""), _sha(after_raw)
                )
            ):
                return False
            jti = str(payload.get("jti") or "")
            with self._lock:
                row = self._conn.execute(
                    "SELECT status,expires_at FROM undo_receipts WHERE jti=?",
                    (jti,),
                ).fetchone()
            return bool(
                row
                and str(row[0]) in {"pending", "executing"}
                and float(row[1]) >= time.time()
            )
        except (UndoReceiptError, UnicodeError, sqlite3.Error):
            return False

    def restore(self, token: str, before: str) -> dict[str, str]:
        payload = self._decode(token)
        before_raw = before.encode("utf-8")
        if len(before_raw) > _MAX_TEXT_BYTES or not hmac.compare_digest(
            _sha(before_raw), str(payload.get("before_sha256") or "")
        ):
            raise UndoReceiptError("撤销内容与服务端凭证不匹配")
        jti = str(payload.get("jti") or "")
        now = time.time()
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                cur = self._conn.execute(
                    "UPDATE undo_receipts SET status='executing',started_at=?,finished_at=NULL "
                    "WHERE jti=? AND expires_at>=? AND "
                    "(status='pending' OR (status='executing' "
                    "AND COALESCE(started_at,created_at)<=?))",
                    (now, jti, now, now - _EXECUTING_LEASE_SECONDS),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            if cur.rowcount != 1:
                raise UndoReceiptError("撤销凭证已使用、已过期或不存在")

        status = "failed"
        try:
            # These absolute canonical paths are covered by the receipt HMAC.
            # Do not realpath them again before comparing the original lexical
            # request, or a swapped reparse point silently changes our baseline.
            root = os.path.normcase(os.path.abspath(str(payload.get("wd") or "")))
            target = os.path.normcase(
                os.path.abspath(str(payload.get("target") or ""))
            )
            try:
                if os.path.commonpath([root, target]) != root:
                    raise UndoReceiptError("撤销目标越出原工作区")
            except ValueError as exc:
                raise UndoReceiptError("撤销目标越出原工作区") from exc
            # Resolve the original lexical request again.  Resolving the already
            # normalized target is a no-op and cannot detect a swapped symlink or
            # directory junction.
            original_path = str(payload.get("path") or "")
            requested = (
                original_path
                if os.path.isabs(original_path)
                else os.path.join(root, original_path)
            )
            if _norm(requested) != target:
                raise UndoReceiptError("撤销目标已改变")
            if bool(payload.get("existed")):
                if not os.path.isfile(target):
                    raise UndoReceiptError("撤销目标不存在或不再是普通文件")
                current = _read_current(target)
                current_sha = _sha(current)
                if hmac.compare_digest(
                    current_sha, str(payload.get("before_sha256") or "")
                ):
                    # Crash after os.replace but before the DB terminal update.
                    status = "restored"
                    return {"path": str(payload.get("path") or ""), "status": status}
                if not hmac.compare_digest(
                    current_sha, str(payload.get("after_sha256") or "")
                ):
                    raise UndoReceiptError("文件在写入后又被修改，拒绝覆盖新改动")
                parent = Path(target).parent
                tmp_name = ""
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", prefix=f".{Path(target).name}.undo-", suffix=".tmp",
                        dir=parent, delete=False,
                    ) as handle:
                        tmp_name = handle.name
                        handle.write(before_raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(tmp_name, target)
                    tmp_name = ""
                finally:
                    if tmp_name:
                        try:
                            os.unlink(tmp_name)
                        except OSError:
                            pass
            else:
                if not os.path.exists(target):
                    # Crash after unlink but before the DB terminal update.
                    status = "restored"
                    return {"path": str(payload.get("path") or ""), "status": status}
                if not os.path.isfile(target):
                    raise UndoReceiptError("撤销目标不再是普通文件")
                current = _read_current(target)
                if not hmac.compare_digest(
                    _sha(current), str(payload.get("after_sha256") or "")
                ):
                    raise UndoReceiptError("文件在写入后又被修改，拒绝覆盖新改动")
                os.unlink(target)
            status = "restored"
            return {"path": str(payload.get("path") or ""), "status": status}
        finally:
            with self._lock:
                self._conn.execute(
                    "UPDATE undo_receipts SET status=?,finished_at=? WHERE jti=? AND status='executing'",
                    (status, time.time(), jti),
                )
                self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_STORE: UndoReceiptStore | None = None


def configure(store: UndoReceiptStore | None) -> None:
    global _STORE
    _STORE = store


def issue(**kwargs: Any) -> str:
    return _STORE.issue(**kwargs) if _STORE is not None else ""


def restore(token: str, before: str) -> dict[str, str]:
    if _STORE is None:
        raise UndoReceiptError("撤销服务未初始化")
    return _STORE.restore(token, before)


def verify_projection(token: str, *, path: str, before: str, after: str) -> bool:
    return bool(
        _STORE is not None
        and _STORE.verify_projection(
            token,
            path=path,
            before=before,
            after=after,
        )
    )
