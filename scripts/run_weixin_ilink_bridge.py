"""微信 iLink 官方 Bot 桥接：个人微信 ↔ 纳川引擎(/v1/agent/chat) ↔ 回复。合法·不封号·无需公网。

走腾讯 2026 官方开放的 iLink Bot API(ilinkai.weixin.qq.com，有《微信 ClawBot 功能使用条款》背书)，
不是 itchat/wechaty 那类会封号的逆向网页协议。**纯 HTTP 自持、零第三方微信 SDK**——因为要处理
微信登录凭证(bot_token)，不引入不可信三方包(供应链/投毒风险)，全用纳川自己可审计的代码。

跟 run_feishu_bridge.py 同构：扫码登录拿 bot_token → 长轮询 getupdates → 转纳川 /v1/agent/chat →
sendmessage 回复(带 context_token)。复用 bridge.policy(白名单/限频/命令/机主归一)；
user_id=微信 from_user_id，纳川长期记忆/每日额度/限频天然生效。

多模态(开源单点 bot 给不了的杀手锏)：
- 出站：纳川生成的**图片/视频真发进微信聊天**(AES-128-ECB+PKCS7 加密 → getuploadurl → CDN 上传
  → sendmessage 带 image_item/video_item)；失败自动退回发链接文字。
- 入站：用户发**图片** → CDN 下载+解密 → 纳川 /v1/vision 看图理解回描述；
  语音是 SILK 编码(ffmpeg 解不了)暂不转写、礼貌提示发文字。
- item type：TEXT=1 / IMAGE=2 / VOICE=3 / FILE=4 / VIDEO=5；上传 media_type：IMAGE=1 / VIDEO=2。

团队用法：**只扫一次码**把一个专用微信号变成 bot；成员各自用微信加它私聊(不扫码)。
安全默认：生产必须配置 data/weixin_access.json，空白名单只开放限频后的 /whoami，
不会把消息送进模型。仅本地开发可双重显式开启 NACHUAN_ENV=development + WEIXIN_ALLOW_ALL=1。
iLink bot 无法进群，只能 1:1 私聊。

跑法：先启动纳川引擎(8080)，再 `uv run python scripts/run_weixin_ilink_bridge.py`，
终端保存并打开二维码，手机微信扫码登录后即可私聊纳川。
持久配置：data/weixin_access.json；旧 WEIXIN_ALLOWED/WEIXIN_OWNER 仅在 NACHUAN_ENV=development 合并。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import math
import os
import random
import re
import secrets
import socket
import sqlite3
import stat as stat_module
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import closing, nullcontext
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bridge.access import ChannelAccessPolicy, explicit_development_allow_all  # noqa: E402
from bridge.policy import RateLimiter, parse_command, resolve_user_id  # noqa: E402
from gateway.config import get_isolated_bridge_settings  # noqa: E402
from gateway.bridge_protocol import request_bridge_bytes  # noqa: E402
from gateway.channel_media_protocol import encode_channel_media_frame  # noqa: E402
from gateway.channel_delivery_claim import (  # noqa: E402
    ClaimLeaseLost,
    ClaimLeaseSession,
)
from gateway.public_media import (  # noqa: E402
    PublicFetchError,
    PublicFetchHTTPError,
    PublicFetchTimeout,
    fetch_public_bytes,
    request_public_bytes,
)
from gateway.secure_store import (  # noqa: E402
    SecureStorageError,
    read_protected_json,
    write_protected_json,
)

S = get_isolated_bridge_settings()
ENGINE = S.bridge_engine_url.rstrip("/")
# Empty means "let the authenticated gateway choose from the currently
# verified chat routes".  A concrete model is accepted only as an explicit
# operator override; a library default must never freeze every channel Turn to
# an obsolete provider id after the customer changes connections.
MODEL = str(
    os.environ.get("WEIXIN_MODEL") or os.environ.get("BRIDGE_MODEL") or ""
).strip()
ENGINE_KEY = ""  # main() 只接受 supervisor/环境精确注入的 key
def _build_engine_opener():
    """Build a loopback-only opener that never inherits ambient proxy settings."""

    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


_ENGINE_OPENER = _build_engine_opener()
BASE = "https://ilinkai.weixin.qq.com"
ILINK_CHANNEL_VERSION = "1.0.2"
_ACCESS_FILE = Path(S.usage_db_path).parent / "weixin_access.json"
_STATE_FILE_MAX_BYTES = 64 * 1024
_REPARSE_ATTRIBUTE = int(
    getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)


class AccessConfigError(ValueError):
    pass


def _is_regular_nonreparse(info: os.stat_result) -> bool:
    return bool(
        stat_module.S_ISREG(info.st_mode)
        and not (int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE)
    )


def _read_bounded_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Bind one bounded read to an ordinary, non-reparse path snapshot."""

    last_race: BaseException | None = None
    for _attempt in range(2):
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (
                not _is_regular_nonreparse(before)
                or before.st_size <= 0
                or before.st_size > max_bytes
            ):
                raise AccessConfigError("state file is not a bounded ordinary file")
            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:
                chunk = os.read(fd, min(8192, max_bytes - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        try:
            current = path.lstat()
            if (
                path.is_symlink()
                or not _is_regular_nonreparse(current)
                or not os.path.samestat(before, after)
                or not os.path.samestat(after, current)
                or total != after.st_size
                or total > max_bytes
            ):
                raise AccessConfigError("state file changed during bounded read")
            return b"".join(chunks)
        except (FileNotFoundError, OSError, AccessConfigError) as exc:
            last_race = exc
    raise AccessConfigError("state file replacement did not stabilize") from last_race


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise AccessConfigError("duplicate JSON key")
        document[key] = value
    return document


def _load_saved_access(path: Path = _ACCESS_FILE) -> tuple[set[str], str]:
    try:
        raw = _read_bounded_regular_file(path, max_bytes=_STATE_FILE_MAX_BYTES)
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(document, dict) or document.get("schema") != "nachuan.weixin-access.v1":
            raise AccessConfigError("微信访问配置 schema 无效")
        if not set(document).issubset({"schema", "allowed_users", "owner"}):
            raise AccessConfigError("微信访问配置包含未知字段")
        raw_users = document.get("allowed_users")
        if not isinstance(raw_users, list) or len(raw_users) > 256:
            raise AccessConfigError("微信访问白名单无效")
        users: set[str] = set()
        for value in raw_users:
            if not isinstance(value, str):
                raise AccessConfigError("微信访问白名单成员类型无效")
            user = value.strip()
            if (
                not user
                or len(user) > 512
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in user)
            ):
                raise AccessConfigError("微信访问白名单成员无效")
            users.add(user)
        raw_owner = document.get("owner", "")
        if not isinstance(raw_owner, str):
            raise AccessConfigError("微信机主标识类型无效")
        owner = raw_owner.strip()
        if len(owner) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in owner):
            raise AccessConfigError("微信机主标识无效")
        return users, owner
    except FileNotFoundError:
        return set(), ""


_ACCESS_LOCK = threading.RLock()
_ACCESS_REFRESH_LOCK = threading.Lock()
ALLOWED: set[str] = set()
OWNER = ""
ACCESS = ChannelAccessPolicy()
_ACCESS_ERROR = ""
_ACCESS_GENERATION = 0


def _refresh_access() -> tuple[ChannelAccessPolicy, str, str]:
    """Load outside SQLite/auth locks, then atomically publish one snapshot."""

    global ACCESS, ALLOWED, OWNER, _ACCESS_ERROR, _ACCESS_GENERATION
    # File replacement checks and bounded reads can still wait on the filesystem.
    # Serialize those refreshes independently so no caller ever needs to hold the
    # short authorization publication lock (or a SQLite writer) across file I/O.
    with _ACCESS_REFRESH_LOCK:
        try:
            saved_allowed, saved_owner = _load_saved_access(_ACCESS_FILE)
        except (AccessConfigError, UnicodeError, json.JSONDecodeError, OSError, ValueError):
            access = ChannelAccessPolicy()
            allowed: set[str] = set()
            owner = ""
            access_error = "access_invalid"
        else:
            allowed = set(saved_allowed)
            owner = saved_owner
            if owner:
                allowed.add(owner)
            if str(os.getenv("NACHUAN_ENV", "production")).strip().lower() == "development":
                legacy_allowed = {
                    item.strip()
                    for item in os.getenv("WEIXIN_ALLOWED", "").split(",")
                    if item.strip()
                }
                legacy_owner = os.getenv("WEIXIN_OWNER", "").strip()
                allowed.update(legacy_allowed)
                if legacy_owner:
                    allowed.add(legacy_owner)
                    owner = legacy_owner
            allow_all = explicit_development_allow_all("WEIXIN")
            access = ChannelAccessPolicy(allowed, allow_all=allow_all)
            access_error = ""

        with _ACCESS_LOCK:
            ACCESS = access
            ALLOWED = allowed
            OWNER = owner
            _ACCESS_ERROR = access_error
            _ACCESS_GENERATION += 1
            return ACCESS, OWNER, _ACCESS_ERROR


_refresh_access()
_limiter = RateLimiter(S.feishu_rate_per_min)
# bot_token 存 data 目录(非 git)，重启复用免重复扫码
_TOKEN_FILE = Path(S.usage_db_path).parent / "ilink_token.json"
_OUTBOX_DB = Path(S.usage_db_path).parent / "weixin_outbox.db"
_HEALTH_FILE = Path(S.usage_db_path).parent / "weixin_bridge_health.json"
_HEALTH_LOCK = threading.RLock()
_HEALTH_FRESHNESS_TTL_SECONDS = 60
_HEALTH_STATE: dict[str, object] = {
    "service_state": "starting",
    "connected": False,
    "consecutive_poll_failures": 0,
    "last_poll_ok_at": 0.0,
    "last_message_finished_at": 0.0,
    "last_error_code": "",
    "last_handler_ok": True,
    "last_handler_error_code": "",
}
_INBOUND_WORKER_LOCK = threading.Lock()
_INBOUND_WORKERS: list[threading.Thread] = []
_INBOUND_WORKERS_CONFIGURED = 0
_ENGINE_HEALTH_LOCK = threading.RLock()
_ENGINE_AVAILABLE = False
_ENGINE_READINESS_REASON = "engine_unavailable"
_LAST_ENGINE_PROBE_MONOTONIC = 0.0
_ENGINE_PROBE_INTERVAL_SECONDS = 30.0


def _bounded_env_seconds(
    name: str, *, default: float, minimum: float, maximum: float
) -> float:
    """Read a finite duration without allowing operators to defeat an SLA cap."""

    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if not math.isfinite(value):
        value = default
    return min(maximum, max(minimum, value))


# Long-polling may wait 40 seconds, but an outbound user-visible send must not
# inherit that latency. A durable row gets one bounded network attempt; later
# attempts are scheduled by SQLite backoff in another drain cycle.
_SEND_ATTEMPT_TIMEOUT_SECONDS = _bounded_env_seconds(
    "WEIXIN_SEND_TIMEOUT_SECONDS", default=10.0, minimum=1.0, maximum=10.0
)
_PROGRESS_SEND_ATTEMPT_TIMEOUT_SECONDS = 2.0
_OUTBOX_LOCAL_PREP_BUDGET_SECONDS = 10.0
_OUTBOX_DRAIN_WALL_BUDGET_SECONDS = (
    _OUTBOX_LOCAL_PREP_BUDGET_SECONDS + _SEND_ATTEMPT_TIMEOUT_SECONDS
)
# A progress sender can spend one 10s SQLite busy wait before the bounded
# outbox drain.  The final reply must never race past that older delivery.
_PROGRESS_SETTLE_TIMEOUT_SECONDS = (
    10.0 + _OUTBOX_DRAIN_WALL_BUDGET_SECONDS + 1.0
)
# Gateway's durable budget is 55s through Agent completion.  Its fenced
# Conversation/idempotency commit tail is intentionally not cancellable and can
# consume roughly another 27s under bounded SQLite waits, so the bridge must
# leave real commit/network margin instead of dropping the socket at 60s.
_AGENT_TURN_HTTP_TIMEOUT_SECONDS = 90.0
_STATE_DB_MAX_BYTES = 256 * 1024 * 1024
_STATE_DB_MAX_WAL_BYTES = 16 * 1024 * 1024
_OUTBOX_APPLICATION_ID = 0x4E435758  # NCWX
_OUTBOX_SCHEMA_VERSION = 2
_MAX_INBOUND_PAYLOAD_BYTES = 256 * 1024
_MAX_INBOUND_ROWS = 50_000
_MAX_UPDATES_PER_POLL = 1000
_MAX_OUTBOUND_ROWS = 50_000
_MAX_OUTBOUND_TEXT_BYTES = 2 * 1024 * 1024
_MAX_PENDING_VIDEO_ROWS = 256
_MAX_PENDING_VIDEO_PER_USER = 8
_VIDEO_TASK_ID_MAX_CHARS = 512
_VIDEO_CONTEXT_MAX_CHARS = 4096
_VIDEO_TASK_TIMEOUT_SECONDS = 25 * 60
_VIDEO_RESERVATION_TTL_SECONDS = 30 * 60
_VIDEO_POLL_INTERVAL_SECONDS = 12
_VIDEO_CLAIM_TTL_SECONDS = 5 * 60
_VIDEO_HEARTBEAT_SECONDS = 30.0
_VIDEO_FINISH_RETRY_DELAYS_SECONDS = (0.0, 0.05, 0.2, 0.5)
_VIDEO_MAX_WORKERS = 4
_DELIVERY_CLAIM_TTL_SECONDS = 3 * 60
_DELIVERY_HEARTBEAT_SECONDS = 30.0
_DELIVERY_FINISH_RETRY_DELAYS_SECONDS = (0.0,)
_DELIVERY_DEAD_ATTEMPTS = 12
_INBOUND_CLAIM_TTL_SECONDS = 5 * 60
_INBOUND_HEARTBEAT_SECONDS = 30.0
_INBOUND_FINISH_RETRY_DELAYS_SECONDS = (0.0, 0.05, 0.2, 0.5)
_COMPLETED_RETENTION_SECONDS = 30 * 24 * 60 * 60
_DEAD_RETENTION_SECONDS = 180 * 24 * 60 * 60
_DEAD_MAX_ROWS = 10_000
_TERMINAL_PRUNE_INTERVAL_SECONDS = 60 * 60
_TERMINAL_PRUNE_LOCK = threading.Lock()
_LAST_TERMINAL_PRUNE_AT = 0.0
_HANDLE_CONTEXT = threading.local()
_OUTBOX_WRITE_CONTEXT = threading.local()
_DELIVERY_SEND_CONTEXT = threading.local()
_OUTBOX_WRITE_AUTHORITY_SEAL = object()


class _OutboxImmediateWriteAuthority:
    """Private transaction contract minted only after BEGIN IMMEDIATE succeeds."""

    __slots__ = ("connection", "generation", "revoked", "thread_id")

    def __init__(
        self,
        seal: object,
        conn: "_OutboxConnection",
        generation: int,
    ) -> None:
        if seal is not _OUTBOX_WRITE_AUTHORITY_SEAL:
            raise TypeError("outbox write authority is private")
        self.connection = conn
        self.generation = int(generation)
        self.revoked = False
        self.thread_id = threading.get_ident()


def _first_sql_keyword(sql: object) -> tuple[str, str]:
    remaining = str(sql)
    while True:
        remaining = remaining.lstrip()
        if remaining.startswith("--"):
            line_end = min(
                (position for position in (
                    remaining.find("\n"),
                    remaining.find("\r"),
                ) if position >= 0),
                default=-1,
            )
            if line_end < 0:
                return "", ""
            remaining = remaining[line_end + 1 :]
            continue
        if remaining.startswith("/*"):
            comment_end = remaining.find("*/", 2)
            if comment_end < 0:
                return "", ""
            remaining = remaining[comment_end + 2 :]
            continue
        break
    match = re.match(r"[A-Za-z]+", remaining)
    if match is None:
        return "", remaining
    return match.group(0).upper(), remaining[match.end() :]


def _sql_ends_transaction(sql: object) -> bool:
    first, remaining = _first_sql_keyword(sql)
    if first in {"COMMIT", "END"}:
        return True
    if first != "ROLLBACK":
        return False
    second, _remaining = _first_sql_keyword(remaining)
    return second != "TO"


class _OutboxConnection(sqlite3.Connection):
    """Connection that revokes transaction authority at every transaction end."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._nachuan_write_generation = 0
        self._nachuan_write_authority: _OutboxImmediateWriteAuthority | None = None
        self._nachuan_external_trace_callback = None
        super().set_trace_callback(self._nachuan_trace_callback)

    def _nachuan_trace_callback(self, statement: str) -> None:
        # Trace callbacks observe statements issued through both Connection and
        # Cursor, closing the standard cursor COMMIT/ROLLBACK bypass.
        if _sql_ends_transaction(statement):
            self._revoke_nachuan_write_authority()
        callback = self._nachuan_external_trace_callback
        if callback is not None:
            callback(statement)

    def set_trace_callback(self, trace_callback) -> None:
        # Preserve the internal transaction-lifecycle observer while still
        # allowing diagnostics to receive the same statements.
        self._nachuan_external_trace_callback = trace_callback
        super().set_trace_callback(self._nachuan_trace_callback)

    def _revoke_nachuan_write_authority(self) -> None:
        authority = self._nachuan_write_authority
        if authority is not None:
            _end_outbox_immediate_write(self, authority)

    def commit(self) -> None:
        self._revoke_nachuan_write_authority()
        return super().commit()

    def rollback(self) -> None:
        self._revoke_nachuan_write_authority()
        return super().rollback()

    def close(self) -> None:
        self._revoke_nachuan_write_authority()
        return super().close()

    def execute(self, sql, parameters=()):
        if _sql_ends_transaction(sql):
            self._revoke_nachuan_write_authority()
        return super().execute(sql, parameters)

    def executescript(self, sql_script: str):
        # sqlite3.executescript() commits any pending transaction first.
        self._revoke_nachuan_write_authority()
        return super().executescript(sql_script)

    def __exit__(self, exc_type, exc_value, traceback):
        self._revoke_nachuan_write_authority()
        return super().__exit__(exc_type, exc_value, traceback)


def _active_outbox_write_authorities(
) -> dict[_OutboxConnection, _OutboxImmediateWriteAuthority]:
    active = getattr(_OUTBOX_WRITE_CONTEXT, "active", None)
    if active is None:
        active = {}
        _OUTBOX_WRITE_CONTEXT.active = active
    return active


def _begin_outbox_immediate_write(
    conn: sqlite3.Connection,
    *,
    deadline_monotonic: float | None = None,
) -> _OutboxImmediateWriteAuthority:
    if not isinstance(conn, _OutboxConnection):
        raise RuntimeError("outbox immediate write authority requires managed connection")
    if conn.in_transaction:
        raise RuntimeError("outbox connection already has a transaction")
    if deadline_monotonic is not None:
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
    conn.execute("BEGIN IMMEDIATE")
    _remaining_outbox_finish_budget(deadline_monotonic)
    begin_hook = getattr(conn, "_nachuan_begin_immediate_hook", None)
    if callable(begin_hook):
        begin_hook()
    conn._nachuan_write_generation += 1
    authority = _OutboxImmediateWriteAuthority(
        _OUTBOX_WRITE_AUTHORITY_SEAL,
        conn,
        conn._nachuan_write_generation,
    )
    active = _active_outbox_write_authorities()
    if conn in active:
        conn.rollback()
        raise RuntimeError("outbox immediate write authority already exists")
    active[conn] = authority
    conn._nachuan_write_authority = authority
    return authority


def _end_outbox_immediate_write(
    conn: sqlite3.Connection,
    authority: _OutboxImmediateWriteAuthority,
) -> None:
    active = _active_outbox_write_authorities()
    authority.revoked = True
    if active.get(conn) is authority:
        del active[conn]
    if (
        isinstance(conn, _OutboxConnection)
        and conn._nachuan_write_authority is authority
    ):
        conn._nachuan_write_authority = None


def _require_outbox_immediate_write(
    conn: sqlite3.Connection,
    authority: _OutboxImmediateWriteAuthority | None,
) -> None:
    active = _active_outbox_write_authorities()
    if (
        authority is None
        or not isinstance(conn, _OutboxConnection)
        or authority.revoked
        or authority.connection is not conn
        or active.get(conn) is not authority
        or conn._nachuan_write_authority is not authority
        or authority.generation != conn._nachuan_write_generation
        or authority.thread_id != threading.get_ident()
        or not conn.in_transaction
    ):
        raise RuntimeError("outbox immediate write authority is required")


class VideoCapacityError(RuntimeError):
    """No async-video slot is available; normal chat may still proceed."""


class BridgeInstanceLock:
    """One bridge process per state database; the OS releases the lock on crash."""

    def __init__(self, path: Path | None = None):
        self.path = path or _OUTBOX_DB.with_suffix(_OUTBOX_DB.suffix + ".bridge.lock")
        self._handle = None

    def acquire(self) -> bool:
        if self._handle is not None:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError):
            handle.close()
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ImportError):
            pass
        finally:
            handle.close()
            self._handle = None

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError("另一个微信桥接实例正在使用同一状态库")
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()


# ── 纳川引擎调用(复用飞书桥同一套 urllib 直连) ──
def _resolve_engine_key() -> str:
    """Use only this channel's endpoint-scoped supervisor capability."""

    return str(S.bridge_api_key or "").strip()


def _set_engine_available(value: bool, reason: str | None = None) -> None:
    global _ENGINE_AVAILABLE, _ENGINE_READINESS_REASON
    available = bool(value)
    normalized_reason = str(reason or "").strip()
    if available:
        normalized_reason = "ready"
    elif normalized_reason not in {
        "ready_no_model",
        "requested_model_unavailable",
        "engine_unavailable",
    }:
        normalized_reason = "engine_unavailable"
    with _ENGINE_HEALTH_LOCK:
        _ENGINE_AVAILABLE = available
        _ENGINE_READINESS_REASON = normalized_reason


def _probe_engine_available(*, timeout: float = 3.0) -> bool:
    """Verify both the configured engine and the bridge key on a bounded endpoint."""

    if not ENGINE_KEY:
        _set_engine_available(False)
        return False
    try:
        health_url = f"{ENGINE}/v1/bridge/health"
        if MODEL:
            health_url += "?model=" + urllib.parse.quote(MODEL, safe="")
        raw = request_bridge_bytes(
            _ENGINE_OPENER,
            url=health_url,
            secret=ENGINE_KEY,
            channel="weixin",
            method="GET",
            body=b"",
            timeout=max(0.1, min(float(timeout), 5.0)),
            max_response_bytes=_STATE_FILE_MAX_BYTES,
        )
        document = json.loads(raw.decode("utf-8"))
        valid_envelope = bool(
            isinstance(document, dict)
            and document.get("status") == "ok"
            and document.get("channel") == "weixin"
        )
        chat_ready = document.get("chat_ready") if isinstance(document, dict) else None
        reason = str(document.get("reason") or "") if isinstance(document, dict) else ""
        available = bool(
            valid_envelope
            and type(chat_ready) is bool
            and chat_ready
            and reason == "ready"
        )
        if not (
            valid_envelope
            and type(chat_ready) is bool
            and chat_ready is False
            and reason in {"ready_no_model", "requested_model_unavailable"}
        ):
            reason = "ready" if available else "engine_unavailable"
    except Exception:  # noqa: BLE001 - readiness must fail closed
        available = False
        reason = "engine_unavailable"
    _set_engine_available(available, reason)
    return available


def _refresh_engine_availability(*, force: bool = False) -> bool:
    global _LAST_ENGINE_PROBE_MONOTONIC
    current = time.monotonic()
    with _ENGINE_HEALTH_LOCK:
        if (
            not force
            and current - _LAST_ENGINE_PROBE_MONOTONIC < _ENGINE_PROBE_INTERVAL_SECONDS
        ):
            return bool(_ENGINE_AVAILABLE)
        _LAST_ENGINE_PROBE_MONOTONIC = current
    return _probe_engine_available()


def _is_socket_timeout(exc: BaseException) -> bool:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, (socket.timeout, TimeoutError))
    return False


def _engine_post(
    path: str,
    payload: dict,
    timeout: float = 120,
    *,
    total_timeout: float | None = None,
) -> dict:
    """Call one fixed supervisor engine key within one shared wall-clock budget.

    A connect/reset before any response may be retried once using the same
    idempotency key.  A socket read timeout is never replayed inline because the
    engine may still be completing the first request.  HTTP 401/403 is final and
    never triggers key discovery.
    """

    data = json.dumps(payload).encode()
    total = max(0.1, min(float(total_timeout or timeout), float(timeout)))
    deadline = time.monotonic() + total
    for attempt in (1, 2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _set_engine_available(False)
            raise TimeoutError("engine request exceeded shared deadline")
        try:
            raw = request_bridge_bytes(
                _ENGINE_OPENER,
                url=f"{ENGINE}{path}",
                secret=ENGINE_KEY,
                channel="weixin",
                method="POST",
                body=data,
                headers={"Content-Type": "application/json"},
                timeout=max(0.1, remaining),
            )
            result = json.loads(raw.decode("utf-8"))
            _set_engine_available(True)
            return result
        except urllib.error.HTTPError:
            # Authentication/business HTTP failures are authoritative.  In
            # particular, never probe alternate credentials after a 401/403.
            _set_engine_available(False)
            raise
        except Exception as exc:  # noqa: BLE001
            if _is_socket_timeout(exc) or attempt == 2:
                _set_engine_available(False)
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0.25:
                raise
            time.sleep(min(0.2, remaining / 2.0))
            continue
    # The loop always returns or raises; retain an explicit defensive terminal.
    if time.monotonic() >= deadline:
        raise TimeoutError("engine request exceeded shared deadline")
    else:
        raise RuntimeError("engine unreachable")


def _agent_chat(
    text: str,
    user_id: str,
    chat_id: str,
    idempotency_key: str,
    *,
    video_async_capacity_available: bool = True,
) -> dict:
    # Interactive text turns must not hold one durable delivery for minutes.
    # Long media work belongs in an async job that acknowledges immediately.
    payload = {
        "message": text,
        "user_id": user_id,
        "chat_id": chat_id,
        "channel": "weixin",
        "video_async": True,
        "video_async_capacity_available": bool(
            video_async_capacity_available
        ),
        "idempotency_key": idempotency_key,
    }
    if MODEL:
        payload["model"] = MODEL
    try:
        return _engine_post(
            "/v1/agent/chat",
            payload,
            timeout=_AGENT_TURN_HTTP_TIMEOUT_SECONDS,
            total_timeout=_AGENT_TURN_HTTP_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as exc:
        # A sealed HTTP error body is already authenticated and decrypted by
        # request_bridge_bytes.  Only two explicit, non-retryable readiness
        # codes become a local terminal reply; every other failure keeps the
        # durable inbox retry semantics.
        if int(exc.code) != 503:
            raise
        raw = exc.read(_STATE_FILE_MAX_BYTES + 1)
        exc.fp = io.BytesIO(raw)
        if len(raw) > _STATE_FILE_MAX_BYTES:
            raise
        try:
            document = json.loads(raw.decode("utf-8"))
            detail = document.get("detail") if isinstance(document, dict) else None
            code = str(detail.get("code") or "") if isinstance(detail, dict) else ""
            retryable = detail.get("retryable") if isinstance(detail, dict) else None
        except (UnicodeError, json.JSONDecodeError):
            code = ""
            retryable = None
        replies = {
            "ready_no_model": (
                "⚠️ 纳川已收到消息，但当前没有已验证可用的聊天模型。"
                "请在桌面端打开“连接中心”，连接一个模型后再发送。"
            ),
            "requested_model_unavailable": (
                "⚠️ 微信指定的模型当前不可用。请在纳川“连接中心”重新验证该模型，"
                "或清除微信固定模型设置后再发送。"
            ),
        }
        if code not in replies or retryable is not False:
            raise
        # The gateway is reachable, but this channel still cannot answer a
        # customer Turn.  Do not let a local explanatory reply turn channel
        # readiness green.
        _set_engine_available(False, code)
        return {
            "reply": replies[code],
            "model": "nachuan-readiness",
            "turns": 0,
            "usage": {},
            "blocked": True,
            "outcome": code,
        }


def _engine_get_json(path: str, *, timeout: float = 30.0) -> dict:
    """Read one bounded engine status document with the scoped bridge key."""

    if not ENGINE_KEY:
        raise RuntimeError("微信桥接引擎 Key 未配置")
    if not re.fullmatch(
        r"/v1/videos/[A-Za-z0-9._~%+-]{1,1600}\?model=agnes-video", path
    ):
        raise ValueError("微信视频状态路径无效")
    bounded_timeout = max(0.1, min(float(timeout), 30.0))
    raw = request_bridge_bytes(
        _ENGINE_OPENER,
        url=f"{ENGINE}{path}",
        secret=ENGINE_KEY,
        channel="weixin",
        method="GET",
        body=b"",
        timeout=bounded_timeout,
        max_response_bytes=_STATE_FILE_MAX_BYTES,
    )
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("微信视频状态响应格式无效")
    _set_engine_available(True)
    return document


def _feedback(
    user_id: str,
    chat_id: str,
    rating: str,
    note: str = "",
    *,
    message_key: str,
) -> None:
    _engine_post(
        "/v1/agent/feedback",
        {
            "user_id": user_id,
            "chat_id": chat_id,
            "channel": "weixin",
            "rating": rating,
            "note": note,
            "idempotency_key": message_key,
        },
        timeout=30,
    )


# ── iLink 官方协议(纯 HTTP/JSON，自持实现) ──
def _uin() -> str:
    """X-WECHAT-UIN：每请求随机 uint32 → base64，防重放(协议要求)。"""
    return base64.b64encode(str(random.randint(0, 2**32 - 1)).encode()).decode()


def _ilink(
    method: str,
    path: str,
    body: dict | None = None,
    token: str = "",
    timeout: float = 40,
) -> dict:
    headers = {"Content-Type": "application/json", "AuthorizationType": "ilink_bot_token"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-WECHAT-UIN"] = _uin()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class ILinkDeliveryError(RuntimeError):
    """iLink returned HTTP success but rejected the operation at protocol level."""

    def __init__(self, operation: str, response: dict):
        self.operation = operation
        self.ret = response.get("ret")
        self.errcode = response.get("errcode")
        self.errmsg = response.get("errmsg") or response.get("msg") or "unknown error"
        super().__init__(
            f"iLink {operation} failed: ret={self.ret} errcode={self.errcode} errmsg={self.errmsg}"
        )


class DeliveryFinishFenceLost(RuntimeError):
    """A delivery finish did not own the durable claim it attempted to close."""


class InboundFinishFenceLost(RuntimeError):
    """An inbound finish no longer owns a live durable claim."""


class _OutboxFinishDeadlineExceeded(sqlite3.OperationalError):
    """The shared finish deadline is exhausted and must never be retried."""


class InboundSemanticConflict(RuntimeError):
    """One scoped provider event id was replayed with different semantics."""


class DeliverySemanticConflict(RuntimeError):
    """One stable delivery key was replayed with different immutable content."""


class DeliveryAckStorageError(RuntimeError):
    """The network send returned success but its durable ack could not be stored."""


class DeliveryRequeueStorageError(RuntimeError):
    """A failed network send could not be durably requeued."""


class WeixinRecoveryConflict(RuntimeError):
    """A manual no-replay decision conflicts with durable Weixin state."""


class _WeixinCloseWithoutReplayRequest(NamedTuple):
    operation_digest: str
    decision_id: str
    target_kind: str
    target_key: str
    expected_before_digest: str
    actor: str
    authorization: str
    reason: str
    decided_at_ms: int


class _WeixinCloseWithoutReplayResult(NamedTuple):
    operation_digest: str
    receipt_sha256: str
    affected_inbound_count: int
    affected_delivery_count: int
    affected_video_count: int
    applied: bool


def _base_info() -> dict[str, str]:
    return {"channel_version": ILINK_CHANNEL_VERSION}


def _ensure_ilink_success(response: dict, operation: str) -> None:
    """Treat non-zero JSON business codes as failures even when HTTP is 200."""
    ret = response.get("ret")
    errcode = response.get("errcode")
    if ret not in (None, 0) or errcode not in (None, 0):
        raise ILinkDeliveryError(operation, response)


def _client_id(prefix: str = "nachuan") -> str:
    return f"{prefix}_{time.time_ns()}_{secrets.token_hex(3)}"


def _show_qrcode(data: str) -> None:
    """把二维码内容(URL)转二维码。Windows cmd 是 GBK 编码，终端 ASCII 二维码会编码崩，
    所以**主路径=存标准白底 PNG 并自动打开**(一定能扫)，终端 ASCII 仅作附加、崩了即跳过。"""
    import qrcode

    qr = qrcode.QRCode(border=2)
    qr.add_data(data)
    qr.make(fit=True)
    shown = False
    try:  # 主路径：白底 PNG + 自动打开看图器
        p = _TOKEN_FILE.parent / "ilink_qrcode.png"
        qr.make_image().save(str(p))
        print(f"\n[login] 用手机微信『扫一扫』扫这张二维码登录(要当 bot 的那个号)：\n   {p}", flush=True)
        try:
            os.startfile(str(p))  # type: ignore[attr-defined]  # 自动打开
            print("   (已自动打开图片；没弹出就手动打开上面路径)", flush=True)
        except Exception:  # noqa: BLE001
            print("   (请手动打开上面的图片扫码)", flush=True)
        shown = True
    except Exception as e:  # noqa: BLE001
        print("存二维码图失败：", e, flush=True)
    try:  # 附加：终端 ASCII(cmd GBK 常崩 → 崩就静默跳过，不影响主路径)
        qr.print_ascii(invert=True)
    except Exception:  # noqa: BLE001
        pass
    if not shown:  # 兜底：连图都没存成 → 给链接手动打开
        print("[warning] 二维码没能显示，把这个链接贴手机浏览器打开也行：", data, flush=True)


def _login() -> str:
    """扫码登录拿 bot_token。有缓存先复用；失效由主循环删缓存重扫。"""
    try:
        cached = read_protected_json(
            _TOKEN_FILE,
            purpose="nachuan/ilink-token",
            migrate_plaintext=True,
        ).get("bot_token", "")
        if cached:
            print("复用已保存的登录态(如失效会自动重新扫码)。", flush=True)
            return cached
    except FileNotFoundError:
        pass
    except SecureStorageError as exc:
        raise RuntimeError("微信登录态安全存储不可读；拒绝按未登录继续") from exc
    r = _ilink("GET", "/ilink/bot/get_bot_qrcode?bot_type=3")
    qr_id = r.get("qrcode", "")  # 轮询登录状态要用这个 id（别删！）
    qr_url = r.get("qrcode_img_content", "")  # 真实 API 返回 URL(非 base64)，编码进二维码给手机扫
    if not qr_url or not qr_id:
        raise RuntimeError(f"没拿到二维码，API 返回：{r}")
    _show_qrcode(qr_url)
    print("等待扫码确认…（会静静挂着等你扫，属正常；扫完自动继续）", flush=True)
    while True:
        try:
            # get_qrcode_status 是长轮询：未扫码会挂起等待，超时属正常 → 直接再拉
            st = _ilink(
                "GET",
                "/ilink/bot/get_qrcode_status?qrcode=" + urllib.parse.quote(qr_id),
                timeout=65,
            )
        except (TimeoutError, urllib.error.URLError, OSError):
            continue  # 长轮询超时=还没扫，继续等，不当错误
        except Exception as e:  # noqa: BLE001  真异常才提示
            print("  轮询状态异常，稍等重试…", e, flush=True)
            time.sleep(3)
            continue
        status = str(st.get("status") or "")
        if status == "confirmed" and st.get("bot_token"):
            token = st["bot_token"]
            try:
                write_protected_json(
                    _TOKEN_FILE,
                    {"bot_token": token},
                    purpose="nachuan/ilink-token",
                )
            except SecureStorageError as exc:
                raise RuntimeError("微信已登录但登录态无法安全保存；桥接未启动") from exc
            print("[ok] 登录成功。", flush=True)
            return token
        # 其它中间状态(已扫未确认等) → 继续轮询


def _split(text: str, n: int = 3500) -> list[str]:
    return [text[i : i + n] for i in range(0, len(text), n)] or [""]


def _send_chunk(
    token: str,
    to_user_id: str,
    context_token: str,
    text: str,
    client_id: str,
) -> dict:
    """Run one bounded attempt and return the exact observed platform response."""

    timeout = float(
        getattr(
            _DELIVERY_SEND_CONTEXT,
            "attempt_timeout_seconds",
            _SEND_ATTEMPT_TIMEOUT_SECONDS,
        )
    )
    response = _ilink(
        "POST",
        "/ilink/bot/sendmessage",
        _sendmessage_body(to_user_id, context_token, text, client_id),
        token=token,
        timeout=timeout,
    )
    if not isinstance(response, dict):
        raise RuntimeError("ilink_sendmessage_response_invalid")
    ret = response.get("ret")
    errcode = response.get("errcode")
    if type(ret) is not int or ret != 0 or (
        errcode is not None and (type(errcode) is not int or errcode != 0)
    ):
        raise ILinkDeliveryError("sendmessage", response)
    return response


def _sendmessage_body(
    to_user_id: str,
    context_token: str,
    text: str,
    client_id: str,
) -> dict:
    return {
        "msg": {
            "from_user_id": "",
            "to_user_id": to_user_id,
            "client_id": client_id,
            "message_type": 2,
            "message_state": 2,
            "context_token": context_token,
            "item_list": [{"type": 1, "text_item": {"text": text}}],
        },
        "base_info": _base_info(),
    }


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _send(token: str, to_user_id: str, context_token: str, text: str) -> bool:
    """Compatibility helper for direct callers; durable delivery uses the outbox."""

    for chunk in _split(text):
        response = _ilink(
            "POST",
            "/ilink/bot/sendmessage",
            _sendmessage_body(to_user_id, context_token, chunk, _client_id()),
            token=token,
            timeout=_SEND_ATTEMPT_TIMEOUT_SECONDS,
        )
        if not isinstance(response, dict):
            raise RuntimeError("ilink_sendmessage_response_invalid")
        _ensure_ilink_success(response, "sendmessage")
    return True


_OUTBOX_V0_SCHEMA_DDL = (
    """CREATE TABLE pending_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        text TEXT NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending'
    )""",
    """CREATE TABLE inbound_message (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL UNIQUE,
        from_user_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        received_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE bridge_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    )""",
    """CREATE TABLE pending_video (
        task_id TEXT PRIMARY KEY,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        source_message_key TEXT NOT NULL,
        created_at REAL NOT NULL,
        deadline_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        result_url TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT '',
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        finished_at REAL NOT NULL DEFAULT 0
    )""",
)


# Frozen declarations from the immediately preceding runtime.  They are
# materialized only in a private in-memory database so that its exact
# sqlite_master tuple can be recognized; they are never executed against the
# live state file.  All live provisioning uses _OUTBOX_SCHEMA_DDL below.
_OUTBOX_PREVIOUS_RUNTIME_V0_DDL = (
    """CREATE TABLE IF NOT EXISTS pending_delivery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            to_user_id TEXT NOT NULL,
            context_token TEXT NOT NULL,
            text TEXT NOT NULL,
            last_error TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            delivery_id TEXT NOT NULL DEFAULT '',
            client_id TEXT NOT NULL DEFAULT '',
            chunk_index INTEGER NOT NULL DEFAULT 0,
            chunk_count INTEGER NOT NULL DEFAULT 1,
            claim_token TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0,
            delivered_at REAL NOT NULL DEFAULT 0
        )""",
    """CREATE TABLE IF NOT EXISTS inbound_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key TEXT NOT NULL UNIQUE,
            from_user_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            received_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            last_error TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0,
            claim_token TEXT NOT NULL DEFAULT '',
            claim_deadline REAL NOT NULL DEFAULT 0,
            heartbeat_at REAL NOT NULL DEFAULT 0,
            claim_epoch INTEGER NOT NULL DEFAULT 0,
            last_finish_token TEXT NOT NULL DEFAULT '',
            last_finish_epoch INTEGER NOT NULL DEFAULT 0,
            last_finish_outcome TEXT NOT NULL DEFAULT '',
            request_sha256 TEXT NOT NULL DEFAULT ''
        )""",
    """CREATE TABLE IF NOT EXISTS bridge_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at REAL NOT NULL
        )""",
    """CREATE TABLE IF NOT EXISTS pending_video (
            task_id TEXT PRIMARY KEY,
            to_user_id TEXT NOT NULL,
            context_token TEXT NOT NULL,
            source_message_key TEXT NOT NULL,
            created_at REAL NOT NULL,
            deadline_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            result_url TEXT NOT NULL DEFAULT '',
            direct_attempted INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            claim_token TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0,
            finished_at REAL NOT NULL DEFAULT 0
        )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_delivery_chunk "
    "ON pending_delivery(delivery_id, chunk_index) WHERE delivery_id <> ''",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_delivery_client "
    "ON pending_delivery(client_id) WHERE client_id <> ''",
    "CREATE INDEX IF NOT EXISTS idx_pending_delivery_claim "
    "ON pending_delivery(status, next_attempt_at, id)",
    "CREATE INDEX IF NOT EXISTS idx_pending_delivery_chat_order "
    "ON pending_delivery(to_user_id, status, id)",
    "CREATE INDEX IF NOT EXISTS idx_inbound_message_claim "
    "ON inbound_message(status, next_attempt_at, claim_deadline, id)",
    "CREATE INDEX IF NOT EXISTS idx_pending_video_claim "
    "ON pending_video(status, next_attempt_at, created_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_video_source "
    "ON pending_video(source_message_key)",
)


_OUTBOX_V1_SCHEMA_DDL = (
    """CREATE TABLE pending_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        text TEXT NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        delivery_id TEXT NOT NULL DEFAULT '',
        client_id TEXT NOT NULL DEFAULT '',
        chunk_index INTEGER NOT NULL DEFAULT 0,
        chunk_count INTEGER NOT NULL DEFAULT 1,
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        delivered_at REAL NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE inbound_message (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL UNIQUE,
        from_user_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        received_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        claim_token TEXT NOT NULL DEFAULT '',
        claim_deadline REAL NOT NULL DEFAULT 0,
        heartbeat_at REAL NOT NULL DEFAULT 0,
        claim_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_token TEXT NOT NULL DEFAULT '',
        last_finish_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_outcome TEXT NOT NULL DEFAULT '',
        request_sha256 TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE bridge_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    )""",
    """CREATE TABLE pending_video (
        task_id TEXT PRIMARY KEY,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        source_message_key TEXT NOT NULL,
        created_at REAL NOT NULL,
        deadline_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        result_url TEXT NOT NULL DEFAULT '',
        direct_attempted INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NOT NULL DEFAULT '',
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        finished_at REAL NOT NULL DEFAULT 0
    )""",
    """CREATE UNIQUE INDEX uq_pending_delivery_chunk
       ON pending_delivery(delivery_id, chunk_index) WHERE delivery_id <> ''""",
    """CREATE UNIQUE INDEX uq_pending_delivery_client
       ON pending_delivery(client_id) WHERE client_id <> ''""",
    """CREATE INDEX idx_pending_delivery_claim
       ON pending_delivery(status, next_attempt_at, id)""",
    """CREATE INDEX idx_pending_delivery_chat_order
       ON pending_delivery(to_user_id, status, id)""",
    """CREATE INDEX idx_inbound_message_claim
       ON inbound_message(status, next_attempt_at, claim_deadline, id)""",
    """CREATE INDEX idx_pending_video_claim
       ON pending_video(status, next_attempt_at, created_at)""",
    """CREATE UNIQUE INDEX uq_pending_video_source
       ON pending_video(source_message_key)""",
)


# NCWX v2 freezes the complete SQLite authority.  Keep this tuple free of
# ``IF NOT EXISTS``: accepting a partial schema would silently reinterpret an
# unknown crash or foreign-write state as a supported generation.
_OUTBOX_SCHEMA_DDL = (
    """CREATE TABLE pending_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        text TEXT NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        delivery_id TEXT NOT NULL DEFAULT '',
        client_id TEXT NOT NULL DEFAULT '',
        chunk_index INTEGER NOT NULL DEFAULT 0,
        chunk_count INTEGER NOT NULL DEFAULT 1,
        chat_seq INTEGER NOT NULL DEFAULT 0,
        parent_message_key TEXT NOT NULL DEFAULT '',
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        claim_deadline REAL NOT NULL DEFAULT 0,
        heartbeat_at REAL NOT NULL DEFAULT 0,
        claim_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_token TEXT NOT NULL DEFAULT '',
        last_finish_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_outcome TEXT NOT NULL DEFAULT '',
        request_sha256 TEXT NOT NULL DEFAULT '',
        submission_started_at REAL NOT NULL DEFAULT 0,
        platform_response_sha256 TEXT NOT NULL DEFAULT '',
        terminal_verification TEXT NOT NULL DEFAULT '',
        delivered_at REAL NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE inbound_message (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL UNIQUE,
        from_user_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        received_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        claim_token TEXT NOT NULL DEFAULT '',
        claim_deadline REAL NOT NULL DEFAULT 0,
        heartbeat_at REAL NOT NULL DEFAULT 0,
        claim_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_token TEXT NOT NULL DEFAULT '',
        last_finish_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_outcome TEXT NOT NULL DEFAULT '',
        request_sha256 TEXT NOT NULL DEFAULT '',
        chat_seq INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE bridge_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    )""",
    """CREATE TABLE pending_video (
        task_id TEXT PRIMARY KEY,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        source_message_key TEXT NOT NULL,
        created_at REAL NOT NULL,
        deadline_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        result_url TEXT NOT NULL DEFAULT '',
        direct_attempted INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NOT NULL DEFAULT '',
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        claim_deadline REAL NOT NULL DEFAULT 0,
        heartbeat_at REAL NOT NULL DEFAULT 0,
        claim_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_token TEXT NOT NULL DEFAULT '',
        last_finish_epoch INTEGER NOT NULL DEFAULT 0,
        last_finish_outcome TEXT NOT NULL DEFAULT '',
        finished_at REAL NOT NULL DEFAULT 0,
        chat_seq INTEGER NOT NULL DEFAULT 0,
        submission_phase TEXT NOT NULL DEFAULT '',
        upload_grant_request_sha256 TEXT NOT NULL DEFAULT '',
        upload_grant_started_at REAL NOT NULL DEFAULT 0,
        upload_request_sha256 TEXT NOT NULL DEFAULT '',
        upload_started_at REAL NOT NULL DEFAULT 0,
        send_request_sha256 TEXT NOT NULL DEFAULT '',
        send_started_at REAL NOT NULL DEFAULT 0,
        platform_response_sha256 TEXT NOT NULL DEFAULT '',
        terminal_verification TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE recovery_receipt (
        id INTEGER NOT NULL,
        created_at REAL NOT NULL,
        operation TEXT NOT NULL,
        operation_digest TEXT NOT NULL,
        decision_id TEXT NOT NULL,
        principal_sha256 TEXT NOT NULL,
        row_before_sha256 TEXT NOT NULL,
        previous_receipt_sha256 TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        record_json TEXT NOT NULL
    )""",
    """CREATE UNIQUE INDEX uq_pending_delivery_chunk
       ON pending_delivery(delivery_id, chunk_index) WHERE delivery_id <> ''""",
    """CREATE UNIQUE INDEX uq_pending_delivery_client
       ON pending_delivery(client_id) WHERE client_id <> ''""",
    """CREATE INDEX idx_pending_delivery_claim
       ON pending_delivery(status, next_attempt_at, claim_deadline, id)""",
    """CREATE INDEX idx_pending_delivery_chat_order
       ON pending_delivery(to_user_id, chat_seq, status, id)""",
    """CREATE INDEX idx_inbound_message_claim
       ON inbound_message(status, next_attempt_at, claim_deadline, id)""",
    """CREATE INDEX idx_pending_video_claim
       ON pending_video(status, next_attempt_at, claim_deadline, created_at)""",
    """CREATE UNIQUE INDEX uq_pending_video_source
       ON pending_video(source_message_key)""",
    """CREATE INDEX idx_inbound_message_claim_barrier
       ON inbound_message(from_user_id, chat_seq, status, id)""",
    """CREATE INDEX idx_pending_video_claim_barrier
       ON pending_video(to_user_id, chat_seq, status, created_at)""",
    """CREATE UNIQUE INDEX uq_recovery_receipt_id
       ON recovery_receipt(id)""",
    """CREATE UNIQUE INDEX uq_recovery_receipt_operation_digest
       ON recovery_receipt(operation_digest)""",
    """CREATE UNIQUE INDEX uq_recovery_receipt_decision_id
       ON recovery_receipt(decision_id)""",
    """CREATE UNIQUE INDEX uq_recovery_receipt_sha256
       ON recovery_receipt(receipt_sha256)""",
    """CREATE UNIQUE INDEX uq_recovery_receipt_previous_sha256
       ON recovery_receipt(previous_receipt_sha256)""",
    """CREATE TRIGGER trg_recovery_receipt_no_replace
       BEFORE INSERT ON recovery_receipt
       WHEN EXISTS (
         SELECT 1 FROM recovery_receipt AS existing
         WHERE existing.id=NEW.id
            OR existing.operation_digest=NEW.operation_digest
            OR existing.decision_id=NEW.decision_id
            OR existing.receipt_sha256=NEW.receipt_sha256
            OR existing.previous_receipt_sha256=NEW.previous_receipt_sha256
       )
       BEGIN
         SELECT RAISE(ABORT, 'recovery receipt replacement forbidden');
       END""",
    """CREATE TRIGGER trg_recovery_receipt_no_update
       BEFORE UPDATE ON recovery_receipt
       BEGIN
         SELECT RAISE(ABORT, 'recovery receipt update forbidden');
       END""",
    """CREATE TRIGGER trg_recovery_receipt_no_delete
       BEFORE DELETE ON recovery_receipt
       BEGIN
         SELECT RAISE(ABORT, 'recovery receipt delete forbidden');
       END""",
)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _outbox_schema_rows(
    conn: sqlite3.Connection,
) -> tuple[tuple[object, object, object, object], ...]:
    return tuple(
        conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "ORDER BY type,name,tbl_name"
        ).fetchall()
    )


@lru_cache(maxsize=4)
def _materialized_outbox_schema(
    statements: tuple[str, ...],
) -> tuple[tuple[object, object, object, object], ...]:
    with closing(sqlite3.connect(":memory:")) as conn:
        for statement in statements:
            conn.execute(statement)
        return _outbox_schema_rows(conn)


def _classify_outbox_schema(conn: sqlite3.Connection) -> str:
    application_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    rows = _outbox_schema_rows(conn)
    current = _materialized_outbox_schema(_OUTBOX_SCHEMA_DDL)
    v1 = _materialized_outbox_schema(_OUTBOX_V1_SCHEMA_DDL)
    if (
        application_id == _OUTBOX_APPLICATION_ID
        and user_version == _OUTBOX_SCHEMA_VERSION
        and rows == current
    ):
        return "v2"
    if (
        application_id == _OUTBOX_APPLICATION_ID
        and user_version == 1
        and rows == v1
    ):
        return "v1"
    if application_id == 0 and user_version == 0:
        if not rows:
            return "empty"
        if rows == _materialized_outbox_schema(_OUTBOX_V0_SCHEMA_DDL):
            return "v0_base"
        if rows == _materialized_outbox_schema(_OUTBOX_PREVIOUS_RUNTIME_V0_DDL):
            return "v0_previous_runtime"
        if rows == v1:
            return "v0_current_shape"
    raise sqlite3.DatabaseError("unknown Weixin state schema")


def _create_outbox_schema(conn: sqlite3.Connection) -> None:
    for statement in _OUTBOX_SCHEMA_DDL:
        conn.execute(statement)
    conn.execute(f"PRAGMA application_id={_OUTBOX_APPLICATION_ID}")
    conn.execute(f"PRAGMA user_version={_OUTBOX_SCHEMA_VERSION}")


def _create_outbox_v1_schema(conn: sqlite3.Connection) -> None:
    """Materialize the frozen intermediate used by every legacy migration."""

    for statement in _OUTBOX_V1_SCHEMA_DDL:
        conn.execute(statement)
    conn.execute(f"PRAGMA application_id={_OUTBOX_APPLICATION_ID}")
    conn.execute("PRAGMA user_version=1")


def _capture_outbox_autoincrement_sequences(
    conn: sqlite3.Connection,
) -> dict[str, int]:
    captured: dict[str, int] = {}
    for table in ("pending_delivery", "inbound_message"):
        rows = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name=?",
            (table,),
        ).fetchall()
        if len(rows) > 1:
            raise sqlite3.DatabaseError(
                "Weixin state AUTOINCREMENT authority is ambiguous"
            )
        if rows:
            try:
                sequence = int(rows[0][0])
            except (TypeError, ValueError) as exc:
                raise sqlite3.DatabaseError(
                    "Weixin state AUTOINCREMENT authority is invalid"
                ) from exc
            if sequence < 0:
                raise sqlite3.DatabaseError(
                    "Weixin state AUTOINCREMENT authority is invalid"
                )
            captured[table] = sequence
    return captured


def _restore_outbox_autoincrement_sequences(
    conn: sqlite3.Connection,
    captured: dict[str, int],
) -> None:
    for table, previous in captured.items():
        rows = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name=?",
            (table,),
        ).fetchall()
        if len(rows) > 1:
            raise sqlite3.DatabaseError(
                "Weixin state AUTOINCREMENT authority is ambiguous"
            )
        current = int(rows[0][0]) if rows else 0
        target = max(previous, current)
        if rows:
            conn.execute(
                "UPDATE sqlite_sequence SET seq=? WHERE name=?",
                (target, table),
            )
        else:
            conn.execute(
                "INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)",
                (table, target),
            )


def _migrate_outbox_v0(conn: sqlite3.Connection) -> None:
    sequences = _capture_outbox_autoincrement_sequences(conn)
    for table in (
        "pending_delivery",
        "inbound_message",
        "bridge_state",
        "pending_video",
    ):
        conn.execute(f"ALTER TABLE {table} RENAME TO {table}_v0")
    _create_outbox_v1_schema(conn)
    conn.execute(
        """INSERT INTO pending_delivery(
            id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,
            last_error,status,delivery_id,client_id,chunk_index,chunk_count,
            claim_token,claimed_at,delivered_at
        )
        SELECT id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,
               CASE WHEN status='processing'
                    THEN 'legacy_provider_outcome_unknown' ELSE last_error END,
               CASE WHEN status='processing'
                    THEN 'recovery_required' ELSE status END,
               'legacy-' || id,'nachuan_legacy_' || id,0,1,'',0,0
        FROM pending_delivery_v0"""
    )
    conn.execute(
        """INSERT INTO inbound_message(
            id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,
            status,last_error,claimed_at,claim_token,claim_deadline,heartbeat_at,
            claim_epoch,last_finish_token,last_finish_epoch,last_finish_outcome,
            request_sha256
        )
        SELECT id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,
               CASE WHEN status='processing'
                    THEN 'recovery_required' ELSE status END,
               CASE WHEN status='processing'
                    THEN 'legacy_provider_outcome_unknown' ELSE last_error END,
               0,'',0,0,0,'',0,'',''
        FROM inbound_message_v0"""
    )
    conn.execute(
        "INSERT INTO bridge_state(key,value,updated_at) "
        "SELECT key,value,updated_at FROM bridge_state_v0"
    )
    conn.execute(
        """INSERT INTO pending_video(
            task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,
            next_attempt_at,attempts,status,result_url,direct_attempted,last_error,
            claim_token,claimed_at,finished_at
        )
        SELECT task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,
               next_attempt_at,attempts,
               CASE WHEN status='processing'
                    THEN 'recovery_required' ELSE status END,
               result_url,
               CASE WHEN status='processing' THEN 1 ELSE 0 END,
               CASE WHEN status='processing'
                    THEN 'legacy_video_delivery_outcome_unknown' ELSE last_error END,
               CASE WHEN status='processing' THEN '' ELSE claim_token END,
               CASE WHEN status='processing' THEN 0 ELSE claimed_at END,
               finished_at
        FROM pending_video_v0"""
    )
    for table in (
        "pending_delivery_v0",
        "inbound_message_v0",
        "bridge_state_v0",
        "pending_video_v0",
    ):
        conn.execute(f"DROP TABLE {table}")
    _restore_outbox_autoincrement_sequences(conn, sequences)


def _migrate_outbox_previous_runtime_v0(conn: sqlite3.Connection) -> None:
    sequences = _capture_outbox_autoincrement_sequences(conn)
    for index in (
        "uq_pending_delivery_chunk",
        "uq_pending_delivery_client",
        "idx_pending_delivery_claim",
        "idx_pending_delivery_chat_order",
        "idx_inbound_message_claim",
        "idx_pending_video_claim",
        "uq_pending_video_source",
    ):
        conn.execute(f"DROP INDEX {index}")
    for table in (
        "pending_delivery",
        "inbound_message",
        "bridge_state",
        "pending_video",
    ):
        conn.execute(f"ALTER TABLE {table} RENAME TO {table}_v0")
    _create_outbox_v1_schema(conn)
    conn.execute(
        """INSERT INTO pending_delivery(
            id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,
            last_error,status,delivery_id,client_id,chunk_index,chunk_count,
            claim_token,claimed_at,delivered_at
        )
        SELECT id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,
               last_error,status,
               CASE WHEN delivery_id='' THEN 'legacy-' || id ELSE delivery_id END,
               CASE WHEN client_id='' THEN 'nachuan_legacy_' || id ELSE client_id END,
               chunk_index,chunk_count,claim_token,claimed_at,delivered_at
        FROM pending_delivery_v0"""
    )
    conn.execute(
        """INSERT INTO inbound_message(
            id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,
            status,last_error,claimed_at,claim_token,claim_deadline,heartbeat_at,
            claim_epoch,last_finish_token,last_finish_epoch,last_finish_outcome,
            request_sha256
        )
        SELECT id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,heartbeat_at,
               claim_epoch,last_finish_token,last_finish_epoch,last_finish_outcome,
               request_sha256
        FROM inbound_message_v0"""
    )
    conn.execute(
        "INSERT INTO bridge_state(key,value,updated_at) "
        "SELECT key,value,updated_at FROM bridge_state_v0"
    )
    conn.execute(
        """INSERT INTO pending_video(
            task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,
            next_attempt_at,attempts,status,result_url,direct_attempted,last_error,
            claim_token,claimed_at,finished_at
        )
        SELECT task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,
               next_attempt_at,attempts,status,result_url,direct_attempted,last_error,
               claim_token,claimed_at,finished_at
        FROM pending_video_v0"""
    )
    for table in (
        "pending_delivery_v0",
        "inbound_message_v0",
        "bridge_state_v0",
        "pending_video_v0",
    ):
        conn.execute(f"DROP TABLE {table}")
    _restore_outbox_autoincrement_sequences(conn, sequences)


_CHAT_SEQ_STATE_KEY = "__ncwx_chat_seq"
_SQLITE_SIGNED_INT64_MAX = (1 << 63) - 1
_DELIVERY_V1_STATUSES = frozenset(
    {"pending", "processing", "done", "dead", "recovery_required"}
)
_INBOUND_V1_STATUSES = frozenset(
    {"pending", "processing", "done", "dead", "recovery_required"}
)
_VIDEO_V1_STATUSES = frozenset(
    {"reserved", "pending", "processing", "done", "dead", "recovery_required"}
)
_ACTIVE_DELIVERY_STATUSES = frozenset(
    {"pending", "processing", "submitting", "recovery_required"}
)
_ACTIVE_INBOUND_STATUSES = frozenset(
    {"pending", "processing", "recovery_required"}
)
_ACTIVE_VIDEO_STATUSES = frozenset(
    {"reserved", "pending", "processing", "recovery_required"}
)


def _require_legal_outbox_v1_rows(conn: sqlite3.Connection) -> None:
    """Reject values that the v1 runtime could never interpret safely."""

    if conn.execute(
        "SELECT 1 FROM bridge_state WHERE key=? LIMIT 1",
        (_CHAT_SEQ_STATE_KEY,),
    ).fetchone() is not None:
        raise sqlite3.DatabaseError("Weixin v1 chat sequence authority conflicts")
    for table, allowed in (
        ("pending_delivery", _DELIVERY_V1_STATUSES),
        ("inbound_message", _INBOUND_V1_STATUSES),
        ("pending_video", _VIDEO_V1_STATUSES),
    ):
        placeholders = ",".join("?" for _ in allowed)
        if conn.execute(
            f"SELECT 1 FROM {table} WHERE status NOT IN ({placeholders}) LIMIT 1",
            tuple(sorted(allowed)),
        ).fetchone() is not None:
            raise sqlite3.DatabaseError(f"Weixin v1 {table} status is invalid")
    if conn.execute(
        "SELECT 1 FROM pending_video WHERE direct_attempted NOT IN (0,1) LIMIT 1"
    ).fetchone() is not None:
        raise sqlite3.DatabaseError("Weixin v1 video boundary marker is invalid")
    if conn.execute(
        """
        SELECT 1 FROM pending_delivery
        WHERE delivery_id='' OR client_id='' OR chunk_count<1
           OR chunk_index<0 OR chunk_index>=chunk_count
        LIMIT 1
        """
    ).fetchone() is not None:
        raise sqlite3.DatabaseError("Weixin v1 delivery identity is invalid")
    if conn.execute(
        """
        SELECT 1
        FROM pending_delivery
        GROUP BY delivery_id
        HAVING COUNT(DISTINCT to_user_id)<>1
            OR COUNT(DISTINCT context_token)<>1
            OR COUNT(DISTINCT chunk_count)<>1
            OR COUNT(*)<>MAX(chunk_count)
            OR MIN(chunk_index)<>0
            OR MAX(chunk_index)<>MAX(chunk_count)-1
        LIMIT 1
        """
    ).fetchone() is not None:
        raise sqlite3.DatabaseError("Weixin v1 delivery chunk set is invalid")


def _legacy_chat_sequence_plan(
    conn: sqlite3.Connection,
) -> tuple[dict[tuple[str, str, str], int], frozenset[str], int]:
    """Derive only structural causality; timestamps are never used for order."""

    groups: set[tuple[str, str, str]] = set()
    active_by_principal: dict[str, set[tuple[str, str]]] = {}

    def add(
        principal: object,
        kind: str,
        key: object,
        status: object,
        active: frozenset[str],
    ) -> None:
        rendered_principal = str(principal)
        rendered_key = str(key)
        group = (rendered_principal, kind, rendered_key)
        groups.add(group)
        if str(status) in active:
            active_by_principal.setdefault(rendered_principal, set()).add(
                (kind, rendered_key)
            )

    for principal, message_key, status in conn.execute(
        "SELECT from_user_id,message_key,status FROM inbound_message"
    ):
        add(principal, "message", message_key, status, _ACTIVE_INBOUND_STATUSES)
    for principal, delivery_id, status in conn.execute(
        "SELECT to_user_id,delivery_id,status FROM pending_delivery"
    ):
        add(principal, "delivery", delivery_id, status, _ACTIVE_DELIVERY_STATUSES)
    for principal, source_message_key, status in conn.execute(
        "SELECT to_user_id,source_message_key,status FROM pending_video"
    ):
        add(principal, "message", source_message_key, status, _ACTIVE_VIDEO_STATUSES)

    if len(groups) >= _SQLITE_SIGNED_INT64_MAX:
        raise sqlite3.DatabaseError("Weixin chat sequence space is exhausted")
    plan = {group: index for index, group in enumerate(sorted(groups), start=1)}
    ambiguous = frozenset(
        principal
        for principal, principal_groups in active_by_principal.items()
        if len(principal_groups) > 1
    )
    head = len(plan) + 1
    if head > _SQLITE_SIGNED_INT64_MAX:
        raise sqlite3.DatabaseError("Weixin chat sequence space is exhausted")
    return plan, ambiguous, head


def _migrate_outbox_v1(conn: sqlite3.Connection) -> None:
    """Upgrade the exact v1 authority to v2 inside the caller's writer txn."""

    _require_legal_outbox_v1_rows(conn)
    sequences = _capture_outbox_autoincrement_sequences(conn)
    chat_plan, ambiguous_principals, chat_head = _legacy_chat_sequence_plan(conn)
    deliveries = conn.execute(
        """
        SELECT id,created_at,next_attempt_at,attempts,to_user_id,context_token,
               text,last_error,status,delivery_id,client_id,chunk_index,
               chunk_count,claim_token,claimed_at,delivered_at
        FROM pending_delivery ORDER BY id
        """
    ).fetchall()
    inbound = conn.execute(
        """
        SELECT id,message_key,from_user_id,payload,received_at,next_attempt_at,
               attempts,status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,request_sha256
        FROM inbound_message ORDER BY id
        """
    ).fetchall()
    videos = conn.execute(
        """
        SELECT task_id,to_user_id,context_token,source_message_key,created_at,
               deadline_at,next_attempt_at,attempts,status,result_url,
               direct_attempted,last_error,claim_token,claimed_at,finished_at
        FROM pending_video ORDER BY task_id
        """
    ).fetchall()
    state_rows = conn.execute(
        "SELECT key,value,updated_at FROM bridge_state ORDER BY key"
    ).fetchall()

    for index in (
        "uq_pending_delivery_chunk",
        "uq_pending_delivery_client",
        "idx_pending_delivery_claim",
        "idx_pending_delivery_chat_order",
        "idx_inbound_message_claim",
        "idx_pending_video_claim",
        "uq_pending_video_source",
    ):
        conn.execute(f"DROP INDEX {index}")
    for table in (
        "pending_delivery",
        "inbound_message",
        "bridge_state",
        "pending_video",
    ):
        conn.execute(f"ALTER TABLE {table} RENAME TO {table}_v1")
    _create_outbox_schema(conn)

    for row in deliveries:
        principal = str(row[4])
        status = str(row[8])
        last_error = str(row[7])
        if principal in ambiguous_principals and status in _ACTIVE_DELIVERY_STATUSES:
            status = "recovery_required"
            last_error = "legacy_chat_order_ambiguous"
        elif status == "processing":
            status = "recovery_required"
            last_error = "legacy_provider_outcome_unknown"
        chat_seq = chat_plan[(principal, "delivery", str(row[9]))]
        terminal_verification = (
            "legacy_terminal_unverified" if status == "done" else ""
        )
        conn.execute(
            """
            INSERT INTO pending_delivery(
                id,created_at,next_attempt_at,attempts,to_user_id,context_token,
                text,last_error,status,delivery_id,client_id,chunk_index,
                chunk_count,chat_seq,parent_message_key,claim_token,claimed_at,
                claim_deadline,heartbeat_at,claim_epoch,last_finish_token,
                last_finish_epoch,last_finish_outcome,request_sha256,
                submission_started_at,platform_response_sha256,
                terminal_verification,delivered_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',0,0,0,0,'',0,'','',0,'',?,?)
            """,
            (*row[:7], last_error, status, *row[9:13], chat_seq, "", terminal_verification, row[15]),
        )

    for row in inbound:
        principal = str(row[2])
        status = str(row[7])
        last_error = str(row[8])
        if principal in ambiguous_principals and status in _ACTIVE_INBOUND_STATUSES:
            status = "recovery_required"
            last_error = "legacy_chat_order_ambiguous"
        elif status == "processing":
            status = "recovery_required"
            last_error = "legacy_provider_outcome_unknown"
        chat_seq = chat_plan[(principal, "message", str(row[1]))]
        clear_claim = status == "recovery_required"
        conn.execute(
            """
            INSERT INTO inbound_message(
                id,message_key,from_user_id,payload,received_at,next_attempt_at,
                attempts,status,last_error,claimed_at,claim_token,claim_deadline,
                heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                last_finish_outcome,request_sha256,chat_seq
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                *row[:7],
                status,
                last_error,
                0 if clear_claim else row[9],
                "" if clear_claim else row[10],
                0 if clear_claim else row[11],
                0 if clear_claim else row[12],
                row[13],
                row[14],
                row[15],
                row[16],
                row[17],
                chat_seq,
            ),
        )

    for row in videos:
        principal = str(row[1])
        status = str(row[8])
        direct_attempted = int(row[10])
        last_error = str(row[11])
        if principal in ambiguous_principals and status in _ACTIVE_VIDEO_STATUSES:
            status = "recovery_required"
            last_error = "legacy_chat_order_ambiguous"
        elif status == "processing" and direct_attempted == 0:
            status = "pending"
            last_error = ""
        elif status in _ACTIVE_VIDEO_STATUSES and direct_attempted == 1:
            status = "recovery_required"
            last_error = "legacy_video_delivery_outcome_unknown"
        chat_seq = chat_plan[(principal, "message", str(row[3]))]
        terminal_verification = (
            "legacy_terminal_unverified" if status == "done" else ""
        )
        conn.execute(
            """
            INSERT INTO pending_video(
                task_id,to_user_id,context_token,source_message_key,created_at,
                deadline_at,next_attempt_at,attempts,status,result_url,
                direct_attempted,last_error,claim_token,claimed_at,claim_deadline,
                heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                last_finish_outcome,finished_at,chat_seq,submission_phase,
                upload_grant_request_sha256,upload_grant_started_at,
                upload_request_sha256,upload_started_at,send_request_sha256,
                send_started_at,platform_response_sha256,terminal_verification
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'',0,0,0,0,'',0,'',?,?, '', '',0,'',0,'',0,'',?)
            """,
            (*row[:8], status, row[9], direct_attempted, last_error, row[14], chat_seq, terminal_verification),
        )

    conn.executemany(
        "INSERT INTO bridge_state(key,value,updated_at) VALUES(?,?,?)",
        state_rows,
    )
    conn.execute(
        "INSERT INTO bridge_state(key,value,updated_at) VALUES(?,?,0)",
        (_CHAT_SEQ_STATE_KEY, str(chat_head)),
    )
    for table in (
        "pending_delivery_v1",
        "inbound_message_v1",
        "bridge_state_v1",
        "pending_video_v1",
    ):
        conn.execute(f"DROP TABLE {table}")
    _restore_outbox_autoincrement_sequences(conn, sequences)


_RECOVERY_RECEIPT_SCHEMA = "nachuan.weixin-recovery-receipt.v2"
_RECOVERY_RECEIPT_GENESIS = "0" * 64
_RECOVERY_RECEIPT_OPERATIONS = frozenset({"close_without_replay"})
_MAX_RECOVERY_RECEIPTS = 50_000
_RECOVERY_TOMBSTONE = '{"state":"closed_without_replay","version":1}'
_WEIXIN_RECOVERY_KINDS = frozenset({"inbound", "delivery", "video"})


def _canonical_weixin_recovery_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_recovery_receipt_record(
    *,
    receipt_id: int,
    created_at: float,
    operation: str,
    operation_digest: str,
    decision_id: str,
    principal_sha256: str,
    row_before_sha256: str,
    previous_receipt_sha256: str,
    target_kind: str,
    target_key_sha256: str,
    actor: str,
    authorization: str,
    reason: str,
    decided_at_ms: int,
    closed_at_ms: int,
    after_sha256: str,
    affected_counts: dict[str, int],
    affected_rows: list[dict[str, object]],
) -> tuple[str, str]:
    unsigned = {
        "schema": _RECOVERY_RECEIPT_SCHEMA,
        "id": int(receipt_id),
        "created_at": float(created_at),
        "operation": str(operation),
        "operation_digest": str(operation_digest),
        "decision_id": str(decision_id),
        "principal_sha256": str(principal_sha256),
        "row_before_sha256": str(row_before_sha256),
        "previous_receipt_sha256": str(previous_receipt_sha256),
        "target_kind": str(target_kind),
        "target_key_sha256": str(target_key_sha256),
        "actor": str(actor),
        "authorization": str(authorization),
        "reason": str(reason),
        "decided_at_ms": int(decided_at_ms),
        "closed_at_ms": int(closed_at_ms),
        "after_sha256": str(after_sha256),
        "affected_counts": dict(affected_counts),
        "affected_rows": list(affected_rows),
    }
    unsigned_json = _canonical_weixin_recovery_json(unsigned)
    receipt_sha256 = hashlib.sha256(unsigned_json.encode("utf-8")).hexdigest()
    record = dict(unsigned)
    record["receipt_sha256"] = receipt_sha256
    return receipt_sha256, _canonical_weixin_recovery_json(record)


def _validate_recovery_receipts(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id,created_at,operation,operation_digest,decision_id,
               principal_sha256,row_before_sha256,previous_receipt_sha256,
               receipt_sha256,record_json
        FROM recovery_receipt ORDER BY id
        """
    ).fetchall()
    previous = _RECOVERY_RECEIPT_GENESIS
    for expected_id, row in enumerate(rows, start=1):
        if expected_id > max(1, min(int(_MAX_RECOVERY_RECEIPTS), 50_000)):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        try:
            receipt_id = int(row[0])
            created_at = float(row[1])
            operation = str(row[2])
            operation_digest = str(row[3])
            decision_id = str(row[4])
            principal_sha256 = str(row[5])
            row_before_sha256 = str(row[6])
            previous_receipt_sha256 = str(row[7])
            receipt_sha256 = str(row[8])
            record_json = str(row[9])
            record = json.loads(record_json)
        except (TypeError, ValueError, OverflowError, json.JSONDecodeError) as exc:
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt") from exc
        if not isinstance(record, dict):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        digests = (
            operation_digest,
            principal_sha256,
            row_before_sha256,
            previous_receipt_sha256,
            receipt_sha256,
        )
        if (
            receipt_id != expected_id
            or not math.isfinite(created_at)
            or created_at <= 0
            or operation not in _RECOVERY_RECEIPT_OPERATIONS
            or not decision_id
            or re.fullmatch(r"[0-9a-f]{64}", decision_id) is None
            or decision_id == _RECOVERY_RECEIPT_GENESIS
            or any(
                len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests
            )
            or not secrets.compare_digest(previous_receipt_sha256, previous)
            or any(
                value == _RECOVERY_RECEIPT_GENESIS
                for value in (
                    operation_digest,
                    principal_sha256,
                    row_before_sha256,
                    receipt_sha256,
                )
            )
        ):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        required_record_fields = {
            "schema", "id", "created_at", "operation", "operation_digest",
            "decision_id", "principal_sha256", "row_before_sha256",
            "previous_receipt_sha256", "target_kind", "target_key_sha256",
            "actor", "authorization", "reason", "decided_at_ms",
            "closed_at_ms", "after_sha256", "affected_counts",
            "affected_rows", "receipt_sha256",
        }
        if set(record) != required_record_fields:
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        counts = record.get("affected_counts")
        affected_rows = record.get("affected_rows")
        if (
            record.get("target_kind") not in _WEIXIN_RECOVERY_KINDS
            or not isinstance(counts, dict)
            or set(counts) != _WEIXIN_RECOVERY_KINDS
            or any(type(counts[kind]) is not int or counts[kind] < 0 for kind in counts)
            or not isinstance(affected_rows, list)
            or len(affected_rows) != sum(counts.values())
            or not affected_rows
        ):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        previous_identity: tuple[int, str] | None = None
        observed = {kind: 0 for kind in _WEIXIN_RECOVERY_KINDS}
        target_seen = False
        for member in affected_rows:
            if not isinstance(member, dict) or set(member) != {
                "kind", "row_key_sha256", "target_key_sha256",
                "before_sha256", "after_sha256"
            }:
                raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
            kind = member.get("kind")
            if kind not in _WEIXIN_RECOVERY_KINDS:
                raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
            member_digests = (
                member.get("row_key_sha256"),
                member.get("target_key_sha256"),
                member.get("before_sha256"),
                member.get("after_sha256"),
            )
            if any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == _RECOVERY_RECEIPT_GENESIS
                for value in member_digests
            ) or member.get("before_sha256") == member.get("after_sha256"):
                raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
            identity = (
                (0 if kind == "inbound" else 1 if kind == "delivery" else 2),
                str(member["row_key_sha256"]),
            )
            if previous_identity is not None and identity <= previous_identity:
                raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
            previous_identity = identity
            observed[str(kind)] += 1
            target_seen = target_seen or (
                kind == record["target_kind"]
                and member["target_key_sha256"] == record["target_key_sha256"]
            )
        record_digests = (
            record.get("target_key_sha256"),
            record.get("authorization"),
            record.get("after_sha256"),
        )
        if (
            observed != counts
            or not target_seen
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == _RECOVERY_RECEIPT_GENESIS
                for value in record_digests
            )
            or not isinstance(record.get("actor"), str)
            or not isinstance(record.get("reason"), str)
            or type(record.get("decided_at_ms")) is not int
            or type(record.get("closed_at_ms")) is not int
            or int(record.get("closed_at_ms")) < int(record.get("decided_at_ms"))
            or float(record.get("closed_at_ms")) / 1000.0 != created_at
            or not isinstance(record.get("actor"), str)
            or not record.get("actor")
            or str(record.get("actor")) != str(record.get("actor")).strip()
            or len(str(record.get("actor")).encode("utf-8")) > 256
            or not isinstance(record.get("reason"), str)
            or not record.get("reason")
            or str(record.get("reason")) != str(record.get("reason")).strip()
            or len(str(record.get("reason")).encode("utf-8")) > 2048
            or any(
                ord(character) < 32 or ord(character) == 127
                for value in (record.get("actor"), record.get("reason"))
                for character in str(value)
            )
        ):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        expected_sha256, expected_record = _canonical_recovery_receipt_record(
            receipt_id=receipt_id,
            created_at=created_at,
            operation=operation,
            operation_digest=operation_digest,
            decision_id=decision_id,
            principal_sha256=principal_sha256,
            row_before_sha256=row_before_sha256,
            previous_receipt_sha256=previous_receipt_sha256,
            target_kind=str(record["target_kind"]),
            target_key_sha256=str(record["target_key_sha256"]),
            actor=str(record["actor"]),
            authorization=str(record["authorization"]),
            reason=str(record["reason"]),
            decided_at_ms=int(record["decided_at_ms"]),
            closed_at_ms=int(record["closed_at_ms"]),
            after_sha256=str(record["after_sha256"]),
            affected_counts={str(k): int(v) for k, v in counts.items()},
            affected_rows=[dict(member) for member in affected_rows],
        )
        if not secrets.compare_digest(receipt_sha256, expected_sha256) or not secrets.compare_digest(
            record_json, expected_record
        ):
            raise sqlite3.DatabaseError("invalid Weixin recovery receipt")
        previous = receipt_sha256


_WEIXIN_RECOVERY_TARGETS = {
    "inbound": ("inbound_message", "message_key", "from_user_id", "id"),
    "delivery": ("pending_delivery", "delivery_id", "to_user_id", "id"),
    "video": ("pending_video", "task_id", "to_user_id", "task_id"),
}
_WEIXIN_RECOVERY_KIND_ORDER = {"inbound": 0, "delivery": 1, "video": 2}
_WEIXIN_RECOVERY_OPERATION_DOMAIN = b"nachuan.weixin.close-without-replay.operation/v1\0"
_WEIXIN_RECOVERY_SET_DOMAIN = b"nachuan.weixin.close-without-replay.set/v1\0"
_WEIXIN_RECOVERY_ROW_DOMAIN = b"nachuan.weixin.close-without-replay.row/v1\0"
_WEIXIN_RECOVERY_TARGET_DOMAIN = b"nachuan.weixin.close-without-replay.target/v1\0"
_WEIXIN_RECOVERY_PRINCIPAL_DOMAIN = b"nachuan.weixin.close-without-replay.principal/v1\0"


def _weixin_recovery_digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(
        domain + _canonical_weixin_recovery_json(value).encode("ascii")
    ).hexdigest()


def _require_weixin_recovery_digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
        or value == _RECOVERY_RECEIPT_GENESIS
    ):
        raise ValueError(
            f"Weixin recovery {field} must be a nonzero lowercase SHA-256"
        )
    return value


def _require_weixin_recovery_text(
    value: object, field: str, *, max_bytes: int
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"Weixin recovery {field} is invalid")
    if len(value.encode("utf-8")) > max_bytes or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError(f"Weixin recovery {field} is invalid")
    return value


def _require_weixin_recovery_ms(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 9_223_372_036_854_775_807
    ):
        raise ValueError(
            f"Weixin recovery {field} must be a non-negative integer millisecond value"
        )
    return value


def _validated_weixin_recovery_target(
    target_kind: object, target_key: object
) -> tuple[str, str]:
    if target_kind not in _WEIXIN_RECOVERY_TARGETS:
        raise ValueError(
            "Weixin recovery target kind must be inbound, delivery, or video"
        )
    return str(target_kind), _require_weixin_recovery_text(
        target_key, "target key", max_bytes=512
    )


def _weixin_recovery_target_key_sha256(kind: str, key: str) -> str:
    return _weixin_recovery_digest(
        _WEIXIN_RECOVERY_TARGET_DOMAIN,
        {"kind": kind, "key": key},
    )


def _weixin_close_without_replay_operation_digest(
    *,
    decision_id: str,
    target_kind: str,
    target_key: str,
    expected_before_digest: str,
    actor: str,
    authorization: str,
    reason: str,
    decided_at_ms: int,
) -> str:
    kind, key = _validated_weixin_recovery_target(target_kind, target_key)
    decision = _require_weixin_recovery_digest(decision_id, "decision id")
    before = _require_weixin_recovery_digest(
        expected_before_digest, "before digest"
    )
    authorized_by = _require_weixin_recovery_digest(
        authorization, "authorization"
    )
    normalized_actor = _require_weixin_recovery_text(
        actor, "actor", max_bytes=256
    )
    normalized_reason = _require_weixin_recovery_text(
        reason, "reason", max_bytes=2048
    )
    decided = _require_weixin_recovery_ms(decided_at_ms, "decision time")
    return _weixin_recovery_digest(
        _WEIXIN_RECOVERY_OPERATION_DOMAIN,
        {
            "schema": "nachuan.weixin-recovery-close-request.v1",
            "operation": "close_without_replay",
            "decision_id": decision,
            "target_kind": kind,
            "target_key": key,
            "expected_before_digest": before,
            "actor": normalized_actor,
            "authorization": authorized_by,
            "reason": normalized_reason,
            "decided_at_ms": decided,
        },
    )


def _validated_weixin_close_request(
    request: _WeixinCloseWithoutReplayRequest,
) -> _WeixinCloseWithoutReplayRequest:
    if not isinstance(request, _WeixinCloseWithoutReplayRequest):
        raise TypeError("Weixin close_without_replay requires its typed request")
    expected = _weixin_close_without_replay_operation_digest(
        decision_id=request.decision_id,
        target_kind=request.target_kind,
        target_key=request.target_key,
        expected_before_digest=request.expected_before_digest,
        actor=request.actor,
        authorization=request.authorization,
        reason=request.reason,
        decided_at_ms=request.decided_at_ms,
    )
    operation = _require_weixin_recovery_digest(
        request.operation_digest, "operation digest"
    )
    if not secrets.compare_digest(operation, expected):
        raise WeixinRecoveryConflict(
            "Weixin recovery operation digest does not match canonical request"
        )
    return request


def _weixin_recovery_columns(
    conn: sqlite3.Connection, table: str
) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})"))


def _weixin_recovery_record(
    kind: str, columns: tuple[str, ...], row: tuple[object, ...]
) -> dict[str, object]:
    return {
        "kind": kind,
        "values": dict(zip(columns, row, strict=True)),
    }


def _weixin_recovery_row_is_unclaimed(record: dict[str, object]) -> bool:
    values = record["values"]
    assert isinstance(values, dict)
    return bool(
        float(values["claimed_at"]) == 0.0
        and str(values["claim_token"]) == ""
        and float(values["claim_deadline"]) == 0.0
        and float(values["heartbeat_at"]) == 0.0
    )


def _weixin_recovery_target_rows_in_transaction(
    conn: sqlite3.Connection, target_kind: str, target_key: str
) -> tuple[str, list[dict[str, object]]]:
    table, key_column, principal_column, _identity_column = (
        _WEIXIN_RECOVERY_TARGETS[target_kind]
    )
    principals = conn.execute(
        f"SELECT DISTINCT {principal_column} FROM {table} "
        f"WHERE {key_column}=? AND status='recovery_required'",
        (target_key,),
    ).fetchall()
    if len(principals) != 1 or not str(principals[0][0]):
        raise WeixinRecoveryConflict(
            "Weixin recovery target is not a recovery_required row"
        )
    principal = str(principals[0][0])
    affected: list[dict[str, object]] = []
    for kind in ("inbound", "delivery", "video"):
        affected_table, _key, affected_principal, identity_column = (
            _WEIXIN_RECOVERY_TARGETS[kind]
        )
        columns = _weixin_recovery_columns(conn, affected_table)
        selected = ",".join(columns)
        rows = conn.execute(
            f"SELECT {selected} FROM {affected_table} "
            f"WHERE {affected_principal}=? AND status='recovery_required' "
            f"ORDER BY {identity_column}",
            (principal,),
        ).fetchall()
        for row in rows:
            record = _weixin_recovery_record(kind, columns, tuple(row))
            if not _weixin_recovery_row_is_unclaimed(record):
                raise WeixinRecoveryConflict(
                    "Weixin recovery principal contains an actively claimed row"
                )
            affected.append(record)
    if not affected:
        raise WeixinRecoveryConflict("Weixin recovery affected set is empty")
    return principal, affected


def _weixin_recovery_affected_set_digest(
    rows: list[dict[str, object]],
) -> str:
    return _weixin_recovery_digest(_WEIXIN_RECOVERY_SET_DOMAIN, rows)


def _weixin_recovery_target_before_digest(
    target_kind: str, target_key: str
) -> str:
    return str(
        _weixin_recovery_target_snapshot(target_kind, target_key)[
            "expected_before_digest"
        ]
    )


def _weixin_recovery_target_snapshot(
    target_kind: str, target_key: str
) -> dict[str, object]:
    kind, key = _validated_weixin_recovery_target(target_kind, target_key)
    with closing(_outbox_connect()) as conn:
        principal, rows = _weixin_recovery_target_rows_in_transaction(
            conn, kind, key
        )
    return {
        "schema": "nachuan.weixin-recovery-snapshot.v1",
        "target_kind": kind,
        "target_key_sha256": _weixin_recovery_target_key_sha256(kind, key),
        "principal_sha256": _weixin_recovery_digest(
            _WEIXIN_RECOVERY_PRINCIPAL_DOMAIN, principal
        ),
        "expected_before_digest": _weixin_recovery_affected_set_digest(rows),
        "affected_counts": {
            affected_kind: sum(
                row["kind"] == affected_kind for row in rows
            )
            for affected_kind in ("inbound", "delivery", "video")
        },
    }


def _weixin_recovery_rows_by_identity(
    conn: sqlite3.Connection, before_rows: list[dict[str, object]]
) -> list[dict[str, object]]:
    after: list[dict[str, object]] = []
    for record in before_rows:
        kind = str(record["kind"])
        table, _key, _principal, identity_column = _WEIXIN_RECOVERY_TARGETS[kind]
        values = record["values"]
        assert isinstance(values, dict)
        columns = _weixin_recovery_columns(conn, table)
        row = conn.execute(
            f"SELECT {','.join(columns)} FROM {table} WHERE {identity_column}=?",
            (values[identity_column],),
        ).fetchone()
        if row is None:
            raise WeixinRecoveryConflict(
                "Weixin recovery closed row set is incomplete"
            )
        after.append(_weixin_recovery_record(kind, columns, tuple(row)))
    return after


def _weixin_existing_recovery_result(
    row: tuple[object, ...], request: _WeixinCloseWithoutReplayRequest
) -> _WeixinCloseWithoutReplayResult:
    try:
        record = json.loads(str(row[2]))
        counts = record["affected_counts"]
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise WeixinRecoveryConflict(
            "Weixin recovery receipt is invalid"
        ) from exc
    if (
        not secrets.compare_digest(str(row[0]), request.operation_digest)
        or not secrets.compare_digest(str(record["decision_id"]), request.decision_id)
        or not secrets.compare_digest(str(record["actor"]), request.actor)
        or not secrets.compare_digest(str(record["authorization"]), request.authorization)
        or not secrets.compare_digest(str(record["reason"]), request.reason)
        or int(record["decided_at_ms"]) != request.decided_at_ms
        or not secrets.compare_digest(
            str(record["row_before_sha256"]), request.expected_before_digest
        )
        or str(record["target_kind"]) != request.target_kind
        or not secrets.compare_digest(
            str(record["target_key_sha256"]),
            _weixin_recovery_target_key_sha256(
                request.target_kind, request.target_key
            ),
        )
    ):
        raise WeixinRecoveryConflict(
            "Weixin recovery operation conflicts with durable receipt"
        )
    return _WeixinCloseWithoutReplayResult(
        operation_digest=request.operation_digest,
        receipt_sha256=str(row[1]),
        affected_inbound_count=int(counts["inbound"]),
        affected_delivery_count=int(counts["delivery"]),
        affected_video_count=int(counts["video"]),
        applied=False,
    )


def _weixin_close_without_replay(
    request: _WeixinCloseWithoutReplayRequest,
    *,
    closed_at_ms: int,
) -> _WeixinCloseWithoutReplayResult:
    """Atomically tombstone one principal's uncertain work without replay."""

    request = _validated_weixin_close_request(request)
    closed_ms = _require_weixin_recovery_ms(closed_at_ms, "close time")
    if closed_ms < request.decided_at_ms or closed_ms <= 0:
        raise ValueError("Weixin recovery close time precedes decision")
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _validate_recovery_receipts(conn)
        existing = conn.execute(
            "SELECT operation_digest,receipt_sha256,record_json "
            "FROM recovery_receipt WHERE operation_digest=?",
            (request.operation_digest,),
        ).fetchone()
        if existing is not None:
            result = _weixin_existing_recovery_result(tuple(existing), request)
            conn.commit()
            return result
        if conn.execute(
            "SELECT 1 FROM recovery_receipt WHERE decision_id=?",
            (request.decision_id,),
        ).fetchone() is not None:
            raise WeixinRecoveryConflict(
                "Weixin recovery decision id belongs to another operation"
            )
        receipt_count, previous_sha256 = conn.execute(
            "SELECT COUNT(*),COALESCE(MAX(receipt_sha256),'') "
            "FROM recovery_receipt"
        ).fetchone()
        receipt_count = int(receipt_count)
        receipt_cap = max(1, min(int(_MAX_RECOVERY_RECEIPTS), 50_000))
        if receipt_count >= receipt_cap:
            raise WeixinRecoveryConflict(
                "Weixin recovery receipt capacity is full"
            )
        if receipt_count == 0:
            previous_sha256 = _RECOVERY_RECEIPT_GENESIS
        else:
            previous_sha256 = conn.execute(
                "SELECT receipt_sha256 FROM recovery_receipt ORDER BY id DESC LIMIT 1"
            ).fetchone()[0]
        principal, before_rows = _weixin_recovery_target_rows_in_transaction(
            conn, request.target_kind, request.target_key
        )
        before_digest = _weixin_recovery_affected_set_digest(before_rows)
        if not secrets.compare_digest(
            before_digest, request.expected_before_digest
        ):
            raise WeixinRecoveryConflict(
                "Weixin recovery target set drifted after adjudication"
            )
        opaque_principal = _opaque_identity(principal)
        closed_seconds = closed_ms / 1000.0
        counts = {
            kind: sum(row["kind"] == kind for row in before_rows)
            for kind in ("inbound", "delivery", "video")
        }
        changed_inbound = conn.execute(
            """
            UPDATE inbound_message
            SET status='dead',from_user_id=?,payload=?,last_error='closed_without_replay',
                claim_token='',claimed_at=0,claim_deadline=0,heartbeat_at=0
            WHERE from_user_id=? AND status='recovery_required' AND claimed_at=0
              AND claim_token='' AND claim_deadline=0 AND heartbeat_at=0
            """,
            (opaque_principal, _RECOVERY_TOMBSTONE, principal),
        ).rowcount
        changed_delivery = conn.execute(
            """
            UPDATE pending_delivery
            SET status='dead',to_user_id=?,context_token='',text='',
                last_error='closed_without_replay',claim_token='',claimed_at=0,
                claim_deadline=0,heartbeat_at=0,
                terminal_verification='closed_without_replay'
            WHERE to_user_id=? AND status='recovery_required' AND claimed_at=0
              AND claim_token='' AND claim_deadline=0 AND heartbeat_at=0
            """,
            (opaque_principal, principal),
        ).rowcount
        changed_video = conn.execute(
            """
            UPDATE pending_video
            SET status='dead',to_user_id=?,context_token='',result_url='',
                last_error='closed_without_replay',claim_token='',claimed_at=0,
                claim_deadline=0,heartbeat_at=0,finished_at=?,
                terminal_verification='closed_without_replay'
            WHERE to_user_id=? AND status='recovery_required' AND claimed_at=0
              AND claim_token='' AND claim_deadline=0 AND heartbeat_at=0
            """,
            (opaque_principal, closed_seconds, principal),
        ).rowcount
        changed = {
            "inbound": int(changed_inbound),
            "delivery": int(changed_delivery),
            "video": int(changed_video),
        }
        if changed != counts:
            raise WeixinRecoveryConflict(
                "Weixin recovery target changed during close transaction"
            )
        after_rows = _weixin_recovery_rows_by_identity(conn, before_rows)
        after_digest = _weixin_recovery_affected_set_digest(after_rows)
        affected_manifest: list[dict[str, object]] = []
        for before, after in zip(before_rows, after_rows, strict=True):
            kind = str(before["kind"])
            if kind != str(after["kind"]):
                raise WeixinRecoveryConflict("Weixin recovery row order drifted")
            _table, key_column, _principal, identity_column = (
                _WEIXIN_RECOVERY_TARGETS[kind]
            )
            before_values = before["values"]
            after_values = after["values"]
            assert isinstance(before_values, dict) and isinstance(after_values, dict)
            if before_values[identity_column] != after_values[identity_column]:
                raise WeixinRecoveryConflict("Weixin recovery row identity drifted")
            affected_manifest.append(
                {
                    "kind": kind,
                    "row_key_sha256": _weixin_recovery_digest(
                        _WEIXIN_RECOVERY_TARGET_DOMAIN,
                        {
                            "kind": kind,
                            "identity": before_values[identity_column],
                        },
                    ),
                    "target_key_sha256": _weixin_recovery_target_key_sha256(
                        kind, str(before_values[key_column])
                    ),
                    "before_sha256": _weixin_recovery_digest(
                        _WEIXIN_RECOVERY_ROW_DOMAIN, before
                    ),
                    "after_sha256": _weixin_recovery_digest(
                        _WEIXIN_RECOVERY_ROW_DOMAIN, after
                    ),
                }
            )
        affected_manifest.sort(
            key=lambda row: (
                _WEIXIN_RECOVERY_KIND_ORDER[str(row["kind"])],
                str(row["row_key_sha256"]),
            )
        )
        receipt_id = receipt_count + 1
        target_key_sha256 = _weixin_recovery_target_key_sha256(
            request.target_kind, request.target_key
        )
        principal_sha256 = _weixin_recovery_digest(
            _WEIXIN_RECOVERY_PRINCIPAL_DOMAIN, principal
        )
        receipt_sha256, record_json = _canonical_recovery_receipt_record(
            receipt_id=receipt_id,
            created_at=closed_seconds,
            operation="close_without_replay",
            operation_digest=request.operation_digest,
            decision_id=request.decision_id,
            principal_sha256=principal_sha256,
            row_before_sha256=before_digest,
            previous_receipt_sha256=str(previous_sha256),
            target_kind=request.target_kind,
            target_key_sha256=target_key_sha256,
            actor=request.actor,
            authorization=request.authorization,
            reason=request.reason,
            decided_at_ms=request.decided_at_ms,
            closed_at_ms=closed_ms,
            after_sha256=after_digest,
            affected_counts=counts,
            affected_rows=affected_manifest,
        )
        conn.execute(
            """
            INSERT INTO recovery_receipt(
                id,created_at,operation,operation_digest,decision_id,
                principal_sha256,row_before_sha256,previous_receipt_sha256,
                receipt_sha256,record_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id,
                closed_seconds,
                "close_without_replay",
                request.operation_digest,
                request.decision_id,
                principal_sha256,
                before_digest,
                previous_sha256,
                receipt_sha256,
                record_json,
            ),
        )
        _validate_recovery_receipts(conn)
        conn.commit()
        return _WeixinCloseWithoutReplayResult(
            operation_digest=request.operation_digest,
            receipt_sha256=receipt_sha256,
            affected_inbound_count=counts["inbound"],
            affected_delivery_count=counts["delivery"],
            affected_video_count=counts["video"],
            applied=True,
        )
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _validate_current_outbox_schema(conn: sqlite3.Connection) -> None:
    if _classify_outbox_schema(conn) != "v2":
        raise sqlite3.DatabaseError("unknown Weixin state schema")
    _validate_recovery_receipts(conn)


class _OutboxDatabaseFamilyChanged(sqlite3.DatabaseError):
    pass


def _outbox_database_family_presence() -> dict[str, bool]:
    return {
        suffix: Path(f"{_OUTBOX_DB}{suffix}").is_file()
        for suffix in ("", "-wal", "-shm", "-journal")
    }


def _outbox_readonly_uri(*, wal_aware: bool) -> str:
    suffix = "?mode=ro" if wal_aware else "?mode=ro&immutable=1"
    return "file:" + urllib.parse.quote(
        _OUTBOX_DB.resolve().as_posix(), safe="/:"
    ) + suffix


def _remaining_outbox_finish_budget(
    deadline_monotonic: float | None,
) -> float | None:
    """Return one absolute finish deadline's remainder or fail closed."""

    if deadline_monotonic is None:
        return None
    deadline = float(deadline_monotonic)
    if not math.isfinite(deadline):
        raise ValueError("Weixin finish deadline must be finite")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _OutboxFinishDeadlineExceeded("Weixin finish deadline exceeded")
    return remaining


def _constrain_outbox_busy_timeout(
    conn: sqlite3.Connection,
    *,
    deadline_monotonic: float | None,
    default_busy_timeout_ms: int,
) -> int:
    """Shrink each SQLite lock wait to the same absolute finish deadline."""

    remaining = _remaining_outbox_finish_budget(deadline_monotonic)
    busy_timeout_ms = max(0, int(default_busy_timeout_ms))
    if remaining is not None:
        busy_timeout_ms = min(busy_timeout_ms, max(0, int(remaining * 1000)))
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    _remaining_outbox_finish_budget(deadline_monotonic)
    return busy_timeout_ms


def _preflight_outbox_schema(
    *, deadline_monotonic: float | None = None
) -> tuple[str, os.stat_result | None, dict[str, bool]]:
    _remaining_outbox_finish_budget(deadline_monotonic)
    presence = _outbox_database_family_presence()
    if not presence[""]:
        if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
            raise _OutboxDatabaseFamilyChanged(
                "Weixin state main database is missing beside sidecars"
            )
        return "empty", None, presence
    if presence["-journal"]:
        raise _OutboxDatabaseFamilyChanged(
            "Weixin state rollback journal has not stabilized"
        )
    if presence["-wal"] != presence["-shm"]:
        raise _OutboxDatabaseFamilyChanged(
            "Weixin state WAL and SHM sidecars have not stabilized"
        )
    identity = os.lstat(_OUTBOX_DB)
    remaining = _remaining_outbox_finish_budget(deadline_monotonic)
    connect_timeout = 10.0 if remaining is None else min(10.0, remaining)
    with closing(
        sqlite3.connect(
            _outbox_readonly_uri(wal_aware=presence["-wal"]),
            uri=True,
            timeout=max(0.0, connect_timeout),
            isolation_level=None,
        )
    ) as conn:
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("BEGIN")
        try:
            generation = _classify_outbox_schema(conn)
            if generation == "v2":
                _validate_recovery_receipts(conn)
        finally:
            conn.rollback()
    _remaining_outbox_finish_budget(deadline_monotonic)
    if _outbox_database_family_presence() != presence:
        raise _OutboxDatabaseFamilyChanged(
            "Weixin state database family changed during read-only preflight"
        )
    try:
        current_identity = os.lstat(_OUTBOX_DB)
    except FileNotFoundError as exc:
        raise _OutboxDatabaseFamilyChanged(
            "Weixin state database disappeared during read-only preflight"
        ) from exc
    if not os.path.samestat(identity, current_identity):
        raise _OutboxDatabaseFamilyChanged(
            "Weixin state database identity changed during read-only preflight"
        )
    _remaining_outbox_finish_budget(deadline_monotonic)
    return generation, identity, presence


def _stabilized_outbox_preflight(
    *, deadline_monotonic: float | None = None
) -> tuple[str, os.stat_result | None, dict[str, bool]]:
    last_change: _OutboxDatabaseFamilyChanged | None = None
    deadline = (
        float(deadline_monotonic)
        if deadline_monotonic is not None
        else time.monotonic() + 10.0
    )
    if not math.isfinite(deadline):
        raise ValueError("Weixin finish deadline must be finite")
    while True:
        try:
            if deadline_monotonic is None:
                return _preflight_outbox_schema()
            return _preflight_outbox_schema(deadline_monotonic=deadline)
        except _OutboxDatabaseFamilyChanged as exc:
            last_change = exc
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.025, remaining))
                continue
            raise sqlite3.DatabaseError(
                "Weixin state database family did not stabilize"
            ) from last_change


def _outbox_connect(
    *, deadline_monotonic: float | None = None
) -> sqlite3.Connection:
    _remaining_outbox_finish_budget(deadline_monotonic)
    _OUTBOX_DB.parent.mkdir(parents=True, exist_ok=True)
    if deadline_monotonic is None:
        preflight = _stabilized_outbox_preflight()
    else:
        preflight = _stabilized_outbox_preflight(
            deadline_monotonic=deadline_monotonic
        )
    preflight_generation, preflight_identity, _preflight_family = preflight
    remaining = _remaining_outbox_finish_budget(deadline_monotonic)
    connect_timeout = 10.0 if remaining is None else min(10.0, remaining)
    conn = sqlite3.connect(
        _OUTBOX_DB,
        timeout=max(0.0, connect_timeout),
        factory=_OutboxConnection,
    )
    try:
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.execute("PRAGMA trusted_schema=OFF")
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.execute("BEGIN IMMEDIATE")
        _remaining_outbox_finish_budget(deadline_monotonic)
        generation = _classify_outbox_schema(conn)
        if preflight_identity is not None:
            opened_identity = os.lstat(_OUTBOX_DB)
            if not os.path.samestat(preflight_identity, opened_identity):
                raise sqlite3.DatabaseError(
                    "Weixin state database identity changed before locked open"
                )
        peer_converged = preflight_generation != "v2" and generation == "v2"
        if generation != preflight_generation and not peer_converged:
            raise sqlite3.DatabaseError(
                "Weixin state database changed during initialization"
            )
        if generation == "empty":
            _create_outbox_schema(conn)
        elif generation == "v0_base":
            _migrate_outbox_v0(conn)
            if _classify_outbox_schema(conn) != "v1":
                raise sqlite3.DatabaseError("Weixin v0 to v1 migration failed")
            _migrate_outbox_v1(conn)
        elif generation == "v0_previous_runtime":
            _migrate_outbox_previous_runtime_v0(conn)
            if _classify_outbox_schema(conn) != "v1":
                raise sqlite3.DatabaseError("Weixin v0 to v1 migration failed")
            _migrate_outbox_v1(conn)
        elif generation == "v0_current_shape":
            conn.execute(f"PRAGMA application_id={_OUTBOX_APPLICATION_ID}")
            conn.execute("PRAGMA user_version=1")
            if _classify_outbox_schema(conn) != "v1":
                raise sqlite3.DatabaseError("Weixin v0 current shape stamp failed")
            _migrate_outbox_v1(conn)
        elif generation == "v1":
            _migrate_outbox_v1(conn)
        _validate_current_outbox_schema(conn)
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.commit()
        _remaining_outbox_finish_budget(deadline_monotonic)

        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        _remaining_outbox_finish_budget(deadline_monotonic)
        if not journal_mode or str(journal_mode[0]).lower() != "wal":
            raise sqlite3.DatabaseError("Weixin state database requires WAL mode")
        page_size = max(512, int(conn.execute("PRAGMA page_size").fetchone()[0]))
        max_pages = max(1, _STATE_DB_MAX_BYTES // page_size)
        conn.execute(f"PRAGMA max_page_count={max_pages}")
        conn.execute(f"PRAGMA journal_size_limit={_STATE_DB_MAX_WAL_BYTES}")
        conn.execute("PRAGMA wal_autocheckpoint=1000")
        _validate_current_outbox_schema(conn)
        _remaining_outbox_finish_budget(deadline_monotonic)
        return conn
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        conn.close()
        raise


def _video_reservation_id(source_message_key: str) -> str:
    digest = hashlib.sha256(source_message_key.encode("utf-8")).hexdigest()
    return f"reservation:{digest}"


def _require_pending_video_mutation_fence(
    conn: sqlite3.Connection,
    *,
    source_message_key: str,
    now=None,
    _write_authority: _OutboxImmediateWriteAuthority | None,
    _internal_maintenance: bool,
) -> None:
    """Authorize a video mutation as either one live inbound or explicit maintenance."""

    _require_outbox_immediate_write(conn, _write_authority)
    fields = (
        "claim_id",
        "claim_token",
        "claim_epoch",
        "claim_message_key",
        "lease_session",
    )
    present = tuple(hasattr(_HANDLE_CONTEXT, name) for name in fields)
    if any(present):
        if _internal_maintenance:
            raise RuntimeError("inbound video mutation cannot bypass its claim fence")
        if not all(present):
            raise InboundFinishFenceLost("pending_video_source_fence_lost")
        context_message_key = str(
            getattr(_HANDLE_CONTEXT, "claim_message_key", "") or ""
        )
        if not context_message_key or not secrets.compare_digest(
            context_message_key,
            str(source_message_key),
        ):
            raise InboundFinishFenceLost("pending_video_source_fence_lost")
        _require_inbound_outbox_fence(
            conn,
            now=now,
            _write_authority=_write_authority,
            expected_message_key=context_message_key,
        )
        return
    if not _internal_maintenance:
        raise InboundFinishFenceLost("pending_video_inbound_fence_required")


def _pending_video_commit_fence():
    session = getattr(_HANDLE_CONTEXT, "lease_session", None)
    if session is None:
        return nullcontext()
    fence_factory = getattr(session, "commit_fence", None)
    if not callable(fence_factory):
        raise InboundFinishFenceLost("pending_video_commit_fence_required")
    return fence_factory()


def _reserve_pending_video_capacity(
    to_user_id: object,
    context_token: object,
    *,
    source_message_key: object,
    now=None,
    _internal_maintenance: bool = False,
) -> str:
    with _pending_video_commit_fence():
        return _reserve_pending_video_capacity_fenced(
            to_user_id,
            context_token,
            source_message_key=source_message_key,
            now=now,
            _internal_maintenance=_internal_maintenance,
        )


def _reserve_pending_video_capacity_fenced(
    to_user_id: object,
    context_token: object,
    *,
    source_message_key: object,
    now=None,
    _internal_maintenance: bool = False,
) -> str:
    """Reserve one durable slot before an Agent call can create an upstream task."""

    recipient = str(to_user_id or "").strip()
    context = str(context_token or "")
    source = str(source_message_key or "").strip()
    if (
        not recipient
        or len(recipient) > 512
        or len(context) > _VIDEO_CONTEXT_MAX_CHARS
        or not source
        or len(source) > 512
        or any(ord(char) < 32 or ord(char) == 127 for char in recipient)
    ):
        raise ValueError("微信异步视频预留身份无效")
    reservation_id = _video_reservation_id(source)
    conn = _outbox_connect()
    write_authority: _OutboxImmediateWriteAuthority | None = None
    try:
        write_authority = _begin_outbox_immediate_write(conn)
        current = _policy_time(now)
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        conn.execute(
            """
            DELETE FROM pending_video
            WHERE status='reserved' AND created_at<?
              AND NOT EXISTS (
                SELECT 1 FROM inbound_message AS inbound
                WHERE inbound.message_key=pending_video.source_message_key
                  AND inbound.status IN ('pending','processing','recovery_required')
              )
            """,
            (current - _VIDEO_RESERVATION_TTL_SECONDS,),
        )
        chat_group = _claimed_inbound_chat_group(conn, recipient=recipient)
        existing = conn.execute(
            "SELECT task_id,to_user_id,context_token,status,chat_seq FROM pending_video "
            "WHERE source_message_key=?",
            (source,),
        ).fetchone()
        if existing is not None:
            if (str(existing[1]), str(existing[2])) != (recipient, context):
                raise RuntimeError("微信视频预留与另一会话冲突")
            if chat_group is not None and int(existing[4] or 0) != chat_group[0]:
                raise RuntimeError("微信视频预留与另一因果组冲突")
            _require_pending_video_mutation_fence(
                conn,
                source_message_key=source,
                now=now,
                _write_authority=write_authority,
                _internal_maintenance=_internal_maintenance,
            )
            conn.commit()
            return str(existing[0])
        active = int(
            conn.execute(
                "SELECT COUNT(*) FROM pending_video "
                "WHERE status IN ('reserved','pending','processing','recovery_required')"
            ).fetchone()[0]
        )
        if active >= _MAX_PENDING_VIDEO_ROWS:
            raise VideoCapacityError("微信异步视频待办容量已耗尽")
        per_user_active = int(
            conn.execute(
                "SELECT COUNT(*) FROM pending_video WHERE to_user_id=? "
                "AND status IN ('reserved','pending','processing','recovery_required')",
                (recipient,),
            ).fetchone()[0]
        )
        if per_user_active >= _MAX_PENDING_VIDEO_PER_USER:
            raise VideoCapacityError("微信异步视频单用户待办容量已耗尽")
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        chat_seq = chat_group[0] if chat_group is not None else _allocate_chat_seq(conn)
        conn.execute(
            """
            INSERT INTO pending_video(
                task_id,to_user_id,context_token,source_message_key,
                created_at,deadline_at,next_attempt_at,status,chat_seq
            ) VALUES(?,?,?,?,?,?,?,'reserved',?)
            """,
            (
                reservation_id,
                recipient,
                context,
                source,
                current,
                current + _VIDEO_TASK_TIMEOUT_SECONDS,
                current,
                chat_seq,
            ),
        )
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        _end_outbox_immediate_write(conn, write_authority)
        write_authority = None
        conn.commit()
        return reservation_id
    except BaseException:
        conn.rollback()
        raise
    finally:
        if write_authority is not None:
            _end_outbox_immediate_write(conn, write_authority)
        conn.close()


def _release_pending_video_reservation(
    source_message_key: object,
    *,
    now=None,
    _internal_maintenance: bool = False,
) -> bool:
    with _pending_video_commit_fence():
        return _release_pending_video_reservation_fenced(
            source_message_key,
            now=now,
            _internal_maintenance=_internal_maintenance,
        )


def _release_pending_video_reservation_fenced(
    source_message_key: object,
    *,
    now=None,
    _internal_maintenance: bool = False,
) -> bool:
    source = str(source_message_key or "").strip()
    if not source:
        return False
    conn = _outbox_connect()
    write_authority: _OutboxImmediateWriteAuthority | None = None
    try:
        write_authority = _begin_outbox_immediate_write(conn)
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        changed = conn.execute(
            "DELETE FROM pending_video WHERE source_message_key=? AND status='reserved'",
            (source,),
        ).rowcount
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        _end_outbox_immediate_write(conn, write_authority)
        write_authority = None
        conn.commit()
        return changed == 1
    except BaseException:
        conn.rollback()
        raise
    finally:
        if write_authority is not None:
            _end_outbox_immediate_write(conn, write_authority)
        conn.close()


def _enqueue_pending_video(
    task_id: object,
    to_user_id: object,
    context_token: object,
    *,
    source_message_key: object,
    now=None,
    _internal_maintenance: bool = False,
) -> bool:
    with _pending_video_commit_fence():
        return _enqueue_pending_video_fenced(
            task_id,
            to_user_id,
            context_token,
            source_message_key=source_message_key,
            now=now,
            _internal_maintenance=_internal_maintenance,
        )


def _enqueue_pending_video_fenced(
    task_id: object,
    to_user_id: object,
    context_token: object,
    *,
    source_message_key: object,
    now=None,
    _internal_maintenance: bool = False,
) -> bool:
    """Durably bind one async engine task to its original WeChat recipient."""

    task = str(task_id or "").strip()
    recipient = str(to_user_id or "").strip()
    context = str(context_token or "")
    source = str(source_message_key or "").strip()
    if (
        not task
        or len(task) > _VIDEO_TASK_ID_MAX_CHARS
        or task.startswith("reservation:")
        or not recipient
        or len(recipient) > 512
        or len(context) > _VIDEO_CONTEXT_MAX_CHARS
        or not source
        or len(source) > 512
        or any(ord(char) < 32 or ord(char) == 127 for char in task)
        or any(ord(char) < 32 or ord(char) == 127 for char in recipient)
    ):
        raise ValueError("微信异步视频任务身份无效")
    conn = _outbox_connect()
    write_authority: _OutboxImmediateWriteAuthority | None = None
    try:
        write_authority = _begin_outbox_immediate_write(conn)
        current = _policy_time(now)
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        chat_group = _claimed_inbound_chat_group(conn, recipient=recipient)
        existing = conn.execute(
            "SELECT to_user_id,context_token,source_message_key,chat_seq "
            "FROM pending_video WHERE task_id=?",
            (task,),
        ).fetchone()
        if existing is not None:
            if tuple(existing[:3]) != (recipient, context, source):
                raise RuntimeError("微信视频 task_id 与另一会话冲突")
            if chat_group is not None and int(existing[3] or 0) != chat_group[0]:
                raise RuntimeError("微信视频 task_id 与另一因果组冲突")
            conn.commit()
            return False
        reserved = conn.execute(
            "SELECT task_id,to_user_id,context_token,status,chat_seq FROM pending_video "
            "WHERE source_message_key=?",
            (source,),
        ).fetchone()
        if reserved is not None:
            if (str(reserved[1]), str(reserved[2])) != (recipient, context):
                raise RuntimeError("微信视频预留与另一会话冲突")
            # A reservation created out-of-turn (explicit maintenance) for this
            # same source message is re-bound to the live turn's chat position;
            # the mutation fence above has already pinned source == claim turn.
            if str(reserved[3]) != "reserved":
                raise RuntimeError("同一微信消息返回了冲突的视频 task_id")
            _require_pending_video_mutation_fence(
                conn,
                source_message_key=source,
                now=now,
                _write_authority=write_authority,
                _internal_maintenance=_internal_maintenance,
            )
            changed = conn.execute(
                """
                UPDATE pending_video
                SET task_id=?,created_at=?,deadline_at=?,next_attempt_at=?,
                    attempts=0,status='pending',result_url='',last_error='',
                    direct_attempted=0,claim_token='',claimed_at=0,finished_at=0,
                    chat_seq=?
                WHERE task_id=? AND source_message_key=? AND status='reserved'
                """,
                (
                    task,
                    current,
                    current + _VIDEO_TASK_TIMEOUT_SECONDS,
                    current,
                    (
                        chat_group[0]
                        if chat_group is not None
                        else int(reserved[4] or 0)
                    ),
                    str(reserved[0]),
                    source,
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError("微信视频预留转正失败")
            _require_pending_video_mutation_fence(
                conn,
                source_message_key=source,
                now=now,
                _write_authority=write_authority,
                _internal_maintenance=_internal_maintenance,
            )
            conn.commit()
            return True
        active = int(
            conn.execute(
                "SELECT COUNT(*) FROM pending_video "
                "WHERE status IN ('reserved','pending','processing','recovery_required')"
            ).fetchone()[0]
        )
        if active >= _MAX_PENDING_VIDEO_ROWS:
            raise VideoCapacityError("微信异步视频待办容量已耗尽")
        per_user_active = int(
            conn.execute(
                "SELECT COUNT(*) FROM pending_video WHERE to_user_id=? "
                "AND status IN ('reserved','pending','processing','recovery_required')",
                (recipient,),
            ).fetchone()[0]
        )
        if per_user_active >= _MAX_PENDING_VIDEO_PER_USER:
            raise VideoCapacityError("微信异步视频单用户待办容量已耗尽")
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        chat_seq = chat_group[0] if chat_group is not None else _allocate_chat_seq(conn)
        conn.execute(
            """
            INSERT INTO pending_video(
                task_id,to_user_id,context_token,source_message_key,
                created_at,deadline_at,next_attempt_at,status,chat_seq
            ) VALUES(?,?,?,?,?,?,?,'pending',?)
            """,
            (
                task,
                recipient,
                context,
                source,
                current,
                current + _VIDEO_TASK_TIMEOUT_SECONDS,
                current,
                chat_seq,
            ),
        )
        _require_pending_video_mutation_fence(
            conn,
            source_message_key=source,
            now=now,
            _write_authority=write_authority,
            _internal_maintenance=_internal_maintenance,
        )
        _end_outbox_immediate_write(conn, write_authority)
        write_authority = None
        conn.commit()
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        if write_authority is not None:
            _end_outbox_immediate_write(conn, write_authority)
        conn.close()


def _recover_pending_video_claims(
    *, force: bool = False, now: float | None = None
) -> int:
    """Recover only video work that provably stayed before a remote mutation."""

    current = time.time() if now is None else float(now)
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        abandoned = "status='processing'" if force else (
            "status='processing' AND claim_deadline<=?"
        )
        abandoned_args: tuple[float, ...] = () if force else (current,)
        confirmed = conn.execute(
            f"""
            UPDATE pending_video
            SET status='done',claimed_at=0,claim_deadline=0,heartbeat_at=0,
                finished_at=?,last_error='',last_finish_token=claim_token,
                last_finish_epoch=claim_epoch,last_finish_outcome='done',
                claim_token='',terminal_verification='ilink_sendmessage_response_sha256'
            WHERE {abandoned} AND submission_phase='send_confirmed'
              AND length(platform_response_sha256)=64
              AND platform_response_sha256 NOT GLOB '*[^0-9a-f]*'
            """,
            (current, *abandoned_args),
        ).rowcount
        ambiguous = conn.execute(
            f"""
            UPDATE pending_video
            SET status='recovery_required',claimed_at=0,claim_deadline=0,
                heartbeat_at=0,last_error='video_submission_outcome_unknown',
                last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                last_finish_outcome='recovery_required',claim_token=''
            WHERE (
                status='pending' AND (direct_attempted=1 OR submission_phase<>'')
            ) OR (
                {abandoned} AND (direct_attempted=1 OR submission_phase<>'')
                AND NOT (
                    submission_phase='send_confirmed'
                    AND length(platform_response_sha256)=64
                    AND platform_response_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            )
            """,
            abandoned_args,
        ).rowcount
        recovered = conn.execute(
            f"""
            UPDATE pending_video
            SET status='pending',claim_token='',claimed_at=0,
                claim_deadline=0,heartbeat_at=0
            WHERE {abandoned} AND direct_attempted=0 AND submission_phase=''
            """,
            abandoned_args,
        ).rowcount
        conn.commit()
        return sum(max(0, int(value)) for value in (confirmed, ambiguous, recovered))
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _claim_pending_video(*, now: float | None = None) -> dict[str, object] | None:
    current = time.time() if now is None else float(now)
    _recover_pending_video_claims(now=current)
    claim_token = secrets.token_hex(16)
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT candidate.task_id,candidate.to_user_id,candidate.context_token,
                   candidate.source_message_key,candidate.created_at,
                   candidate.deadline_at,candidate.next_attempt_at,
                   candidate.attempts,candidate.result_url,
                   candidate.direct_attempted,candidate.claim_epoch
            FROM pending_video AS candidate
            WHERE candidate.status='pending' AND candidate.next_attempt_at<=?
              AND candidate.direct_attempted=0
              AND candidate.submission_phase=''
              AND NOT EXISTS (
                SELECT 1 FROM inbound_message AS earlier_inbound
                WHERE earlier_inbound.from_user_id=candidate.to_user_id
                  AND earlier_inbound.chat_seq<candidate.chat_seq
                  AND earlier_inbound.status IN
                      ('pending','processing','recovery_required')
              )
              AND NOT EXISTS (
                SELECT 1 FROM pending_delivery AS earlier_delivery
                WHERE earlier_delivery.to_user_id=candidate.to_user_id
                  AND earlier_delivery.chat_seq<candidate.chat_seq
                  AND earlier_delivery.status IN
                      ('pending','processing','submitting','recovery_required')
              )
              AND NOT EXISTS (
                SELECT 1 FROM pending_video AS earlier_video
                WHERE earlier_video.to_user_id=candidate.to_user_id
                  AND earlier_video.chat_seq<candidate.chat_seq
                  AND earlier_video.status IN
                      ('reserved','pending','processing','recovery_required')
              )
            ORDER BY candidate.chat_seq,candidate.next_attempt_at,
                     candidate.created_at,candidate.task_id
            LIMIT 1
            """,
            (current,),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        changed = conn.execute(
            "UPDATE pending_video SET status='processing',claim_token=?,claimed_at=?,"
            "claim_deadline=?,heartbeat_at=?,claim_epoch=claim_epoch+1 "
            "WHERE task_id=? AND status='pending' AND direct_attempted=0 "
            "AND submission_phase=''",
            (
                claim_token,
                current,
                current + _VIDEO_CLAIM_TTL_SECONDS,
                current,
                row[0],
            ),
        ).rowcount
        if changed != 1:
            conn.rollback()
            return None
        conn.commit()
        return {
            "task_id": str(row[0]),
            "to_user_id": str(row[1]),
            "context_token": str(row[2]),
            "source_message_key": str(row[3]),
            "created_at": float(row[4]),
            "deadline_at": float(row[5]),
            "next_attempt_at": float(row[6]),
            "attempts": int(row[7]),
            "result_url": str(row[8] or ""),
            "direct_attempted": bool(int(row[9] or 0)),
            "claim_token": claim_token,
            "claim_epoch": int(row[10] or 0) + 1,
        }
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _renew_pending_video_claim(
    claim: dict[str, object], *, now: float | None = None
) -> bool:
    current = time.time() if now is None else float(now)
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            """
            UPDATE pending_video
            SET claim_deadline=?,heartbeat_at=?
            WHERE task_id=? AND status='processing' AND claim_token=?
              AND claim_epoch=? AND claim_deadline>?
            """,
            (
                current + _VIDEO_CLAIM_TTL_SECONDS,
                current,
                claim["task_id"],
                claim["claim_token"],
                int(claim["claim_epoch"]),
                current,
            ),
        ).rowcount
        conn.commit()
        return changed == 1
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _pending_video_claim_is_current(
    claim: dict[str, object], *, now: float | None = None
) -> bool:
    current = time.time() if now is None else float(now)
    with closing(_outbox_connect()) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM pending_video
            WHERE task_id=? AND status='processing' AND claim_token=?
              AND claim_epoch=? AND claim_deadline>?
            """,
            (
                claim["task_id"],
                claim["claim_token"],
                int(claim["claim_epoch"]),
                current,
            ),
        ).fetchone()
    return row is not None


def _pending_video_claim_commit_fence(claim: dict[str, object]):
    session = claim.get("_lease_session")
    return session.commit_fence() if session is not None else nullcontext()


def _store_pending_video_result(
    claim: dict[str, object], url: str, *, now: float | None = None
) -> bool:
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ValueError("微信异步视频结果 URL 无效")
    current = (
        _pending_video_claim_now(claim)
        if claim.get("_lease_session") is not None
        else time.time() if now is None else float(now)
    )
    with _pending_video_claim_commit_fence(claim):
        conn = _outbox_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                "UPDATE pending_video SET result_url=?,last_error='' "
                "WHERE task_id=? AND status='processing' AND claim_token=? "
                "AND claim_epoch=? AND claim_deadline>?",
                (
                    url,
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    current,
                ),
            ).rowcount
            conn.commit()
            return changed == 1
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


def _mark_pending_video_direct_attempt(
    claim: dict[str, object], *, now: float | None = None
) -> bool:
    """Commit the ambiguity marker before crossing the remote send boundary."""

    current = (
        _pending_video_claim_now(claim)
        if claim.get("_lease_session") is not None
        else time.time() if now is None else float(now)
    )
    with _pending_video_claim_commit_fence(claim):
        conn = _outbox_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                "UPDATE pending_video SET direct_attempted=1 "
                "WHERE task_id=? AND status='processing' AND claim_token=? "
                "AND claim_epoch=? AND claim_deadline>? AND direct_attempted=0",
                (
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    current,
                ),
            ).rowcount
            conn.commit()
            if changed == 1:
                claim["direct_attempted"] = True
            return changed == 1
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


_PENDING_VIDEO_SUBMISSION_FIELDS = {
    "upload_grant_submitting": (
        "",
        "upload_grant_request_sha256",
        "upload_grant_started_at",
    ),
    "upload_submitting": (
        "upload_grant_submitting",
        "upload_request_sha256",
        "upload_started_at",
    ),
    "send_submitting": (
        "upload_submitting",
        "send_request_sha256",
        "send_started_at",
    ),
}


def _pending_video_claim_now(claim: dict[str, object]) -> float:
    clock = claim.get("_lease_clock")
    return float(clock()) if callable(clock) else time.time()


def _mark_pending_video_submission(
    claim: dict[str, object],
    phase: str,
    request_sha256: str,
    *,
    now: float | None = None,
) -> bool:
    fields = _PENDING_VIDEO_SUBMISSION_FIELDS.get(str(phase))
    if fields is None:
        raise ValueError("pending video submission phase is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(request_sha256)):
        raise ValueError("pending video submission digest is invalid")
    previous_phase, digest_column, started_column = fields
    current = _pending_video_claim_now(claim) if now is None else float(now)
    with _pending_video_claim_commit_fence(claim):
        conn = _outbox_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                f"""
                UPDATE pending_video
                SET submission_phase=?,{digest_column}=?,{started_column}=?
                WHERE task_id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>? AND direct_attempted=1
                  AND submission_phase=? AND {digest_column}=''
                """,
                (
                    phase,
                    request_sha256,
                    current,
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    current,
                    previous_phase,
                ),
            ).rowcount
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    if changed == 1:
        claim["submission_phase"] = phase
        claim[digest_column] = request_sha256
        return True
    return False


def _record_pending_video_platform_response(
    claim: dict[str, object], response_sha256: str, *, now: float | None = None
) -> bool:
    if not re.fullmatch(r"[0-9a-f]{64}", str(response_sha256)):
        raise ValueError("pending video platform response digest is invalid")
    current = _pending_video_claim_now(claim) if now is None else float(now)
    with _pending_video_claim_commit_fence(claim):
        conn = _outbox_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                """
                UPDATE pending_video
                SET submission_phase='send_confirmed',platform_response_sha256=?
                WHERE task_id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                  AND submission_phase='send_submitting'
                  AND length(send_request_sha256)=64
                """,
                (
                    response_sha256,
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    current,
                ),
            ).rowcount
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    if changed == 1:
        claim["submission_phase"] = "send_confirmed"
        claim["platform_response_sha256"] = response_sha256
        return True
    return False


def _pending_video_submission_boundary(phase: str, request_sha256: str) -> None:
    claim = getattr(_HANDLE_CONTEXT, "pending_video_claim", None)
    if claim is None:
        return
    session = claim.get("_lease_session")
    if session is None or not session.before_provider():
        raise ClaimLeaseLost("pending video provider fence lost")
    if not _mark_pending_video_submission(claim, phase, request_sha256):
        raise ClaimLeaseLost("pending video submission fence lost")


def _pending_video_platform_response(response: dict) -> None:
    claim = getattr(_HANDLE_CONTEXT, "pending_video_claim", None)
    if claim is None:
        return
    response_sha256 = _canonical_json_sha256(response)
    if not _record_pending_video_platform_response(claim, response_sha256):
        raise ClaimLeaseLost("pending video response receipt fence lost")


class _PendingVideoFinishRequest:
    __slots__ = (
        "terminal",
        "recovery_required",
        "now",
        "error_code",
        "outcome",
        "platform_response_sha256",
        "terminal_verification",
    )

    def __init__(
        self,
        *,
        terminal: bool,
        now: float,
        error: object = "",
        recovery_required: bool = False,
        platform_response_sha256: str = "",
        terminal_verification: str = "",
    ) -> None:
        current = float(now)
        if not math.isfinite(current):
            raise ValueError("pending video finish time must be finite")
        if terminal and recovery_required:
            raise ValueError("pending video finish outcome is contradictory")
        response_digest = str(platform_response_sha256)
        if response_digest and not re.fullmatch(r"[0-9a-f]{64}", response_digest):
            raise ValueError("pending video finish response digest is invalid")
        verification = str(terminal_verification)
        if len(verification) > 128:
            raise ValueError("pending video terminal verification is invalid")
        self.terminal = bool(terminal)
        self.recovery_required = bool(recovery_required)
        self.now = current
        self.error_code = _error_code(error) if error else ""
        self.outcome = (
            "done"
            if self.terminal
            else "recovery_required"
            if self.recovery_required
            else "pending"
        )
        self.platform_response_sha256 = response_digest
        self.terminal_verification = verification


def _commit_pending_video_finish(
    claim: dict[str, object],
    outcome: _PendingVideoFinishRequest,
    *,
    deadline_monotonic: float | None = None,
) -> bool:
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    try:
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.execute("BEGIN IMMEDIATE")
        if outcome.outcome == "done":
            changed = conn.execute(
                """
                UPDATE pending_video
                SET status='done',claim_token='',claimed_at=0,claim_deadline=0,
                    heartbeat_at=0,finished_at=?,last_error=?,last_finish_token=?,
                    last_finish_epoch=?,last_finish_outcome='done',
                    terminal_verification=CASE WHEN ?<>'' THEN ?
                                               ELSE terminal_verification END
                WHERE task_id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                  AND (?='' OR (
                      submission_phase='send_confirmed'
                      AND platform_response_sha256=?
                  ))
                """,
                (
                    outcome.now,
                    outcome.error_code,
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    outcome.terminal_verification,
                    outcome.terminal_verification,
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    outcome.now,
                    outcome.platform_response_sha256,
                    outcome.platform_response_sha256,
                ),
            ).rowcount
        elif outcome.outcome == "recovery_required":
            changed = conn.execute(
                """
                UPDATE pending_video
                SET status='recovery_required',claim_token='',claimed_at=0,
                    claim_deadline=0,heartbeat_at=0,last_error=?,
                    last_finish_token=?,last_finish_epoch=?,
                    last_finish_outcome='recovery_required'
                WHERE task_id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    outcome.error_code or "video_submission_outcome_unknown",
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    outcome.now,
                ),
            ).rowcount
        else:
            attempts = int(claim.get("attempts") or 0) + 1
            delay = max(
                float(_VIDEO_POLL_INTERVAL_SECONDS),
                min(60.0, float(2 ** min(attempts, 5))),
            )
            changed = conn.execute(
                """
                UPDATE pending_video
                SET status='pending',claim_token='',claimed_at=0,attempts=?,
                    claim_deadline=0,heartbeat_at=0,next_attempt_at=?,last_error=?,
                    last_finish_token=?,last_finish_epoch=?,last_finish_outcome='pending'
                WHERE task_id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                  AND direct_attempted=0 AND submission_phase=''
                """,
                (
                    attempts,
                    outcome.now + delay,
                    outcome.error_code,
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    claim["task_id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    outcome.now,
                ),
            ).rowcount
        if changed != 1:
            conn.rollback()
            return False
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.commit()
        _remaining_outbox_finish_budget(deadline_monotonic)
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _pending_video_finish_was_committed(
    claim: dict[str, object],
    outcome: _PendingVideoFinishRequest,
    *,
    deadline_monotonic: float | None = None,
) -> bool:
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    try:
        row = conn.execute(
            """
            SELECT status,last_error,last_finish_token,last_finish_epoch,
                   last_finish_outcome,platform_response_sha256,
                   terminal_verification
            FROM pending_video WHERE task_id=?
            """,
            (claim["task_id"],),
        ).fetchone()
        _remaining_outbox_finish_budget(deadline_monotonic)
    finally:
        conn.close()
    return bool(
        row is not None
        and secrets.compare_digest(str(row[0]), outcome.outcome)
        and secrets.compare_digest(str(row[1]), outcome.error_code)
        and secrets.compare_digest(str(row[2]), str(claim["claim_token"]))
        and int(row[3] or 0) == int(claim["claim_epoch"])
        and secrets.compare_digest(str(row[4]), outcome.outcome)
        and (
            not outcome.platform_response_sha256
            or secrets.compare_digest(
                str(row[5]), outcome.platform_response_sha256
            )
        )
        and (
            not outcome.terminal_verification
            or secrets.compare_digest(
                str(row[6]), outcome.terminal_verification
            )
        )
    )


class _PendingVideoClaimStorage:
    def __init__(
        self,
        claim: dict[str, object],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.claim = claim
        self.clock = clock

    def renew(self) -> bool:
        return _renew_pending_video_claim(self.claim, now=self.clock())

    def owns(self) -> bool:
        return _pending_video_claim_is_current(self.claim, now=self.clock())

    def _at_policy_time(
        self, outcome: _PendingVideoFinishRequest
    ) -> _PendingVideoFinishRequest:
        return _PendingVideoFinishRequest(
            terminal=outcome.terminal,
            now=self.clock(),
            error=outcome.error_code,
            recovery_required=outcome.recovery_required,
            platform_response_sha256=outcome.platform_response_sha256,
            terminal_verification=outcome.terminal_verification,
        )

    def finish_before(
        self,
        outcome: _PendingVideoFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        return _commit_pending_video_finish(
            self.claim,
            self._at_policy_time(outcome),
            deadline_monotonic=deadline_monotonic,
        )

    def confirm_finish_before(
        self,
        outcome: _PendingVideoFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        return _pending_video_finish_was_committed(
            self.claim,
            self._at_policy_time(outcome),
            deadline_monotonic=deadline_monotonic,
        )


class _PendingVideoClaimPolicy:
    heartbeat_interval = max(
        0.05,
        min(float(_VIDEO_HEARTBEAT_SECONDS), float(_VIDEO_CLAIM_TTL_SECONDS) / 3.0),
    )
    stop_timeout = min(float(_VIDEO_CLAIM_TTL_SECONDS) / 4.0 + 0.5, 8.0)
    finish_timeout = min(float(_VIDEO_CLAIM_TTL_SECONDS) / 4.0, 15.0)
    finish_retry_delays = tuple(
        float(value) for value in _VIDEO_FINISH_RETRY_DELAYS_SECONDS
    )

    @staticmethod
    def is_retryable(error: BaseException) -> bool:
        return isinstance(error, (sqlite3.Error, OSError)) and not isinstance(
            error, _OutboxFinishDeadlineExceeded
        )

    @staticmethod
    def fault(code: str, error: BaseException | None = None) -> None:
        rendered = f"video_claim:{code}"
        if error is not None:
            rendered = f"{rendered}:{type(error).__name__}"
        _record_inbound_claim_health_nonblocking(rendered[:500])


def _new_pending_video_lease_session(
    claim: dict[str, object], *, clock: Callable[[], float] = time.time
) -> ClaimLeaseSession[_PendingVideoFinishRequest]:
    return ClaimLeaseSession(
        storage=_PendingVideoClaimStorage(claim, clock=clock),
        policy=_PendingVideoClaimPolicy(),
        thread_name="weixin-video-heartbeat",
    )


def _finish_pending_video(
    claim: dict[str, object],
    *,
    terminal: bool,
    now: float,
    error: object = "",
    recovery_required: bool = False,
    platform_response_sha256: str = "",
    terminal_verification: str = "",
) -> bool:
    outcome = _PendingVideoFinishRequest(
        terminal=terminal,
        now=now,
        error=error,
        recovery_required=recovery_required,
        platform_response_sha256=platform_response_sha256,
        terminal_verification=terminal_verification,
    )
    session = claim.get("_lease_session")
    if session is not None:
        return bool(session.finish(outcome))
    return _commit_pending_video_finish(claim, outcome)


def _video_delivery_key(task_id: object, suffix: str) -> str:
    digest = hashlib.sha256(str(task_id).encode("utf-8", errors="replace")).hexdigest()
    return f"video-task:{digest}:{suffix}"


def _process_pending_video(
    token: str, claim: dict[str, object], *, now: float
) -> None:
    task_id = str(claim["task_id"])
    recipient = str(claim["to_user_id"])
    context = str(claim["context_token"])
    result_url = str(claim.get("result_url") or "")
    if not result_url and now >= float(claim["deadline_at"]):
        _deliver_text(
            token,
            recipient,
            context,
            "🎬 视频生成太慢，已超过 25 分钟；上游可能繁忙，请稍后重试。",
            delivery_key=_video_delivery_key(task_id, "timeout"),
        )
        _finish_pending_video(claim, terminal=True, now=now, error="video_timeout")
        return

    if not result_url:
        encoded_task = urllib.parse.quote(task_id, safe="")
        session = claim.get("_lease_session")
        if session is not None and not session.before_provider():
            raise ClaimLeaseLost("pending video poll fence lost")
        status_document = _engine_get_json(
            f"/v1/videos/{encoded_task}?model=agnes-video",
            timeout=30.0,
        )
        if session is not None and not session.before_provider():
            raise ClaimLeaseLost("pending video poll response fence lost")
        from orchestrator.media import _find_media_url

        result_url = _find_media_url(status_document)
        if result_url:
            if not _store_pending_video_result(claim, result_url, now=now):
                return
            claim["result_url"] = result_url
        else:
            nested = status_document.get("data")
            nested_status = nested.get("status") if isinstance(nested, dict) else ""
            status = str(status_document.get("status") or nested_status or "").lower()
            if any(marker in status for marker in ("fail", "error", "cancel")):
                _deliver_text(
                    token,
                    recipient,
                    context,
                    "🎬 这个视频生成失败了，请换个描述再试一次。",
                    delivery_key=_video_delivery_key(task_id, "failed"),
                )
                _finish_pending_video(
                    claim, terminal=True, now=now, error="video_failed"
                )
            else:
                _finish_pending_video(claim, terminal=False, now=now)
            return

    client_id = "nachuan_video_task_" + hashlib.sha256(
        task_id.encode("utf-8", errors="replace")
    ).hexdigest()[:32]
    if bool(claim.get("direct_attempted")):
        # Crossing any upload/send boundary without an exact platform receipt
        # requires explicit adjudication; an automatic fallback is another
        # customer-visible side effect and must not disguise the uncertainty.
        _finish_pending_video(
            claim,
            terminal=False,
            now=now,
            error="video_submission_outcome_unknown",
            recovery_required=True,
        )
        return
    try:
        session = claim.get("_lease_session")
        if session is not None and not session.before_provider():
            raise ClaimLeaseLost("pending video fetch fence lost")
        media = _fetch_media(result_url, "video")
        if session is not None and not session.before_provider():
            raise ClaimLeaseLost("pending video fetch response fence lost")
    except Exception as exc:  # noqa: BLE001 - a safe public link remains deliverable
        _deliver_text(
            token,
            recipient,
            context,
            f"🎬 视频已经生成，但微信直发失败，链接：{result_url}",
            delivery_key=_video_delivery_key(task_id, "fallback"),
        )
        _finish_pending_video(
            claim,
            terminal=True,
            now=now,
            error=f"direct_delivery_{type(exc).__name__}",
        )
        return
    if not _mark_pending_video_direct_attempt(claim, now=now):
        return
    claim["direct_attempted"] = True
    try:
        sent = _send_media(
            token,
            recipient,
            context,
            media,
            "video",
            client_id=client_id,
        )
        if not sent:
            raise RuntimeError("微信视频直发未确认成功")
    except Exception as exc:  # noqa: BLE001 - durable text fallback is the terminal delivery
        _finish_pending_video(
            claim,
            terminal=False,
            now=now,
            error="video_submission_outcome_unknown",
            recovery_required=True,
        )
        return
    _finish_pending_video(
        claim,
        terminal=True,
        now=now,
        platform_response_sha256=str(
            claim.get("platform_response_sha256") or ""
        ),
        terminal_verification=(
            "ilink_sendmessage_response_sha256"
            if claim.get("platform_response_sha256")
            else "sender_returned_true"
        ),
    )


def _drain_pending_videos(
    token: str, *, limit: int = 4, now: float | None = None
) -> int:
    fixed_clock = now is not None
    current = time.time() if now is None else float(now)
    processed = 0
    for _index in range(max(1, min(int(limit), _VIDEO_MAX_WORKERS))):
        claim = _claim_pending_video(now=current)
        if claim is None:
            break
        lease_clock = (lambda: current) if fixed_clock else time.time
        session = _new_pending_video_lease_session(claim, clock=lease_clock)
        if not session.start():
            session.close()
            processed += 1
            continue
        claim["_lease_session"] = session
        claim["_lease_clock"] = lease_clock
        previous_session = getattr(_HANDLE_CONTEXT, "lease_session", None)
        previous_video_claim = getattr(
            _HANDLE_CONTEXT, "pending_video_claim", None
        )
        _HANDLE_CONTEXT.lease_session = session
        _HANDLE_CONTEXT.pending_video_claim = claim
        try:
            _process_pending_video(token, claim, now=current)
        except Exception as exc:  # noqa: BLE001 - leave a bounded durable retry
            uncertain = bool(
                claim.get("direct_attempted") or claim.get("submission_phase")
            )
            _finish_pending_video(
                claim,
                terminal=False,
                now=current,
                error=(
                    "video_submission_outcome_unknown" if uncertain else exc
                ),
                recovery_required=uncertain,
            )
            with _HEALTH_LOCK:
                _HEALTH_STATE["service_state"] = "degraded"
                _HEALTH_STATE["last_error_code"] = "video_worker_error"
        finally:
            if previous_session is None:
                try:
                    delattr(_HANDLE_CONTEXT, "lease_session")
                except AttributeError:
                    pass
            else:
                _HANDLE_CONTEXT.lease_session = previous_session
            if previous_video_claim is None:
                try:
                    delattr(_HANDLE_CONTEXT, "pending_video_claim")
                except AttributeError:
                    pass
            else:
                _HANDLE_CONTEXT.pending_video_claim = previous_video_claim
            claim.pop("_lease_session", None)
            claim.pop("_lease_clock", None)
            session.close()
        processed += 1
    return processed


def _video_queue_worker(
    token_ref: dict[str, str], stop_event: threading.Event
) -> None:
    while not stop_event.is_set():
        token = str(token_ref.get("value") or "")
        try:
            processed = _drain_pending_videos(token, limit=1) if token else 0
        except Exception:  # noqa: BLE001 - one transient DB/poll error must not kill the worker
            with _HEALTH_LOCK:
                _HEALTH_STATE["service_state"] = "degraded"
                _HEALTH_STATE["last_error_code"] = "video_worker_error"
            processed = 0
        if not processed:
            stop_event.wait(0.5)


def _start_video_workers(
    token_ref: dict[str, str],
    stop_event: threading.Event,
    *,
    worker_count: int | None = None,
) -> list[threading.Thread]:
    if worker_count is None:
        try:
            worker_count = int(os.environ.get("WEIXIN_VIDEO_WORKERS", "4"))
        except ValueError:
            worker_count = 4
    bounded_count = max(1, min(int(worker_count), _VIDEO_MAX_WORKERS))
    workers: list[threading.Thread] = []
    for index in range(bounded_count):
        worker = threading.Thread(
            target=_video_queue_worker,
            args=(token_ref, stop_event),
            name=f"weixin-video-{index + 1}",
            daemon=True,
        )
        worker.start()
        workers.append(worker)
    return workers


_DEAD_INBOUND_TOMBSTONE = '{"state":"dead_tombstone","version":1}'
_UNAUTHORIZED_INBOUND_TOMBSTONE = (
    '{"state":"unauthorized_tombstone","version":1}'
)
_OVERSIZE_INBOUND_TOMBSTONE = '{"state":"oversize_tombstone","version":1}'
_INVALID_INBOUND_TOMBSTONE = '{"state":"invalid_tombstone","version":1}'
_RETRYING_FAILURE_NOTICE = (
    "⚠️ 本次处理遇到临时问题，纳川正在自动重试；稍后会给出最终结果。"
)
_TERMINAL_FAILURE_NOTICE = (
    "⚠️ 这条消息暂时处理失败，纳川已停止自动重试，请稍后重新发送。"
)


def _opaque_identity(value: object) -> str:
    raw = str(value or "").encode("utf-8", errors="replace")
    return "sha256:" + hashlib.sha256(b"nachuan-weixin-dead-v1\0" + raw).hexdigest()


def _error_code(value: object) -> str:
    prefix = str(value or "error").split(":", 1)[0]
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", prefix)[:64]
    return safe or "error"


def _terminal_maintenance(
    *,
    now: float | None = None,
    completed_retention_seconds: float = _COMPLETED_RETENTION_SECONDS,
    dead_retention_seconds: float = _DEAD_RETENTION_SECONDS,
    dead_max_rows: int = _DEAD_MAX_ROWS,
    inbound_batch: int = 256,
    group_batch: int = 16,
    group_row_batch: int = 2048,
) -> dict[str, int]:
    """Tombstone dead data and prune old terminal rows in bounded batches.

    Live ``pending``/``processing``/``recovery_required`` rows are never selected.  Successful
    outbound chunks are deleted only when the complete ``delivery_id`` group is
    done, so cleanup cannot destroy the evidence needed to suppress a replay.
    """

    current = time.time() if now is None else float(now)
    completed_cutoff = current - max(
        float(completed_retention_seconds), _DELIVERY_CLAIM_TTL_SECONDS * 2
    )
    dead_cutoff = current - max(
        float(dead_retention_seconds), float(completed_retention_seconds)
    )
    inbound_limit = max(1, min(int(inbound_batch), 2048))
    group_limit = max(1, min(int(group_batch), 64))
    row_limit = max(1, min(int(group_row_batch), 8192))
    max_dead = max(1, min(int(dead_max_rows), 1_000_000))
    result = {
        "inbound_tombstoned": 0,
        "outbound_tombstoned": 0,
        "done_inbound_deleted": 0,
        "done_outbound_deleted": 0,
        "done_video_deleted": 0,
        "reserved_video_deleted": 0,
        "dead_inbound_deleted": 0,
        "dead_outbound_deleted": 0,
    }
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        inbound_dead = conn.execute(
            "SELECT id,from_user_id,last_error FROM inbound_message "
            "WHERE status='dead' AND payload<>? ORDER BY id LIMIT ?",
            (_DEAD_INBOUND_TOMBSTONE, inbound_limit),
        ).fetchall()
        for row_id, from_user_id, last_error in inbound_dead:
            result["inbound_tombstoned"] += conn.execute(
                "UPDATE inbound_message SET from_user_id=?,payload=?,last_error=? "
                "WHERE id=? AND status='dead'",
                (
                    _opaque_identity(from_user_id),
                    _DEAD_INBOUND_TOMBSTONE,
                    _error_code(last_error),
                    row_id,
                ),
            ).rowcount

        outbound_dead = conn.execute(
            "SELECT id,to_user_id,last_error FROM pending_delivery "
            "WHERE status='dead' AND (context_token<>'' OR text<>'') "
            "ORDER BY id LIMIT ?",
            (min(row_limit, 512),),
        ).fetchall()
        for row_id, to_user_id, last_error in outbound_dead:
            result["outbound_tombstoned"] += conn.execute(
                "UPDATE pending_delivery SET to_user_id=?,context_token='',text='',"
                "last_error=? WHERE id=? AND status='dead'",
                (
                    _opaque_identity(to_user_id),
                    _error_code(last_error),
                    row_id,
                ),
            ).rowcount

        old_done_inbound = conn.execute(
            "SELECT id FROM inbound_message WHERE status='done' AND received_at<? "
            "ORDER BY id LIMIT ?",
            (completed_cutoff, inbound_limit),
        ).fetchall()
        if old_done_inbound:
            placeholders = ",".join("?" for _ in old_done_inbound)
            result["done_inbound_deleted"] = conn.execute(
                f"DELETE FROM inbound_message WHERE status='done' AND id IN ({placeholders})",
                tuple(int(row[0]) for row in old_done_inbound),
            ).rowcount

        done_groups = conn.execute(
            "SELECT delivery_id,COUNT(*) FROM pending_delivery "
            "WHERE delivery_id<>'' GROUP BY delivery_id "
            "HAVING SUM(CASE WHEN status='done' THEN 0 ELSE 1 END)=0 "
            "AND MAX(CASE WHEN delivered_at>0 THEN delivered_at ELSE created_at END)<? "
            "AND COUNT(*)<=? ORDER BY MIN(id) LIMIT ?",
            (completed_cutoff, row_limit, group_limit),
        ).fetchall()
        selected_done_groups: list[str] = []
        selected_done_rows = 0
        for delivery_id, row_count in done_groups:
            count = int(row_count)
            if selected_done_rows + count > row_limit:
                break
            selected_done_groups.append(str(delivery_id))
            selected_done_rows += count
        if selected_done_groups:
            placeholders = ",".join("?" for _ in selected_done_groups)
            result["done_outbound_deleted"] = conn.execute(
                f"DELETE FROM pending_delivery WHERE status='done' "
                f"AND delivery_id IN ({placeholders})",
                tuple(selected_done_groups),
            ).rowcount

        old_done_video = conn.execute(
            "SELECT task_id FROM pending_video WHERE status='done' "
            "AND COALESCE(NULLIF(finished_at,0),created_at)<? "
            "ORDER BY COALESCE(NULLIF(finished_at,0),created_at),task_id LIMIT ?",
            (completed_cutoff, inbound_limit),
        ).fetchall()
        if old_done_video:
            placeholders = ",".join("?" for _ in old_done_video)
            result["done_video_deleted"] = conn.execute(
                f"DELETE FROM pending_video WHERE status='done' "
                f"AND task_id IN ({placeholders})",
                tuple(str(row[0]) for row in old_done_video),
            ).rowcount

        abandoned_reservations = conn.execute(
            """
            SELECT video.task_id
            FROM pending_video AS video
            WHERE video.status='reserved'
              AND (
                EXISTS (
                  SELECT 1 FROM inbound_message AS inbound
                  WHERE inbound.message_key=video.source_message_key
                    AND inbound.status IN ('done','dead')
                )
                OR (
                  video.created_at<? AND NOT EXISTS (
                    SELECT 1 FROM inbound_message AS inbound
                    WHERE inbound.message_key=video.source_message_key
                      AND inbound.status IN ('pending','processing','recovery_required')
                  )
                )
              )
            ORDER BY video.created_at,video.task_id
            LIMIT ?
            """,
            (current - _VIDEO_RESERVATION_TTL_SECONDS, inbound_limit),
        ).fetchall()
        if abandoned_reservations:
            placeholders = ",".join("?" for _ in abandoned_reservations)
            result["reserved_video_deleted"] = conn.execute(
                f"DELETE FROM pending_video WHERE status='reserved' "
                f"AND task_id IN ({placeholders})",
                tuple(str(row[0]) for row in abandoned_reservations),
            ).rowcount

        dead_inbound_count_row = conn.execute(
            "SELECT COUNT(*) FROM inbound_message WHERE status='dead'"
        ).fetchone()
        dead_inbound_excess = max(
            0, int(dead_inbound_count_row[0] if dead_inbound_count_row else 0) - max_dead
        )
        dead_inbound_ids = conn.execute(
            "SELECT id FROM inbound_message WHERE status='dead' "
            "AND payload=? AND received_at<? ORDER BY id LIMIT ?",
            (_DEAD_INBOUND_TOMBSTONE, dead_cutoff, inbound_limit),
        ).fetchall()
        # TTL removal also reduces any count excess.  Add only the still-needed
        # number of recent tombstones; never let ``excess > 0`` turn the filter
        # into an all-rows deletion.
        remaining_excess = max(0, dead_inbound_excess - len(dead_inbound_ids))
        remaining_batch = max(0, inbound_limit - len(dead_inbound_ids))
        if remaining_excess and remaining_batch:
            selected_ids = [int(row[0]) for row in dead_inbound_ids]
            exclusion = ""
            parameters: list[object] = [_DEAD_INBOUND_TOMBSTONE]
            if selected_ids:
                exclusion = " AND id NOT IN (" + ",".join("?" for _ in selected_ids) + ")"
                parameters.extend(selected_ids)
            parameters.append(min(remaining_excess, remaining_batch))
            dead_inbound_ids.extend(
                conn.execute(
                    "SELECT id FROM inbound_message WHERE status='dead' AND payload=?"
                    + exclusion
                    + " ORDER BY id LIMIT ?",
                    tuple(parameters),
                ).fetchall()
            )
        if dead_inbound_ids:
            placeholders = ",".join("?" for _ in dead_inbound_ids)
            result["dead_inbound_deleted"] = conn.execute(
                f"DELETE FROM inbound_message WHERE status='dead' AND payload=? "
                f"AND id IN ({placeholders})",
                (_DEAD_INBOUND_TOMBSTONE, *(int(row[0]) for row in dead_inbound_ids)),
            ).rowcount

        dead_outbound_count_row = conn.execute(
            "SELECT COUNT(*) FROM pending_delivery WHERE status='dead'"
        ).fetchone()
        dead_outbound_excess = max(
            0,
            int(dead_outbound_count_row[0] if dead_outbound_count_row else 0) - max_dead,
        )
        dead_groups = conn.execute(
            "SELECT delivery_id,COUNT(*),"
            "SUM(CASE WHEN status='dead' THEN 1 ELSE 0 END) AS dead_count "
            "FROM pending_delivery WHERE delivery_id<>'' GROUP BY delivery_id "
            "HAVING dead_count>0 "
            "AND SUM(CASE WHEN status IN ('pending','processing','recovery_required') "
            "THEN 1 ELSE 0 END)=0 "
            "AND COUNT(*)<=? AND (MAX(created_at)<? OR ? > 0) "
            "ORDER BY MIN(id) LIMIT ?",
            (row_limit, dead_cutoff, dead_outbound_excess, group_limit),
        ).fetchall()
        selected_dead_groups: list[str] = []
        selected_dead_rows = 0
        removed_dead_rows = 0
        for delivery_id, row_count, dead_count in dead_groups:
            count = int(row_count)
            if selected_dead_rows + count > row_limit:
                break
            if dead_outbound_excess > 0 and removed_dead_rows >= dead_outbound_excess:
                break
            selected_dead_groups.append(str(delivery_id))
            selected_dead_rows += count
            removed_dead_rows += int(dead_count)
        if selected_dead_groups:
            placeholders = ",".join("?" for _ in selected_dead_groups)
            result["dead_outbound_deleted"] = conn.execute(
                f"DELETE FROM pending_delivery WHERE delivery_id IN ({placeholders}) "
                "AND status IN ('done','dead')",
                tuple(selected_dead_groups),
            ).rowcount

        conn.commit()
        return result
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _maybe_terminal_maintenance(*, force: bool = False) -> dict[str, int] | None:
    global _LAST_TERMINAL_PRUNE_AT
    current = time.time()
    with _TERMINAL_PRUNE_LOCK:
        if (
            not force
            and current - _LAST_TERMINAL_PRUNE_AT < _TERMINAL_PRUNE_INTERVAL_SECONDS
        ):
            return None
        result = _terminal_maintenance(now=current)
        _LAST_TERMINAL_PRUNE_AT = current
        return result


def _health_error_code(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw.split(":", 1)[0])[:64]
    if not candidate or re.search(
        r"(?i)(?:secret|access.?key|ticket|token|password|authorization|bearer)",
        candidate,
    ):
        return "health_error"
    return candidate


def _strict_health_count(value: object, *, invalid: int = 0) -> int:
    if type(value) is not int or value < 0:  # bool is deliberately not an integer here
        return max(0, int(invalid))
    return min(value, 1_000_000_000)


def _strict_health_time(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    rendered = float(value)
    return rendered if math.isfinite(rendered) and rendered >= 0 else 0.0


def _inbound_worker_counts() -> tuple[int, int]:
    with _INBOUND_WORKER_LOCK:
        configured = max(0, int(_INBOUND_WORKERS_CONFIGURED))
        workers = tuple(_INBOUND_WORKERS)
    alive = 0
    for worker in workers:
        try:
            alive += int(bool(worker.is_alive()))
        except Exception:  # noqa: BLE001 - health must survive a broken thread handle
            continue
    return configured, min(alive, configured)


def _write_health_snapshot(snapshot: dict[str, object]) -> None:
    """fsync one bounded ordinary file and atomically replace the prior snapshot."""

    encoded = json.dumps(
        snapshot,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if not encoded or len(encoded) > _STATE_FILE_MAX_BYTES:
        raise ValueError("微信健康快照超过 64KiB 上限")
    _HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = _HEALTH_FILE.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            _HEALTH_FILE.is_symlink()
            or not _is_regular_nonreparse(existing)
            or existing.st_size > _STATE_FILE_MAX_BYTES
        ):
            raise ValueError("微信健康快照目标不是有界普通文件")
    temporary = _HEALTH_FILE.with_name(
        f".{_HEALTH_FILE.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temp_info = temporary.lstat()
        if (
            temporary.is_symlink()
            or not _is_regular_nonreparse(temp_info)
            or temp_info.st_size != len(encoded)
        ):
            raise ValueError("微信健康临时文件校验失败")
        os.replace(temporary, _HEALTH_FILE)
        final_info = _HEALTH_FILE.lstat()
        if (
            _HEALTH_FILE.is_symlink()
            or not _is_regular_nonreparse(final_info)
            or final_info.st_size != len(encoded)
        ):
            raise ValueError("微信健康快照落盘校验失败")
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _update_health(state: str, **fields) -> dict[str, object]:
    """Publish an exact, typed, expiring readiness contract with no old fields."""

    current_time = time.time()
    with _HEALTH_LOCK:
        requested_state = str(state or "degraded").strip().lower()
        if requested_state not in {"starting", "healthy", "degraded", "stopping"}:
            requested_state = "degraded"
        _HEALTH_STATE["service_state"] = requested_state
        _HEALTH_STATE["connected"] = requested_state == "healthy"
        if "consecutive_poll_failures" in fields:
            _HEALTH_STATE["consecutive_poll_failures"] = _strict_health_count(
                fields["consecutive_poll_failures"], invalid=1
            )
        for name in ("last_poll_ok_at", "last_message_finished_at"):
            if name in fields:
                _HEALTH_STATE[name] = _strict_health_time(fields[name])
        if "last_error" in fields:
            _HEALTH_STATE["last_error_code"] = _health_error_code(fields["last_error"])
        if "last_handler_ok" in fields:
            handler_ok = fields["last_handler_ok"]
            _HEALTH_STATE["last_handler_ok"] = (
                handler_ok if isinstance(handler_ok, bool) else False
            )
            if _HEALTH_STATE["last_handler_ok"]:
                _HEALTH_STATE["last_handler_error_code"] = ""
            elif "last_error" in fields:
                _HEALTH_STATE["last_handler_error_code"] = _health_error_code(
                    fields["last_error"]
                )

        (
            pending_inbound,
            pending_outbound,
            pending_video,
            dead_inbound,
            dead_outbound,
            recovery_required_inbound,
            recovery_required_outbound,
            recovery_required_video,
            oldest_processing_age_seconds,
        ) = _queue_health_counts(now=current_time)
        counts = {
            "pending_inbound": _strict_health_count(pending_inbound),
            "pending_outbound": _strict_health_count(pending_outbound),
            "pending_video": _strict_health_count(pending_video),
            "dead_inbound": _strict_health_count(dead_inbound),
            "dead_outbound": _strict_health_count(dead_outbound),
        }
        workers_configured, workers_alive = _inbound_worker_counts()
        poll_failures = _strict_health_count(
            _HEALTH_STATE["consecutive_poll_failures"], invalid=1
        )
        access, _owner, access_error = _refresh_access()
        with _ENGINE_HEALTH_LOCK:
            engine_available = bool(_ENGINE_AVAILABLE)
            engine_readiness_reason = str(_ENGINE_READINESS_REASON or "")
        if engine_available:
            engine_readiness_reason = "ready"
        elif engine_readiness_reason not in {
            "ready_no_model",
            "requested_model_unavailable",
            "engine_unavailable",
        }:
            engine_readiness_reason = "engine_unavailable"
        key_configured = bool(str(ENGINE_KEY or "").strip())
        connected = bool(_HEALTH_STATE["connected"])
        reasons: list[str] = []
        if not connected:
            reasons.append("disconnected")
        for name, count in counts.items():
            if count:
                reasons.append(name)
        for name, count in (
            ("recovery_required_inbound", recovery_required_inbound),
            ("recovery_required_outbound", recovery_required_outbound),
            ("recovery_required_video", recovery_required_video),
        ):
            if count:
                reasons.append(name)
        if poll_failures:
            reasons.append("poll_failures")
        if not bool(_HEALTH_STATE["last_handler_ok"]):
            reasons.append("handler_failure")
        if workers_configured < 1 or workers_alive != workers_configured:
            reasons.append("inbound_workers_missing")
        if access_error:
            reasons.append(access_error)
        if not access.configured:
            reasons.append("access_locked")
        if not key_configured:
            reasons.append("bridge_key_missing")
        if not engine_available:
            reasons.append(engine_readiness_reason)
        if requested_state == "stopping":
            reasons.append("stopping")
        elif requested_state not in {"healthy", "stopping"}:
            reasons.append(f"state:{requested_state}")
        reasons = list(dict.fromkeys(reasons))
        ready = requested_state == "healthy" and not reasons
        if ready:
            reported_state = "healthy"
        elif requested_state == "stopping":
            reported_state = "stopping"
        elif requested_state == "starting":
            reported_state = "starting"
        else:
            reported_state = "degraded"
        snapshot: dict[str, object] = {
            "schema": "nachuan.weixin-bridge-health.v1",
            "state": reported_state,
            "ready": bool(ready),
            "connected": connected,
            "fresh": True,
            "pid": _strict_health_count(os.getpid()),
            "updated_at": current_time,
            "heartbeat_at": current_time,
            "fresh_until": current_time + _HEALTH_FRESHNESS_TTL_SECONDS,
            "freshness_ttl_seconds": _HEALTH_FRESHNESS_TTL_SECONDS,
            **counts,
            "oldest_processing_age_seconds": _strict_health_time(
                oldest_processing_age_seconds
            ),
            "consecutive_poll_failures": poll_failures,
            "last_poll_ok_at": _strict_health_time(_HEALTH_STATE["last_poll_ok_at"]),
            "last_message_finished_at": _strict_health_time(
                _HEALTH_STATE["last_message_finished_at"]
            ),
            "last_error_code": str(_HEALTH_STATE["last_error_code"]),
            "last_handler_ok": bool(_HEALTH_STATE["last_handler_ok"]),
            "last_handler_error_code": str(
                _HEALTH_STATE["last_handler_error_code"]
            ),
            "workers_configured": _strict_health_count(workers_configured),
            "workers_alive": _strict_health_count(workers_alive),
            "access_configured": bool(access.configured),
            "bridge_key_configured": key_configured,
            "engine_available": engine_available,
            "engine_readiness_reason": engine_readiness_reason,
            "readiness_reasons": reasons,
        }
        _write_health_snapshot(snapshot)
        return snapshot


def _bounded_message_payload(message: dict) -> tuple[str | None, str]:
    """Serialize once without ever accumulating more than the durable payload cap."""

    digest = hashlib.sha256(b"payload\0")
    pieces: list[str] | None = []
    total = 0
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    for piece in encoder.iterencode(message):
        encoded = piece.encode("utf-8")
        digest.update(encoded)
        total += len(encoded)
        if pieces is not None:
            if total <= _MAX_INBOUND_PAYLOAD_BYTES:
                pieces.append(piece)
            else:
                pieces = None
    return ("".join(pieces) if pieces is not None else None), digest.hexdigest()


def _inbound_validation_error(message: dict) -> str:
    """Return a bounded dead-letter code for protocol drift or malformed input."""

    sender = message.get("from_user_id")
    if (
        not isinstance(sender, str)
        or not sender
        or len(sender) > 512
        or any(ord(char) < 32 or ord(char) == 127 for char in sender)
    ):
        return "invalid_sender"
    context_token = message.get("context_token", "")
    if not isinstance(context_token, str) or len(context_token) > _VIDEO_CONTEXT_MAX_CHARS:
        return "invalid_context_token"
    items = message.get("item_list")
    if not isinstance(items, list) or not items or len(items) > 1000:
        return "unsupported_items"
    for item in items:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type == 1:
            text_item = item.get("text_item")
            if isinstance(text_item, dict) and isinstance(text_item.get("text"), str):
                return ""
        elif item_type == 2 and isinstance(item.get("image_item"), dict):
            return ""
        elif item_type == 3:
            return ""
    return "unsupported_items"


def _legacy_message_key(message: dict, *, payload_digest: str | None = None) -> str:
    for field in ("message_id", "msg_id", "client_id"):
        if message.get(field):
            canonical = f"{field}\0{message[field]}".encode("utf-8")
            return "wxmsg-v1:" + hashlib.sha256(canonical).hexdigest()
    if payload_digest:
        return "wxmsg-v1:" + payload_digest
    canonical = json.dumps(
        message, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "wxmsg-v1:" + hashlib.sha256(b"payload\0" + canonical).hexdigest()


def _message_key(message: dict, *, payload_digest: str | None = None) -> str:
    """Bind an upstream event id to its immutable original sender principal."""

    sender = str(message.get("from_user_id") or "")
    for field in ("message_id", "msg_id", "client_id"):
        if message.get(field):
            canonical = f"sender\0{sender}\0{field}\0{message[field]}".encode("utf-8")
            return "wxmsg-v1:" + hashlib.sha256(canonical).hexdigest()
    if payload_digest:
        canonical = f"sender\0{sender}\0payload\0{payload_digest}".encode("utf-8")
        return "wxmsg-v1:" + hashlib.sha256(canonical).hexdigest()
    canonical = json.dumps(
        message, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "wxmsg-v1:" + hashlib.sha256(
        b"sender\0" + sender.encode("utf-8") + b"\0payload\0" + canonical
    ).hexdigest()


def _reserve_inbound_rows(conn: sqlite3.Connection, incoming: int) -> bool:
    """Prune only successful terminal rows, then fail closed before row overflow."""

    limit = max(1, min(int(_MAX_INBOUND_ROWS), 1_000_000))
    row = conn.execute("SELECT COUNT(*) FROM inbound_message").fetchone()
    current = max(0, int(row[0] if row else 0))
    excess = max(0, current + max(0, incoming) - limit)
    if excess:
        ids = conn.execute(
            "SELECT id FROM inbound_message WHERE status='done' ORDER BY id LIMIT ?",
            (min(excess, 2048),),
        ).fetchall()
        if ids:
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                f"DELETE FROM inbound_message WHERE status='done' AND id IN ({placeholders})",
                tuple(int(item[0]) for item in ids),
            )
            current -= len(ids)
    return current + max(0, incoming) <= limit


def _new_inbound_key_count(conn: sqlite3.Connection, keys: list[str]) -> int:
    unique = list(dict.fromkeys(keys))
    existing: set[str] = set()
    for start in range(0, len(unique), 400):
        batch = unique[start : start + 400]
        if not batch:
            continue
        placeholders = ",".join("?" for _ in batch)
        existing.update(
            str(row[0])
            for row in conn.execute(
                f"SELECT message_key FROM inbound_message "
                f"WHERE message_key IN ({placeholders})",
                tuple(batch),
            )
        )
    return len(unique) - len(existing)


def _store_updates(messages: list[dict], cursor: str) -> bool:
    """Commit received messages and their cursor in one durable transaction."""
    if len(messages) > _MAX_UPDATES_PER_POLL or any(
        not isinstance(message, dict) for message in messages
    ):
        return False
    now = time.time()
    prepared: list[tuple[str, str, str, str, str, str, str]] = []
    for message in messages:
        payload, payload_digest = _bounded_message_payload(message)
        message_key = _message_key(message, payload_digest=payload_digest)
        legacy_key = _legacy_message_key(message, payload_digest=payload_digest)
        from_user_id = str(message.get("from_user_id") or "")
        validation_error = _inbound_validation_error(message)
        if payload is None:
            prepared.append(
                (
                    message_key,
                    legacy_key,
                    payload_digest,
                    _opaque_identity(from_user_id),
                    _OVERSIZE_INBOUND_TOMBSTONE,
                    "dead",
                    "payload_too_large",
                )
            )
        elif validation_error:
            prepared.append(
                (
                    message_key,
                    legacy_key,
                    payload_digest,
                    _opaque_identity(from_user_id),
                    _INVALID_INBOUND_TOMBSTONE,
                    "dead",
                    validation_error,
                )
            )
        else:
            prepared.append(
                (
                    message_key,
                    legacy_key,
                    payload_digest,
                    from_user_id,
                    payload,
                    "pending",
                    "",
                )
            )

    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        inserts: list[tuple[str, str, str, str, str, str, str]] = []
        batch_digests: dict[str, str] = {}
        for item in prepared:
            (
                message_key,
                legacy_key,
                request_sha256,
                from_user_id,
                payload,
                status,
                last_error,
            ) = item
            previous_digest = batch_digests.get(message_key)
            if previous_digest is not None:
                if not secrets.compare_digest(previous_digest, request_sha256):
                    raise InboundSemanticConflict("inbound_semantic_conflict")
                continue
            batch_digests[message_key] = request_sha256
            candidates = (message_key,) if legacy_key == message_key else (message_key, legacy_key)
            placeholders = ",".join("?" for _ in candidates)
            existing = conn.execute(
                "SELECT message_key,from_user_id,payload,request_sha256 "
                f"FROM inbound_message WHERE message_key IN ({placeholders}) "
                "ORDER BY CASE WHEN message_key=? THEN 0 ELSE 1 END LIMIT 1",
                (*candidates, message_key),
            ).fetchone()
            if existing is not None:
                existing_digest = str(existing[3] or "")
                if existing_digest and not secrets.compare_digest(
                    existing_digest, request_sha256
                ):
                    raise InboundSemanticConflict("inbound_semantic_conflict")
                if (
                    not existing_digest
                    and str(existing[0]) == message_key
                    and (
                        str(existing[1]) != from_user_id
                        or str(existing[2]) != payload
                    )
                ):
                    raise InboundSemanticConflict("inbound_semantic_conflict")
                continue
            inserts.append(item)

        incoming = len(inserts)
        if not _reserve_inbound_rows(conn, incoming):
            conn.rollback()
            return False
        for (
            message_key,
            _legacy_key,
            request_sha256,
            from_user_id,
            payload,
            status,
            last_error,
        ) in inserts:
            chat_seq = _allocate_chat_seq(conn)
            conn.execute(
                """
                INSERT INTO inbound_message
                  (message_key, from_user_id, payload, received_at, next_attempt_at,
                   status, last_error, request_sha256, chat_seq)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_key,
                    from_user_id,
                    payload,
                    now,
                    now,
                    status,
                    last_error,
                    request_sha256,
                    chat_seq,
                ),
            )
        if cursor:
            conn.execute(
                """
                INSERT INTO bridge_state(key, value, updated_at) VALUES('cursor', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (cursor, now),
            )
        conn.commit()
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _load_cursor() -> str:
    with closing(_outbox_connect()) as conn, conn:
        row = conn.execute("SELECT value FROM bridge_state WHERE key = 'cursor'").fetchone()
    return str(row[0]) if row else ""


def _inbox_status_count(statuses: tuple[str, ...]) -> int:
    placeholders = ", ".join("?" for _ in statuses)
    with closing(_outbox_connect()) as conn, conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM inbound_message WHERE status IN ({placeholders})",
            statuses,
        ).fetchone()
    return int(row[0] if row else 0)


def _inbox_pending_count() -> int:
    return _inbox_status_count(("pending", "processing", "recovery_required"))


def _queue_health_counts(
    *, now: float | None = None
) -> tuple[int, int, int, int, int, int, int, int, float]:
    """Read every readiness queue count from one SQLite snapshot/connection."""
    current = time.time() if now is None else now
    with closing(_outbox_connect()) as conn, conn:
        row = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM inbound_message
               WHERE status IN ('pending', 'processing', 'recovery_required')),
              (SELECT COUNT(*) FROM pending_delivery
               WHERE status IN ('pending', 'processing', 'recovery_required')),
              (SELECT COUNT(*) FROM pending_video
               WHERE status IN ('reserved', 'pending', 'processing', 'recovery_required')),
              (SELECT COUNT(*) FROM inbound_message WHERE status = 'dead'),
              (SELECT COUNT(*) FROM pending_delivery WHERE status = 'dead'),
              (SELECT COUNT(*) FROM inbound_message WHERE status = 'recovery_required'),
              (SELECT COUNT(*) FROM pending_delivery WHERE status = 'recovery_required'),
              (SELECT COUNT(*) FROM pending_video WHERE status = 'recovery_required'),
              (SELECT MIN(claimed_at) FROM inbound_message
               WHERE status = 'processing' AND claimed_at > 0)
            """
        ).fetchone()
    if row is None:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0.0
    counts = tuple(max(0, int(value or 0)) for value in row[:8])
    oldest_claimed_at = _strict_health_time(row[8])
    oldest_age = max(0.0, float(current) - oldest_claimed_at) if oldest_claimed_at else 0.0
    return (*counts, _strict_health_time(oldest_age))


def _policy_time(now=None) -> float:
    return float(now() if callable(now) else time.time() if now is None else now)


def _claim_inbound(
    *, now=None
) -> tuple[int, dict, str, int] | None:
    """Atomically claim one message while preserving order within each user chat."""
    claim_token = secrets.token_hex(16)
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = _policy_time(now)
        claim_deadline = current + _INBOUND_CLAIM_TTL_SECONDS
        row = conn.execute(
            """
            SELECT candidate.id, candidate.payload, candidate.message_key,
                   candidate.claim_epoch
            FROM inbound_message AS candidate
            WHERE (
                (candidate.status = 'pending' AND candidate.next_attempt_at <= ?)
                OR
                (candidate.status = 'processing' AND candidate.claim_deadline <= ?)
              )
              AND NOT EXISTS (
                SELECT 1 FROM inbound_message AS earlier
                WHERE earlier.from_user_id = candidate.from_user_id
                  AND earlier.chat_seq < candidate.chat_seq
                  AND earlier.status IN ('pending', 'processing', 'recovery_required')
              )
              AND NOT EXISTS (
                SELECT 1 FROM pending_delivery AS earlier_delivery
                WHERE earlier_delivery.to_user_id = candidate.from_user_id
                  AND earlier_delivery.chat_seq < candidate.chat_seq
                  AND earlier_delivery.status IN
                      ('pending','processing','submitting','recovery_required')
              )
            ORDER BY candidate.chat_seq,candidate.id
            LIMIT 1
            """,
            (current, current),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        changed = conn.execute(
            """
            UPDATE inbound_message
            SET status='processing',claimed_at=?,claim_token=?,claim_deadline=?,
                heartbeat_at=?,claim_epoch=claim_epoch+1
            WHERE id=? AND (
                (status='pending' AND next_attempt_at <= ?)
                OR
                (status='processing' AND claim_deadline <= ?)
            )
            """,
            (
                current,
                claim_token,
                claim_deadline,
                current,
                row[0],
                current,
                current,
            ),
        ).rowcount
        conn.commit()
        if changed != 1:
            return None
        message = json.loads(row[1])
        if not isinstance(message, dict):
            raise RuntimeError("invalid durable inbound payload")
        message["_nachuan_message_key"] = str(row[2])
        return int(row[0]), message, claim_token, int(row[3]) + 1
    finally:
        conn.close()


def _renew_inbound_claim(
    row_id: int,
    claim_token: str,
    claim_epoch: int,
    *,
    now=None,
) -> bool:
    """Extend only a still-live claim, sampling policy time after the write lock."""

    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = _policy_time(now)
        deadline = current + _INBOUND_CLAIM_TTL_SECONDS
        changed = conn.execute(
            "UPDATE inbound_message SET heartbeat_at=?,claim_deadline=? "
            "WHERE id=? AND status='processing' AND claim_token=? "
            "AND claim_epoch=? AND claim_deadline>?",
            (current, deadline, row_id, claim_token, int(claim_epoch), current),
        ).rowcount
        conn.commit()
        return changed == 1
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _require_live_inbound_provider_fence() -> None:
    session = getattr(_HANDLE_CONTEXT, "lease_session", None)
    if session is not None and not session.before_provider():
        raise InboundFinishFenceLost("inbound_provider_fence_lost")
    permits_provider = getattr(_HANDLE_CONTEXT, "permits_provider", None)
    if permits_provider is not None and not permits_provider():
        raise InboundFinishFenceLost("inbound_provider_fence_lost")


def _authorized_inbound_reply_route(
    row: tuple | None,
    *,
    access: ChannelAccessPolicy,
) -> tuple[str, str] | None:
    if row is None:
        return None
    from_user_id = str(row[1] or "")
    payload: dict = {}
    try:
        decoded = json.loads(str(row[2] or ""))
        if isinstance(decoded, dict):
            payload = decoded
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    context_token = str(payload.get("context_token") or "")
    if (
        access.permits(from_user_id)
        and 0 < len(from_user_id) <= 512
        and not any(ord(char) < 32 or ord(char) == 127 for char in from_user_id)
        and len(context_token) <= _VIDEO_CONTEXT_MAX_CHARS
    ):
        return from_user_id, context_token
    return None


def _finish_inbound(
    row_id: int,
    *,
    claim_token: str,
    claim_epoch: int,
    ok: bool,
    error: Exception | None = None,
    unauthorized_at_claim: bool = False,
    now=None,
    deadline_monotonic: float | None = None,
    access_generation_before_refresh: int | None = None,
    refreshed_access: ChannelAccessPolicy | None = None,
) -> bool:
    # Production ClaimLeaseStorage always receives a preloaded access snapshot
    # through its outcome, so filesystem I/O happens before the total finish
    # clock starts.  The fallback keeps direct maintenance/test callers source
    # compatible while still performing the refresh before opening a writer.
    if access_generation_before_refresh is None or refreshed_access is None:
        with _ACCESS_LOCK:
            access_generation_before_refresh = _ACCESS_GENERATION
        refreshed_access, _refreshed_owner, _refreshed_error = _refresh_access()
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    write_authority: _OutboxImmediateWriteAuthority | None = None
    access_lock_held = False
    try:
        write_authority = _begin_outbox_immediate_write(
            conn, deadline_monotonic=deadline_monotonic
        )
        if deadline_monotonic is None:
            access_lock_acquired = _ACCESS_LOCK.acquire()
        else:
            remaining = _remaining_outbox_finish_budget(deadline_monotonic)
            access_lock_acquired = _ACCESS_LOCK.acquire(timeout=remaining)
        if not access_lock_acquired:
            raise _OutboxFinishDeadlineExceeded(
                "Weixin finish access gate deadline exceeded"
            )
        access_lock_held = True
        _remaining_outbox_finish_budget(deadline_monotonic)
        # Production refreshes always publish a new generation.  Keeping the
        # returned value when a test/private embedding replaces the refresh
        # callable preserves the established dependency seam without weakening
        # real hot-reload ordering.
        access = (
            ACCESS
            if _ACCESS_GENERATION != access_generation_before_refresh
            else refreshed_access
        )
        if ok:
            row = conn.execute(
                "SELECT from_user_id,status,claim_token,claim_epoch,claim_deadline "
                "FROM inbound_message WHERE id = ?",
                (row_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("inbound_finish_missing")
            from_user_id = str(row[0])
            current = _policy_time(now)
            if (
                str(row[1]) != "processing"
                or not secrets.compare_digest(str(row[2]), str(claim_token))
                or int(row[3] or 0) != int(claim_epoch)
                or float(row[4] or 0) <= current
            ):
                raise InboundFinishFenceLost("inbound_finish_fence_lost")
            if unauthorized_at_claim or not access.permits(from_user_id):
                changed = conn.execute(
                    "UPDATE inbound_message SET status='done',last_error='',"
                    "from_user_id=?,payload=?,claimed_at=0,claim_token='',"
                    "claim_deadline=0,heartbeat_at=0,last_finish_token=?,"
                    "last_finish_epoch=?,last_finish_outcome='done' "
                    "WHERE id=? AND status='processing' AND claim_token=? "
                    "AND claim_epoch=? AND claim_deadline>?",
                    (
                        _opaque_identity(from_user_id),
                        _UNAUTHORIZED_INBOUND_TOMBSTONE,
                        claim_token,
                        int(claim_epoch),
                        row_id,
                        claim_token,
                        int(claim_epoch),
                        current,
                    ),
                ).rowcount
            else:
                changed = conn.execute(
                    "UPDATE inbound_message SET status='done',last_error='',"
                    "claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,"
                    "last_finish_token=?,last_finish_epoch=?,"
                    "last_finish_outcome='done' "
                    "WHERE id=? AND status='processing' AND claim_token=? "
                    "AND claim_epoch=? AND claim_deadline>?",
                    (
                        claim_token,
                        int(claim_epoch),
                        row_id,
                        claim_token,
                        int(claim_epoch),
                        current,
                    ),
                ).rowcount
            if changed != 1:
                raise InboundFinishFenceLost("inbound_finish_fence_lost")
        else:
            row = conn.execute(
                "SELECT attempts,from_user_id,payload,message_key,status,"
                "claim_token,claim_epoch,claim_deadline,chat_seq "
                "FROM inbound_message WHERE id = ?",
                (row_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("inbound_finish_missing")
            attempts = int(row[0]) + 1
            status = "dead" if attempts >= 8 else "pending"
            reply_route = (
                _authorized_inbound_reply_route(row, access=access)
                if attempts == 1 or status == "dead"
                else None
            )
            # Failure notices inherit the finished turn's own chat position so
            # the same-chat order gate cannot hold them behind that turn's
            # pending retry.
            notice_group = (
                (int(row[8]), str(row[3])) if int(row[8] or 0) >= 1 else None
            )
            current = _policy_time(now)
            if (
                str(row[4]) != "processing"
                or not secrets.compare_digest(str(row[5]), str(claim_token))
                or int(row[6] or 0) != int(claim_epoch)
                or float(row[7] or 0) <= current
            ):
                raise InboundFinishFenceLost("inbound_finish_fence_lost")
            delay = min(2 ** min(attempts, 8), 300)
            if attempts == 1 and reply_route is not None:
                _enqueue_delivery_in_transaction(
                    conn,
                    reply_route[0],
                    reply_route[1],
                    _RETRYING_FAILURE_NOTICE,
                    delivery_key=f"{str(row[3])}:retrying",
                    now=now,
                    _write_authority=write_authority,
                    _chat_group=notice_group,
                )
            finish_outcome = "dead" if status == "dead" else "retry"
            if status == "dead":
                if reply_route is not None:
                    _enqueue_delivery_in_transaction(
                        conn,
                        reply_route[0],
                        reply_route[1],
                        _TERMINAL_FAILURE_NOTICE,
                        delivery_key=f"{str(row[3])}:terminal-failure",
                        now=now,
                        _write_authority=write_authority,
                        _chat_group=notice_group,
                    )
                finish_current = _policy_time(now)
                changed = conn.execute(
                    """
                    UPDATE inbound_message
                    SET status='dead',attempts=?,next_attempt_at=?,last_error=?,
                        from_user_id=?,payload=?,claimed_at=0,claim_token='',
                        claim_deadline=0,heartbeat_at=0,last_finish_token=?,
                        last_finish_epoch=?,last_finish_outcome=?
                    WHERE id=? AND status='processing' AND claim_token=?
                      AND claim_epoch=? AND claim_deadline>?
                    """,
                    (
                        attempts,
                        finish_current + delay,
                        _error_code(
                            type(error).__name__ if error else "unknown_error"
                        ),
                        _opaque_identity(row[1] if row else ""),
                        _DEAD_INBOUND_TOMBSTONE,
                        claim_token,
                        int(claim_epoch),
                        finish_outcome,
                        row_id,
                        claim_token,
                        int(claim_epoch),
                        finish_current,
                    ),
                ).rowcount
            else:
                finish_current = _policy_time(now)
                changed = conn.execute(
                    """
                    UPDATE inbound_message
                    SET status=?,attempts=?,next_attempt_at=?,last_error=?,
                        claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                        last_finish_token=?,last_finish_epoch=?,last_finish_outcome=?
                    WHERE id=? AND status='processing' AND claim_token=?
                      AND claim_epoch=? AND claim_deadline>?
                    """,
                    (
                        status,
                        attempts,
                        finish_current + delay,
                        _error_code(
                            type(error).__name__ if error else "unknown_error"
                        ),
                        claim_token,
                        int(claim_epoch),
                        finish_outcome,
                        row_id,
                        claim_token,
                        int(claim_epoch),
                        finish_current,
                    ),
                ).rowcount
            if changed != 1:
                raise InboundFinishFenceLost("inbound_finish_fence_lost")
        _end_outbox_immediate_write(conn, write_authority)
        write_authority = None
        if deadline_monotonic is not None:
            _constrain_outbox_busy_timeout(
                conn,
                deadline_monotonic=deadline_monotonic,
                default_busy_timeout_ms=10_000,
            )
        conn.commit()
        _remaining_outbox_finish_budget(deadline_monotonic)
        _ACCESS_LOCK.release()
        access_lock_held = False
        _remaining_outbox_finish_budget(deadline_monotonic)
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        if access_lock_held:
            _ACCESS_LOCK.release()
        if write_authority is not None:
            _end_outbox_immediate_write(conn, write_authority)
        conn.close()


def _inbound_finish_was_committed(
    row_id: int,
    *,
    claim_token: str,
    claim_epoch: int,
    ok: bool,
    deadline_monotonic: float | None = None,
) -> bool:
    """Confirm only this exact claim epoch/token and requested finish class."""

    _remaining_outbox_finish_budget(deadline_monotonic)
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    try:
        row = conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM inbound_message WHERE id=?",
            (row_id,),
        ).fetchone()
        _remaining_outbox_finish_budget(deadline_monotonic)
    finally:
        conn.close()
    if row is None:
        _remaining_outbox_finish_budget(deadline_monotonic)
        return False
    if ok:
        expected = "done"
    elif str(row[0]) == "pending":
        expected = "retry"
    elif str(row[0]) == "dead":
        expected = "dead"
    else:
        _remaining_outbox_finish_budget(deadline_monotonic)
        return False
    result = bool(
        secrets.compare_digest(str(row[1] or ""), str(claim_token))
        and int(row[2] or 0) == int(claim_epoch)
        and secrets.compare_digest(str(row[3] or ""), expected)
    )
    _remaining_outbox_finish_budget(deadline_monotonic)
    return result


def _inbound_claim_is_current(
    row_id: int,
    *,
    claim_token: str,
    claim_epoch: int,
    now=None,
) -> bool:
    conn = _outbox_connect()
    try:
        row = conn.execute(
            "SELECT claim_deadline FROM inbound_message "
            "WHERE id=? AND status='processing' AND claim_token=? AND claim_epoch=?",
            (row_id, claim_token, int(claim_epoch)),
        ).fetchone()
        current = _policy_time(now)
    finally:
        conn.close()
    return bool(row is not None and float(row[0] or 0) > current)


class _InboundFinishRequest:
    __slots__ = (
        "ok",
        "error",
        "unauthorized_at_claim",
        "access_generation_before_refresh",
        "refreshed_access",
    )

    def __init__(
        self,
        *,
        ok: bool,
        error: Exception | None,
        unauthorized_at_claim: bool,
        access_generation_before_refresh: int,
        refreshed_access: ChannelAccessPolicy,
    ) -> None:
        self.ok = bool(ok)
        self.error = error
        self.unauthorized_at_claim = bool(unauthorized_at_claim)
        self.access_generation_before_refresh = int(
            access_generation_before_refresh
        )
        self.refreshed_access = refreshed_access


class _InboundClaimStorage:
    """Weixin-specific SQLite adapter for the channel-neutral lease session."""

    def __init__(
        self,
        row_id: int,
        claim_token: str,
        claim_epoch: int,
        worker_stop,
    ) -> None:
        self.row_id = int(row_id)
        self.claim_token = str(claim_token)
        self.claim_epoch = int(claim_epoch)
        self.worker_stop = worker_stop

    def renew(self) -> bool:
        return bool(
            not self.worker_stop.is_set()
            and _renew_inbound_claim(
                self.row_id,
                self.claim_token,
                self.claim_epoch,
            )
        )

    def owns(self) -> bool:
        return bool(
            not self.worker_stop.is_set()
            and _inbound_claim_is_current(
                self.row_id,
                claim_token=self.claim_token,
                claim_epoch=self.claim_epoch,
            )
        )

    def finish_before(
        self,
        outcome: _InboundFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        try:
            return _finish_inbound(
                self.row_id,
                claim_token=self.claim_token,
                claim_epoch=self.claim_epoch,
                ok=outcome.ok,
                error=outcome.error,
                unauthorized_at_claim=outcome.unauthorized_at_claim,
                deadline_monotonic=deadline_monotonic,
                access_generation_before_refresh=(
                    outcome.access_generation_before_refresh
                ),
                refreshed_access=outcome.refreshed_access,
            )
        except InboundFinishFenceLost:
            return False

    def confirm_finish_before(
        self,
        outcome: _InboundFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        return _inbound_finish_was_committed(
            self.row_id,
            claim_token=self.claim_token,
            claim_epoch=self.claim_epoch,
            ok=outcome.ok,
            deadline_monotonic=deadline_monotonic,
        )


def _record_inbound_claim_health_nonblocking(rendered: str) -> None:
    """Best-effort deadline-path projection without SQLite or filesystem I/O.

    Records error evidence only; the service_state transition belongs to the
    worker/main loop that surfaces the failure, so a lease fault cannot
    double-project a degraded state the worker already reported.
    """

    if not _HEALTH_LOCK.acquire(blocking=False):
        return
    try:
        error_code = _health_error_code(rendered.replace(":", "_"))
        _HEALTH_STATE["connected"] = False
        _HEALTH_STATE["last_handler_ok"] = False
        _HEALTH_STATE["last_error_code"] = error_code
        _HEALTH_STATE["last_handler_error_code"] = error_code
    finally:
        _HEALTH_LOCK.release()


class _InboundClaimPolicy:
    heartbeat_interval = max(
        0.05,
        min(
            float(_INBOUND_HEARTBEAT_SECONDS),
            float(_INBOUND_CLAIM_TTL_SECONDS) / 3.0,
        ),
    )
    stop_timeout = min(float(_INBOUND_CLAIM_TTL_SECONDS) / 4.0 + 0.5, 8.0)
    finish_timeout = min(float(_INBOUND_CLAIM_TTL_SECONDS) / 4.0, 15.0)
    finish_retry_delays = tuple(
        float(value) for value in _INBOUND_FINISH_RETRY_DELAYS_SECONDS
    )

    @staticmethod
    def is_retryable(error: BaseException) -> bool:
        return isinstance(error, (sqlite3.Error, OSError)) and not isinstance(
            error, _OutboxFinishDeadlineExceeded
        )

    @staticmethod
    def fault(code: str, error: BaseException | None = None) -> None:
        rendered = f"inbound_claim:{code}"
        if error is not None:
            rendered = f"{rendered}:{type(error).__name__}"
        _record_inbound_claim_health_nonblocking(rendered[:500])


def _new_inbound_lease_session(
    row_id: int,
    claim_token: str,
    claim_epoch: int,
    worker_stop,
) -> ClaimLeaseSession[_InboundFinishRequest]:
    return ClaimLeaseSession(
        storage=_InboundClaimStorage(
            row_id,
            claim_token,
            claim_epoch,
            worker_stop,
        ),
        policy=_InboundClaimPolicy(),
        thread_name="weixin-inbound-heartbeat",
    )


def _recover_inbound(*, force: bool = False, now: float | None = None) -> int:
    """Recover expired leases; force is safe only while holding the process mutex."""
    current = time.time() if now is None else now
    with closing(_outbox_connect()) as conn, conn:
        if force:
            result = conn.execute(
                """
                UPDATE inbound_message
                SET status='pending',claimed_at=0,claim_token='',claim_deadline=0,
                    heartbeat_at=0
                WHERE status='processing'
                """
            )
        else:
            result = conn.execute(
                """
                UPDATE inbound_message
                SET status='pending',claimed_at=0,claim_token='',claim_deadline=0,
                    heartbeat_at=0
                WHERE status='processing' AND claim_deadline<=?
                """,
                (current,),
            )
        return max(0, int(result.rowcount))


def _delivery_id(delivery_key: str | None) -> str:
    seed = delivery_key or _client_id("nachuan_delivery")
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()


def _allocate_chat_seq(conn: sqlite3.Connection) -> int:
    """Allocate one structural chat order without consulting wall-clock time."""

    row = conn.execute(
        "SELECT value FROM bridge_state WHERE key=?",
        (_CHAT_SEQ_STATE_KEY,),
    ).fetchone()
    max_row = conn.execute(
        """
        SELECT MAX(chat_seq) FROM (
          SELECT chat_seq FROM inbound_message
          UNION ALL SELECT chat_seq FROM pending_delivery
          UNION ALL SELECT chat_seq FROM pending_video
        )
        """
    ).fetchone()
    maximum = max(0, int(max_row[0] or 0))
    if row is None:
        head = maximum + 1
    else:
        rendered = str(row[0])
        try:
            head = int(rendered)
        except (TypeError, ValueError, OverflowError) as exc:
            raise sqlite3.DatabaseError("Weixin chat sequence authority is invalid") from exc
        if str(head) != rendered or head <= maximum or head < 1:
            raise sqlite3.DatabaseError("Weixin chat sequence authority is invalid")
    if head >= _SQLITE_SIGNED_INT64_MAX:
        raise sqlite3.DatabaseError("Weixin chat sequence space is exhausted")
    conn.execute(
        """
        INSERT INTO bridge_state(key,value,updated_at) VALUES(?,?,0)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=0
        """,
        (_CHAT_SEQ_STATE_KEY, str(head + 1)),
    )
    return head


def _claimed_inbound_chat_group(
    conn: sqlite3.Connection,
    *,
    recipient: str,
) -> tuple[int, str] | None:
    fields = ("claim_id", "claim_token", "claim_epoch", "lease_session")
    present = tuple(hasattr(_HANDLE_CONTEXT, field) for field in fields)
    if not any(present):
        return None
    if not all(present):
        raise InboundFinishFenceLost("inbound_chat_sequence_fence_lost")
    row = conn.execute(
        """
        SELECT chat_seq,message_key,from_user_id
        FROM inbound_message
        WHERE id=? AND status='processing' AND claim_token=? AND claim_epoch=?
        """,
        (
            int(getattr(_HANDLE_CONTEXT, "claim_id")),
            str(getattr(_HANDLE_CONTEXT, "claim_token")),
            int(getattr(_HANDLE_CONTEXT, "claim_epoch")),
        ),
    ).fetchone()
    # ``claim_message_key`` is a defense-in-depth binding that only the worker's
    # own turn sets; progress/notice paths deliberately carry the four-field
    # claim identity and rely on the fenced row lookup alone.
    expected_key = str(getattr(_HANDLE_CONTEXT, "claim_message_key", "") or "")
    if (
        row is None
        or (
            expected_key
            and not secrets.compare_digest(str(row[1]), expected_key)
        )
        or not secrets.compare_digest(str(row[2]), str(recipient))
    ):
        raise InboundFinishFenceLost("inbound_chat_sequence_fence_lost")
    chat_seq = int(row[0] or 0)
    if chat_seq < 1:
        # Legacy rows ingested before the sequence authority existed get their
        # position stamped on first use, inside the caller's write transaction.
        chat_seq = _allocate_chat_seq(conn)
        changed = conn.execute(
            """
            UPDATE inbound_message SET chat_seq=?
            WHERE id=? AND status='processing' AND claim_token=?
              AND claim_epoch=? AND chat_seq<1
            """,
            (
                chat_seq,
                int(getattr(_HANDLE_CONTEXT, "claim_id")),
                str(getattr(_HANDLE_CONTEXT, "claim_token")),
                int(getattr(_HANDLE_CONTEXT, "claim_epoch")),
            ),
        ).rowcount
        if changed != 1:
            raise InboundFinishFenceLost("inbound_chat_sequence_fence_lost")
    return chat_seq, str(row[1])


def _reserve_outbound_rows(conn: sqlite3.Connection, incoming: int) -> bool:
    limit = max(1, min(int(_MAX_OUTBOUND_ROWS), 1_000_000))
    row = conn.execute("SELECT COUNT(*) FROM pending_delivery").fetchone()
    current = max(0, int(row[0] if row else 0))
    needed = max(0, current + max(0, incoming) - limit)
    if needed:
        groups = conn.execute(
            "SELECT delivery_id,COUNT(*) FROM pending_delivery "
            "WHERE delivery_id<>'' GROUP BY delivery_id "
            "HAVING SUM(CASE WHEN status='done' THEN 0 ELSE 1 END)=0 "
            "ORDER BY MIN(id) LIMIT 256"
        ).fetchall()
        selected: list[str] = []
        reclaimed = 0
        for delivery_id, row_count in groups:
            selected.append(str(delivery_id))
            reclaimed += max(0, int(row_count))
            if reclaimed >= needed:
                break
        if selected:
            placeholders = ",".join("?" for _ in selected)
            deleted = conn.execute(
                f"DELETE FROM pending_delivery WHERE status='done' "
                f"AND delivery_id IN ({placeholders})",
                tuple(selected),
            ).rowcount
            current -= max(0, int(deleted))
    return current + max(0, incoming) <= limit


def _require_inbound_outbox_fence(
    conn: sqlite3.Connection,
    *,
    now=None,
    _write_authority: _OutboxImmediateWriteAuthority | None,
    expected_message_key: str | None = None,
) -> None:
    """Recheck worker ownership on the exact transaction that will persist reply."""

    _require_outbox_immediate_write(conn, _write_authority)
    context_fields = ("claim_id", "claim_token", "claim_epoch", "lease_session")
    present = tuple(hasattr(_HANDLE_CONTEXT, name) for name in context_fields)
    if not any(present):
        return
    if not all(present):
        raise InboundFinishFenceLost("inbound_outbox_fence_lost")
    context_claim_id = int(getattr(_HANDLE_CONTEXT, "claim_id", 0) or 0)
    context_token = str(getattr(_HANDLE_CONTEXT, "claim_token", "") or "")
    context_epoch = int(getattr(_HANDLE_CONTEXT, "claim_epoch", 0) or 0)
    session = getattr(_HANDLE_CONTEXT, "lease_session", None)
    if (
        not context_token
        or context_epoch < 1
        or session is None
        or bool(getattr(session, "lost", True))
    ):
        raise InboundFinishFenceLost("inbound_outbox_fence_lost")
    current = _policy_time(now)
    sql = (
        "SELECT 1 FROM inbound_message WHERE id=? AND status='processing' "
        "AND claim_token=? AND claim_epoch=? AND claim_deadline>?"
    )
    parameters: tuple[object, ...] = (
        context_claim_id,
        context_token,
        context_epoch,
        current,
    )
    if expected_message_key is not None:
        sql += " AND message_key=?"
        parameters += (str(expected_message_key),)
    owned = conn.execute(sql, parameters).fetchone()
    if owned is None:
        raise InboundFinishFenceLost("inbound_outbox_fence_lost")


def _enqueue_delivery_in_transaction(
    conn: sqlite3.Connection,
    to_user_id: str,
    context_token: str,
    text: str,
    *,
    delivery_key: str | None = None,
    now: float | None = None,
    _write_authority: _OutboxImmediateWriteAuthority | None,
    _chat_group: tuple[int, str] | None = None,
) -> tuple[str, list[int]]:
    """Insert one immutable delivery group into the caller's transaction."""

    rendered = str(text)
    if len(rendered.encode("utf-8")) > _MAX_OUTBOUND_TEXT_BYTES:
        raise RuntimeError("微信回复超过 durable outbox 字节预算")
    current = _policy_time(now)
    _require_inbound_outbox_fence(
        conn,
        now=now,
        _write_authority=_write_authority,
    )
    chunks = _split(rendered)
    delivery_id = _delivery_id(delivery_key)
    progress_delivery = bool(
        isinstance(delivery_key, str) and delivery_key.endswith(":progress")
    )
    chat_group = _chat_group
    if chat_group is None:
        chat_group = _claimed_inbound_chat_group(conn, recipient=str(to_user_id))
    expected_parent = chat_group[1] if chat_group is not None else None
    existing = conn.execute(
        """
        SELECT id,to_user_id,context_token,text,client_id,chunk_index,
               chunk_count,chat_seq,parent_message_key
        FROM pending_delivery WHERE delivery_id = ? ORDER BY chunk_index
        """,
        (delivery_id,),
    ).fetchall()
    if existing:
        expected = [
            (
                str(to_user_id),
                str(context_token),
                chunk,
                chunk_index,
                len(chunks),
            )
            for chunk_index, chunk in enumerate(chunks)
        ]
        observed = [
            (
                str(row[1]),
                str(row[2]),
                str(row[3]),
                int(row[5]),
                int(row[6]),
            )
            for row in existing
        ]
        if observed != expected:
            raise DeliverySemanticConflict("delivery_semantic_conflict")
        for row in existing:
            chunk_index = int(row[5])
            allowed_client_ids = {
                f"nachuan_{delivery_id[:32]}_{chunk_index}"
            }
            if progress_delivery:
                allowed_client_ids.add(
                    f"nachuan_progress_{delivery_id[:32]}_{chunk_index}"
                )
            if str(row[4]) not in allowed_client_ids:
                raise DeliverySemanticConflict("delivery_semantic_conflict")
        if chat_group is not None and any(
            int(row[7] or 0) != chat_group[0]
            or not secrets.compare_digest(str(row[8]), str(expected_parent))
            for row in existing
        ):
            raise DeliverySemanticConflict("delivery_semantic_conflict")
        return delivery_id, [int(row[0]) for row in existing]
    if not _reserve_outbound_rows(conn, len(chunks)):
        raise RuntimeError("微信 durable outbox 行预算已耗尽")
    chat_seq = chat_group[0] if chat_group is not None else _allocate_chat_seq(conn)
    parent_message_key = expected_parent or ""
    for chunk_index, chunk in enumerate(chunks):
        # Splitting/capacity work can cross the hard deadline while this write
        # transaction excludes reclaimers.  Sample policy time again directly
        # before each durable INSERT; equality is already loss of ownership.
        _require_inbound_outbox_fence(
            conn,
            now=now,
            _write_authority=_write_authority,
        )
        client_id_prefix = "nachuan_progress_" if progress_delivery else "nachuan_"
        client_id = f"{client_id_prefix}{delivery_id[:32]}_{chunk_index}"
        conn.execute(
            """
            INSERT INTO pending_delivery
              (created_at, next_attempt_at, attempts, to_user_id, context_token,
               text, last_error, status, delivery_id, client_id, chunk_index,
               chunk_count, chat_seq, parent_message_key, claim_token,
               claimed_at, delivered_at)
            VALUES (?, ?, 0, ?, ?, ?, '', 'pending', ?, ?, ?, ?, ?, ?, '', 0, 0)
            """,
            (
                current,
                current,
                to_user_id,
                context_token,
                chunk,
                delivery_id,
                client_id,
                chunk_index,
                len(chunks),
                chat_seq,
                parent_message_key,
            ),
        )
    rows = conn.execute(
        "SELECT id FROM pending_delivery WHERE delivery_id = ? ORDER BY chunk_index",
        (delivery_id,),
    ).fetchall()
    if not rows:
        raise RuntimeError("微信回复持久化失败")
    return delivery_id, [int(row[0]) for row in rows]


def _enqueue_delivery(
    to_user_id: str,
    context_token: str,
    text: str,
    *,
    delivery_key: str | None = None,
) -> tuple[str, list[int]]:
    """Persist every chunk before network I/O and return its immutable row ids."""

    session = getattr(_HANDLE_CONTEXT, "lease_session", None)
    fence = session.commit_fence() if session is not None else nullcontext()
    with fence:
        conn = _outbox_connect()
        write_authority: _OutboxImmediateWriteAuthority | None = None
        try:
            write_authority = _begin_outbox_immediate_write(conn)
            result = _enqueue_delivery_in_transaction(
                conn,
                to_user_id,
                context_token,
                text,
                delivery_key=delivery_key,
                _write_authority=write_authority,
            )
            _end_outbox_immediate_write(conn, write_authority)
            write_authority = None
            conn.commit()
            return result
        except BaseException:
            conn.rollback()
            raise
        finally:
            if write_authority is not None:
                _end_outbox_immediate_write(conn, write_authority)
            conn.close()


def _outbox_status_count(statuses: tuple[str, ...]) -> int:
    placeholders = ", ".join("?" for _ in statuses)
    with closing(_outbox_connect()) as conn, conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM pending_delivery WHERE status IN ({placeholders})",
            statuses,
        ).fetchone()
    return int(row[0] if row else 0)


def _outbox_pending_count() -> int:
    return _outbox_status_count(("pending", "processing", "recovery_required"))


def _claim_delivery(
    *,
    now: float | None = None,
    delivery_id: str | None = None,
) -> dict | None:
    """Atomically lease one due chunk; earlier chunks in its message must be done."""

    now = time.time() if now is None else float(now)
    claim_deadline = now + _DELIVERY_CLAIM_TTL_SECONDS
    claim_token = secrets.token_hex(16)
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        filter_sql = ""
        params: list[object] = [now]
        if delivery_id:
            filter_sql = " AND candidate.delivery_id = ?"
            params.append(delivery_id)
        row = conn.execute(
            f"""
            SELECT candidate.id, candidate.attempts, candidate.to_user_id,
                   candidate.context_token, candidate.text, candidate.client_id,
                   candidate.delivery_id, candidate.chunk_index,
                   candidate.chunk_count,candidate.claim_epoch,
                   candidate.parent_message_key
            FROM pending_delivery AS candidate
            WHERE candidate.status = 'pending'
              AND candidate.next_attempt_at <= ?
              {filter_sql}
              AND NOT EXISTS (
                SELECT 1 FROM pending_delivery AS earlier
                WHERE earlier.delivery_id = candidate.delivery_id
                  AND earlier.chunk_index < candidate.chunk_index
                  AND earlier.status <> 'done'
              )
              AND NOT EXISTS (
                SELECT 1 FROM pending_delivery AS earlier_chat
                WHERE earlier_chat.to_user_id = candidate.to_user_id
                  AND earlier_chat.delivery_id <> candidate.delivery_id
                  AND (
                    earlier_chat.chat_seq < candidate.chat_seq
                    OR (
                      earlier_chat.chat_seq = candidate.chat_seq
                      AND earlier_chat.id < candidate.id
                    )
                  )
                  AND earlier_chat.status IN
                      ('pending','processing','submitting','recovery_required')
              )
              AND NOT EXISTS (
                SELECT 1 FROM inbound_message AS earlier_inbound
                WHERE earlier_inbound.from_user_id = candidate.to_user_id
                  AND earlier_inbound.chat_seq >= 1
                  AND earlier_inbound.chat_seq < candidate.chat_seq
                  AND earlier_inbound.status IN
                      ('pending','processing','recovery_required')
              )
              AND NOT EXISTS (
                SELECT 1 FROM pending_video AS earlier_video
                WHERE earlier_video.to_user_id = candidate.to_user_id
                  AND earlier_video.chat_seq < candidate.chat_seq
                  AND earlier_video.status IN
                      ('reserved','pending','processing','recovery_required')
              )
            ORDER BY candidate.chat_seq,candidate.id
            LIMIT 1
            """,
            params,
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        changed = conn.execute(
            """
            UPDATE pending_delivery
            SET status='processing',claim_token=?,claimed_at=?,claim_deadline=?,
                heartbeat_at=?,claim_epoch=claim_epoch+1
            WHERE id = ? AND status = 'pending'
            """,
            (claim_token, now, claim_deadline, now, row[0]),
        ).rowcount
        conn.commit()
        if changed != 1:
            return None
        return {
            "id": int(row[0]),
            "attempts": int(row[1]),
            "to_user_id": str(row[2]),
            "context_token": str(row[3]),
            "text": str(row[4]),
            "client_id": str(row[5]),
            "delivery_id": str(row[6]),
            "chunk_index": int(row[7]),
            "chunk_count": int(row[8]),
            "claim_token": claim_token,
            "claim_epoch": int(row[9]) + 1,
            "claim_deadline": claim_deadline,
            "parent_message_key": str(row[10]),
        }
    finally:
        conn.close()


def _renew_delivery_claim(claim: dict, *, now=None) -> bool:
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = _policy_time(now)
        deadline = current + _DELIVERY_CLAIM_TTL_SECONDS
        changed = conn.execute(
            """
            UPDATE pending_delivery SET heartbeat_at=?,claim_deadline=?
            WHERE id=? AND status IN ('processing','submitting')
              AND claim_token=? AND claim_epoch=? AND claim_deadline>?
            """,
            (
                current,
                deadline,
                claim["id"],
                claim["claim_token"],
                int(claim["claim_epoch"]),
                current,
            ),
        ).rowcount
        conn.commit()
        return changed == 1
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _delivery_claim_is_current(claim: dict, *, now=None) -> bool:
    with closing(_outbox_connect()) as conn:
        row = conn.execute(
            """
            SELECT claim_deadline FROM pending_delivery
            WHERE id=? AND status IN ('processing','submitting')
              AND claim_token=? AND claim_epoch=?
            """,
            (claim["id"], claim["claim_token"], int(claim["claim_epoch"])),
        ).fetchone()
    return bool(row is not None and float(row[0] or 0) > _policy_time(now))


def _mark_delivery_submitting(
    claim: dict,
    request_sha256: str,
    *,
    now=None,
) -> bool:
    conn = _outbox_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = _policy_time(now)
        changed = conn.execute(
            """
            UPDATE pending_delivery
            SET status='submitting',request_sha256=?,submission_started_at=?
            WHERE id=? AND status='processing' AND claim_token=?
              AND claim_epoch=? AND claim_deadline>?
            """,
            (
                str(request_sha256),
                current,
                claim["id"],
                claim["claim_token"],
                int(claim["claim_epoch"]),
                current,
            ),
        ).rowcount
        conn.commit()
        if changed != 1:
            raise DeliveryFinishFenceLost("delivery_submission_fence_lost")
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _delivery_submission_was_committed(
    claim: dict,
    request_sha256: str,
) -> bool:
    with closing(_outbox_connect()) as conn:
        row = conn.execute(
            """
            SELECT request_sha256 FROM pending_delivery
            WHERE id=? AND status='submitting' AND claim_token=? AND claim_epoch=?
            """,
            (claim["id"], claim["claim_token"], int(claim["claim_epoch"])),
        ).fetchone()
    return bool(
        row is not None
        and secrets.compare_digest(str(row[0] or ""), str(request_sha256))
    )


class _DeliveryFinishRequest:
    __slots__ = ("outcome", "error", "platform_response_sha256")

    def __init__(
        self,
        *,
        outcome: str,
        error: Exception | None = None,
        platform_response_sha256: str = "",
    ) -> None:
        if outcome not in {"done", "recovery_required"}:
            raise ValueError("invalid delivery finish outcome")
        self.outcome = outcome
        self.error = error
        self.platform_response_sha256 = str(platform_response_sha256)


def _finish_delivery(
    claim: dict,
    *,
    ok: bool,
    error: Exception | None = None,
    now: float | None = None,
    deadline_monotonic: float | None = None,
    platform_response_sha256: str = "",
    recovery_required: bool = False,
) -> bool:
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    try:
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.execute("BEGIN IMMEDIATE")
        current = time.time() if now is None else float(now)
        if ok:
            fence_row = conn.execute(
                "SELECT status,claim_token,claim_epoch,claim_deadline "
                "FROM pending_delivery WHERE id=?",
                (claim["id"],),
            ).fetchone()
            if (
                fence_row is None
                or str(fence_row[0]) not in ("processing", "submitting")
                or not secrets.compare_digest(
                    str(fence_row[1]), str(claim["claim_token"])
                )
                or int(fence_row[2] or 0) != int(claim["claim_epoch"])
                or float(fence_row[3] or 0) <= current
            ):
                raise DeliveryFinishFenceLost("delivery_finish_fence_lost")
            submitting = str(fence_row[0]) == "submitting"
            if submitting and len(platform_response_sha256) != 64:
                raise ValueError("delivery platform response digest is required")
            changed = conn.execute(
                """
                UPDATE pending_delivery
                SET status='done',last_error='',claim_token='',claimed_at=0,
                    claim_deadline=0,heartbeat_at=0,last_finish_token=?,
                    last_finish_epoch=?,last_finish_outcome='done',
                    platform_response_sha256=?,
                    terminal_verification=?,
                    delivered_at=?
                WHERE id=? AND status IN ('processing','submitting') AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    platform_response_sha256,
                    (
                        "platform_response_observed_unverified"
                        if submitting
                        else ""
                    ),
                    current,
                    claim["id"],
                    claim["claim_token"],
                    int(claim["claim_epoch"]),
                    current,
                ),
            ).rowcount
            outcome = "done"
        else:
            current_row = conn.execute(
                "SELECT status,attempts,to_user_id FROM pending_delivery WHERE id=?",
                (claim["id"],),
            ).fetchone()
            current_status = (
                str(current_row[0]) if current_row is not None else ""
            )
            target = (
                "recovery_required"
                if recovery_required or current_status == "submitting"
                else "pending"
            )
            detail = _error_code(type(error).__name__ if error else "unknown_error")
            new_attempts = (
                int(current_row[1]) + 1 if current_row is not None else 1
            )
            # The retry clock starts when this finish is recorded, never before
            # the bounded network attempt has ended.
            retry_delay = min(2 ** min(new_attempts, 8), 300)
            dead = (
                target == "pending"
                and current_row is not None
                and new_attempts >= _DELIVERY_DEAD_ATTEMPTS
            )
            if dead:
                changed = conn.execute(
                    """
                    UPDATE pending_delivery
                    SET status='dead',attempts=attempts+1,last_error=?,
                        to_user_id=?,context_token='',text='',claim_token='',
                        claimed_at=0,claim_deadline=0,heartbeat_at=0,
                        last_finish_token=?,last_finish_epoch=?,
                        last_finish_outcome='dead'
                    WHERE id=? AND status IN ('processing','submitting')
                      AND claim_token=? AND claim_epoch=? AND claim_deadline>?
                    """,
                    (
                        detail,
                        _opaque_identity(current_row[2]),
                        claim["claim_token"],
                        int(claim["claim_epoch"]),
                        claim["id"],
                        claim["claim_token"],
                        int(claim["claim_epoch"]),
                        current,
                    ),
                ).rowcount
                outcome = "dead"
                if changed == 1:
                    conn.execute(
                        """
                        UPDATE pending_delivery
                        SET status='dead',last_error=?,to_user_id=?,
                            context_token='',text='',claim_token='',claimed_at=0,
                            claim_deadline=0,heartbeat_at=0
                        WHERE delivery_id=? AND id<>? AND status<>'done'
                        """,
                        (
                            detail,
                            _opaque_identity(current_row[2]),
                            str(claim["delivery_id"]),
                            claim["id"],
                        ),
                    )
            else:
                changed = conn.execute(
                    """
                    UPDATE pending_delivery
                    SET status=?,attempts=attempts+1,
                        next_attempt_at=CASE WHEN ?='pending'
                            THEN ? ELSE next_attempt_at END,
                        last_error=?,
                        claim_token='',claimed_at=0,claim_deadline=0,heartbeat_at=0,
                        last_finish_token=?,last_finish_epoch=?,last_finish_outcome=?
                    WHERE id=? AND status IN ('processing','submitting')
                      AND claim_token=? AND claim_epoch=? AND claim_deadline>?
                    """,
                    (
                        target,
                        target,
                        current + retry_delay,
                        detail,
                        claim["claim_token"],
                        int(claim["claim_epoch"]),
                        target,
                        claim["id"],
                        claim["claim_token"],
                        int(claim["claim_epoch"]),
                        current,
                    ),
                ).rowcount
                outcome = target
        if changed != 1:
            raise DeliveryFinishFenceLost("delivery_finish_fence_lost")
        _constrain_outbox_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=10_000,
        )
        conn.commit()
        _remaining_outbox_finish_budget(deadline_monotonic)
        return True
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _delivery_finish_was_committed(
    claim: dict,
    outcome: _DeliveryFinishRequest,
    *,
    deadline_monotonic: float | None = None,
) -> bool:
    conn = (
        _outbox_connect()
        if deadline_monotonic is None
        else _outbox_connect(deadline_monotonic=deadline_monotonic)
    )
    try:
        row = conn.execute(
            """
            SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome,
                   platform_response_sha256
            FROM pending_delivery WHERE id=?
            """,
            (claim["id"],),
        ).fetchone()
        _remaining_outbox_finish_budget(deadline_monotonic)
    finally:
        conn.close()
    if row is None:
        return False
    expected = outcome.outcome
    expected_status = {
        "done": "done",
        "recovery_required": "recovery_required",
        "retry": "pending",
    }[expected]
    return bool(
        secrets.compare_digest(str(row[0]), expected_status)
        and secrets.compare_digest(str(row[1]), str(claim["claim_token"]))
        and int(row[2] or 0) == int(claim["claim_epoch"])
        and secrets.compare_digest(str(row[3]), expected)
        and (
            expected != "done"
            or secrets.compare_digest(
                str(row[4]), outcome.platform_response_sha256
            )
        )
    )


class _DeliveryClaimStorage:
    def __init__(self, claim: dict) -> None:
        self.claim = claim

    def renew(self) -> bool:
        return _renew_delivery_claim(self.claim)

    def owns(self) -> bool:
        return _delivery_claim_is_current(self.claim)

    def finish_before(
        self,
        outcome: _DeliveryFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        try:
            return _finish_delivery(
                self.claim,
                ok=outcome.outcome == "done",
                error=outcome.error,
                deadline_monotonic=deadline_monotonic,
                platform_response_sha256=outcome.platform_response_sha256,
                recovery_required=outcome.outcome == "recovery_required",
            )
        except DeliveryFinishFenceLost:
            return False

    def confirm_finish_before(
        self,
        outcome: _DeliveryFinishRequest,
        *,
        deadline_monotonic: float,
    ) -> bool:
        return _delivery_finish_was_committed(
            self.claim,
            outcome,
            deadline_monotonic=deadline_monotonic,
        )


class _DeliveryClaimPolicy:
    heartbeat_interval = max(
        0.05,
        min(
            float(_DELIVERY_HEARTBEAT_SECONDS),
            float(_DELIVERY_CLAIM_TTL_SECONDS) / 3.0,
        ),
    )
    stop_timeout = min(float(_DELIVERY_CLAIM_TTL_SECONDS) / 4.0 + 0.5, 8.0)
    finish_timeout = min(float(_DELIVERY_CLAIM_TTL_SECONDS) / 4.0, 15.0)
    finish_retry_delays = tuple(
        float(value) for value in _DELIVERY_FINISH_RETRY_DELAYS_SECONDS
    )

    @staticmethod
    def is_retryable(error: BaseException) -> bool:
        return isinstance(error, (sqlite3.Error, OSError)) and not isinstance(
            error, _OutboxFinishDeadlineExceeded
        )

    @staticmethod
    def fault(code: str, error: BaseException | None = None) -> None:
        rendered = f"delivery_claim:{code}"
        if error is not None:
            rendered = f"{rendered}:{type(error).__name__}"
        _record_inbound_claim_health_nonblocking(rendered[:500])


def _new_delivery_lease_session(claim: dict) -> ClaimLeaseSession[_DeliveryFinishRequest]:
    return ClaimLeaseSession(
        storage=_DeliveryClaimStorage(claim),
        policy=_DeliveryClaimPolicy(),
        thread_name="weixin-delivery-heartbeat",
    )


def _release_delivery_claim(claim: dict) -> None:
    """Return an unsent claim unchanged when the drain wall budget is exhausted."""

    with closing(_outbox_connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute(
            """
            UPDATE pending_delivery
            SET status='pending',claim_token='',claimed_at=0,claim_deadline=0,
                heartbeat_at=0
            WHERE id=? AND status='processing' AND claim_token=? AND claim_epoch=?
            """,
            (claim["id"], claim["claim_token"], int(claim["claim_epoch"])),
        ).rowcount
        if changed != 1:
            raise DeliveryFinishFenceLost("delivery_release_fence_lost")
        conn.commit()


def _recover_delivery_claims(*, force: bool = False, now: float | None = None) -> int:
    """Recover only abandoned leases; force is safe after the process mutex is held."""

    now = time.time() if now is None else now
    with closing(_outbox_connect()) as conn, conn:
        if force:
            processing = conn.execute(
                """
                UPDATE pending_delivery
                SET status='pending',claim_token='',claimed_at=0,claim_deadline=0,
                    heartbeat_at=0
                WHERE status = 'processing'
                """
            )
            submitting = conn.execute(
                """
                UPDATE pending_delivery
                SET status='recovery_required',claim_token='',claimed_at=0,
                    claim_deadline=0,heartbeat_at=0,
                    last_error='submission_outcome_unknown_after_restart'
                WHERE status='submitting'
                """
            )
        else:
            processing = conn.execute(
                """
                UPDATE pending_delivery
                SET status='pending',claim_token='',claimed_at=0,claim_deadline=0,
                    heartbeat_at=0
                WHERE status='processing' AND claim_deadline<=?
                """,
                (now,),
            )
            submitting = conn.execute(
                """
                UPDATE pending_delivery
                SET status='recovery_required',claim_token='',claimed_at=0,
                    claim_deadline=0,heartbeat_at=0,
                    last_error='submission_outcome_unknown_after_lease_loss'
                WHERE status='submitting' AND claim_deadline<=?
                """,
                (now,),
            )
        return max(0, int(processing.rowcount)) + max(0, int(submitting.rowcount))


def _delivery_complete(delivery_id: str) -> bool:
    with closing(_outbox_connect()) as conn, conn:
        row = conn.execute(
            """
            SELECT COUNT(*), SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END)
            FROM pending_delivery WHERE delivery_id = ?
            """,
            (delivery_id,),
        ).fetchone()
    total = int(row[0] if row else 0)
    done = int(row[1] if row and row[1] is not None else 0)
    return total > 0 and total == done


def _deliver_text(
    token: str,
    to_user_id: str,
    context_token: str,
    text: str,
    *,
    delivery_key: str | None = None,
) -> bool:
    """Outbox-first delivery: no network byte is sent before all chunks are durable."""

    delivery_id, row_ids = _enqueue_delivery(
        to_user_id,
        context_token,
        text,
        delivery_key=delivery_key,
    )
    _drain_outbox(token, limit=max(1, len(row_ids)), delivery_id=delivery_id)
    return _delivery_complete(delivery_id)


def _drain_outbox(
    token: str,
    *,
    now: float | None = None,
    limit: int = 20,
    delivery_id: str | None = None,
) -> int:
    now = time.time() if now is None else now
    # ``processing`` is provably pre-network and can be reclaimed.  A lost
    # ``submitting`` lease is never replayed: Weixin exposes no authoritative
    # client_id lookup/receipt that could prove the first send was absent.
    _recover_delivery_claims(now=now)
    # Recovery/schema reconciliation is local maintenance, not one outbound
    # network attempt.  Give the actual drain its full bounded budget after
    # that maintenance so a busy cold start cannot starve every send cycle.
    drain_deadline = time.monotonic() + _OUTBOX_DRAIN_WALL_BUDGET_SECONDS
    delivered = 0
    minimum_attempt_timeout = min(
        _SEND_ATTEMPT_TIMEOUT_SECONDS,
        _PROGRESS_SEND_ATTEMPT_TIMEOUT_SECONDS,
    )
    for _ in range(max(0, min(int(limit), 1000))):
        if drain_deadline - time.monotonic() < (
            minimum_attempt_timeout + _OUTBOX_LOCAL_PREP_BUDGET_SECONDS
        ):
            break
        claim = _claim_delivery(now=now, delivery_id=delivery_id)
        if claim is None:
            break
        lease_session = _new_delivery_lease_session(claim)
        if not lease_session.start():
            lease_session.close()
            continue
        attempt_timeout = (
            _PROGRESS_SEND_ATTEMPT_TIMEOUT_SECONDS
            if str(claim.get("client_id") or "").startswith("nachuan_progress_")
            else _SEND_ATTEMPT_TIMEOUT_SECONDS
        )
        # SQLite contention can consume most of the shared budget after the
        # pre-claim check. Do not start a network side effect that no longer
        # fits; release the still-unsent fenced row without incrementing it.
        if drain_deadline - time.monotonic() < attempt_timeout:
            try:
                with lease_session.commit_fence():
                    _release_delivery_claim(claim)
            except Exception as release_error:  # noqa: BLE001
                lease_session.close()
                raise DeliveryRequeueStorageError(
                    "delivery_claim_release_storage_failure"
                ) from release_error
            lease_session.close()
            break
        request_body = _sendmessage_body(
            claim["to_user_id"],
            claim["context_token"],
            claim["text"],
            claim["client_id"],
        )
        request_sha256 = _canonical_json_sha256(request_body)
        try:
            if not lease_session.before_provider():
                lease_session.close()
                continue
            try:
                with lease_session.commit_fence():
                    _mark_delivery_submitting(claim, request_sha256)
            except Exception as submission_error:  # noqa: BLE001
                if not _delivery_submission_was_committed(claim, request_sha256):
                    lease_session.close()
                    raise DeliveryRequeueStorageError(
                        "delivery_submission_storage_failure"
                    ) from submission_error
            had_attempt_timeout = hasattr(
                _DELIVERY_SEND_CONTEXT, "attempt_timeout_seconds"
            )
            previous_attempt_timeout = getattr(
                _DELIVERY_SEND_CONTEXT, "attempt_timeout_seconds", None
            )
            _DELIVERY_SEND_CONTEXT.attempt_timeout_seconds = attempt_timeout
            try:
                response = _send_chunk(
                    token,
                    claim["to_user_id"],
                    claim["context_token"],
                    claim["text"],
                    claim["client_id"],
                )
            finally:
                if had_attempt_timeout:
                    _DELIVERY_SEND_CONTEXT.attempt_timeout_seconds = (
                        previous_attempt_timeout
                    )
                else:
                    delattr(_DELIVERY_SEND_CONTEXT, "attempt_timeout_seconds")
            outcome = _DeliveryFinishRequest(
                outcome="done",
                platform_response_sha256=_canonical_json_sha256(response),
            )
        except Exception as e:  # noqa: BLE001
            # Once ``submitting`` is durable, no transport exception proves
            # that zero request bytes reached Weixin.  Every missing/invalid
            # platform result is therefore non-replayable until adjudicated.
            outcome = _DeliveryFinishRequest(
                outcome="recovery_required",
                error=e,
            )
        try:
            committed = lease_session.finish(outcome)
        finally:
            lease_session.close()
        if not committed:
            # Keep the durable ``submitting`` boundary intact.  Its abandoned
            # lease is isolated as ``recovery_required``; reverting to
            # ``processing`` here would permit an automatic duplicate send.
            if outcome.outcome == "done":
                raise DeliveryAckStorageError("delivery_ack_storage_failure")
            raise DeliveryRequeueStorageError("delivery_requeue_storage_failure")
        if outcome.outcome == "done":
            delivered += 1
        else:
            print(
                f"[send RECOVERY REQUIRED] {type(outcome.error).__name__}",
                flush=True,
            )
        if time.monotonic() >= drain_deadline:
            break
    return delivered


# ── 媒体收发（iLink 官方协议·自持实现，零第三方微信 SDK）──
_CDN_C2C = "https://novac2c.cdn.weixin.qq.com/c2c"  # 媒体 CDN（下载/上传兜底基址）
_WEIXIN_CDN_HOSTS = frozenset({"novac2c.cdn.weixin.qq.com"})
# `/v1/vision` accepts at most 25 MiB of sealed plaintext.  Reserve the
# protocol's full 32-KiB metadata envelope plus its four-byte length prefix so
# a locally accepted CDN object can always be encoded before any HTTP attempt.
_MAX_INBOUND_MEDIA_BYTES = 25 * 1024 * 1024 - 32 * 1024 - 4
_MAX_GENERATED_IMAGE_BYTES = 20 * 1024 * 1024
_MAX_GENERATED_VIDEO_BYTES = 128 * 1024 * 1024
_MEDIA_SOCKET_TIMEOUT_SECONDS = 30
_MEDIA_TOTAL_TIMEOUT_SECONDS = 120


class MediaFetchError(ValueError):
    pass


def _is_official_cdn_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.hostname.rstrip(".").lower() in _WEIXIN_CDN_HOSTS
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
        )
    except (UnicodeError, ValueError):
        return False


def _aes_ecb(data: bytes, key: bytes, *, enc: bool) -> bytes:
    """iLink 媒体加密口径：AES-128-ECB + PKCS7。cryptography 已是现有依赖，零新增。"""
    from cryptography.hazmat.primitives import padding as _pad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    c = Cipher(algorithms.AES(key), modes.ECB())
    if enc:
        p = _pad.PKCS7(128).padder()
        data = p.update(data) + p.finalize()
        e = c.encryptor()
        return e.update(data) + e.finalize()
    d = c.decryptor()
    out = d.update(data) + d.finalize()
    u = _pad.PKCS7(128).unpadder()
    return u.update(out) + u.finalize()


def _parse_aes_key(b64s: str):
    """入站媒体的 aes_key：base64 解出来要么是 16 字节原钥、要么是 32 位 hex 文本。都兼容。"""
    try:
        raw = base64.b64decode(b64s)
        if len(raw) == 16:
            return raw
        s = raw.decode("ascii", errors="ignore").strip()
        if len(s) == 32:
            return bytes.fromhex(s)
    except Exception:  # noqa: BLE001
        pass
    return None


def _upload_media(token: str, to_user_id: str, data: bytes, media_type: int) -> dict:
    """加密 → getuploadurl 拿预签名地址 → POST 密文 → 拿响应头 x-encrypted-param(下载令牌)。"""
    key = os.urandom(16)
    hexkey = key.hex()
    cipher = _aes_ecb(data, key, enc=True)
    body = {
        "filekey": os.urandom(16).hex(),
        "media_type": media_type,  # IMAGE=1 / VIDEO=2
        "to_user_id": to_user_id,
        "rawsize": len(data),
        "rawfilemd5": hashlib.md5(data).hexdigest(),
        "filesize": len(cipher),
        "no_need_thumb": True,
        "aeskey": hexkey,
        "base_info": _base_info(),
    }
    _require_live_inbound_provider_fence()
    _pending_video_submission_boundary(
        "upload_grant_submitting", _canonical_json_sha256(body)
    )
    r = _ilink("POST", "/ilink/bot/getuploadurl", body, token=token, timeout=40)
    _ensure_ilink_success(r, "getuploadurl")
    _require_live_inbound_provider_fence()
    up = r.get("upload_full_url") or ""
    if not up:
        p = str(r.get("upload_param") or "")
        if p.startswith("http"):
            up = p
        elif p:
            up = _CDN_C2C + ("" if p.startswith("?") else "?") + p
    if not up:
        raise RuntimeError(f"getuploadurl 未返回上传地址(keys={list(r.keys())})")
    if not _is_official_cdn_url(up):
        raise MediaFetchError("iLink 返回了非官方 CDN 上传地址")
    last = None
    deadline = time.monotonic() + _MEDIA_TOTAL_TIMEOUT_SECONDS
    pending_video_claim = getattr(_HANDLE_CONTEXT, "pending_video_claim", None)
    upload_attempts = 1 if pending_video_claim is not None else 3
    upload_request_sha256 = _canonical_json_sha256(
        {
            "method": "POST",
            "url_sha256": hashlib.sha256(up.encode("utf-8")).hexdigest(),
            "body_sha256": hashlib.sha256(cipher).hexdigest(),
            "body_bytes": len(cipher),
        }
    )
    _require_live_inbound_provider_fence()
    _pending_video_submission_boundary("upload_submitting", upload_request_sha256)
    for att in range(upload_attempts):  # pending-video mutations are never replayed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise MediaFetchError("CDN 上传超过总时限")
        try:
            response = request_public_bytes(
                up,
                method="POST",
                request_body=cipher,
                request_content_type="application/octet-stream",
                max_request_bytes=len(cipher),
                max_bytes=64 * 1024,
                require_content_type=False,
                total_timeout=remaining,
                idle_timeout=min(remaining, _MEDIA_SOCKET_TIMEOUT_SECONDS),
                max_redirects=0,
                url_guard=_is_official_cdn_url,
            )
            eqp = response.headers.get("x-encrypted-param") or ""
            if not eqp:
                raise RuntimeError("CDN 上传响应缺 x-encrypted-param")
            _require_live_inbound_provider_fence()
            return {
                "encrypt_query_param": eqp,
                "aes_key": base64.b64encode(hexkey.encode()).decode(),  # 口径：base64(hex串)
                "size": len(cipher),
            }
        except PublicFetchHTTPError as e:
            last = e
            if e.status < 500 or att == upload_attempts - 1:
                raise MediaFetchError("CDN 上传失败") from e
            wait = 2 * (att + 1)
            if time.monotonic() + wait >= deadline:
                raise MediaFetchError("CDN 上传超过总时限") from e
            time.sleep(wait)
        except PublicFetchTimeout as exc:
            raise MediaFetchError("CDN 上传超过总时限") from exc
        except PublicFetchError as exc:
            raise MediaFetchError("CDN 上传失败") from exc
    raise RuntimeError(f"CDN 上传失败：{last}")


def _send_media(
    token: str,
    to: str,
    ctx: str,
    data: bytes,
    kind: str,
    *,
    client_id: str | None = None,
) -> bool:
    """把图片/视频字节发进微信聊天。kind: image|video。"""
    _require_live_inbound_provider_fence()
    up = _upload_media(token, to, data, 1 if kind == "image" else 2)
    _require_live_inbound_provider_fence()
    media = {
        "encrypt_query_param": up["encrypt_query_param"],
        "aes_key": up["aes_key"],
        "encrypt_type": 1,
    }
    if kind == "image":
        item = {"type": 2, "image_item": {"media": media, "mid_size": up["size"]}}
    else:
        item = {"type": 5, "video_item": {"media": media, "video_size": up["size"]}}
    _require_live_inbound_provider_fence()
    send_body = {
        "msg": {
            "from_user_id": "",
            "to_user_id": to,
            "client_id": client_id or _client_id("nachuan_media"),
            "message_type": 2,
            "message_state": 2,
            "context_token": ctx,
            "item_list": [item],
        },
        "base_info": _base_info(),
    }
    _pending_video_submission_boundary(
        "send_submitting", _canonical_json_sha256(send_body)
    )
    response = _ilink(
        "POST", "/ilink/bot/sendmessage",
        send_body,
        token=token, timeout=60,
    )
    _ensure_ilink_success(response, "sendmessage")
    _require_live_inbound_provider_fence()
    _pending_video_platform_response(response)
    return True


def _fetch_media(url: str, kind: str = "image") -> bytes:
    """Fetch generated media with public-hop, type, size and deadline guards."""

    if kind not in {"image", "video"}:
        raise MediaFetchError("未知媒体类型")
    max_bytes = (
        _MAX_GENERATED_IMAGE_BYTES if kind == "image" else _MAX_GENERATED_VIDEO_BYTES
    )
    allowed_prefixes = ("image/",) if kind == "image" else ("video/",)
    allowed_exact = () if kind == "image" else ("application/octet-stream",)
    if url.startswith("data:"):
        header, separator, payload = url.partition(",")
        expected_prefix = "data:image/" if kind == "image" else "data:video/"
        if not separator or not header.lower().startswith(expected_prefix) or ";base64" not in header.lower():
            raise MediaFetchError("data URI 类型不允许")
        if len(payload) > ((max_bytes + 2) // 3) * 4 + 4:
            raise MediaFetchError("媒体超过大小上限")
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise MediaFetchError("data URI base64 无效") from exc
        if len(decoded) > max_bytes:
            raise MediaFetchError("媒体超过大小上限")
        return decoded
    try:
        return fetch_public_bytes(
            url,
            max_bytes=max_bytes,
            allowed_type_prefixes=allowed_prefixes,
            allowed_exact_types=allowed_exact,
            total_timeout=_MEDIA_TOTAL_TIMEOUT_SECONDS,
            idle_timeout=_MEDIA_SOCKET_TIMEOUT_SECONDS,
            max_redirects=5,
            headers={"Accept": "image/*" if kind == "image" else "video/*"},
        ).data
    except PublicFetchError as exc:
        raise MediaFetchError("生成媒体 URL/响应不符合公网安全策略或大小上限") from exc


def _cdn_download(media: dict):
    """Download inbound media once; failures remain owned by the durable inbox."""

    eqp = str(media.get("encrypt_query_param") or media.get("url") or "")
    if not eqp:
        raise MediaFetchError("微信入站媒体缺少 CDN URL")
    url = eqp if eqp.startswith("http") else _CDN_C2C + ("" if eqp.startswith("?") else "?") + eqp
    if not _is_official_cdn_url(url):
        raise MediaFetchError("微信入站媒体不是官方 CDN URL")
    raw = fetch_public_bytes(
        url,
        max_bytes=_MAX_INBOUND_MEDIA_BYTES,
        allowed_type_prefixes=("image/",),
        allowed_exact_types=("application/octet-stream",),
        require_content_type=False,
        total_timeout=_MEDIA_TOTAL_TIMEOUT_SECONDS,
        idle_timeout=_MEDIA_SOCKET_TIMEOUT_SECONDS,
        max_redirects=5,
        headers={"Accept": "application/octet-stream, image/*"},
        url_guard=_is_official_cdn_url,
    ).data
    key = _parse_aes_key(str(media.get("aes_key") or ""))
    if key and int(media.get("encrypt_type") or 1) == 1:
        try:
            return _aes_ecb(raw, key, enc=False)
        except Exception:  # noqa: BLE001  个别不加密/口径不同 → 原样返回兜底
            return raw
    return raw


def _engine_raw(path: str, data: bytes, timeout: int = 120) -> dict:
    """Submit one paid-media request; durable inbox recovery owns every retry."""

    try:
        raw = request_bridge_bytes(
            _ENGINE_OPENER,
            url=f"{ENGINE}{path}",
            secret=ENGINE_KEY,
            channel="weixin",
            method="POST",
            body=data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=timeout,
        )
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("engine_response_invalid")
        _set_engine_available(True)
        return result
    except Exception:  # noqa: BLE001 - preserve the root cause for durable retry
        _set_engine_available(False)
        raise


def _describe(
    data: bytes,
    *,
    user_id: str,
    chat_id: str,
    message_key: str,
) -> str:
    frame = encode_channel_media_frame(
        channel="weixin",
        user_id=user_id,
        chat_id=chat_id,
        message_key=message_key,
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={
            "question": "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。",
            "model": "",
        },
        raw=data,
    )
    result = _engine_raw("/v1/vision", frame)
    text = result.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("vision_response_invalid")
    return text.strip()


def _extract_items(msg: dict):
    """把 item_list 拆成 (文本, 首个图片 media dict|None, 是否有语音)。"""
    text = ""
    img = None
    voice = False
    for it in msg.get("item_list") or []:
        t = it.get("type")
        if t == 1 and isinstance(it.get("text_item"), dict):
            text += it["text_item"].get("text", "") or ""
        elif t == 2 and img is None and isinstance(it.get("image_item"), dict):
            img = it["image_item"].get("media") or it["image_item"]
        elif t == 3:
            voice = True
    return text.strip(), img, voice


def _send_generated_media(
    token: str,
    to: str,
    ctx: str,
    d: dict,
    *,
    delivery_key: str | None = None,
) -> None:
    """把纳川生成的图/视频直发微信（杀手锏）；直发失败退回发链接，绝不吞结果。"""
    for index, url in enumerate((d.get("images") or [])[:3]):
        item_key = f"{delivery_key or _client_id('media')}:{index}:{url}"
        media_client_id = "nachuan_media_" + hashlib.sha256(item_key.encode()).hexdigest()[:32]
        try:
            _require_live_inbound_provider_fence()
            data = _fetch_media(url, "image")
            _require_live_inbound_provider_fence()
            _send_media(
                token,
                to,
                ctx,
                data,
                "image",
                client_id=media_client_id,
            )
        except InboundFinishFenceLost:
            raise
        except Exception as e:  # noqa: BLE001
            print("[send image FAIL]", e, flush=True)
            _require_live_inbound_provider_fence()
            _deliver_text(
                token,
                to,
                ctx,
                f"（图片直发失败，链接：{url}）",
                delivery_key=f"{item_key}:fallback",
            )
    vurl = d.get("video")
    if vurl:
        item_key = f"{delivery_key or _client_id('media')}:video:{vurl}"
        media_client_id = "nachuan_media_" + hashlib.sha256(item_key.encode()).hexdigest()[:32]
        try:
            _require_live_inbound_provider_fence()
            data = _fetch_media(vurl, "video")
            _require_live_inbound_provider_fence()
            _send_media(
                token,
                to,
                ctx,
                data,
                "video",
                client_id=media_client_id,
            )
        except InboundFinishFenceLost:
            raise
        except Exception as e:  # noqa: BLE001
            print("[send video FAIL]", e, flush=True)
            _require_live_inbound_provider_fence()
            _deliver_text(
                token,
                to,
                ctx,
                f"（视频直发失败，链接：{vurl}）",
                delivery_key=f"{item_key}:fallback",
            )


def _progress_notice(
    done: threading.Event,
    token: str,
    to: str,
    ctx: str,
    delivery_key: str,
    permits_delivery=None,
    claim_context: tuple[int, str, int, object] | None = None,
) -> None:
    # A channel Turn needs immediate user-visible evidence that the durable
    # inbox owns it. Operators may tune the delay, but cannot recreate the
    # former multi-minute silent window with an unbounded value.
    delay = _bounded_env_seconds(
        "WEIXIN_PROGRESS_AFTER_SECONDS",
        default=2.0,
        minimum=1.0,
        maximum=5.0,
    )
    if not done.wait(delay) and (
        permits_delivery is None or bool(permits_delivery())
    ):
        if claim_context is not None:
            (
                _HANDLE_CONTEXT.claim_id,
                _HANDLE_CONTEXT.claim_token,
                _HANDLE_CONTEXT.claim_epoch,
                _HANDLE_CONTEXT.lease_session,
            ) = claim_context
        try:
            _deliver_text(
                token,
                to,
                ctx,
                "收到，正在处理中；完成后会继续回复你。",
                delivery_key=delivery_key,
            )
        finally:
            if claim_context is not None:
                for name in (
                    "claim_id",
                    "claim_token",
                    "claim_epoch",
                    "lease_session",
                ):
                    try:
                        delattr(_HANDLE_CONTEXT, name)
                    except AttributeError:
                        pass


def _handle(msg: dict, token: str) -> None:
    from_id = msg.get("from_user_id", "")
    ctx = msg.get("context_token", "")
    if not from_id:
        return
    persisted_message_key = msg.get("_nachuan_message_key")
    message_key = (
        str(persisted_message_key)
        if isinstance(persisted_message_key, str)
        and re.fullmatch(r"wxmsg-v1:[0-9a-f]{64}", persisted_message_key)
        else _message_key(msg)
    )

    def deliver(text: str, suffix: str) -> bool:
        return _deliver_text(
            token,
            from_id,
            ctx,
            text,
            delivery_key=f"{message_key}:{suffix}",
        )

    text, img_media, has_voice = _extract_items(msg)
    if not text and img_media is None and not has_voice:
        return
    kind, payload = parse_command(text)
    access, owner, _access_error = _refresh_access()
    # 身份自查不调用模型，在锁定态也开放，解决首次配置白名单的引导死循环。
    if kind == "whoami":
        if _limiter.allow(str(from_id)):
            deliver(f"你的微信标识：{from_id}", "whoami")
        return
    if not access.permits(from_id):
        if _limiter.allow(str(from_id)):
            deliver(
                "纳川微信当前处于安全锁定状态，本消息没有调用模型。"
                "请先发送 /whoami 获取微信标识，再由管理员加入白名单。",
                "access-locked",
            )
        return
    uid = resolve_user_id(from_id, owner)
    if not _limiter.allow(uid):
        deliver("⏳ 消息太快了，歇一秒再发~", "rate-limit")
        return
    if img_media is not None:  # 用户发图 → 纳川看图理解（#28 同款体验）
        data = _cdn_download(img_media)
        if not data:
            deliver("🖼 图片没取下来（CDN 下载失败），再发一次试试？", "vision-download-error")
            return
        latest_access, latest_owner, _access_error = _refresh_access()
        if not latest_access.permits(from_id):
            return
        _require_live_inbound_provider_fence()
        desc = _describe(
            data,
            user_id=from_id,
            chat_id=from_id,
            message_key=message_key,
        )
        _require_live_inbound_provider_fence()
        deliver(f"🖼 我看到：\n{desc}" if desc else "🖼 这张图我没看清，换一张试试？", "vision-result")
        return
    if has_voice and not text:
        deliver("🎤 微信语音是 SILK 编码，暂不支持转写；先打字发我吧~", "voice-unsupported")
        return
    if kind in ("up", "down"):
        latest_access, latest_owner, _access_error = _refresh_access()
        if not latest_access.permits(from_id):
            return
        uid = resolve_user_id(from_id, latest_owner)
        _require_live_inbound_provider_fence()
        _feedback(uid, from_id, kind, payload, message_key=message_key)
        _require_live_inbound_provider_fence()
        deliver("收到反馈，谢谢👌", "feedback")
        return
    latest_access, latest_owner, _access_error = _refresh_access()
    if not latest_access.permits(from_id):
        return
    uid = resolve_user_id(from_id, latest_owner)
    # The engine may create an upstream video task before returning its task_id.
    # Reserve durable capacity first so a successful creation can always be
    # converted into a recoverable pending row instead of becoming an orphan.
    video_capacity_available = True
    try:
        _reserve_pending_video_capacity(
            from_id,
            ctx,
            source_message_key=message_key,
        )
    except VideoCapacityError:
        # Capacity is a transient permission, not a reason to block ordinary
        # chat.  The authenticated engine contract must classify first and
        # fast-reject only video intent without creating an upstream job.
        video_capacity_available = False
    done = threading.Event()
    progress_thread = threading.Thread(
        target=_progress_notice,
        args=(
            done,
            token,
            from_id,
            ctx,
            f"{message_key}:progress",
            (
                getattr(_HANDLE_CONTEXT, "lease_session", None).before_provider
                if getattr(_HANDLE_CONTEXT, "lease_session", None) is not None
                else None
            ),
            (
                int(getattr(_HANDLE_CONTEXT, "claim_id", 0) or 0),
                str(getattr(_HANDLE_CONTEXT, "claim_token", "") or ""),
                int(getattr(_HANDLE_CONTEXT, "claim_epoch", 0) or 0),
                getattr(_HANDLE_CONTEXT, "lease_session", None),
            )
            if getattr(_HANDLE_CONTEXT, "lease_session", None) is not None
            else None,
        ),
        name="weixin-progress-notice",
        daemon=True,
    )
    progress_thread.start()
    progress_stuck = False
    try:
        _require_live_inbound_provider_fence()
        d = _agent_chat(
            payload,
            uid,
            from_id,
            message_key,
            video_async_capacity_available=video_capacity_available,
        )
        _require_live_inbound_provider_fence()
        task_id = d.get("video_task")
        if task_id and not d.get("video"):
            if not video_capacity_available:
                raise RuntimeError("引擎在异步视频容量关闭时仍创建了任务")
            # Persist before acknowledging the accepted async job.  If this write
            # cannot be committed, the durable inbound turn is retried instead of
            # telling the user that a result will arrive and then losing it.
            _enqueue_pending_video(
                task_id,
                from_id,
                ctx,
                source_message_key=message_key,
            )
        elif video_capacity_available:
            _release_pending_video_reservation(message_key)
    finally:
        done.set()
        progress_thread.join(_PROGRESS_SETTLE_TIMEOUT_SECONDS)
        progress_stuck = progress_thread.is_alive()
    if progress_stuck:
        # Sending the final reply concurrently could place the older progress
        # notice after it.  Keep the final reply durable-retryable instead.
        raise RuntimeError("微信进度提示未在有界时间内收口")
    reply = d.get("reply") or "(空回复)"
    deliver(reply, "reply")
    _send_generated_media(
        token,
        from_id,
        ctx,
        d,
        delivery_key=f"{message_key}:generated",
    )  # 生图/生视频真发进微信


_HANDLE_FAILURE = threading.local()


def _handle_safe(msg: dict, token: str) -> bool:
    """线程入口：包异常，单条消息崩不影响长轮询与别的消息。"""
    try:
        _handle(msg, token)
        _HANDLE_FAILURE.error = None
        return True
    except Exception as e:  # noqa: BLE001
        _HANDLE_FAILURE.error = e
        print(f"[handle FAIL] {_error_code(type(e).__name__)}", flush=True)
        return False


def _handle_result(msg: dict, token: str) -> tuple[bool, Exception | None]:
    """Return the compatibility bool together with this worker's root cause."""

    _HANDLE_FAILURE.error = None
    ok = _handle_safe(msg, token)
    error = getattr(_HANDLE_FAILURE, "error", None)
    if not ok and not isinstance(error, Exception):
        error = RuntimeError("handler failed")
    _HANDLE_FAILURE.error = None
    return ok, error


def _inbound_worker(token_ref: dict[str, str], stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            claimed = _claim_inbound()
        except Exception as e:  # noqa: BLE001
            try:
                _update_health(
                    "degraded",
                    last_error=f"inbound_claim: {type(e).__name__}: {e}"[:500],
                )
            except Exception:  # noqa: BLE001 - health failure must not kill a worker
                pass
            stop.wait(1.0)
            continue
        if claimed is None:
            stop.wait(0.5)
            continue
        row_id, message, claim_token, claim_epoch = claimed
        lease_session = _new_inbound_lease_session(
            row_id,
            claim_token,
            claim_epoch,
            stop,
        )
        if not lease_session.start():
            lease_session.close()
            continue
        _HANDLE_CONTEXT.claim_id = row_id
        _HANDLE_CONTEXT.claim_token = claim_token
        _HANDLE_CONTEXT.claim_epoch = claim_epoch
        _HANDLE_CONTEXT.claim_message_key = str(message["_nachuan_message_key"])
        _HANDLE_CONTEXT.lease_session = lease_session
        try:
            claim_access, _claim_owner, _claim_error = _refresh_access()
            unauthorized_at_claim = not claim_access.permits(
                message.get("from_user_id", "")
            )
            ok, handler_error = _handle_result(message, token_ref["value"])
        except Exception as e:  # noqa: BLE001
            ok = False
            unauthorized_at_claim = False
            handler_error = e
        if lease_session.lost and ok:
            ok = False
            handler_error = InboundFinishFenceLost("inbound_provider_fence_lost")

        # Loading and validating the access file can block on filesystem I/O.
        # Keep it outside ClaimLeaseSession.finish(), whose clock is reserved for
        # the durable SQLite finish and exact response-loss confirmation.
        with _ACCESS_LOCK:
            access_generation_before_refresh = _ACCESS_GENERATION
        refreshed_access, _finish_owner, _finish_access_error = _refresh_access()
        outcome = _InboundFinishRequest(
            ok=ok,
            error=handler_error,
            unauthorized_at_claim=unauthorized_at_claim,
            access_generation_before_refresh=access_generation_before_refresh,
            refreshed_access=refreshed_access,
        )
        try:
            committed = lease_session.finish(outcome)
        finally:
            lease_session.close()
            for name in (
                "claim_id",
                "claim_token",
                "claim_epoch",
                "claim_message_key",
                "lease_session",
            ):
                try:
                    delattr(_HANDLE_CONTEXT, name)
                except AttributeError:
                    pass
        if stop.is_set() or not committed:
            continue
        try:
            with _HEALTH_LOCK:
                health_state = str(_HEALTH_STATE["service_state"])
            _update_health(
                health_state if ok else "degraded",
                last_message_finished_at=time.time(),
                last_handler_ok=ok,
                last_error=(
                    ""
                    if handler_error is None
                    else f"{type(handler_error).__name__}: {handler_error}"[:500]
                ),
            )
        except Exception:  # noqa: BLE001 - delivery workers must outlive health I/O
            pass
        if not ok:
            # ``_finish_inbound`` has already committed the stable retry or
            # terminal notice into the outbox. Do not wait for the unrelated
            # 40-second getupdates poll to return before making one bounded
            # delivery attempt; any failure remains durable for the main
            # drainer and must never re-enter the provider.
            try:
                _drain_outbox(token_ref["value"], limit=20)
            except Exception as delivery_error:  # noqa: BLE001
                try:
                    _update_health(
                        "degraded",
                        last_handler_ok=False,
                        last_error=(
                            "inbound_failure_notice: "
                            f"{type(delivery_error).__name__}: {delivery_error}"
                        )[:500],
                    )
                except Exception:  # noqa: BLE001
                    pass


def _start_inbound_workers(token_ref: dict[str, str]) -> threading.Event:
    global _INBOUND_WORKERS_CONFIGURED
    stop = threading.Event()
    worker_count = max(1, min(int(os.environ.get("WEIXIN_WORKERS", "4")), 16))
    workers = [
        threading.Thread(
            target=_inbound_worker,
            args=(token_ref, stop),
            name=f"weixin-worker-{index + 1}",
            daemon=True,
        )
        for index in range(worker_count)
    ]
    with _INBOUND_WORKER_LOCK:
        _INBOUND_WORKERS_CONFIGURED = worker_count
        _INBOUND_WORKERS[:] = workers
    for worker in workers:
        worker.start()
    return stop


def _main_locked() -> None:
    global ENGINE_KEY
    ENGINE_KEY = _resolve_engine_key()
    if not ENGINE_KEY:
        print("[warning] 没找到引擎认的 Key——引擎没跑？或 8080 是旧引擎；请结束监听 8080 的旧进程后重启纳川。", flush=True)
    else:
        print("引擎 Key 已锁定（值不写日志）。", flush=True)
    _refresh_engine_availability(force=True)
    access, _owner, _access_error = _refresh_access()
    if not access.configured:
        print(
            "[secure] 微信已锁定：先发 /whoami 获取标识，再写入 data/weixin_access.json 白名单。"
            "仅本地开发可同时设置 NACHUAN_ENV=development 与 WEIXIN_ALLOW_ALL=1。",
            flush=True,
        )
    print(f"纳川引擎：{ENGINE}  模型：{MODEL}", flush=True)
    token = _login()
    token_ref = {"value": token}
    _recover_inbound(force=True)
    try:
        maintenance = _maybe_terminal_maintenance(force=True) or {}
        if sum(maintenance.values()):
            print(f"微信终态库清理：{maintenance}", flush=True)
    except Exception as exc:  # noqa: BLE001 - maintenance failure must degrade, not stop delivery
        print(f"[终态库清理 FAIL] {type(exc).__name__}", flush=True)
    worker_stop = _start_inbound_workers(token_ref)
    _start_video_workers(token_ref, worker_stop)
    _update_health("starting", started_at=time.time(), consecutive_poll_failures=0, last_error="")
    print("开始收微信消息(长轮询)...  Ctrl+C 退出。", flush=True)
    cursor = _load_cursor()
    fails = 0
    while True:
        try:
            _maybe_terminal_maintenance()
        except Exception as exc:  # noqa: BLE001
            _update_health(
                "degraded",
                last_error=f"terminal_maintenance: {type(exc).__name__}"[:500],
            )
        try:
            _drain_outbox(token_ref["value"])
        except Exception as e:  # noqa: BLE001
            print("[outbox FAIL]", type(e).__name__, flush=True)
            _update_health(
                "degraded", last_error=f"{type(e).__name__}: {e}"[:500]
            )
        try:
            r = _ilink(
                "POST",
                "/ilink/bot/getupdates",
                {"get_updates_buf": cursor, "base_info": _base_info()},
                token=token_ref["value"],
                timeout=40,
            )
            _ensure_ilink_success(r, "getupdates")
            fails = 0
        except urllib.error.HTTPError as e:  # token 失效等 → 删缓存重新扫码
            if e.code in (401, 403):
                print("登录态失效，重新扫码…", flush=True)
                try:
                    _TOKEN_FILE.unlink(missing_ok=True)
                except Exception:  # noqa: BLE001
                    pass
                token_ref["value"] = _login()
                continue
            fails += 1
            _update_health(
                "degraded",
                consecutive_poll_failures=fails,
                last_error=f"HTTPError: {e.code}"[:500],
            )
            time.sleep(min(3 * fails, 15))
            continue
        except ILinkDeliveryError as e:
            if e.errcode == -14:
                print("登录态失效，重新扫码…", flush=True)
                _TOKEN_FILE.unlink(missing_ok=True)
                token_ref["value"] = _login()
                continue
            fails += 1
            print("getupdates 业务失败，重试…", e, flush=True)
            _update_health(
                "degraded",
                consecutive_poll_failures=fails,
                last_error=f"{type(e).__name__}: {e}"[:500],
            )
            time.sleep(min(2 * fails, 15))
            continue
        except Exception as e:  # noqa: BLE001  长轮询超时/抖动 → 稍等续拉
            fails += 1
            if fails <= 1 or fails % 5 == 0:
                print("getupdates 抖动，重试…", e, flush=True)
            _update_health(
                "degraded",
                consecutive_poll_failures=fails,
                last_error=f"{type(e).__name__}: {e}"[:500],
            )
            time.sleep(min(2 * fails, 15))
            continue
        next_cursor = r.get("get_updates_buf", cursor) or cursor
        try:
            stored = _store_updates(list(r.get("msgs") or []), next_cursor)
        except InboundSemanticConflict as exc:
            _update_health(
                "degraded",
                consecutive_poll_failures=0,
                last_error=str(exc),
            )
            time.sleep(1)
            continue
        if not stored:
            _update_health(
                "degraded",
                consecutive_poll_failures=0,
                last_error="durable_budget_exhausted",
            )
            time.sleep(1)
            continue
        cursor = next_cursor
        _refresh_engine_availability()
        _update_health(
            "healthy",
            last_poll_ok_at=time.time(),
            consecutive_poll_failures=0,
            last_error="",
        )


def main() -> None:
    lock = BridgeInstanceLock()
    if not lock.acquire():
        raise RuntimeError("微信桥接已在运行；拒绝启动第二个会重复收发的实例")
    try:
        # Holding the process mutex proves no live bridge owns these row leases.
        _recover_delivery_claims(force=True)
        _recover_pending_video_claims(force=True)
        _main_locked()
    finally:
        lock.release()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已退出。", flush=True)
