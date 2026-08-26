"""飞书桥接（长连接）：私聊/群@ → 超级智能体引擎(/v1/agent/chat) → 回复。无需公网。

需 FEISHU_APP_ID / FEISHU_APP_SECRET（启动时经 env 传入）。飞书后台需开启：
  ① 权限 im:message + im:message:send_as_bot；② 事件 im.message.receive_v1；③ 长连接接收。

特性：按用户隔离记忆（user_id=open_id，机主归一为 'owner' 与桌面共享）；
白名单 + 每用户限频（防群里烧额度）；命令 /whoami、👍/👎 反馈。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import logging
import math
import os
import queue
import re
import socket
import sqlite3
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_NACHUAN_FEISHU_STATE_ONLY = bool(
    globals().get("_NACHUAN_FEISHU_STATE_ONLY", False)
)
if _NACHUAN_FEISHU_STATE_ONLY:
    # The Gateway recovery coordinator needs only the exact SQLite authority.
    # Loading the very large SDK in its request path can take minutes on a cold
    # Windows host and creates an unnecessary channel-capability surface.
    lark = None
    _lark_logger = logging.getLogger("nachuan-feishu-state-only")
else:
    import lark_oapi as lark  # noqa: E402
    from lark_oapi.api.im.v1 import (  # noqa: E402
        CreateFileRequest,
        CreateFileRequestBody,
        CreateImageRequest,
        CreateImageRequestBody,
        CreateMessageRequest,
        CreateMessageRequestBody,
        GetMessageResourceRequest,
        P2ImMessageReceiveV1,
    )
    from lark_oapi.core.log import logger as _lark_logger  # noqa: E402

from bridge.policy import (  # noqa: E402
    RateLimiter,
    is_allowed,
    parse_command,
    resolve_user_id,
)
from gateway.bridge_protocol import (  # noqa: E402
    MAX_PLAINTEXT_REQUEST_BYTES,
    request_bridge_bytes,
)
from gateway.channel_delivery_claim import (  # noqa: E402
    ClaimLeaseLost,
    ClaimLeaseSession,
)
from gateway.channel_media_protocol import (  # noqa: E402
    MAX_CHANNEL_MEDIA_METADATA_BYTES,
    encode_channel_media_frame,
)
from gateway.config import get_isolated_bridge_settings  # noqa: E402
from gateway.public_media import PublicFetchError, fetch_public_bytes  # noqa: E402
from gateway.sqlite_runtime import enable_wal_with_deadline  # noqa: E402
from orchestrator.media import detect_media_intent  # noqa: E402

_LOG_SECRET_VALUE = re.compile(
    r"(?i)(\b(?:access_key|ticket|app_secret|(?:access|refresh|tenant|app|bot|user)?_?token)\b"
    r"(?:\s*(?:=|:)|%3[dD])\s*[\"']?)([^&\s\"',}\]]+)"
)
_LOG_BEARER_VALUE = re.compile(r"(?i)(\bBearer\s+)([^\s,;]+)")


def _redact_log_text(value: object) -> str:
    """Remove connection/session credentials before text reaches a log handler."""

    text = str(value or "")
    text = _LOG_SECRET_VALUE.sub(lambda match: f"{match.group(1)}[redacted]", text)
    return _LOG_BEARER_VALUE.sub(lambda match: f"{match.group(1)}[redacted]", text)


class FeishuSecretRedactionFilter(logging.Filter):
    """Fail closed: redact the rendered record and discard unsafe tracebacks."""

    _nachuan_feishu_secret_filter = True

    def filter(self, record: logging.LogRecord) -> bool:
        rendered = _redact_log_text(record.getMessage())
        if record.exc_info:
            rendered = f"{rendered} exception={record.exc_info[0].__name__}"
        record.msg = rendered
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        return True


def _install_lark_log_security() -> logging.Logger:
    """Keep the SDK at ERROR and redact every record before any handler emits it."""

    targets: list[logging.Filterer] = [_lark_logger, *_lark_logger.handlers]
    for target in targets:
        if not any(
            getattr(item, "_nachuan_feishu_secret_filter", False)
            for item in target.filters
        ):
            target.addFilter(FeishuSecretRedactionFilter())
    _lark_logger.setLevel(logging.ERROR)
    return _lark_logger


_install_lark_log_security()

S = get_isolated_bridge_settings()
ENGINE = S.bridge_engine_url.rstrip("/")
# Empty means "let the authenticated gateway choose from the currently
# verified chat routes".  Only an explicit operator override may pin Feishu to
# one model; a library default must not freeze every Turn after connections
# change.
MODEL = str(
    os.environ.get("FEISHU_MODEL") or os.environ.get("BRIDGE_MODEL") or ""
).strip()
ENGINE_KEY = S.bridge_api_key
_limiter = RateLimiter(S.feishu_rate_per_min)
_api: dict[str, lark.Client] = {}
_STATE_DB = Path(S.usage_db_path).parent / "feishu_bridge.db"
_HEALTH_FILE = Path(S.usage_db_path).parent / "feishu_bridge_health.json"
_ACCESS_FILE = Path(S.usage_db_path).parent / "feishu_access.json"
_FEISHU_UUID_NAMESPACE = uuid.UUID("63e9ef4f-4bb6-4fbe-8918-d11a40b2358d")
_DELIVERY_CONTEXT = threading.local()
_HEALTH_LOCK = threading.RLock()
_HEALTH_STATE: dict[str, object] = {
    "connected": False,
    "service_state": "starting",
    "consecutive_reconnect_failures": 0,
    "last_connected_at": 0.0,
    "last_event_received_at": 0.0,
    "last_message_finished_at": 0.0,
    "last_error_code": "",
    "connection_generation": 0,
}
_ACCESS_CONFIGURED = False
_ENGINE_AVAILABLE = False
_ENGINE_READINESS_REASON = "engine_unavailable"
_CURRENT_WS: object | None = None
_FEISHU_TURN_KEY_DOMAIN = b"nachuan-feishu-provider-message-v1\x00"
_VISION_DEFAULT_QUESTION = (
    "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。"
)
_MAX_INBOUND_AUDIO_BYTES = 32 * 1024 * 1024
_MAX_INBOUND_IMAGE_BYTES = 20 * 1024 * 1024
_MAX_INBOUND_VIDEO_BYTES = (
    MAX_PLAINTEXT_REQUEST_BYTES - MAX_CHANNEL_MEDIA_METADATA_BYTES - 4
)
_MAX_GENERATED_IMAGE_BYTES = 20 * 1024 * 1024
_MAX_GENERATED_VIDEO_BYTES = 128 * 1024 * 1024
_MEDIA_TOTAL_TIMEOUT_SECONDS = 120.0
_MEDIA_IDLE_TIMEOUT_SECONDS = 30.0
# The Gateway's 55s Agent deadline is followed by a fenced, intentionally
# uncancellable durable commit tail.  Reserve enough wall time for that tail;
# an 8s progress notice keeps authorized text users informed meanwhile.
_AGENT_TURN_HTTP_TIMEOUT_SECONDS = 90.0
_STATE_DB_MAX_BYTES = 256 * 1024 * 1024
_STATE_WAL_MAX_BYTES = 16 * 1024 * 1024
_STATE_WAL_AUTOCHECKPOINT_PAGES = 512
_STATE_SCHEMA_VERSION = 5
_STATE_LEGACY_SCHEMA_VERSIONS = frozenset({0, 2, 3, 4})
_STATE_STRUCTURAL_SCHEMA_VERSIONS = frozenset({2, 3, 4})
# Claims are deliberately short and renewable.  The grace period is only for
# the reclaimer; ownership itself ends at claim_deadline.
_CLAIM_TTL_SECONDS = 30.0
_CLAIM_GRACE_SECONDS = 5.0
_CLAIM_HEARTBEAT_SECONDS = 5.0
_FINISH_RETRY_DELAYS_SECONDS = (0.0, 0.05, 0.2, 0.5)
_MAX_ACTIVE_INBOUND_ROWS = 10_000
_MAX_ACTIVE_OUTBOUND_ROWS = 10_000
_MAX_ACTIVE_INBOUND_PER_CHAT = 256
_MAX_ACTIVE_OUTBOUND_PER_CHAT = 512
_MAX_RECOVERY_RECEIPTS = 50_000
_READINESS_ERROR_MAX_BYTES = 64 * 1024
_RECOVERY_TOMBSTONE = '{"state":"closed_without_replay","version":1}'
_RECOVERY_OPERATION_DOMAIN = b"nachuan.feishu.close-without-replay.operation/v1\x00"
_RECOVERY_SET_DOMAIN = b"nachuan.feishu.close-without-replay.affected-set/v1\x00"
_RECOVERY_ROW_DOMAIN = b"nachuan.feishu.close-without-replay.row/v1\x00"
_RECOVERY_RECEIPT_DOMAIN = b"nachuan.feishu.close-without-replay.receipt/v1\x00"
_INBOUND_RETRYING_NOTICE = "消息处理遇到问题，正在自动重试，请稍候。"
_INBOUND_TERMINAL_NOTICE = (
    "消息处理多次失败，本次请求未完成。"
    "请稍后重新发送，或联系管理员检查纳川服务状态。"
)
_TEXT_PROGRESS_NOTICE = "还在处理中，我会继续处理并尽快回复，请稍候。"
_TEXT_PROGRESS_AFTER_SECONDS = 8.0
_ACCESS_GUIDANCE_NOTICE = (
    "纳川尚未为此账号开通使用权限。"
    "请联系管理员完成接入，或发送 /whoami 获取你的飞书标识。"
)
_ACCESS_GUIDANCE_INTERVAL_SECONDS = 60.0
_ACCESS_GUIDANCE_MAX_KEYS = 10_000
_ACCESS_GUIDANCE_LOCK = threading.Lock()
_ACCESS_GUIDANCE_LAST_SENT: dict[str, float] = {}


class FeishuQueueFull(RuntimeError):
    """A durable Feishu queue reached a configured hard capacity."""


class FeishuLeaseLost(RuntimeError):
    """The inbound worker no longer owns the durable Turn."""


class FeishuProviderRejected(RuntimeError):
    """Feishu returned an explicit business rejection before delivery."""


class FeishuProviderOutcomeUnknown(RuntimeError):
    """The provider may have accepted a request whose response is unavailable."""


class FeishuMediaUploadOutcomeUnknown(FeishuProviderOutcomeUnknown):
    """A Feishu image/file upload may have created an untracked remote asset."""


class FeishuRecoveryConflict(RuntimeError):
    """A manual no-replay decision conflicts with the durable queue truth."""


class _FeishuCloseWithoutReplayRequest(NamedTuple):
    operation_digest: str
    decision_id: str
    target_kind: str
    target_key: str
    expected_before_digest: str
    actor: str
    authorization: str
    reason: str
    decided_at_ms: int


class _FeishuCloseWithoutReplayResult(NamedTuple):
    operation_digest: str
    receipt_sha256: str
    affected_inbox_count: int
    affected_outbox_count: int
    affected_video_count: int
    applied: bool


_InboxFinishOutcome = tuple[bool, str] | tuple[bool, str, bool]
_OutboxFinishOutcome = tuple[bool, str] | tuple[bool, str, bool]


def _build_engine_opener():
    """Bearer-bearing loopback requests must never honor HTTP(S)_PROXY."""

    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


_ENGINE_OPENER = _build_engine_opener()


def _engine_open(request: urllib.request.Request, *, timeout: float):
    return _ENGINE_OPENER.open(request, timeout=timeout)


def _read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    before = os.lstat(path)
    reparse = int(getattr(before, "st_file_attributes", 0)) & 0x400
    if not stat.S_ISREG(before.st_mode) or reparse or path.is_symlink():
        raise ValueError("Feishu access policy must be a regular non-link file")
    if before.st_size < 0 or before.st_size > max_bytes:
        raise ValueError("Feishu access policy exceeds size limit")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size < 0
            or opened.st_size > max_bytes
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("Feishu access policy identity changed")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if (
            total > max_bytes
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
            or after.st_size != total
            or getattr(after, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            raise ValueError("Feishu access policy changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _valid_access_id(value: object, *, allow_empty: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    if not value:
        return "" if allow_empty else None
    if value != value.strip() or len(value.encode("utf-8")) > 512:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _load_access_document() -> tuple[frozenset[str], str]:
    raw = _read_regular_file(_ACCESS_FILE, max_bytes=64 * 1024)
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "allowed_users",
        "owner",
    }:
        raise ValueError("invalid Feishu access policy fields")
    if document["schema"] != "nachuan.feishu-access.v1":
        raise ValueError("invalid Feishu access policy schema")
    users = document["allowed_users"]
    if not isinstance(users, list) or len(users) > 256:
        raise ValueError("invalid Feishu access policy user list")
    normalized: list[str] = []
    for value in users:
        user = _valid_access_id(value)
        if user is None:
            raise ValueError("invalid Feishu access policy user")
        normalized.append(user)
    owner = _valid_access_id(document["owner"], allow_empty=True)
    if owner is None:
        raise ValueError("invalid Feishu access policy owner")
    return frozenset(normalized), owner


def _load_feishu_access() -> tuple[frozenset[str], str]:
    try:
        allowed, owner = _load_access_document()
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        allowed, owner = frozenset(), ""
    if os.getenv("NACHUAN_ENV", "").strip().lower() != "development":
        return allowed, owner

    legacy_values = [
        value.strip()
        for value in str(getattr(S, "feishu_allowed_users", "") or "").split(",")
        if value.strip()
    ]
    legacy_owner = _valid_access_id(
        getattr(S, "feishu_owner_open_id", ""), allow_empty=True
    )
    if len(legacy_values) > 256 or legacy_owner is None:
        return frozenset(), ""
    merged = set(allowed)
    for value in legacy_values:
        user = _valid_access_id(value)
        if user is None:
            return frozenset(), ""
        merged.add(user)
    if legacy_owner:
        if owner:
            merged.add(legacy_owner)
        else:
            owner = legacy_owner
    if len(merged) > 256:
        return frozenset(), ""
    return frozenset(merged), owner


def _refresh_access_configured() -> bool:
    """Refresh the fail-closed access-policy readiness bit without retaining IDs."""

    allowed, owner = _load_feishu_access()
    configured = bool(allowed or owner)
    global _ACCESS_CONFIGURED
    with _HEALTH_LOCK:
        _ACCESS_CONFIGURED = configured
    return configured


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
    with _HEALTH_LOCK:
        _ENGINE_AVAILABLE = available
        _ENGINE_READINESS_REASON = normalized_reason


def _probe_engine_available(*, timeout: float = 3.0) -> bool:
    """Authenticate the scoped bridge key against the exact loopback health route."""

    if not str(ENGINE_KEY or "").strip():
        _set_engine_available(False, "engine_unavailable")
        return False
    try:
        bounded_timeout = max(0.1, min(float(timeout), 5.0))
    except (TypeError, ValueError, OverflowError):
        bounded_timeout = 3.0
    available = False
    reason = "engine_unavailable"
    try:
        health_url = f"{ENGINE}/v1/bridge/health"
        if MODEL:
            health_url += "?model=" + urllib.parse.quote(MODEL, safe="")
        raw = request_bridge_bytes(
            _ENGINE_OPENER,
            url=health_url,
            secret=ENGINE_KEY,
            channel="feishu",
            method="GET",
            body=b"",
            timeout=bounded_timeout,
            max_response_bytes=64 * 1024,
        )
        document = json.loads(raw.decode("utf-8"))
        expected_fields = {"status", "channel", "chat_ready", "reason"}
        valid_envelope = bool(
            isinstance(document, dict)
            and set(document) == expected_fields
            and document.get("status") == "ok"
            and document.get("channel") == "feishu"
        )
        chat_ready = document.get("chat_ready") if isinstance(document, dict) else None
        reported_reason = (
            str(document.get("reason") or "") if isinstance(document, dict) else ""
        )
        available = bool(
            valid_envelope
            and type(chat_ready) is bool
            and chat_ready
            and reported_reason == "ready"
        )
        if available:
            reason = "ready"
        elif (
            valid_envelope
            and type(chat_ready) is bool
            and chat_ready is False
            and reported_reason
            in {"ready_no_model", "requested_model_unavailable"}
        ):
            reason = reported_reason
    except Exception:  # noqa: BLE001 - any malformed/unavailable local probe fails closed
        available = False
        reason = "engine_unavailable"
    _set_engine_available(available, reason)
    return available


def _refresh_runtime_readiness() -> None:
    _refresh_access_configured()
    _probe_engine_available()


def _require_live_inbound_provider_fence() -> None:
    """Synchronously renew the active inbox lease around a provider seam."""

    if not str(getattr(_DELIVERY_CONTEXT, "message_id", "") or ""):
        return
    guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
    permit = getattr(guard, "permits_provider", None)
    if not callable(permit):
        raise FeishuLeaseLost("inbound_provider_fence_lost")
    try:
        permitted = bool(permit())
    except FeishuLeaseLost:
        raise
    except Exception as exc:  # noqa: BLE001 - uncertain ownership fails closed
        raise FeishuLeaseLost("inbound_provider_fence_lost") from exc
    if not permitted:
        raise FeishuLeaseLost("inbound_provider_fence_lost")


def _call_with_inbound_provider_fence(callback):  # noqa: ANN001, ANN202
    _require_live_inbound_provider_fence()
    try:
        return callback()
    finally:
        # If the call completed after ownership was lost, discard its response
        # and prevent every downstream completion/side effect in this worker.
        _require_live_inbound_provider_fence()


def _inbound_media_upload_request_sha256(
    kind: str,
    data: bytes,
    *,
    name: str,
    ftype: str,
) -> str:
    document = {
        "schema": "nachuan.feishu-inbound-media-upload.v1",
        "kind": str(kind),
        "file_name": str(name),
        "file_type": str(ftype),
        "body_sha256": hashlib.sha256(data).hexdigest(),
    }
    encoded = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _begin_inbound_media_upload_submission(
    kind: str,
    data: bytes,
    *,
    name: str,
    ftype: str,
) -> str:
    message_id = str(getattr(_DELIVERY_CONTEXT, "message_id", "") or "")
    if not message_id:
        return ""
    claim_id = int(getattr(_DELIVERY_CONTEXT, "claim_id", 0) or 0)
    claim_token = str(getattr(_DELIVERY_CONTEXT, "claim_token", "") or "")
    claim_epoch = int(getattr(_DELIVERY_CONTEXT, "claim_epoch", 0) or 0)
    guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
    fence_factory = getattr(guard, "commit_fence", None)
    if claim_id < 1 or not claim_token or claim_epoch < 1 or not callable(
        fence_factory
    ):
        raise FeishuLeaseLost("incomplete Feishu inbound media lease context")
    request_sha256 = _inbound_media_upload_request_sha256(
        kind,
        data,
        name=name,
        ftype=ftype,
    )
    verification = f"feishu_media_upload_request_sha256:{request_sha256}"
    with fence_factory():
        with _state_write_transaction() as conn:
            current = _policy_time()
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status='submitting',last_error='media_upload_submitting',
                    terminal_verification=?
                WHERE id=? AND message_id=? AND status='processing'
                  AND claim_token=? AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    verification,
                    claim_id,
                    message_id,
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
    if changed != 1:
        raise FeishuLeaseLost("Feishu inbound media submission fence was lost")
    _DELIVERY_CONTEXT.media_submission_sha256 = request_sha256
    return request_sha256


def _complete_inbound_media_upload_submission(request_sha256: str) -> None:
    digest = str(request_sha256 or "")
    if not digest:
        return
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid Feishu inbound media upload receipt")
    message_id = str(getattr(_DELIVERY_CONTEXT, "message_id", "") or "")
    claim_id = int(getattr(_DELIVERY_CONTEXT, "claim_id", 0) or 0)
    claim_token = str(getattr(_DELIVERY_CONTEXT, "claim_token", "") or "")
    claim_epoch = int(getattr(_DELIVERY_CONTEXT, "claim_epoch", 0) or 0)
    guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
    fence_factory = getattr(guard, "commit_fence", None)
    if not message_id or claim_id < 1 or not claim_token or not callable(fence_factory):
        raise FeishuLeaseLost("incomplete Feishu inbound media lease context")
    verification = f"feishu_media_upload_request_sha256:{digest}"
    with fence_factory():
        with _state_write_transaction() as conn:
            current = _policy_time()
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status='processing',last_error='',terminal_verification=''
                WHERE id=? AND message_id=? AND status='submitting'
                  AND terminal_verification=? AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    claim_id,
                    message_id,
                    verification,
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
    if changed != 1:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu upload completed before durable handoff"
        )
    _DELIVERY_CONTEXT.media_submission_sha256 = ""


def _abort_inbound_media_upload_submission(request_sha256: str) -> None:
    """Return a definitely rejected pre-asset upload to normal processing."""

    _complete_inbound_media_upload_submission(request_sha256)


def _post(path: str, payload: dict, timeout: int = 300) -> dict:
    body = json.dumps(payload).encode()
    raw = _call_with_inbound_provider_fence(
        lambda: request_bridge_bytes(
            _ENGINE_OPENER,
            url=f"{ENGINE}{path}",
            secret=ENGINE_KEY,
            channel="feishu",
            method="POST",
            body=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    )
    return json.loads(raw.decode("utf-8"))


def _post_binary(path: str, body: bytes, timeout: int) -> dict:
    """Send binary plaintext through the authenticated AES-GCM bridge."""

    raw = _call_with_inbound_provider_fence(
        lambda: request_bridge_bytes(
            _ENGINE_OPENER,
            url=f"{ENGINE}{path}",
            secret=ENGINE_KEY,
            channel="feishu",
            method="POST",
            body=body,
            headers={"Content-Type": "application/octet-stream"},
            timeout=timeout,
        )
    )
    return json.loads(raw.decode("utf-8"))


def _get(path: str, timeout: int = 30) -> dict:
    raw = request_bridge_bytes(
        _ENGINE_OPENER,
        url=f"{ENGINE}{path}",
        secret=ENGINE_KEY,
        channel="feishu",
        method="GET",
        body=b"",
        timeout=timeout,
    )
    return json.loads(raw.decode("utf-8"))


def _feishu_idempotency_key(message_id: object, chat_id: object) -> str:
    """Bind a provider message to one Feishu conversation without retaining it."""

    values = (str(chat_id or ""), str(message_id or ""))
    if not values[0] or not values[1] or any(len(v.encode("utf-8")) > 512 for v in values):
        raise ValueError("canonical Feishu chat_id and message_id are required")
    digest = hashlib.sha256(_FEISHU_TURN_KEY_DOMAIN)
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"fsmsg-v1:{digest.hexdigest()}"


def _active_feishu_idempotency_key(chat_id: str) -> str:
    return _feishu_idempotency_key(
        getattr(_DELIVERY_CONTEXT, "message_id", ""), chat_id
    )


def _allow_inbound(open_id: str) -> bool:
    """A durable retry is the same turn and must not consume rate limit twice."""

    if int(getattr(_DELIVERY_CONTEXT, "attempts", 0)) > 0:
        return True
    return _limiter.allow(open_id)


def _agent_chat(
    text: str,
    user_id: str,
    chat_id: str,
    video_async: bool = False,
    *,
    idempotency_key: str | None = None,
) -> dict:
    """返回引擎完整响应（含 reply / images / video / video_task）。
    video_async=True 时生视频只创建任务、立即回执，调用方拿 video_task 自己异步轮询（不卡几分钟、不超时丢结果）。
    """
    turn_key = idempotency_key or _active_feishu_idempotency_key(chat_id)
    if not re.fullmatch(r"fsmsg-v1:[0-9a-f]{64}", turn_key):
        raise ValueError("invalid Feishu idempotency key")
    payload = {
        "message": text,
        "user_id": user_id,
        "chat_id": chat_id,
        "channel": "feishu",
        "video_async": video_async,
        "idempotency_key": turn_key,
    }
    if MODEL:
        payload["model"] = MODEL
    try:
        return _post(
            "/v1/agent/chat",
            payload,
            timeout=_AGENT_TURN_HTTP_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as exc:
        # request_bridge_bytes raises HTTPError only after authenticating and
        # decrypting the response envelope.  Unknown failures retain durable
        # inbox retry semantics.
        if int(exc.code) != 503:
            raise
        raw = exc.read(_READINESS_ERROR_MAX_BYTES + 1)
        exc.fp = io.BytesIO(raw)
        if len(raw) > _READINESS_ERROR_MAX_BYTES:
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
                "⚠️ 飞书指定的模型当前不可用。请在纳川“连接中心”重新验证"
                "该模型，或清除飞书固定模型设置后再发送。"
            ),
        }
        if code not in replies or retryable is not False:
            raise
        _set_engine_available(False, code)
        return {
            "reply": replies[code],
            "model": "nachuan-readiness",
            "turns": 0,
            "usage": {},
            "blocked": True,
            "outcome": code,
        }


def _media_policy(kind: str) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    if kind == "audio":
        return _MAX_INBOUND_AUDIO_BYTES, ("audio/",), ("application/octet-stream",)
    if kind == "image":
        return _MAX_INBOUND_IMAGE_BYTES, ("image/",), ("application/octet-stream",)
    if kind == "video":
        return _MAX_INBOUND_VIDEO_BYTES, ("video/",), ("application/octet-stream",)
    raise ValueError("未知媒体类型")


def _header(headers, name: str) -> str:  # noqa: ANN001
    if headers is None:
        return ""
    try:
        direct = headers.get(name) or headers.get(name.lower())
        if direct:
            return str(direct).strip()
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value).strip()
        return ""
    except (AttributeError, TypeError):
        return ""


def _read_resource_stream(
    stream,
    *,
    headers,
    max_bytes: int,
    allowed_prefixes: tuple[str, ...],
    allowed_exact: tuple[str, ...],
) -> bytes:  # noqa: ANN001
    content_type = _header(headers, "content-type").split(";", 1)[0].lower()
    if content_type and not (
        content_type in allowed_exact
        or any(content_type.startswith(prefix) for prefix in allowed_prefixes)
    ):
        raise ValueError("飞书资源 Content-Type 不符合媒体类型")
    raw_length = _header(headers, "content-length")
    declared = None
    if raw_length:
        try:
            declared = int(raw_length)
        except ValueError as exc:
            raise ValueError("飞书资源 Content-Length 无效") from exc
        if declared < 0 or declared > max_bytes:
            raise ValueError("飞书资源超过大小上限")
    out = bytearray()
    while True:
        try:
            chunk = stream.read(min(64 * 1024, max_bytes - len(out) + 1))
        except TypeError as exc:
            raise ValueError("飞书资源流不支持限量读取") from exc
        if not chunk:
            if declared is not None and len(out) != declared:
                raise ValueError("飞书资源长度与 Content-Length 不一致")
            return bytes(out)
        out.extend(chunk)
        if len(out) > max_bytes:
            raise ValueError("飞书资源超过大小上限")


def _download_resource(
    message_id: str,
    file_key: str,
    ftype: str = "file",
    *,
    media_kind: str = "audio",
) -> bytes:
    """下载消息里的文件/图片资源（需 im:resource 权限）。"""
    max_bytes, allowed_prefixes, allowed_exact = _media_policy(media_kind)
    req = (
        GetMessageResourceRequest.builder()
        .message_id(message_id)
        .file_key(file_key)
        .type(ftype)
        .build()
    )
    _require_live_inbound_provider_fence()
    resp = _api["c"].im.v1.message_resource.get(req)
    f = getattr(resp, "file", None)
    if f is not None:
        if not hasattr(f, "read"):
            raise ValueError("飞书资源不是可限量读取的流")
        headers = getattr(f, "headers", None) or getattr(resp, "headers", None)
        data = _read_resource_stream(
            f,
            headers=headers,
            max_bytes=max_bytes,
            allowed_prefixes=allowed_prefixes,
            allowed_exact=allowed_exact,
        )
        _require_live_inbound_provider_fence()
        return data
    raw = getattr(resp, "raw", None)
    if raw is None:
        _require_live_inbound_provider_fence()
        return b""
    if not hasattr(raw, "read"):
        # raw.content has already been fully buffered by the SDK.  Checking len
        # afterwards cannot prevent memory exhaustion, so fail closed.
        raise ValueError("飞书 SDK 未提供可限量读取的资源流")
    data = _read_resource_stream(
        raw,
        headers=getattr(raw, "headers", None) or getattr(resp, "headers", None),
        max_bytes=max_bytes,
        allowed_prefixes=allowed_prefixes,
        allowed_exact=allowed_exact,
    )
    _require_live_inbound_provider_fence()
    return data


def _transcribe(data: bytes) -> str:
    raw = _call_with_inbound_provider_fence(
        lambda: request_bridge_bytes(
            _ENGINE_OPENER,
            url=f"{ENGINE}/v1/audio/transcriptions",
            secret=ENGINE_KEY,
            channel="feishu",
            method="POST",
            body=data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=120,
        )
    )
    return json.loads(raw.decode("utf-8")).get("text", "")


def _describe(
    data: bytes,
    *,
    message_id: str,
    user_id: str,
    chat_id: str,
) -> str:
    """图片 → 引擎看图理解 / OCR（#28）。"""
    frame = encode_channel_media_frame(
        channel="feishu",
        user_id=user_id,
        chat_id=chat_id,
        message_key=_feishu_idempotency_key(message_id, chat_id),
        operation="vision.describe",
        pipeline_version="vision.describe/v1",
        params={"question": _VISION_DEFAULT_QUESTION, "model": ""},
        raw=data,
    )
    result = _post_binary("/v1/vision", frame, timeout=120)
    if not isinstance(result, dict):
        raise RuntimeError("vision_response_invalid")
    text = result.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("vision_response_invalid")
    return text.strip()


def _lapian(
    data: bytes,
    *,
    message_id: str,
    user_id: str,
    chat_id: str,
) -> str:
    """视频 → 引擎拉片（#29），返回报告文本。"""
    frame = encode_channel_media_frame(
        channel="feishu",
        user_id=user_id,
        chat_id=chat_id,
        message_key=_feishu_idempotency_key(message_id, chat_id),
        operation="lapian.analyze",
        pipeline_version="lapian.analyze/v1",
        params={
            "vision_model": "agnes-flash",
            "synth_model": "",
            "max_frames": 40,
            "with_audio": True,
        },
        raw=data,
    )
    result = _post_binary("/v1/lapian", frame, timeout=600)
    if not isinstance(result, dict):
        raise RuntimeError("lapian_response_invalid")
    report = result.get("report")
    if not isinstance(report, str) or not report.strip():
        raise RuntimeError("lapian_response_invalid")
    return report.strip()


def _split(text: str, n: int = 3500) -> list[str]:
    return [text[i : i + n] for i in range(0, len(text), n)] or [""]


def _feedback(
    user_id: str,
    chat_id: str,
    rating: str,
    note: str = "",
    *,
    message_id: str,
) -> None:
    _post(
        "/v1/agent/feedback",
        {
            "user_id": user_id,
            "chat_id": chat_id,
            "channel": "feishu",
            "rating": rating,
            "note": note,
            "idempotency_key": message_id,
        },
        timeout=30,
    )


_STATE_COLUMN_DEFINITIONS = {
    "id": ("INTEGER", 0, None, 1, 0),
    "message_id": ("TEXT", 1, None, 0, 0),
    "delivery_uuid": ("TEXT", 1, None, 0, 0),
    "chat_id": ("TEXT", 1, None, 0, 0),
    "payload": ("TEXT", 1, None, 0, 0),
    "msg_type": ("TEXT", 1, None, 0, 0),
    "content": ("TEXT", 1, None, 0, 0),
    "received_at": ("REAL", 1, None, 0, 0),
    "created_at": ("REAL", 1, None, 0, 0),
    "next_attempt_at": ("REAL", 1, None, 0, 0),
    "attempts": ("INTEGER", 1, "0", 0, 0),
    "status": ("TEXT", 1, "'pending'", 0, 0),
    "last_error": ("TEXT", 1, "''", 0, 0),
    "claimed_at": ("REAL", 1, "0", 0, 0),
    "claim_token": ("TEXT", 1, "''", 0, 0),
    "claim_deadline": ("REAL", 1, "0", 0, 0),
    "heartbeat_at": ("REAL", 1, "0", 0, 0),
    "claim_epoch": ("INTEGER", 1, "0", 0, 0),
    "last_finish_token": ("TEXT", 1, "''", 0, 0),
    "last_finish_epoch": ("INTEGER", 1, "0", 0, 0),
    "last_finish_outcome": ("TEXT", 1, "''", 0, 0),
    "terminal_verification": ("TEXT", 1, "''", 0, 0),
    "closed_at": ("REAL", 1, "0", 0, 0),
    "finished_at": ("REAL", 1, "0", 0, 0),
    "delivered_at": ("REAL", 1, "0", 0, 0),
}

_STATE_TABLE_LAYOUTS = {
    "feishu_inbox": {
        (
            "id", "message_id", "chat_id", "payload", "received_at",
            "next_attempt_at", "attempts", "status", "last_error",
            "claimed_at", "claim_token", "claim_deadline", "heartbeat_at",
            "claim_epoch", "last_finish_token", "last_finish_epoch",
            "last_finish_outcome", "finished_at",
        ),
        # Canonical v0 -> current ALTER order retained for historical databases.
        (
            "id", "message_id", "chat_id", "payload", "received_at",
            "next_attempt_at", "attempts", "status", "last_error",
            "claimed_at", "finished_at", "claim_token", "claim_deadline",
            "heartbeat_at", "claim_epoch", "last_finish_token",
            "last_finish_epoch", "last_finish_outcome",
        ),
    },
    "feishu_outbox": {
        (
            "id", "delivery_uuid", "chat_id", "msg_type", "content",
            "created_at", "next_attempt_at", "attempts", "status",
            "last_error", "claimed_at", "claim_token", "claim_deadline",
            "heartbeat_at", "claim_epoch", "last_finish_token",
            "last_finish_epoch", "last_finish_outcome", "delivered_at",
        ),
        (
            "id", "delivery_uuid", "chat_id", "msg_type", "content",
            "created_at", "next_attempt_at", "attempts", "status",
            "last_error", "claimed_at", "delivered_at", "claim_token",
            "claim_deadline", "heartbeat_at", "claim_epoch",
            "last_finish_token", "last_finish_epoch", "last_finish_outcome",
        ),
    },
}


_STATE_V5_TABLE_LAYOUTS = {
    table: tuple((*layout, "terminal_verification", "closed_at") for layout in layouts)
    for table, layouts in _STATE_TABLE_LAYOUTS.items()
}


_STATE_V0_TABLE_LAYOUTS = {
    "feishu_inbox": (
        "id", "message_id", "chat_id", "payload", "received_at",
        "next_attempt_at", "attempts", "status", "last_error",
        "claimed_at", "finished_at",
    ),
    "feishu_outbox": (
        "id", "delivery_uuid", "chat_id", "msg_type", "content",
        "created_at", "next_attempt_at", "attempts", "status",
        "last_error", "claimed_at", "delivered_at",
    ),
}


_STATE_CANONICAL_COLUMN_SQL = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "message_id": "TEXT NOT NULL UNIQUE",
    "delivery_uuid": "TEXT NOT NULL UNIQUE",
    "chat_id": "TEXT NOT NULL",
    "payload": "TEXT NOT NULL",
    "msg_type": "TEXT NOT NULL",
    "content": "TEXT NOT NULL",
    "received_at": "REAL NOT NULL",
    "created_at": "REAL NOT NULL",
    "next_attempt_at": "REAL NOT NULL",
    "attempts": "INTEGER NOT NULL DEFAULT 0",
    "status": "TEXT NOT NULL DEFAULT 'pending'",
    "last_error": "TEXT NOT NULL DEFAULT ''",
    "claimed_at": "REAL NOT NULL DEFAULT 0",
    "claim_token": "TEXT NOT NULL DEFAULT ''",
    "claim_deadline": "REAL NOT NULL DEFAULT 0",
    "heartbeat_at": "REAL NOT NULL DEFAULT 0",
    "claim_epoch": "INTEGER NOT NULL DEFAULT 0",
    "last_finish_token": "TEXT NOT NULL DEFAULT ''",
    "last_finish_epoch": "INTEGER NOT NULL DEFAULT 0",
    "last_finish_outcome": "TEXT NOT NULL DEFAULT ''",
    "terminal_verification": "TEXT NOT NULL DEFAULT ''",
    "closed_at": "REAL NOT NULL DEFAULT 0",
    "finished_at": "REAL NOT NULL DEFAULT 0",
    "delivered_at": "REAL NOT NULL DEFAULT 0",
}


_RECOVERY_RECEIPT_TABLE_SQL = """
CREATE TABLE feishu_recovery_receipt (
    id INTEGER PRIMARY KEY,
    operation_digest TEXT NOT NULL CHECK(
        length(operation_digest)=64 AND
        operation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    decision_id TEXT NOT NULL CHECK(
        length(decision_id)=64 AND decision_id NOT GLOB '*[^0-9a-f]*'
    ),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('inbox','outbox')),
    target_key_sha256 TEXT NOT NULL CHECK(
        length(target_key_sha256)=64 AND
        target_key_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    chat_sha256 TEXT NOT NULL CHECK(
        length(chat_sha256)=64 AND chat_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
    authorization TEXT NOT NULL CHECK(
        length(authorization)=64 AND authorization NOT GLOB '*[^0-9a-f]*'
    ),
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 2048),
    decided_at_ms INTEGER NOT NULL CHECK(
        typeof(decided_at_ms)='integer' AND decided_at_ms>=0
    ),
    closed_at_ms INTEGER NOT NULL CHECK(
        typeof(closed_at_ms)='integer' AND closed_at_ms>=0
    ),
    affected_inbox_count INTEGER NOT NULL CHECK(affected_inbox_count>=0),
    affected_outbox_count INTEGER NOT NULL CHECK(affected_outbox_count>=0),
    before_digest TEXT NOT NULL CHECK(
        length(before_digest)=64 AND before_digest NOT GLOB '*[^0-9a-f]*'
    ),
    after_digest TEXT NOT NULL CHECK(
        length(after_digest)=64 AND after_digest NOT GLOB '*[^0-9a-f]*'
    ),
    affected_rows_json TEXT NOT NULL CHECK(
        length(affected_rows_json) BETWEEN 2 AND 1048576
    ),
    previous_receipt_sha256 TEXT NOT NULL CHECK(
        length(previous_receipt_sha256)=64 AND
        previous_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_sha256 TEXT NOT NULL CHECK(
        length(receipt_sha256)=64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK(affected_inbox_count + affected_outbox_count >= 1)
)
"""
_RECOVERY_RECEIPT_INDEX_SQL = {
    "uq_feishu_recovery_receipt_operation": (
        "CREATE UNIQUE INDEX uq_feishu_recovery_receipt_operation "
        "ON feishu_recovery_receipt(operation_digest)"
    ),
    "uq_feishu_recovery_receipt_decision": (
        "CREATE UNIQUE INDEX uq_feishu_recovery_receipt_decision "
        "ON feishu_recovery_receipt(decision_id)"
    ),
    "uq_feishu_recovery_receipt_sha256": (
        "CREATE UNIQUE INDEX uq_feishu_recovery_receipt_sha256 "
        "ON feishu_recovery_receipt(receipt_sha256)"
    ),
    "uq_feishu_recovery_receipt_previous_sha256": (
        "CREATE UNIQUE INDEX uq_feishu_recovery_receipt_previous_sha256 "
        "ON feishu_recovery_receipt(previous_receipt_sha256)"
    ),
    "idx_feishu_recovery_receipt_target": (
        "CREATE INDEX idx_feishu_recovery_receipt_target "
        "ON feishu_recovery_receipt(target_kind,target_key_sha256,id)"
    ),
}
_RECOVERY_RECEIPT_TRIGGER_SQL = {
    "feishu_recovery_receipt_no_update": """
        CREATE TRIGGER feishu_recovery_receipt_no_update
        BEFORE UPDATE ON feishu_recovery_receipt
        BEGIN
            SELECT RAISE(ABORT, 'Feishu recovery receipts are append-only');
        END
    """,
    "feishu_recovery_receipt_no_delete": """
        CREATE TRIGGER feishu_recovery_receipt_no_delete
        BEFORE DELETE ON feishu_recovery_receipt
        BEGIN
            SELECT RAISE(ABORT, 'Feishu recovery receipts are append-only');
        END
    """,
    "feishu_recovery_receipt_no_replace": """
        CREATE TRIGGER feishu_recovery_receipt_no_replace
        BEFORE INSERT ON feishu_recovery_receipt
        WHEN EXISTS (
            SELECT 1 FROM feishu_recovery_receipt
            WHERE id=NEW.id
               OR operation_digest=NEW.operation_digest
               OR decision_id=NEW.decision_id
               OR previous_receipt_sha256=NEW.previous_receipt_sha256
               OR receipt_sha256=NEW.receipt_sha256
        )
        BEGIN
            SELECT RAISE(ABORT, 'Feishu recovery receipts are append-only');
        END
    """,
}


def _normalized_state_schema_sql(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", "", value).casefold()


def _canonical_state_table_sql(table: str, layout: tuple[str, ...]) -> str:
    columns = ",".join(
        f"{name} {_STATE_CANONICAL_COLUMN_SQL[name]}" for name in layout
    )
    return _normalized_state_schema_sql(f"CREATE TABLE {table} ({columns})")


def _assert_closed_state_schema_v2_to_v4(conn: sqlite3.Connection) -> None:
    """Validate the closed table/index layout shared by semantic v2-v4."""

    expected_objects = {
        ("table", "feishu_inbox", "feishu_inbox"),
        ("table", "feishu_outbox", "feishu_outbox"),
        ("table", "sqlite_sequence", "sqlite_sequence"),
        ("index", "sqlite_autoindex_feishu_inbox_1", "feishu_inbox"),
        ("index", "sqlite_autoindex_feishu_outbox_1", "feishu_outbox"),
        ("index", "idx_feishu_inbox_due", "feishu_inbox"),
        ("index", "idx_feishu_outbox_due", "feishu_outbox"),
    }
    objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in conn.execute(
            "SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name"
        )
    }
    if objects != expected_objects:
        raise RuntimeError("unsupported Feishu version 2-4 state database table schema")

    expected_indexes = {
        "feishu_inbox": {
            "idx_feishu_inbox_due": (0, "c", 0, ("status", "next_attempt_at", "id")),
            "sqlite_autoindex_feishu_inbox_1": (1, "u", 0, ("message_id",)),
        },
        "feishu_outbox": {
            "idx_feishu_outbox_due": (0, "c", 0, ("status", "next_attempt_at", "id")),
            "sqlite_autoindex_feishu_outbox_1": (1, "u", 0, ("delivery_uuid",)),
        },
    }
    for table, layouts in _STATE_TABLE_LAYOUTS.items():
        schema_row = conn.execute(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        canonical_table_sql = {
            _canonical_state_table_sql(table, layout) for layout in layouts
        }
        if (
            schema_row is None
            or _normalized_state_schema_sql(schema_row[0]) not in canonical_table_sql
        ):
            # table_xinfo does not expose column COLLATE or CHECK constraints.
            # Freeze the canonical CREATE TABLE text as well as the PRAGMAs below.
            raise RuntimeError("unsupported Feishu version 2-4 state database table schema")
        rows = list(conn.execute(f"PRAGMA table_xinfo({table})"))
        actual = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]),
                int(row[5]),
                int(row[6]),
            )
            for row in rows
        )
        allowed = {
            tuple((name, *_STATE_COLUMN_DEFINITIONS[name]) for name in layout)
            for layout in layouts
        }
        if actual not in allowed:
            raise RuntimeError("unsupported Feishu version 2-4 state database table schema")

        indexes = {
            str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
            for row in conn.execute(f"PRAGMA index_list({table})")
        }
        expected = expected_indexes[table]
        if set(indexes) != set(expected):
            raise RuntimeError("unsupported Feishu version 2-4 state database index schema")
        for name, (unique, origin, partial, columns) in expected.items():
            if indexes[name] != (unique, origin, partial):
                raise RuntimeError("unsupported Feishu version 2-4 state database index schema")
            key_columns = tuple(
                (str(row[2]), int(row[3]), str(row[4]).upper())
                for row in conn.execute(f'PRAGMA index_xinfo("{name}")')
                if int(row[5]) == 1
            )
            if key_columns != tuple((column, 0, "BINARY") for column in columns):
                raise RuntimeError("unsupported Feishu version 2-4 state database index schema")


def _assert_closed_state_schema_v5(conn: sqlite3.Connection) -> None:
    """Validate every v5 table, explicit index, and trigger definition exactly."""

    expected_sql: dict[tuple[str, str, str], set[str | None]] = {
        ("table", "feishu_inbox", "feishu_inbox"): {
            _canonical_state_table_sql("feishu_inbox", layout)
            for layout in _STATE_V5_TABLE_LAYOUTS["feishu_inbox"]
        },
        ("table", "feishu_outbox", "feishu_outbox"): {
            _canonical_state_table_sql("feishu_outbox", layout)
            for layout in _STATE_V5_TABLE_LAYOUTS["feishu_outbox"]
        },
        ("table", "feishu_recovery_receipt", "feishu_recovery_receipt"): {
            _normalized_state_schema_sql(_RECOVERY_RECEIPT_TABLE_SQL)
        },
        ("table", "sqlite_sequence", "sqlite_sequence"): {
            _normalized_state_schema_sql("CREATE TABLE sqlite_sequence(name,seq)")
        },
        ("index", "sqlite_autoindex_feishu_inbox_1", "feishu_inbox"): {None},
        ("index", "sqlite_autoindex_feishu_outbox_1", "feishu_outbox"): {None},
        ("index", "idx_feishu_inbox_due", "feishu_inbox"): {
            _normalized_state_schema_sql(
                "CREATE INDEX idx_feishu_inbox_due "
                "ON feishu_inbox(status,next_attempt_at,id)"
            )
        },
        ("index", "idx_feishu_outbox_due", "feishu_outbox"): {
            _normalized_state_schema_sql(
                "CREATE INDEX idx_feishu_outbox_due "
                "ON feishu_outbox(status,next_attempt_at,id)"
            )
        },
    }
    expected_sql.update(
        {
            ("index", name, "feishu_recovery_receipt"): {
                _normalized_state_schema_sql(sql)
            }
            for name, sql in _RECOVERY_RECEIPT_INDEX_SQL.items()
        }
    )
    expected_sql.update(
        {
            ("trigger", name, "feishu_recovery_receipt"): {
                _normalized_state_schema_sql(sql)
            }
            for name, sql in _RECOVERY_RECEIPT_TRIGGER_SQL.items()
        }
    )
    for table, layouts in _STATE_V5_TABLE_LAYOUTS.items():
        rows = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]),
                int(row[5]),
                int(row[6]),
            )
            for row in conn.execute(f"PRAGMA table_xinfo({table})")
        )
        allowed = {
            tuple((name, *_STATE_COLUMN_DEFINITIONS[name]) for name in layout)
            for layout in layouts
        }
        if rows not in allowed:
            raise RuntimeError("unsupported Feishu version 5 state database table schema")

    actual = {
        (str(row[0]), str(row[1]), str(row[2])): (
            None if row[3] is None else _normalized_state_schema_sql(row[3])
        )
        for row in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        )
    }
    if set(actual) != set(expected_sql) or any(
        actual[identity] not in expected
        for identity, expected in expected_sql.items()
    ):
        raise RuntimeError("unsupported Feishu version 5 state database schema")


def _assert_closed_state_schema_v0(conn: sqlite3.Connection) -> None:
    """Validate a populated legacy database before any persistent mutation."""

    required_objects = {
        ("table", "feishu_inbox", "feishu_inbox"),
        ("table", "feishu_outbox", "feishu_outbox"),
        ("table", "sqlite_sequence", "sqlite_sequence"),
        ("index", "sqlite_autoindex_feishu_inbox_1", "feishu_inbox"),
        ("index", "sqlite_autoindex_feishu_outbox_1", "feishu_outbox"),
    }
    optional_due_indexes = {
        ("index", "idx_feishu_inbox_due", "feishu_inbox"),
        ("index", "idx_feishu_outbox_due", "feishu_outbox"),
    }
    objects = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in conn.execute(
            "SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name"
        )
    }
    if not required_objects.issubset(objects) or not objects.issubset(
        required_objects | optional_due_indexes
    ):
        raise RuntimeError("unsupported Feishu version 0 state database schema")

    due_columns = {
        "feishu_inbox": ("status", "next_attempt_at", "id"),
        "feishu_outbox": ("status", "next_attempt_at", "id"),
    }
    unique_columns = {
        "feishu_inbox": ("message_id",),
        "feishu_outbox": ("delivery_uuid",),
    }
    for table, layout in _STATE_V0_TABLE_LAYOUTS.items():
        schema_row = conn.execute(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if (
            schema_row is None
            or _normalized_state_schema_sql(schema_row[0])
            != _canonical_state_table_sql(table, layout)
        ):
            raise RuntimeError("unsupported Feishu version 0 state database table schema")

        actual_columns = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]),
                int(row[5]),
                int(row[6]),
            )
            for row in conn.execute(f"PRAGMA table_xinfo({table})")
        )
        expected_columns = tuple(
            (name, *_STATE_COLUMN_DEFINITIONS[name]) for name in layout
        )
        if actual_columns != expected_columns:
            raise RuntimeError("unsupported Feishu version 0 state database table schema")

        autoindex = f"sqlite_autoindex_{table}_1"
        due_index = f"idx_{table}_due"
        expected_indexes = {
            autoindex: (1, "u", 0, unique_columns[table]),
        }
        if ("index", due_index, table) in objects:
            expected_indexes[due_index] = (0, "c", 0, due_columns[table])
        indexes = {
            str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
            for row in conn.execute(f"PRAGMA index_list({table})")
        }
        if set(indexes) != set(expected_indexes):
            raise RuntimeError("unsupported Feishu version 0 state database index schema")
        for name, (unique, origin, partial, columns) in expected_indexes.items():
            if indexes[name] != (unique, origin, partial):
                raise RuntimeError("unsupported Feishu version 0 state database index schema")
            key_columns = tuple(
                (str(row[2]), int(row[3]), str(row[4]).upper())
                for row in conn.execute(f'PRAGMA index_xinfo("{name}")')
                if int(row[5]) == 1
            )
            if key_columns != tuple((column, 0, "BINARY") for column in columns):
                raise RuntimeError("unsupported Feishu version 0 state database index schema")


def _remaining_finish_budget(deadline_monotonic: float | None) -> float | None:
    """Return one absolute finish deadline's remainder or fail closed."""

    if deadline_monotonic is None:
        return None
    deadline = float(deadline_monotonic)
    if not math.isfinite(deadline):
        raise ValueError("Feishu finish deadline must be finite")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise sqlite3.OperationalError("Feishu finish deadline exceeded")
    return remaining


def _constrain_state_busy_timeout(
    conn: sqlite3.Connection,
    *,
    deadline_monotonic: float | None,
    default_busy_timeout_ms: int,
) -> int:
    """Shrink SQLite lock waiting to the current absolute deadline remainder."""

    remaining = _remaining_finish_budget(deadline_monotonic)
    busy_timeout_ms = int(default_busy_timeout_ms)
    if remaining is not None:
        busy_timeout_ms = min(busy_timeout_ms, max(0, int(remaining * 1000)))
    conn.execute(f"PRAGMA busy_timeout={max(0, busy_timeout_ms)}")
    _remaining_finish_budget(deadline_monotonic)
    return max(0, busy_timeout_ms)


def _enable_state_wal(
    conn: sqlite3.Connection,
    *,
    busy_timeout_ms: int,
    deadline_monotonic: float | None = None,
) -> None:
    """Converge concurrent validated initializers on WAL within one hard bound."""
    enable_wal_with_deadline(
        conn,
        max_wait_seconds=max(0.05, busy_timeout_ms / 1000.0),
        deadline_monotonic=deadline_monotonic,
        error_message="Feishu state database refused WAL journal mode",
    )


def _state_connect(
    *, deadline_monotonic: float | None = None
) -> sqlite3.Connection:
    _STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    ttl = max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
    busy_timeout_ms = max(50, min(10_000, int((ttl / 4.0) * 1000)))
    remaining = _remaining_finish_budget(deadline_monotonic)
    connect_timeout = busy_timeout_ms / 1000.0
    if remaining is not None:
        connect_timeout = min(connect_timeout, remaining)
    conn = sqlite3.connect(_STATE_DB, timeout=max(0.0, connect_timeout))
    try:
        _constrain_state_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=busy_timeout_ms,
        )
        # Reject unsupported or non-canonical databases before any persistent
        # storage PRAGMA.  A forensic failure path must not silently switch the
        # journal mode or otherwise rewrite the database it is rejecting.
        # The version banner and the schema generation it selects must come
        # from one read snapshot: a concurrent initializer may commit the
        # legacy -> v5 migration between two autocommit statements, which would
        # otherwise pair a stale version with the post-migration schema and
        # misjudge a converging database as unsupported.
        conn.execute("BEGIN")
        try:
            preflight_schema_version = int(
                conn.execute("PRAGMA user_version").fetchone()[0]
            )
            if preflight_schema_version not in (
                _STATE_LEGACY_SCHEMA_VERSIONS | {_STATE_SCHEMA_VERSION}
            ):
                raise RuntimeError("unsupported Feishu state database schema version")
            if preflight_schema_version == _STATE_SCHEMA_VERSION:
                _assert_closed_state_schema_v5(conn)
            elif preflight_schema_version in _STATE_STRUCTURAL_SCHEMA_VERSIONS:
                _assert_closed_state_schema_v2_to_v4(conn)
            elif conn.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None:
                _assert_closed_state_schema_v0(conn)
        finally:
            conn.rollback()
        _enable_state_wal(
            conn,
            busy_timeout_ms=busy_timeout_ms,
            deadline_monotonic=deadline_monotonic,
        )
        page_size = max(512, int(conn.execute("PRAGMA page_size").fetchone()[0]))
        max_pages = int(_STATE_DB_MAX_BYTES) // page_size
        if max_pages < 1:
            raise RuntimeError("Feishu state database byte budget is too small")
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        if page_count > max_pages:
            raise FeishuQueueFull("Feishu state database already exceeds its byte budget")
        actual_max_pages = int(
            conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        )
        if actual_max_pages > max_pages:
            raise FeishuQueueFull("Feishu state database byte budget cannot be applied")
        conn.execute(f"PRAGMA journal_size_limit={int(_STATE_WAL_MAX_BYTES)}")
        conn.execute(
            f"PRAGMA wal_autocheckpoint={int(_STATE_WAL_AUTOCHECKPOINT_PAGES)}"
        )
        if preflight_schema_version == _STATE_SCHEMA_VERSION:
            # Steady-state callers already passed the closed-schema preflight.
            # Do not take a redundant writer lock before every read/heartbeat;
            # the migration barrier below exists only for legacy generations.
            if int(conn.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
                raise FeishuQueueFull(
                    "Feishu state database exceeded its byte budget"
                )
            _remaining_finish_budget(deadline_monotonic)
            return conn
        # The writer barrier makes every legacy -> v5 quarantine and structural
        # v0 migration one atomic generation change.  Re-read
        # the version after the lock because another initializer may have
        # completed that migration while this connection waited.
        _constrain_state_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=busy_timeout_ms,
        )
        conn.execute("BEGIN IMMEDIATE")
        _remaining_finish_budget(deadline_monotonic)
        schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if schema_version not in (
            _STATE_LEGACY_SCHEMA_VERSIONS | {_STATE_SCHEMA_VERSION}
        ):
            raise RuntimeError("unsupported Feishu state database schema version")
        if schema_version == _STATE_SCHEMA_VERSION:
            _assert_closed_state_schema_v5(conn)
            # Another validated initializer completed v5 while this connection
            # waited for BEGIN IMMEDIATE.  Release our writer barrier and reuse
            # that exact generation; never execute the migration twice.
            _constrain_state_busy_timeout(
                conn,
                deadline_monotonic=deadline_monotonic,
                default_busy_timeout_ms=busy_timeout_ms,
            )
            conn.commit()
            _remaining_finish_budget(deadline_monotonic)
            if int(conn.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
                raise FeishuQueueFull(
                    "Feishu state database exceeded its byte budget"
                )
            return conn
        elif schema_version in _STATE_STRUCTURAL_SCHEMA_VERSIONS:
            _assert_closed_state_schema_v2_to_v4(conn)
        elif conn.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None:
            _assert_closed_state_schema_v0(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feishu_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_uuid TEXT NOT NULL UNIQUE,
                chat_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at REAL NOT NULL,
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
                delivered_at REAL NOT NULL DEFAULT 0,
                terminal_verification TEXT NOT NULL DEFAULT '',
                closed_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feishu_outbox_due "
            "ON feishu_outbox(status, next_attempt_at, id)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feishu_inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                chat_id TEXT NOT NULL,
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
                finished_at REAL NOT NULL DEFAULT 0,
                terminal_verification TEXT NOT NULL DEFAULT '',
                closed_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_feishu_inbox_due "
            "ON feishu_inbox(status, next_attempt_at, id)"
        )
        required_legacy_columns = {
            "feishu_inbox": {
                "id", "message_id", "chat_id", "payload", "received_at",
                "next_attempt_at", "attempts", "status", "last_error",
                "claimed_at", "finished_at",
            },
            "feishu_outbox": {
                "id", "delivery_uuid", "chat_id", "msg_type", "content",
                "created_at", "next_attempt_at", "attempts", "status",
                "last_error", "claimed_at", "delivered_at",
            },
        }
        migration_columns = {
            "claim_token": "TEXT NOT NULL DEFAULT ''",
            "claim_deadline": "REAL NOT NULL DEFAULT 0",
            "heartbeat_at": "REAL NOT NULL DEFAULT 0",
            "claim_epoch": "INTEGER NOT NULL DEFAULT 0",
            "last_finish_token": "TEXT NOT NULL DEFAULT ''",
            "last_finish_epoch": "INTEGER NOT NULL DEFAULT 0",
            "last_finish_outcome": "TEXT NOT NULL DEFAULT ''",
            "terminal_verification": "TEXT NOT NULL DEFAULT ''",
            "closed_at": "REAL NOT NULL DEFAULT 0",
        }
        expected_columns = {
            table: required | set(migration_columns)
            for table, required in required_legacy_columns.items()
        }
        expected_pre_v5_columns = {
            table: required
            | (set(migration_columns) - {"terminal_verification", "closed_at"})
            for table, required in required_legacy_columns.items()
        }
        for table in ("feishu_inbox", "feishu_outbox"):
            columns = {
                str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")
            }
            allowed = expected_columns[table]
            if (
                schema_version in _STATE_STRUCTURAL_SCHEMA_VERSIONS
                and columns != expected_pre_v5_columns[table]
            ):
                raise RuntimeError(
                    "unsupported Feishu version 2-4 state database table schema"
                )
            if not required_legacy_columns[table].issubset(columns) or not columns.issubset(allowed):
                raise RuntimeError("unsupported Feishu state database table schema")
            for column, declaration in migration_columns.items():
                if column in columns:
                    continue
                try:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
                    )
                except sqlite3.OperationalError:
                    # A concurrent first connection may have completed the fixed
                    # migration after our PRAGMA snapshot.  Re-verify, never guess.
                    columns = {
                        str(row[1])
                        for row in conn.execute(f"PRAGMA table_info({table})")
                    }
                    if column not in columns:
                        raise
                else:
                    columns.add(column)
            final_columns = {
                str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if final_columns != expected_columns[table]:
                raise RuntimeError("Feishu state database migration was incomplete")
        if schema_version in {0, 2, 3}:
            # Historical inbox processing predates a complete provider-side
            # receipt for every handler seam.  It is manual-only evidence:
            # no claim/recover/retention path may silently reinterpret it.
            conn.execute(
                """
                UPDATE feishu_inbox
                SET status='recovery_required',
                    last_error='legacy_processing_provider_outcome_unknown',
                    claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                    last_finish_outcome='recovery_required',finished_at=0
                WHERE status='processing'
                """
            )
        if schema_version in {0, 2}:
            conn.execute(
                """
                UPDATE feishu_outbox
                SET status='recovery_required',
                    last_error='legacy_processing_provider_outcome_unknown',
                    claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                    last_finish_outcome='recovery_required',delivered_at=0
                WHERE status='processing'
                """
            )
        conn.execute(_RECOVERY_RECEIPT_TABLE_SQL)
        for sql in _RECOVERY_RECEIPT_INDEX_SQL.values():
            conn.execute(sql)
        for sql in _RECOVERY_RECEIPT_TRIGGER_SQL.values():
            conn.execute(sql)
        conn.execute(f"PRAGMA user_version={_STATE_SCHEMA_VERSION}")
        _assert_closed_state_schema_v5(conn)
        _constrain_state_busy_timeout(
            conn,
            deadline_monotonic=deadline_monotonic,
            default_busy_timeout_ms=busy_timeout_ms,
        )
        conn.commit()
        _remaining_finish_budget(deadline_monotonic)
        if int(conn.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
            raise FeishuQueueFull("Feishu state database exceeded its byte budget")
        return conn
    except BaseException:
        conn.close()
        raise


@contextmanager
def _state_transaction(*, deadline_monotonic: float | None = None):
    """Commit or roll back, and always close the SQLite handle on Windows."""

    if deadline_monotonic is None:
        conn = _state_connect()
    else:
        conn = _state_connect(deadline_monotonic=deadline_monotonic)
    try:
        with conn:
            yield conn
            if deadline_monotonic is not None:
                _constrain_state_busy_timeout(
                    conn,
                    deadline_monotonic=deadline_monotonic,
                    default_busy_timeout_ms=10_000,
                )
        _remaining_finish_budget(deadline_monotonic)
    finally:
        conn.close()


@contextmanager
def _state_write_transaction(*, deadline_monotonic: float | None = None):
    """Acquire SQLite's writer barrier before any deadline clock is sampled."""

    transaction = (
        _state_transaction()
        if deadline_monotonic is None
        else _state_transaction(deadline_monotonic=deadline_monotonic)
    )
    with transaction as conn:
        if deadline_monotonic is not None:
            _constrain_state_busy_timeout(
                conn,
                deadline_monotonic=deadline_monotonic,
                default_busy_timeout_ms=10_000,
            )
        conn.execute("BEGIN IMMEDIATE")
        _remaining_finish_budget(deadline_monotonic)
        yield conn


def _policy_time(now=None) -> float:
    """Resolve an injectable policy clock at its actual decision boundary."""

    value = time.time() if now is None else now() if callable(now) else now
    current = float(value)
    if not math.isfinite(current) or current < 0:
        raise ValueError("Feishu policy clock must be finite and non-negative")
    return current


_RECOVERY_QUEUE_COLUMNS = {
    "inbox": (
        "id", "message_id", "chat_id", "payload", "received_at",
        "next_attempt_at", "attempts", "status", "last_error", "claimed_at",
        "claim_token", "claim_deadline", "heartbeat_at", "claim_epoch",
        "last_finish_token", "last_finish_epoch", "last_finish_outcome",
        "finished_at", "terminal_verification", "closed_at",
    ),
    "outbox": (
        "id", "delivery_uuid", "chat_id", "msg_type", "content", "created_at",
        "next_attempt_at", "attempts", "status", "last_error", "claimed_at",
        "claim_token", "claim_deadline", "heartbeat_at", "claim_epoch",
        "last_finish_token", "last_finish_epoch", "last_finish_outcome",
        "delivered_at", "terminal_verification", "closed_at",
    ),
}
_RECOVERY_QUEUE_TABLE = {
    "inbox": ("feishu_inbox", "message_id"),
    "outbox": ("feishu_outbox", "delivery_uuid"),
}
_RECOVERY_RECEIPT_COLUMNS = (
    "id", "operation_digest", "decision_id", "target_kind",
    "target_key_sha256", "chat_sha256", "actor", "authorization", "reason",
    "decided_at_ms", "closed_at_ms", "affected_inbox_count",
    "affected_outbox_count", "before_digest", "after_digest",
    "affected_rows_json", "previous_receipt_sha256", "receipt_sha256",
)


def _canonical_recovery_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _recovery_digest(domain: bytes, value: object) -> str:
    encoded = _canonical_recovery_json(value).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _require_recovery_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"Feishu recovery {field} must be 64 lowercase hex characters")
    if value == "0" * 64:
        raise ValueError(f"Feishu recovery {field} cannot be the zero digest")
    return value


def _require_recovery_text(
    value: object,
    field: str,
    *,
    max_bytes: int,
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"Feishu recovery {field} is invalid")
    if len(value.encode("utf-8")) > max_bytes or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError(f"Feishu recovery {field} is invalid")
    return value


def _require_recovery_ms(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 9_223_372_036_854_775_807
    ):
        raise ValueError(f"Feishu recovery {field} must be a non-negative integer millisecond value")
    return value


def _validated_recovery_target(target_kind: object, target_key: object) -> tuple[str, str]:
    if target_kind not in {*_RECOVERY_QUEUE_TABLE, "video"}:
        raise ValueError("Feishu recovery target kind must be inbox, outbox, or video")
    return str(target_kind), _require_recovery_text(
        target_key,
        "target key",
        max_bytes=512,
    )


def _recovery_target_key_sha256(target_kind: str, target_key: str) -> str:
    return _recovery_digest(
        b"nachuan.feishu.close-without-replay.target/v1\x00",
        {"kind": target_kind, "key": target_key},
    )


def _close_without_replay_operation_digest(
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
    """Derive one canonical no-replay decision identity without executing it."""

    kind, key = _validated_recovery_target(target_kind, target_key)
    decision = _require_recovery_digest(decision_id, "decision id")
    expected = _require_recovery_digest(expected_before_digest, "before digest")
    authorized_by = _require_recovery_digest(authorization, "authorization")
    normalized_actor = _require_recovery_text(actor, "actor", max_bytes=256)
    normalized_reason = _require_recovery_text(reason, "reason", max_bytes=2048)
    decided = _require_recovery_ms(decided_at_ms, "decision time")
    return _recovery_digest(
        _RECOVERY_OPERATION_DOMAIN,
        {
            "actor": normalized_actor,
            "authorization": authorized_by,
            "decided_at_ms": decided,
            "decision_id": decision,
            "expected_before_digest": expected,
            "operation": "close_without_replay",
            "reason": normalized_reason,
            "schema": "nachuan.feishu-recovery-close-request.v1",
            "target_key": key,
            "target_kind": kind,
        },
    )


def _validated_close_without_replay_request(
    request: _FeishuCloseWithoutReplayRequest,
) -> _FeishuCloseWithoutReplayRequest:
    if not isinstance(request, _FeishuCloseWithoutReplayRequest):
        raise TypeError("Feishu close_without_replay requires its typed request")
    expected_operation = _close_without_replay_operation_digest(
        decision_id=request.decision_id,
        target_kind=request.target_kind,
        target_key=request.target_key,
        expected_before_digest=request.expected_before_digest,
        actor=request.actor,
        authorization=request.authorization,
        reason=request.reason,
        decided_at_ms=request.decided_at_ms,
    )
    operation = _require_recovery_digest(request.operation_digest, "operation digest")
    if operation != expected_operation:
        raise FeishuRecoveryConflict(
            "Feishu recovery operation digest does not match the canonical request"
        )
    return request


def _recovery_record(kind: str, row: tuple[object, ...]) -> dict[str, object]:
    return {
        "kind": kind,
        **dict(zip(_RECOVERY_QUEUE_COLUMNS[kind], row, strict=True)),
    }


def _recovery_row_is_unclaimed(record: dict[str, object]) -> bool:
    return bool(
        float(record["claimed_at"]) == 0.0
        and str(record["claim_token"]) == ""
        and float(record["claim_deadline"]) == 0.0
        and float(record["heartbeat_at"]) == 0.0
    )


def _recovery_target_rows_in_transaction(
    conn: sqlite3.Connection,
    target_kind: str,
    target_key: str,
) -> tuple[str, list[dict[str, object]]]:
    table, key_column = _RECOVERY_QUEUE_TABLE[target_kind]
    columns = ",".join(_RECOVERY_QUEUE_COLUMNS[target_kind])
    target_row = conn.execute(
        f"SELECT {columns} FROM {table} WHERE {key_column}=?",
        (target_key,),
    ).fetchone()
    if target_row is None:
        raise FeishuRecoveryConflict("Feishu recovery target does not exist")
    target = _recovery_record(target_kind, tuple(target_row))
    if target["status"] != "recovery_required" or not _recovery_row_is_unclaimed(target):
        raise FeishuRecoveryConflict(
            "Feishu recovery target is not an unclaimed recovery_required row"
        )
    chat_id = str(target["chat_id"])
    if not chat_id:
        raise FeishuRecoveryConflict("Feishu recovery target chat has already drifted")
    affected: list[dict[str, object]] = []
    for kind in ("inbox", "outbox"):
        affected_table, _ = _RECOVERY_QUEUE_TABLE[kind]
        affected_columns = ",".join(_RECOVERY_QUEUE_COLUMNS[kind])
        rows = conn.execute(
            f"SELECT {affected_columns} FROM {affected_table} "
            "WHERE chat_id=? AND status='recovery_required' ORDER BY id",
            (chat_id,),
        )
        for row in rows:
            record = _recovery_record(kind, tuple(row))
            if not _recovery_row_is_unclaimed(record):
                raise FeishuRecoveryConflict(
                    "Feishu recovery chat contains an actively claimed row"
                )
            affected.append(record)
    if not affected:
        raise FeishuRecoveryConflict("Feishu recovery target set is empty")
    return chat_id, affected


def _recovery_affected_set_digest(rows: list[dict[str, object]]) -> str:
    return _recovery_digest(_RECOVERY_SET_DOMAIN, rows)


def _recovery_target_before_digest(target_kind: str, target_key: str) -> str:
    """Read one exact affected-set fingerprint for an offline adjudicator."""

    kind, key = _validated_recovery_target(target_kind, target_key)
    if kind == "video":
        return _pending_recovery_target_before_digest(key)
    with _state_transaction() as conn:
        _chat_id, rows = _recovery_target_rows_in_transaction(conn, kind, key)
    return _recovery_affected_set_digest(rows)


def _recovery_target_snapshot(
    target_kind: object,
    target_key: object,
) -> dict[str, object]:
    """Return only hashed, bounded adjudication data for the coordinator."""

    kind, key = _validated_recovery_target(target_kind, target_key)
    if kind == "video":
        return _pending_recovery_target_snapshot(key)
    with _state_transaction() as conn:
        _chat_id, rows = _recovery_target_rows_in_transaction(conn, kind, key)
    return {
        "schema": "nachuan.feishu-recovery-inspect.v1",
        "target_kind": kind,
        "target_key_sha256": _recovery_target_key_sha256(kind, key),
        "expected_before_digest": _recovery_affected_set_digest(rows),
        "affected_counts": {
            "inbox": sum(row["kind"] == "inbox" for row in rows),
            "outbox": sum(row["kind"] == "outbox" for row in rows),
            "video": 0,
        },
    }


def _recovery_rows_by_identity(
    conn: sqlite3.Connection,
    before_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    after_rows: list[dict[str, object]] = []
    for kind in ("inbox", "outbox"):
        ids = [int(row["id"]) for row in before_rows if row["kind"] == kind]
        table, _ = _RECOVERY_QUEUE_TABLE[kind]
        columns = ",".join(_RECOVERY_QUEUE_COLUMNS[kind])
        for offset in range(0, len(ids), 500):
            batch = ids[offset : offset + 500]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            fetched = conn.execute(
                f"SELECT {columns} FROM {table} WHERE id IN ({placeholders}) ORDER BY id",
                batch,
            )
            after_rows.extend(_recovery_record(kind, tuple(row)) for row in fetched)
    return after_rows


def _recovery_receipt_record(row: tuple[object, ...]) -> dict[str, object]:
    return dict(zip(_RECOVERY_RECEIPT_COLUMNS, row, strict=True))


def _recovery_receipt_sha256(record: dict[str, object]) -> str:
    payload = {name: record[name] for name in _RECOVERY_RECEIPT_COLUMNS[:-1]}
    return _recovery_digest(_RECOVERY_RECEIPT_DOMAIN, payload)


def _validate_recovery_receipt_manifest(receipt: dict[str, object]) -> None:
    """Reject a self-consistent hash over a semantically impossible manifest."""

    raw = receipt["affected_rows_json"]
    try:
        manifest = json.loads(raw) if isinstance(raw, str) else None
    except (TypeError, ValueError):
        manifest = None
    inbox_count = receipt["affected_inbox_count"]
    outbox_count = receipt["affected_outbox_count"]
    invalid = (
        not isinstance(manifest, list)
        or type(inbox_count) is not int
        or type(outbox_count) is not int
        or inbox_count < 0
        or outbox_count < 0
        or len(manifest) != inbox_count + outbox_count
        or not isinstance(raw, str)
        or _canonical_recovery_json(manifest) != raw
    )
    expected_fields = {
        "after_sha256",
        "before_sha256",
        "kind",
        "row_id",
        "target_sha256",
    }
    observed_counts = {"inbox": 0, "outbox": 0}
    target_seen = False
    previous_identity: tuple[int, int] | None = None
    if not invalid:
        for member in manifest:
            if not isinstance(member, dict) or set(member) != expected_fields:
                invalid = True
                break
            kind = member["kind"]
            row_id = member["row_id"]
            if kind not in observed_counts or type(row_id) is not int or row_id < 1:
                invalid = True
                break
            digests = (
                member["after_sha256"],
                member["before_sha256"],
                member["target_sha256"],
            )
            if any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
                or value == "0" * 64
                for value in digests
            ) or member["after_sha256"] == member["before_sha256"]:
                invalid = True
                break
            identity = (0 if kind == "inbox" else 1, row_id)
            if previous_identity is not None and identity <= previous_identity:
                invalid = True
                break
            previous_identity = identity
            observed_counts[str(kind)] += 1
            target_seen = target_seen or (
                kind == receipt["target_kind"]
                and member["target_sha256"] == receipt["target_key_sha256"]
            )
    invalid = invalid or observed_counts != {
        "inbox": inbox_count,
        "outbox": outbox_count,
    } or not target_seen
    if invalid:
        raise FeishuRecoveryConflict(
            "Feishu recovery receipt manifest is invalid"
        )


def _validated_recovery_receipt_chain_head(
    conn: sqlite3.Connection,
) -> tuple[int, str]:
    """Recompute the bounded receipt chain before returning or appending."""

    columns = ",".join(_RECOVERY_RECEIPT_COLUMNS)
    expected_id = 1
    expected_previous = "0" * 64
    for row in conn.execute(
        f"SELECT {columns} FROM feishu_recovery_receipt ORDER BY id"
    ):
        if expected_id > 50_000:
            raise FeishuRecoveryConflict(
                "Feishu recovery receipt chain exceeds its hard capacity"
            )
        receipt = _recovery_receipt_record(tuple(row))
        if (
            type(receipt["id"]) is not int
            or int(receipt["id"]) != expected_id
            or str(receipt["previous_receipt_sha256"]) != expected_previous
            or str(receipt["receipt_sha256"])
            != _recovery_receipt_sha256(receipt)
        ):
            raise FeishuRecoveryConflict(
                "Feishu recovery receipt chain is invalid"
            )
        _validate_recovery_receipt_manifest(receipt)
        expected_previous = str(receipt["receipt_sha256"])
        expected_id += 1
    return expected_id - 1, expected_previous


def _existing_recovery_result(
    row: tuple[object, ...],
    request: _FeishuCloseWithoutReplayRequest,
) -> _FeishuCloseWithoutReplayResult:
    receipt = _recovery_receipt_record(row)
    expected = {
        "operation_digest": request.operation_digest,
        "decision_id": request.decision_id,
        "target_kind": request.target_kind,
        "target_key_sha256": _recovery_target_key_sha256(
            request.target_kind, request.target_key
        ),
        "actor": request.actor,
        "authorization": request.authorization,
        "reason": request.reason,
        "decided_at_ms": request.decided_at_ms,
        "before_digest": request.expected_before_digest,
    }
    if any(receipt[name] != value for name, value in expected.items()):
        raise FeishuRecoveryConflict(
            "Feishu recovery operation conflicts with its durable receipt"
        )
    if receipt["receipt_sha256"] != _recovery_receipt_sha256(receipt):
        raise FeishuRecoveryConflict("Feishu recovery receipt digest is invalid")
    return _FeishuCloseWithoutReplayResult(
        operation_digest=str(receipt["operation_digest"]),
        receipt_sha256=str(receipt["receipt_sha256"]),
        affected_inbox_count=int(receipt["affected_inbox_count"]),
        affected_outbox_count=int(receipt["affected_outbox_count"]),
        affected_video_count=0,
        applied=False,
    )


def _close_without_replay(
    request: _FeishuCloseWithoutReplayRequest,
    *,
    closed_at_ms: int,
) -> _FeishuCloseWithoutReplayResult:
    """Atomically tombstone one chat's unknown outcomes without replaying them.

    Phase A deliberately exposes no route, CLI command, or background caller for
    this primitive.  A later restricted coordinator must provide authorization.
    """

    request = _validated_close_without_replay_request(request)
    closed_ms = _require_recovery_ms(closed_at_ms, "close time")
    if closed_ms < request.decided_at_ms:
        raise ValueError("Feishu recovery close time precedes the decision")
    if request.target_kind == "video":
        return _close_pending_video_without_replay(request, closed_at_ms=closed_ms)
    receipt_columns = ",".join(_RECOVERY_RECEIPT_COLUMNS)
    with _state_write_transaction() as conn:
        receipt_count, previous_sha256 = _validated_recovery_receipt_chain_head(conn)
        existing = conn.execute(
            f"SELECT {receipt_columns} FROM feishu_recovery_receipt "
            "WHERE operation_digest=?",
            (request.operation_digest,),
        ).fetchone()
        if existing is not None:
            return _existing_recovery_result(tuple(existing), request)
        if conn.execute(
            "SELECT 1 FROM feishu_recovery_receipt WHERE decision_id=?",
            (request.decision_id,),
        ).fetchone() is not None:
            raise FeishuRecoveryConflict(
                "Feishu recovery decision id belongs to another operation"
            )
        receipt_cap = max(1, min(int(_MAX_RECOVERY_RECEIPTS), 50_000))
        if receipt_count >= receipt_cap:
            raise FeishuQueueFull("Feishu recovery receipt capacity is full")

        chat_id, before_rows = _recovery_target_rows_in_transaction(
            conn,
            request.target_kind,
            request.target_key,
        )
        before_digest = _recovery_affected_set_digest(before_rows)
        if before_digest != request.expected_before_digest:
            raise FeishuRecoveryConflict(
                "Feishu recovery target set drifted after adjudication"
            )
        closed_seconds = closed_ms / 1000.0
        inbox_count = sum(row["kind"] == "inbox" for row in before_rows)
        outbox_count = sum(row["kind"] == "outbox" for row in before_rows)
        changed_inbox = conn.execute(
            "UPDATE feishu_inbox SET status='closed',chat_id='',payload=?,"
            "claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,"
            "terminal_verification='closed_without_replay',closed_at=? "
            "WHERE chat_id=? AND status='recovery_required' AND claimed_at=0 "
            "AND claim_token='' AND claim_deadline=0 AND heartbeat_at=0",
            (_RECOVERY_TOMBSTONE, closed_seconds, chat_id),
        ).rowcount
        changed_outbox = conn.execute(
            "UPDATE feishu_outbox SET status='closed',chat_id='',content=?,"
            "claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,"
            "terminal_verification='closed_without_replay',closed_at=? "
            "WHERE chat_id=? AND status='recovery_required' AND claimed_at=0 "
            "AND claim_token='' AND claim_deadline=0 AND heartbeat_at=0",
            (_RECOVERY_TOMBSTONE, closed_seconds, chat_id),
        ).rowcount
        if changed_inbox != inbox_count or changed_outbox != outbox_count:
            raise FeishuRecoveryConflict(
                "Feishu recovery target changed during the close transaction"
            )
        after_rows = _recovery_rows_by_identity(conn, before_rows)
        if len(after_rows) != len(before_rows):
            raise FeishuRecoveryConflict("Feishu recovery closed row set is incomplete")
        after_digest = _recovery_affected_set_digest(after_rows)
        affected_rows = []
        for before, after in zip(before_rows, after_rows, strict=True):
            if (before["kind"], before["id"]) != (after["kind"], after["id"]):
                raise FeishuRecoveryConflict("Feishu recovery row order drifted")
            key_column = _RECOVERY_QUEUE_TABLE[str(before["kind"])][1]
            affected_rows.append(
                {
                    "after_sha256": _recovery_digest(_RECOVERY_ROW_DOMAIN, after),
                    "before_sha256": _recovery_digest(_RECOVERY_ROW_DOMAIN, before),
                    "kind": before["kind"],
                    "row_id": before["id"],
                    "target_sha256": _recovery_target_key_sha256(
                        str(before["kind"]), str(before[key_column])
                    ),
                }
            )
        affected_rows_json = _canonical_recovery_json(affected_rows)
        receipt_id = receipt_count + 1
        receipt: dict[str, object] = {
            "id": receipt_id,
            "operation_digest": request.operation_digest,
            "decision_id": request.decision_id,
            "target_kind": request.target_kind,
            "target_key_sha256": _recovery_target_key_sha256(
                request.target_kind, request.target_key
            ),
            "chat_sha256": _recovery_digest(
                b"nachuan.feishu.close-without-replay.chat/v1\x00", chat_id
            ),
            "actor": request.actor,
            "authorization": request.authorization,
            "reason": request.reason,
            "decided_at_ms": request.decided_at_ms,
            "closed_at_ms": closed_ms,
            "affected_inbox_count": inbox_count,
            "affected_outbox_count": outbox_count,
            "before_digest": before_digest,
            "after_digest": after_digest,
            "affected_rows_json": affected_rows_json,
            "previous_receipt_sha256": previous_sha256,
        }
        receipt["receipt_sha256"] = _recovery_receipt_sha256(receipt)
        conn.execute(
            f"INSERT INTO feishu_recovery_receipt({receipt_columns}) "
            f"VALUES({','.join('?' for _ in _RECOVERY_RECEIPT_COLUMNS)})",
            tuple(receipt[name] for name in _RECOVERY_RECEIPT_COLUMNS),
        )
        return _FeishuCloseWithoutReplayResult(
            operation_digest=request.operation_digest,
            receipt_sha256=str(receipt["receipt_sha256"]),
            affected_inbox_count=inbox_count,
            affected_outbox_count=outbox_count,
            affected_video_count=0,
            applied=True,
        )


def _validated_inbound_payload(payload: dict) -> dict[str, str]:
    allowed = {"message_id", "chat_id", "message_type", "content", "open_id"}
    if not isinstance(payload, dict) or set(payload) != allowed:
        raise ValueError("invalid Feishu inbound payload fields")
    normalized = {name: str(payload.get(name) or "") for name in allowed}
    if (
        not normalized["message_id"]
        or not normalized["chat_id"]
        or len(normalized["message_id"]) > 512
        or len(normalized["chat_id"]) > 512
        or len(normalized["message_type"]) > 32
        or len(normalized["open_id"]) > 512
        or len(normalized["content"].encode("utf-8")) > 1024 * 1024
    ):
        raise ValueError("Feishu inbound payload is empty or too large")
    return normalized


def _store_inbound(payload: dict, *, now: float | None = None) -> bool:
    normalized = _validated_inbound_payload(payload)
    current = time.time() if now is None else float(now)
    encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
    with _state_transaction() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT 1 FROM feishu_inbox WHERE message_id=?",
            (normalized["message_id"],),
        ).fetchone()
        if existing:
            return False
        active = conn.execute(
            """
            SELECT COUNT(*),
                   SUM(CASE WHEN chat_id=? THEN 1 ELSE 0 END)
            FROM feishu_inbox
            WHERE status IN ('pending','processing','submitting','recovery_required')
            """,
            (normalized["chat_id"],),
        ).fetchone()
        total_active = int(active[0] or 0)
        chat_active = int(active[1] or 0)
        if (
            total_active >= max(1, int(_MAX_ACTIVE_INBOUND_ROWS))
            or chat_active >= max(1, int(_MAX_ACTIVE_INBOUND_PER_CHAT))
        ):
            raise FeishuQueueFull("Feishu inbound durable queue is full")
        changed = conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at)
            VALUES (?,?,?,?,?)
            """,
            (
                normalized["message_id"],
                normalized["chat_id"],
                encoded,
                current,
                current,
            ),
        ).rowcount
    return changed == 1


def _inbox_status_counts(statuses: tuple[str, ...]) -> int:
    if not statuses:
        return 0
    placeholders = ",".join("?" for _ in statuses)
    with _state_transaction() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM feishu_inbox WHERE status IN ({placeholders})",
            statuses,
        ).fetchone()
    return int(row[0] if row else 0)


def _claim_inbound(*, now=None) -> dict[str, object] | None:
    ttl = max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
    claim_token = uuid.uuid4().hex
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        row = conn.execute(
            """
            SELECT candidate.id,candidate.payload,candidate.attempts,
                   candidate.claim_epoch
            FROM feishu_inbox AS candidate
            WHERE candidate.status='pending' AND candidate.next_attempt_at<=?
              AND NOT EXISTS (
                SELECT 1 FROM feishu_inbox AS earlier
                WHERE earlier.chat_id=candidate.chat_id
                  AND earlier.id<candidate.id
                  AND earlier.status IN ('pending','processing','submitting','recovery_required')
              )
            ORDER BY candidate.id
            LIMIT 1
            """,
            (current,),
        ).fetchone()
        if row is None:
            return None
        changed = conn.execute(
            "UPDATE feishu_inbox SET status='processing',claimed_at=?,claim_token=?, "
            "claim_deadline=?,heartbeat_at=?,claim_epoch=claim_epoch+1 "
            "WHERE id=? AND status='pending'",
            (current, claim_token, current + ttl, current, row[0]),
        ).rowcount
        if changed != 1:
            return None
        return {
            "id": int(row[0]),
            "payload": json.loads(str(row[1])),
            "attempts": int(row[2]),
            "claim_token": claim_token,
            "claim_deadline": current + ttl,
            "claim_epoch": int(row[3]) + 1,
        }


def _finish_inbound(
    claim: dict[str, object],
    *,
    ok: bool,
    error_code: str = "",
    recovery_required: bool = False,
    now=None,
    deadline_monotonic: float | None = None,
) -> bool:
    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if not claim_token or claim_epoch < 1:
        return False
    if recovery_required and ok:
        raise ValueError("a successful inbound Turn cannot require recovery")
    if recovery_required:
        safe_error = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "_",
            error_code or "inbound_provider_outcome_unknown",
        )[:64]
        with _state_write_transaction(
            deadline_monotonic=deadline_monotonic
        ) as conn:
            current = _policy_time(now)
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status='recovery_required',last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,
                    last_finish_outcome='recovery_required',finished_at=0
                WHERE id=? AND status IN ('processing','submitting') AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    safe_error,
                    claim_token,
                    claim_epoch,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
        return changed == 1
    if ok:
        with _state_write_transaction(
            deadline_monotonic=deadline_monotonic
        ) as conn:
            current = _policy_time(now)
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status='done',last_error='',claimed_at=0,claim_token='',
                    claim_deadline=0,heartbeat_at=0,last_finish_token=?,
                    last_finish_epoch=?,last_finish_outcome='done',finished_at=?
                WHERE id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    claim_token,
                    claim_epoch,
                    current,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
        return changed == 1
    attempts = int(claim["attempts"]) + 1
    status = "dead" if attempts >= 8 else "pending"
    safe_error = re.sub(r"[^A-Za-z0-9_.-]+", "_", error_code or "handler_failed")[:64]
    payload = '{"state":"dead_tombstone","version":1}' if status == "dead" else None
    with _state_write_transaction(
        deadline_monotonic=deadline_monotonic
    ) as conn:
        current = _policy_time(now)
        next_attempt = current + min(2 ** min(attempts, 8), 300)
        if payload is None:
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status=?,attempts=?,next_attempt_at=?,last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,last_finish_outcome='retry'
                WHERE id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    status,
                    attempts,
                    next_attempt,
                    safe_error,
                    claim_token,
                    claim_epoch,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
            if changed == 1 and attempts == 1:
                _enqueue_inbound_notice_in_transaction(
                    conn,
                    claim,
                    notice_kind="retrying",
                    text=_INBOUND_RETRYING_NOTICE,
                    now=current,
                )
        else:
            changed = conn.execute(
                """
                UPDATE feishu_inbox
                SET status='dead',attempts=?,next_attempt_at=?,last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,last_finish_outcome='dead',
                    payload=?,chat_id='',finished_at=?
                WHERE id=? AND status='processing' AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    attempts,
                    next_attempt,
                    safe_error,
                    claim_token,
                    claim_epoch,
                    payload,
                    current,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
            if changed == 1:
                _enqueue_inbound_notice_in_transaction(
                    conn,
                    claim,
                    notice_kind="terminal",
                    text=_INBOUND_TERMINAL_NOTICE,
                    now=current,
                )
    return changed == 1


def _recover_inflight() -> int:
    """Requeue only current-generation claims after the old process is gone."""

    with _state_write_transaction() as conn:
        inbox = conn.execute(
            "UPDATE feishu_inbox SET status='pending',claimed_at=0,claim_token='', "
            "claim_deadline=0,heartbeat_at=0 "
            "WHERE status='processing'"
        ).rowcount
        inbox_submitted = conn.execute(
            """
            UPDATE feishu_inbox
            SET status='recovery_required',last_error='media_upload_interrupted',
                claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                last_finish_outcome='recovery_required',finished_at=0
            WHERE status='submitting'
            """
        ).rowcount
        outbox = conn.execute(
            "UPDATE feishu_outbox SET status='pending',claimed_at=0,claim_token='', "
            "claim_deadline=0,heartbeat_at=0 "
            "WHERE status='processing'"
        ).rowcount
        submitted = conn.execute(
            """
            UPDATE feishu_outbox
            SET status='recovery_required',last_error='provider_submission_interrupted',
                claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                last_finish_outcome='recovery_required',delivered_at=0
            WHERE status='submitting'
            """
        ).rowcount
    return (
        max(0, int(inbox))
        + max(0, int(inbox_submitted))
        + max(0, int(outbox))
        + max(0, int(submitted))
    )


def _recover_stale_inflight(*, now=None) -> int:
    """Requeue claims only after their authoritative deadline plus grace."""

    grace = max(0.0, min(float(_CLAIM_GRACE_SECONDS), 60.0))
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        inbox = conn.execute(
            """
            UPDATE feishu_inbox SET status='pending',claimed_at=0,claim_token='',
                claim_deadline=0,heartbeat_at=0
            WHERE status='processing'
              AND (claim_deadline<=0 OR claim_deadline+?<=?)
            """,
            (grace, current),
        ).rowcount
        inbox_submitted = conn.execute(
            """
            UPDATE feishu_inbox
            SET status='recovery_required',last_error='media_upload_abandoned',
                claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                last_finish_outcome='recovery_required',finished_at=0
            WHERE status='submitting'
              AND (claim_deadline<=0 OR claim_deadline+?<=?)
            """,
            (grace, current),
        ).rowcount
        outbox = conn.execute(
            """
            UPDATE feishu_outbox SET status='pending',claimed_at=0,claim_token='',
                claim_deadline=0,heartbeat_at=0
            WHERE status='processing'
              AND (claim_deadline<=0 OR claim_deadline+?<=?)
            """,
            (grace, current),
        ).rowcount
        submitted = conn.execute(
            """
            UPDATE feishu_outbox
            SET status='recovery_required',last_error='provider_submission_abandoned',
                claimed_at=0,claim_token='',claim_deadline=0,heartbeat_at=0,
                last_finish_token=claim_token,last_finish_epoch=claim_epoch,
                last_finish_outcome='recovery_required',delivered_at=0
            WHERE status='submitting'
              AND (claim_deadline<=0 OR claim_deadline+?<=?)
            """,
            (grace, current),
        ).rowcount
    return (
        max(0, int(inbox))
        + max(0, int(inbox_submitted))
        + max(0, int(outbox))
        + max(0, int(submitted))
    )


def _claim_is_current(
    kind: str, claim: dict[str, object], *, now=None
) -> bool:
    """Validate token, monotonic claim epoch, and the hard lease deadline."""

    table = {"inbox": "feishu_inbox", "outbox": "feishu_outbox"}.get(kind)
    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if table is None or not claim_token or claim_epoch < 1:
        return False
    with _state_transaction() as conn:
        status_predicate = (
            "status IN ('processing','submitting')"
            if kind == "outbox"
            else "status IN ('processing','submitting')"
        )
        row = conn.execute(
            f"SELECT claim_deadline FROM {table} WHERE id=? AND {status_predicate} "
            "AND claim_token=? AND claim_epoch=?",
            (int(claim["id"]), claim_token, claim_epoch),
        ).fetchone()
        current = _policy_time(now)
    return bool(row is not None and float(row[0]) > current)


def _heartbeat_claim(
    kind: str, claim: dict[str, object], *, now=None
) -> bool:
    """Renew one still-live claim; an expired/reclaimed claim cannot resurrect."""

    table = {"inbox": "feishu_inbox", "outbox": "feishu_outbox"}.get(kind)
    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if table is None or not claim_token or claim_epoch < 1:
        return False
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        deadline = current + max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
        status_predicate = (
            "status IN ('processing','submitting')"
            if kind == "outbox"
            else "status IN ('processing','submitting')"
        )
        changed = conn.execute(
            f"UPDATE {table} SET heartbeat_at=?,claim_deadline=? "
            f"WHERE id=? AND {status_predicate} AND claim_token=? "
            "AND claim_epoch=? AND claim_deadline>?",
            (
                current,
                deadline,
                int(claim["id"]),
                claim_token,
                claim_epoch,
                current,
            ),
        ).rowcount
    if changed == 1:
        claim["claim_deadline"] = deadline
        return True
    return False


def _claim_finish_outcome(
    kind: str,
    claim: dict[str, object],
    *,
    ok: bool,
    recovery_required: bool = False,
) -> str:
    if recovery_required:
        return "recovery_required"
    if ok:
        return "done"
    attempts = int(claim.get("attempts") or 0) + 1
    terminal_at = 8 if kind == "inbox" else 12
    return "dead" if attempts >= terminal_at else "retry"


def _finish_was_committed(
    kind: str,
    claim: dict[str, object],
    *,
    ok: bool,
    recovery_required: bool = False,
    deadline_monotonic: float | None = None,
) -> bool:
    """Confirm a post-commit response loss without treating stale replay as success."""

    table = {"inbox": "feishu_inbox", "outbox": "feishu_outbox"}.get(kind)
    token = str(claim.get("claim_token") or "")
    epoch = int(claim.get("claim_epoch") or 0)
    if table is None or not token or epoch < 1:
        return False
    expected = _claim_finish_outcome(
        kind,
        claim,
        ok=ok,
        recovery_required=recovery_required,
    )
    with _state_transaction(deadline_monotonic=deadline_monotonic) as conn:
        row = conn.execute(
            f"SELECT last_finish_token,last_finish_epoch,last_finish_outcome "
            f"FROM {table} WHERE id=?",
            (int(claim["id"]),),
        ).fetchone()
    return bool(row and tuple(row) == (token, epoch, expected))


def _record_claim_health(error_code: str) -> None:
    with _HEALTH_LOCK:
        _HEALTH_STATE["service_state"] = "degraded"
        _HEALTH_STATE["last_error_code"] = error_code


def _record_claim_health_nonblocking(error_code: str) -> None:
    """Best-effort deadline-path projection; never wait or perform I/O."""

    if not _HEALTH_LOCK.acquire(blocking=False):
        return
    try:
        _HEALTH_STATE["service_state"] = "degraded"
        _HEALTH_STATE["last_error_code"] = error_code
    finally:
        _HEALTH_LOCK.release()


class _FeishuInboxClaimStorage:
    """Bind the shared lease lifecycle to one exact Feishu inbox epoch."""

    def __init__(self, claim: dict[str, object], *, clock=None) -> None:
        self._claim = claim
        self._clock = clock if callable(clock) else time.time

    def renew(self) -> bool:
        return _heartbeat_claim("inbox", self._claim, now=self._clock)

    def owns(self) -> bool:
        return _claim_is_current("inbox", self._claim, now=self._clock)

    def finish_before(
        self,
        outcome: _InboxFinishOutcome,
        *,
        deadline_monotonic: float,
    ) -> bool:
        ok, error_code = outcome[:2]
        recovery_required = bool(outcome[2]) if len(outcome) == 3 else False
        try:
            changed = _finish_inbound(
                self._claim,
                ok=bool(ok),
                error_code=str(error_code),
                recovery_required=recovery_required,
                now=self._clock,
                deadline_monotonic=deadline_monotonic,
            )
            _remaining_finish_budget(deadline_monotonic)
            return changed
        except sqlite3.Error:
            _record_claim_health_nonblocking("inbox_finish_storage_retry")
            raise

    def confirm_finish_before(
        self,
        outcome: _InboxFinishOutcome,
        *,
        deadline_monotonic: float,
    ) -> bool:
        ok, _error_code = outcome[:2]
        recovery_required = bool(outcome[2]) if len(outcome) == 3 else False
        confirmed = _finish_was_committed(
            "inbox",
            self._claim,
            ok=bool(ok),
            recovery_required=recovery_required,
            deadline_monotonic=deadline_monotonic,
        )
        _remaining_finish_budget(deadline_monotonic)
        return confirmed


class _FeishuInboxClaimPolicy:
    """Freeze the historical Feishu inbox timing and health projection."""

    def __init__(self, *, wait=None) -> None:
        ttl = max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
        self.heartbeat_interval = max(
            0.25,
            min(float(_CLAIM_HEARTBEAT_SECONDS), ttl / 3.0),
        )
        self.stop_timeout = min(ttl / 4.0 + 0.5, 8.0)
        self.finish_timeout = min(ttl / 4.0, 8.0)
        delays = tuple(float(value) for value in _FINISH_RETRY_DELAYS_SECONDS)
        self.finish_retry_delays = delays or (0.0,)
        self._wait = wait if callable(wait) else time.sleep

    def sleep(self, delay: float) -> None:
        self._wait(delay)

    @staticmethod
    def is_retryable(error: BaseException) -> bool:
        return isinstance(error, sqlite3.Error)

    @staticmethod
    def fault(code: str, error: BaseException | None = None) -> None:
        del error
        if code in {"heartbeat_storage_error", "commit_fence_storage_error"}:
            projected = "inbox_heartbeat_storage_error"
        elif code in {
            "heartbeat_lost",
            "heartbeat_not_started",
            "commit_fence_lost",
            "finish_fence_lost",
        }:
            projected = "inbox_heartbeat_lost"
        elif code == "heartbeat_start_error":
            projected = "inbox_heartbeat_start_error"
        elif code == "heartbeat_stop_timeout":
            projected = "inbox_heartbeat_stop_timeout"
        elif code == "finish_retry_exhausted":
            projected = "inbox_finish_storage_stuck"
        elif code in {"finish_storage_retry", "finish_confirmation_retry"}:
            projected = "inbox_finish_storage_retry"
        else:
            projected = f"inbox_{code}"
        _record_claim_health_nonblocking(projected)


class _FeishuInboxClaimSession(ClaimLeaseSession[_InboxFinishOutcome]):
    """Expose Feishu's provider/exception vocabulary over the shared session."""

    def permits_provider(self) -> bool:
        return self.before_provider()

    @contextmanager
    def commit_fence(self):
        try:
            with super().commit_fence():
                yield
        except ClaimLeaseLost as exc:
            raise FeishuLeaseLost("Feishu heartbeat no longer permits commit") from exc


def _new_inbound_claim_session(
    claim: dict[str, object], *, clock=None, wait=None
) -> _FeishuInboxClaimSession:
    return _FeishuInboxClaimSession(
        storage=_FeishuInboxClaimStorage(claim, clock=clock),
        policy=_FeishuInboxClaimPolicy(wait=wait),
        thread_name="feishu-inbox-heartbeat",
    )


class _FeishuOutboxClaimStorage:
    """Bind the shared lease lifecycle to one exact Feishu outbox epoch."""

    def __init__(self, claim: dict[str, object], *, clock=None) -> None:
        self._claim = claim
        self._clock = clock if callable(clock) else time.time

    def renew(self) -> bool:
        return _heartbeat_claim("outbox", self._claim, now=self._clock)

    def owns(self) -> bool:
        return _claim_is_current("outbox", self._claim, now=self._clock)

    def finish_before(
        self,
        outcome: _OutboxFinishOutcome,
        *,
        deadline_monotonic: float,
    ) -> bool:
        ok, error_code = outcome[:2]
        recovery_required = bool(outcome[2]) if len(outcome) == 3 else False
        try:
            changed = _finish_outbox(
                self._claim,
                ok=bool(ok),
                error_code=str(error_code),
                recovery_required=recovery_required,
                now=self._clock,
                deadline_monotonic=deadline_monotonic,
            )
            _remaining_finish_budget(deadline_monotonic)
            return changed
        except sqlite3.Error:
            _record_claim_health_nonblocking("outbox_finish_storage_retry")
            raise

    def confirm_finish_before(
        self,
        outcome: _OutboxFinishOutcome,
        *,
        deadline_monotonic: float,
    ) -> bool:
        ok, _error_code = outcome[:2]
        recovery_required = bool(outcome[2]) if len(outcome) == 3 else False
        confirmed = _finish_was_committed(
            "outbox",
            self._claim,
            ok=bool(ok),
            recovery_required=recovery_required,
            deadline_monotonic=deadline_monotonic,
        )
        _remaining_finish_budget(deadline_monotonic)
        return confirmed


class _FeishuOutboxClaimPolicy:
    """Freeze one outbox worker's timing, retry, and health projection policy."""

    def __init__(self, *, wait=None) -> None:
        ttl = max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
        self.heartbeat_interval = max(
            0.25,
            min(float(_CLAIM_HEARTBEAT_SECONDS), ttl / 3.0),
        )
        self.stop_timeout = min(ttl / 4.0 + 0.5, 8.0)
        self.finish_timeout = min(ttl / 4.0, 8.0)
        delays = tuple(float(value) for value in _FINISH_RETRY_DELAYS_SECONDS)
        self.finish_retry_delays = delays or (0.0,)
        self._wait = wait if callable(wait) else time.sleep

    def sleep(self, delay: float) -> None:
        self._wait(delay)

    @staticmethod
    def is_retryable(error: BaseException) -> bool:
        return isinstance(error, sqlite3.Error)

    @staticmethod
    def fault(code: str, error: BaseException | None = None) -> None:
        del error
        if code in {"heartbeat_storage_error", "commit_fence_storage_error"}:
            projected = "outbox_heartbeat_storage_error"
        elif code in {
            "heartbeat_lost",
            "heartbeat_not_started",
            "commit_fence_lost",
            "finish_fence_lost",
        }:
            projected = "outbox_heartbeat_lost"
        elif code == "heartbeat_start_error":
            projected = "outbox_heartbeat_start_error"
        elif code == "heartbeat_stop_timeout":
            projected = "outbox_heartbeat_stop_timeout"
        elif code == "finish_retry_exhausted":
            projected = "outbox_finish_storage_stuck"
        elif code in {"finish_storage_retry", "finish_confirmation_retry"}:
            projected = "outbox_finish_storage_retry"
        else:
            projected = f"outbox_{code}"
        _record_claim_health_nonblocking(projected)


class _FeishuOutboxClaimSession(ClaimLeaseSession[_OutboxFinishOutcome]):
    """Feishu outbox adapter over the channel-neutral shared lease session."""


def _new_outbox_claim_session(
    claim: dict[str, object], *, clock=None, wait=None
) -> _FeishuOutboxClaimSession:
    return _FeishuOutboxClaimSession(
        storage=_FeishuOutboxClaimStorage(claim, clock=clock),
        policy=_FeishuOutboxClaimPolicy(wait=wait),
        thread_name="feishu-outbox-heartbeat",
    )


def _maintain_state(
    *,
    now: float | None = None,
    done_ttl_seconds: float = 7 * 24 * 60 * 60,
    dead_ttl_seconds: float = 30 * 24 * 60 * 60,
    max_terminal_rows: int = 10_000,
) -> dict[str, int]:
    """Minimize retained personal data and place a hard cap on terminal rows."""

    current = time.time() if now is None else float(now)
    done_cutoff = current - max(0.0, float(done_ttl_seconds))
    dead_cutoff = current - max(0.0, float(dead_ttl_seconds))
    terminal_cap = max(0, min(int(max_terminal_rows), 1_000_000))
    removed = {"inbox": 0, "outbox": 0}
    with _state_transaction() as conn:
        # Upgrade legacy dead rows to the same privacy-minimized representation.
        conn.execute(
            """
            UPDATE feishu_inbox
            SET chat_id='',payload='{"state":"dead_tombstone","version":1}'
            WHERE status='dead'
            """
        )
        conn.execute(
            """
            UPDATE feishu_outbox
            SET chat_id='',content='{"state":"dead_tombstone","version":1}'
            WHERE status='dead'
            """
        )
        removed["inbox"] += max(
            0,
            conn.execute(
                """
                DELETE FROM feishu_inbox
                WHERE (status='done' AND COALESCE(NULLIF(finished_at,0),received_at)<?)
                   OR (status='dead' AND COALESCE(NULLIF(finished_at,0),received_at)<?)
                """,
                (done_cutoff, dead_cutoff),
            ).rowcount,
        )
        removed["outbox"] += max(
            0,
            conn.execute(
                """
                DELETE FROM feishu_outbox
                WHERE (status='done' AND COALESCE(NULLIF(delivered_at,0),created_at)<?)
                   OR (status='dead' AND COALESCE(NULLIF(delivered_at,0),created_at)<?)
                """,
                (done_cutoff, dead_cutoff),
            ).rowcount,
        )
        removed["inbox"] += max(
            0,
            conn.execute(
                """
                DELETE FROM feishu_inbox WHERE id IN (
                  SELECT id FROM feishu_inbox
                  WHERE status IN ('done','dead')
                  ORDER BY COALESCE(NULLIF(finished_at,0),received_at) DESC,id DESC
                  LIMIT -1 OFFSET ?
                )
                """,
                (terminal_cap,),
            ).rowcount,
        )
        removed["outbox"] += max(
            0,
            conn.execute(
                """
                DELETE FROM feishu_outbox WHERE id IN (
                  SELECT id FROM feishu_outbox
                  WHERE status IN ('done','dead')
                  ORDER BY COALESCE(NULLIF(delivered_at,0),created_at) DESC,id DESC
                  LIMIT -1 OFFSET ?
                )
                """,
                (terminal_cap,),
            ).rowcount,
        )
    return removed


def _safe_error_code(value: object, fallback: str = "connection_error") -> str:
    candidate = str(value or "")
    if (
        not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", candidate)
        or re.search(
            r"(?i)(?:secret|access.?key|ticket|token|password|authorization|bearer)",
            candidate,
        )
    ):
        return fallback
    return candidate


def _mark_connected(*, now: float | None = None) -> None:
    current = time.time() if now is None else float(now)
    with _HEALTH_LOCK:
        generation = int(_HEALTH_STATE["connection_generation"]) + 1
        _HEALTH_STATE.update(
            {
                "connected": True,
                "service_state": "running",
                "consecutive_reconnect_failures": 0,
                "last_connected_at": current,
                "last_error_code": "",
                "connection_generation": generation,
            }
        )


def _connection_generation() -> int:
    with _HEALTH_LOCK:
        return int(_HEALTH_STATE["connection_generation"])


def _reconnect_backoff_step(
    current_backoff: int, *, observed_connected: bool
) -> tuple[int, int]:
    bounded = max(3, min(int(current_backoff), 30))
    delay = 3 if observed_connected else bounded
    return delay, min(delay * 2, 30)


def _mark_disconnected(
    error_code: object = "connection_error",
    *,
    now: float | None = None,
    count_failure: bool = True,
) -> None:
    del now  # Kept in the interface so deterministic tests/callers share one clock shape.
    with _HEALTH_LOCK:
        failures = int(_HEALTH_STATE["consecutive_reconnect_failures"])
        _HEALTH_STATE.update(
            {
                "connected": False,
                "service_state": "degraded",
                "consecutive_reconnect_failures": failures + int(count_failure),
                "last_error_code": _safe_error_code(error_code),
            }
        )


def _touch_event_received(*, now: float | None = None) -> None:
    with _HEALTH_LOCK:
        _HEALTH_STATE["last_event_received_at"] = (
            time.time() if now is None else float(now)
        )


def _touch_message_finished(*, now: float | None = None) -> None:
    with _HEALTH_LOCK:
        _HEALTH_STATE["last_message_finished_at"] = (
            time.time() if now is None else float(now)
        )


def _processing_claim_evidence(*, now: float) -> dict[str, float | int]:
    """Project aggregate lease evidence without IDs, payloads, or claim tokens."""

    current = float(now)
    grace = max(0.0, min(float(_CLAIM_GRACE_SECONDS), 60.0))
    evidence: dict[str, float | int] = {}
    oldest_values: list[float] = []
    expiry_values: list[float] = []
    expired_total = 0
    stuck_total = 0
    with _state_transaction() as conn:
        for kind, table in (
            ("inbound", "feishu_inbox"),
            ("outbound", "feishu_outbox"),
        ):
            active_statuses = (
                "('processing','submitting')"
                if kind == "outbound"
                else "('processing','submitting')"
            )
            row = conn.execute(
                f"""
                SELECT COUNT(*),
                       MIN(CASE WHEN claimed_at>0 THEN claimed_at END),
                       MIN(CASE WHEN claim_deadline>0 THEN claim_deadline END),
                       SUM(CASE WHEN claim_deadline>0 AND claim_deadline<=? THEN 1 ELSE 0 END),
                       SUM(CASE WHEN claim_deadline<=0 OR claim_deadline+?<? THEN 1 ELSE 0 END)
                FROM {table} WHERE status IN {active_statuses}
                """,
                (current, grace, current),
            ).fetchone()
            count = int(row[0] or 0)
            oldest = (
                max(0.0, current - float(row[1]))
                if row[1] is not None
                else 0.0
            )
            next_expiry = (
                max(0.0, float(row[2]) - current)
                if row[2] is not None
                else 0.0
            )
            expired = int(row[3] or 0)
            stuck = int(row[4] or 0)
            evidence[f"processing_{kind}"] = count
            evidence[f"oldest_{kind}_processing_age_seconds"] = oldest
            evidence[f"expired_{kind}_claims"] = expired
            evidence[f"processing_stuck_{kind}"] = stuck
            if count:
                oldest_values.append(oldest)
                expiry_values.append(next_expiry)
            expired_total += expired
            stuck_total += stuck
    evidence.update(
        {
            "oldest_processing_age_seconds": max(oldest_values, default=0.0),
            "next_claim_expiry_seconds": min(expiry_values, default=0.0),
            "expired_claims": expired_total,
            "processing_stuck": stuck_total,
            "claim_ttl_seconds": max(
                1.0, min(float(_CLAIM_TTL_SECONDS), 300.0)
            ),
            "claim_grace_seconds": grace,
        }
    )
    return evidence


def _claim_failure_still_active(error_code: object) -> bool:
    code = str(error_code or "")
    if code.startswith("inbox_") and (
        "finish_storage" in code or "heartbeat" in code
    ):
        try:
            return _inbox_status_counts(("processing",)) > 0
        except Exception:  # noqa: BLE001 - a failed health read remains degraded
            return True
    if code == "inbox_recovery_required":
        try:
            return _inbox_status_counts(("recovery_required",)) > 0
        except Exception:  # noqa: BLE001 - a failed health read remains degraded
            return True
    if code.startswith("outbox_") and (
        "finish_storage" in code or "heartbeat" in code
    ):
        try:
            return _outbox_status_counts(("processing", "submitting")) > 0
        except Exception:  # noqa: BLE001 - a failed health read remains degraded
            return True
    if code == "outbox_recovery_required":
        try:
            return _outbox_status_counts(("recovery_required",)) > 0
        except Exception:  # noqa: BLE001 - a failed health read remains degraded
            return True
    if code in {"video_recovery_required", "video_state_invalid"}:
        try:
            return any(
                str(record.get("state") or "") == "recovery_required"
                for record in _pending_load().values()
                if isinstance(record, dict)
            )
        except Exception:  # noqa: BLE001 - unreadable durable state stays degraded
            return True
    return False


def _health_snapshot(*, now: float | None = None) -> dict[str, object]:
    current = time.time() if now is None else float(now)
    recovery_required_inbound = _inbox_status_counts(("recovery_required",))
    pending_inbound = _inbox_status_counts(
        ("pending", "processing", "submitting", "recovery_required")
    )
    pending_outbound = _outbox_status_counts(
        ("pending", "processing", "submitting", "recovery_required")
    )
    dead_inbound = _inbox_status_counts(("dead",))
    dead_outbound = _outbox_status_counts(("dead",))
    video_state_invalid = False
    try:
        pending_videos = _pending_load()
        recovery_required_video = sum(
            1
            for record in pending_videos.values()
            if isinstance(record, dict)
            and str(record.get("state") or "") == "recovery_required"
        )
    except Exception:  # noqa: BLE001 - unreadable durable state fails readiness
        recovery_required_video = 0
        video_state_invalid = True
    claim_evidence = _processing_claim_evidence(now=current)
    with _HEALTH_LOCK:
        state = dict(_HEALTH_STATE)
        access_configured = bool(_ACCESS_CONFIGURED)
        engine_available = bool(_ENGINE_AVAILABLE)
        engine_readiness_reason = str(_ENGINE_READINESS_REASON)
    bridge_key_configured = bool(str(ENGINE_KEY or "").strip())
    reasons: list[str] = []
    if not state["connected"]:
        reasons.append("disconnected")
    if pending_inbound:
        reasons.append("pending_inbound")
    if recovery_required_inbound:
        reasons.append("inbox_recovery_required")
    if pending_outbound:
        reasons.append("pending_outbound")
    if recovery_required_video:
        reasons.append("video_recovery_required")
    if video_state_invalid:
        reasons.append("video_state_invalid")
    if int(claim_evidence["expired_claims"]):
        reasons.append("claim_expired")
    if int(claim_evidence["processing_stuck"]):
        reasons.append("processing_stuck")
    if int(state["consecutive_reconnect_failures"]):
        reasons.append("reconnect_failures")
    if dead_inbound:
        reasons.append("dead_inbound")
    if dead_outbound:
        reasons.append("dead_outbound")
    if not access_configured:
        reasons.append("access_locked")
    if not bridge_key_configured:
        reasons.append("bridge_key_missing")
    if not engine_available:
        reasons.append(
            engine_readiness_reason
            if engine_readiness_reason
            in {
                "ready_no_model",
                "requested_model_unavailable",
                "engine_unavailable",
            }
            else "engine_unavailable"
        )
    if state["service_state"] == "stopping":
        reasons.append("stopping")
    elif state["service_state"] == "degraded" and not reasons:
        reasons.append("degraded")
    ready = not reasons
    if ready:
        reported_state = "healthy"
    elif state["service_state"] == "stopping":
        reported_state = "stopping"
    elif state["service_state"] == "starting":
        reported_state = "starting"
    else:
        reported_state = "degraded"
    return {
        # v1 is an additive projection consumed by the existing Supervisor;
        # the new lease evidence fields are backward compatible.
        "schema": "nachuan.feishu-bridge-health.v1",
        "state": reported_state,
        "ready": ready,
        "connected": bool(state["connected"]),
        "fresh": True,
        "pid": os.getpid(),
        "updated_at": current,
        "heartbeat_at": current,
        "fresh_until": current + 10.0,
        "freshness_ttl_seconds": 10,
        "pending_inbound": pending_inbound,
        "recovery_required_inbound": recovery_required_inbound,
        "pending_outbound": pending_outbound,
        "recovery_required_video": recovery_required_video,
        "video_state_invalid": video_state_invalid,
        "dead_inbound": dead_inbound,
        "dead_outbound": dead_outbound,
        **claim_evidence,
        "consecutive_reconnect_failures": int(
            state["consecutive_reconnect_failures"]
        ),
        "last_connected_at": float(state["last_connected_at"]),
        "last_event_received_at": float(state["last_event_received_at"]),
        "last_message_finished_at": float(state["last_message_finished_at"]),
        "last_error_code": str(state["last_error_code"]),
        "access_configured": access_configured,
        "bridge_key_configured": bridge_key_configured,
        "engine_available": engine_available,
        "engine_readiness_reason": engine_readiness_reason,
        "readiness_reasons": reasons,
    }


def _update_health(*, now: float | None = None) -> dict[str, object]:
    """Publish an allow-listed, secret-free snapshot using fsync + atomic replace."""

    _refresh_access_configured()
    with _HEALTH_LOCK:
        snapshot = _health_snapshot(now=now)
        _HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = _HEALTH_FILE.with_name(
            f".{_HEALTH_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        encoded = json.dumps(
            snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, _HEALTH_FILE)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return snapshot


def _stable_delivery_uuid(delivery_key: str | None) -> str:
    if delivery_key:
        return str(uuid.uuid5(_FEISHU_UUID_NAMESPACE, delivery_key))
    return str(uuid.uuid4())


def _enqueue_outbox_in_transaction(
    conn: sqlite3.Connection,
    chat_id: str,
    msg_type: str,
    content: str,
    *,
    delivery_key: str | None,
    now: float,
) -> str:
    """Persist one idempotent delivery on the caller's SQLite transaction."""

    context_message_id = str(
        getattr(_DELIVERY_CONTEXT, "message_id", "") or ""
    )
    if context_message_id:
        context_claim_id = int(
            getattr(_DELIVERY_CONTEXT, "claim_id", 0) or 0
        )
        context_token = str(
            getattr(_DELIVERY_CONTEXT, "claim_token", "") or ""
        )
        context_epoch = int(
            getattr(_DELIVERY_CONTEXT, "claim_epoch", 0) or 0
        )
        context_guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
        if context_guard is not None and bool(getattr(context_guard, "lost", True)):
            raise FeishuLeaseLost("Feishu inbound heartbeat already lost")
        if context_claim_id < 1 or not context_token or context_epoch < 1:
            raise FeishuLeaseLost("incomplete Feishu inbound lease context")
        owned = conn.execute(
            """
            SELECT 1 FROM feishu_inbox
            WHERE id=? AND message_id=? AND status IN ('processing','submitting')
              AND claim_token=? AND claim_epoch=? AND claim_deadline>?
            """,
            (
                context_claim_id,
                context_message_id,
                context_token,
                context_epoch,
                float(now),
            ),
        ).fetchone()
        if owned is None:
            raise FeishuLeaseLost("Feishu inbound lease is no longer current")
    if not chat_id or msg_type not in {"text", "image", "media"}:
        raise ValueError("invalid Feishu delivery")
    if (
        not isinstance(content, str)
        or not content
        or len(content.encode("utf-8")) > 64 * 1024
    ):
        raise ValueError("Feishu delivery content is empty or too large")
    delivery_uuid = _stable_delivery_uuid(delivery_key)
    existing = conn.execute(
        "SELECT chat_id,msg_type,content FROM feishu_outbox WHERE delivery_uuid=?",
        (delivery_uuid,),
    ).fetchone()
    if existing:
        if tuple(existing) != (chat_id, msg_type, content):
            raise RuntimeError("Feishu idempotency key conflicts with another payload")
        return delivery_uuid
    active = conn.execute(
        """
        SELECT COUNT(*),
               SUM(CASE WHEN chat_id=? THEN 1 ELSE 0 END)
        FROM feishu_outbox
        WHERE status IN ('pending','processing','submitting','recovery_required')
        """,
        (chat_id,),
    ).fetchone()
    total_active = int(active[0] or 0)
    chat_active = int(active[1] or 0)
    if (
        total_active >= max(1, int(_MAX_ACTIVE_OUTBOUND_ROWS))
        or chat_active >= max(1, int(_MAX_ACTIVE_OUTBOUND_PER_CHAT))
    ):
        raise FeishuQueueFull("Feishu outbound durable queue is full")
    conn.execute(
        """
        INSERT INTO feishu_outbox
          (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at)
        VALUES (?,?,?,?,?,?)
        """,
        (delivery_uuid, chat_id, msg_type, content, now, now),
    )
    return delivery_uuid


def _enqueue_inbound_notice_in_transaction(
    conn: sqlite3.Connection,
    claim: dict[str, object],
    *,
    notice_kind: str,
    text: str,
    now: float,
) -> str | None:
    inbound = claim.get("payload")
    if not isinstance(inbound, dict):
        raise ValueError("Feishu inbound claim payload is missing")
    if str(inbound.get("message_type") or "") != "text":
        return None
    message_id = str(inbound.get("message_id") or "")
    chat_id = str(inbound.get("chat_id") or "")
    return _enqueue_outbox_in_transaction(
        conn,
        chat_id,
        "text",
        json.dumps({"text": text}, ensure_ascii=False),
        delivery_key=f"inbound:{message_id}:notice:{notice_kind}",
        now=now,
    )


def _persist_text_progress_notice(
    message_id: str,
    chat_id: str,
    claim_token: str,
    claim_epoch: int,
    cancelled: threading.Event,
    *,
    lease_guard=None,
    now=None,
) -> bool:
    """Use a fresh connection and fence progress against cancellation/claim loss."""

    if (
        not message_id
        or not chat_id
        or not claim_token
        or int(claim_epoch) < 1
        or cancelled.is_set()
        or (
            lease_guard is not None
            and bool(getattr(lease_guard, "lost", True))
        )
    ):
        return False
    fence_factory = getattr(lease_guard, "commit_fence", None)
    if lease_guard is not None and not callable(fence_factory):
        return False
    fence = fence_factory() if callable(fence_factory) else nullcontext()
    with fence:
        with _state_write_transaction() as conn:
            current = _policy_time(now)
            # The worker sets cancellation before it can enqueue the final reply.
            # Rechecking while holding the DB write lock makes the ordering atomic:
            # progress commits first, or it is omitted entirely.
            if cancelled.is_set():
                return False
            row = conn.execute(
                """
                SELECT payload FROM feishu_inbox
                WHERE message_id=? AND chat_id=? AND status='processing'
                  AND claim_token=? AND claim_epoch=? AND claim_deadline>?
                """,
                (message_id, chat_id, claim_token, int(claim_epoch), current),
            ).fetchone()
            if row is None:
                return False
            try:
                inbound = json.loads(str(row[0]))
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            if str(inbound.get("message_type") or "") != "text":
                return False
            _enqueue_outbox_in_transaction(
                conn,
                chat_id,
                "text",
                json.dumps({"text": _TEXT_PROGRESS_NOTICE}, ensure_ascii=False),
                delivery_key=f"inbound:{message_id}:notice:progress",
                now=current,
            )
    return True


def _fire_text_progress_notice(
    message_id: str,
    chat_id: str,
    claim_token: str,
    claim_epoch: int,
    lease_guard,
    cancelled: threading.Event,
) -> None:
    try:
        _persist_text_progress_notice(
            message_id,
            chat_id,
            claim_token,
            claim_epoch,
            cancelled,
            lease_guard=lease_guard,
        )
    except FeishuLeaseLost:
        return
    except Exception as exc:  # noqa: BLE001 - progress is optional, the Turn is not
        with _HEALTH_LOCK:
            _HEALTH_STATE["service_state"] = "degraded"
            _HEALTH_STATE["last_error_code"] = _safe_error_code(
                type(exc).__name__, "progress_notice_error"
            )


def _start_text_progress_timer(
    chat_id: str,
) -> tuple[threading.Timer, threading.Event] | None:
    message_id = str(getattr(_DELIVERY_CONTEXT, "message_id", "") or "")
    claim_token = str(getattr(_DELIVERY_CONTEXT, "claim_token", "") or "")
    claim_epoch = int(getattr(_DELIVERY_CONTEXT, "claim_epoch", 0) or 0)
    lease_guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
    if not message_id or not chat_id or not claim_token or claim_epoch < 1:
        return None
    cancelled = threading.Event()
    timer: threading.Timer | None = None
    try:
        timer = threading.Timer(
            _TEXT_PROGRESS_AFTER_SECONDS,
            _fire_text_progress_notice,
            args=(
                message_id,
                chat_id,
                claim_token,
                claim_epoch,
                lease_guard,
                cancelled,
            ),
        )
        timer.daemon = True
        timer.start()
    except Exception as exc:  # noqa: BLE001 - progress is optional, the Turn is not
        cancelled.set()
        if timer is not None:
            try:
                timer.cancel()
            except Exception:  # noqa: BLE001 - best-effort cleanup only
                pass
        with _HEALTH_LOCK:
            _HEALTH_STATE["service_state"] = "degraded"
            _HEALTH_STATE["last_error_code"] = _safe_error_code(
                type(exc).__name__, "progress_timer_start_error"
            )
        return None
    return timer, cancelled


def _cancel_text_progress_timer(
    progress_timer: tuple[threading.Timer, threading.Event] | None,
) -> None:
    if progress_timer is None:
        return
    timer, cancelled = progress_timer
    cancelled.set()
    timer.cancel()


def _enqueue_outbox(
    chat_id: str,
    msg_type: str,
    content: str,
    *,
    delivery_key: str | None = None,
) -> str:
    context_message_id = str(
        getattr(_DELIVERY_CONTEXT, "message_id", "") or ""
    )
    lease_guard = getattr(_DELIVERY_CONTEXT, "lease_guard", None)
    fence_factory = getattr(lease_guard, "commit_fence", None)
    if context_message_id and lease_guard is not None and not callable(fence_factory):
        raise FeishuLeaseLost("Feishu heartbeat commit fence is unavailable")
    fence = fence_factory() if callable(fence_factory) else nullcontext()
    with fence:
        with _state_write_transaction() as conn:
            now = _policy_time()
            return _enqueue_outbox_in_transaction(
                conn,
                chat_id,
                msg_type,
                content,
                delivery_key=delivery_key,
                now=now,
            )


def _outbox_status_counts(statuses: tuple[str, ...]) -> int:
    if not statuses:
        return 0
    placeholders = ",".join("?" for _ in statuses)
    with _state_transaction() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM feishu_outbox WHERE status IN ({placeholders})",
            statuses,
        ).fetchone()
    return int(row[0] if row else 0)


def _claim_outbox(
    *, now=None, delivery_uuid: str | None = None
) -> dict[str, object] | None:
    ttl = max(1.0, min(float(_CLAIM_TTL_SECONDS), 300.0))
    claim_token = uuid.uuid4().hex
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        extra = ""
        params: list[object] = [current]
        if delivery_uuid:
            extra = " AND candidate.delivery_uuid=?"
            params.append(delivery_uuid)
        row = conn.execute(
            """
            SELECT candidate.id,candidate.delivery_uuid,candidate.chat_id,
                   candidate.msg_type,candidate.content,candidate.attempts,
                   candidate.claim_epoch
            FROM feishu_outbox AS candidate
            WHERE candidate.status='pending' AND candidate.next_attempt_at<=?
            """
            + extra
            + """
              AND NOT EXISTS (
                SELECT 1 FROM feishu_outbox AS earlier
                WHERE earlier.chat_id=candidate.chat_id
                  AND earlier.id<candidate.id
                  AND earlier.status IN (
                    'pending','processing','submitting','recovery_required'
                  )
              )
              ORDER BY candidate.id LIMIT 1
              """,
            params,
        ).fetchone()
        if row is None:
            return None
        changed = conn.execute(
            "UPDATE feishu_outbox SET status='processing',claimed_at=?,claim_token=?, "
            "claim_deadline=?,heartbeat_at=?,claim_epoch=claim_epoch+1 "
            "WHERE id=? AND status='pending'",
            (current, claim_token, current + ttl, current, row[0]),
        ).rowcount
        if changed != 1:
            return None
        return {
            "id": int(row[0]),
            "delivery_uuid": str(row[1]),
            "chat_id": str(row[2]),
            "msg_type": str(row[3]),
            "content": str(row[4]),
            "attempts": int(row[5]),
            "claim_token": claim_token,
            "claim_deadline": current + ttl,
            "claim_epoch": int(row[6]) + 1,
        }


def _finish_outbox(
    claim: dict[str, object],
    *,
    ok: bool,
    error_code: str = "",
    recovery_required: bool = False,
    now=None,
    deadline_monotonic: float | None = None,
) -> bool:
    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if not claim_token or claim_epoch < 1:
        return False
    if recovery_required and ok:
        raise ValueError("a successful delivery cannot require recovery")
    attempts = int(claim["attempts"]) + (0 if ok or recovery_required else 1)
    status = "done" if ok else "dead" if attempts >= 12 else "pending"
    safe_error = re.sub(r"[^A-Za-z0-9_.-]+", "_", error_code or "delivery_failed")[:64]
    with _state_write_transaction(
        deadline_monotonic=deadline_monotonic
    ) as conn:
        current = _policy_time(now)
        if recovery_required:
            changed = conn.execute(
                """
                UPDATE feishu_outbox
                SET status='recovery_required',last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,
                    last_finish_outcome='recovery_required',delivered_at=0
                WHERE id=? AND status IN ('processing','submitting') AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    safe_error,
                    claim_token,
                    claim_epoch,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
            return changed == 1
        next_attempt = (
            current if ok else current + min(2 ** min(attempts, 8), 300)
        )
        if status == "dead":
            changed = conn.execute(
                """
                UPDATE feishu_outbox
                SET status='dead',attempts=?,next_attempt_at=?,last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,last_finish_outcome='dead',
                    delivered_at=?,chat_id='',
                    content='{"state":"dead_tombstone","version":1}'
                WHERE id=? AND status IN ('processing','submitting') AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    attempts,
                    next_attempt,
                    safe_error,
                    claim_token,
                    claim_epoch,
                    current,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
        else:
            changed = conn.execute(
                """
                UPDATE feishu_outbox
                SET status=?,attempts=?,next_attempt_at=?,last_error=?,claimed_at=0,
                    claim_token='',claim_deadline=0,heartbeat_at=0,
                    last_finish_token=?,last_finish_epoch=?,last_finish_outcome=?,
                    delivered_at=?
                WHERE id=? AND status IN ('processing','submitting') AND claim_token=?
                  AND claim_epoch=? AND claim_deadline>?
                """,
                (
                    status,
                    attempts,
                    next_attempt,
                    "" if ok else safe_error,
                    claim_token,
                    claim_epoch,
                    "done" if ok else "retry",
                    current if ok else 0,
                    int(claim["id"]),
                    claim_token,
                    claim_epoch,
                    current,
                ),
            ).rowcount
    return changed == 1


def _begin_outbox_submission(
    claim: dict[str, object], *, now=None
) -> bool:
    """Durably cross the no-automatic-replay boundary before provider I/O."""

    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if not claim_token or claim_epoch < 1:
        return False
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        changed = conn.execute(
            """
            UPDATE feishu_outbox
            SET status='submitting',last_error=''
            WHERE id=? AND status='processing' AND claim_token=?
              AND claim_epoch=? AND claim_deadline>?
            """,
            (
                int(claim["id"]),
                claim_token,
                claim_epoch,
                current,
            ),
        ).rowcount
    return changed == 1


def _quarantine_outbox_submission(
    claim: dict[str, object], *, error_code: str, now=None
) -> bool:
    """Exact-CAS an uncertain submitted row into permanent manual recovery."""

    claim_token = str(claim.get("claim_token") or "")
    claim_epoch = int(claim.get("claim_epoch") or 0)
    if not claim_token or claim_epoch < 1:
        return False
    safe_error = re.sub(
        r"[^A-Za-z0-9_.-]+", "_", error_code or "provider_outcome_unknown"
    )[:64]
    with _state_write_transaction() as conn:
        current = _policy_time(now)
        changed = conn.execute(
            """
            UPDATE feishu_outbox
            SET status='recovery_required',last_error=?,claimed_at=0,
                claim_token='',claim_deadline=0,heartbeat_at=0,
                last_finish_token=?,last_finish_epoch=?,
                last_finish_outcome='recovery_required',delivered_at=0
            WHERE id=? AND status='submitting' AND claim_token=?
              AND claim_epoch=? AND claim_deadline>?
            """,
            (
                safe_error,
                claim_token,
                claim_epoch,
                int(claim["id"]),
                claim_token,
                claim_epoch,
                current,
            ),
        ).rowcount
    return changed == 1


def _send_outbox_claim(claim: dict[str, object]) -> None:
    body = (
        CreateMessageRequestBody.builder()
        .receive_id(str(claim["chat_id"]))
        .msg_type(str(claim["msg_type"]))
        .content(str(claim["content"]))
        .uuid(str(claim["delivery_uuid"]))
        .build()
    )
    request = (
        CreateMessageRequest.builder()
        .receive_id_type("chat_id")
        .request_body(body)
        .build()
    )
    try:
        response = _api["c"].im.v1.message.create(request)
        success_value = response.success()
        code = response.code if success_value is False else None
    except Exception as exc:
        raise FeishuProviderOutcomeUnknown("Feishu send outcome is unknown") from exc
    if success_value is True:
        return
    if (
        success_value is False
        and isinstance(code, int)
        and not isinstance(code, bool)
        and code > 0
    ):
        raise FeishuProviderRejected(f"feishu_business_{code}")
    raise FeishuProviderOutcomeUnknown("Feishu send outcome is unknown")


def _deliver_outbox_claim(
    claim: dict[str, object], *, now=None, lease_session=None
) -> bool:
    """Persist the submission phase, then fence both sides of provider I/O."""

    if lease_session is None:
        clock = (
            time.time
            if now is None
            else now
            if callable(now)
            else (lambda value=float(now): value)
        )
        owned_session = _new_outbox_claim_session(claim, clock=clock)
        if not owned_session.start():
            owned_session.close()
            return False
        try:
            return _deliver_outbox_claim(
                claim,
                now=now,
                lease_session=owned_session,
            )
        finally:
            owned_session.close()
    if not lease_session.before_provider():
        return False
    try:
        with lease_session.commit_fence():
            if not _begin_outbox_submission(claim, now=now):
                return False
    except ClaimLeaseLost:
        return False
    try:
        _send_outbox_claim(claim)
    finally:
        still_owned = lease_session.before_provider()
    return bool(still_owned)


def _finish_outbox_session(
    lease_session: _FeishuOutboxClaimSession,
    *,
    ok: bool,
    error_code: str = "",
    recovery_required: bool = False,
) -> bool:
    """Let the shared session own the single finish gate and durable CAS."""

    outcome: _OutboxFinishOutcome
    if recovery_required:
        outcome = (False, str(error_code), True)
    else:
        outcome = (bool(ok), str(error_code))
    return lease_session.finish(outcome)


def _drain_outbox(
    *,
    now: float | None = None,
    limit: int = 20,
    delivery_uuid: str | None = None,
) -> int:
    fixed_now = None if now is None else float(now)
    delivered = 0
    for _ in range(max(0, min(int(limit), 200))):
        current = time.time() if fixed_now is None else fixed_now
        claim = _claim_outbox(
            now=time.time if fixed_now is None else current,
            delivery_uuid=delivery_uuid,
        )
        if claim is None:
            break
        clock = time.time if fixed_now is None else (lambda value=current: value)
        lease_session = _new_outbox_claim_session(claim, clock=clock)
        if not lease_session.start():
            lease_session.close()
            continue
        sent = False
        try:
            boundary_now = time.time if fixed_now is None else current
            sent = _deliver_outbox_claim(
                claim,
                now=boundary_now,
                lease_session=lease_session,
            )
        except FeishuProviderRejected as exc:
            if lease_session.lost:
                if _quarantine_outbox_submission(
                    claim,
                    error_code="provider_rejection_lease_lost",
                    now=clock,
                ):
                    _record_claim_health("outbox_recovery_required")
            else:
                _finish_outbox_session(
                    lease_session,
                    ok=False,
                    error_code=type(exc).__name__,
                )
        except Exception:  # noqa: BLE001 - any non-rejection outcome is unknown
            isolated = False
            if lease_session.lost:
                isolated = _quarantine_outbox_submission(
                    claim,
                    error_code="provider_outcome_unknown",
                    now=clock,
                )
            else:
                isolated = _finish_outbox_session(
                    lease_session,
                    ok=False,
                    error_code="provider_outcome_unknown",
                    recovery_required=True,
                )
            if isolated:
                _record_claim_health("outbox_recovery_required")
        else:
            if (
                sent
                and _finish_outbox_session(lease_session, ok=True)
            ):
                delivered += 1
            elif not sent and _quarantine_outbox_submission(
                claim,
                error_code="provider_post_pulse_lost",
                now=clock,
            ):
                _record_claim_health("outbox_recovery_required")
        finally:
            lease_session.close()
    return delivered


def _delivery_done(delivery_uuid: str) -> bool:
    with _state_transaction() as conn:
        row = conn.execute(
            "SELECT status FROM feishu_outbox WHERE delivery_uuid=?", (delivery_uuid,)
        ).fetchone()
    return bool(row and row[0] == "done")


def _next_delivery_key(kind: str) -> str | None:
    """Derive repeatable message UUID inputs while handling one durable inbox row."""

    message_id = getattr(_DELIVERY_CONTEXT, "message_id", "")
    if not message_id:
        return None
    sequence = int(getattr(_DELIVERY_CONTEXT, "sequence", 0))
    _DELIVERY_CONTEXT.sequence = sequence + 1
    return f"inbound:{message_id}:{sequence}:{kind}"


def _reply(chat_id: str, text: str, *, delivery_key: str | None = None) -> bool:
    content = json.dumps({"text": text[:4000]}, ensure_ascii=False)
    if delivery_key is None:
        delivery_key = _next_delivery_key("text")
    delivery_uuid = _enqueue_outbox(
        chat_id, "text", content, delivery_key=delivery_key
    )
    _drain_outbox(limit=1, delivery_uuid=delivery_uuid)
    return _delivery_done(delivery_uuid)


def _download_url(url: str, kind: str) -> bytes:
    """下载媒体 URL；支持 data:base64 内联图。"""
    if kind == "image":
        max_bytes = _MAX_GENERATED_IMAGE_BYTES
        allowed_prefixes = ("image/",)
        allowed_exact = ()
    elif kind == "video":
        max_bytes = _MAX_GENERATED_VIDEO_BYTES
        allowed_prefixes = ("video/",)
        allowed_exact = ("application/octet-stream",)
    else:
        raise ValueError("未知媒体类型")
    if url.startswith("data:"):
        header, separator, payload = url.partition(",")
        if (
            not separator
            or not header.lower().startswith(f"data:{kind}/")
            or ";base64" not in header.lower()
        ):
            raise ValueError("data URI 类型不允许")
        if len(payload) > ((max_bytes + 2) // 3) * 4 + 4:
            raise ValueError("媒体超过大小上限")
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("data URI base64 无效") from exc
        if len(decoded) > max_bytes:
            raise ValueError("媒体超过大小上限")
        return decoded
    try:
        _require_live_inbound_provider_fence()
        data = fetch_public_bytes(
            url,
            max_bytes=max_bytes,
            allowed_type_prefixes=allowed_prefixes,
            allowed_exact_types=allowed_exact,
            total_timeout=_MEDIA_TOTAL_TIMEOUT_SECONDS,
            idle_timeout=_MEDIA_IDLE_TIMEOUT_SECONDS,
            max_redirects=5,
            headers={"Accept": "image/*" if kind == "image" else "video/*"},
        ).data
        _require_live_inbound_provider_fence()
        return data
    except PublicFetchError as exc:
        raise ValueError("媒体 URL/响应不符合公网安全策略") from exc


def _upload_image(data: bytes) -> str:
    from io import BytesIO

    req = (
        CreateImageRequest.builder()
        .request_body(
            CreateImageRequestBody.builder().image_type("message").image(BytesIO(data)).build()
        )
        .build()
    )
    submission_sha256 = _begin_inbound_media_upload_submission(
        "image",
        data,
        name="message-image",
        ftype="image",
    )
    _require_live_inbound_provider_fence()
    try:
        resp = _api["c"].im.v1.image.create(req)
    except Exception as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu image upload outcome is unknown"
        ) from exc
    try:
        success = resp.success()
    except Exception as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu image upload outcome is unknown"
        ) from exc
    if success is not True and success is not False:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu image upload outcome is unknown"
        )
    if not success:
        _abort_inbound_media_upload_submission(submission_sha256)
        raise RuntimeError(f"上传图片失败 {resp.code} {resp.msg}")
    image_key = str(getattr(getattr(resp, "data", None), "image_key", "") or "")
    if not image_key or len(image_key) > 512:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu image upload outcome is unknown"
        )
    try:
        _require_live_inbound_provider_fence()
    except FeishuLeaseLost as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu image upload outcome is unknown"
        ) from exc
    return image_key


def _mp4_duration_ms(data: bytes) -> int:
    """从 mp4 字节解析时长(ms)；失败返回 0。读 moov/mvhd 的 timescale+duration。"""
    try:
        idx = data.find(b"mvhd")
        if idx < 0:
            return 0
        p = idx + 4
        ver = data[p]
        if ver == 1:
            ts = int.from_bytes(data[p + 20 : p + 24], "big")
            dur = int.from_bytes(data[p + 24 : p + 32], "big")
        else:
            ts = int.from_bytes(data[p + 12 : p + 16], "big")
            dur = int.from_bytes(data[p + 16 : p + 20], "big")
        return int(dur * 1000 / ts) if ts else 0
    except Exception:  # noqa: BLE001
        return 0


def _upload_file(data: bytes, name: str, ftype: str) -> str:
    from io import BytesIO

    body = CreateFileRequestBody.builder().file_type(ftype).file_name(name).file(BytesIO(data))
    if ftype in ("mp4", "opus"):  # 飞书视频/音频上传必须带时长(ms)，缺了直发就失败 → 退回发链接
        body = body.duration(str(_mp4_duration_ms(data) or 5000))
    req = CreateFileRequest.builder().request_body(body.build()).build()
    submission_sha256 = _begin_inbound_media_upload_submission(
        "file",
        data,
        name=name,
        ftype=ftype,
    )
    _require_live_inbound_provider_fence()
    try:
        resp = _api["c"].im.v1.file.create(req)
    except Exception as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        ) from exc
    try:
        success = resp.success()
    except Exception as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        ) from exc
    if success is not True and success is not False:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        )
    if not success:
        _abort_inbound_media_upload_submission(submission_sha256)
        raise RuntimeError(f"上传文件失败 {resp.code} {resp.msg}")
    file_key = str(getattr(getattr(resp, "data", None), "file_key", "") or "")
    if not file_key or len(file_key) > 512:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        )
    try:
        _require_live_inbound_provider_fence()
    except FeishuLeaseLost as exc:
        raise FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        ) from exc
    return file_key


def _send_image(chat_id: str, image_key: str) -> bool:
    delivery_uuid = _enqueue_outbox(
        chat_id,
        "image",
        json.dumps({"image_key": image_key}, separators=(",", ":")),
        delivery_key=_next_delivery_key("image"),
    )
    _drain_outbox(limit=1, delivery_uuid=delivery_uuid)
    return _delivery_done(delivery_uuid)


def _send_video(
    chat_id: str, file_key: str, *, delivery_key: str | None = None
) -> bool:
    if delivery_key is None:
        delivery_key = _next_delivery_key("media")
    delivery_uuid = _enqueue_outbox(
        chat_id,
        "media",
        json.dumps({"file_key": file_key}, separators=(",", ":")),
        delivery_key=delivery_key,
    )
    _drain_outbox(limit=1, delivery_uuid=delivery_uuid)
    return _delivery_done(delivery_uuid)


def _send_reply(chat_id: str, d: dict) -> None:
    """文本回复 + 把生成的图片/视频作为飞书消息直接发出（接 #3 多模态）。"""
    _reply(chat_id, d.get("reply") or "(空回复)")
    for url in d.get("images") or []:
        try:
            image_key = _upload_image(_download_url(url, "image"))
            submission_sha256 = str(
                getattr(_DELIVERY_CONTEXT, "media_submission_sha256", "") or ""
            )
            try:
                _send_image(chat_id, image_key)
                _complete_inbound_media_upload_submission(submission_sha256)
            except Exception as exc:
                raise FeishuMediaUploadOutcomeUnknown(
                    "Feishu image upload completed before durable delivery"
                ) from exc
        except (FeishuMediaUploadOutcomeUnknown, FeishuLeaseLost):
            raise
        except Exception:  # noqa: BLE001
            _reply(chat_id, f"（图片直发失败，链接：{url}）")
    vurl = d.get("video")
    if vurl:
        try:
            file_key = _upload_file(
                _download_url(vurl, "video"), "video.mp4", "mp4"
            )
            submission_sha256 = str(
                getattr(_DELIVERY_CONTEXT, "media_submission_sha256", "") or ""
            )
            try:
                _send_video(chat_id, file_key)
                _complete_inbound_media_upload_submission(submission_sha256)
            except Exception as exc:
                raise FeishuMediaUploadOutcomeUnknown(
                    "Feishu file upload completed before durable delivery"
                ) from exc
        except (FeishuMediaUploadOutcomeUnknown, FeishuLeaseLost):
            raise
        except Exception:  # noqa: BLE001
            _reply(chat_id, f"（视频直发失败，链接：{vurl}）")


def _handle_file(
    msg,
    *,
    message_id: str,
    user_id: str,
    chat_id: str,
) -> None:
    """非文本消息：语音→下载→转写→对话（接 D1）；图片/文件→先确认。"""
    try:
        content = json.loads(msg.content or "{}")
    except Exception:  # noqa: BLE001
        content = {}
    rkey = content.get("file_key") or content.get("image_key") or ""
    if msg.message_type == "audio" and rkey:
        try:
            data = _download_resource(message_id, rkey, "file", media_kind="audio")
            transcript = _transcribe(data).strip()
        except Exception as e:  # noqa: BLE001
            _reply(chat_id, f"⚠️ 语音处理失败：{e}")
            return
        if not transcript:
            _reply(chat_id, "（没听清，请再说一遍或发文字）")
            return
        _, owner = _load_feishu_access()
        d = _agent_chat(transcript, resolve_user_id(user_id, owner), chat_id)
        d["reply"] = f"🎧 听到：{transcript}\n\n{d.get('reply', '')}"
        _send_reply(chat_id, d)
    elif msg.message_type == "image" and rkey:
        data = _download_resource(message_id, rkey, "image", media_kind="image")
        desc = _describe(
            data,
            message_id=message_id,
            user_id=user_id,
            chat_id=chat_id,
        ).strip()
        _reply(chat_id, f"🖼 我看到：\n{desc}" if desc else "🖼 这张图我没看清，换一张再试试？")
    elif msg.message_type == "media" and rkey:  # 视频 → 拉片（#29）
        _reply(chat_id, "🎬 收到视频，拉片中（逐帧分析+出报告，约 2-5 分钟）…")
        data = _download_resource(message_id, rkey, "file", media_kind="video")
        report = _lapian(
            data,
            message_id=message_id,
            user_id=user_id,
            chat_id=chat_id,
        )
        for chunk in _split(report):
            _reply(chat_id, chunk)
    else:
        _reply(chat_id, "📎 收到文件（文档总结即将支持）。")


# ── 异步生视频：后台耐心轮询，好了发回飞书；待办任务持久化，桥重启能续着发、不丢结果 ──
_PENDING = Path(S.usage_db_path).parent / "feishu_pending_videos.json"
_pending_lock = threading.RLock()
_VIDEO_QUEUE_CAPACITY = 64
_VIDEO_QUEUE: queue.Queue[tuple[str, str]] = queue.Queue(
    maxsize=_VIDEO_QUEUE_CAPACITY
)
_VIDEO_DISPATCH_LOCK = threading.Lock()
_VIDEO_QUEUED: set[str] = set()
_VIDEO_ACTIVE: set[str] = set()
_PENDING_VIDEO_STATES = frozenset(
    {"polling", "upload_submitting", "upload_confirmed", "recovery_required"}
)
_PENDING_VIDEO_FIELDS = frozenset(
    {
        "chat_id",
        "ts",
        "state",
        "upload_request_sha256",
        "upload_started_at",
        "file_key",
        "last_error",
    }
)
_PENDING_STATE_APPLICATION_ID = 0x4E435646  # "NCVF"
_PENDING_STATE_SCHEMA_VERSION = 1
_PENDING_STATE_MAX_BYTES = 256 * 1024 * 1024
_PENDING_LEGACY_JSON_MAX_BYTES = 4 * 1024 * 1024
_MAX_PENDING_VIDEO_ROWS = 50_000
_PENDING_VIDEO_TABLE_SQL = """
CREATE TABLE feishu_pending_video (
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE CHECK(length(task_id) BETWEEN 1 AND 512),
    chat_id TEXT NOT NULL CHECK(length(chat_id) <= 512),
    created_at REAL NOT NULL CHECK(created_at >= 0),
    state TEXT NOT NULL CHECK(
        state IN ('polling','upload_submitting','upload_confirmed','recovery_required','closed')
    ),
    upload_request_sha256 TEXT NOT NULL CHECK(
        upload_request_sha256='' OR (
            length(upload_request_sha256)=64 AND
            upload_request_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    upload_started_at REAL NOT NULL CHECK(upload_started_at >= 0),
    file_key TEXT NOT NULL CHECK(length(file_key) <= 512),
    last_error TEXT NOT NULL CHECK(length(last_error) <= 64),
    terminal_verification TEXT NOT NULL DEFAULT '' CHECK(
        length(terminal_verification) <= 128
    ),
    closed_at REAL NOT NULL DEFAULT 0 CHECK(closed_at >= 0)
)
"""
_PENDING_VIDEO_RECEIPT_TABLE_SQL = """
CREATE TABLE feishu_pending_video_recovery_receipt (
    id INTEGER PRIMARY KEY,
    operation_digest TEXT NOT NULL CHECK(
        length(operation_digest)=64 AND operation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    decision_id TEXT NOT NULL CHECK(
        length(decision_id)=64 AND decision_id NOT GLOB '*[^0-9a-f]*'
    ),
    target_kind TEXT NOT NULL CHECK(target_kind='video'),
    target_key_sha256 TEXT NOT NULL CHECK(
        length(target_key_sha256)=64 AND target_key_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    chat_sha256 TEXT NOT NULL CHECK(
        length(chat_sha256)=64 AND chat_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
    authorization TEXT NOT NULL CHECK(
        length(authorization)=64 AND authorization NOT GLOB '*[^0-9a-f]*'
    ),
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 2048),
    decided_at_ms INTEGER NOT NULL CHECK(decided_at_ms>=0),
    closed_at_ms INTEGER NOT NULL CHECK(closed_at_ms>=0),
    affected_video_count INTEGER NOT NULL CHECK(affected_video_count>=1),
    before_digest TEXT NOT NULL CHECK(
        length(before_digest)=64 AND before_digest NOT GLOB '*[^0-9a-f]*'
    ),
    after_digest TEXT NOT NULL CHECK(
        length(after_digest)=64 AND after_digest NOT GLOB '*[^0-9a-f]*'
    ),
    affected_rows_json TEXT NOT NULL CHECK(
        length(affected_rows_json) BETWEEN 2 AND 1048576
    ),
    previous_receipt_sha256 TEXT NOT NULL CHECK(
        length(previous_receipt_sha256)=64 AND
        previous_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_sha256 TEXT NOT NULL CHECK(
        length(receipt_sha256)=64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    )
)
"""
_PENDING_VIDEO_RECEIPT_COLUMNS = (
    "id", "operation_digest", "decision_id", "target_kind",
    "target_key_sha256", "chat_sha256", "actor", "authorization", "reason",
    "decided_at_ms", "closed_at_ms", "affected_video_count",
    "before_digest", "after_digest", "affected_rows_json",
    "previous_receipt_sha256", "receipt_sha256",
)
_PENDING_VIDEO_RECEIPT_INDEX_SQL = {
    "uq_feishu_pending_video_recovery_operation": (
        "CREATE UNIQUE INDEX uq_feishu_pending_video_recovery_operation "
        "ON feishu_pending_video_recovery_receipt(operation_digest)"
    ),
    "uq_feishu_pending_video_recovery_decision": (
        "CREATE UNIQUE INDEX uq_feishu_pending_video_recovery_decision "
        "ON feishu_pending_video_recovery_receipt(decision_id)"
    ),
    "uq_feishu_pending_video_recovery_previous": (
        "CREATE UNIQUE INDEX uq_feishu_pending_video_recovery_previous "
        "ON feishu_pending_video_recovery_receipt(previous_receipt_sha256)"
    ),
    "uq_feishu_pending_video_recovery_sha256": (
        "CREATE UNIQUE INDEX uq_feishu_pending_video_recovery_sha256 "
        "ON feishu_pending_video_recovery_receipt(receipt_sha256)"
    ),
    "idx_feishu_pending_video_recovery_target": (
        "CREATE INDEX idx_feishu_pending_video_recovery_target "
        "ON feishu_pending_video_recovery_receipt(target_key_sha256,id)"
    ),
}
_PENDING_VIDEO_RECEIPT_TRIGGER_SQL = {
    "feishu_pending_video_recovery_no_update": """
        CREATE TRIGGER feishu_pending_video_recovery_no_update
        BEFORE UPDATE ON feishu_pending_video_recovery_receipt
        BEGIN
            SELECT RAISE(ABORT, 'Feishu video recovery receipts are append-only');
        END
    """,
    "feishu_pending_video_recovery_no_delete": """
        CREATE TRIGGER feishu_pending_video_recovery_no_delete
        BEFORE DELETE ON feishu_pending_video_recovery_receipt
        BEGIN
            SELECT RAISE(ABORT, 'Feishu video recovery receipts are append-only');
        END
    """,
    "feishu_pending_video_recovery_no_replace": """
        CREATE TRIGGER feishu_pending_video_recovery_no_replace
        BEFORE INSERT ON feishu_pending_video_recovery_receipt
        WHEN EXISTS (
            SELECT 1 FROM feishu_pending_video_recovery_receipt
            WHERE id=NEW.id
               OR operation_digest=NEW.operation_digest
               OR decision_id=NEW.decision_id
               OR previous_receipt_sha256=NEW.previous_receipt_sha256
               OR receipt_sha256=NEW.receipt_sha256
        )
        BEGIN
            SELECT RAISE(ABORT, 'Feishu video recovery receipts are append-only');
        END
    """,
}
_PENDING_VIDEO_COLUMNS = (
    "id", "task_id", "chat_id", "created_at", "state",
    "upload_request_sha256", "upload_started_at", "file_key", "last_error",
    "terminal_verification", "closed_at",
)
_PENDING_VIDEO_ROW_DOMAIN = b"nachuan.feishu.pending-video.recovery-row/v1\x00"
_PENDING_VIDEO_RECEIPT_DOMAIN = b"nachuan.feishu.pending-video.recovery-receipt/v1\x00"


def _validated_pending_video_entry(task_id: object, value: object) -> dict[str, object]:
    task = str(task_id or "")
    if not task or len(task) > 512 or not isinstance(value, dict):
        raise ValueError("invalid Feishu pending video record")
    unknown = set(value) - _PENDING_VIDEO_FIELDS
    if unknown:
        raise ValueError("unknown Feishu pending video fields")
    chat_id = str(value.get("chat_id") or "")
    if not chat_id or len(chat_id) > 512:
        raise ValueError("invalid Feishu pending video chat identity")
    raw_ts = value.get("ts", 0)
    raw_started = value.get("upload_started_at", 0)
    if isinstance(raw_ts, bool) or isinstance(raw_started, bool):
        raise ValueError("invalid Feishu pending video clock")
    try:
        created_at = float(raw_ts)
        upload_started_at = float(raw_started)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid Feishu pending video clock") from exc
    if (
        not math.isfinite(created_at)
        or created_at < 0
        or not math.isfinite(upload_started_at)
        or upload_started_at < 0
    ):
        raise ValueError("invalid Feishu pending video clock")
    state = str(value.get("state") or "polling")
    request_sha256 = str(value.get("upload_request_sha256") or "")
    file_key = str(value.get("file_key") or "")
    last_error = str(value.get("last_error") or "")
    if state not in _PENDING_VIDEO_STATES:
        raise ValueError("invalid Feishu pending video state")
    if request_sha256 and not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ValueError("invalid Feishu pending video upload digest")
    if len(file_key) > 512 or len(last_error) > 64:
        raise ValueError("invalid Feishu pending video receipt")
    if state == "polling" and (
        request_sha256 or upload_started_at != 0 or file_key or last_error
    ):
        raise ValueError("invalid polling Feishu pending video receipt")
    if state in {"upload_submitting", "recovery_required"} and (
        not request_sha256 or upload_started_at <= 0 or file_key
    ):
        raise ValueError("invalid uncertain Feishu pending video receipt")
    if state == "upload_confirmed" and (
        not request_sha256 or upload_started_at <= 0 or not file_key or last_error
    ):
        raise ValueError("invalid confirmed Feishu pending video receipt")
    return {
        "chat_id": chat_id,
        "ts": created_at,
        "state": state,
        "upload_request_sha256": request_sha256,
        "upload_started_at": upload_started_at,
        "file_key": file_key,
        "last_error": last_error,
    }


def _pending_state_db_path() -> Path:
    """Derive the SQLite authority beside the one-time legacy JSON path."""

    return _PENDING.with_suffix(".sqlite3")


def _pending_expected_schema() -> dict[tuple[str, str, str], str | None]:
    expected = {
        ("table", "feishu_pending_video", "feishu_pending_video"):
            _normalized_state_schema_sql(_PENDING_VIDEO_TABLE_SQL),
        (
            "table",
            "feishu_pending_video_recovery_receipt",
            "feishu_pending_video_recovery_receipt",
        ): _normalized_state_schema_sql(_PENDING_VIDEO_RECEIPT_TABLE_SQL),
        (
            "index",
            "sqlite_autoindex_feishu_pending_video_1",
            "feishu_pending_video",
        ): None,
    }
    expected.update(
        {
            ("index", name, "feishu_pending_video_recovery_receipt"):
                _normalized_state_schema_sql(sql)
            for name, sql in _PENDING_VIDEO_RECEIPT_INDEX_SQL.items()
        }
    )
    expected.update(
        {
            ("trigger", name, "feishu_pending_video_recovery_receipt"):
                _normalized_state_schema_sql(sql)
            for name, sql in _PENDING_VIDEO_RECEIPT_TRIGGER_SQL.items()
        }
    )
    return expected


def _assert_pending_state_schema(conn: sqlite3.Connection) -> None:
    if int(conn.execute("PRAGMA application_id").fetchone()[0]) != (
        _PENDING_STATE_APPLICATION_ID
    ) or int(conn.execute("PRAGMA user_version").fetchone()[0]) != (
        _PENDING_STATE_SCHEMA_VERSION
    ):
        raise RuntimeError("unsupported Feishu pending video state database version")
    actual = {
        (str(row[0]), str(row[1]), str(row[2])): (
            None if row[3] is None else _normalized_state_schema_sql(row[3])
        )
        for row in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        )
    }
    expected = _pending_expected_schema()
    if actual != expected:
        raise RuntimeError("unsupported Feishu pending video state database schema")


def _apply_pending_state_capacity(conn: sqlite3.Connection) -> None:
    page_size = max(512, int(conn.execute("PRAGMA page_size").fetchone()[0]))
    max_pages = int(_PENDING_STATE_MAX_BYTES) // page_size
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    if max_pages < 1 or page_count > max_pages:
        raise FeishuQueueFull("Feishu pending video state exceeds its byte budget")
    actual_max_pages = int(
        conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
    )
    if actual_max_pages > max_pages:
        raise FeishuQueueFull("Feishu pending video byte budget cannot be applied")


def _open_pending_state() -> sqlite3.Connection:
    path = _pending_state_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        objects = int(
            conn.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()[0]
        )
        if objects:
            _assert_pending_state_schema(conn)
            _apply_pending_state_capacity(conn)
            return conn
        if int(conn.execute("PRAGMA application_id").fetchone()[0]) != 0 or int(
            conn.execute("PRAGMA user_version").fetchone()[0]
        ) != 0:
            raise RuntimeError("unsupported Feishu pending video state database")
        conn.execute("BEGIN IMMEDIATE")
        if int(conn.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()[0]):
            conn.rollback()
            _assert_pending_state_schema(conn)
            return conn
        conn.execute(_PENDING_VIDEO_TABLE_SQL)
        conn.execute(_PENDING_VIDEO_RECEIPT_TABLE_SQL)
        for sql in _PENDING_VIDEO_RECEIPT_INDEX_SQL.values():
            conn.execute(sql)
        for sql in _PENDING_VIDEO_RECEIPT_TRIGGER_SQL.values():
            conn.execute(sql)
        conn.execute(f"PRAGMA application_id={_PENDING_STATE_APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version={_PENDING_STATE_SCHEMA_VERSION}")
        conn.commit()
        _assert_pending_state_schema(conn)
        _apply_pending_state_capacity(conn)
        return conn
    except BaseException:
        conn.close()
        raise


@contextmanager
def _pending_state_transaction(*, write: bool = False):
    conn = _open_pending_state()
    try:
        if write:
            conn.execute("BEGIN IMMEDIATE")
        else:
            conn.execute("BEGIN")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _pending_entry_from_row(row: tuple[object, ...]) -> tuple[str, dict[str, object]]:
    record = dict(zip(_PENDING_VIDEO_COLUMNS, row, strict=True))
    task_id = str(record["task_id"])
    state = str(record["state"])
    if state == "closed":
        raise RuntimeError("closed Feishu pending video cannot be loaded as active")
    entry = _validated_pending_video_entry(
        task_id,
        {
            "chat_id": record["chat_id"],
            "ts": record["created_at"],
            "state": state,
            "upload_request_sha256": record["upload_request_sha256"],
            "upload_started_at": record["upload_started_at"],
            "file_key": record["file_key"],
            "last_error": record["last_error"],
        },
    )
    if str(record["terminal_verification"]) or float(record["closed_at"]) != 0:
        raise RuntimeError("active Feishu pending video has terminal evidence")
    return task_id, entry


def _pending_read_legacy_json() -> dict[str, dict[str, object]] | None:
    try:
        raw = _read_regular_file(
            _PENDING,
            max_bytes=_PENDING_LEGACY_JSON_MAX_BYTES,
        ).decode("utf-8", errors="strict")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("Feishu pending video state is unreadable") from exc
    try:
        value = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Feishu pending video state is invalid") from exc
    if not isinstance(value, dict) or len(value) > 10_000:
        raise RuntimeError("Feishu pending video state is invalid")
    try:
        normalized = {
            str(task_id): _validated_pending_video_entry(task_id, info)
            for task_id, info in value.items()
        }
    except ValueError as exc:
        raise RuntimeError("Feishu pending video state is invalid") from exc
    for entry in normalized.values():
        if entry["state"] == "upload_submitting":
            entry["state"] = "recovery_required"
            entry["last_error"] = "upload_interrupted"
    return normalized


def _pending_upsert_entry(
    conn: sqlite3.Connection,
    task_id: str,
    entry: dict[str, object],
) -> None:
    conn.execute(
        "INSERT INTO feishu_pending_video("
        "task_id,chat_id,created_at,state,upload_request_sha256,"
        "upload_started_at,file_key,last_error,terminal_verification,closed_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(task_id) DO UPDATE SET "
        "chat_id=excluded.chat_id,created_at=excluded.created_at,state=excluded.state,"
        "upload_request_sha256=excluded.upload_request_sha256,"
        "upload_started_at=excluded.upload_started_at,file_key=excluded.file_key,"
        "last_error=excluded.last_error,terminal_verification='',closed_at=0",
        (
            task_id,
            entry["chat_id"],
            entry["ts"],
            entry["state"],
            entry["upload_request_sha256"],
            entry["upload_started_at"],
            entry["file_key"],
            entry["last_error"],
            "",
            0,
        ),
    )


def _pending_import_legacy_if_present() -> None:
    legacy = _pending_read_legacy_json()
    if legacy is None:
        return
    with _pending_state_transaction(write=True) as conn:
        for task_id, entry in legacy.items():
            row = conn.execute(
                "SELECT state,chat_id,created_at,upload_request_sha256,"
                "upload_started_at,file_key,last_error,terminal_verification,closed_at "
                "FROM feishu_pending_video WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if row is None:
                _pending_upsert_entry(conn, task_id, entry)
                continue
            expected = (
                entry["state"], entry["chat_id"], entry["ts"],
                entry["upload_request_sha256"], entry["upload_started_at"],
                entry["file_key"], entry["last_error"], "", 0.0,
            )
            if tuple(row) != expected:
                raise RuntimeError("Feishu pending video legacy state conflicts with SQLite")
    try:
        _PENDING.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RuntimeError("Feishu pending video legacy state could not be retired") from exc


def _pending_load() -> dict:
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction() as conn:
            rows = tuple(
                conn.execute(
                    f"SELECT {','.join(_PENDING_VIDEO_COLUMNS)} "
                    "FROM feishu_pending_video WHERE state!='closed' ORDER BY id"
                )
            )
        if len(rows) > 10_000:
            raise RuntimeError("Feishu pending video state exceeds capacity")
        return dict(_pending_entry_from_row(tuple(row)) for row in rows)


def _pending_save(d: dict) -> None:
    if not isinstance(d, dict):
        raise TypeError("Feishu pending video state must be an object")
    if len(d) > 10_000:
        raise ValueError("Feishu pending video state exceeds capacity")
    normalized = {
        str(task_id): _validated_pending_video_entry(task_id, info)
        for task_id, info in d.items()
    }
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction(write=True) as conn:
            closed = {
                str(row[0])
                for row in conn.execute(
                    "SELECT task_id FROM feishu_pending_video WHERE state='closed'"
                )
            }
            if closed & set(normalized):
                raise RuntimeError("Feishu pending video task was already closed")
            if len(closed) + len(normalized) > _MAX_PENDING_VIDEO_ROWS:
                raise FeishuQueueFull("Feishu pending video row capacity is full")
            if normalized:
                placeholders = ",".join("?" for _ in normalized)
                conn.execute(
                    "DELETE FROM feishu_pending_video WHERE state!='closed' "
                    f"AND task_id NOT IN ({placeholders})",
                    tuple(normalized),
                )
            else:
                conn.execute("DELETE FROM feishu_pending_video WHERE state!='closed'")
            for task_id, entry in normalized.items():
                _pending_upsert_entry(conn, task_id, entry)


def _pending_recovery_record(row: tuple[object, ...]) -> dict[str, object]:
    return {
        "kind": "video",
        **dict(zip(_PENDING_VIDEO_COLUMNS, row, strict=True)),
    }


def _pending_recovery_rows_in_transaction(
    conn: sqlite3.Connection,
    target_key: str,
) -> tuple[str, list[dict[str, object]]]:
    columns = ",".join(_PENDING_VIDEO_COLUMNS)
    target_row = conn.execute(
        f"SELECT {columns} FROM feishu_pending_video WHERE task_id=?",
        (target_key,),
    ).fetchone()
    if target_row is None:
        raise FeishuRecoveryConflict("Feishu video recovery target does not exist")
    target = _pending_recovery_record(tuple(target_row))
    if target["state"] != "recovery_required":
        raise FeishuRecoveryConflict(
            "Feishu video recovery target is not recovery_required"
        )
    chat_id = str(target["chat_id"])
    if not chat_id:
        raise FeishuRecoveryConflict("Feishu video recovery target has drifted")
    rows = [
        _pending_recovery_record(tuple(row))
        for row in conn.execute(
            f"SELECT {columns} FROM feishu_pending_video "
            "WHERE chat_id=? AND state='recovery_required' ORDER BY id",
            (chat_id,),
        )
    ]
    if not rows:
        raise FeishuRecoveryConflict("Feishu video recovery target set is empty")
    return chat_id, rows


def _pending_recovery_target_before_digest(target_key: str) -> str:
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction() as conn:
            _chat_id, rows = _pending_recovery_rows_in_transaction(conn, target_key)
    return _recovery_affected_set_digest(rows)


def _pending_recovery_target_snapshot(target_key: str) -> dict[str, object]:
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction() as conn:
            _chat_id, rows = _pending_recovery_rows_in_transaction(conn, target_key)
    return {
        "schema": "nachuan.feishu-recovery-inspect.v1",
        "target_kind": "video",
        "target_key_sha256": _recovery_target_key_sha256("video", target_key),
        "expected_before_digest": _recovery_affected_set_digest(rows),
        "affected_counts": {"inbox": 0, "outbox": 0, "video": len(rows)},
    }


def _pending_video_receipt_record(row: tuple[object, ...]) -> dict[str, object]:
    return dict(zip(_PENDING_VIDEO_RECEIPT_COLUMNS, row, strict=True))


def _pending_video_receipt_sha256(record: dict[str, object]) -> str:
    payload = {
        name: record[name] for name in _PENDING_VIDEO_RECEIPT_COLUMNS[:-1]
    }
    return _recovery_digest(_PENDING_VIDEO_RECEIPT_DOMAIN, payload)


def _validate_pending_video_receipt_manifest(receipt: dict[str, object]) -> None:
    raw = receipt["affected_rows_json"]
    try:
        manifest = json.loads(raw) if isinstance(raw, str) else None
    except (TypeError, ValueError):
        manifest = None
    count = receipt["affected_video_count"]
    invalid = (
        not isinstance(manifest, list)
        or type(count) is not int
        or count < 1
        or len(manifest) != count
        or _canonical_recovery_json(manifest) != raw
    )
    expected_fields = {
        "after_sha256", "before_sha256", "kind", "row_id", "target_sha256"
    }
    target_seen = False
    previous_id = 0
    if not invalid:
        for member in manifest:
            if not isinstance(member, dict) or set(member) != expected_fields:
                invalid = True
                break
            row_id = member["row_id"]
            digests = (
                member["after_sha256"],
                member["before_sha256"],
                member["target_sha256"],
            )
            if (
                member["kind"] != "video"
                or type(row_id) is not int
                or row_id <= previous_id
                or any(
                    not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{64}", value) is None
                    or value == "0" * 64
                    for value in digests
                )
                or member["after_sha256"] == member["before_sha256"]
            ):
                invalid = True
                break
            previous_id = row_id
            target_seen = target_seen or (
                member["target_sha256"] == receipt["target_key_sha256"]
            )
    if invalid or not target_seen:
        raise FeishuRecoveryConflict(
            "Feishu video recovery receipt manifest is invalid"
        )


def _validated_pending_video_receipt_chain_head(
    conn: sqlite3.Connection,
) -> tuple[int, str]:
    columns = ",".join(_PENDING_VIDEO_RECEIPT_COLUMNS)
    expected_id = 1
    expected_previous = "0" * 64
    for row in conn.execute(
        f"SELECT {columns} FROM feishu_pending_video_recovery_receipt ORDER BY id"
    ):
        if expected_id > 50_000:
            raise FeishuRecoveryConflict(
                "Feishu video recovery receipt chain exceeds its hard capacity"
            )
        receipt = _pending_video_receipt_record(tuple(row))
        if (
            type(receipt["id"]) is not int
            or receipt["id"] != expected_id
            or receipt["previous_receipt_sha256"] != expected_previous
            or receipt["receipt_sha256"] != _pending_video_receipt_sha256(receipt)
        ):
            raise FeishuRecoveryConflict(
                "Feishu video recovery receipt chain is invalid"
            )
        _validate_pending_video_receipt_manifest(receipt)
        expected_previous = str(receipt["receipt_sha256"])
        expected_id += 1
    return expected_id - 1, expected_previous


def _existing_pending_video_recovery_result(
    row: tuple[object, ...],
    request: _FeishuCloseWithoutReplayRequest,
) -> _FeishuCloseWithoutReplayResult:
    receipt = _pending_video_receipt_record(row)
    expected = {
        "operation_digest": request.operation_digest,
        "decision_id": request.decision_id,
        "target_kind": "video",
        "target_key_sha256": _recovery_target_key_sha256(
            "video", request.target_key
        ),
        "actor": request.actor,
        "authorization": request.authorization,
        "reason": request.reason,
        "decided_at_ms": request.decided_at_ms,
        "before_digest": request.expected_before_digest,
    }
    if any(receipt[name] != value for name, value in expected.items()):
        raise FeishuRecoveryConflict(
            "Feishu video recovery operation conflicts with its durable receipt"
        )
    if receipt["receipt_sha256"] != _pending_video_receipt_sha256(receipt):
        raise FeishuRecoveryConflict("Feishu video recovery receipt digest is invalid")
    return _FeishuCloseWithoutReplayResult(
        operation_digest=str(receipt["operation_digest"]),
        receipt_sha256=str(receipt["receipt_sha256"]),
        affected_inbox_count=0,
        affected_outbox_count=0,
        affected_video_count=int(receipt["affected_video_count"]),
        applied=False,
    )


def _close_pending_video_without_replay(
    request: _FeishuCloseWithoutReplayRequest,
    *,
    closed_at_ms: int,
) -> _FeishuCloseWithoutReplayResult:
    if request.target_kind != "video":
        raise TypeError("Feishu video recovery requires a video target")
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction(write=True) as conn:
            receipt_count, previous_sha256 = (
                _validated_pending_video_receipt_chain_head(conn)
            )
            columns = ",".join(_PENDING_VIDEO_RECEIPT_COLUMNS)
            existing = conn.execute(
                f"SELECT {columns} FROM feishu_pending_video_recovery_receipt "
                "WHERE operation_digest=?",
                (request.operation_digest,),
            ).fetchone()
            if existing is not None:
                return _existing_pending_video_recovery_result(
                    tuple(existing), request
                )
            if conn.execute(
                "SELECT 1 FROM feishu_pending_video_recovery_receipt "
                "WHERE decision_id=?",
                (request.decision_id,),
            ).fetchone() is not None:
                raise FeishuRecoveryConflict(
                    "Feishu video recovery decision id belongs to another operation"
                )
            receipt_cap = max(1, min(int(_MAX_RECOVERY_RECEIPTS), 50_000))
            if receipt_count >= receipt_cap:
                raise FeishuQueueFull("Feishu video recovery receipt capacity is full")
            chat_id, before_rows = _pending_recovery_rows_in_transaction(
                conn, request.target_key
            )
            before_digest = _recovery_affected_set_digest(before_rows)
            if before_digest != request.expected_before_digest:
                raise FeishuRecoveryConflict(
                    "Feishu video recovery target set drifted after adjudication"
                )
            closed_seconds = closed_at_ms / 1000.0
            changed = conn.execute(
                "UPDATE feishu_pending_video SET state='closed',chat_id='',"
                "file_key='',terminal_verification='closed_without_replay',closed_at=? "
                "WHERE chat_id=? AND state='recovery_required'",
                (closed_seconds, chat_id),
            ).rowcount
            if changed != len(before_rows):
                raise FeishuRecoveryConflict(
                    "Feishu video recovery target changed during close"
                )
            ids = [int(row["id"]) for row in before_rows]
            placeholders = ",".join("?" for _ in ids)
            after_rows = [
                _pending_recovery_record(tuple(row))
                for row in conn.execute(
                    f"SELECT {','.join(_PENDING_VIDEO_COLUMNS)} "
                    f"FROM feishu_pending_video WHERE id IN ({placeholders}) ORDER BY id",
                    ids,
                )
            ]
            if len(after_rows) != len(before_rows):
                raise FeishuRecoveryConflict(
                    "Feishu video recovery closed row set is incomplete"
                )
            after_digest = _recovery_affected_set_digest(after_rows)
            affected_rows = []
            for before, after in zip(before_rows, after_rows, strict=True):
                if before["id"] != after["id"]:
                    raise FeishuRecoveryConflict("Feishu video recovery row order drifted")
                affected_rows.append(
                    {
                        "after_sha256": _recovery_digest(
                            _PENDING_VIDEO_ROW_DOMAIN, after
                        ),
                        "before_sha256": _recovery_digest(
                            _PENDING_VIDEO_ROW_DOMAIN, before
                        ),
                        "kind": "video",
                        "row_id": before["id"],
                        "target_sha256": _recovery_target_key_sha256(
                            "video", str(before["task_id"])
                        ),
                    }
                )
            receipt: dict[str, object] = {
                "id": receipt_count + 1,
                "operation_digest": request.operation_digest,
                "decision_id": request.decision_id,
                "target_kind": "video",
                "target_key_sha256": _recovery_target_key_sha256(
                    "video", request.target_key
                ),
                "chat_sha256": _recovery_digest(
                    b"nachuan.feishu.pending-video.recovery-chat/v1\x00", chat_id
                ),
                "actor": request.actor,
                "authorization": request.authorization,
                "reason": request.reason,
                "decided_at_ms": request.decided_at_ms,
                "closed_at_ms": closed_at_ms,
                "affected_video_count": len(before_rows),
                "before_digest": before_digest,
                "after_digest": after_digest,
                "affected_rows_json": _canonical_recovery_json(affected_rows),
                "previous_receipt_sha256": previous_sha256,
            }
            receipt["receipt_sha256"] = _pending_video_receipt_sha256(receipt)
            conn.execute(
                f"INSERT INTO feishu_pending_video_recovery_receipt({columns}) "
                f"VALUES({','.join('?' for _ in _PENDING_VIDEO_RECEIPT_COLUMNS)})",
                tuple(receipt[name] for name in _PENDING_VIDEO_RECEIPT_COLUMNS),
            )
            return _FeishuCloseWithoutReplayResult(
                operation_digest=request.operation_digest,
                receipt_sha256=str(receipt["receipt_sha256"]),
                affected_inbox_count=0,
                affected_outbox_count=0,
                affected_video_count=len(before_rows),
                applied=True,
            )


def _validate_recovery_ledgers_before_channel_start() -> None:
    """Validate both bounded receipt chains once before channel activity.

    Schema checks alone cannot prove that an append-only ledger has no gap,
    disconnected predecessor, forged self-digest, or impossible manifest. Do
    the O(N) scans at process startup rather than on every ordinary state open;
    the close paths retain their own validation inside the write transaction.
    """

    with _state_transaction() as conn:
        _validated_recovery_receipt_chain_head(conn)
    with _pending_lock:
        _pending_import_legacy_if_present()
        with _pending_state_transaction() as conn:
            _validated_pending_video_receipt_chain_head(conn)


def _pending_add(task_id: str, chat_id: str) -> None:
    task_id = str(task_id or "")
    chat_id = str(chat_id or "")
    if not task_id or not chat_id or len(task_id) > 512 or len(chat_id) > 512:
        raise ValueError("invalid Feishu pending video identity")
    with _pending_lock:
        d = _pending_load()
        existing = d.get(task_id)
        if isinstance(existing, dict) and str(existing.get("chat_id") or "") != chat_id:
            raise RuntimeError("Feishu video task_id conflicts with another chat")
        if not existing:
            d[task_id] = {
                "chat_id": chat_id,
                "ts": time.time(),
                "state": "polling",
                "upload_request_sha256": "",
                "upload_started_at": 0,
                "file_key": "",
                "last_error": "",
            }
        _pending_save(d)


def _pending_remove(task_id: str) -> None:
    with _pending_lock:
        d = _pending_load()
        if d.pop(task_id, None) is not None:
            _pending_save(d)


def _pending_upload_request_sha256(
    task_id: str, chat_id: str, data: bytes, name: str, ftype: str
) -> str:
    body = {
        "schema": "nachuan.feishu-pending-video-upload.v1",
        "task_id": str(task_id),
        "chat_id": str(chat_id),
        "file_name": str(name),
        "file_type": str(ftype),
        "body_sha256": hashlib.sha256(data).hexdigest(),
    }
    encoded = json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _pending_begin_upload(
    task_id: str,
    chat_id: str,
    request_sha256: str,
    *,
    now: float | None = None,
) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", str(request_sha256)):
        raise ValueError("invalid Feishu pending video upload digest")
    current = time.time() if now is None else float(now)
    if not math.isfinite(current) or current <= 0:
        raise ValueError("invalid Feishu pending video upload clock")
    with _pending_lock:
        pending = _pending_load()
        record = pending.get(str(task_id))
        if not isinstance(record, dict) or str(record.get("chat_id") or "") != str(
            chat_id
        ):
            raise RuntimeError("Feishu pending video identity changed")
        state = str(record.get("state") or "")
        if state == "upload_confirmed":
            if str(record.get("upload_request_sha256") or "") != request_sha256:
                raise RuntimeError("Feishu pending video upload digest changed")
            return "confirmed", str(record.get("file_key") or "")
        if state in {"upload_submitting", "recovery_required"}:
            return "recovery_required", ""
        if state != "polling":
            raise RuntimeError("Feishu pending video is not uploadable")
        record.update(
            {
                "state": "upload_submitting",
                "upload_request_sha256": request_sha256,
                "upload_started_at": current,
                "file_key": "",
                "last_error": "",
            }
        )
        _pending_save(pending)
    return "submit", ""


def _pending_confirm_upload(
    task_id: str, chat_id: str, request_sha256: str, file_key: str
) -> None:
    key = str(file_key or "")
    if not key or len(key) > 512:
        raise ValueError("invalid Feishu pending video file key")
    with _pending_lock:
        pending = _pending_load()
        record = pending.get(str(task_id))
        if (
            not isinstance(record, dict)
            or str(record.get("chat_id") or "") != str(chat_id)
            or str(record.get("state") or "") != "upload_submitting"
            or str(record.get("upload_request_sha256") or "") != request_sha256
        ):
            raise RuntimeError("Feishu pending video upload receipt changed")
        record.update(
            {
                "state": "upload_confirmed",
                "file_key": key,
                "last_error": "",
            }
        )
        _pending_save(pending)


def _pending_require_upload_recovery(
    task_id: str, chat_id: str, *, error_code: str
) -> bool:
    safe_error = re.sub(
        r"[^A-Za-z0-9_.-]+", "_", str(error_code or "upload_outcome_unknown")
    )[:64]
    with _pending_lock:
        pending = _pending_load()
        record = pending.get(str(task_id))
        if not isinstance(record, dict) or str(record.get("chat_id") or "") != str(
            chat_id
        ):
            return False
        state = str(record.get("state") or "")
        if state == "recovery_required":
            return True
        if state != "upload_submitting":
            return False
        record.update(
            {
                "state": "recovery_required",
                "file_key": "",
                "last_error": safe_error,
            }
        )
        _pending_save(pending)
    return True


def _enqueue_video_task(task_id: object, chat_id: object) -> bool:
    task = str(task_id or "")
    chat = str(chat_id or "")
    if not task or not chat or len(task) > 512 or len(chat) > 512:
        return False
    with _VIDEO_DISPATCH_LOCK:
        if task in _VIDEO_QUEUED or task in _VIDEO_ACTIVE:
            return False
        try:
            _VIDEO_QUEUE.put_nowait((task, chat))
        except queue.Full:
            return False
        _VIDEO_QUEUED.add(task)
    return True


def _feed_pending_videos() -> int:
    with _pending_lock:
        pending = dict(_pending_load())
    added = 0
    for task_id, info in pending.items():
        if _VIDEO_QUEUE.full():
            break
        chat_id = str(info.get("chat_id") or "") if isinstance(info, dict) else ""
        state = str(info.get("state") or "") if isinstance(info, dict) else ""
        if state == "upload_submitting":
            _pending_require_upload_recovery(
                task_id,
                chat_id,
                error_code="upload_interrupted",
            )
            continue
        if state == "recovery_required":
            continue
        if state not in {"polling", "upload_confirmed"}:
            raise RuntimeError("Feishu pending video state is not dispatchable")
        if _enqueue_video_task(task_id, chat_id):
            added += 1
    return added


def _run_one_video_queue_item(*, timeout: float = 0.5) -> bool:
    try:
        task_id, queued_chat_id = _VIDEO_QUEUE.get(timeout=max(0.0, float(timeout)))
    except queue.Empty:
        return False
    with _VIDEO_DISPATCH_LOCK:
        _VIDEO_QUEUED.discard(task_id)
        _VIDEO_ACTIVE.add(task_id)
    try:
        with _pending_lock:
            current = _pending_load().get(task_id)
        if not isinstance(current, dict):
            return True
        chat_id = str(current.get("chat_id") or queued_chat_id)
        try:
            _video_worker(task_id, chat_id)
        except Exception as exc:  # noqa: BLE001 - durable pending remains for feeder retry
            with _HEALTH_LOCK:
                _HEALTH_STATE["service_state"] = "degraded"
                _HEALTH_STATE["last_error_code"] = _safe_error_code(
                    type(exc).__name__, "video_worker_error"
                )
        return True
    finally:
        with _VIDEO_DISPATCH_LOCK:
            _VIDEO_ACTIVE.discard(task_id)
        _VIDEO_QUEUE.task_done()


def _video_queue_worker(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        _run_one_video_queue_item(timeout=0.5)


def _start_video_workers(
    stop_event: threading.Event, *, worker_count: int | None = None
) -> list[threading.Thread]:
    if worker_count is None:
        try:
            worker_count = int(os.getenv("FEISHU_VIDEO_WORKERS", "4"))
        except ValueError:
            worker_count = 4
    bounded_count = max(1, min(int(worker_count), 4))
    workers: list[threading.Thread] = []
    for index in range(bounded_count):
        worker = threading.Thread(
            target=_video_queue_worker,
            args=(stop_event,),
            name=f"feishu-video-{index + 1}",
            daemon=True,
        )
        worker.start()
        workers.append(worker)
    return workers


def _video_worker(task_id: str, chat_id: str) -> None:
    """Poll, upload and hand off one video without replaying an uncertain upload."""

    from orchestrator.media import _find_media_url

    with _pending_lock:
        record = _pending_load().get(str(task_id))
    if not isinstance(record, dict):
        return
    if str(record.get("chat_id") or "") != str(chat_id):
        raise RuntimeError("Feishu pending video chat identity changed")
    state = str(record.get("state") or "")
    if state == "upload_submitting":
        _pending_require_upload_recovery(
            task_id,
            chat_id,
            error_code="upload_interrupted",
        )
        return
    if state == "recovery_required":
        return
    if state == "upload_confirmed":
        try:
            _send_video(
                chat_id,
                str(record["file_key"]),
                delivery_key=f"video-task:{task_id}:media",
            )
        except Exception:  # durable upload receipt remains retryable with the same key
            return
        _pending_remove(task_id)
        return
    if state != "polling":
        raise RuntimeError("Feishu pending video state is not executable")

    deadline = time.time() + 1500
    while time.time() < deadline:
        time.sleep(12)
        try:
            status_document = _get(f"/v1/videos/{task_id}?model=agnes-video")
        except Exception:  # upstream polling is a read and remains retryable
            continue
        url = _find_media_url(status_document)
        if url:
            try:
                data = _download_url(url, "video")
            except Exception:  # no upload boundary was crossed; a link is safe
                _reply(
                    chat_id,
                    f"视频已经生成，但下载失败。链接：{url}",
                    delivery_key=f"video-task:{task_id}:fallback",
                )
                _pending_remove(task_id)
                return
            request_sha256 = _pending_upload_request_sha256(
                task_id,
                chat_id,
                data,
                "video.mp4",
                "mp4",
            )
            action, confirmed_key = _pending_begin_upload(
                task_id,
                chat_id,
                request_sha256,
            )
            if action == "recovery_required":
                return
            if action == "confirmed":
                file_key = confirmed_key
            else:
                try:
                    file_key = _upload_file(data, "video.mp4", "mp4")
                except FeishuMediaUploadOutcomeUnknown:
                    _pending_require_upload_recovery(
                        task_id,
                        chat_id,
                        error_code="upload_outcome_unknown",
                    )
                    return
                except Exception:  # explicit provider rejection: no asset was accepted
                    _reply(
                        chat_id,
                        f"视频已经生成，但飞书直传被拒绝。链接：{url}",
                        delivery_key=f"video-task:{task_id}:fallback",
                    )
                    _pending_remove(task_id)
                    return
                _pending_confirm_upload(
                    task_id,
                    chat_id,
                    request_sha256,
                    file_key,
                )
            try:
                _send_video(
                    chat_id,
                    file_key,
                    delivery_key=f"video-task:{task_id}:media",
                )
            except Exception:
                # The confirmed file_key is durable.  A later worker reuses it
                # and the stable delivery key instead of uploading again.
                return
            _pending_remove(task_id)
            return
        status = str(
            status_document.get("status")
            or (status_document.get("data") or {}).get("status")
            or ""
        ).lower()
        if any(value in status for value in ("fail", "error", "cancel")):
            _reply(
                chat_id,
                "视频生成失败了，请换个描述再试一次。",
                delivery_key=f"video-task:{task_id}:failed",
            )
            _pending_remove(task_id)
            return
    _reply(
        chat_id,
        "视频生成等待超时，本次任务已经停止。请稍后重新发起。",
        delivery_key=f"video-task:{task_id}:timeout",
    )
    _pending_remove(task_id)


def _parse_nl_schedule(text: str) -> "tuple[str, str] | None":
    """认自然语言"每天X点做Y"→(hhmm, task)；认不出返回 None（要有"每天"+时间+任务动作词，防误触）。"""
    if not re.search(r"每天|每日|天天", text):
        return None
    if not re.search(r"提醒|帮我|给我|记得|搜|查|总结|汇总|发|做|生成|报告|通知|汇报|播报|整理|看|盘点", text):
        return None
    pm = bool(re.search(r"下午|晚上|傍晚", text))
    m = re.search(r"(\d{1,2})\s*[:：]\s*(\d{2})", text)
    if m:
        h, mi = int(m.group(1)), int(m.group(2))
    else:
        m = re.search(r"(\d{1,2})\s*点\s*(?:(\d{1,2})\s*分|(半))?", text)
        if not m:
            return None
        h = int(m.group(1))
        mi = 30 if m.group(3) else (int(m.group(2)) if m.group(2) else 0)
    if pm and h < 12:
        h += 12
    h, mi = h % 24, mi % 60
    task = re.sub(
        r"每天|每日|天天|早上|上午|中午|下午|晚上|傍晚|凌晨|准时|"
        r"\d{1,2}\s*[:：]\s*\d{2}|\d{1,2}\s*点\s*(?:\d{1,2}\s*分|半)?",
        "",
        text,
    ).strip("，,。.、！!？? ")
    return (f"{h:02d}:{mi:02d}", task or text)


def _handle_schedule_cmd(chat_id: str, text: str) -> None:
    """Reject scheduling until identity-bound durable tasks are implemented."""

    del text
    _reply(
        chat_id,
        "⏰ 定时任务生产能力尚未启用；旧版会错误借用 owner 身份，现已安全停用。",
    )


def _schedule_worker() -> None:
    """Compatibility stub: production scheduling is intentionally disabled."""

    return None


def _event_payload(data: P2ImMessageReceiveV1) -> dict[str, str]:
    msg = data.event.message
    try:
        open_id = data.event.sender.sender_id.open_id or ""
    except Exception:  # noqa: BLE001 - optional SDK field
        open_id = ""
    return _validated_inbound_payload(
        {
            "message_id": msg.message_id,
            "chat_id": msg.chat_id,
            "message_type": msg.message_type,
            "content": msg.content,
            "open_id": open_id,
        }
    )


def _payload_event(payload: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id=payload["message_id"],
                chat_id=payload["chat_id"],
                message_type=payload["message_type"],
                content=payload["content"],
            ),
            sender=SimpleNamespace(
                sender_id=SimpleNamespace(open_id=payload["open_id"])
            ),
        )
    )


def _inbound_worker(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            claim = _claim_inbound()
        except Exception as exc:  # noqa: BLE001 - a worker must survive DB transients
            with _HEALTH_LOCK:
                _HEALTH_STATE["service_state"] = "degraded"
                _HEALTH_STATE["last_error_code"] = _safe_error_code(
                    type(exc).__name__, "inbox_claim_error"
                )
            stop_event.wait(1.0)
            continue
        if claim is None:
            stop_event.wait(0.25)
            continue
        payload = claim["payload"]
        ok = False
        error_code = "handler_failed"
        recovery_required = False
        finished = False
        session = _new_inbound_claim_session(claim)
        if not session.start():
            session.close()
            stop_event.wait(0.25)
            continue
        try:
            _DELIVERY_CONTEXT.message_id = payload["message_id"]
            _DELIVERY_CONTEXT.sequence = 0
            _DELIVERY_CONTEXT.attempts = int(claim["attempts"])
            _DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
            _DELIVERY_CONTEXT.claim_id = int(claim["id"])
            _DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
            _DELIVERY_CONTEXT.lease_guard = session
            _DELIVERY_CONTEXT.media_submission_sha256 = ""
            _handle_message(_payload_event(payload))
        except FeishuMediaUploadOutcomeUnknown:
            error_code = "media_upload_outcome_unknown"
            recovery_required = True
        except Exception as exc:  # noqa: BLE001 - persisted for bounded retry
            error_code = type(exc).__name__
        else:
            ok = True
        finally:
            _DELIVERY_CONTEXT.message_id = ""
            _DELIVERY_CONTEXT.sequence = 0
            _DELIVERY_CONTEXT.attempts = 0
            _DELIVERY_CONTEXT.claim_token = ""
            _DELIVERY_CONTEXT.claim_id = 0
            _DELIVERY_CONTEXT.claim_epoch = 0
            _DELIVERY_CONTEXT.lease_guard = None
            _DELIVERY_CONTEXT.media_submission_sha256 = ""
        try:
            outcome: _InboxFinishOutcome = (
                (ok, error_code, True)
                if recovery_required
                else (ok, error_code)
            )
            finished = session.finish(outcome)
        except Exception as exc:  # noqa: BLE001 - short lease recovery stays authoritative
            _record_claim_health(
                _safe_error_code(type(exc).__name__, "inbox_finish_error")
            )
            stop_event.wait(1.0)
        finally:
            session.close()
        if finished:
            _touch_message_finished()


def _start_inbound_workers(
    stop_event: threading.Event, *, worker_count: int | None = None
) -> list[threading.Thread]:
    if worker_count is None:
        try:
            worker_count = int(os.getenv("FEISHU_WORKERS", "4"))
        except ValueError:
            worker_count = 4
    bounded_count = max(1, min(int(worker_count), 8))
    workers: list[threading.Thread] = []
    for index in range(bounded_count):
        worker = threading.Thread(
            target=_inbound_worker,
            args=(stop_event,),
            name=f"feishu-inbound-{index + 1}",
            daemon=True,
        )
        worker.start()
        workers.append(worker)
    return workers


def _queue_access_guidance(payload: dict[str, str]) -> bool:
    """Queue at most one generic access notice per chat and minute."""

    chat_id = str(payload.get("chat_id") or "")
    message_id = str(payload.get("message_id") or "")
    if not chat_id or not message_id:
        return False
    current = time.monotonic()
    cutoff = current - _ACCESS_GUIDANCE_INTERVAL_SECONDS
    with _ACCESS_GUIDANCE_LOCK:
        previous = _ACCESS_GUIDANCE_LAST_SENT.get(chat_id)
        if previous is not None and previous > cutoff:
            return False
        _enqueue_outbox(
            chat_id,
            "text",
            json.dumps({"text": _ACCESS_GUIDANCE_NOTICE}, ensure_ascii=False),
            delivery_key=f"inbound:{message_id}:notice:access-guidance",
        )
        # Record the limiter hit only after the outbox transaction commits.  If
        # persistence fails, an upstream retry must be allowed to try again.
        _ACCESS_GUIDANCE_LAST_SENT[chat_id] = current
        if len(_ACCESS_GUIDANCE_LAST_SENT) > _ACCESS_GUIDANCE_MAX_KEYS:
            oldest = min(
                _ACCESS_GUIDANCE_LAST_SENT,
                key=_ACCESS_GUIDANCE_LAST_SENT.__getitem__,
            )
            if oldest != chat_id:
                _ACCESS_GUIDANCE_LAST_SENT.pop(oldest, None)
    return True


def on_message(data: P2ImMessageReceiveV1) -> None:
    """Persist authorized work and queue bounded guidance for locked text."""

    payload = _event_payload(data)
    _touch_event_received()
    allowed, owner = _load_feishu_access()
    open_id = payload["open_id"]
    authorized = (bool(owner) and open_id == owner) or is_allowed(open_id, allowed)
    if not authorized:
        if payload["message_type"] != "text":
            return
        try:
            text = re.sub(
                r"@_user_\d+|@_all",
                "",
                json.loads(payload["content"]).get("text", ""),
            ).strip()
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            return
        if parse_command(text)[0] != "whoami":
            if text:
                _queue_access_guidance(payload)
            return
    try:
        _store_inbound(payload)
    except FeishuQueueFull:
        with _HEALTH_LOCK:
            _HEALTH_STATE["service_state"] = "degraded"
            _HEALTH_STATE["last_error_code"] = "inbox_capacity"
        # The callback must not turn an unpersisted event into an apparent
        # success.  Propagate so the SDK/upstream can redeliver it.
        raise


def _handle_message(data: P2ImMessageReceiveV1) -> None:
    msg = data.event.message
    chat_id = msg.chat_id
    try:
        open_id = data.event.sender.sender_id.open_id or ""
    except Exception:  # noqa: BLE001
        open_id = ""
    mtype = msg.message_type

    if mtype == "text":
        text = re.sub(r"@_user_\d+|@_all", "", json.loads(msg.content).get("text", "")).strip()
    else:
        text = ""
    kind, payload = parse_command(text) if mtype == "text" else ("file", "")

    if kind == "whoami":
        if not _allow_inbound(open_id):
            _reply(chat_id, "⏳ 你发得有点快，稍后再试。")
            return
        _reply(chat_id, f"你的 open_id：{open_id or '(未取到)'}")
        return

    allowed, owner = _load_feishu_access()
    is_owner = bool(owner) and open_id == owner
    if not (is_owner or is_allowed(open_id, allowed)):
        _reply(chat_id, "抱歉，你暂未被授权使用本机器人。")
        return

    user_id = resolve_user_id(open_id, owner)

    if mtype != "text":  # 文件/图片/语音 → 下载并处理
        if not _allow_inbound(open_id):
            _reply(chat_id, "⏳ 你发得有点快，稍后再试。")
            return
        _handle_file(
            msg,
            message_id=msg.message_id,
            user_id=open_id,
            chat_id=chat_id,
        )
        return

    if not text:
        return
    if text.startswith("/定时"):
        _handle_schedule_cmd(chat_id, text)
        return
    _nl = _parse_nl_schedule(text)
    if _nl:
        _handle_schedule_cmd(chat_id, text)
        return
    if kind in ("up", "down"):
        _feedback(user_id, chat_id, kind, payload, message_id=msg.message_id)
        _reply(chat_id, "✅ 已记录，我会改进。" if kind == "down" else "👍 已记下，谢谢！")
        return

    if not _allow_inbound(open_id):
        _reply(chat_id, "⏳ 你发得有点快，稍后再试。")
        return

    vid = detect_media_intent(payload) == "video"
    if vid:  # 立即回执，别让用户干等创建（上游忙时创建也可能慢几十秒）
        _reply(chat_id, "🎬 收到～视频在生成了，好了我直接发你（这期间可以继续聊别的）。")
    progress_timer = None if vid else _start_text_progress_timer(chat_id)
    try:
        d = _agent_chat(payload, user_id, chat_id, video_async=vid)
    finally:
        _cancel_text_progress_timer(progress_timer)
    task_id, early = d.get("video_task"), d.get("video")
    if vid and (task_id or early):  # 早结果直发/否则后台耐心轮询，不卡、不丢
        if early:
            _send_reply(chat_id, {"reply": "", "video": early})
        else:
            _pending_add(task_id, chat_id)
            _enqueue_video_task(task_id, chat_id)
        return
    if vid:  # 有视频意图但没拿到任务/结果 = 创建就没成功
        _reply(chat_id, "🎬 这个视频没能开始生成（上游忙？），换个描述或过会儿再试。")
        return
    _send_reply(chat_id, d)


_SINGLETON_PORT = 47615  # 占坑端口：保证全机只有一个飞书桥，防多开导致一条消息被多个桥各发一遍
_singleton: "socket.socket | None" = None


def _observe_ws_connection() -> None:
    ws = _CURRENT_WS
    conn = getattr(ws, "_conn", None) if ws is not None else None
    observed = conn is not None and not bool(getattr(conn, "closed", False))
    with _HEALTH_LOCK:
        previous = bool(_HEALTH_STATE["connected"])
    if observed and not previous:
        _mark_connected()
    elif previous and not observed:
        _mark_disconnected("connection_lost")


def _maintenance_worker(stop_event: threading.Event) -> None:
    last_retention_run = 0.0
    while not stop_event.is_set():
        now = time.time()
        try:
            _observe_ws_connection()
            _refresh_runtime_readiness()
            _recover_stale_inflight(now=now)
            _drain_outbox(limit=100)
            _feed_pending_videos()
            if now - last_retention_run >= 60 * 60:
                _maintain_state(now=now)
                last_retention_run = now
            with _HEALTH_LOCK:
                if _HEALTH_STATE["connected"]:
                    if _claim_failure_still_active(
                        _HEALTH_STATE["last_error_code"]
                    ):
                        _HEALTH_STATE["service_state"] = "degraded"
                    else:
                        _HEALTH_STATE["service_state"] = "running"
                        _HEALTH_STATE["last_error_code"] = ""
            _update_health(now=now)
        except Exception as exc:  # noqa: BLE001 - keep the bridge alive, store type only
            with _HEALTH_LOCK:
                _HEALTH_STATE["service_state"] = "degraded"
                _HEALTH_STATE["last_error_code"] = _safe_error_code(
                    type(exc).__name__, "maintenance_error"
                )
        stop_event.wait(2.0)


def main() -> int:
    if _NACHUAN_FEISHU_STATE_ONLY:
        print("飞书 state-only 模块禁止启动渠道客户端。", flush=True)
        return 78
    app_id, app_secret = S.feishu_app_id, S.feishu_app_secret
    if not app_id or not app_secret:
        print("缺 FEISHU_APP_ID / FEISHU_APP_SECRET（启动时用 env 传入）")
        return 1
    # 单例守卫：占本地端口；已有桥在跑就退出（重复推送的根因就是多开）。进程退出时端口自动释放。
    global _singleton, _CURRENT_WS
    _singleton = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _singleton.bind(("127.0.0.1", _SINGLETON_PORT))
    except OSError:
        print(f"已有飞书桥在运行（端口 {_SINGLETON_PORT} 被占），本次不重复启动。", flush=True)
        return 2
    try:  # 写 PID 文件，方便后续可靠地重启/排障（不用再靠猜进程）
        (Path(S.usage_db_path).parent / "feishu_bridge.pid").write_text(str(os.getpid()), "utf-8")
    except Exception:  # noqa: BLE001
        pass
    _validate_recovery_ledgers_before_channel_start()
    _api["c"] = lark.Client.builder().app_id(app_id).app_secret(app_secret).build()
    _recover_inflight()
    stop_event = threading.Event()
    _start_inbound_workers(stop_event)
    _start_video_workers(stop_event)
    threading.Thread(
        target=_maintenance_worker,
        args=(stop_event,),
        name="feishu-maintenance",
        daemon=True,
    ).start()
    # 桥重启：durable pending 分批进入有界队列；满载时由 maintenance 以后补入。
    _feed_pending_videos()
    handler = (
        lark.EventDispatcherHandler.builder("", "")
        .register_p2_im_message_receive_v1(on_message)
        .build()
    )
    print(f"飞书桥接已启动（长连接·超级智能体），默认模型 {MODEL}。给机器人发消息试试。")
    # 长连接断了自动重连——网络抖动/飞书侧断开都不让桥接挂掉（之前 start() 一返回进程就退=老断线）。
    # 指数退避 3→30s 封顶；干净断开则重置退避。生成中的请求各自在独立线程里，不受重连影响。
    backoff = 3
    while True:
        generation_before = _connection_generation()
        try:
            ws = lark.ws.Client(
                app_id,
                app_secret,
                event_handler=handler,
                log_level=lark.LogLevel.ERROR,
            )
            ws.on_reconnecting = lambda: _mark_disconnected("sdk_reconnecting")
            ws.on_reconnected = lambda: _mark_connected()
            _CURRENT_WS = ws
            ws.start()  # 阻塞；正常不返回，一返回即代表断开
            _mark_disconnected("connection_ended")
            print("[warning] 飞书长连接结束。")
        except KeyboardInterrupt:
            stop_event.set()
            with _HEALTH_LOCK:
                _HEALTH_STATE["connected"] = False
                _HEALTH_STATE["service_state"] = "stopping"
                _HEALTH_STATE["last_error_code"] = ""
            _update_health()
            print("收到中断，退出。")
            return 0
        except Exception as e:  # noqa: BLE001
            _mark_disconnected(type(e).__name__)
            print(f"[warning] 飞书长连接异常：{type(e).__name__}")
        finally:
            _CURRENT_WS = None
        delay, backoff = _reconnect_backoff_step(
            backoff,
            observed_connected=_connection_generation() > generation_before,
        )
        time.sleep(delay)
        print("↻ 重连飞书长连接…")


if __name__ == "__main__":
    sys.exit(main())
