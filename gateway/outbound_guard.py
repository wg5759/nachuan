"""统一网络出站审计缓冲区与纯离线（空气间隙 Air-Gap）模式防火墙（P2-2）。

核心能力：
1. 线程安全环形缓冲区 ``OutboundAuditBuffer``（默认 ``maxlen=500`` + ``threading.Lock``）：
   记录每一笔出站请求的结构化元信息（严格脱敏：仅记录 ``scheme``/``host``/``port``/``path``，
   绝不记录 query string、Authorization、Cookie、请求正文与 API Key）。
2. 运行态 ``offline_mode`` 开关：
   初始化读取 ``Settings.offline_mode`` / ``NACHUAN_OFFLINE_MODE`` 环境变量以及持久化偏好文件
   ``data_dir/privacy_prefs.json``（兼容迁移读取旧 ``privacy_state.json``）；开启后，所有非回环
   出站请求在建连前即写入 ``blocked=True, block_reason="offline_mode"`` 审计条目并抛出
   ``OfflineModeBlockedError``（``OutboundBlockedError`` 为其同义别名）。
3. 统一 ``httpx`` 审计与拦截传输层：
   提供 ``AuditedAsyncTransport`` / ``AuditedSyncTransport`` 以及工厂函数
   ``create_async_client(caller=...)`` / ``create_sync_client(caller=...)``，同时保留幂等的全局
   ``install_httpx_outbound_guard()`` 守卫钩子（自动识别已挂 ``Audited*Transport`` 的客户端，
   杜绝重复记账）。
4. 进程级可重入兜底 socket 离线保护：
   ``install_socket_offline_guard()`` / ``uninstall_socket_offline_guard()`` /
   ``socket_offline_guard()``，确保纯离线模式下连绕过 ``httpx`` 的 ``urllib`` / ``http.client`` /
   裸 ``socket`` 非回环外联也 100% 被硬拦截。
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import http.client
import inspect
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import threading
import time
from typing import Any, Iterator
from urllib.parse import urlsplit
import urllib.request

import httpx

_LOG = logging.getLogger(__name__)
_DEFAULT_MAX_ENTRIES = 500
_OFFLINE_ENV_VAR = "NACHUAN_OFFLINE_MODE"
_SENSITIVE_ERROR_RE = re.compile(
    r"(?:bearer\s+[a-z0-9._\-+/=]+|sk-[a-z0-9_\-]{6,}|(?:api[_-]?key|token|secret|password|authorization)\s*[=:]\s*[^\s,&;]+)",
    re.I,
)
_CALLER_SKIP_MODULES = frozenset(
    {
        "gateway.outbound_guard",
        "httpx",
        "httpx._client",
        "httpx._transports",
        "httpcore",
        "anyio",
        "asyncio",
        "contextlib",
        "threading",
        "concurrent.futures",
        "socket",
        "urllib",
        "urllib.request",
        "http.client",
    }
)


class OfflineModeBlockedError(PermissionError):
    """请求被纳川纯离线（空气间隙）出站防火墙硬拦截时抛出。"""

    def __init__(
        self,
        message: str,
        *,
        host: str = "",
        reason: str = "offline_mode",
        caller: str = "",
    ) -> None:
        super().__init__(message)
        self.host = host
        self.reason = reason
        self.caller = caller


# 兼容旧命名
OutboundBlockedError = OfflineModeBlockedError


@dataclass(frozen=True)
class OutboundAuditEntry:
    """单条网络出站审计记录（与前端 OutboundAuditPane 契约字段 100% 对齐）。"""

    id: int
    ts_ms: int
    method: str
    scheme: str
    host: str
    port: int | None
    path: str
    caller: str
    is_loopback: bool
    blocked: bool
    block_reason: str
    status_code: int | None
    latency_ms: float | None
    error: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_loopback_host(host: str | None) -> bool:
    """严格判定目标主机是否为本地回环地址（严防 127.0.0.1.evil.com 伪装）。"""
    raw = str(host or "").strip().lower().rstrip(".")
    if not raw:
        return False
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    if raw == "localhost" or raw.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(raw)
        if addr.is_loopback:
            return True
        mapped = getattr(addr, "ipv4_mapped", None)
        return bool(mapped is not None and mapped.is_loopback)
    except ValueError:
        return False


def _sanitize_path(path: str | None) -> str:
    """仅保留路径部分并截断，彻底剥离 query string 与 fragment 以防密钥泄漏。"""
    raw = str(path or "/").split("?", 1)[0].split("#", 1)[0]
    if not raw:
        raw = "/"
    if len(raw) > 256:
        raw = raw[:253] + "..."
    return raw


def _sanitize_error(error: str | None) -> str:
    """脱敏错误信息，彻底清除可能混入的 query string、Bearer Token 与 API Key。"""
    raw = str(error or "").strip()
    if not raw:
        return ""
    raw = re.sub(r"\?[^\s\"']+", "", raw)
    raw = _SENSITIVE_ERROR_RE.sub("[REDACTED]", raw)
    return raw[:240]


def _parse_url_parts(url: str) -> tuple[str, str, int | None, str]:
    raw_url = str(url or "")
    parsed = urlsplit(raw_url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").strip().lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = _sanitize_path(parsed.path)
    return scheme, host, port, path


def _detect_caller(explicit_caller: str | None = None) -> str:
    if explicit_caller:
        return str(explicit_caller)[:120]
    frame = inspect.currentframe()
    try:
        cur = frame.f_back if frame else None
        depth = 0
        while cur is not None and depth < 28:
            mod = str(cur.f_globals.get("__name__", "") or "")
            fn = cur.f_code.co_name
            root_mod = mod.split(".", 1)[0]
            if (
                mod
                and mod not in _CALLER_SKIP_MODULES
                and root_mod not in _CALLER_SKIP_MODULES
                and not mod.startswith("httpx.")
                and not mod.startswith("httpcore.")
                and not mod.startswith("starlette.")
                and not mod.startswith("fastapi.")
                and not mod.startswith("uvicorn.")
            ):
                return f"{mod}:{fn}"[:120]
            cur = cur.f_back
            depth += 1
    finally:
        del frame
    return "unknown"


def _parse_bool_env(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    norm = raw.strip().lower()
    if norm in {"1", "true", "yes", "on"}:
        return True
    if norm in {"0", "false", "no", "off"}:
        return False
    return None


class OutboundAuditBuffer:
    """线程安全的出站审计环形缓冲区（默认 maxlen=500）。"""

    def __init__(self, *, maxlen: int = _DEFAULT_MAX_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._maxlen = max(1, int(maxlen))
        self._entries: deque[OutboundAuditEntry] = deque(maxlen=self._maxlen)
        self._next_id = 1
        self._total_allowed = 0
        self._total_blocked = 0
        self._non_loopback_count = 0

    @property
    def maxlen(self) -> int:
        return self._maxlen

    def record(
        self,
        *,
        method: str,
        url: str,
        caller: str | None = None,
        blocked: bool = False,
        block_reason: str = "",
        status_code: int | None = None,
        latency_ms: float | None = None,
        error: str = "",
    ) -> OutboundAuditEntry:
        """写入一条严格脱敏的出站审计记录。"""
        scheme, host, port, path = _parse_url_parts(url)
        loopback = is_loopback_host(host)
        resolved_caller = _detect_caller(caller)
        norm_method = (str(method or "GET").strip().upper() or "GET")[:16]
        rounded_latency = round(float(latency_ms), 2) if latency_ms is not None else None
        safe_error = _sanitize_error(error)

        with self._lock:
            entry = OutboundAuditEntry(
                id=self._next_id,
                ts_ms=int(time.time() * 1000),
                method=norm_method,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                caller=resolved_caller,
                is_loopback=loopback,
                blocked=bool(blocked),
                block_reason=str(block_reason or "")[:120],
                status_code=int(status_code) if status_code is not None else None,
                latency_ms=rounded_latency,
                error=safe_error,
            )
            self._next_id += 1
            self._entries.append(entry)
            if blocked:
                self._total_blocked += 1
            else:
                self._total_allowed += 1
                if not loopback:
                    self._non_loopback_count += 1
            return entry

    def snapshot(
        self,
        *,
        limit: int = 100,
        since_id: int = 0,
        blocked_only: bool = False,
        offline_mode: bool = False,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(int(limit), self._maxlen))
        safe_since = max(0, int(since_id))
        with self._lock:
            filtered = [
                e.to_dict()
                for e in self._entries
                if e.id > safe_since and (not blocked_only or e.blocked)
            ]
            items = filtered[-safe_limit:]
            return {
                "offline_mode": bool(offline_mode),
                "total_allowed": self._total_allowed,
                "total_blocked": self._total_blocked,
                "non_loopback_count": self._non_loopback_count,
                "items": items,
            }

    def clear(self) -> int:
        with self._lock:
            cleared = len(self._entries)
            self._entries.clear()
            self._total_allowed = 0
            self._total_blocked = 0
            self._non_loopback_count = 0
            return cleared

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
            self._next_id = 1
            self._total_allowed = 0
            self._total_blocked = 0
            self._non_loopback_count = 0


def _read_persisted_offline_flag(path: Path | None) -> bool | None:
    if path is None:
        return None
    candidates = [path]
    # 兼容迁移：若 privacy_prefs.json 尚不存在，尝试读取旧版 privacy_state.json
    if path.name == "privacy_prefs.json":
        candidates.append(path.parent / "privacy_state.json")
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("offline_mode"), bool):
                return data["offline_mode"]
        except (OSError, ValueError, TypeError):
            _LOG.warning("Failed to read %s; falling back to default", candidate.name)
    return None


def _write_persisted_offline_flag(path: Path, enabled: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, ValueError, TypeError):
            existing = {}
    existing["offline_mode"] = bool(enabled)
    tmp.write_text(json.dumps(existing, ensure_ascii=True), encoding="utf-8")
    os.replace(tmp, path)


class OutboundGuard:
    """线程安全的出站审计控制器与空气间隙模式防火墙。"""

    def __init__(
        self,
        *,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        state_path: str | Path | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._buffer = OutboundAuditBuffer(maxlen=max_entries)
        self._state_path: Path | None = Path(state_path) if state_path else None
        self._offline_mode = False
        self._offline_source = "default"
        self._load_initial_offline_state()

    @property
    def buffer(self) -> OutboundAuditBuffer:
        return self._buffer

    def _load_initial_offline_state(self) -> None:
        env_val = _parse_bool_env(_OFFLINE_ENV_VAR)
        if env_val is not None:
            self._offline_mode = env_val
            self._offline_source = "env"
            return
        persisted = _read_persisted_offline_flag(self._state_path)
        if persisted is not None:
            self._offline_mode = persisted
            self._offline_source = "persisted"

    def configure_state_path(
        self,
        state_path: str | Path,
        *,
        settings_offline_mode: bool | None = None,
    ) -> None:
        """在网关启动确定 DATA_DIR 后绑定纯离线模式持久化文件（privacy_prefs.json）。"""
        with self._lock:
            self._state_path = Path(state_path)
            env_val = _parse_bool_env(_OFFLINE_ENV_VAR)
            if env_val is not None:
                self._offline_mode = env_val
                self._offline_source = "env"
                return
            if self._offline_source == "default":
                persisted = _read_persisted_offline_flag(self._state_path)
                if persisted is not None:
                    self._offline_mode = persisted
                    self._offline_source = "persisted"
                elif settings_offline_mode is True:
                    self._offline_mode = True
                    self._offline_source = "settings"

    def is_offline_mode(self) -> bool:
        with self._lock:
            return self._offline_mode

    def offline_mode_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._offline_mode,
                "source": self._offline_source,
            }

    def set_offline_mode(
        self,
        enabled: bool,
        *,
        persist_path: str | Path | None = None,
        source: str = "api",
        persist: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ValueError("offline_mode enabled flag must be a boolean")
        with self._lock:
            self._offline_mode = enabled
            self._offline_source = source
            if persist_path is not None:
                self._state_path = Path(persist_path)
            state_path = self._state_path
        if persist and state_path is not None:
            try:
                _write_persisted_offline_flag(state_path, enabled)
            except OSError as exc:
                _LOG.warning("Failed to persist offline_mode state: %s", type(exc).__name__)
        return {"enabled": enabled, "source": source}

    def check_allowed(
        self,
        *,
        method: str = "GET",
        url: str,
        caller: str | None = None,
    ) -> None:
        """发包前预检：若纯离线开启且目标不是本地回环，立即记账并抛 OfflineModeBlockedError。"""
        _scheme, host, _port, _path = _parse_url_parts(url)
        loopback = is_loopback_host(host)
        if self.is_offline_mode() and not loopback:
            resolved_caller = _detect_caller(caller)
            self.record(
                method=method,
                url=url,
                caller=resolved_caller,
                blocked=True,
                block_reason="offline_mode",
                status_code=None,
                latency_ms=0.0,
                error=f"Blocked non-loopback host '{host}' in air-gapped offline mode",
            )
            raise OfflineModeBlockedError(
                f"纯离线（空气间隙）模式已开启，已拦截外网请求：{host or url}",
                host=host,
                reason="offline_mode",
                caller=resolved_caller,
            )

    def record(
        self,
        *,
        method: str,
        url: str,
        caller: str | None = None,
        blocked: bool = False,
        block_reason: str = "",
        status_code: int | None = None,
        latency_ms: float | None = None,
        error: str = "",
    ) -> OutboundAuditEntry:
        return self._buffer.record(
            method=method,
            url=url,
            caller=caller,
            blocked=blocked,
            block_reason=block_reason,
            status_code=status_code,
            latency_ms=latency_ms,
            error=error,
        )

    def snapshot(
        self,
        *,
        limit: int = 100,
        since_id: int = 0,
        blocked_only: bool = False,
    ) -> dict[str, Any]:
        return self._buffer.snapshot(
            limit=limit,
            since_id=since_id,
            blocked_only=blocked_only,
            offline_mode=self.is_offline_mode(),
        )

    def clear(self) -> int:
        return self._buffer.clear()

    def reset_for_tests(self, *, offline_mode: bool = False) -> None:
        self._buffer.reset()
        with self._lock:
            self._offline_mode = offline_mode
            self._offline_source = "test"
            self._state_path = None


_GLOBAL_GUARD = OutboundGuard()
_PATCH_LOCK = threading.Lock()
_HTTPX_PATCHED = False
_ORIG_CLIENT_SEND: Any = None
_ORIG_ASYNC_CLIENT_SEND: Any = None

_SOCKET_PATCH_LOCK = threading.Lock()
_SOCKET_GUARD_INSTALLED = False
_ORIG_SOCKET_CREATE_CONNECTION: Any = None
_ORIG_SOCKET_CONNECT: Any = None
_ORIG_SOCKET_CONNECT_EX: Any = None
_ORIG_HTTP_SET_TUNNEL: Any = None
_ORIG_HTTP_REQUEST: Any = None
_ORIG_URLLIB_OPEN: Any = None
_SOCKET_GUARD_TLS = threading.local()


def get_outbound_guard() -> OutboundGuard:
    """获取进程级唯一 OutboundGuard 单例。"""
    return _GLOBAL_GUARD


def get_outbound_audit_buffer() -> OutboundAuditBuffer:
    """获取进程级唯一 OutboundAuditBuffer 实例。"""
    return _GLOBAL_GUARD.buffer


def is_offline_mode() -> bool:
    """返回当前是否处于纯离线（空气间隙）模式。"""
    return _GLOBAL_GUARD.is_offline_mode()


def set_offline_mode(
    enabled: bool,
    *,
    persist_path: str | Path | None = None,
    source: str = "api",
    persist: bool = True,
) -> dict[str, Any]:
    """切换纯离线模式并按需持久化到 ``privacy_prefs.json``。"""
    return _GLOBAL_GUARD.set_offline_mode(
        enabled,
        persist_path=persist_path,
        source=source,
        persist=persist,
    )


def check_outbound_allowed(
    url: str,
    caller: str = "",
    method: str = "GET",
) -> None:
    """发包前离线闸门预检；纯离线开启且非回环目标时记账并抛出 OfflineModeBlockedError。"""
    _GLOBAL_GUARD.check_allowed(
        method=method,
        url=url,
        caller=caller or None,
    )


class AuditedAsyncTransport(httpx.AsyncBaseTransport):
    """统一异步出站审计与纯离线硬拦截传输层。"""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        caller: str = "",
        guard: OutboundGuard | None = None,
        **transport_kwargs: Any,
    ) -> None:
        self._inner = transport if transport is not None else httpx.AsyncHTTPTransport(**transport_kwargs)
        self._caller = caller
        self._guard = guard

    @property
    def caller(self) -> str:
        return self._caller

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        guard = self._guard or get_outbound_guard()
        url_str = str(request.url)
        method = request.method
        caller = self._caller or _detect_caller()
        guard.check_allowed(method=method, url=url_str, caller=caller)
        t0 = time.perf_counter()
        try:
            resp = await self._inner.handle_async_request(request)
        except OfflineModeBlockedError:
            raise
        except Exception as exc:
            guard.record(
                method=method,
                url=url_str,
                caller=caller,
                blocked=False,
                status_code=None,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                error=type(exc).__name__,
            )
            raise
        guard.record(
            method=method,
            url=url_str,
            caller=caller,
            blocked=False,
            status_code=resp.status_code,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return resp

    async def aclose(self) -> None:
        await self._inner.aclose()


class AuditedSyncTransport(httpx.BaseTransport):
    """统一同步出站审计与纯离线硬拦截传输层。"""

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        *,
        caller: str = "",
        guard: OutboundGuard | None = None,
        **transport_kwargs: Any,
    ) -> None:
        self._inner = transport if transport is not None else httpx.HTTPTransport(**transport_kwargs)
        self._caller = caller
        self._guard = guard

    @property
    def caller(self) -> str:
        return self._caller

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        guard = self._guard or get_outbound_guard()
        url_str = str(request.url)
        method = request.method
        caller = self._caller or _detect_caller()
        guard.check_allowed(method=method, url=url_str, caller=caller)
        t0 = time.perf_counter()
        try:
            resp = self._inner.handle_request(request)
        except OfflineModeBlockedError:
            raise
        except Exception as exc:
            guard.record(
                method=method,
                url=url_str,
                caller=caller,
                blocked=False,
                status_code=None,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                error=type(exc).__name__,
            )
            raise
        guard.record(
            method=method,
            url=url_str,
            caller=caller,
            blocked=False,
            status_code=resp.status_code,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
        return resp

    def close(self) -> None:
        self._inner.close()


_TRANSPORT_ONLY_KWARGS = frozenset(
    {
        "verify",
        "cert",
        "http1",
        "http2",
        "limits",
        "proxy",
        "uds",
        "local_address",
        "retries",
    }
)


def _split_transport_kwargs(kwargs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    transport_kw: dict[str, Any] = {}
    client_kw: dict[str, Any] = {}
    for k, v in kwargs.items():
        if k in _TRANSPORT_ONLY_KWARGS:
            transport_kw[k] = v
        else:
            client_kw[k] = v
    if "trust_env" in client_kw and "trust_env" not in transport_kw:
        transport_kw["trust_env"] = client_kw["trust_env"]
    return transport_kw, client_kw


def create_async_client(
    *,
    caller: str = "",
    guard: OutboundGuard | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """创建挂载 ``AuditedAsyncTransport`` 的 ``httpx.AsyncClient``。"""
    raw_transport = kwargs.pop("transport", None)
    raw_mounts = kwargs.pop("mounts", None)
    if raw_transport is not None:
        transport = (
            raw_transport
            if isinstance(raw_transport, AuditedAsyncTransport)
            else AuditedAsyncTransport(raw_transport, caller=caller, guard=guard)
        )
        client_kw = dict(kwargs)
    else:
        transport_kw, client_kw = _split_transport_kwargs(kwargs)
        transport = AuditedAsyncTransport(caller=caller, guard=guard, **transport_kw)
    if isinstance(raw_mounts, dict):
        client_kw["mounts"] = {
            pattern: (
                t
                if isinstance(t, AuditedAsyncTransport) or t is None
                else AuditedAsyncTransport(t, caller=caller, guard=guard)
            )
            for pattern, t in raw_mounts.items()
        }
    return httpx.AsyncClient(transport=transport, **client_kw)


def create_sync_client(
    *,
    caller: str = "",
    guard: OutboundGuard | None = None,
    **kwargs: Any,
) -> httpx.Client:
    """创建挂载 ``AuditedSyncTransport`` 的 ``httpx.Client``。"""
    raw_transport = kwargs.pop("transport", None)
    raw_mounts = kwargs.pop("mounts", None)
    if raw_transport is not None:
        transport = (
            raw_transport
            if isinstance(raw_transport, AuditedSyncTransport)
            else AuditedSyncTransport(raw_transport, caller=caller, guard=guard)
        )
        client_kw = dict(kwargs)
    else:
        transport_kw, client_kw = _split_transport_kwargs(kwargs)
        transport = AuditedSyncTransport(caller=caller, guard=guard, **transport_kw)
    if isinstance(raw_mounts, dict):
        client_kw["mounts"] = {
            pattern: (
                t
                if isinstance(t, AuditedSyncTransport) or t is None
                else AuditedSyncTransport(t, caller=caller, guard=guard)
            )
            for pattern, t in raw_mounts.items()
        }
    return httpx.Client(transport=transport, **client_kw)


def _is_in_memory_transport(client: Any) -> bool:
    """跳过 FastAPI TestClient / ASGI 内存假传输，避免把本地测试入站请求误算作出站外联。"""
    transport = getattr(client, "_transport", None)
    if transport is None:
        return False
    cls_name = type(transport).__name__
    mod_name = type(transport).__module__
    if cls_name in {"ASGITransport", "WSGITransport", "MockTransport"}:
        return True
    if "starlette.testclient" in mod_name or "_TestClientTransport" in cls_name:
        return True
    return False


def _has_audited_transport(client: Any, request: httpx.Request) -> bool:
    """检查本次请求是否已经交由 Audited*Transport 处理，避免外层 httpx 钩子重复记账。"""
    resolver = getattr(client, "_transport_for_url", None)
    if callable(resolver):
        try:
            selected = resolver(request.url)
            if isinstance(selected, (AuditedAsyncTransport, AuditedSyncTransport)):
                return True
        except Exception:  # noqa: BLE001
            pass
    return isinstance(
        getattr(client, "_transport", None),
        (AuditedAsyncTransport, AuditedSyncTransport),
    )


def install_httpx_outbound_guard() -> bool:
    """幂等安装 httpx 同步/异步客户端透明出站防火墙与审计钩子（兜底未改写调用点）。"""
    global _HTTPX_PATCHED, _ORIG_CLIENT_SEND, _ORIG_ASYNC_CLIENT_SEND
    with _PATCH_LOCK:
        if _HTTPX_PATCHED:
            return False
        _ORIG_CLIENT_SEND = httpx.Client.send
        _ORIG_ASYNC_CLIENT_SEND = httpx.AsyncClient.send

        def _guarded_sync_send(
            self: httpx.Client, request: httpx.Request, *args: Any, **kwargs: Any
        ) -> httpx.Response:
            if _is_in_memory_transport(self) or _has_audited_transport(self, request):
                return _ORIG_CLIENT_SEND(self, request, *args, **kwargs)
            guard = get_outbound_guard()
            url_str = str(request.url)
            method = request.method
            caller = _detect_caller()
            guard.check_allowed(method=method, url=url_str, caller=caller)
            t0 = time.perf_counter()
            try:
                resp = _ORIG_CLIENT_SEND(self, request, *args, **kwargs)
            except OfflineModeBlockedError:
                raise
            except Exception as exc:
                guard.record(
                    method=method,
                    url=url_str,
                    caller=caller,
                    blocked=False,
                    status_code=None,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                    error=type(exc).__name__,
                )
                raise
            guard.record(
                method=method,
                url=url_str,
                caller=caller,
                blocked=False,
                status_code=resp.status_code,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )
            return resp

        async def _guarded_async_send(
            self: httpx.AsyncClient, request: httpx.Request, *args: Any, **kwargs: Any
        ) -> httpx.Response:
            if _is_in_memory_transport(self) or _has_audited_transport(self, request):
                return await _ORIG_ASYNC_CLIENT_SEND(self, request, *args, **kwargs)
            guard = get_outbound_guard()
            url_str = str(request.url)
            method = request.method
            caller = _detect_caller()
            guard.check_allowed(method=method, url=url_str, caller=caller)
            t0 = time.perf_counter()
            try:
                resp = await _ORIG_ASYNC_CLIENT_SEND(self, request, *args, **kwargs)
            except OfflineModeBlockedError:
                raise
            except Exception as exc:
                guard.record(
                    method=method,
                    url=url_str,
                    caller=caller,
                    blocked=False,
                    status_code=None,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                    error=type(exc).__name__,
                )
                raise
            guard.record(
                method=method,
                url=url_str,
                caller=caller,
                blocked=False,
                status_code=resp.status_code,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )
            return resp

        httpx.Client.send = _guarded_sync_send  # type: ignore[method-assign]
        httpx.AsyncClient.send = _guarded_async_send  # type: ignore[method-assign]
        _HTTPX_PATCHED = True
        return True


def uninstall_httpx_outbound_guard() -> bool:
    """卸载 httpx 守卫钩子（主要供单元测试清理环境）。"""
    global _HTTPX_PATCHED
    with _PATCH_LOCK:
        if not _HTTPX_PATCHED:
            return False
        if _ORIG_CLIENT_SEND is not None:
            httpx.Client.send = _ORIG_CLIENT_SEND  # type: ignore[method-assign]
        if _ORIG_ASYNC_CLIENT_SEND is not None:
            httpx.AsyncClient.send = _ORIG_ASYNC_CLIENT_SEND  # type: ignore[method-assign]
        _HTTPX_PATCHED = False
        return True


def _check_socket_target_offline(address: Any, *, family: int | None = None) -> None:
    """纯离线模式下的进程级兜底 socket 目标拦截（放行 AF_UNIX 与所有 loopback）。"""
    if not is_offline_mode():
        return
    if getattr(_SOCKET_GUARD_TLS, "in_check", False):
        return
    if family is not None and family not in (socket.AF_INET, socket.AF_INET6):
        return
    if not isinstance(address, tuple) or len(address) < 2:
        return
    raw_host = address[0]
    raw_port = address[1]
    if not isinstance(raw_host, str):
        return
    host = raw_host.strip()
    if not host or is_loopback_host(host):
        return
    port_part = f":{raw_port}" if isinstance(raw_port, int) and raw_port > 0 else ""
    bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
    _SOCKET_GUARD_TLS.in_check = True
    try:
        check_outbound_allowed(
            f"tcp://{bracketed}{port_part}/",
            caller=_detect_caller(),
            method="CONNECT",
        )
    finally:
        _SOCKET_GUARD_TLS.in_check = False


def install_socket_offline_guard() -> bool:
    """幂等安装进程级兜底离线保护（覆盖 socket + http.client + urllib，防本机代理隧道绕过）。"""
    global _SOCKET_GUARD_INSTALLED, _ORIG_SOCKET_CREATE_CONNECTION
    global _ORIG_SOCKET_CONNECT, _ORIG_SOCKET_CONNECT_EX
    global _ORIG_HTTP_SET_TUNNEL, _ORIG_HTTP_REQUEST, _ORIG_URLLIB_OPEN
    with _SOCKET_PATCH_LOCK:
        if _SOCKET_GUARD_INSTALLED:
            return False
        _ORIG_SOCKET_CREATE_CONNECTION = socket.create_connection
        _ORIG_SOCKET_CONNECT = socket.socket.connect
        _ORIG_SOCKET_CONNECT_EX = socket.socket.connect_ex
        _ORIG_HTTP_SET_TUNNEL = http.client.HTTPConnection.set_tunnel
        _ORIG_HTTP_REQUEST = http.client.HTTPConnection.request
        _ORIG_URLLIB_OPEN = urllib.request.OpenerDirector.open

        def _guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
            _check_socket_target_offline(address)
            return _ORIG_SOCKET_CREATE_CONNECTION(address, *args, **kwargs)

        def _guarded_connect(self: socket.socket, address: Any) -> Any:
            _check_socket_target_offline(address, family=self.family)
            return _ORIG_SOCKET_CONNECT(self, address)

        def _guarded_connect_ex(self: socket.socket, address: Any) -> Any:
            _check_socket_target_offline(address, family=self.family)
            return _ORIG_SOCKET_CONNECT_EX(self, address)

        def _guarded_set_tunnel(
            self: http.client.HTTPConnection,
            host: str,
            port: int | None = None,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if is_offline_mode() and not getattr(_SOCKET_GUARD_TLS, "in_check", False):
                target_host = str(host or "").strip()
                if target_host and not is_loopback_host(target_host):
                    port_part = f":{port}" if isinstance(port, int) and port > 0 else ""
                    bracketed = (
                        f"[{target_host}]"
                        if ":" in target_host and not target_host.startswith("[")
                        else target_host
                    )
                    _SOCKET_GUARD_TLS.in_check = True
                    try:
                        check_outbound_allowed(
                            f"https://{bracketed}{port_part}/",
                            caller=_detect_caller(),
                            method="CONNECT",
                        )
                    finally:
                        _SOCKET_GUARD_TLS.in_check = False
            return _ORIG_HTTP_SET_TUNNEL(self, host, port, *args, **kwargs)

        def _guarded_http_request(
            self: http.client.HTTPConnection,
            method: str,
            url: str,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if is_offline_mode() and not getattr(_SOCKET_GUARD_TLS, "in_check", False):
                raw_url = str(url or "")
                scheme = "https" if isinstance(self, http.client.HTTPSConnection) else "http"
                check_url = ""
                if raw_url.startswith(("http://", "https://")):
                    check_url = raw_url
                else:
                    tunnel_host = getattr(self, "_tunnel_host", None)
                    tunnel_port = getattr(self, "_tunnel_port", None)
                    target_host = str(tunnel_host or getattr(self, "host", "") or "").strip()
                    target_port = tunnel_port if tunnel_host else getattr(self, "port", None)
                    if target_host and not is_loopback_host(target_host):
                        bracketed = (
                            f"[{target_host}]"
                            if ":" in target_host and not target_host.startswith("[")
                            else target_host
                        )
                        port_part = (
                            f":{target_port}"
                            if isinstance(target_port, int) and target_port > 0
                            else ""
                        )
                        path_part = raw_url if raw_url.startswith("/") else f"/{raw_url}"
                        check_url = f"{scheme}://{bracketed}{port_part}{path_part}"
                if check_url:
                    _SOCKET_GUARD_TLS.in_check = True
                    try:
                        check_outbound_allowed(
                            check_url,
                            caller=_detect_caller(),
                            method=str(method or "GET"),
                        )
                    finally:
                        _SOCKET_GUARD_TLS.in_check = False
            return _ORIG_HTTP_REQUEST(self, method, url, *args, **kwargs)

        def _guarded_urllib_open(
            self: urllib.request.OpenerDirector,
            fullurl: Any,
            data: Any = None,
            timeout: Any = socket._GLOBAL_DEFAULT_TIMEOUT,
        ) -> Any:
            if is_offline_mode() and not getattr(_SOCKET_GUARD_TLS, "in_check", False):
                if isinstance(fullurl, urllib.request.Request):
                    target_url = fullurl.full_url
                    method = fullurl.get_method()
                else:
                    target_url = str(fullurl or "")
                    method = "POST" if data is not None else "GET"
                if target_url.startswith(("http://", "https://")):
                    _SOCKET_GUARD_TLS.in_check = True
                    try:
                        check_outbound_allowed(
                            target_url,
                            caller=_detect_caller(),
                            method=method,
                        )
                    finally:
                        _SOCKET_GUARD_TLS.in_check = False
            return _ORIG_URLLIB_OPEN(self, fullurl, data=data, timeout=timeout)

        socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
        socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
        http.client.HTTPConnection.set_tunnel = _guarded_set_tunnel  # type: ignore[method-assign]
        http.client.HTTPConnection.request = _guarded_http_request  # type: ignore[method-assign]
        urllib.request.OpenerDirector.open = _guarded_urllib_open  # type: ignore[method-assign]
        _SOCKET_GUARD_INSTALLED = True
        return True


def uninstall_socket_offline_guard() -> bool:
    """卸载进程级兜底离线保护。"""
    global _SOCKET_GUARD_INSTALLED
    with _SOCKET_PATCH_LOCK:
        if not _SOCKET_GUARD_INSTALLED:
            return False
        if _ORIG_SOCKET_CREATE_CONNECTION is not None:
            socket.create_connection = _ORIG_SOCKET_CREATE_CONNECTION  # type: ignore[assignment]
        if _ORIG_SOCKET_CONNECT is not None:
            socket.socket.connect = _ORIG_SOCKET_CONNECT  # type: ignore[method-assign]
        if _ORIG_SOCKET_CONNECT_EX is not None:
            socket.socket.connect_ex = _ORIG_SOCKET_CONNECT_EX  # type: ignore[method-assign]
        if _ORIG_HTTP_SET_TUNNEL is not None:
            http.client.HTTPConnection.set_tunnel = _ORIG_HTTP_SET_TUNNEL  # type: ignore[method-assign]
        if _ORIG_HTTP_REQUEST is not None:
            http.client.HTTPConnection.request = _ORIG_HTTP_REQUEST  # type: ignore[method-assign]
        if _ORIG_URLLIB_OPEN is not None:
            urllib.request.OpenerDirector.open = _ORIG_URLLIB_OPEN  # type: ignore[method-assign]
        _SOCKET_GUARD_INSTALLED = False
        return True


@contextmanager
def socket_offline_guard() -> Iterator[None]:
    """可重入上下文管理器：在作用域内保证进程级 socket 离线保护开启。"""
    installed_here = install_socket_offline_guard()
    try:
        yield
    finally:
        if installed_here:
            uninstall_socket_offline_guard()


__all__ = [
    "AuditedAsyncTransport",
    "AuditedSyncTransport",
    "OfflineModeBlockedError",
    "OutboundAuditBuffer",
    "OutboundAuditEntry",
    "OutboundBlockedError",
    "OutboundGuard",
    "check_outbound_allowed",
    "create_async_client",
    "create_sync_client",
    "get_outbound_audit_buffer",
    "get_outbound_guard",
    "install_httpx_outbound_guard",
    "install_socket_offline_guard",
    "is_loopback_host",
    "is_offline_mode",
    "set_offline_mode",
    "socket_offline_guard",
    "uninstall_httpx_outbound_guard",
    "uninstall_socket_offline_guard",
]
