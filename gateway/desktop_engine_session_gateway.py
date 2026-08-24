"""Raw-ASGI Desktop Main to Engine boot-session boundary.

Importing this module is side-effect free; ``gateway.app`` composes the wrapper
outside FastAPI for the packaged Engine and for an Electron-owned source launch
that presents boot authority.  It authenticates one exact HTTP/1.1 loopback
connection, delegates only closed privileged JSON routes, injects only
non-secret session state, and signs the complete bounded JSON response.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, unquote_to_bytes

from gateway.desktop_engine_session_protocol import (
    CHALLENGE_BODY,
    CHALLENGE_PATH,
    HEADER_PREFIX,
    NonceRegistry,
    DesktopEngineSessionProtocolError,
    SignedResponse,
    sign_response,
    verify_request,
)


SESSION_STATE_KEY = "nachuan_desktop_engine_session"

_BOOT_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_BUFFERED_RESPONSE = 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_ASGI_BODY_MESSAGES = 4096
_CHANNEL_TTL_MS = 10_000
_MAX_CHANNELS = 4096
_SECURITY_PREFIX = HEADER_PREFIX.lower().encode("ascii")
_CHALLENGE_RAW = CHALLENGE_PATH.encode("ascii")
_SESSION_ROOT = b"/internal/v1/desktop/session"
_APPROVALS = b"/v1/approvals"
_APPROVAL_RESOLVE_RE = re.compile(rb"^/v1/approvals/([1-9][0-9]*)/resolve$")
_CONNECTION_RE = re.compile(
    rb"^/admin/connections/([A-Za-z0-9][A-Za-z0-9_.-]{0,63})$"
)
_CHANNEL_RECOVERY_RE = re.compile(
    rb"^/admin/channel-recovery/(weixin|feishu)/(inspect|close-without-replay)$"
)
_SYNC_CONFIG = b"/v1/sync/config"
_SYNC_LOGIN = b"/v1/sync/login"
_SYNC_SIGNUP = b"/v1/sync/signup"
_SYNC_TOGGLE = b"/v1/sync/toggle"
_SYNC_RUN = b"/v1/sync/run"
_SYNC_POLICIES = {
    _SYNC_CONFIG: ("sync.config", 24 * 1024),
    _SYNC_LOGIN: ("sync.auth", 4 * 1024),
    _SYNC_SIGNUP: ("sync.auth", 4 * 1024),
    _SYNC_TOGGLE: ("sync.toggle", 1024),
    _SYNC_RUN: ("sync.run", 16),
}
_SYNC_PATH_TEXT = frozenset(path.decode("ascii") for path in _SYNC_POLICIES)
_APPROVAL_BODY_LIMIT = 16 * 1024
_CONNECTION_BODY_LIMIT = 512 * 1024
_CHANNEL_RECOVERY_BODY_LIMIT = 32 * 1024
_LEGACY_SECRET_HEADERS = frozenset(
    {
        b"authorization",
        b"proxy-authorization",
        b"x-nachuan-approval-key",
        b"x-nachuan-paid-media-key",
        b"cookie",
        b"x-api-key",
    }
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


_UNAVAILABLE_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "session_unavailable"}
)
_AUTHENTICATION_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "authentication_failed"}
)
_INVALID_REQUEST_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "invalid_request"}
)
_PAYLOAD_TOO_LARGE_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "payload_too_large"}
)
_SESSION_CHANGED_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "session_changed"}
)
_DOWNSTREAM_BODY = _json_bytes(
    {"schema": "nachuan.desktop.engine-session.error.v1", "code": "downstream_response_invalid"}
)


@dataclass(frozen=True, slots=True)
class _AuthorityIdentity:
    generation: int
    pid: int
    port: int


class _Authority:
    __slots__ = ("_boot_token", "identity")

    def __init__(self, boot_token: str, identity: _AuthorityIdentity) -> None:
        self._boot_token = boot_token
        self.identity = identity

    @property
    def boot_token(self) -> str:
        return self._boot_token

    def __repr__(self) -> str:
        return f"_Authority(identity={self.identity!r}, boot_token=<redacted>)"


@dataclass(frozen=True, slots=True)
class _RoutePolicy:
    capability: str
    method: str
    body_limit: int
    json_body: bool


class _ChallengeRegistry:
    """One actual request may consume a challenge on the same client socket."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, int, str], int] = {}
        self._lock = threading.Lock()

    def _prune_locked(self, now_ms: int) -> None:
        for key in [key for key, expiry in self._entries.items() if expiry <= now_ms]:
            del self._entries[key]

    def register(self, connection: tuple[str, int], nonce: str, *, now_ms: int) -> None:
        key = (*connection, nonce)
        with self._lock:
            self._prune_locked(now_ms)
            if len(self._entries) >= _MAX_CHANNELS:
                raise ValueError("engine session challenge registry is full")
            self._entries[key] = now_ms + _CHANNEL_TTL_MS

    def consume(self, connection: tuple[str, int], nonce: str, *, now_ms: int) -> None:
        key = (*connection, nonce)
        with self._lock:
            self._prune_locked(now_ms)
            expiry = self._entries.pop(key, None)
            if expiry is None or expiry <= now_ms:
                raise ValueError("engine session challenge is absent or expired")


def _parse_positive(value: object, *, maximum: int, label: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL_RE.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    parsed = int(value)
    if not 1 <= parsed <= maximum:
        raise ValueError(f"invalid {label}")
    return parsed


def _raw_headers(scope: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
    headers = scope.get("headers")
    if not isinstance(headers, (list, tuple)):
        raise ValueError("raw ASGI headers are unavailable")
    output: list[tuple[bytes, bytes]] = []
    for item in headers:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
            or _HEADER_NAME_RE.fullmatch(item[0]) is None
        ):
            raise ValueError("raw ASGI headers are invalid")
        try:
            item[1].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("raw ASGI header value is not ASCII") from exc
        output.append((item[0], item[1]))
    return output


def _normalized_name(name: bytes) -> bytes:
    try:
        return name.decode("ascii", "strict").lower().encode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII header name") from exc


def _scope_mentions_session_header(scope: Mapping[str, Any]) -> bool:
    """Detect our ASCII prefix without normalizing unrelated request values."""

    headers = scope.get("headers")
    if not isinstance(headers, (list, tuple)):
        return False
    for item in headers:
        if (
            isinstance(item, (list, tuple))
            and len(item) == 2
            and isinstance(item[0], bytes)
            and item[0].lower().startswith(_SECURITY_PREFIX)
        ):
            return True
    return False


def _contains_legacy_secret(headers: list[tuple[bytes, bytes]]) -> bool:
    return any(_normalized_name(name) in _LEGACY_SECRET_HEADERS for name, _ in headers)


def _ordinary_headers(headers: list[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    output: dict[bytes, bytes] = {}
    for name, value in headers:
        normalized = _normalized_name(name)
        if normalized.startswith(_SECURITY_PREFIX):
            continue
        if normalized in output:
            raise ValueError("duplicate ordinary request header")
        output[normalized] = value
    return output


def _validate_request_headers(
    headers: list[tuple[bytes, bytes]],
    *,
    authority: _Authority,
    body: bytes,
    challenge: bool,
    json_body: bool,
) -> None:
    ordinary = _ordinary_headers(headers)
    expected = {
        b"host": f"127.0.0.1:{authority.identity.port}".encode("ascii"),
        b"connection": b"keep-alive" if challenge else b"close",
        b"content-length": str(len(body)).encode("ascii"),
        b"accept": b"application/json",
        b"accept-encoding": b"identity",
        b"cache-control": b"no-store",
        **({b"content-type": b"application/json"} if json_body else {}),
    }
    if ordinary != expected:
        raise ValueError("ordinary request headers do not match the closed contract")


def _validate_scope(
    scope: Mapping[str, Any], *, expected_port: int
) -> tuple[str, bytes, bytes, str, tuple[str, int]]:
    if scope.get("type") != "http" or scope.get("http_version") != "1.1":
        raise ValueError("engine session requires HTTP/1.1")
    if scope.get("scheme") != "http":
        raise ValueError("engine session requires local HTTP")
    client = scope.get("client")
    if (
        not isinstance(client, (list, tuple))
        or len(client) < 2
        or client[0] != "127.0.0.1"
        or isinstance(client[1], bool)
        or not isinstance(client[1], int)
        or not 1 <= client[1] <= 65535
    ):
        raise ValueError("engine session peer is not exact IPv4 loopback")
    server = scope.get("server")
    if (
        not isinstance(server, (list, tuple))
        or len(server) < 2
        or server[0] != "127.0.0.1"
        or server[1] != expected_port
    ):
        raise ValueError("engine session listener is not exact")
    method = scope.get("method")
    raw_path = scope.get("raw_path")
    query = scope.get("query_string", b"")
    decoded_path = scope.get("path")
    if (
        not isinstance(method, str)
        or re.fullmatch(r"[A-Z]{1,16}", method) is None
        or type(raw_path) is not bytes
        or type(query) is not bytes
        or not isinstance(decoded_path, str)
    ):
        raise ValueError("engine session raw target is unavailable")
    try:
        raw_path_text = raw_path.decode("ascii", "strict")
        query_text = query.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("engine session raw target is not ASCII") from exc
    if (
        not raw_path.startswith(b"/")
        or any(byte < 0x21 or byte > 0x7E for byte in raw_path)
        or b"?" in raw_path
        or b"#" in raw_path
        or b"\\" in raw_path
        or any(byte < 0x21 or byte > 0x7E for byte in query)
        or b"?" in query
        or b"#" in query
        or b"\\" in query
        or decoded_path != raw_path_text
    ):
        raise ValueError("engine session raw target is ambiguous")
    target = raw_path_text + ("?" + query_text if query else "")
    if len(target.encode("ascii")) > 8 * 1024:
        raise ValueError("engine session raw target is too long")
    return method, raw_path, query, target, (client[0], client[1])


async def _read_body(receive: Any, *, limit: int) -> bytes:
    body = bytearray()
    messages = 0
    while True:
        message = await receive()
        messages += 1
        if messages > _MAX_ASGI_BODY_MESSAGES:
            raise ValueError("too many ASGI request body messages")
        if not isinstance(message, Mapping):
            raise ValueError("invalid ASGI request message")
        if message.get("type") == "http.disconnect":
            raise ConnectionError("client disconnected")
        if message.get("type") != "http.request":
            raise ValueError("invalid ASGI request message")
        chunk = message.get("body", b"")
        more_body = message.get("more_body", False)
        if type(chunk) is not bytes or type(more_body) is not bool:
            raise ValueError("invalid ASGI request body")
        body.extend(chunk)
        if len(body) > limit:
            raise OverflowError("engine session body limit exceeded")
        if not more_body:
            return bytes(body)


def _replay_body(body: bytes) -> Callable[[], Any]:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _parse_json(body: bytes) -> Any:
    try:
        value = json.loads(
            body.decode("utf-8", "strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid strict JSON") from exc

    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting exceeds the closed contract")
        if type(item) is float and not math.isfinite(item):
            raise ValueError("non-finite JSON number")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le", "strict")) // 2


def _contains_control(value: str, *, nul_only: bool = False) -> bool:
    if nul_only:
        return "\x00" in value
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _closed_object(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{label} must contain exactly the closed fields")
    return value


def _canonical_user_query(query: bytes) -> None:
    prefix = b"user_id="
    if not query.startswith(prefix) or b"&" in query or b"+" in query:
        raise ValueError("approval list query is not canonical")
    encoded = query[len(prefix) :]
    if not encoded:
        raise ValueError("approval user id is empty")
    try:
        value = unquote_to_bytes(encoded).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("approval user id is not UTF-8") from exc
    if (
        not value
        or _utf16_length(value) > 128
        or _contains_control(value)
        or quote(value, safe="-_.!~*'()").encode("ascii") != encoded
    ):
        raise ValueError("approval list query is not canonical")


def _reserved_path(raw_path: Any, decoded_path: Any) -> bool:
    if raw_path == _CHALLENGE_RAW:
        return True
    if isinstance(raw_path, bytes):
        if raw_path == _SESSION_ROOT or raw_path.startswith(_SESSION_ROOT + b"/"):
            return True
        if raw_path == _APPROVALS or (
            raw_path.startswith(_APPROVALS + b"/") and raw_path.endswith(b"/resolve")
        ):
            return True
        if _CONNECTION_RE.fullmatch(raw_path) is not None:
            return True
        if _CHANNEL_RECOVERY_RE.fullmatch(raw_path) is not None:
            return True
        if raw_path in _SYNC_POLICIES:
            return True
    if isinstance(decoded_path, str):
        try:
            decoded = decoded_path.encode("ascii", "strict")
        except UnicodeEncodeError:
            return False
        if decoded == _CHALLENGE_RAW or decoded == _APPROVALS:
            return True
        if _APPROVAL_RESOLVE_RE.fullmatch(decoded) is not None:
            return True
        if _CONNECTION_RE.fullmatch(decoded) is not None:
            return True
        if _CHANNEL_RECOVERY_RE.fullmatch(decoded) is not None:
            return True
        if decoded_path in _SYNC_PATH_TEXT:
            return True
    return False


def _route_policy(raw_path: bytes, query: bytes, method: str) -> _RoutePolicy | None:
    if raw_path == _APPROVALS:
        if method != "GET":
            return None
        _canonical_user_query(query)
        return _RoutePolicy("approval.list", "GET", 0, False)
    approval = _APPROVAL_RESOLVE_RE.fullmatch(raw_path)
    if approval is not None:
        approval_id = int(approval.group(1))
        if (
            method != "POST"
            or query
            or not 1 <= approval_id <= _MAX_SAFE_INTEGER
        ):
            return None
        return _RoutePolicy(
            "approval.resolve", "POST", _APPROVAL_BODY_LIMIT, True
        )
    connection = _CONNECTION_RE.fullmatch(raw_path)
    if connection is not None:
        if query:
            return None
        if method == "POST":
            return _RoutePolicy(
                "connection.save", "POST", _CONNECTION_BODY_LIMIT, True
            )
        if method == "DELETE":
            return _RoutePolicy("connection.delete", "DELETE", 0, False)
        return None
    recovery = _CHANNEL_RECOVERY_RE.fullmatch(raw_path)
    if recovery is not None:
        if method != "POST" or query:
            return None
        action = recovery.group(2)
        if action == b"inspect":
            return _RoutePolicy(
                "channel-recovery.inspect", "POST", _CHANNEL_RECOVERY_BODY_LIMIT, True
            )
        if action == b"close-without-replay":
            return _RoutePolicy(
                "channel-recovery.close", "POST", _CHANNEL_RECOVERY_BODY_LIMIT, True
            )
        return None
    sync = _SYNC_POLICIES.get(raw_path)
    if sync is not None and not query and method == "POST":
        return _RoutePolicy(sync[0], "POST", sync[1], True)
    return None


def _validate_route_body(policy: _RoutePolicy, body: bytes) -> None:
    if policy.capability in {"approval.list", "connection.delete"}:
        if body:
            raise ValueError("body is forbidden for this route")
        return
    value = _parse_json(body)
    if policy.capability == "approval.resolve":
        obj = _closed_object(value, {"decision", "note"}, "approval decision")
        decision = obj["decision"]
        note = obj["note"]
        if decision not in {"approve", "reject", "revise"}:
            raise ValueError("approval decision is invalid")
        if (
            type(note) is not str
            or _utf16_length(note) > 2000
            or _contains_control(note, nul_only=True)
        ):
            raise ValueError("approval note is invalid")
        return
    if policy.capability == "connection.save":
        obj = _closed_object(
            value,
            {
                "type",
                "api_key",
                "base_url",
                "enabled_models",
                "preserve_existing_credential",
            },
            "connection configuration",
        )
        connection_type = obj["type"]
        api_key = obj["api_key"]
        base_url = obj["base_url"]
        enabled_models = obj["enabled_models"]
        preserve_existing_credential = obj["preserve_existing_credential"]
        if (
            type(connection_type) is not str
            or not 1 <= _utf16_length(connection_type) <= 128
            or _contains_control(connection_type)
            or type(api_key) is not str
            or _utf16_length(api_key) > 32_768
            or _contains_control(api_key, nul_only=True)
            or type(base_url) is not str
            or _utf16_length(base_url) > 2048
            or _contains_control(base_url)
            or type(enabled_models) is not list
            or len(enabled_models) > 200
            or any(type(item) is not dict for item in enabled_models)
            or type(preserve_existing_credential) is not bool
        ):
            raise ValueError("connection configuration is invalid")
        return
    if policy.capability == "sync.config":
        obj = _closed_object(value, {"url", "anon_key"}, "sync configuration")
        url = obj["url"]
        anon_key = obj["anon_key"]
        if (
            type(url) is not str
            or not 1 <= _utf16_length(url) <= 2048
            or _contains_control(url)
            or type(anon_key) is not str
            or not 1 <= _utf16_length(anon_key) <= 16_384
            or _contains_control(anon_key, nul_only=True)
        ):
            raise ValueError("sync configuration is invalid")
        return
    if policy.capability == "sync.auth":
        obj = _closed_object(value, {"email", "password"}, "sync credentials")
        email = obj["email"]
        password = obj["password"]
        if (
            type(email) is not str
            or not 1 <= _utf16_length(email) <= 320
            or _contains_control(email)
            or type(password) is not str
            or not 1 <= _utf16_length(password) <= 1024
            or _contains_control(password, nul_only=True)
        ):
            raise ValueError("sync credentials are invalid")
        return
    if policy.capability == "sync.toggle":
        obj = _closed_object(value, {"enabled"}, "sync toggle")
        if type(obj["enabled"]) is not bool:
            raise ValueError("sync toggle is invalid")
        return
    if policy.capability == "sync.run":
        if type(value) is not dict or value:
            raise ValueError("sync.run body must be an empty JSON object")
        return
    if policy.capability in {
        "channel-recovery.inspect",
        "channel-recovery.close",
    }:
        obj = _closed_object(
            value,
            {"target_kind", "target_key"}
            if policy.capability == "channel-recovery.inspect"
            else {
                "target_kind",
                "target_key",
                "expected_before_digest",
                "decision_id",
                "decided_at_ms",
                "reason",
                "user_confirmed",
                "confirm_final",
            },
            "channel recovery request",
        )
        target_kind = obj["target_kind"]
        target_key = obj["target_key"]
        if (
            type(target_kind) is not str
            or target_kind
            not in {"inbound", "delivery", "video", "inbox", "outbox"}
            or type(target_key) is not str
            or not 1 <= _utf16_length(target_key) <= 512
            or _contains_control(target_key)
        ):
            raise ValueError("channel recovery target is invalid")
        if policy.capability == "channel-recovery.inspect":
            return
        before = obj["expected_before_digest"]
        decision = obj["decision_id"]
        decided_at_ms = obj["decided_at_ms"]
        reason = obj["reason"]
        if (
            type(before) is not str
            or re.fullmatch(r"[0-9a-f]{64}", before) is None
            or before == "0" * 64
            or type(decision) is not str
            or re.fullmatch(r"[0-9a-f]{64}", decision) is None
            or decision == "0" * 64
            or type(decided_at_ms) is not int
            or not 0 <= decided_at_ms <= _MAX_SAFE_INTEGER
            or type(reason) is not str
            or not 1 <= _utf16_length(reason) <= 2048
            or _contains_control(reason)
            or obj["user_confirmed"] is not True
            or obj["confirm_final"] is not True
        ):
            raise ValueError("channel recovery decision is invalid")
        return
    raise ValueError("unknown Desktop engine-session route")


def _response_headers(message: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
    headers = message.get("headers", [])
    if not isinstance(headers, (list, tuple)):
        raise ValueError("invalid ASGI response headers")
    output: dict[bytes, bytes] = {}
    allowed = {b"content-type", b"content-length", b"cache-control"}
    for item in headers:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
            or _HEADER_NAME_RE.fullmatch(item[0]) is None
        ):
            raise ValueError("invalid ASGI response headers")
        name = _normalized_name(item[0])
        if name.startswith(_SECURITY_PREFIX):
            raise ValueError("downstream emitted a reserved engine session header")
        if name not in allowed or name in output:
            raise ValueError("downstream emitted an unbound or duplicate response header")
        try:
            value = item[1].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("downstream emitted a non-ASCII response header") from exc
        if not value or value != value.strip() or "\r" in value or "\n" in value:
            raise ValueError("downstream emitted an invalid response header")
        output[name] = item[1]
    return list(output.items())


def _normalize_json_response_headers(
    headers: list[tuple[bytes, bytes]], body: bytes, *, connection: bytes
) -> list[tuple[bytes, bytes]]:
    values = dict(headers)
    if values.get(b"content-type") != b"application/json":
        raise ValueError("downstream response must be application/json")
    length = values.get(b"content-length")
    if length is not None:
        if re.fullmatch(rb"0|[1-9][0-9]*", length) is None or int(length) != len(body):
            raise ValueError("downstream response content length mismatch")
    if values.get(b"cache-control") not in {None, b"no-store"}:
        raise ValueError("downstream response cache policy is invalid")
    _parse_json(body)
    return [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"connection", connection),
    ]


def _signature_headers(signed: SignedResponse) -> list[tuple[bytes, bytes]]:
    return [(name.encode("ascii"), value.encode("ascii")) for name, value in signed.headers.items()]


async def _send_unsigned_json(send: Any, *, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class DesktopEngineSessionGatewayApp:
    """Authenticate and sign the closed Desktop privileged JSON surface."""

    def __init__(
        self,
        downstream: Any,
        *,
        configured_port: int,
        environ: Mapping[str, str] | None = None,
        pid_provider: Callable[[], int] = os.getpid,
        now_ms_provider: Callable[[], int] | None = None,
        nonce_registry: NonceRegistry | None = None,
    ) -> None:
        self._downstream = downstream
        self._configured_port = configured_port
        self._environ = os.environ if environ is None else environ
        self._pid_provider = pid_provider
        self._now_ms_provider = now_ms_provider or (lambda: time.time_ns() // 1_000_000)
        self._nonce_registry = nonce_registry or NonceRegistry()
        self._challenges = _ChallengeRegistry()
        self._active_states: dict[int, dict[str, object]] = {}
        self._active_states_lock = threading.Lock()
        try:
            self._baseline = self._read_authority()
        except (TypeError, ValueError):
            self._baseline = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._downstream, name)

    @property
    def ready(self) -> bool:
        if self._baseline is None:
            return False
        try:
            return self._same_authority(self._baseline, self._read_authority())
        except (TypeError, ValueError):
            return False

    def accepts_authenticated_state(
        self, value: object, *, expected_capability: str
    ) -> bool:
        """Re-bind inner FastAPI auth to this wrapper's current authority.

        The injected mapping is deliberately non-secret.  Object identity is
        registered only while this verifier instance is actively delegating the
        authenticated request, so an equal copied mapping cannot bypass the
        outer boundary and a retained mapping stops working after delegation.
        """

        try:
            authority = self._current_authority()
        except (TypeError, ValueError):
            return False
        if type(value) is not dict:
            return False
        with self._active_states_lock:
            if self._active_states.get(id(value)) is not value:
                return False
        identity = authority.identity
        expected_fields = {
            "schema",
            "authenticated",
            "principal",
            "capability",
            "nonce",
            "generation",
            "pid",
            "port",
        }
        return (
            set(value) == expected_fields
            and value.get("schema") == "nachuan.desktop.engine-session.state.v1"
            and value.get("authenticated") is True
            and value.get("principal") == "desktop-main"
            and value.get("capability") == expected_capability
            and isinstance(value.get("nonce"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is not None
            and value["nonce"] != "0" * 64
            and type(value.get("generation")) is int
            and value["generation"] == identity.generation
            and type(value.get("pid")) is int
            and value["pid"] == identity.pid
            and type(value.get("port")) is int
            and value["port"] == identity.port
        )

    def _register_authenticated_state(self, value: dict[str, object]) -> None:
        with self._active_states_lock:
            key = id(value)
            if key in self._active_states:
                raise RuntimeError("Desktop engine session state is already active")
            self._active_states[key] = value

    def _unregister_authenticated_state(self, value: dict[str, object]) -> None:
        with self._active_states_lock:
            key = id(value)
            if self._active_states.get(key) is value:
                del self._active_states[key]

    def _read_authority(self) -> _Authority:
        boot_token = self._environ.get("NACHUAN_ENGINE_BOOT_TOKEN", "")
        if (
            not isinstance(boot_token, str)
            or _BOOT_TOKEN_RE.fullmatch(boot_token) is None
            or boot_token == "0" * 64
        ):
            raise ValueError("Desktop engine boot token is unavailable")
        generation = _parse_positive(
            self._environ.get("NACHUAN_ENGINE_GENERATION"),
            maximum=_MAX_SAFE_INTEGER,
            label="engine generation",
        )
        port = _parse_positive(
            self._environ.get("NACHUAN_ENGINE_PORT"),
            maximum=65535,
            label="engine port",
        )
        if port < 1024 or port != self._configured_port:
            raise ValueError("engine listener port is inconsistent")
        pid = self._pid_provider()
        if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= _MAX_SAFE_INTEGER:
            raise ValueError("engine pid is invalid")
        return _Authority(
            boot_token,
            _AuthorityIdentity(generation=generation, pid=pid, port=port),
        )

    @staticmethod
    def _same_authority(left: _Authority, right: _Authority) -> bool:
        return left.identity == right.identity and left.boot_token == right.boot_token

    def _current_authority(self) -> _Authority:
        if self._baseline is None:
            raise ValueError("Desktop engine session authority is unavailable")
        current = self._read_authority()
        if not self._same_authority(self._baseline, current):
            raise ValueError("Desktop engine session authority changed")
        return current

    def _authority_still_current(self, authority: _Authority) -> bool:
        try:
            return self._same_authority(authority, self._current_authority())
        except (TypeError, ValueError):
            return False

    async def _send_signed_json(
        self,
        send: Any,
        *,
        authority: _Authority,
        request_nonce: str,
        capability: str,
        status: int,
        body: bytes,
        connection: bytes,
    ) -> None:
        headers = _normalize_json_response_headers(
            [(b"content-type", b"application/json")],
            body,
            connection=connection,
        )
        identity = authority.identity
        signed = sign_response(
            boot_token=authority.boot_token,
            request_nonce=request_nonce,
            generation=identity.generation,
            pid=identity.pid,
            port=identity.port,
            capability=capability,
            status=status,
            contract_headers=headers,
            body=body,
        )
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [*headers, *_signature_headers(signed)],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _delegate_and_sign(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        *,
        authority: _Authority,
        request_nonce: str,
        capability: str,
    ) -> None:
        start: dict[str, Any] | None = None
        chunks: list[bytes] = []
        total = 0
        complete = False
        body_messages = 0

        async def downstream_send(message: Mapping[str, Any]) -> None:
            nonlocal start, total, complete, body_messages
            kind = message.get("type")
            if kind == "http.response.start":
                if start is not None:
                    raise ValueError("downstream sent duplicate response start")
                status = message.get("status")
                if (
                    isinstance(status, bool)
                    or not isinstance(status, int)
                    or not 200 <= status <= 599
                    or status == 204
                    or 300 <= status <= 399
                ):
                    raise ValueError("downstream response status is not bounded JSON")
                start = {"status": status, "headers": _response_headers(message)}
                return
            if kind != "http.response.body" or start is None or complete:
                raise ValueError("invalid downstream ASGI response sequence")
            body_messages += 1
            if body_messages > _MAX_ASGI_BODY_MESSAGES:
                raise ValueError("too many downstream ASGI body messages")
            chunk = message.get("body", b"")
            more_body = message.get("more_body", False)
            if type(chunk) is not bytes or type(more_body) is not bool:
                raise ValueError("invalid downstream response body")
            total += len(chunk)
            if total > _MAX_BUFFERED_RESPONSE:
                raise OverflowError("downstream JSON response exceeds signing bound")
            chunks.append(chunk)
            complete = not more_body

        try:
            await self._downstream(scope, receive, downstream_send)
            if start is None or not complete:
                raise ValueError("downstream omitted a complete JSON response")
            if not self._authority_still_current(authority):
                status = 503
                body = _SESSION_CHANGED_BODY
            else:
                status = start["status"]
                body = b"".join(chunks)
                _normalize_json_response_headers(
                    start["headers"], body, connection=b"close"
                )
        except Exception:  # noqa: BLE001 -- replace unsigned downstream output
            status = 503
            body = _DOWNSTREAM_BODY
        # No exception handler surrounds the outward send: once response.start may
        # have committed, attempting a second signed response would violate ASGI.
        await self._send_signed_json(
            send,
            authority=authority,
            request_nonce=request_nonce,
            capability=capability,
            status=status,
            body=body,
            connection=b"close",
        )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if not isinstance(scope, Mapping) or scope.get("type") != "http":
            await self._downstream(scope, receive, send)
            return
        raw_path = scope.get("raw_path")
        decoded_path = scope.get("path")
        session_named = _scope_mentions_session_header(scope)
        candidate = _reserved_path(raw_path, decoded_path) or session_named
        if not candidate:
            # Preserve unrelated ASGI bytes exactly.  Strict ASCII/header
            # parsing belongs only to this wrapper's reserved surface.
            await self._downstream(scope, receive, send)
            return
        try:
            headers = _raw_headers(scope)
        except ValueError:
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        if _contains_legacy_secret(headers):
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        try:
            authority = self._current_authority()
        except (TypeError, ValueError):
            await _send_unsigned_json(send, status=503, body=_UNAVAILABLE_BODY)
            return
        try:
            method, raw_path, query, target, connection = _validate_scope(
                scope, expected_port=authority.identity.port
            )
        except (TypeError, ValueError):
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        is_challenge = raw_path == _CHALLENGE_RAW and not query
        try:
            policy = None if is_challenge else _route_policy(raw_path, query, method)
        except ValueError:
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        if (is_challenge and method != "GET") or (not is_challenge and policy is None):
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        limit = 0 if is_challenge else policy.body_limit
        try:
            body = await _read_body(receive, limit=limit)
        except OverflowError:
            await _send_unsigned_json(send, status=413, body=_PAYLOAD_TOO_LARGE_BODY)
            return
        except (ConnectionError, TypeError, ValueError):
            await _send_unsigned_json(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        capability = "session.challenge" if is_challenge else policy.capability
        try:
            authenticated = verify_request(
                boot_token=authority.boot_token,
                expected_generation=authority.identity.generation,
                expected_pid=authority.identity.pid,
                expected_port=authority.identity.port,
                expected_capability=capability,
                method=method,
                target=target,
                headers=headers,
                body=body,
                nonce_registry=self._nonce_registry,
                now_ms=self._now_ms_provider(),
            )
        except DesktopEngineSessionProtocolError:
            await _send_unsigned_json(send, status=401, body=_AUTHENTICATION_BODY)
            return
        try:
            _validate_request_headers(
                headers,
                authority=authority,
                body=body,
                challenge=is_challenge,
                json_body=False if is_challenge else policy.json_body,
            )
        except ValueError:
            await self._send_signed_json(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                capability=capability,
                status=400,
                body=_INVALID_REQUEST_BODY,
                connection=b"close",
            )
            return
        now_ms = self._now_ms_provider()
        if is_challenge:
            if body or authenticated.channel_nonce != "0" * 64:
                await self._send_signed_json(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    capability=capability,
                    status=400,
                    body=_INVALID_REQUEST_BODY,
                    connection=b"close",
                )
                return
            try:
                self._challenges.register(connection, authenticated.nonce, now_ms=now_ms)
            except ValueError:
                await self._send_signed_json(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    capability=capability,
                    status=503,
                    body=_UNAVAILABLE_BODY,
                    connection=b"close",
                )
                return
            if not self._authority_still_current(authority):
                await self._send_signed_json(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    capability=capability,
                    status=503,
                    body=_SESSION_CHANGED_BODY,
                    connection=b"close",
                )
                return
            await self._send_signed_json(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                capability=capability,
                status=200,
                body=CHALLENGE_BODY,
                connection=b"keep-alive",
            )
            return
        try:
            self._challenges.consume(
                connection, authenticated.channel_nonce, now_ms=now_ms
            )
            _validate_route_body(policy, body)
        except ValueError:
            await self._send_signed_json(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                capability=capability,
                status=400,
                body=_INVALID_REQUEST_BODY,
                connection=b"close",
            )
            return
        if not self._authority_still_current(authority):
            await self._send_signed_json(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                capability=capability,
                status=503,
                body=_SESSION_CHANGED_BODY,
                connection=b"close",
            )
            return
        authorized_scope = dict(scope)
        authorized_scope["headers"] = [
            (name, value)
            for name, value in headers
            if not _normalized_name(name).startswith(_SECURITY_PREFIX)
        ]
        state = dict(scope.get("state") or {})
        session_state: dict[str, object] = {
            "schema": "nachuan.desktop.engine-session.state.v1",
            "authenticated": True,
            "principal": "desktop-main",
            "capability": capability,
            "nonce": authenticated.nonce,
            "generation": authority.identity.generation,
            "pid": authority.identity.pid,
            "port": authority.identity.port,
        }
        state[SESSION_STATE_KEY] = session_state
        authorized_scope["state"] = state
        self._register_authenticated_state(session_state)
        try:
            await self._delegate_and_sign(
                authorized_scope,
                _replay_body(body),
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                capability=capability,
            )
        finally:
            self._unregister_authenticated_state(session_state)


__all__ = ["DesktopEngineSessionGatewayApp", "SESSION_STATE_KEY"]
