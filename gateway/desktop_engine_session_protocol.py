"""Boot-scoped HMAC protocol for Desktop Main to the exact Engine process.

The namespace and KDF domains are intentionally independent from paid-media.
Adapters must supply raw, uncollapsed headers.  Every non-session request header
is authenticated; session headers are a closed, single-valued set.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
import struct
import threading
import time
from typing import Any


PROTOCOL_VERSION = "1"
CHALLENGE_PATH = "/internal/v1/desktop/session/challenge"
CHALLENGE_SCHEMA = "nachuan.desktop.engine-session.challenge.v1"
CHALLENGE_BODY = b'{"schema":"nachuan.desktop.engine-session.challenge.v1","ok":true}'

HEADER_PREFIX = "x-nachuan-engine-session-"
HEADER_VERSION = "X-Nachuan-Engine-Session-Protocol"
HEADER_TIMESTAMP_MS = "X-Nachuan-Engine-Session-Timestamp-Ms"
HEADER_NONCE = "X-Nachuan-Engine-Session-Nonce"
HEADER_CHANNEL_NONCE = "X-Nachuan-Engine-Session-Channel-Nonce"
HEADER_GENERATION = "X-Nachuan-Engine-Session-Generation"
HEADER_PID = "X-Nachuan-Engine-Session-Pid"
HEADER_PORT = "X-Nachuan-Engine-Session-Port"
HEADER_CAPABILITY = "X-Nachuan-Engine-Session-Capability"
HEADER_BODY_SHA256 = "X-Nachuan-Engine-Session-Body-SHA256"
HEADER_REQUEST_CONTRACT_SHA256 = "X-Nachuan-Engine-Session-Request-Contract-SHA256"
HEADER_SIGNATURE = "X-Nachuan-Engine-Session-Signature"
HEADER_RESPONSE_REQUEST_NONCE = "X-Nachuan-Engine-Session-Request-Nonce"
HEADER_RESPONSE_BODY_SHA256 = "X-Nachuan-Engine-Session-Response-Body-SHA256"
HEADER_RESPONSE_CONTRACT_SHA256 = "X-Nachuan-Engine-Session-Response-Contract-SHA256"
HEADER_RESPONSE_SIGNATURE = "X-Nachuan-Engine-Session-Response-Signature"

REQUEST_HEADER_NAMES = (
    HEADER_VERSION,
    HEADER_TIMESTAMP_MS,
    HEADER_NONCE,
    HEADER_CHANNEL_NONCE,
    HEADER_GENERATION,
    HEADER_PID,
    HEADER_PORT,
    HEADER_CAPABILITY,
    HEADER_BODY_SHA256,
    HEADER_REQUEST_CONTRACT_SHA256,
    HEADER_SIGNATURE,
)
RESPONSE_HEADER_NAMES = (
    HEADER_VERSION,
    HEADER_RESPONSE_REQUEST_NONCE,
    HEADER_GENERATION,
    HEADER_PID,
    HEADER_PORT,
    HEADER_CAPABILITY,
    HEADER_RESPONSE_BODY_SHA256,
    HEADER_RESPONSE_CONTRACT_SHA256,
    HEADER_RESPONSE_SIGNATURE,
)

DEFAULT_MAX_PAST_MS = 30_000
DEFAULT_MAX_FUTURE_MS = 5_000
DEFAULT_REPLAY_TTL_MS = 35_001
DEFAULT_MAX_NONCES = 4_096

_MAX_CONFIGURED_WINDOW_MS = 5 * 60_000
_MAX_TIMESTAMP_MS = (1 << 63) - 1
_MAX_SAFE_INTEGER = (1 << 53) - 1
_KDF_DOMAIN = b"nachuan.desktop.engine-session.key.v1"
_REQUEST_DOMAIN = b"nachuan.desktop.engine-session.request.v1"
_REQUEST_CONTRACT_DOMAIN = b"nachuan.desktop.engine-session.request-contract.v1"
_RESPONSE_DOMAIN = b"nachuan.desktop.engine-session.response.v1"
_RESPONSE_CONTRACT_DOMAIN = b"nachuan.desktop.engine-session.response-contract.v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]{1,16}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_ZERO_DIGEST = "0" * 64
_ALL_SESSION_HEADERS = frozenset(
    name.lower() for name in (*REQUEST_HEADER_NAMES, *RESPONSE_HEADER_NAMES)
)
_UNSIGNED_TRANSPORT_RESPONSE_HEADERS = frozenset({"date", "server", "keep-alive"})


class DesktopEngineSessionProtocolError(ValueError):
    """The Desktop engine-session envelope is invalid."""


class DesktopEngineSessionHeaderError(DesktopEngineSessionProtocolError):
    """A security or contract header is malformed or ambiguous."""


class DesktopEngineSessionAuthenticationError(DesktopEngineSessionProtocolError):
    """A digest, HMAC, capability, or exact session did not authenticate."""


class DesktopEngineSessionTimestampError(DesktopEngineSessionProtocolError):
    """The signed timestamp is outside the bounded acceptance window."""


class DesktopEngineSessionReplayError(DesktopEngineSessionProtocolError):
    """An authenticated request nonce has already been consumed."""


class DesktopEngineSessionCapacityError(DesktopEngineSessionProtocolError):
    """The bounded replay registry cannot safely accept another nonce."""


class DesktopEngineSessionTransportError(DesktopEngineSessionProtocolError):
    """The ASGI transport is not the exact expected loopback endpoint."""


@dataclass(frozen=True, slots=True)
class EngineSessionIdentity:
    generation: int
    pid: int
    port: int


@dataclass(frozen=True, slots=True)
class SignedRequest:
    headers: dict[str, str]
    timestamp_ms: int
    nonce: str
    channel_nonce: str
    capability: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class AuthenticatedRequest:
    timestamp_ms: int
    nonce: str
    channel_nonce: str
    capability: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class SignedResponse:
    headers: dict[str, str]
    request_nonce: str
    capability: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class AuthenticatedResponse:
    request_nonce: str
    capability: str
    status: int
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


def _validated_hex(
    value: str, label: str, *, allow_zero: bool = True
) -> tuple[str, bytes]:
    if (
        not isinstance(value, str)
        or _HEX_64.fullmatch(value) is None
        or (not allow_zero and value == _ZERO_DIGEST)
    ):
        raise DesktopEngineSessionProtocolError(f"invalid {label}")
    return value, bytes.fromhex(value)


def derive_session_key(boot_token: str) -> bytes:
    _, token = _validated_hex(boot_token, "engine boot token", allow_zero=False)
    return hmac.new(token, _KDF_DOMAIN, hashlib.sha256).digest()


def _u64(value: int, label: str, *, maximum: int = _MAX_TIMESTAMP_MS) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        raise DesktopEngineSessionProtocolError(f"invalid {label}")
    return struct.pack(">Q", value)


def _u32(value: int, label: str) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        raise DesktopEngineSessionProtocolError(f"invalid {label}")
    return struct.pack(">I", value)


def framed(domain: bytes, fields: Sequence[bytes]) -> bytes:
    if not isinstance(domain, bytes) or not domain or len(domain) > 0xFFFFFFFF:
        raise DesktopEngineSessionProtocolError("invalid signing frame")
    if len(fields) > 0xFFFFFFFF:
        raise DesktopEngineSessionProtocolError("invalid signing frame")
    output = bytearray(struct.pack(">I", len(domain)))
    output.extend(domain)
    output.extend(struct.pack(">I", len(fields)))
    for field in fields:
        try:
            value = bytes(field)
        except (TypeError, ValueError) as exc:
            raise DesktopEngineSessionProtocolError("invalid signing frame field") from exc
        output.extend(struct.pack(">Q", len(value)))
        output.extend(value)
    return bytes(output)


def _validated_positive(value: int, label: str) -> tuple[int, str]:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_SAFE_INTEGER
    ):
        raise DesktopEngineSessionProtocolError(f"invalid {label}")
    return value, str(value)


def _parsed_positive(value: str, label: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise DesktopEngineSessionProtocolError(f"invalid {label}")
    observed = int(value)
    _validated_positive(observed, label)
    return observed


def _validated_port(value: int) -> tuple[int, str]:
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
        raise DesktopEngineSessionProtocolError("invalid engine session port")
    return value, str(value)


def _parsed_port(value: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise DesktopEngineSessionProtocolError("invalid engine session port")
    observed = int(value)
    _validated_port(observed)
    return observed


def _session(generation: int, pid: int, port: int) -> EngineSessionIdentity:
    generation, _ = _validated_positive(generation, "engine session generation")
    pid, _ = _validated_positive(pid, "engine session pid")
    port, _ = _validated_port(port)
    return EngineSessionIdentity(generation=generation, pid=pid, port=port)


def _validated_method(value: str) -> str:
    if not isinstance(value, str) or _METHOD.fullmatch(value) is None:
        raise DesktopEngineSessionProtocolError("method must be uppercase ASCII")
    return value


def _validated_capability(value: str) -> str:
    if not isinstance(value, str) or _CAPABILITY.fullmatch(value) is None:
        raise DesktopEngineSessionProtocolError("invalid engine session capability")
    return value


def _validated_target(value: str) -> str:
    if not isinstance(value, str):
        raise DesktopEngineSessionProtocolError("invalid engine session target")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise DesktopEngineSessionProtocolError("target must be ASCII origin-form") from exc
    if (
        not encoded.startswith(b"/")
        or b"#" in encoded
        or b"\\" in encoded
        or encoded.count(b"?") > 1
        or len(encoded) > 8 * 1024
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise DesktopEngineSessionProtocolError("target must be exact ASCII origin-form")
    return value


def request_mac_input(
    *,
    timestamp_ms: int,
    nonce: str,
    channel_nonce: str,
    generation: int,
    pid: int,
    port: int,
    capability: str,
    method: str,
    target: str,
    body_sha256: str,
    contract_sha256: str,
) -> bytes:
    _u64(timestamp_ms, "engine session timestamp")
    _, nonce_bytes = _validated_hex(nonce, "request nonce", allow_zero=False)
    _, channel_bytes = _validated_hex(channel_nonce, "channel nonce")
    session = _session(generation, pid, port)
    capability = _validated_capability(capability)
    method = _validated_method(method)
    target = _validated_target(target)
    _, body_digest = _validated_hex(body_sha256, "request body digest")
    _, contract_digest = _validated_hex(contract_sha256, "request contract digest")
    return framed(
        _REQUEST_DOMAIN,
        (
            PROTOCOL_VERSION.encode("ascii"),
            _u64(timestamp_ms, "engine session timestamp"),
            nonce_bytes,
            channel_bytes,
            _u64(session.generation, "engine session generation", maximum=_MAX_SAFE_INTEGER),
            _u64(session.pid, "engine session pid", maximum=_MAX_SAFE_INTEGER),
            _u32(session.port, "engine session port"),
            capability.encode("ascii"),
            method.encode("ascii"),
            target.encode("ascii"),
            body_digest,
            contract_digest,
        ),
    )


def response_mac_input(
    *,
    request_nonce: str,
    generation: int,
    pid: int,
    port: int,
    capability: str,
    status: int,
    body_sha256: str,
    contract_sha256: str,
) -> bytes:
    _, nonce_bytes = _validated_hex(request_nonce, "request nonce", allow_zero=False)
    session = _session(generation, pid, port)
    capability = _validated_capability(capability)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise DesktopEngineSessionProtocolError("invalid engine session HTTP status")
    _, body_digest = _validated_hex(body_sha256, "response body digest")
    _, contract_digest = _validated_hex(contract_sha256, "response contract digest")
    return framed(
        _RESPONSE_DOMAIN,
        (
            PROTOCOL_VERSION.encode("ascii"),
            nonce_bytes,
            _u64(session.generation, "engine session generation", maximum=_MAX_SAFE_INTEGER),
            _u64(session.pid, "engine session pid", maximum=_MAX_SAFE_INTEGER),
            _u32(session.port, "engine session port"),
            capability.encode("ascii"),
            _u32(status, "engine session HTTP status"),
            body_digest,
            contract_digest,
        ),
    )


def _header_pairs(headers: Any) -> list[tuple[Any, Any]]:
    raw = getattr(headers, "raw", None)
    if raw is not None:
        return list(raw)
    if isinstance(headers, Mapping):
        pairs: list[tuple[Any, Any]] = []
        for key, value in headers.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((key, item) for item in value)
            else:
                pairs.append((key, value))
        return pairs
    if isinstance(headers, Iterable) and not isinstance(headers, (str, bytes, bytearray)):
        pairs = []
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise DesktopEngineSessionHeaderError("invalid raw HTTP header sequence")
            pairs.append((item[0], item[1]))
        return pairs
    raise DesktopEngineSessionHeaderError("raw HTTP headers are required")


def _header_text(value: Any, *, name: bool) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise DesktopEngineSessionHeaderError("non-ASCII engine session header") from exc
    if not isinstance(value, str):
        raise DesktopEngineSessionHeaderError("invalid engine session header")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise DesktopEngineSessionHeaderError("non-ASCII engine session header") from exc
    if name:
        if _HEADER_NAME.fullmatch(value) is None:
            raise DesktopEngineSessionHeaderError("invalid engine session header name")
    elif not value or value != value.strip() or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise DesktopEngineSessionHeaderError("invalid engine session header value")
    return value


def extract_security_headers(headers: Any, required_names: Sequence[str]) -> dict[str, str]:
    expected = {name.lower(): name for name in required_names}
    observed: dict[str, list[str]] = {name: [] for name in expected}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        value = _header_text(raw_value, name=False)
        if name.startswith(HEADER_PREFIX):
            if name not in _ALL_SESSION_HEADERS:
                raise DesktopEngineSessionHeaderError("unknown engine session header")
            if name not in expected:
                raise DesktopEngineSessionHeaderError("wrong-direction engine session header")
            if "," in value:
                raise DesktopEngineSessionHeaderError("comma-combined engine session header")
            observed[name].append(value)
    result: dict[str, str] = {}
    for lower_name, canonical_name in expected.items():
        values = observed[lower_name]
        if len(values) != 1:
            raise DesktopEngineSessionHeaderError("missing or duplicate engine session header")
        result[canonical_name] = values[0]
    return result


def _request_contract_frame(headers: Any) -> bytes:
    observed: dict[str, list[str]] = {}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        value = _header_text(raw_value, name=False)
        if name.startswith(HEADER_PREFIX):
            if name not in _ALL_SESSION_HEADERS:
                raise DesktopEngineSessionHeaderError("unknown engine session header")
            if name not in {item.lower() for item in REQUEST_HEADER_NAMES}:
                raise DesktopEngineSessionHeaderError("wrong-direction engine session header")
            continue
        observed.setdefault(name, []).append(value)
    fields: list[bytes] = []
    for name in sorted(observed, key=lambda item: item.encode("ascii")):
        values = observed[name]
        if len(values) != 1:
            raise DesktopEngineSessionHeaderError("duplicate request contract header")
        fields.extend((name.encode("ascii"), values[0].encode("ascii")))
    return framed(_REQUEST_CONTRACT_DOMAIN, fields)


def request_contract_sha256(headers: Any) -> str:
    return hashlib.sha256(_request_contract_frame(headers)).hexdigest()


def _response_contract_frame(headers: Any) -> bytes:
    observed: dict[str, list[str]] = {}
    response_names = {item.lower() for item in RESPONSE_HEADER_NAMES}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        value = _header_text(raw_value, name=False)
        if name.startswith(HEADER_PREFIX):
            if name not in _ALL_SESSION_HEADERS:
                raise DesktopEngineSessionHeaderError("unknown engine session header")
            if name not in response_names:
                raise DesktopEngineSessionHeaderError("wrong-direction engine session header")
            continue
        observed.setdefault(name, []).append(value)
    fields: list[bytes] = []
    for name in sorted(observed, key=lambda item: item.encode("ascii")):
        values = observed[name]
        if len(values) != 1:
            raise DesktopEngineSessionHeaderError("duplicate response contract header")
        if name in _UNSIGNED_TRANSPORT_RESPONSE_HEADERS:
            continue
        fields.extend((name.encode("ascii"), values[0].encode("ascii")))
    return framed(_RESPONSE_CONTRACT_DOMAIN, fields)


def response_contract_sha256(headers: Any) -> str:
    return hashlib.sha256(_response_contract_frame(headers)).hexdigest()


class NonceRegistry:
    """Bounded, thread-safe consume-once registry for authenticated requests."""

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_NONCES,
        max_ttl_ms: int = DEFAULT_REPLAY_TTL_MS,
    ) -> None:
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries < 1
            or isinstance(max_ttl_ms, bool)
            or not isinstance(max_ttl_ms, int)
            or max_ttl_ms < 1
            or max_ttl_ms > _MAX_CONFIGURED_WINDOW_MS + 1
        ):
            raise ValueError("invalid engine session nonce registry limits")
        self._max_entries = max_entries
        self._max_ttl_ms = max_ttl_ms
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def max_ttl_ms(self) -> int:
        return self._max_ttl_ms

    def _prune_locked(self, now_ms: int) -> None:
        for nonce in [key for key, expiry in self._entries.items() if expiry <= now_ms]:
            del self._entries[nonce]

    def consume(self, nonce: str, *, now_ms: int, expires_at_ms: int) -> None:
        _validated_hex(nonce, "request nonce", allow_zero=False)
        _u64(now_ms, "nonce registry time")
        _u64(expires_at_ms, "nonce expiry")
        if expires_at_ms <= now_ms or expires_at_ms - now_ms > self._max_ttl_ms:
            raise DesktopEngineSessionProtocolError("nonce expiry is outside bounded TTL")
        with self._lock:
            self._prune_locked(now_ms)
            if nonce in self._entries:
                raise DesktopEngineSessionReplayError("authenticated engine session nonce replay")
            if len(self._entries) >= self._max_entries:
                raise DesktopEngineSessionCapacityError("engine session nonce registry is full")
            self._entries[nonce] = expires_at_ms


def sign_request(
    *,
    boot_token: str,
    generation: int,
    pid: int,
    port: int,
    capability: str,
    method: str,
    target: str,
    contract_headers: Any,
    body: bytes = b"",
    timestamp_ms: int | None = None,
    nonce: str | None = None,
    channel_nonce: str = _ZERO_DIGEST,
) -> SignedRequest:
    key = derive_session_key(boot_token)
    session = _session(generation, pid, port)
    capability = _validated_capability(capability)
    payload = bytes(body)
    timestamp = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    _u64(timestamp, "engine session timestamp")
    request_nonce = secrets.token_hex(32) if nonce is None else nonce
    _validated_hex(request_nonce, "request nonce", allow_zero=False)
    _validated_hex(channel_nonce, "channel nonce")
    digest = hashlib.sha256(payload).hexdigest()
    contract_digest = request_contract_sha256(contract_headers)
    signature = hmac.new(
        key,
        request_mac_input(
            timestamp_ms=timestamp,
            nonce=request_nonce,
            channel_nonce=channel_nonce,
            generation=session.generation,
            pid=session.pid,
            port=session.port,
            capability=capability,
            method=method,
            target=target,
            body_sha256=digest,
            contract_sha256=contract_digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    return SignedRequest(
        headers={
            HEADER_VERSION: PROTOCOL_VERSION,
            HEADER_TIMESTAMP_MS: str(timestamp),
            HEADER_NONCE: request_nonce,
            HEADER_CHANNEL_NONCE: channel_nonce,
            HEADER_GENERATION: str(session.generation),
            HEADER_PID: str(session.pid),
            HEADER_PORT: str(session.port),
            HEADER_CAPABILITY: capability,
            HEADER_BODY_SHA256: digest,
            HEADER_REQUEST_CONTRACT_SHA256: contract_digest,
            HEADER_SIGNATURE: signature,
        },
        timestamp_ms=timestamp,
        nonce=request_nonce,
        channel_nonce=channel_nonce,
        capability=capability,
        body_sha256=digest,
        contract_sha256=contract_digest,
        session=session,
    )


def verify_request(
    *,
    boot_token: str,
    expected_generation: int,
    expected_pid: int,
    expected_port: int,
    expected_capability: str,
    method: str,
    target: str,
    headers: Any,
    body: bytes,
    nonce_registry: NonceRegistry,
    now_ms: int | None = None,
    max_past_ms: int = DEFAULT_MAX_PAST_MS,
    max_future_ms: int = DEFAULT_MAX_FUTURE_MS,
) -> AuthenticatedRequest:
    if not isinstance(nonce_registry, NonceRegistry):
        raise TypeError("nonce_registry must be a Desktop NonceRegistry")
    if (
        isinstance(max_past_ms, bool)
        or not isinstance(max_past_ms, int)
        or isinstance(max_future_ms, bool)
        or not isinstance(max_future_ms, int)
        or max_past_ms < 0
        or max_future_ms < 0
        or max_past_ms + max_future_ms > _MAX_CONFIGURED_WINDOW_MS
        or max_past_ms + max_future_ms + 1 > nonce_registry.max_ttl_ms
    ):
        raise DesktopEngineSessionProtocolError("invalid engine session time window")
    expected_session = _session(expected_generation, expected_pid, expected_port)
    expected_capability = _validated_capability(expected_capability)
    method = _validated_method(method)
    target = _validated_target(target)
    envelope = extract_security_headers(headers, REQUEST_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise DesktopEngineSessionProtocolError("unsupported engine session version")
    try:
        timestamp = int(envelope[HEADER_TIMESTAMP_MS])
    except (TypeError, ValueError) as exc:
        raise DesktopEngineSessionProtocolError("invalid engine session timestamp") from exc
    if str(timestamp) != envelope[HEADER_TIMESTAMP_MS]:
        raise DesktopEngineSessionProtocolError("non-canonical engine session timestamp")
    _u64(timestamp, "engine session timestamp")
    request_nonce, _ = _validated_hex(
        envelope[HEADER_NONCE], "request nonce", allow_zero=False
    )
    channel_nonce, _ = _validated_hex(envelope[HEADER_CHANNEL_NONCE], "channel nonce")
    observed_session = _session(
        _parsed_positive(envelope[HEADER_GENERATION], "engine session generation"),
        _parsed_positive(envelope[HEADER_PID], "engine session pid"),
        _parsed_port(envelope[HEADER_PORT]),
    )
    observed_capability = _validated_capability(envelope[HEADER_CAPABILITY])
    claimed_digest, _ = _validated_hex(envelope[HEADER_BODY_SHA256], "request body digest")
    claimed_contract, _ = _validated_hex(
        envelope[HEADER_REQUEST_CONTRACT_SHA256], "request contract digest"
    )
    claimed_signature, _ = _validated_hex(envelope[HEADER_SIGNATURE], "request signature")
    observed_now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    _u64(observed_now, "engine session current time")
    if timestamp < observed_now - max_past_ms:
        raise DesktopEngineSessionTimestampError("engine session request has expired")
    if timestamp > observed_now + max_future_ms:
        raise DesktopEngineSessionTimestampError("engine session request is too far in the future")
    actual_digest = hashlib.sha256(bytes(body)).hexdigest()
    actual_contract = request_contract_sha256(headers)
    expected_signature = hmac.new(
        derive_session_key(boot_token),
        request_mac_input(
            timestamp_ms=timestamp,
            nonce=request_nonce,
            channel_nonce=channel_nonce,
            generation=observed_session.generation,
            pid=observed_session.pid,
            port=observed_session.port,
            capability=observed_capability,
            method=method,
            target=target,
            body_sha256=actual_digest,
            contract_sha256=actual_contract,
        ),
        hashlib.sha256,
    ).hexdigest()
    if (
        observed_session != expected_session
        or observed_capability != expected_capability
        or not hmac.compare_digest(actual_digest, claimed_digest)
        or not hmac.compare_digest(actual_contract, claimed_contract)
        or not hmac.compare_digest(expected_signature, claimed_signature)
    ):
        raise DesktopEngineSessionAuthenticationError("engine session request failed authentication")
    nonce_registry.consume(
        request_nonce,
        now_ms=observed_now,
        expires_at_ms=timestamp + max_past_ms + 1,
    )
    return AuthenticatedRequest(
        timestamp_ms=timestamp,
        nonce=request_nonce,
        channel_nonce=channel_nonce,
        capability=observed_capability,
        body_sha256=actual_digest,
        contract_sha256=actual_contract,
        session=observed_session,
    )


def _response_digest(*, body: bytes | None, body_sha256: str | None) -> str:
    if (body is None) == (body_sha256 is None):
        raise DesktopEngineSessionProtocolError(
            "provide exactly one response body or response body digest"
        )
    if body_sha256 is not None:
        value, _ = _validated_hex(body_sha256, "response body digest")
        return value
    return hashlib.sha256(bytes(body)).hexdigest()


def sign_response(
    *,
    boot_token: str,
    request_nonce: str,
    generation: int,
    pid: int,
    port: int,
    capability: str,
    status: int,
    contract_headers: Any,
    body: bytes | None = None,
    body_sha256: str | None = None,
) -> SignedResponse:
    key = derive_session_key(boot_token)
    request_nonce, _ = _validated_hex(
        request_nonce, "request nonce", allow_zero=False
    )
    session = _session(generation, pid, port)
    capability = _validated_capability(capability)
    digest = _response_digest(body=body, body_sha256=body_sha256)
    contract_digest = response_contract_sha256(contract_headers)
    signature = hmac.new(
        key,
        response_mac_input(
            request_nonce=request_nonce,
            generation=session.generation,
            pid=session.pid,
            port=session.port,
            capability=capability,
            status=status,
            body_sha256=digest,
            contract_sha256=contract_digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    return SignedResponse(
        headers={
            HEADER_VERSION: PROTOCOL_VERSION,
            HEADER_RESPONSE_REQUEST_NONCE: request_nonce,
            HEADER_GENERATION: str(session.generation),
            HEADER_PID: str(session.pid),
            HEADER_PORT: str(session.port),
            HEADER_CAPABILITY: capability,
            HEADER_RESPONSE_BODY_SHA256: digest,
            HEADER_RESPONSE_CONTRACT_SHA256: contract_digest,
            HEADER_RESPONSE_SIGNATURE: signature,
        },
        request_nonce=request_nonce,
        capability=capability,
        body_sha256=digest,
        contract_sha256=contract_digest,
        session=session,
    )


def verify_response(
    *,
    boot_token: str,
    request_nonce: str,
    expected_generation: int,
    expected_pid: int,
    expected_port: int,
    expected_capability: str,
    status: int,
    headers: Any,
    body: bytes | None = None,
    body_sha256: str | None = None,
) -> AuthenticatedResponse:
    expected_nonce, _ = _validated_hex(
        request_nonce, "request nonce", allow_zero=False
    )
    expected_session = _session(expected_generation, expected_pid, expected_port)
    expected_capability = _validated_capability(expected_capability)
    envelope = extract_security_headers(headers, RESPONSE_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise DesktopEngineSessionProtocolError("unsupported engine session version")
    observed_nonce, _ = _validated_hex(
        envelope[HEADER_RESPONSE_REQUEST_NONCE],
        "response request nonce",
        allow_zero=False,
    )
    observed_session = _session(
        _parsed_positive(envelope[HEADER_GENERATION], "engine session generation"),
        _parsed_positive(envelope[HEADER_PID], "engine session pid"),
        _parsed_port(envelope[HEADER_PORT]),
    )
    observed_capability = _validated_capability(envelope[HEADER_CAPABILITY])
    claimed_digest, _ = _validated_hex(
        envelope[HEADER_RESPONSE_BODY_SHA256], "response body digest"
    )
    claimed_contract, _ = _validated_hex(
        envelope[HEADER_RESPONSE_CONTRACT_SHA256], "response contract digest"
    )
    claimed_signature, _ = _validated_hex(
        envelope[HEADER_RESPONSE_SIGNATURE], "response signature"
    )
    actual_digest = _response_digest(body=body, body_sha256=body_sha256)
    actual_contract = response_contract_sha256(headers)
    expected_signature = hmac.new(
        derive_session_key(boot_token),
        response_mac_input(
            request_nonce=observed_nonce,
            generation=observed_session.generation,
            pid=observed_session.pid,
            port=observed_session.port,
            capability=observed_capability,
            status=status,
            body_sha256=actual_digest,
            contract_sha256=actual_contract,
        ),
        hashlib.sha256,
    ).hexdigest()
    if (
        not hmac.compare_digest(observed_nonce, expected_nonce)
        or observed_session != expected_session
        or observed_capability != expected_capability
        or not hmac.compare_digest(actual_digest, claimed_digest)
        or not hmac.compare_digest(actual_contract, claimed_contract)
        or not hmac.compare_digest(expected_signature, claimed_signature)
    ):
        raise DesktopEngineSessionAuthenticationError(
            "engine session response failed authentication"
        )
    return AuthenticatedResponse(
        request_nonce=observed_nonce,
        capability=observed_capability,
        status=status,
        body_sha256=actual_digest,
        contract_sha256=actual_contract,
        session=observed_session,
    )


__all__ = [
    "AuthenticatedRequest",
    "AuthenticatedResponse",
    "CHALLENGE_BODY",
    "CHALLENGE_PATH",
    "CHALLENGE_SCHEMA",
    "DEFAULT_MAX_FUTURE_MS",
    "DEFAULT_MAX_NONCES",
    "DEFAULT_MAX_PAST_MS",
    "DEFAULT_REPLAY_TTL_MS",
    "DesktopEngineSessionAuthenticationError",
    "DesktopEngineSessionCapacityError",
    "DesktopEngineSessionHeaderError",
    "DesktopEngineSessionProtocolError",
    "DesktopEngineSessionReplayError",
    "DesktopEngineSessionTimestampError",
    "DesktopEngineSessionTransportError",
    "EngineSessionIdentity",
    "HEADER_BODY_SHA256",
    "HEADER_CAPABILITY",
    "HEADER_CHANNEL_NONCE",
    "HEADER_GENERATION",
    "HEADER_NONCE",
    "HEADER_PID",
    "HEADER_PORT",
    "HEADER_PREFIX",
    "HEADER_RESPONSE_BODY_SHA256",
    "HEADER_RESPONSE_CONTRACT_SHA256",
    "HEADER_RESPONSE_REQUEST_NONCE",
    "HEADER_RESPONSE_SIGNATURE",
    "HEADER_REQUEST_CONTRACT_SHA256",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP_MS",
    "HEADER_VERSION",
    "NonceRegistry",
    "PROTOCOL_VERSION",
    "REQUEST_HEADER_NAMES",
    "RESPONSE_HEADER_NAMES",
    "SignedRequest",
    "SignedResponse",
    "derive_session_key",
    "extract_security_headers",
    "framed",
    "request_contract_sha256",
    "request_mac_input",
    "response_contract_sha256",
    "response_mac_input",
    "sign_request",
    "sign_response",
    "verify_request",
    "verify_response",
]
