"""Independent boot-session HMAC protocol for packaged paid-media routes.

The desktop must authenticate the exact engine generation/PID/port before it
sends a paid-media body.  This protocol never accepts the long-lived runtime,
paid-media, approval, bridge, or Installation Root credentials as substitutes.

HTTP adapters must pass raw, uncollapsed header pairs.  Security headers are a
closed set: duplicates, comma-combined values, unknown extensions, and headers
from the opposite direction are rejected.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import re
import secrets
import struct
import threading
import time
from typing import Any


PROTOCOL_VERSION = "1"
CHALLENGE_PATH = "/internal/v1/paid-media/session/challenge"
CHALLENGE_SCHEMA = "nachuan.paid-media.engine-session.challenge.v1"
CHALLENGE_BODY = (
    b'{"schema":"nachuan.paid-media.engine-session.challenge.v1","ok":true}'
)

HEADER_PREFIX = "x-nachuan-paid-session-"
HEADER_VERSION = "X-Nachuan-Paid-Session-Protocol"
HEADER_TIMESTAMP_MS = "X-Nachuan-Paid-Session-Timestamp-Ms"
HEADER_NONCE = "X-Nachuan-Paid-Session-Nonce"
HEADER_GENERATION = "X-Nachuan-Paid-Session-Generation"
HEADER_PID = "X-Nachuan-Paid-Session-Pid"
HEADER_PORT = "X-Nachuan-Paid-Session-Port"
HEADER_BODY_SHA256 = "X-Nachuan-Paid-Session-Body-SHA256"
HEADER_REQUEST_CONTRACT_SHA256 = (
    "X-Nachuan-Paid-Session-Request-Contract-SHA256"
)
HEADER_SIGNATURE = "X-Nachuan-Paid-Session-Signature"

HEADER_RESPONSE_REQUEST_NONCE = "X-Nachuan-Paid-Session-Request-Nonce"
HEADER_RESPONSE_BODY_SHA256 = "X-Nachuan-Paid-Session-Response-Body-SHA256"
HEADER_RESPONSE_CONTRACT_SHA256 = (
    "X-Nachuan-Paid-Session-Response-Contract-SHA256"
)
HEADER_RESPONSE_SIGNATURE = "X-Nachuan-Paid-Session-Response-Signature"

REQUEST_HEADER_NAMES = (
    HEADER_VERSION,
    HEADER_TIMESTAMP_MS,
    HEADER_NONCE,
    HEADER_GENERATION,
    HEADER_PID,
    HEADER_PORT,
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
    HEADER_RESPONSE_BODY_SHA256,
    HEADER_RESPONSE_CONTRACT_SHA256,
    HEADER_RESPONSE_SIGNATURE,
)

RESPONSE_CONTRACT_HEADER_NAMES = (
    "content-type",
    "content-length",
    "cache-control",
    "x-nachuan-paid-media-protocol",
    "idempotency-replayed",
    "retry-after",
    "x-content-sha256",
    "x-content-type-options",
    "content-encoding",
    "transfer-encoding",
    "content-range",
    "location",
    "trailer",
    "upgrade",
)

DEFAULT_MAX_PAST_MS = 30_000
DEFAULT_MAX_FUTURE_MS = 5_000
DEFAULT_REPLAY_TTL_MS = 35_001
DEFAULT_MAX_NONCES = 4_096

_MAX_CONFIGURED_WINDOW_MS = 5 * 60_000
_MAX_TIMESTAMP_MS = (1 << 63) - 1
_MAX_SAFE_INTEGER = (1 << 53) - 1
_KDF_DOMAIN = b"nachuan.paid-media.engine-session.key.v1"
_REQUEST_DOMAIN = b"nachuan.paid-media.engine-session.request.v1"
_REQUEST_CONTRACT_DOMAIN = (
    b"nachuan.paid-media.engine-session.request-contract.v1"
)
_RESPONSE_DOMAIN = b"nachuan.paid-media.engine-session.response.v1"
_CONTRACT_DOMAIN = b"nachuan.paid-media.engine-session.response-contract.v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]+$")
_TIMESTAMP = re.compile(r"^[1-9][0-9]{12,15}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")


class PaidMediaEngineSessionProtocolError(ValueError):
    """The independent paid-media engine-session envelope is invalid."""


class PaidMediaEngineSessionHeaderError(PaidMediaEngineSessionProtocolError):
    """A closed-set security/contract header was invalid or ambiguous."""


class PaidMediaEngineSessionAuthenticationError(
    PaidMediaEngineSessionProtocolError
):
    """A digest, HMAC, nonce binding, or exact session did not authenticate."""


class PaidMediaEngineSessionTimestampError(PaidMediaEngineSessionProtocolError):
    """The signed timestamp is outside the bounded acceptance window."""


class PaidMediaEngineSessionReplayError(PaidMediaEngineSessionProtocolError):
    """An authenticated request nonce was already consumed."""


class PaidMediaEngineSessionCapacityError(PaidMediaEngineSessionProtocolError):
    """The bounded replay authority cannot safely accept another nonce."""


class PaidMediaEngineSessionTransportError(PaidMediaEngineSessionProtocolError):
    """The request is not an exact query-free loopback transport."""


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
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class AuthenticatedRequest:
    timestamp_ms: int
    nonce: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class SignedResponse:
    headers: dict[str, str]
    request_nonce: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


@dataclass(frozen=True, slots=True)
class AuthenticatedResponse:
    request_nonce: str
    body_sha256: str
    contract_sha256: str
    session: EngineSessionIdentity


def _validated_hex(value: str, label: str) -> tuple[str, bytes]:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise PaidMediaEngineSessionProtocolError(f"invalid {label}")
    return value, bytes.fromhex(value)


def derive_session_key(boot_token: str) -> bytes:
    """Derive the one 32-byte paid-media session key from this boot token."""

    _, token = _validated_hex(boot_token, "engine boot token")
    return hmac.new(token, _KDF_DOMAIN, hashlib.sha256).digest()


def _u64(value: int, label: str, *, maximum: int = _MAX_TIMESTAMP_MS) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        raise PaidMediaEngineSessionProtocolError(f"invalid {label}")
    return struct.pack(">Q", value)


def _u32(value: int, label: str) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        raise PaidMediaEngineSessionProtocolError(f"invalid {label}")
    return struct.pack(">I", value)


def framed(domain: bytes, fields: Sequence[bytes]) -> bytes:
    """Encode the normative cross-language length-delimited frame."""

    if (
        not isinstance(domain, bytes)
        or not domain
        or len(domain) > 0xFFFFFFFF
        or len(fields) > 0xFFFFFFFF
    ):
        raise PaidMediaEngineSessionProtocolError("invalid signing frame")
    output = bytearray(struct.pack(">I", len(domain)))
    output.extend(domain)
    output.extend(struct.pack(">I", len(fields)))
    for field in fields:
        try:
            value = bytes(field)
        except (TypeError, ValueError) as exc:
            raise PaidMediaEngineSessionProtocolError(
                "invalid signing frame field"
            ) from exc
        output.extend(struct.pack(">Q", len(value)))
        output.extend(value)
    return bytes(output)


def _validated_timestamp(value: int) -> tuple[int, str]:
    raw = _u64(value, "paid-media timestamp")
    del raw
    text = str(value)
    if _TIMESTAMP.fullmatch(text) is None:
        raise PaidMediaEngineSessionProtocolError("invalid paid-media timestamp")
    return value, text


def _parsed_timestamp(value: str) -> int:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise PaidMediaEngineSessionProtocolError("invalid paid-media timestamp")
    observed = int(value)
    _u64(observed, "paid-media timestamp")
    return observed


def _validated_positive(value: int, label: str) -> tuple[int, str]:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_SAFE_INTEGER
    ):
        raise PaidMediaEngineSessionProtocolError(f"invalid {label}")
    return value, str(value)


def _parsed_positive(value: str, label: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise PaidMediaEngineSessionProtocolError(f"invalid {label}")
    observed = int(value)
    _validated_positive(observed, label)
    return observed


def _validated_port(value: int) -> tuple[int, str]:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1024 <= value <= 65535
    ):
        raise PaidMediaEngineSessionProtocolError("invalid paid-media session port")
    return value, str(value)


def _parsed_port(value: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise PaidMediaEngineSessionProtocolError("invalid paid-media session port")
    observed = int(value)
    _validated_port(observed)
    return observed


def _session(generation: int, pid: int, port: int) -> EngineSessionIdentity:
    generation, _ = _validated_positive(generation, "paid-media session generation")
    pid, _ = _validated_positive(pid, "paid-media session pid")
    port, _ = _validated_port(port)
    return EngineSessionIdentity(generation=generation, pid=pid, port=port)


def _validated_method(method: str) -> str:
    if not isinstance(method, str) or _METHOD.fullmatch(method) is None:
        raise PaidMediaEngineSessionProtocolError(
            "paid-media method must be uppercase ASCII"
        )
    return method


def _validated_target(target: str) -> str:
    if not isinstance(target, str):
        raise PaidMediaEngineSessionProtocolError("invalid paid-media target")
    try:
        encoded = target.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise PaidMediaEngineSessionProtocolError(
            "paid-media target must be exact ASCII origin-form"
        ) from exc
    if (
        not encoded
        or not encoded.startswith(b"/")
        or b"?" in encoded
        or b"#" in encoded
        or b"\\" in encoded
        or any(value < 0x20 or value == 0x7F for value in encoded)
    ):
        raise PaidMediaEngineSessionProtocolError(
            "paid-media target must be query-free ASCII origin-form"
        )
    return target


def request_mac_input(
    *,
    timestamp_ms: int,
    nonce: str,
    generation: int,
    pid: int,
    port: int,
    method: str,
    target: str,
    body_sha256: str,
    contract_sha256: str,
) -> bytes:
    timestamp_ms, _ = _validated_timestamp(timestamp_ms)
    nonce, nonce_bytes = _validated_hex(nonce, "paid-media request nonce")
    del nonce
    session = _session(generation, pid, port)
    method = _validated_method(method)
    target = _validated_target(target)
    _, body_digest = _validated_hex(body_sha256, "paid-media request body digest")
    _, contract_digest = _validated_hex(
        contract_sha256, "paid-media request contract digest"
    )
    return framed(
        _REQUEST_DOMAIN,
        (
            PROTOCOL_VERSION.encode("ascii"),
            _u64(timestamp_ms, "paid-media timestamp"),
            nonce_bytes,
            _u64(
                session.generation,
                "paid-media session generation",
                maximum=_MAX_SAFE_INTEGER,
            ),
            _u64(session.pid, "paid-media session pid", maximum=_MAX_SAFE_INTEGER),
            _u32(session.port, "paid-media session port"),
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
    status: int,
    body_sha256: str,
    contract_sha256: str,
) -> bytes:
    _, nonce_bytes = _validated_hex(request_nonce, "paid-media request nonce")
    session = _session(generation, pid, port)
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
    ):
        raise PaidMediaEngineSessionProtocolError("invalid paid-media HTTP status")
    _, body_digest = _validated_hex(body_sha256, "paid-media response body digest")
    _, contract_digest = _validated_hex(
        contract_sha256, "paid-media response contract digest"
    )
    return framed(
        _RESPONSE_DOMAIN,
        (
            PROTOCOL_VERSION.encode("ascii"),
            nonce_bytes,
            _u64(
                session.generation,
                "paid-media session generation",
                maximum=_MAX_SAFE_INTEGER,
            ),
            _u64(session.pid, "paid-media session pid", maximum=_MAX_SAFE_INTEGER),
            _u32(session.port, "paid-media session port"),
            _u32(status, "paid-media HTTP status"),
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
    if isinstance(headers, Iterable) and not isinstance(
        headers, (str, bytes, bytearray)
    ):
        pairs = []
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise PaidMediaEngineSessionHeaderError(
                    "invalid raw HTTP header sequence"
                )
            pairs.append((item[0], item[1]))
        return pairs
    raise PaidMediaEngineSessionHeaderError("raw HTTP headers are required")


def _header_text(value: Any, *, name: bool) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise PaidMediaEngineSessionHeaderError(
                "non-ASCII paid-media session header"
            ) from exc
    if not isinstance(value, str):
        raise PaidMediaEngineSessionHeaderError(
            "invalid paid-media session header"
        )
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise PaidMediaEngineSessionHeaderError(
            "non-ASCII paid-media session header"
        ) from exc
    if name and (not value or any(char.isspace() for char in value)):
        raise PaidMediaEngineSessionHeaderError(
            "invalid paid-media session header name"
        )
    return value


def _security_value(value: Any) -> str:
    text = _header_text(value, name=False)
    if (
        not text
        or text != text.strip()
        or "," in text
        or "\r" in text
        or "\n" in text
        or "\x00" in text
    ):
        raise PaidMediaEngineSessionHeaderError(
            "invalid or comma-combined paid-media session header"
        )
    return text


def extract_security_headers(
    headers: Any, required_names: Sequence[str]
) -> dict[str, str]:
    """Extract one direction's exact closed security-header set."""

    expected = {name.lower(): name for name in required_names}
    if len(expected) != len(required_names):
        raise PaidMediaEngineSessionProtocolError(
            "duplicate required paid-media header definition"
        )
    observed: dict[str, list[str]] = {name: [] for name in expected}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        if name.startswith(HEADER_PREFIX) and name not in expected:
            raise PaidMediaEngineSessionHeaderError(
                "unknown or direction-confused paid-media session header"
            )
        if name in expected:
            observed[name].append(_security_value(raw_value))
    result: dict[str, str] = {}
    for lower_name, canonical_name in expected.items():
        values = observed[lower_name]
        if len(values) != 1:
            raise PaidMediaEngineSessionHeaderError(
                f"missing or duplicate paid-media session header {canonical_name}"
            )
        result[canonical_name] = values[0]
    return result


def _request_contract_frame(
    headers: Any, *, allowed_session_names: frozenset[str]
) -> bytes:
    """Bind every ordinary request header in a sorted closed frame."""

    observed: dict[str, str] = {}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        if name.startswith(HEADER_PREFIX):
            if name not in allowed_session_names:
                raise PaidMediaEngineSessionHeaderError(
                    "unknown or direction-confused paid-media session header"
                )
            continue
        value = _header_text(raw_value, name=False)
        if (
            not value
            or value != value.strip()
            or "," in value
            or "\r" in value
            or "\n" in value
            or "\x00" in value
        ):
            raise PaidMediaEngineSessionHeaderError(
                f"invalid ordinary request header {name}"
            )
        if name in observed:
            raise PaidMediaEngineSessionHeaderError(
                f"duplicate ordinary request header {name}"
            )
        observed[name] = value
    fields: list[bytes] = []
    for name in sorted(observed):
        fields.extend((name.encode("ascii"), observed[name].encode("ascii")))
    return framed(_REQUEST_CONTRACT_DOMAIN, fields)


def request_contract_frame(headers: Any) -> bytes:
    """Canonicalize ordinary client headers before session fields are added."""

    return _request_contract_frame(headers, allowed_session_names=frozenset())


def request_contract_sha256(headers: Any) -> str:
    return hashlib.sha256(request_contract_frame(headers)).hexdigest()


def response_contract_frame(headers: Any) -> bytes:
    """Canonicalize the fixed 14-field response contract."""

    observed: dict[str, list[str]] = {
        name: [] for name in RESPONSE_CONTRACT_HEADER_NAMES
    }
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        if name in observed:
            value = _header_text(raw_value, name=False)
            if (
                not value
                or value != value.strip()
                or "," in value
                or "\r" in value
                or "\n" in value
                or "\x00" in value
            ):
                raise PaidMediaEngineSessionHeaderError(
                    f"invalid response contract header {name}"
                )
            observed[name].append(value)
    fields: list[bytes] = []
    for name in RESPONSE_CONTRACT_HEADER_NAMES:
        values = observed[name]
        if len(values) > 1:
            raise PaidMediaEngineSessionHeaderError(
                f"duplicate response contract header {name}"
            )
        fields.append(b"\x00" if not values else b"\x01" + values[0].encode("ascii"))
    return framed(_CONTRACT_DOMAIN, fields)


def response_contract_sha256(headers: Any) -> str:
    return hashlib.sha256(response_contract_frame(headers)).hexdigest()


class NonceRegistry:
    """Independent, thread-safe, TTL- and capacity-bounded replay authority."""

    __slots__ = ("_entries", "_lock", "_max_entries", "_max_ttl_ms")

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_NONCES,
        max_ttl_ms: int = DEFAULT_REPLAY_TTL_MS,
    ) -> None:
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or not 1 <= max_entries <= 1_000_000
        ):
            raise ValueError("max_entries must be between 1 and 1000000")
        if (
            isinstance(max_ttl_ms, bool)
            or not isinstance(max_ttl_ms, int)
            or not 1 <= max_ttl_ms <= _MAX_CONFIGURED_WINDOW_MS + 1
        ):
            raise ValueError("max_ttl_ms is outside the bounded replay range")
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._max_ttl_ms = max_ttl_ms

    @property
    def max_ttl_ms(self) -> int:
        return self._max_ttl_ms

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def _prune_locked(self, now_ms: int) -> None:
        expired = [
            nonce for nonce, expiry in self._entries.items() if expiry <= now_ms
        ]
        for nonce in expired:
            del self._entries[nonce]

    def prune(self, *, now_ms: int) -> int:
        _u64(now_ms, "paid-media nonce registry time")
        with self._lock:
            before = len(self._entries)
            self._prune_locked(now_ms)
            return before - len(self._entries)

    def consume(self, nonce: str, *, now_ms: int, expires_at_ms: int) -> None:
        _validated_hex(nonce, "paid-media request nonce")
        _u64(now_ms, "paid-media nonce registry time")
        _u64(expires_at_ms, "paid-media nonce expiry")
        if expires_at_ms <= now_ms or expires_at_ms - now_ms > self._max_ttl_ms:
            raise PaidMediaEngineSessionProtocolError(
                "paid-media nonce expiry is outside bounded TTL"
            )
        with self._lock:
            self._prune_locked(now_ms)
            if nonce in self._entries:
                raise PaidMediaEngineSessionReplayError(
                    "authenticated paid-media request nonce replay"
                )
            if len(self._entries) >= self._max_entries:
                raise PaidMediaEngineSessionCapacityError(
                    "paid-media nonce registry is full"
                )
            self._entries[nonce] = expires_at_ms


def sign_request(
    *,
    boot_token: str,
    generation: int,
    pid: int,
    port: int,
    method: str,
    target: str,
    contract_headers: Any,
    body: bytes = b"",
    timestamp_ms: int | None = None,
    nonce: str | None = None,
) -> SignedRequest:
    key = derive_session_key(boot_token)
    session = _session(generation, pid, port)
    payload = bytes(body)
    timestamp = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    timestamp, timestamp_text = _validated_timestamp(timestamp)
    request_nonce = secrets.token_hex(32) if nonce is None else nonce
    _validated_hex(request_nonce, "paid-media request nonce")
    digest = hashlib.sha256(payload).hexdigest()
    contract_digest = request_contract_sha256(contract_headers)
    signature = hmac.new(
        key,
        request_mac_input(
            timestamp_ms=timestamp,
            nonce=request_nonce,
            generation=session.generation,
            pid=session.pid,
            port=session.port,
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
            HEADER_TIMESTAMP_MS: timestamp_text,
            HEADER_NONCE: request_nonce,
            HEADER_GENERATION: str(session.generation),
            HEADER_PID: str(session.pid),
            HEADER_PORT: str(session.port),
            HEADER_BODY_SHA256: digest,
            HEADER_REQUEST_CONTRACT_SHA256: contract_digest,
            HEADER_SIGNATURE: signature,
        },
        timestamp_ms=timestamp,
        nonce=request_nonce,
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
        raise TypeError("nonce_registry must be a paid-media NonceRegistry")
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
        raise PaidMediaEngineSessionProtocolError(
            "invalid paid-media request time window"
        )
    expected_session = _session(expected_generation, expected_pid, expected_port)
    method = _validated_method(method)
    target = _validated_target(target)
    envelope = extract_security_headers(headers, REQUEST_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise PaidMediaEngineSessionProtocolError(
            "unsupported paid-media engine-session version"
        )
    timestamp = _parsed_timestamp(envelope[HEADER_TIMESTAMP_MS])
    request_nonce, _ = _validated_hex(
        envelope[HEADER_NONCE], "paid-media request nonce"
    )
    observed_session = _session(
        _parsed_positive(
            envelope[HEADER_GENERATION], "paid-media session generation"
        ),
        _parsed_positive(envelope[HEADER_PID], "paid-media session pid"),
        _parsed_port(envelope[HEADER_PORT]),
    )
    claimed_digest, _ = _validated_hex(
        envelope[HEADER_BODY_SHA256], "paid-media request body digest"
    )
    claimed_contract, _ = _validated_hex(
        envelope[HEADER_REQUEST_CONTRACT_SHA256],
        "paid-media request contract digest",
    )
    claimed_signature, _ = _validated_hex(
        envelope[HEADER_SIGNATURE], "paid-media request signature"
    )
    observed_now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    _u64(observed_now, "paid-media current time")
    if timestamp < observed_now - max_past_ms:
        raise PaidMediaEngineSessionTimestampError(
            "paid-media engine-session request has expired"
        )
    if timestamp > observed_now + max_future_ms:
        raise PaidMediaEngineSessionTimestampError(
            "paid-media engine-session request is too far in the future"
        )
    actual_digest = hashlib.sha256(bytes(body)).hexdigest()
    if not hmac.compare_digest(actual_digest, claimed_digest):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media request body digest mismatch"
        )
    actual_contract = hashlib.sha256(
        _request_contract_frame(
            headers,
            allowed_session_names=frozenset(
                name.lower() for name in REQUEST_HEADER_NAMES
            ),
        )
    ).hexdigest()
    if not hmac.compare_digest(actual_contract, claimed_contract):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media request contract digest mismatch"
        )
    expected_signature = hmac.new(
        derive_session_key(boot_token),
        request_mac_input(
            timestamp_ms=timestamp,
            nonce=request_nonce,
            generation=observed_session.generation,
            pid=observed_session.pid,
            port=observed_session.port,
            method=method,
            target=target,
            body_sha256=actual_digest,
            contract_sha256=actual_contract,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media request signature is invalid"
        )
    if observed_session != expected_session:
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media request session identity mismatch"
        )
    nonce_registry.consume(
        request_nonce,
        now_ms=observed_now,
        expires_at_ms=timestamp + max_past_ms + 1,
    )
    return AuthenticatedRequest(
        timestamp_ms=timestamp,
        nonce=request_nonce,
        body_sha256=actual_digest,
        contract_sha256=actual_contract,
        session=observed_session,
    )


def _response_digest(*, body: bytes | None, body_sha256: str | None) -> str:
    if (body is None) == (body_sha256 is None):
        raise PaidMediaEngineSessionProtocolError(
            "provide exactly one response body or response body digest"
        )
    if body_sha256 is not None:
        value, _ = _validated_hex(body_sha256, "paid-media response body digest")
        return value
    return hashlib.sha256(bytes(body)).hexdigest()


def sign_response(
    *,
    boot_token: str,
    request_nonce: str,
    generation: int,
    pid: int,
    port: int,
    status: int,
    contract_headers: Any,
    body: bytes | None = None,
    body_sha256: str | None = None,
) -> SignedResponse:
    key = derive_session_key(boot_token)
    _validated_hex(request_nonce, "paid-media request nonce")
    session = _session(generation, pid, port)
    digest = _response_digest(body=body, body_sha256=body_sha256)
    contract_digest = response_contract_sha256(contract_headers)
    signature = hmac.new(
        key,
        response_mac_input(
            request_nonce=request_nonce,
            generation=session.generation,
            pid=session.pid,
            port=session.port,
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
            HEADER_RESPONSE_BODY_SHA256: digest,
            HEADER_RESPONSE_CONTRACT_SHA256: contract_digest,
            HEADER_RESPONSE_SIGNATURE: signature,
        },
        request_nonce=request_nonce,
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
    status: int,
    headers: Any,
    body: bytes | None = None,
    body_sha256: str | None = None,
) -> AuthenticatedResponse:
    expected_nonce, _ = _validated_hex(request_nonce, "paid-media request nonce")
    expected_session = _session(expected_generation, expected_pid, expected_port)
    envelope = extract_security_headers(headers, RESPONSE_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise PaidMediaEngineSessionProtocolError(
            "unsupported paid-media engine-session version"
        )
    observed_nonce, _ = _validated_hex(
        envelope[HEADER_RESPONSE_REQUEST_NONCE], "paid-media response request nonce"
    )
    observed_session = _session(
        _parsed_positive(
            envelope[HEADER_GENERATION], "paid-media session generation"
        ),
        _parsed_positive(envelope[HEADER_PID], "paid-media session pid"),
        _parsed_port(envelope[HEADER_PORT]),
    )
    claimed_digest, _ = _validated_hex(
        envelope[HEADER_RESPONSE_BODY_SHA256], "paid-media response body digest"
    )
    claimed_contract, _ = _validated_hex(
        envelope[HEADER_RESPONSE_CONTRACT_SHA256],
        "paid-media response contract digest",
    )
    claimed_signature, _ = _validated_hex(
        envelope[HEADER_RESPONSE_SIGNATURE], "paid-media response signature"
    )
    actual_digest = _response_digest(body=body, body_sha256=body_sha256)
    actual_contract = response_contract_sha256(headers)
    if not hmac.compare_digest(observed_nonce, expected_nonce):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media response request nonce mismatch"
        )
    if observed_session != expected_session:
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media response session identity mismatch"
        )
    if not hmac.compare_digest(actual_digest, claimed_digest):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media response body digest mismatch"
        )
    if not hmac.compare_digest(actual_contract, claimed_contract):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media response contract digest mismatch"
        )
    expected_signature = hmac.new(
        derive_session_key(boot_token),
        response_mac_input(
            request_nonce=expected_nonce,
            generation=observed_session.generation,
            pid=observed_session.pid,
            port=observed_session.port,
            status=status,
            body_sha256=actual_digest,
            contract_sha256=actual_contract,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise PaidMediaEngineSessionAuthenticationError(
            "paid-media response signature is invalid"
        )
    return AuthenticatedResponse(
        request_nonce=expected_nonce,
        body_sha256=actual_digest,
        contract_sha256=actual_contract,
        session=observed_session,
    )


def validate_asgi_loopback_scope(
    scope: Mapping[str, Any], *, expected_port: int
) -> tuple[str, str]:
    """Validate the exact peer, server port, method, raw target, and no query."""

    expected_port, _ = _validated_port(expected_port)
    if not isinstance(scope, Mapping) or scope.get("type") != "http":
        raise PaidMediaEngineSessionTransportError(
            "paid-media session requires an HTTP ASGI scope"
        )
    client = scope.get("client")
    if not isinstance(client, (list, tuple)) or not client:
        raise PaidMediaEngineSessionTransportError(
            "paid-media session peer address is unavailable"
        )
    peer = client[0]
    if isinstance(peer, bytes):
        try:
            peer = peer.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise PaidMediaEngineSessionTransportError(
                "paid-media session peer is not loopback"
            ) from exc
    try:
        address = ipaddress.ip_address(str(peer))
    except ValueError as exc:
        raise PaidMediaEngineSessionTransportError(
            "paid-media session peer is not loopback"
        ) from exc
    if not address.is_loopback:
        raise PaidMediaEngineSessionTransportError(
            "paid-media session peer is not loopback"
        )
    server = scope.get("server")
    if (
        not isinstance(server, (list, tuple))
        or len(server) < 2
        or server[1] != expected_port
    ):
        raise PaidMediaEngineSessionTransportError(
            "paid-media session listener port mismatch"
        )
    query = scope.get("query_string", b"")
    if not isinstance(query, (bytes, bytearray)) or bytes(query):
        raise PaidMediaEngineSessionTransportError(
            "paid-media session query strings are forbidden"
        )
    raw_target = scope.get("raw_path")
    if not isinstance(raw_target, (bytes, bytearray)):
        raise PaidMediaEngineSessionTransportError(
            "paid-media session exact raw target is unavailable"
        )
    try:
        target = bytes(raw_target).decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise PaidMediaEngineSessionTransportError(
            "paid-media session raw target is not ASCII"
        ) from exc
    try:
        return _validated_method(scope.get("method")), _validated_target(target)
    except PaidMediaEngineSessionProtocolError as exc:
        raise PaidMediaEngineSessionTransportError(
            "paid-media session method or raw target is invalid"
        ) from exc


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
    "EngineSessionIdentity",
    "HEADER_BODY_SHA256",
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
    "PaidMediaEngineSessionAuthenticationError",
    "PaidMediaEngineSessionCapacityError",
    "PaidMediaEngineSessionHeaderError",
    "PaidMediaEngineSessionProtocolError",
    "PaidMediaEngineSessionReplayError",
    "PaidMediaEngineSessionTimestampError",
    "PaidMediaEngineSessionTransportError",
    "REQUEST_HEADER_NAMES",
    "RESPONSE_CONTRACT_HEADER_NAMES",
    "RESPONSE_HEADER_NAMES",
    "SignedRequest",
    "SignedResponse",
    "derive_session_key",
    "extract_security_headers",
    "framed",
    "request_mac_input",
    "request_contract_frame",
    "request_contract_sha256",
    "response_contract_frame",
    "response_contract_sha256",
    "response_mac_input",
    "sign_request",
    "sign_response",
    "validate_asgi_loopback_scope",
    "verify_request",
    "verify_response",
]
