"""HMAC envelope for the Installation Root's private loopback API.

The protocol deliberately does not use JSON canonicalisation and never sends
the boot token.  A boot token is exactly 32 random bytes represented by 64
lower-case hexadecimal characters; the decoded bytes are used only as the
HMAC-SHA256 key.

HTTP integration must pass the uncollapsed/raw header sequence to the verify
functions so duplicate security headers remain observable.  It must also call
``validate_asgi_loopback_scope`` before authentication: peer and query-string
policy are transport properties and therefore cannot be inferred from the
signed method/path/body tuple alone.
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

HEADER_VERSION = "X-Nachuan-Root-Protocol"
HEADER_TIMESTAMP_MS = "X-Nachuan-Root-Timestamp-Ms"
HEADER_NONCE = "X-Nachuan-Root-Nonce"
HEADER_BODY_SHA256 = "X-Nachuan-Root-Body-SHA256"
HEADER_SIGNATURE = "X-Nachuan-Root-Signature"

HEADER_RESPONSE_REQUEST_NONCE = "X-Nachuan-Root-Request-Nonce"
HEADER_RESPONSE_BODY_SHA256 = "X-Nachuan-Root-Response-Body-SHA256"
HEADER_RESPONSE_SIGNATURE = "X-Nachuan-Root-Response-Signature"

REQUEST_HEADER_NAMES = (
    HEADER_VERSION,
    HEADER_TIMESTAMP_MS,
    HEADER_NONCE,
    HEADER_BODY_SHA256,
    HEADER_SIGNATURE,
)
RESPONSE_HEADER_NAMES = (
    HEADER_VERSION,
    HEADER_RESPONSE_REQUEST_NONCE,
    HEADER_RESPONSE_BODY_SHA256,
    HEADER_RESPONSE_SIGNATURE,
)

DEFAULT_MAX_PAST_MS = 30_000
DEFAULT_MAX_FUTURE_MS = 5_000
DEFAULT_REPLAY_TTL_MS = DEFAULT_MAX_PAST_MS + DEFAULT_MAX_FUTURE_MS + 1
DEFAULT_MAX_NONCES = 4_096

_MAX_CONFIGURED_WINDOW_MS = 5 * 60_000
_MAX_TIMESTAMP_MS = (1 << 63) - 1
_REQUEST_DOMAIN = b"nachuan.installation-root.internal.request.v1"
_RESPONSE_DOMAIN = b"nachuan.installation-root.internal.response.v1"
_ROOT_HEADER_PREFIX = "x-nachuan-root-"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]+$")
_TIMESTAMP = re.compile(r"^[1-9][0-9]{12,15}$")


class InstallationRootProtocolError(ValueError):
    """The private Installation Root envelope is invalid."""


class DuplicateHeaderError(InstallationRootProtocolError):
    """A security header was absent or appeared more than once."""


class InstallationRootAuthenticationError(InstallationRootProtocolError):
    """The body digest or HMAC did not authenticate."""


class InstallationRootTimestampError(InstallationRootProtocolError):
    """The signed millisecond timestamp is outside the accepted window."""


class NonceReplayError(InstallationRootProtocolError):
    """An authenticated request nonce was already consumed."""


class NonceCapacityError(InstallationRootProtocolError):
    """The bounded nonce authority cannot safely accept another nonce."""


class LoopbackPolicyError(InstallationRootProtocolError):
    """The transport is not an exact, query-free loopback request."""


@dataclass(frozen=True, slots=True)
class SignedRequest:
    headers: dict[str, str]
    timestamp_ms: int
    nonce: str
    body_sha256: str


@dataclass(frozen=True, slots=True)
class AuthenticatedRequest:
    timestamp_ms: int
    nonce: str
    body_sha256: str


@dataclass(frozen=True, slots=True)
class SignedResponse:
    headers: dict[str, str]
    request_nonce: str
    body_sha256: str


@dataclass(frozen=True, slots=True)
class AuthenticatedResponse:
    request_nonce: str
    body_sha256: str


def generate_boot_token() -> str:
    """Return a 32-byte boot token in its only accepted wire/config form."""

    return secrets.token_hex(32)


def _boot_hmac_key(boot_token: str) -> bytes:
    if not isinstance(boot_token, str) or not _HEX_64.fullmatch(boot_token):
        raise InstallationRootProtocolError(
            "installation root boot token must be 32-byte lower-case hex"
        )
    return bytes.fromhex(boot_token)


def _u64(value: int, label: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InstallationRootProtocolError(f"invalid {label}")
    if value < 0 or value > _MAX_TIMESTAMP_MS:
        raise InstallationRootProtocolError(f"invalid {label}")
    return struct.pack(">Q", value)


def _u32(value: int, label: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InstallationRootProtocolError(f"invalid {label}")
    if value < 0 or value > 0xFFFFFFFF:
        raise InstallationRootProtocolError(f"invalid {label}")
    return struct.pack(">I", value)


def _framed(domain: bytes, fields: Sequence[bytes]) -> bytes:
    """Encode a cross-language message using only big-endian lengths.

    Layout: ``u32(domain_len) || domain || u32(field_count) ||`` followed by
    ``u64(field_len) || field`` for every field.  Numeric fields are themselves
    fixed-width big-endian byte strings before framing.
    """

    if not domain or len(domain) > 0xFFFFFFFF or len(fields) > 0xFFFFFFFF:
        raise InstallationRootProtocolError("invalid signing frame")
    output = bytearray(struct.pack(">I", len(domain)))
    output.extend(domain)
    output.extend(struct.pack(">I", len(fields)))
    for field in fields:
        value = bytes(field)
        output.extend(struct.pack(">Q", len(value)))
        output.extend(value)
    return bytes(output)


def _validated_method(method: str) -> str:
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise InstallationRootProtocolError(
            "installation root method must already be upper-case ASCII"
        )
    return method


def _validated_path(path: str) -> str:
    if not isinstance(path, str):
        raise InstallationRootProtocolError("invalid installation root path")
    try:
        encoded = path.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise InstallationRootProtocolError(
            "installation root path must be exact ASCII origin-form"
        ) from exc
    if (
        not encoded
        or not encoded.startswith(b"/")
        or b"?" in encoded
        or b"#" in encoded
        or b"\\" in encoded
        or any(value < 0x20 or value == 0x7F for value in encoded)
    ):
        raise InstallationRootProtocolError(
            "installation root path must be exact query-free origin-form"
        )
    return path


def _validated_hex_32(value: str, label: str) -> tuple[str, bytes]:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise InstallationRootProtocolError(f"invalid {label}")
    return value, bytes.fromhex(value)


def _validated_timestamp_text(value: str) -> int:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise InstallationRootProtocolError(
            "invalid installation root millisecond timestamp"
        )
    timestamp_ms = int(value)
    if timestamp_ms > _MAX_TIMESTAMP_MS:
        raise InstallationRootProtocolError(
            "invalid installation root millisecond timestamp"
        )
    return timestamp_ms


def request_mac_input(
    *,
    timestamp_ms: int,
    nonce: str,
    method: str,
    path: str,
    body_sha256: str,
) -> bytes:
    """Return the normative v1 request HMAC input."""

    normalized_method = _validated_method(method)
    normalized_path = _validated_path(path)
    _, nonce_bytes = _validated_hex_32(nonce, "installation root nonce")
    _, digest_bytes = _validated_hex_32(body_sha256, "request body digest")
    return _framed(
        _REQUEST_DOMAIN,
        (
            _u64(timestamp_ms, "installation root timestamp"),
            nonce_bytes,
            normalized_method.encode("ascii"),
            normalized_path.encode("ascii"),
            digest_bytes,
        ),
    )


def response_mac_input(
    *, request_nonce: str, status: int, body_sha256: str
) -> bytes:
    """Return the normative v1 response HMAC input."""

    _, nonce_bytes = _validated_hex_32(
        request_nonce, "installation root request nonce"
    )
    _, digest_bytes = _validated_hex_32(body_sha256, "response body digest")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise InstallationRootProtocolError("invalid installation root HTTP status")
    return _framed(
        _RESPONSE_DOMAIN,
        (nonce_bytes, _u32(status, "installation root HTTP status"), digest_bytes),
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
                raise InstallationRootProtocolError("invalid raw HTTP header sequence")
            pairs.append((item[0], item[1]))
        return pairs
    raise InstallationRootProtocolError("raw HTTP headers are required")


def _header_text(value: Any, *, name: bool) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise InstallationRootProtocolError("non-ASCII security header") from exc
    if not isinstance(value, str):
        raise InstallationRootProtocolError("invalid HTTP security header")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise InstallationRootProtocolError("non-ASCII security header") from exc
    if name and (not value or any(char.isspace() for char in value)):
        raise InstallationRootProtocolError("invalid HTTP security header name")
    return value


def extract_single_headers(
    headers: Any, required_names: Sequence[str]
) -> dict[str, str]:
    """Extract exact-once headers without case-sensitive duplicate bypasses.

    Header *names* remain case-insensitive as HTTP requires.  Required values
    are later checked in their single canonical casing/format.  Unknown
    ``X-Nachuan-Root-*`` fields are rejected so request and response envelopes
    cannot be confused or silently extended.
    """

    expected = {name.lower(): name for name in required_names}
    if len(expected) != len(required_names):
        raise InstallationRootProtocolError("duplicate required header definition")
    observed: dict[str, list[str]] = {name: [] for name in expected}
    for raw_name, raw_value in _header_pairs(headers):
        name = _header_text(raw_name, name=True).lower()
        if name.startswith(_ROOT_HEADER_PREFIX) and name not in expected:
            raise InstallationRootProtocolError(
                "unknown installation root security header"
            )
        if name in expected:
            observed[name].append(_header_text(raw_value, name=False))
    result: dict[str, str] = {}
    for lower_name, canonical_name in expected.items():
        values = observed[lower_name]
        if len(values) != 1:
            raise DuplicateHeaderError(
                f"missing or duplicate installation root header {canonical_name}"
            )
        result[canonical_name] = values[0]
    return result


class NonceRegistry:
    """Thread-safe, in-memory, TTL- and capacity-bounded replay authority."""

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
        expired = [nonce for nonce, expiry in self._entries.items() if expiry <= now_ms]
        for nonce in expired:
            del self._entries[nonce]

    def prune(self, *, now_ms: int) -> int:
        _u64(now_ms, "nonce registry time")
        with self._lock:
            before = len(self._entries)
            self._prune_locked(now_ms)
            return before - len(self._entries)

    def consume(self, nonce: str, *, now_ms: int, expires_at_ms: int) -> None:
        """Atomically consume one already-authenticated nonce."""

        _validated_hex_32(nonce, "installation root nonce")
        _u64(now_ms, "nonce registry time")
        _u64(expires_at_ms, "nonce expiry")
        if expires_at_ms <= now_ms or expires_at_ms - now_ms > self._max_ttl_ms:
            raise InstallationRootProtocolError("nonce expiry is outside bounded TTL")
        with self._lock:
            self._prune_locked(now_ms)
            if nonce in self._entries:
                raise NonceReplayError("authenticated installation root nonce replay")
            if len(self._entries) >= self._max_entries:
                raise NonceCapacityError("installation root nonce registry is full")
            self._entries[nonce] = expires_at_ms


def sign_request(
    *,
    boot_token: str,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp_ms: int | None = None,
    nonce: str | None = None,
) -> SignedRequest:
    """Create a request envelope; the token itself is never returned."""

    key = _boot_hmac_key(boot_token)
    payload = bytes(body)
    observed_timestamp = (
        time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    )
    timestamp_text = str(observed_timestamp)
    _validated_timestamp_text(timestamp_text)
    request_nonce = secrets.token_hex(32) if nonce is None else nonce
    _validated_hex_32(request_nonce, "installation root nonce")
    digest = hashlib.sha256(payload).hexdigest()
    signature = hmac.new(
        key,
        request_mac_input(
            timestamp_ms=observed_timestamp,
            nonce=request_nonce,
            method=method,
            path=path,
            body_sha256=digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    return SignedRequest(
        headers={
            HEADER_VERSION: PROTOCOL_VERSION,
            HEADER_TIMESTAMP_MS: timestamp_text,
            HEADER_NONCE: request_nonce,
            HEADER_BODY_SHA256: digest,
            HEADER_SIGNATURE: signature,
        },
        timestamp_ms=observed_timestamp,
        nonce=request_nonce,
        body_sha256=digest,
    )


def verify_request(
    *,
    boot_token: str,
    method: str,
    path: str,
    headers: Any,
    body: bytes,
    nonce_registry: NonceRegistry,
    now_ms: int | None = None,
    max_past_ms: int = DEFAULT_MAX_PAST_MS,
    max_future_ms: int = DEFAULT_MAX_FUTURE_MS,
) -> AuthenticatedRequest:
    """Authenticate and atomically consume one private API request."""

    if not isinstance(nonce_registry, NonceRegistry):
        raise TypeError("nonce_registry must be a NonceRegistry")
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
        raise InstallationRootProtocolError("invalid installation root time window")
    normalized_method = _validated_method(method)
    normalized_path = _validated_path(path)
    envelope = extract_single_headers(headers, REQUEST_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise InstallationRootProtocolError(
            "unsupported installation root protocol version"
        )
    timestamp_ms = _validated_timestamp_text(envelope[HEADER_TIMESTAMP_MS])
    request_nonce, _ = _validated_hex_32(
        envelope[HEADER_NONCE], "installation root nonce"
    )
    claimed_digest, _ = _validated_hex_32(
        envelope[HEADER_BODY_SHA256], "request body digest"
    )
    claimed_signature, _ = _validated_hex_32(
        envelope[HEADER_SIGNATURE], "request signature"
    )
    observed_now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    _u64(observed_now, "installation root current time")
    if timestamp_ms < observed_now - max_past_ms:
        raise InstallationRootTimestampError("installation root request has expired")
    if timestamp_ms > observed_now + max_future_ms:
        raise InstallationRootTimestampError(
            "installation root request is too far in the future"
        )
    actual_digest = hashlib.sha256(bytes(body)).hexdigest()
    if not hmac.compare_digest(actual_digest, claimed_digest):
        raise InstallationRootAuthenticationError(
            "installation root request body digest mismatch"
        )
    expected_signature = hmac.new(
        _boot_hmac_key(boot_token),
        request_mac_input(
            timestamp_ms=timestamp_ms,
            nonce=request_nonce,
            method=normalized_method,
            path=normalized_path,
            body_sha256=actual_digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise InstallationRootAuthenticationError(
            "installation root request signature is invalid"
        )

    # Consumption is deliberately last: malformed or unauthenticated traffic
    # cannot burn a nonce.  The lock makes concurrent identical requests have
    # exactly one winner.
    nonce_registry.consume(
        request_nonce,
        now_ms=observed_now,
        expires_at_ms=timestamp_ms + max_past_ms + 1,
    )
    return AuthenticatedRequest(
        timestamp_ms=timestamp_ms,
        nonce=request_nonce,
        body_sha256=actual_digest,
    )


def sign_response(
    *,
    boot_token: str,
    request_nonce: str,
    status: int,
    body: bytes = b"",
) -> SignedResponse:
    """Create the separately domain-bound response envelope."""

    key = _boot_hmac_key(boot_token)
    payload = bytes(body)
    digest = hashlib.sha256(payload).hexdigest()
    signature = hmac.new(
        key,
        response_mac_input(
            request_nonce=request_nonce, status=status, body_sha256=digest
        ),
        hashlib.sha256,
    ).hexdigest()
    return SignedResponse(
        headers={
            HEADER_VERSION: PROTOCOL_VERSION,
            HEADER_RESPONSE_REQUEST_NONCE: request_nonce,
            HEADER_RESPONSE_BODY_SHA256: digest,
            HEADER_RESPONSE_SIGNATURE: signature,
        },
        request_nonce=request_nonce,
        body_sha256=digest,
    )


def verify_response(
    *,
    boot_token: str,
    request_nonce: str,
    status: int,
    headers: Any,
    body: bytes,
) -> AuthenticatedResponse:
    """Authenticate a response against its exact request nonce/status/body."""

    expected_nonce, _ = _validated_hex_32(
        request_nonce, "installation root request nonce"
    )
    envelope = extract_single_headers(headers, RESPONSE_HEADER_NAMES)
    if envelope[HEADER_VERSION] != PROTOCOL_VERSION:
        raise InstallationRootProtocolError(
            "unsupported installation root protocol version"
        )
    response_nonce, _ = _validated_hex_32(
        envelope[HEADER_RESPONSE_REQUEST_NONCE],
        "installation root response request nonce",
    )
    claimed_digest, _ = _validated_hex_32(
        envelope[HEADER_RESPONSE_BODY_SHA256], "response body digest"
    )
    claimed_signature, _ = _validated_hex_32(
        envelope[HEADER_RESPONSE_SIGNATURE], "response signature"
    )
    if not hmac.compare_digest(response_nonce, expected_nonce):
        raise InstallationRootAuthenticationError(
            "installation root response request nonce mismatch"
        )
    actual_digest = hashlib.sha256(bytes(body)).hexdigest()
    if not hmac.compare_digest(actual_digest, claimed_digest):
        raise InstallationRootAuthenticationError(
            "installation root response body digest mismatch"
        )
    expected_signature = hmac.new(
        _boot_hmac_key(boot_token),
        response_mac_input(
            request_nonce=expected_nonce,
            status=status,
            body_sha256=actual_digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise InstallationRootAuthenticationError(
            "installation root response signature is invalid"
        )
    return AuthenticatedResponse(
        request_nonce=expected_nonce,
        body_sha256=actual_digest,
    )


def validate_asgi_loopback_scope(
    scope: Mapping[str, Any], *, allowed_paths: Iterable[str] | None = None
) -> tuple[str, str]:
    """Return the exact signed method/path after transport policy validation.

    Only the actual TCP peer is trusted; ``Host: localhost`` is intentionally
    irrelevant.  ``raw_path`` is mandatory so percent-encoding cannot be
    reconstructed differently by Python and TypeScript.
    """

    if not isinstance(scope, Mapping) or scope.get("type") != "http":
        raise LoopbackPolicyError("installation root requires an HTTP ASGI scope")
    client = scope.get("client")
    if not isinstance(client, (list, tuple)) or not client:
        raise LoopbackPolicyError("installation root peer address is unavailable")
    peer = client[0]
    if isinstance(peer, bytes):
        try:
            peer = peer.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise LoopbackPolicyError("installation root peer is not loopback") from exc
    try:
        address = ipaddress.ip_address(str(peer))
    except ValueError as exc:
        raise LoopbackPolicyError("installation root peer is not loopback") from exc
    if not address.is_loopback:
        raise LoopbackPolicyError("installation root peer is not loopback")
    query = scope.get("query_string", b"")
    if not isinstance(query, (bytes, bytearray)) or bytes(query):
        raise LoopbackPolicyError("installation root query strings are forbidden")
    raw_path = scope.get("raw_path")
    if not isinstance(raw_path, (bytes, bytearray)):
        raise LoopbackPolicyError("installation root exact raw path is unavailable")
    try:
        path = bytes(raw_path).decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise LoopbackPolicyError("installation root raw path is not ASCII") from exc
    method = _validated_method(scope.get("method"))
    path = _validated_path(path)
    if allowed_paths is not None:
        allowed = {_validated_path(candidate) for candidate in allowed_paths}
        if path not in allowed:
            raise LoopbackPolicyError("installation root path is not allowed")
    return method, path


__all__ = [
    "AuthenticatedRequest",
    "AuthenticatedResponse",
    "DEFAULT_MAX_FUTURE_MS",
    "DEFAULT_MAX_NONCES",
    "DEFAULT_MAX_PAST_MS",
    "DEFAULT_REPLAY_TTL_MS",
    "DuplicateHeaderError",
    "HEADER_BODY_SHA256",
    "HEADER_NONCE",
    "HEADER_RESPONSE_BODY_SHA256",
    "HEADER_RESPONSE_REQUEST_NONCE",
    "HEADER_RESPONSE_SIGNATURE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP_MS",
    "HEADER_VERSION",
    "InstallationRootAuthenticationError",
    "InstallationRootProtocolError",
    "InstallationRootTimestampError",
    "LoopbackPolicyError",
    "NonceCapacityError",
    "NonceRegistry",
    "NonceReplayError",
    "PROTOCOL_VERSION",
    "REQUEST_HEADER_NAMES",
    "RESPONSE_HEADER_NAMES",
    "SignedRequest",
    "SignedResponse",
    "extract_single_headers",
    "generate_boot_token",
    "request_mac_input",
    "response_mac_input",
    "sign_request",
    "sign_response",
    "validate_asgi_loopback_scope",
    "verify_request",
    "verify_response",
]
