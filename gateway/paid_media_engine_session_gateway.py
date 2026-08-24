"""Raw-ASGI paid-media engine-session authentication/signing boundary.

This module is deliberately not an authorization fallback.  It accepts only a
boot-scoped authority bound to the exact generation, process PID and listener
port, authenticates raw request bytes before delegation, and signs the complete
response contract.  The public application must keep its packaged paid-media
gate closed until the desktop protocol and this wrapper are integrated together.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import os
import re
import threading
from typing import Any, Callable, Mapping

from gateway.paid_media_engine_session_protocol import (
    CHALLENGE_BODY,
    CHALLENGE_PATH,
    HEADER_PREFIX,
    NonceRegistry,
    PaidMediaEngineSessionProtocolError,
    SignedResponse,
    sign_response,
    validate_asgi_loopback_scope,
    verify_request,
)


SESSION_STATE_KEY = "nachuan_paid_media_engine_session"

_BOOT_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_IMAGE_BODY = 1 * 1024 * 1024
_MAX_ACK_BODY = 1 * 1024 * 1024
_MAX_VIDEO_BODY = 32 * 1024 * 1024
_MAX_PROBE_BODY = 32 * 1024 * 1024
_MAX_STAGE_READY_BODY = 512
_MAX_BUFFERED_RESPONSE = 2 * 1024 * 1024
_MAX_STREAM_ASSET_BYTES = 24 * 1024 * 1024
_SECURITY_PREFIX = HEADER_PREFIX.encode("ascii")
_LEGACY_SECRET_HEADERS = frozenset(
    {b"authorization", b"x-nachuan-paid-media-key"}
)

_CHALLENGE_RAW = CHALLENGE_PATH.encode("ascii")
_SESSION_PREFIX = b"/internal/v1/paid-media/session"
STAGE_READY_PATH = "/internal/v1/paid-media/session/stage-ready"
_STAGE_READY_RAW = STAGE_READY_PATH.encode("ascii")
_STAGE_READY_SCHEMA = "nachuan.paid-media.engine-session.stage-ready.v1"
_STAGE_READY_RECEIPT_SCHEMA = (
    "nachuan.paid-media.engine-session.stage-ready.receipt.v1"
)
_IMAGE_CREATE = b"/v1/images/generations"
_VIDEO_CREATE = b"/v1/videos/generations"
_VIDEO_PREFIX = b"/v1/videos/"
_VIDEO_FETCH = b"/v1/videos/fetch"
_PAID_ROOT = b"/v1/paid-media"
_PAID_PREFIX = b"/v1/paid-media/"
_ASSET_PREFIX = b"/v1/paid-media/assets/"
_ASSET_ACK = b"/v1/paid-media/assets/ack"
_PROBE = b"/v1/paid-media/probe"
_PROBE_READINESS = b"/v1/paid-media/probe/readiness"

_CHALLENGE_HEADERS = [
    (b"content-type", b"application/json"),
    (b"content-length", str(len(CHALLENGE_BODY)).encode("ascii")),
    (b"cache-control", b"no-store"),
    (b"connection", b"keep-alive"),
]


def _error_body(code: str) -> bytes:
    return json.dumps(
        {
            "schema": "nachuan.paid-media.engine-session.error.v1",
            "code": code,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


_UNAVAILABLE_BODY = _error_body("session_unavailable")
_AUTHENTICATION_BODY = _error_body("authentication_failed")
_INVALID_REQUEST_BODY = _error_body("invalid_request")
_PAYLOAD_TOO_LARGE_BODY = _error_body("payload_too_large")
_SESSION_CHANGED_BODY = _error_body("session_changed")
_DOWNSTREAM_BODY = _error_body("downstream_response_invalid")
_DESKTOP_V2_STAGE_BODY = _error_body(
    "desktop-v2-stage-authority-unavailable"
)
_INSTALLATION_AUTHORITY_BODY = _error_body(
    "installation_authority_unavailable"
)
_STAGE_BINDING_CONFLICT_BODY = _error_body("stage_binding_conflict")


@dataclass(frozen=True, slots=True)
class _AuthorityIdentity:
    generation: int
    pid: int
    port: int


@dataclass(frozen=True, slots=True)
class _StageBinding:
    installation_principal: str
    vault_evidence_sha256: str


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


def _parse_positive(value: object, *, maximum: int, label: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL_RE.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    parsed = int(value)
    if not 1 <= parsed <= maximum:
        raise ValueError(f"invalid {label}")
    return parsed


def _raw_path(scope: Mapping[str, Any]) -> bytes | None:
    value = scope.get("raw_path")
    return value if type(value) is bytes else None


def _has_segment_prefix(value: object, prefix: bytes | str) -> bool:
    if isinstance(prefix, bytes):
        return type(value) is bytes and (
            value == prefix or value.startswith(prefix + b"/")
        )
    return isinstance(value, str) and (
        value == prefix or value.startswith(prefix + "/")
    )


def _is_paid_target(raw_path: bytes) -> bool:
    if _has_segment_prefix(raw_path, _IMAGE_CREATE) or _has_segment_prefix(
        raw_path, _VIDEO_CREATE
    ):
        return True
    if raw_path.startswith(_VIDEO_PREFIX) and raw_path != _VIDEO_FETCH:
        return True
    return _has_segment_prefix(raw_path, _PAID_ROOT)


def _is_paid_decoded_target(path: object) -> bool:
    if not isinstance(path, str):
        return False
    if _has_segment_prefix(path, _IMAGE_CREATE.decode("ascii")) or _has_segment_prefix(
        path, _VIDEO_CREATE.decode("ascii")
    ):
        return True
    if path.startswith(_VIDEO_PREFIX.decode("ascii")) and path != _VIDEO_FETCH.decode(
        "ascii"
    ):
        return True
    return _has_segment_prefix(path, _PAID_ROOT.decode("ascii"))


def _body_limit(raw_path: bytes, method: str) -> int:
    if method == "GET":
        return 0
    if raw_path == _IMAGE_CREATE or raw_path == _ASSET_ACK:
        return _MAX_IMAGE_BODY if raw_path == _IMAGE_CREATE else _MAX_ACK_BODY
    if raw_path == _VIDEO_CREATE:
        return _MAX_VIDEO_BODY
    if raw_path == _PROBE:
        return _MAX_PROBE_BODY
    if raw_path == _STAGE_READY_RAW:
        return _MAX_STAGE_READY_BODY
    return _MAX_IMAGE_BODY


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate stage-ready JSON field")
        result[name] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite stage-ready JSON number")


def _parse_stage_ready_body(
    body: bytes, *, authority: _Authority
) -> _StageBinding:
    try:
        decoded = body.decode("ascii", "strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid stage-ready JSON") from exc
    if type(value) is not dict or list(value) != [
        "schema",
        "generation",
        "pid",
        "port",
        "installationPrincipal",
        "vaultEvidenceSha256",
    ]:
        raise ValueError("invalid stage-ready schema")
    identity = authority.identity
    principal = value.get("installationPrincipal")
    vault_digest = value.get("vaultEvidenceSha256")
    if (
        value.get("schema") != _STAGE_READY_SCHEMA
        or type(value.get("generation")) is not int
        or value["generation"] != identity.generation
        or type(value.get("pid")) is not int
        or value["pid"] != identity.pid
        or type(value.get("port")) is not int
        or value["port"] != identity.port
        or not isinstance(principal, str)
        or _BOOT_TOKEN_RE.fullmatch(principal) is None
        or principal == "0" * 64
        or not isinstance(vault_digest, str)
        or _BOOT_TOKEN_RE.fullmatch(vault_digest) is None
        or vault_digest == "0" * 64
    ):
        raise ValueError("invalid stage-ready binding")
    canonical = json.dumps(
        {
            "schema": _STAGE_READY_SCHEMA,
            "generation": identity.generation,
            "pid": identity.pid,
            "port": identity.port,
            "installationPrincipal": principal,
            "vaultEvidenceSha256": vault_digest,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    if not hmac.compare_digest(body, canonical):
        raise ValueError("non-canonical stage-ready JSON")
    return _StageBinding(
        installation_principal=principal,
        vault_evidence_sha256=vault_digest,
    )


def _stage_ready_receipt(binding: _StageBinding) -> bytes:
    return json.dumps(
        {
            "schema": _STAGE_READY_RECEIPT_SCHEMA,
            "ok": True,
            "vaultEvidenceSha256": binding.vault_evidence_sha256,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


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
        ):
            raise ValueError("raw ASGI headers are invalid")
        output.append((item[0], item[1]))
    return output


def _contains_legacy_secret(headers: list[tuple[bytes, bytes]]) -> bool:
    for name, _value in headers:
        try:
            normalized = name.decode("ascii", "strict").lower().encode("ascii")
        except UnicodeDecodeError:
            continue
        if normalized in _LEGACY_SECRET_HEADERS:
            return True
    return False


def _ordinary_value(
    headers: list[tuple[bytes, bytes]], name: bytes
) -> bytes | None:
    values = [
        value
        for observed, value in headers
        if observed.decode("ascii", "strict").lower().encode("ascii") == name
    ]
    if len(values) > 1:
        raise ValueError("duplicate ordinary request header")
    return values[0] if values else None


def _validate_signed_request_headers(
    headers: list[tuple[bytes, bytes]],
    *,
    authority: _Authority,
    body: bytes,
    challenge: bool,
) -> None:
    if _ordinary_value(headers, b"host") != (
        f"127.0.0.1:{authority.identity.port}".encode("ascii")
    ):
        raise ValueError("paid-media request Host is not the exact listener")
    if _ordinary_value(headers, b"connection") != b"keep-alive":
        raise ValueError("paid-media request must keep the challenged socket alive")
    if _ordinary_value(headers, b"content-length") != str(len(body)).encode("ascii"):
        raise ValueError("paid-media request Content-Length is not exact")
    if _ordinary_value(headers, b"transfer-encoding") is not None:
        raise ValueError("paid-media session rejects transfer-encoding")
    if _ordinary_value(headers, b"content-encoding") is not None:
        raise ValueError("paid-media session rejects content-encoding")
    if challenge:
        return
    if _ordinary_value(headers, b"x-nachuan-paid-media-protocol") != b"2":
        raise ValueError("paid-media asset protocol v2 is required")
    if _ordinary_value(headers, b"cache-control") != b"no-store":
        raise ValueError("paid-media request must be no-store")
    if _ordinary_value(headers, b"accept-encoding") != b"identity":
        raise ValueError("paid-media response encoding must remain identity")


async def _read_body(receive: Any, *, limit: int) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if not isinstance(message, Mapping):
            raise ValueError("invalid ASGI request message")
        kind = message.get("type")
        if kind == "http.disconnect":
            raise ConnectionError("client disconnected")
        if kind != "http.request":
            raise ValueError("invalid ASGI request message")
        chunk = message.get("body", b"")
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("invalid ASGI request body")
        body.extend(chunk)
        if len(body) > limit:
            raise OverflowError("paid-media session body limit exceeded")
        if not bool(message.get("more_body", False)):
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


def _response_headers(message: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
    headers = message.get("headers", [])
    if not isinstance(headers, (list, tuple)):
        raise ValueError("invalid ASGI response headers")
    output: list[tuple[bytes, bytes]] = []
    for item in headers:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
        ):
            raise ValueError("invalid ASGI response headers")
        try:
            name = item[0].decode("ascii", "strict").lower().encode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII ASGI response header") from exc
        if name.startswith(_SECURITY_PREFIX):
            raise ValueError("downstream emitted a reserved session header")
        output.append((name, item[1]))
    return output


def _single_header(
    headers: list[tuple[bytes, bytes]], name: bytes
) -> bytes | None:
    values = [value for observed, value in headers if observed == name]
    if len(values) > 1:
        raise ValueError("duplicate signed response header")
    return values[0] if values else None


def _normalize_buffered_headers(
    headers: list[tuple[bytes, bytes]], body: bytes
) -> list[tuple[bytes, bytes]]:
    if _single_header(headers, b"transfer-encoding") is not None:
        raise ValueError("buffered paid-media response cannot set transfer-encoding")
    existing_length = _single_header(headers, b"content-length")
    if existing_length is not None:
        try:
            if int(existing_length.decode("ascii", "strict")) != len(body):
                raise ValueError("paid-media response content length mismatch")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid paid-media response content length") from exc
    cache_control = _single_header(headers, b"cache-control")
    if cache_control not in {None, b"no-store"}:
        raise ValueError("paid-media response must be no-store")
    normalized = [
        item
        for item in headers
        if item[0] not in {b"content-length", b"cache-control"}
    ]
    normalized.extend(
        [
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
    )
    return normalized


def _validate_streaming_headers(
    headers: list[tuple[bytes, bytes]],
) -> tuple[str, int]:
    descriptor = _single_header(headers, b"x-content-sha256")
    try:
        digest = descriptor.decode("ascii", "strict") if descriptor is not None else ""
    except UnicodeDecodeError as exc:
        raise ValueError("invalid streaming asset digest") from exc
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid streaming asset digest")

    content_length = _single_header(headers, b"content-length")
    if content_length is None or re.fullmatch(rb"[1-9][0-9]*", content_length) is None:
        raise ValueError("streaming asset lacks canonical content length")
    expected_length = int(content_length)
    if expected_length > _MAX_STREAM_ASSET_BYTES:
        raise ValueError("streaming asset exceeds the protocol byte limit")

    if not _single_header(headers, b"content-type"):
        raise ValueError("streaming asset lacks content type")
    if _single_header(headers, b"cache-control") != b"no-store":
        raise ValueError("streaming asset must be no-store")
    if _single_header(headers, b"x-nachuan-paid-media-protocol") != b"2":
        raise ValueError("streaming asset protocol is not v2")
    if _single_header(headers, b"x-content-type-options") != b"nosniff":
        raise ValueError("streaming asset must disable content sniffing")
    if _single_header(headers, b"content-encoding") is not None:
        raise ValueError("streaming asset cannot use content encoding")
    if _single_header(headers, b"transfer-encoding") is not None:
        raise ValueError("streaming asset cannot use transfer encoding")
    return digest, expected_length


def _signature_headers(signed: SignedResponse) -> list[tuple[bytes, bytes]]:
    return [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in signed.headers.items()
    ]


async def _send_unsigned_error(
    send: Any, *, status: int, body: bytes, close: bool = True
) -> None:
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if close:
        headers.append((b"connection", b"close"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class PaidMediaEngineSessionGatewayApp:
    """Authenticate/sign protected paid-media requests outside FastAPI."""

    def __init__(
        self,
        downstream: Any,
        *,
        configured_port: int,
        environ: Mapping[str, str] | None = None,
        pid_provider: Callable[[], int] = os.getpid,
        nonce_registry: NonceRegistry | None = None,
        installation_principal_supplier: Callable[[], str | None] | None = None,
        hide_auth_failures: bool = False,
    ) -> None:
        self._downstream = downstream
        self._configured_port = configured_port
        self._environ = os.environ if environ is None else environ
        self._pid_provider = pid_provider
        self._nonce_registry = nonce_registry or NonceRegistry()
        self._installation_principal_supplier = (
            installation_principal_supplier
            if installation_principal_supplier is not None
            else lambda: None
        )
        self._stage_lock = threading.Lock()
        self._stage_binding: _StageBinding | None = None
        self._stage_fused = False
        self._active_states: dict[int, dict[str, object]] = {}
        self._active_states_lock = threading.Lock()
        self._hide_auth_failures = bool(hide_auth_failures)
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

    @property
    def stage_ready(self) -> bool:
        with self._stage_lock:
            if self._stage_fused or self._stage_binding is None:
                return False
            try:
                current = self._read_installation_principal()
            except Exception:  # noqa: BLE001 -- authority reads fail closed
                self._stage_fused = True
                return False
            if not hmac.compare_digest(
                current, self._stage_binding.installation_principal
            ):
                self._stage_fused = True
                return False
            return True

    @property
    def stage_vault_evidence_sha256(self) -> str | None:
        if not self.stage_ready:
            return None
        with self._stage_lock:
            return (
                None
                if self._stage_binding is None
                else self._stage_binding.vault_evidence_sha256
            )

    @property
    def new_operations_ready(self) -> bool:
        return self.ready and self.stage_ready

    def accepts_authenticated_state(self, value: object) -> bool:
        """Accept only the exact state object active in this wrapper call.

        The mapping deliberately contains no secret.  Object identity is kept
        in a verifier-local registry only while the authenticated downstream
        request is executing, so copying the same public fields into a direct
        FastAPI invocation cannot bypass the raw-ASGI boundary.
        """

        try:
            authority = self._current_authority()
        except (TypeError, ValueError):
            return False
        if not self.stage_ready:
            return False
        if type(value) is not dict:
            return False
        with self._active_states_lock:
            if self._active_states.get(id(value)) is not value:
                return False
        identity = authority.identity
        return (
            set(value) == {"authenticated", "nonce", "generation", "pid", "port"}
            and value.get("authenticated") is True
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
                raise RuntimeError("Paid-media engine session state is already active")
            self._active_states[key] = value

    def _unregister_authenticated_state(self, value: dict[str, object]) -> None:
        with self._active_states_lock:
            key = id(value)
            if self._active_states.get(key) is value:
                del self._active_states[key]

    def _read_installation_principal(self) -> str:
        principal = self._installation_principal_supplier()
        if (
            not isinstance(principal, str)
            or _BOOT_TOKEN_RE.fullmatch(principal) is None
            or principal == "0" * 64
        ):
            raise ValueError("Installation Root principal is unavailable")
        return principal

    def _latch_stage_binding(
        self, authority: _Authority, binding: _StageBinding
    ) -> str:
        try:
            observed = self._read_installation_principal()
        except Exception:  # noqa: BLE001 -- external authority fails closed
            return "unavailable"
        if not hmac.compare_digest(observed, binding.installation_principal):
            return "unavailable"
        if not self._authority_still_current(authority):
            return "session_changed"
        with self._stage_lock:
            if self._stage_fused:
                return "unavailable"
            try:
                observed = self._read_installation_principal()
            except Exception:  # noqa: BLE001 -- external authority fails closed
                return "unavailable"
            if not hmac.compare_digest(observed, binding.installation_principal):
                return "unavailable"
            if not self._authority_still_current(authority):
                return "session_changed"
            if self._stage_binding is None:
                self._stage_binding = binding
                return "accepted"
            if hmac.compare_digest(
                self._stage_binding.installation_principal,
                binding.installation_principal,
            ) and hmac.compare_digest(
                self._stage_binding.vault_evidence_sha256,
                binding.vault_evidence_sha256,
            ):
                return "accepted"
            return "conflict"

    def _read_authority(self) -> _Authority:
        boot_token = self._environ.get("NACHUAN_ENGINE_BOOT_TOKEN", "")
        if (
            not isinstance(boot_token, str)
            or _BOOT_TOKEN_RE.fullmatch(boot_token) is None
            or boot_token == "0" * 64
        ):
            raise ValueError("paid-media boot token is unavailable")
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
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or not 1 <= pid <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("engine pid is invalid")
        return _Authority(
            boot_token,
            _AuthorityIdentity(generation=generation, pid=pid, port=port),
        )

    @staticmethod
    def _same_authority(left: _Authority, right: _Authority) -> bool:
        return (
            left.identity == right.identity
            and left.boot_token == right.boot_token
        )

    def _current_authority(self) -> _Authority:
        if self._baseline is None:
            raise ValueError("paid-media session authority is unavailable")
        current = self._read_authority()
        if not self._same_authority(self._baseline, current):
            raise ValueError("paid-media session authority changed")
        return current

    def _authority_still_current(self, authority: _Authority) -> bool:
        try:
            return self._same_authority(authority, self._current_authority())
        except (TypeError, ValueError):
            return False

    async def _send_signed(
        self,
        send: Any,
        *,
        authority: _Authority,
        request_nonce: str,
        status: int,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        connection: bytes | None = None,
    ) -> None:
        headers = _normalize_buffered_headers(headers, body)
        if connection is not None:
            headers = [item for item in headers if item[0] != b"connection"]
            headers.append((b"connection", connection))
        identity = authority.identity
        signed = sign_response(
            boot_token=authority.boot_token,
            request_nonce=request_nonce,
            generation=identity.generation,
            pid=identity.pid,
            port=identity.port,
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
        await send(
            {"type": "http.response.body", "body": body, "more_body": False}
        )

    async def _signed_error(
        self,
        send: Any,
        *,
        authority: _Authority,
        request_nonce: str,
        status: int,
        body: bytes,
    ) -> None:
        await self._send_signed(
            send,
            authority=authority,
            request_nonce=request_nonce,
            status=status,
            headers=[(b"content-type", b"application/json")],
            body=body,
            connection=b"close",
        )

    async def _delegate_and_sign(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        *,
        authority: _Authority,
        request_nonce: str,
        raw_path: bytes,
    ) -> None:
        start: dict[str, Any] | None = None
        chunks: list[bytes] = []
        total = 0
        streaming = False
        body_complete = False
        response_committed = False
        stream_total = 0
        stream_expected_length: int | None = None

        async def downstream_send(message: Mapping[str, Any]) -> None:
            nonlocal start, total, streaming, body_complete
            nonlocal response_committed, stream_total, stream_expected_length
            kind = message.get("type")
            if kind == "http.response.start":
                if start is not None:
                    raise ValueError("downstream sent duplicate response start")
                status = message.get("status")
                if (
                    isinstance(status, bool)
                    or not isinstance(status, int)
                    or not 100 <= status <= 599
                ):
                    raise ValueError("invalid downstream response status")
                headers = _response_headers(message)
                start = {"status": status, "headers": headers}
                descriptor = _single_header(headers, b"x-content-sha256")
                streaming = (
                    status == 200
                    and raw_path.startswith(_ASSET_PREFIX)
                    and raw_path != _ASSET_ACK
                    and descriptor is not None
                )
                if streaming:
                    digest, stream_expected_length = _validate_streaming_headers(
                        headers
                    )
                    if not self._authority_still_current(authority):
                        raise ValueError("paid-media authority changed before stream")
                    identity = authority.identity
                    signed = sign_response(
                        boot_token=authority.boot_token,
                        request_nonce=request_nonce,
                        generation=identity.generation,
                        pid=identity.pid,
                        port=identity.port,
                        status=status,
                        contract_headers=headers,
                        body_sha256=digest,
                    )
                    response_committed = True
                    await send(
                        {
                            "type": "http.response.start",
                            "status": status,
                            "headers": [*headers, *_signature_headers(signed)],
                        }
                    )
                return
            if kind != "http.response.body" or start is None:
                raise ValueError("invalid downstream ASGI response sequence")
            if body_complete:
                raise ValueError("downstream sent data after the final body")
            chunk = message.get("body", b"")
            if not isinstance(chunk, (bytes, bytearray)):
                raise ValueError("invalid downstream ASGI response body")
            if streaming:
                if not self._authority_still_current(authority):
                    raise ValueError("paid-media authority changed during stream")
                if stream_expected_length is None:
                    raise ValueError("streaming asset length was not established")
                more_body = bool(message.get("more_body", False))
                next_total = stream_total + len(chunk)
                if next_total > stream_expected_length or (
                    not more_body and next_total != stream_expected_length
                ):
                    raise ValueError("streaming asset content length mismatch")
                await send(
                    {
                        "type": "http.response.body",
                        "body": bytes(chunk),
                        "more_body": more_body,
                    }
                )
                stream_total = next_total
                body_complete = not more_body
                return
            total += len(chunk)
            if total > _MAX_BUFFERED_RESPONSE:
                raise OverflowError("paid-media response exceeds signing bound")
            chunks.append(bytes(chunk))
            body_complete = not bool(message.get("more_body", False))

        try:
            await self._downstream(scope, receive, downstream_send)
            if streaming:
                if not body_complete:
                    raise ValueError("streaming response ended without a final body")
                return
            if start is None:
                raise ValueError("downstream omitted response start")
            if not body_complete:
                raise ValueError("downstream response ended without a final body")
            if not self._authority_still_current(authority):
                response_committed = True
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=request_nonce,
                    status=503,
                    body=_SESSION_CHANGED_BODY,
                )
                return
            body = b"".join(chunks)
            headers = _normalize_buffered_headers(start["headers"], body)
            identity = authority.identity
            signed = sign_response(
                boot_token=authority.boot_token,
                request_nonce=request_nonce,
                generation=identity.generation,
                pid=identity.pid,
                port=identity.port,
                status=start["status"],
                contract_headers=headers,
                body=body,
            )
            response_committed = True
            await send(
                {
                    "type": "http.response.start",
                    "status": start["status"],
                    "headers": [*headers, *_signature_headers(signed)],
                }
            )
            await send(
                {"type": "http.response.body", "body": body, "more_body": False}
            )
        except Exception:  # noqa: BLE001 -- replace unsigned downstream failure
            if streaming or response_committed:
                # Response headers are already committed. Raising aborts the
                # connection; the desktop cannot verify a complete body/digest.
                raise
            await self._signed_error(
                send,
                authority=authority,
                request_nonce=request_nonce,
                status=503,
                body=_DOWNSTREAM_BODY,
            )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if not isinstance(scope, Mapping) or scope.get("type") != "http":
            await self._downstream(scope, receive, send)
            return
        raw_path = _raw_path(scope)
        decoded_path = scope.get("path")
        is_challenge = raw_path == _CHALLENGE_RAW
        is_stage_ready = raw_path == _STAGE_READY_RAW
        is_paid = raw_path is not None and _is_paid_target(raw_path)
        reserved_alias = (
            _has_segment_prefix(raw_path, _SESSION_PREFIX)
            or _has_segment_prefix(decoded_path, CHALLENGE_PATH.rsplit("/", 1)[0])
            or _is_paid_decoded_target(decoded_path)
        )
        if not is_challenge and not is_stage_ready and not is_paid:
            if reserved_alias:
                await _send_unsigned_error(
                    send, status=400, body=_INVALID_REQUEST_BODY
                )
                return
            await self._downstream(scope, receive, send)
            return
        try:
            authority = self._current_authority()
            method, target = validate_asgi_loopback_scope(
                scope, expected_port=authority.identity.port
            )
            headers = _raw_headers(scope)
        except (PaidMediaEngineSessionProtocolError, TypeError, ValueError):
            await _send_unsigned_error(send, status=503, body=_UNAVAILABLE_BODY)
            return
        if _contains_legacy_secret(headers):
            if self._hide_auth_failures:
                await _send_unsigned_error(
                    send, status=503, body=_UNAVAILABLE_BODY
                )
            else:
                await _send_unsigned_error(
                    send, status=400, body=_INVALID_REQUEST_BODY
                )
            return
        limit = 0 if is_challenge else _body_limit(raw_path, method)
        try:
            body = await _read_body(receive, limit=limit)
        except OverflowError:
            await _send_unsigned_error(
                send, status=413, body=_PAYLOAD_TOO_LARGE_BODY
            )
            return
        except (ConnectionError, TypeError, ValueError):
            await _send_unsigned_error(send, status=400, body=_INVALID_REQUEST_BODY)
            return
        try:
            authenticated = verify_request(
                boot_token=authority.boot_token,
                expected_generation=authority.identity.generation,
                expected_pid=authority.identity.pid,
                expected_port=authority.identity.port,
                method=method,
                target=target,
                headers=headers,
                body=body,
                nonce_registry=self._nonce_registry,
            )
        except PaidMediaEngineSessionProtocolError:
            if self._hide_auth_failures:
                await _send_unsigned_error(
                    send, status=503, body=_UNAVAILABLE_BODY
                )
            else:
                await _send_unsigned_error(
                    send, status=401, body=_AUTHENTICATION_BODY
                )
            return
        try:
            _validate_signed_request_headers(
                headers,
                authority=authority,
                body=body,
                challenge=is_challenge,
            )
        except (UnicodeDecodeError, ValueError):
            await self._signed_error(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                status=400,
                body=_INVALID_REQUEST_BODY,
            )
            return
        if is_challenge:
            if method != "GET" or body:
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=400,
                    body=_INVALID_REQUEST_BODY,
                )
                return
            if not self._authority_still_current(authority):
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=503,
                    body=_SESSION_CHANGED_BODY,
                )
                return
            await self._send_signed(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                status=200,
                headers=list(_CHALLENGE_HEADERS),
                body=CHALLENGE_BODY,
                connection=b"keep-alive",
            )
            return
        if is_stage_ready:
            if (
                method != "POST"
                or _ordinary_value(headers, b"content-type")
                != b"application/json"
            ):
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=400,
                    body=_INVALID_REQUEST_BODY,
                )
                return
            try:
                binding = _parse_stage_ready_body(body, authority=authority)
            except ValueError:
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=400,
                    body=_INVALID_REQUEST_BODY,
                )
                return
            result = self._latch_stage_binding(authority, binding)
            if result == "session_changed":
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=503,
                    body=_SESSION_CHANGED_BODY,
                )
                return
            if result == "unavailable":
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=503,
                    body=_INSTALLATION_AUTHORITY_BODY,
                )
                return
            if result == "conflict":
                await self._signed_error(
                    send,
                    authority=authority,
                    request_nonce=authenticated.nonce,
                    status=409,
                    body=_STAGE_BINDING_CONFLICT_BODY,
                )
                return
            await self._send_signed(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                status=200,
                headers=[(b"content-type", b"application/json")],
                body=_stage_ready_receipt(binding),
                connection=b"close",
            )
            return
        if not self._authority_still_current(authority):
            await self._signed_error(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                status=503,
                body=_SESSION_CHANGED_BODY,
            )
            return
        if not self.stage_ready:
            await self._signed_error(
                send,
                authority=authority,
                request_nonce=authenticated.nonce,
                status=503,
                body=_DESKTOP_V2_STAGE_BODY,
            )
            return
        authorized_scope = dict(scope)
        state = dict(scope.get("state") or {})
        session_state: dict[str, object] = {
            "authenticated": True,
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
                raw_path=raw_path,
            )
        finally:
            self._unregister_authenticated_state(session_state)


__all__ = [
    "PaidMediaEngineSessionGatewayApp",
    "SESSION_STATE_KEY",
    "STAGE_READY_PATH",
]
