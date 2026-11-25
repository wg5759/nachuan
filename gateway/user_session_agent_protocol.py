"""Identity-bound minimal protocol for NachuanCore user-session agents.

Version 1 authenticates only an empty ``subscription.status`` request.  HMAC is
not confidentiality: prompts, results, credentials, argv, cwd and environment
must remain structurally impossible here.  Any later payload-bearing capability
requires a separately reviewed authenticated-encryption protocol.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import uuid
from dataclasses import dataclass


_SCHEMA = "nachuan.user-session-agent-frame.v1"
_PRINCIPAL_KEY_DOMAIN = b"nachuan-user-session-agent-principal-key-v1\0"
_SESSION_KEY_DOMAIN = b"nachuan-user-session-agent-session-key-v1\0"
_FRAME_DOMAIN = b"nachuan-user-session-agent-frame-v1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ROOT_KEY = re.compile(r"^sk-service-pipe-([0-9a-f]{64})$")
_DIRECTIONS = {"agent_to_service", "service_to_agent"}
_CONNECTORS = {"codex", "kimi_code"}
_CAPABILITY = "subscription.status"


class UserSessionAgentProtocolError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise UserSessionAgentProtocolError(
            "session agent canonical JSON is invalid"
        ) from exc


def _counter(value: object, *, minimum: int = 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > 2**63 - 1
    ):
        raise UserSessionAgentProtocolError("session agent counter is invalid")
    return value


def _hex(value: object, name: str) -> str:
    normalized = str(value or "").casefold()
    if _HEX64.fullmatch(normalized) is None or normalized == "0" * 64:
        raise UserSessionAgentProtocolError(
            f"session agent {name} is invalid"
        )
    return normalized


def _context(
    *,
    installation_id: object,
    root_epoch: object,
    service_boot_id: object,
    principal_hash: object,
    session_id: object,
    agent_generation: object,
) -> dict[str, object]:
    return {
        "installation_id": _hex(installation_id, "installation"),
        "root_epoch": _counter(root_epoch),
        "service_boot_id": _hex(service_boot_id, "service boot"),
        "principal_hash": _hex(principal_hash, "principal"),
        "session_id": _counter(session_id),
        "agent_generation": _counter(agent_generation),
    }


def derive_user_principal_key(
    *,
    root_key: str,
    installation_id: str,
    root_epoch: int,
    principal_hash: str,
) -> bytes:
    """Derive the only secret that may leave the service for one principal.

    The installation root key remains service-only.  A principal key cannot
    authenticate another principal because the service derives a different key
    for that identity and the complete identity is bound again below.
    """

    match = _ROOT_KEY.fullmatch(str(root_key or ""))
    if match is None or match.group(1) == "0" * 64:
        raise UserSessionAgentProtocolError(
            "session agent root key is invalid"
        )
    principal_context = {
        "installation_id": _hex(installation_id, "installation"),
        "root_epoch": _counter(root_epoch),
        "principal_hash": _hex(principal_hash, "principal"),
    }
    return hmac.new(
        bytes.fromhex(match.group(1)),
        _PRINCIPAL_KEY_DOMAIN + _canonical(principal_context),
        hashlib.sha256,
    ).digest()


def derive_user_session_key(
    *,
    principal_key: bytes,
    installation_id: str,
    root_epoch: int,
    service_boot_id: str,
    principal_hash: str,
    session_id: int,
    agent_generation: int,
) -> bytes:
    if (
        not isinstance(principal_key, bytes)
        or len(principal_key) != 32
        or principal_key == b"\0" * 32
    ):
        raise UserSessionAgentProtocolError(
            "session agent principal key is invalid"
        )
    context = _context(
        installation_id=installation_id,
        root_epoch=root_epoch,
        service_boot_id=service_boot_id,
        principal_hash=principal_hash,
        session_id=session_id,
        agent_generation=agent_generation,
    )
    return hmac.new(
        principal_key,
        _SESSION_KEY_DOMAIN + _canonical(context),
        hashlib.sha256,
    ).digest()


def encode_user_session_frame(
    *,
    session_key: bytes,
    installation_id: str,
    root_epoch: int,
    service_boot_id: str,
    principal_hash: str,
    session_id: int,
    agent_generation: int,
    direction: str,
    sequence: int,
    operation_id: str,
    connector: str,
    capability: str,
    payload: dict[str, object],
    fence: str,
) -> bytes:
    if (
        not isinstance(session_key, bytes)
        or len(session_key) != 32
        or session_key == b"\0" * 32
    ):
        raise UserSessionAgentProtocolError(
            "session agent session key is invalid"
        )
    context = _context(
        installation_id=installation_id,
        root_epoch=root_epoch,
        service_boot_id=service_boot_id,
        principal_hash=principal_hash,
        session_id=session_id,
        agent_generation=agent_generation,
    )
    try:
        operation = str(uuid.UUID(str(operation_id))).lower()
    except (ValueError, AttributeError) as exc:
        raise UserSessionAgentProtocolError(
            "session agent operation is invalid"
        ) from exc
    if (
        direction not in _DIRECTIONS
        or connector not in _CONNECTORS
        or capability != _CAPABILITY
        or not isinstance(payload, dict)
        or payload
    ):
        raise UserSessionAgentProtocolError(
            "session agent capability is invalid"
        )
    payload_bytes = _canonical(payload)
    body = {
        "schema": _SCHEMA,
        **context,
        "direction": direction,
        "sequence": _counter(sequence),
        "operation_id": operation,
        "connector": connector,
        "capability": capability,
        "payload": payload,
        "request_digest": hashlib.sha256(payload_bytes).hexdigest(),
        "fence": _hex(fence, "fence"),
    }
    body["mac"] = hmac.new(
        session_key,
        _FRAME_DOMAIN + _canonical(body),
        hashlib.sha256,
    ).hexdigest()
    raw = _canonical(body)
    if len(raw) > 16 * 1024:
        raise UserSessionAgentProtocolError(
            "session agent frame exceeds its byte limit"
        )
    return raw


_SCOPE_AUTHORITY = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedUserSessionOperationScope:
    installation_id: str
    root_epoch: int
    service_boot_id: str
    principal_hash: str
    session_id: int
    agent_generation: int
    operation_id: str
    connector: str
    request_digest: str
    fence: str
    direction: str
    sequence: int
    capability: str

    def __init__(
        self,
        *,
        installation_id: str,
        root_epoch: int,
        service_boot_id: str,
        principal_hash: str,
        session_id: int,
        agent_generation: int,
        operation_id: str,
        connector: str,
        request_digest: str,
        fence: str,
        direction: str,
        sequence: int,
        capability: str,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SCOPE_AUTHORITY:
            raise UserSessionAgentProtocolError(
                "session agent operation scope is not authenticated"
            )
        values = {
            "installation_id": installation_id,
            "root_epoch": root_epoch,
            "service_boot_id": service_boot_id,
            "principal_hash": principal_hash,
            "session_id": session_id,
            "agent_generation": agent_generation,
            "operation_id": operation_id,
            "connector": connector,
            "request_digest": request_digest,
            "fence": fence,
            "direction": direction,
            "sequence": sequence,
            "capability": capability,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class VerifiedUserSessionFrame:
    scope: VerifiedUserSessionOperationScope
    capability: str
    payload: dict[str, object]
    direction: str
    sequence: int

    @property
    def operation_id(self) -> str:
        return self.scope.operation_id

    @property
    def connector(self) -> str:
        return self.scope.connector

    @property
    def fence(self) -> str:
        return self.scope.fence


class UserSessionAgentVerifier:
    def __init__(
        self,
        *,
        session_key: bytes,
        installation_id: str,
        root_epoch: int,
        service_boot_id: str,
        principal_hash: str,
        session_id: int,
        agent_generation: int,
        expected_direction: str,
        expected_sequence: int,
    ) -> None:
        if (
            not isinstance(session_key, bytes)
            or len(session_key) != 32
            or session_key == b"\0" * 32
            or expected_direction not in _DIRECTIONS
        ):
            raise UserSessionAgentProtocolError(
                "session agent verifier is invalid"
            )
        self._key = session_key
        self._context = _context(
            installation_id=installation_id,
            root_epoch=root_epoch,
            service_boot_id=service_boot_id,
            principal_hash=principal_hash,
            session_id=session_id,
            agent_generation=agent_generation,
        )
        self._direction = expected_direction
        self._next_sequence = _counter(expected_sequence)
        self._lock = threading.Lock()

    @property
    def next_sequence(self) -> int:
        with self._lock:
            return self._next_sequence

    def verify(self, raw: bytes) -> VerifiedUserSessionFrame:
        with self._lock:
            return self._verify_locked(raw)

    def _verify_locked(self, raw: bytes) -> VerifiedUserSessionFrame:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= 16 * 1024:
            raise UserSessionAgentProtocolError("session agent frame is invalid")

        def no_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result

        try:
            document = json.loads(
                raw.decode("ascii", errors="strict"),
                object_pairs_hook=no_duplicates,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValueError("non-finite number")
                ),
            )
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise UserSessionAgentProtocolError(
                "session agent frame JSON is invalid"
            ) from exc
        expected = {
            "schema",
            "installation_id",
            "root_epoch",
            "service_boot_id",
            "principal_hash",
            "session_id",
            "agent_generation",
            "direction",
            "sequence",
            "operation_id",
            "connector",
            "capability",
            "payload",
            "request_digest",
            "fence",
            "mac",
        }
        if (
            not isinstance(document, dict)
            or set(document) != expected
            or document.get("schema") != _SCHEMA
            or raw != _canonical(document)
            or any(document.get(name) != value for name, value in self._context.items())
            or document.get("direction") != self._direction
            or document.get("sequence") != self._next_sequence
        ):
            raise UserSessionAgentProtocolError(
                "session agent frame identity or sequence is invalid"
            )
        if (
            document.get("connector") not in _CONNECTORS
            or document.get("capability") != _CAPABILITY
            or document.get("payload") != {}
        ):
            raise UserSessionAgentProtocolError(
                "session agent frame capability is invalid"
            )
        try:
            operation = str(uuid.UUID(str(document.get("operation_id")))).lower()
        except ValueError as exc:
            raise UserSessionAgentProtocolError(
                "session agent frame operation is invalid"
            ) from exc
        if operation != document.get("operation_id"):
            raise UserSessionAgentProtocolError(
                "session agent frame operation is invalid"
            )
        request_digest = hashlib.sha256(_canonical({})).hexdigest()
        mac = document.get("mac")
        body = {key: value for key, value in document.items() if key != "mac"}
        expected_mac = hmac.new(
            self._key,
            _FRAME_DOMAIN + _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        try:
            fence = _hex(document.get("fence"), "fence")
        except UserSessionAgentProtocolError as exc:
            raise UserSessionAgentProtocolError(
                "session agent frame authentication is invalid"
            ) from exc
        if (
            document.get("request_digest") != request_digest
            or not isinstance(mac, str)
            or _HEX64.fullmatch(mac) is None
            or not hmac.compare_digest(mac, expected_mac)
        ):
            raise UserSessionAgentProtocolError(
                "session agent frame authentication is invalid"
            )
        scope = VerifiedUserSessionOperationScope(
            **self._context,
            operation_id=operation,
            connector=str(document["connector"]),
            request_digest=request_digest,
            fence=fence,
            direction=self._direction,
            sequence=self._next_sequence,
            capability=_CAPABILITY,
            _authority=_SCOPE_AUTHORITY,
        )
        sequence = self._next_sequence
        self._next_sequence += 1
        return VerifiedUserSessionFrame(
            scope=scope,
            capability=_CAPABILITY,
            payload={},
            direction=self._direction,
            sequence=sequence,
        )


__all__ = [
    "UserSessionAgentProtocolError",
    "UserSessionAgentVerifier",
    "VerifiedUserSessionOperationScope",
    "VerifiedUserSessionFrame",
    "derive_user_principal_key",
    "derive_user_session_key",
    "encode_user_session_frame",
]
