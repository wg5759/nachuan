"""Authenticated loopback-only ASGI adapter for :mod:`installation_root`.

This module deliberately has no import-time state and starts no server.  The
gateway entry point may explicitly dispatch the seven frozen private routes to
an instance returned by :func:`create_installation_root_dispatcher`.

The boot token is only an HMAC key.  It is never accepted as a Bearer token or
as JSON data, and errors never include request details or exception text.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Protocol, TypeAlias

from starlette.concurrency import run_in_threadpool

from gateway.installation_root import (
    InstallationRootLocked,
    InstallationRootSnapshot,
    InstallationRootUnavailable,
    RootMutationResult,
)
from gateway.installation_root_protocol import (
    HEADER_NONCE,
    REQUEST_HEADER_NAMES,
    InstallationRootAuthenticationError,
    InstallationRootProtocolError,
    InstallationRootTimestampError,
    LoopbackPolicyError,
    NonceCapacityError,
    NonceRegistry,
    NonceReplayError,
    extract_single_headers,
    sign_response,
    validate_asgi_loopback_scope,
    verify_request,
)


JSON_BYTE_LIMIT = 64 * 1024
MAX_JS_SAFE_INTEGER = (1 << 53) - 1

SNAPSHOT_PATH = "/internal/v1/installation-root/snapshot"
DESKTOP_BIND_PATH = "/internal/v1/installation-root/components/desktop/bind"
DESKTOP_VERIFY_PATH = "/internal/v1/installation-root/components/desktop/verify"
DESKTOP_ADVANCE_PATH = "/internal/v1/installation-root/components/desktop/advance"
DESKTOP_RECOVERY_ACK_PATH = (
    "/internal/v1/installation-root/components/desktop/recovery/ack"
)
UPDATER_VERIFY_PATH = "/internal/v1/installation-root/updater/verify"
UPDATER_ADVANCE_PATH = "/internal/v1/installation-root/updater/advance"

INSTALLATION_ROOT_ROUTES: Mapping[str, str] = MappingProxyType(
    {
        SNAPSHOT_PATH: "GET",
        DESKTOP_BIND_PATH: "POST",
        DESKTOP_VERIFY_PATH: "POST",
        DESKTOP_ADVANCE_PATH: "POST",
        DESKTOP_RECOVERY_ACK_PATH: "POST",
        UPDATER_VERIFY_PATH: "POST",
        UPDATER_ADVANCE_PATH: "POST",
    }
)

SNAPSHOT_SCHEMA = "nachuan.installation-root.snapshot.v1"
MUTATION_SCHEMA = "nachuan.installation-root.mutation.v1"
ERROR_SCHEMA = "nachuan.installation-root.error.v1"

_ERROR_CODES = frozenset(
    {
        "invalid_request",
        "authentication_failed",
        "replay_rejected",
        "root_unavailable",
        "root_locked",
        "conflict",
        "internal_error",
    }
)
_ROOT_STATUSES = frozenset(
    {"provisioning", "active", "maintenance_locked", "retired"}
)
_ROOT_LOCK_KINDS = frozenset(
    {"none", "operator", "integrity", "reanchor", "retired"}
)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_LENGTH = re.compile(rb"^(?:0|[1-9][0-9]*)$")
_HEADER_NAME_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_ZERO_DIGEST = "0" * 64
_MAX_BODY_MESSAGES = 256
_BODY_READ_TIMEOUT_SECONDS = 2.0

ASGIScope: TypeAlias = Mapping[str, Any]
ASGIMessage: TypeAlias = dict[str, Any]
ASGIReceive: TypeAlias = Callable[[], Awaitable[ASGIMessage]]
ASGISend: TypeAlias = Callable[[ASGIMessage], Awaitable[None]]


class _RootLike(Protocol):
    def snapshot(self) -> InstallationRootSnapshot: ...


class InstallationRootAPIConfigurationError(ValueError):
    """The private adapter was constructed with an unsafe configuration."""


class _InvalidRequest(ValueError):
    pass


class _RootWireError(RuntimeError):
    pass


def _compact_json(value: Mapping[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _RootWireError("root response is not JSON-safe") from exc
    if len(payload) > JSON_BYTE_LIMIT:
        raise _RootWireError("root response exceeds the wire limit")
    return payload


def _raw_headers(scope: ASGIScope) -> list[tuple[bytes, bytes]]:
    value = scope.get("headers")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _InvalidRequest("raw request headers are required")
    result: list[tuple[bytes, bytes]] = []
    for item in value:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise _InvalidRequest("raw request headers are invalid")
        raw_name, raw_value = item
        if not isinstance(raw_name, (bytes, bytearray)) or not isinstance(
            raw_value, (bytes, bytearray)
        ):
            raise _InvalidRequest("raw request headers are invalid")
        name = bytes(raw_name)
        header_value = bytes(raw_value)
        if (
            _HEADER_NAME_TOKEN.fullmatch(name) is None
            or b"\r" in header_value
            or b"\n" in header_value
        ):
            raise _InvalidRequest("raw request headers are invalid")
        result.append((name, header_value))
    return result


def _header_values(headers: Sequence[tuple[bytes, bytes]], name: str) -> list[bytes]:
    wanted = name.encode("ascii")
    return [value for key, value in headers if key.lower() == wanted]


def _headers_contain_secret(
    headers: Sequence[tuple[bytes, bytes]], secret: bytes
) -> bool:
    return any(secret in value for _name, value in headers)


def _validate_transport_headers(
    headers: Sequence[tuple[bytes, bytes]], method: str
) -> int:
    if _header_values(headers, "authorization") or _header_values(
        headers, "proxy-authorization"
    ):
        raise _InvalidRequest("authorization headers are forbidden")
    if _header_values(headers, "transfer-encoding") or _header_values(
        headers, "content-encoding"
    ):
        raise _InvalidRequest("ambiguous request framing is forbidden")

    lengths = _header_values(headers, "content-length")
    content_types = _header_values(headers, "content-type")
    cache_controls = _header_values(headers, "cache-control")
    if method == "GET":
        if len(lengths) > 1 or content_types:
            raise _InvalidRequest("GET request framing is invalid")
        if cache_controls != [b"no-store"]:
            raise _InvalidRequest("GET cache policy is invalid")
        if not lengths:
            return 0
        if lengths[0] != b"0":
            raise _InvalidRequest("GET requests must have an empty body")
        return 0

    if method != "POST":
        raise _InvalidRequest("request method is not allowed")
    if content_types != [b"application/json"]:
        raise _InvalidRequest("JSON content type must be exact")
    if cache_controls != [b"no-store"]:
        raise _InvalidRequest("request cache policy must be exact")
    if len(lengths) != 1 or _CONTENT_LENGTH.fullmatch(lengths[0]) is None:
        raise _InvalidRequest("content length must be exact")
    if len(lengths[0]) > len(str(JSON_BYTE_LIMIT)):
        raise _InvalidRequest("request body exceeds the wire limit")
    declared_length = int(lengths[0])
    if declared_length > JSON_BYTE_LIMIT:
        raise _InvalidRequest("request body exceeds the wire limit")
    return declared_length


async def _read_request_body_frames(
    receive: ASGIReceive, *, declared_length: int
) -> bytes:
    body = bytearray()
    messages = 0
    while True:
        messages += 1
        if messages > _MAX_BODY_MESSAGES:
            raise _InvalidRequest("request body stream is invalid")
        try:
            message = await receive()
        except Exception as exc:
            raise _InvalidRequest("request body stream failed") from exc
        if not isinstance(message, Mapping) or message.get("type") != "http.request":
            raise _InvalidRequest("request body stream is invalid")
        chunk = message.get("body", b"")
        if not isinstance(chunk, (bytes, bytearray)):
            raise _InvalidRequest("request body chunk is invalid")
        more_body = message.get("more_body", False)
        if not isinstance(more_body, bool):
            raise _InvalidRequest("request body stream is invalid")
        if len(body) + len(chunk) > JSON_BYTE_LIMIT or len(body) + len(
            chunk
        ) > declared_length:
            # Do not drain an oversized stream.  The hosting server owns the
            # connection lifecycle after this fail-closed response.
            raise _InvalidRequest("request body exceeds its declared limit")
        body.extend(chunk)
        if not more_body:
            break
    if len(body) != declared_length:
        raise _InvalidRequest("request content length does not match its bytes")
    return bytes(body)


async def _read_request_body(
    receive: ASGIReceive, *, declared_length: int
) -> bytes:
    try:
        async with asyncio.timeout(_BODY_READ_TIMEOUT_SECONDS):
            return await _read_request_body_frames(
                receive, declared_length=declared_length
            )
    except TimeoutError as exc:
        raise _InvalidRequest("request body read timed out") from exc


def _reject_json_constant(_value: str) -> Any:
    raise _InvalidRequest("non-finite JSON values are forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _InvalidRequest("duplicate JSON object member")
        value[key] = item
    return value


def _decode_json_object(body: bytes) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8", "strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except _InvalidRequest:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _InvalidRequest("request JSON is invalid") from exc
    if type(value) is not dict:
        raise _InvalidRequest("request JSON must be an object")
    return value


def _contains_forbidden_string(value: Any, forbidden: str) -> bool:
    if isinstance(value, str):
        return forbidden in value
    if isinstance(value, list):
        return any(_contains_forbidden_string(item, forbidden) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_forbidden_string(key, forbidden)
            or _contains_forbidden_string(item, forbidden)
            for key, item in value.items()
        )
    return False


def _exact_object(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        raise _InvalidRequest("request object shape is invalid")
    return value


def _digest(value: Any, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise _InvalidRequest("digest is invalid")
    if not allow_zero and value == _ZERO_DIGEST:
        raise _InvalidRequest("zero digest is forbidden")
    return value


def _counter(value: Any, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > MAX_JS_SAFE_INTEGER
    ):
        raise _InvalidRequest("counter is outside the safe wire range")
    return value


def _optional_digest(value: Any, *, allow_zero: bool = True) -> str | None:
    if value is None:
        return None
    return _digest(value, allow_zero=allow_zero)


def _updater_proof_is_consistent(
    release_sequence: int,
    keyring_sequence: int,
    artifact_digest: str,
    state_digest: str,
) -> bool:
    return (
        (release_sequence == 0) == (artifact_digest == _ZERO_DIGEST)
        and (state_digest == _ZERO_DIGEST)
        == (release_sequence == 0 and keyring_sequence == 0)
    )


def _desktop_common(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "installation_id": _digest(value["installationId"], allow_zero=False),
        "epoch": _counter(value["epoch"], minimum=1),
        "identity": _digest(value["identity"], allow_zero=False),
    }


def _parse_request(
    path: str, body: bytes, *, forbidden_string: str
) -> dict[str, Any]:
    if path == SNAPSHOT_PATH:
        if body:
            raise _InvalidRequest("snapshot request body must be empty")
        return {}
    value = _decode_json_object(body)
    if _contains_forbidden_string(value, forbidden_string):
        raise _InvalidRequest("boot token is forbidden in request JSON")
    if path == DESKTOP_BIND_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "identity",
                    "stateDigest",
                    "expectedRootRevision",
                    "sequenceFloor",
                }
            ),
        )
        return {
            **_desktop_common(value),
            "state_digest": _digest(value["stateDigest"], allow_zero=False),
            "expected_root_revision": _counter(
                value["expectedRootRevision"], minimum=1
            ),
            "sequence_floor": _counter(value["sequenceFloor"]),
        }
    if path == DESKTOP_VERIFY_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "identity",
                    "sequenceFloor",
                    "stateDigest",
                    "previousStateDigest",
                }
            ),
        )
        return {
            **_desktop_common(value),
            "sequence_floor": _counter(value["sequenceFloor"]),
            "state_digest": _digest(value["stateDigest"], allow_zero=False),
            "previous_state_digest": _optional_digest(
                value["previousStateDigest"], allow_zero=False
            ),
        }
    if path == DESKTOP_ADVANCE_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "identity",
                    "expectedFloor",
                    "expectedStateDigest",
                    "nextFloor",
                    "nextStateDigest",
                    "expectedRootRevision",
                }
            ),
        )
        result = {
            **_desktop_common(value),
            "expected_floor": _counter(value["expectedFloor"]),
            "expected_state_digest": _digest(
                value["expectedStateDigest"], allow_zero=False
            ),
            "next_floor": _counter(value["nextFloor"]),
            "next_state_digest": _digest(
                value["nextStateDigest"], allow_zero=False
            ),
            "expected_root_revision": _counter(
                value["expectedRootRevision"], minimum=1
            ),
        }
        if result["next_floor"] != result["expected_floor"] + 1:
            raise _InvalidRequest("component transition must advance exactly once")
        if result["next_state_digest"] == result["expected_state_digest"]:
            raise _InvalidRequest("component transition must change state digest")
        return result
    if path == DESKTOP_RECOVERY_ACK_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "identity",
                    "recoveryFloor",
                    "recoveryStateDigest",
                    "nextFloor",
                    "nextStateDigest",
                    "expectedRootRevision",
                }
            ),
        )
        result = {
            **_desktop_common(value),
            "recovery_floor": _counter(value["recoveryFloor"]),
            "recovery_state_digest": _digest(
                value["recoveryStateDigest"], allow_zero=False
            ),
            "next_floor": _counter(value["nextFloor"]),
            "next_state_digest": _digest(
                value["nextStateDigest"], allow_zero=False
            ),
            "expected_root_revision": _counter(
                value["expectedRootRevision"], minimum=1
            ),
        }
        if result["next_floor"] != result["recovery_floor"] + 1:
            raise _InvalidRequest("recovery acknowledgement must advance exactly once")
        if result["next_state_digest"] == result["recovery_state_digest"]:
            raise _InvalidRequest("recovery acknowledgement must change state digest")
        return result
    if path == UPDATER_VERIFY_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "releaseSequence",
                    "keyringSequence",
                    "artifactDigest",
                    "stateDigest",
                    "previous",
                }
            ),
        )
        result = {
            "installation_id": _digest(value["installationId"], allow_zero=False),
            "epoch": _counter(value["epoch"], minimum=1),
            "release_sequence": _counter(value["releaseSequence"]),
            "keyring_sequence": _counter(value["keyringSequence"]),
            "artifact_digest": _digest(value["artifactDigest"]),
            "updater_state_digest": _digest(value["stateDigest"]),
        }
        if not _updater_proof_is_consistent(
            result["release_sequence"],
            result["keyring_sequence"],
            result["artifact_digest"],
            result["updater_state_digest"],
        ):
            raise _InvalidRequest("updater proof is structurally inconsistent")
        previous = value["previous"]
        if previous is not None:
            previous = _exact_object(
                previous,
                frozenset(
                    {
                        "releaseSequence",
                        "keyringSequence",
                        "artifactDigest",
                        "stateDigest",
                    }
                ),
            )
            result.update(
                {
                    "previous_release_sequence": _counter(
                        previous["releaseSequence"]
                    ),
                    "previous_keyring_sequence": _counter(
                        previous["keyringSequence"]
                    ),
                    "previous_artifact_digest": _digest(
                        previous["artifactDigest"]
                    ),
                    "previous_updater_state_digest": _digest(
                        previous["stateDigest"]
                    ),
                }
            )
            if not _updater_proof_is_consistent(
                result["previous_release_sequence"],
                result["previous_keyring_sequence"],
                result["previous_artifact_digest"],
                result["previous_updater_state_digest"],
            ):
                raise _InvalidRequest(
                    "previous updater proof is structurally inconsistent"
                )
        return result
    if path == UPDATER_ADVANCE_PATH:
        value = _exact_object(
            value,
            frozenset(
                {
                    "installationId",
                    "epoch",
                    "expectedReleaseSequence",
                    "expectedKeyringSequence",
                    "expectedArtifactDigest",
                    "expectedStateDigest",
                    "nextReleaseSequence",
                    "nextKeyringSequence",
                    "nextArtifactDigest",
                    "nextStateDigest",
                    "expectedRootRevision",
                }
            ),
        )
        result = {
            "installation_id": _digest(value["installationId"], allow_zero=False),
            "epoch": _counter(value["epoch"], minimum=1),
            "expected_release_sequence": _counter(
                value["expectedReleaseSequence"]
            ),
            "expected_keyring_sequence": _counter(
                value["expectedKeyringSequence"]
            ),
            "expected_artifact_digest": _digest(value["expectedArtifactDigest"]),
            "expected_updater_state_digest": _digest(value["expectedStateDigest"]),
            "next_release_sequence": _counter(value["nextReleaseSequence"]),
            "next_keyring_sequence": _counter(value["nextKeyringSequence"]),
            "next_artifact_digest": _digest(value["nextArtifactDigest"]),
            "next_updater_state_digest": _digest(value["nextStateDigest"]),
            "expected_root_revision": _counter(
                value["expectedRootRevision"], minimum=1
            ),
        }
        current_release = result["expected_release_sequence"]
        current_keyring = result["expected_keyring_sequence"]
        next_release = result["next_release_sequence"]
        next_keyring = result["next_keyring_sequence"]
        current_artifact = result["expected_artifact_digest"]
        next_artifact = result["next_artifact_digest"]
        current_state = result["expected_updater_state_digest"]
        next_state = result["next_updater_state_digest"]
        valid = (
            _updater_proof_is_consistent(
                current_release,
                current_keyring,
                current_artifact,
                current_state,
            )
            and _updater_proof_is_consistent(
                next_release,
                next_keyring,
                next_artifact,
                next_state,
            )
            and not (
                next_release < current_release
                or next_keyring < current_keyring
                or (
                    next_release == current_release
                    and next_keyring == current_keyring
                )
                or next_state == _ZERO_DIGEST
                or next_state == current_state
                or (
                    next_release == current_release
                    and next_artifact != current_artifact
                )
                or (
                    next_release != current_release
                    and (
                        next_artifact == _ZERO_DIGEST
                        or next_artifact == current_artifact
                    )
                )
            )
        )
        if not valid:
            raise _InvalidRequest("updater transition is invalid")
        return result
    raise _InvalidRequest("request path is not allowed")


def _wire_counter(value: Any, *, minimum: int = 0) -> int:
    try:
        return _counter(value, minimum=minimum)
    except _InvalidRequest as exc:
        raise _RootWireError("root counter is outside the safe wire range") from exc


def _wire_digest(value: Any, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    try:
        return _digest(value)
    except _InvalidRequest as exc:
        raise _RootWireError("root digest is invalid") from exc


def _component_snapshot(value: Any, *, root_epoch: int) -> dict[str, Any]:
    bound = getattr(value, "bound", None)
    if type(bound) is not bool:
        raise _RootWireError("root component binding flag is invalid")
    result = {
        "identity": _wire_digest(getattr(value, "identity", None)),
        "epoch": _wire_counter(getattr(value, "epoch", None), minimum=1),
        "bound": bound,
        "sequenceFloor": _wire_counter(
            getattr(value, "sequence_floor", None)
        ),
        "stateDigest": _wire_digest(
            getattr(value, "state_digest", None), nullable=True
        ),
        "recoveryFloor": (
            None
            if getattr(value, "recovery_floor", None) is None
            else _wire_counter(getattr(value, "recovery_floor"))
        ),
        "recoveryStateDigest": _wire_digest(
            getattr(value, "recovery_state_digest", None), nullable=True
        ),
    }
    if result["identity"] == _ZERO_DIGEST or result["epoch"] != root_epoch:
        raise _RootWireError("root component identity or epoch is invalid")
    recovery_floor = result["recoveryFloor"]
    recovery_digest = result["recoveryStateDigest"]
    state_digest = result["stateDigest"]
    if not bound:
        if (
            result["sequenceFloor"] != 0
            or state_digest is not None
            or recovery_floor is not None
            or recovery_digest is not None
        ):
            raise _RootWireError("unbound root component state is invalid")
    elif (
        state_digest is None
        or state_digest == _ZERO_DIGEST
        or (recovery_floor is None) != (recovery_digest is None)
        or (
            recovery_floor is not None
            and (
                recovery_floor != result["sequenceFloor"]
                or recovery_digest != state_digest
            )
        )
    ):
        raise _RootWireError("bound root component state is invalid")
    return result


def _snapshot_payload(snapshot: Any) -> dict[str, Any]:
    status = getattr(snapshot, "status", None)
    lock_kind = getattr(snapshot, "lock_kind", None)
    reanchor_pending = getattr(snapshot, "reanchor_pending", None)
    if status not in _ROOT_STATUSES or lock_kind not in _ROOT_LOCK_KINDS:
        raise _RootWireError("root status is invalid")
    if type(reanchor_pending) is not bool:
        raise _RootWireError("root reanchor flag is invalid")
    try:
        desktop = snapshot.component("desktop")
        gateway = snapshot.component("gateway")
    except (AttributeError, KeyError, TypeError) as exc:
        raise _RootWireError("root components are incomplete") from exc
    updater = getattr(snapshot, "updater", None)
    if updater is None:
        raise _RootWireError("root updater state is missing")
    epoch = _wire_counter(getattr(snapshot, "epoch", None), minimum=1)
    components = {
        "desktop": _component_snapshot(desktop, root_epoch=epoch),
        "gateway": _component_snapshot(gateway, root_epoch=epoch),
    }
    updater_payload = {
        "releaseSequence": _wire_counter(
            getattr(updater, "release_sequence", None)
        ),
        "keyringSequence": _wire_counter(
            getattr(updater, "keyring_sequence", None)
        ),
        "artifactDigest": _wire_digest(
            getattr(updater, "artifact_digest", None)
        ),
        "stateDigest": _wire_digest(getattr(updater, "state_digest", None)),
    }
    if not _updater_proof_is_consistent(
        updater_payload["releaseSequence"],
        updater_payload["keyringSequence"],
        updater_payload["artifactDigest"],
        updater_payload["stateDigest"],
    ):
        raise _RootWireError("root updater proof is structurally inconsistent")
    installation_id = _wire_digest(getattr(snapshot, "installation_id", None))
    if installation_id == _ZERO_DIGEST:
        raise _RootWireError("root installation identity is invalid")
    result = {
        "installationId": installation_id,
        "ownerSidDigest": _wire_digest(
            getattr(snapshot, "owner_sid_digest", None)
        ),
        "epoch": epoch,
        "rootRevision": _wire_counter(
            getattr(snapshot, "root_revision", None), minimum=1
        ),
        "status": status,
        "lockKind": lock_kind,
        "lockReasonDigest": _wire_digest(
            getattr(snapshot, "lock_reason_digest", None), nullable=True
        ),
        "reanchorPending": reanchor_pending,
        "reanchorOperationDigest": _wire_digest(
            getattr(snapshot, "reanchor_operation_digest", None), nullable=True
        ),
        "reanchorSnapshotDigest": _wire_digest(
            getattr(snapshot, "reanchor_snapshot_digest", None), nullable=True
        ),
        "reanchorSourceEpoch": (
            None
            if getattr(snapshot, "reanchor_source_epoch", None) is None
            else _wire_counter(
                getattr(snapshot, "reanchor_source_epoch"), minimum=1
            )
        ),
        "principalDigest": _wire_digest(
            getattr(snapshot, "principal_digest", None)
        ),
        "components": components,
        "updater": updater_payload,
    }
    triple = (
        result["reanchorOperationDigest"],
        result["reanchorSnapshotDigest"],
        result["reanchorSourceEpoch"],
    )
    triple_present = all(item is not None for item in triple)
    triple_absent = all(item is None for item in triple)
    reason = result["lockReasonDigest"]
    if status == "provisioning":
        # Wire v1 intentionally omits the private ``gateway_assets`` and
        # ``channel_media`` Root-v5 components, so both public components may
        # already be bound while installation is legitimately provisioning.
        valid_status = (
            lock_kind == "none"
            and reason is None
            and not reanchor_pending
            and triple_absent
        )
    elif status == "active":
        valid_status = (
            lock_kind == "none"
            and reason is None
            and not reanchor_pending
            and (
                triple_absent
                or (
                    triple_present
                    and epoch == int(result["reanchorSourceEpoch"]) + 1
                )
            )
            and components["desktop"]["bound"]
            and components["gateway"]["bound"]
        )
    elif status == "maintenance_locked":
        valid_status = (
            (
                lock_kind in {"operator", "integrity"}
                and not reanchor_pending
                and triple_absent
            )
            or (
                lock_kind == "reanchor"
                and reason is not None
                and reanchor_pending
                and triple_present
                and epoch == int(result["reanchorSourceEpoch"]) + 1
            )
        )
    else:
        valid_status = (
            lock_kind == "retired"
            and reason is not None
            and not reanchor_pending
            and triple_absent
        )
    if not valid_status:
        raise _RootWireError("root status tuple is inconsistent")
    return result


def _snapshot_envelope(snapshot: Any) -> dict[str, Any]:
    return {"schema": SNAPSHOT_SCHEMA, "snapshot": _snapshot_payload(snapshot)}


def _mutation_envelope(result: Any) -> dict[str, Any]:
    if not isinstance(result, RootMutationResult):
        # Test doubles and future compatible implementations may use the same
        # frozen attribute contract without subclassing the concrete dataclass.
        if not all(hasattr(result, name) for name in ("snapshot", "applied", "recovered")):
            raise _RootWireError("root mutation result is invalid")
    applied = getattr(result, "applied", None)
    recovered = getattr(result, "recovered", None)
    if type(applied) is not bool or type(recovered) is not bool:
        raise _RootWireError("root mutation flags are invalid")
    return {
        "schema": MUTATION_SCHEMA,
        "snapshot": _snapshot_payload(getattr(result, "snapshot")),
        "applied": applied,
        "recovered": recovered,
    }


def _invoke_root(root_provider: Callable[[], _RootLike], path: str, values: dict[str, Any]) -> Any:
    root = root_provider()
    if root is None:
        raise InstallationRootUnavailable("installation root is unavailable")
    if path == SNAPSHOT_PATH:
        return root.snapshot()
    if path == DESKTOP_BIND_PATH:
        return root.bind_component("desktop", **values)  # type: ignore[attr-defined]
    if path == DESKTOP_VERIFY_PATH:
        return root.verify_component("desktop", **values)  # type: ignore[attr-defined]
    if path == DESKTOP_ADVANCE_PATH:
        return root.advance_component("desktop", **values)  # type: ignore[attr-defined]
    if path == DESKTOP_RECOVERY_ACK_PATH:
        return root.acknowledge_component_recovery(  # type: ignore[attr-defined]
            "desktop", **values
        )
    if path == UPDATER_VERIFY_PATH:
        return root.verify_updater(**values)  # type: ignore[attr-defined]
    if path == UPDATER_ADVANCE_PATH:
        return root.advance_updater(**values)  # type: ignore[attr-defined]
    raise _InvalidRequest("request path is not allowed")


class InstallationRootDispatcher:
    """One boot-session-scoped, replay-protected private ASGI dispatcher."""

    __slots__ = ("_boot_token", "_nonce_registry", "_now_ms", "_root_provider")

    def __init__(
        self,
        *,
        root: _RootLike | Callable[[], _RootLike],
        boot_token: str,
        nonce_registry: NonceRegistry | None = None,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(boot_token, str) or _HEX_64.fullmatch(boot_token) is None:
            raise InstallationRootAPIConfigurationError(
                "installation-root boot token must be exact lower-case hex"
            )
        if nonce_registry is not None and not isinstance(nonce_registry, NonceRegistry):
            raise InstallationRootAPIConfigurationError(
                "installation-root nonce registry is invalid"
            )
        if now_ms is not None and not callable(now_ms):
            raise InstallationRootAPIConfigurationError(
                "installation-root clock is invalid"
            )
        self._boot_token = boot_token
        self._nonce_registry = nonce_registry or NonceRegistry()
        self._now_ms = now_ms
        self._root_provider = root if callable(root) else lambda: root

    async def _send(
        self,
        send: ASGISend,
        *,
        status: int,
        payload: Mapping[str, Any],
        request_nonce: str | None,
    ) -> None:
        body = _compact_json(payload)
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        if request_nonce is not None:
            signed = sign_response(
                boot_token=self._boot_token,
                request_nonce=request_nonce,
                status=status,
                body=body,
            )
            headers.extend(
                (name.encode("ascii"), value.encode("ascii"))
                for name, value in signed.headers.items()
            )
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _error(
        self,
        send: ASGISend,
        *,
        status: int,
        code: str,
        request_nonce: str | None = None,
    ) -> None:
        if code not in _ERROR_CODES:
            code = "internal_error"
            status = 500
        await self._send(
            send,
            status=status,
            payload={"schema": ERROR_SCHEMA, "code": code},
            request_nonce=request_nonce,
        )

    async def __call__(
        self, scope: ASGIScope, receive: ASGIReceive, send: ASGISend
    ) -> None:
        authenticated_nonce: str | None = None
        response_started = False
        raw_send = send

        async def guarded_send(message: ASGIMessage) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                if response_started:
                    raise RuntimeError("installation-root response already started")
                # Mark before awaiting: if the server fails while accepting the
                # start event, its commitment state is unknown and retrying a
                # second status line would be unsafe.
                response_started = True
            await raw_send(message)

        send = guarded_send
        try:
            method, path = validate_asgi_loopback_scope(
                scope, allowed_paths=INSTALLATION_ROOT_ROUTES
            )
            if INSTALLATION_ROOT_ROUTES.get(path) != method:
                raise _InvalidRequest("request route is not allowed")
            headers = _raw_headers(scope)
            declared_length = _validate_transport_headers(headers, method)
            body = await _read_request_body(receive, declared_length=declared_length)

            candidate_nonce: str | None = None
            try:
                extracted = extract_single_headers(headers, REQUEST_HEADER_NAMES)
                candidate = extracted[HEADER_NONCE]
                if _HEX_64.fullmatch(candidate) is not None:
                    candidate_nonce = candidate
            except InstallationRootProtocolError:
                candidate_nonce = None

            verify_kwargs: dict[str, Any] = {}
            if self._now_ms is not None:
                verify_kwargs["now_ms"] = self._now_ms()
            try:
                authenticated = verify_request(
                    boot_token=self._boot_token,
                    method=method,
                    path=path,
                    headers=headers,
                    body=body,
                    nonce_registry=self._nonce_registry,
                    **verify_kwargs,
                )
            except (NonceReplayError, NonceCapacityError):
                await self._error(
                    send,
                    status=409,
                    code="replay_rejected",
                    request_nonce=candidate_nonce,
                )
                return
            except (
                InstallationRootAuthenticationError,
                InstallationRootTimestampError,
                InstallationRootProtocolError,
            ):
                await self._error(
                    send, status=401, code="authentication_failed"
                )
                return
            authenticated_nonce = authenticated.nonce

            if _headers_contain_secret(headers, self._boot_token.encode("ascii")):
                raise _InvalidRequest("boot token is forbidden in request headers")

            values = _parse_request(
                path, body, forbidden_string=self._boot_token
            )
            try:
                result = await run_in_threadpool(
                    _invoke_root, self._root_provider, path, values
                )
                envelope = (
                    _snapshot_envelope(result)
                    if path == SNAPSHOT_PATH
                    else _mutation_envelope(result)
                )
            except _InvalidRequest:
                raise
            except InstallationRootLocked:
                await self._error(
                    send,
                    status=423,
                    code="root_locked",
                    request_nonce=authenticated_nonce,
                )
                return
            except InstallationRootUnavailable:
                await self._error(
                    send,
                    status=503,
                    code="root_unavailable",
                    request_nonce=authenticated_nonce,
                )
                return
            except _RootWireError:
                await self._error(
                    send,
                    status=503,
                    code="root_unavailable",
                    request_nonce=authenticated_nonce,
                )
                return
            except Exception:
                await self._error(
                    send,
                    status=500,
                    code="internal_error",
                    request_nonce=authenticated_nonce,
                )
                return

            await self._send(
                send,
                status=200,
                payload=envelope,
                request_nonce=authenticated_nonce,
            )
        except (LoopbackPolicyError, _InvalidRequest):
            if response_started:
                raise
            await self._error(
                send,
                status=400,
                code="invalid_request",
                request_nonce=authenticated_nonce,
            )
        except Exception:
            if response_started:
                raise
            await self._error(
                send,
                status=500,
                code="internal_error",
                request_nonce=authenticated_nonce,
            )


def create_installation_root_dispatcher(
    *,
    root: _RootLike | Callable[[], _RootLike],
    boot_token: str,
    nonce_registry: NonceRegistry | None = None,
    now_ms: Callable[[], int] | None = None,
) -> InstallationRootDispatcher:
    """Create one boot-session-scoped dispatcher without global side effects."""

    return InstallationRootDispatcher(
        root=root,
        boot_token=boot_token,
        nonce_registry=nonce_registry,
        now_ms=now_ms,
    )


__all__ = [
    "DESKTOP_ADVANCE_PATH",
    "DESKTOP_BIND_PATH",
    "DESKTOP_RECOVERY_ACK_PATH",
    "DESKTOP_VERIFY_PATH",
    "ERROR_SCHEMA",
    "INSTALLATION_ROOT_ROUTES",
    "InstallationRootAPIConfigurationError",
    "InstallationRootDispatcher",
    "JSON_BYTE_LIMIT",
    "MAX_JS_SAFE_INTEGER",
    "MUTATION_SCHEMA",
    "SNAPSHOT_PATH",
    "SNAPSHOT_SCHEMA",
    "UPDATER_ADVANCE_PATH",
    "UPDATER_VERIFY_PATH",
    "create_installation_root_dispatcher",
]
