"""LOCAL-only installed child drain protocol and ordering primitives.

This module deliberately does not discover an Installation Root, open a vault,
register a service, or contact a real channel.  It defines the authenticated
frame, child-side claim/admission fence, and parent ordering contract which a
later reviewed Service Runtime may bind to protected cross-process transport.
The production NachuanCore host continues to use ``EmptyServiceRuntime``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from functools import wraps
from types import MappingProxyType
from typing import Callable, Mapping

from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


_HEX64 = re.compile(r"[0-9a-f]{64}")
_ROLES = ("engine", "weixin", "feishu")
_CHANNEL_ROLES = ("weixin", "feishu")
_ACTIONS = frozenset({"close_claims", "close_admission", "exit"})
_PHASES = frozenset(
    {"running", "claims_closed", "admission_closed", "drained", "exit_requested"}
)
_SCHEMA = "nachuan.installed-channel-drain-frame.v1"
_KEY_DOMAIN = b"nachuan-installed-channel-drain-role-key-v1\x00"


class InstalledChannelDrainContractError(RuntimeError):
    """One drain frame, receipt, state transition, or identity is invalid."""


class InstalledChannelDrainTimeout(InstalledChannelDrainContractError):
    """The shared graceful-drain deadline expired before a safe receipt."""


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InstalledChannelDrainContractError(f"{field} is invalid")
    return value


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InstalledChannelDrainContractError(f"{field} is invalid")
    return value


def _hex64(value: object, field: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise InstalledChannelDrainContractError(f"{field} is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise InstalledChannelDrainContractError("drain frame is invalid") from exc


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate drain frame key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class InstalledDrainBinding:
    installation_id: str
    installation_epoch: int
    config_generation: int
    service_boot_id: str

    def __post_init__(self) -> None:
        _hex64(self.installation_id, "installation id")
        _positive_int(self.installation_epoch, "installation epoch")
        _positive_int(self.config_generation, "config generation")
        _hex64(self.service_boot_id, "service boot id")


@dataclass(frozen=True, slots=True)
class InstalledDrainOperation:
    binding: InstalledDrainBinding
    stop_id: str
    stop_generation: int
    deadline_utc_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.binding, InstalledDrainBinding):
            raise InstalledChannelDrainContractError("drain binding is invalid")
        _hex64(self.stop_id, "stop id")
        _positive_int(self.stop_generation, "stop generation")
        _positive_int(self.deadline_utc_ns, "drain deadline")


@dataclass(frozen=True, slots=True)
class InstalledDrainCommand:
    operation: InstalledDrainOperation
    action: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation, InstalledDrainOperation)
            or self.action not in _ACTIONS
        ):
            raise InstalledChannelDrainContractError("drain command is invalid")


@dataclass(frozen=True, slots=True)
class InstalledDrainRoleReceipt:
    operation: InstalledDrainOperation
    role: str
    process: InstalledChannelProcessReceipt
    phase: str
    claim_gate_closed: bool
    admission_closed: bool
    active_claims: int
    active_requests: int
    active_background_jobs: int
    provider_open_calls: int
    unknown_unpersisted: int
    submitted_unknown: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation, InstalledDrainOperation)
            or self.role not in _ROLES
            or not isinstance(self.process, InstalledChannelProcessReceipt)
            or self.phase not in _PHASES
            or type(self.claim_gate_closed) is not bool
            or type(self.admission_closed) is not bool
        ):
            raise InstalledChannelDrainContractError("drain receipt is invalid")
        for field in (
            "active_claims",
            "active_requests",
            "active_background_jobs",
            "provider_open_calls",
            "unknown_unpersisted",
            "submitted_unknown",
        ):
            _nonnegative_int(getattr(self, field), field.replace("_", " "))
        if self.role == "engine":
            if self.claim_gate_closed or self.active_claims:
                raise InstalledChannelDrainContractError("engine drain receipt is invalid")
            if self.phase in {"admission_closed", "drained", "exit_requested"} and not self.admission_closed:
                raise InstalledChannelDrainContractError("engine admission receipt is invalid")
            if self.phase == "claims_closed":
                raise InstalledChannelDrainContractError("engine drain phase is invalid")
        else:
            if self.admission_closed or self.active_requests or self.active_background_jobs:
                raise InstalledChannelDrainContractError("channel drain receipt is invalid")
            if self.phase in {"claims_closed", "drained", "exit_requested"} and not self.claim_gate_closed:
                raise InstalledChannelDrainContractError("channel claim receipt is invalid")
            if self.phase == "admission_closed":
                raise InstalledChannelDrainContractError("channel drain phase is invalid")
        if self.phase == "running" and (
            self.claim_gate_closed or self.admission_closed
        ):
            raise InstalledChannelDrainContractError("running drain receipt is invalid")
        if self.phase in {"drained", "exit_requested"} and any(
            (
                self.active_claims,
                self.active_requests,
                self.active_background_jobs,
                self.provider_open_calls,
                self.unknown_unpersisted,
            )
        ):
            raise InstalledChannelDrainContractError("drained receipt is not quiescent")


@dataclass(frozen=True, slots=True)
class InstalledDrainPermit:
    kind: str
    permit_id: int
    generation: int

    def __post_init__(self) -> None:
        if self.kind not in {"claim", "admission", "background", "provider"}:
            raise InstalledChannelDrainContractError("drain permit is invalid")
        _positive_int(self.permit_id, "permit id")
        _nonnegative_int(self.generation, "permit generation")


@dataclass(frozen=True, slots=True)
class InstalledDrainUnknownPersistenceReceipt:
    operation: InstalledDrainOperation
    role: str
    process: InstalledChannelProcessReceipt
    provider_permit_id: int
    work_permit_id: int
    ledger_generation: int
    record_sha256: str
    outcome: str
    retry_safe: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation, InstalledDrainOperation)
            or self.role not in _ROLES
            or not isinstance(self.process, InstalledChannelProcessReceipt)
            or self.outcome != "submitted_unknown"
            or self.retry_safe is not False
        ):
            raise InstalledChannelDrainContractError(
                "unknown persistence receipt is invalid"
            )
        _positive_int(self.provider_permit_id, "provider permit id")
        _positive_int(self.work_permit_id, "work permit id")
        _positive_int(self.ledger_generation, "ledger generation")
        _hex64(self.record_sha256, "unknown record digest")


@dataclass(frozen=True, slots=True)
class InstalledDrainSummary:
    operation: InstalledDrainOperation
    business_drained: bool
    exit_acknowledged: bool
    submitted_unknown: int
    action_sequence: tuple[str, ...]
    role_receipts: Mapping[str, InstalledDrainRoleReceipt]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation, InstalledDrainOperation)
            or type(self.business_drained) is not bool
            or type(self.exit_acknowledged) is not bool
            or not isinstance(self.action_sequence, tuple)
            or any(not isinstance(value, str) for value in self.action_sequence)
            or not isinstance(self.role_receipts, Mapping)
            or set(self.role_receipts) != set(_ROLES)
            or any(
                not isinstance(receipt, InstalledDrainRoleReceipt)
                for receipt in self.role_receipts.values()
            )
        ):
            raise InstalledChannelDrainContractError("drain summary is invalid")
        _nonnegative_int(self.submitted_unknown, "submitted unknown")
        if not self.business_drained or not self.exit_acknowledged:
            raise InstalledChannelDrainContractError("drain summary is incomplete")
        if any(
            receipt.phase != "exit_requested"
            for receipt in self.role_receipts.values()
        ):
            raise InstalledChannelDrainContractError("drain exit receipt is incomplete")
        if self.submitted_unknown != sum(
            receipt.submitted_unknown for receipt in self.role_receipts.values()
        ):
            raise InstalledChannelDrainContractError(
                "drain unknown summary is inconsistent"
            )


def _binding_document(binding: InstalledDrainBinding) -> dict[str, object]:
    return {
        "installation_id": binding.installation_id,
        "installation_epoch": binding.installation_epoch,
        "config_generation": binding.config_generation,
        "service_boot_id": binding.service_boot_id,
    }


def _operation_document(operation: InstalledDrainOperation) -> dict[str, object]:
    return {
        "binding": _binding_document(operation.binding),
        "stop_id": operation.stop_id,
        "stop_generation": operation.stop_generation,
        "deadline_utc_ns": operation.deadline_utc_ns,
    }


def _process_document(process: InstalledChannelProcessReceipt) -> dict[str, object]:
    return {
        "pid": process.pid,
        "started_utc_ticks": process.started_utc_ticks,
        "command_line_sha256": process.command_line_sha256,
    }


def _binding_from_document(value: object) -> InstalledDrainBinding:
    if not isinstance(value, dict) or set(value) != {
        "installation_id",
        "installation_epoch",
        "config_generation",
        "service_boot_id",
    }:
        raise InstalledChannelDrainContractError("drain binding is invalid")
    return InstalledDrainBinding(**value)


def _operation_from_document(value: object) -> InstalledDrainOperation:
    if not isinstance(value, dict) or set(value) != {
        "binding",
        "stop_id",
        "stop_generation",
        "deadline_utc_ns",
    }:
        raise InstalledChannelDrainContractError("drain operation is invalid")
    return InstalledDrainOperation(
        binding=_binding_from_document(value["binding"]),
        stop_id=value["stop_id"],
        stop_generation=value["stop_generation"],
        deadline_utc_ns=value["deadline_utc_ns"],
    )


def _process_from_document(value: object) -> InstalledChannelProcessReceipt:
    if not isinstance(value, dict) or set(value) != {
        "pid",
        "started_utc_ticks",
        "command_line_sha256",
    }:
        raise InstalledChannelDrainContractError("drain process identity is invalid")
    try:
        return InstalledChannelProcessReceipt(**value)
    except Exception as exc:
        raise InstalledChannelDrainContractError(
            "drain process identity is invalid"
        ) from exc


def derive_installed_drain_role_key(
    *,
    control_key: bytes,
    binding: InstalledDrainBinding,
    role: str,
    process: InstalledChannelProcessReceipt,
) -> bytes:
    """Derive one child key; the machine-vault control root stays in the parent."""

    if (
        not isinstance(control_key, bytes)
        or len(control_key) != 32
        or not any(control_key)
        or not isinstance(binding, InstalledDrainBinding)
        or role not in _ROLES
        or not isinstance(process, InstalledChannelProcessReceipt)
    ):
        raise InstalledChannelDrainContractError("drain key identity is invalid")
    identity = {
        "binding": _binding_document(binding),
        "role": role,
        "process": _process_document(process),
    }
    return hmac.new(
        control_key,
        _KEY_DOMAIN + _canonical(identity),
        hashlib.sha256,
    ).digest()


class InstalledDrainProtocol:
    """Strict HMAC frame codec with one sequence space per direction."""

    def __init__(
        self,
        *,
        role_key: bytes,
        binding: InstalledDrainBinding,
        role: str,
        process: InstalledChannelProcessReceipt,
    ) -> None:
        if (
            not isinstance(role_key, bytes)
            or len(role_key) != 32
            or not any(role_key)
            or not isinstance(binding, InstalledDrainBinding)
            or role not in _ROLES
            or not isinstance(process, InstalledChannelProcessReceipt)
        ):
            raise InstalledChannelDrainContractError("drain protocol identity is invalid")
        self._key = role_key
        self._binding = binding
        self._role = role
        self._process = process
        self._send = {"parent_to_child": 0, "child_to_parent": 0}
        self._received = {"parent_to_child": 0, "child_to_parent": 0}
        self._lock = threading.RLock()

    def _encode(self, *, direction: str, kind: str, body: dict[str, object]) -> bytes:
        with self._lock:
            self._send[direction] += 1
            frame = {
                "schema": _SCHEMA,
                "direction": direction,
                "sequence": self._send[direction],
                "role": self._role,
                "binding": _binding_document(self._binding),
                "process": _process_document(self._process),
                "kind": kind,
                "body": body,
            }
            payload = _canonical(frame)
            envelope = {
                "frame": frame,
                "authentication": hmac.new(
                    self._key, payload, hashlib.sha256
                ).hexdigest(),
            }
            return _canonical(envelope)

    def _decode(self, raw: bytes, *, direction: str, kind: str) -> dict[str, object]:
        try:
            if not isinstance(raw, bytes) or not raw or len(raw) > 16_384:
                raise ValueError("invalid bytes")
            envelope = json.loads(
                raw.decode("ascii"),
                object_pairs_hook=_strict_json_object,
            )
            if raw != _canonical(envelope):
                raise ValueError("non-canonical envelope")
            if not isinstance(envelope, dict) or set(envelope) != {
                "frame",
                "authentication",
            }:
                raise ValueError("invalid envelope")
            frame = envelope["frame"]
            supplied = envelope["authentication"]
            if not isinstance(frame, dict) or not isinstance(supplied, str):
                raise ValueError("invalid envelope")
            expected = hmac.new(
                self._key, _canonical(frame), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(supplied, expected):
                raise ValueError("invalid mac")
        except InstalledChannelDrainContractError:
            raise
        except Exception as exc:
            raise InstalledChannelDrainContractError(
                "drain frame authentication failed"
            ) from exc
        required = {
            "schema",
            "direction",
            "sequence",
            "role",
            "binding",
            "process",
            "kind",
            "body",
        }
        if (
            set(frame) != required
            or frame["schema"] != _SCHEMA
            or frame["direction"] != direction
            or frame["kind"] != kind
            or frame["role"] != self._role
            or _binding_from_document(frame["binding"]) != self._binding
            or _process_from_document(frame["process"]) != self._process
            or not isinstance(frame["body"], dict)
        ):
            raise InstalledChannelDrainContractError("drain frame identity is invalid")
        sequence = _positive_int(frame["sequence"], "drain sequence")
        with self._lock:
            if sequence != self._received[direction] + 1:
                raise InstalledChannelDrainContractError(
                    "drain frame sequence is invalid"
                )
            self._received[direction] = sequence
        return frame["body"]

    def encode_command(self, command: InstalledDrainCommand) -> bytes:
        if (
            not isinstance(command, InstalledDrainCommand)
            or command.operation.binding != self._binding
        ):
            raise InstalledChannelDrainContractError("drain command is invalid")
        return self._encode(
            direction="parent_to_child",
            kind="command",
            body={
                "operation": _operation_document(command.operation),
                "action": command.action,
            },
        )

    def decode_command(self, raw: bytes) -> InstalledDrainCommand:
        body = self._decode(raw, direction="parent_to_child", kind="command")
        if set(body) != {"operation", "action"}:
            raise InstalledChannelDrainContractError("drain command is invalid")
        command = InstalledDrainCommand(
            operation=_operation_from_document(body["operation"]),
            action=body["action"],
        )
        if command.operation.binding != self._binding:
            raise InstalledChannelDrainContractError("drain command binding is invalid")
        return command

    def encode_receipt(self, receipt: InstalledDrainRoleReceipt) -> bytes:
        if (
            not isinstance(receipt, InstalledDrainRoleReceipt)
            or receipt.role != self._role
            or receipt.process != self._process
            or receipt.operation.binding != self._binding
        ):
            raise InstalledChannelDrainContractError("drain receipt identity is invalid")
        body = {
            "operation": _operation_document(receipt.operation),
            "phase": receipt.phase,
            "claim_gate_closed": receipt.claim_gate_closed,
            "admission_closed": receipt.admission_closed,
            "active_claims": receipt.active_claims,
            "active_requests": receipt.active_requests,
            "active_background_jobs": receipt.active_background_jobs,
            "provider_open_calls": receipt.provider_open_calls,
            "unknown_unpersisted": receipt.unknown_unpersisted,
            "submitted_unknown": receipt.submitted_unknown,
        }
        return self._encode(
            direction="child_to_parent", kind="receipt", body=body
        )

    def decode_receipt(self, raw: bytes) -> InstalledDrainRoleReceipt:
        body = self._decode(raw, direction="child_to_parent", kind="receipt")
        expected = {
            "operation",
            "phase",
            "claim_gate_closed",
            "admission_closed",
            "active_claims",
            "active_requests",
            "active_background_jobs",
            "provider_open_calls",
            "unknown_unpersisted",
            "submitted_unknown",
        }
        if set(body) != expected:
            raise InstalledChannelDrainContractError("drain receipt is invalid")
        receipt = InstalledDrainRoleReceipt(
            operation=_operation_from_document(body.pop("operation")),
            role=self._role,
            process=self._process,
            **body,
        )
        if receipt.operation.binding != self._binding:
            raise InstalledChannelDrainContractError("drain receipt binding is invalid")
        return receipt


class InstalledChildDrainFence:
    """Process-local gate; business ledgers remain the outcome authority."""

    def __init__(
        self,
        *,
        binding: InstalledDrainBinding,
        role: str,
        process: InstalledChannelProcessReceipt,
    ) -> None:
        if (
            not isinstance(binding, InstalledDrainBinding)
            or role not in _ROLES
            or not isinstance(process, InstalledChannelProcessReceipt)
        ):
            raise InstalledChannelDrainContractError("child drain identity is invalid")
        self._binding = binding
        self._role = role
        self._process = process
        self._operation: InstalledDrainOperation | None = None
        self._action: str | None = None
        self._generation = 0
        self._next_permit = 0
        self._pending: dict[int, InstalledDrainPermit] = {}
        self._committed: dict[int, InstalledDrainPermit] = {}
        self._providers: dict[int, tuple[InstalledDrainPermit, InstalledDrainPermit]] = {}
        self._unknown_unpersisted: set[int] = set()
        self._submitted_unknown = 0
        self._lock = threading.RLock()
        self._closing_event = threading.Event()
        self._locally_closed = False

    def fail_closed(self) -> None:
        """Locally stop new work after control loss, without inventing a receipt."""
        with self._lock:
            if not self._locally_closed:
                self._locally_closed = True
                self._generation += 1
                self._pending.clear()
                self._closing_event.set()

    def _new_permit(self, kind: str) -> InstalledDrainPermit | None:
        with self._lock:
            if self._action is not None or self._locally_closed:
                return None
            self._next_permit += 1
            permit = InstalledDrainPermit(
                kind=kind,
                permit_id=self._next_permit,
                generation=self._generation,
            )
            self._pending[permit.permit_id] = permit
            return permit

    def try_begin_claim(self) -> InstalledDrainPermit | None:
        if self._role not in _CHANNEL_ROLES:
            raise InstalledChannelDrainContractError("claim fence role is invalid")
        return self._new_permit("claim")

    def try_begin_admission(self) -> InstalledDrainPermit | None:
        if self._role != "engine":
            raise InstalledChannelDrainContractError("admission fence role is invalid")
        return self._new_permit("admission")

    def try_begin_background(self) -> InstalledDrainPermit | None:
        if self._role != "engine":
            raise InstalledChannelDrainContractError("background fence role is invalid")
        return self._new_permit("background")

    def _commit(self, permit: InstalledDrainPermit, kind: str) -> bool:
        if not isinstance(permit, InstalledDrainPermit) or permit.kind != kind:
            raise InstalledChannelDrainContractError("drain permit is invalid")
        with self._lock:
            current = self._pending.get(permit.permit_id)
            if (
                current != permit
                or permit.generation != self._generation
                or self._action is not None
                or self._locally_closed
            ):
                self._pending.pop(permit.permit_id, None)
                return False
            self._pending.pop(permit.permit_id, None)
            self._committed[permit.permit_id] = permit
            return True

    def commit_claim(self, permit: InstalledDrainPermit) -> bool:
        return self._commit(permit, "claim")

    def commit_admission(self, permit: InstalledDrainPermit) -> bool:
        return self._commit(permit, "admission")

    def commit_background(self, permit: InstalledDrainPermit) -> bool:
        return self._commit(permit, "background")

    def _finish(self, permit: InstalledDrainPermit, kind: str) -> None:
        if not isinstance(permit, InstalledDrainPermit) or permit.kind != kind:
            raise InstalledChannelDrainContractError("drain permit is invalid")
        with self._lock:
            if any(source == permit for _provider, source in self._providers.values()):
                raise InstalledChannelDrainContractError(
                    "provider permit remains active for work"
                )
            if self._committed.pop(permit.permit_id, None) != permit:
                raise InstalledChannelDrainContractError("drain permit is not active")

    def finish_claim(self, permit: InstalledDrainPermit) -> None:
        self._finish(permit, "claim")

    def finish_admission(self, permit: InstalledDrainPermit) -> None:
        self._finish(permit, "admission")

    def finish_background(self, permit: InstalledDrainPermit) -> None:
        self._finish(permit, "background")

    def try_enter_provider(
        self, work_permit: InstalledDrainPermit
    ) -> InstalledDrainPermit | None:
        if (
            not isinstance(work_permit, InstalledDrainPermit)
            or work_permit.kind not in {"claim", "admission", "background"}
        ):
            raise InstalledChannelDrainContractError("provider source permit is invalid")
        with self._lock:
            if (
                self._committed.get(work_permit.permit_id) != work_permit
                or self._locally_closed
                or self._action is not None
                or work_permit.generation != self._generation
            ):
                return None
            self._next_permit += 1
            provider = InstalledDrainPermit(
                kind="provider",
                permit_id=self._next_permit,
                generation=self._generation,
            )
            self._providers[provider.permit_id] = (provider, work_permit)
            return provider

    def _require_provider(
        self, provider_permit: InstalledDrainPermit
    ) -> tuple[InstalledDrainPermit, InstalledDrainPermit]:
        if (
            not isinstance(provider_permit, InstalledDrainPermit)
            or provider_permit.kind != "provider"
        ):
            raise InstalledChannelDrainContractError("provider permit is invalid")
        current = self._providers.get(provider_permit.permit_id)
        if current is None or current[0] != provider_permit:
            raise InstalledChannelDrainContractError("provider permit is not active")
        return current

    def finish_provider(self, provider_permit: InstalledDrainPermit) -> None:
        with self._lock:
            self._require_provider(provider_permit)
            if provider_permit.permit_id in self._unknown_unpersisted:
                raise InstalledChannelDrainContractError(
                    "unknown provider outcome must be persisted"
                )
            self._providers.pop(provider_permit.permit_id)

    def mark_provider_unknown(self, provider_permit: InstalledDrainPermit) -> None:
        with self._lock:
            self._require_provider(provider_permit)
            self._unknown_unpersisted.add(provider_permit.permit_id)

    def persist_provider_unknown(
        self,
        provider_permit: InstalledDrainPermit,
        receipt: InstalledDrainUnknownPersistenceReceipt,
    ) -> None:
        with self._lock:
            _provider, work_permit = self._require_provider(provider_permit)
            if provider_permit.permit_id not in self._unknown_unpersisted:
                raise InstalledChannelDrainContractError(
                    "provider outcome is not marked unknown"
                )
            if (
                not isinstance(receipt, InstalledDrainUnknownPersistenceReceipt)
                or self._operation is None
                or receipt.operation != self._operation
                or receipt.role != self._role
                or receipt.process != self._process
                or receipt.provider_permit_id != provider_permit.permit_id
                or receipt.work_permit_id != work_permit.permit_id
            ):
                raise InstalledChannelDrainContractError(
                    "unknown persistence receipt does not match provider"
                )
            self._unknown_unpersisted.remove(provider_permit.permit_id)
            self._providers.pop(provider_permit.permit_id)
            self._submitted_unknown += 1

    def apply_command(
        self,
        command: InstalledDrainCommand,
    ) -> InstalledDrainRoleReceipt:
        if not isinstance(command, InstalledDrainCommand):
            raise InstalledChannelDrainContractError("drain command is invalid")
        if command.operation.binding != self._binding:
            raise InstalledChannelDrainContractError("drain binding mismatch")
        allowed = (
            {"close_admission", "exit"}
            if self._role == "engine"
            else {"close_claims", "exit"}
        )
        if command.action not in allowed:
            raise InstalledChannelDrainContractError("drain action is invalid for role")
        with self._lock:
            if self._operation is not None and self._operation != command.operation:
                raise InstalledChannelDrainContractError("drain operation conflict")
            if self._operation is None:
                self._operation = command.operation
            if command.action == "exit":
                current = self._snapshot_locked(
                    operation=command.operation,
                )
                if current.phase != "drained":
                    raise InstalledChannelDrainContractError(
                        "drain exit requested before role drained"
                    )
                self._action = "exit"
            elif self._action is None:
                self._action = command.action
                self._generation += 1
                self._pending.clear()
            elif self._action != command.action:
                raise InstalledChannelDrainContractError("drain action conflict")
            self._closing_event.set()
            return self._snapshot_locked(
                operation=command.operation,
            )

    def snapshot(
        self,
        *,
        operation: InstalledDrainOperation,
    ) -> InstalledDrainRoleReceipt:
        with self._lock:
            if self._operation is None or self._operation != operation:
                raise InstalledChannelDrainContractError("drain operation is not active")
            return self._snapshot_locked(
                operation=operation,
            )

    def _snapshot_locked(
        self,
        *,
        operation: InstalledDrainOperation,
    ) -> InstalledDrainRoleReceipt:
        committed = tuple(self._committed.values())
        active_claims = sum(permit.kind == "claim" for permit in committed)
        active_requests = sum(permit.kind == "admission" for permit in committed)
        active_background_jobs = sum(
            permit.kind == "background" for permit in committed
        )
        provider_open_calls = len(self._providers)
        unknown_unpersisted = len(self._unknown_unpersisted)
        claim_closed = self._role in _CHANNEL_ROLES and self._action is not None
        admission_closed = self._role == "engine" and self._action is not None
        drained = (
            not active_claims
            and not active_requests
            and not active_background_jobs
            and not provider_open_calls
            and not unknown_unpersisted
            and (claim_closed or admission_closed)
        )
        if self._action == "exit":
            phase = "exit_requested"
        elif drained:
            phase = "drained"
        elif claim_closed:
            phase = "claims_closed"
        elif admission_closed:
            phase = "admission_closed"
        else:
            phase = "running"
        return InstalledDrainRoleReceipt(
            operation=operation,
            role=self._role,
            process=self._process,
            phase=phase,
            claim_gate_closed=claim_closed,
            admission_closed=admission_closed,
            active_claims=active_claims,
            active_requests=active_requests,
            active_background_jobs=active_background_jobs,
            provider_open_calls=provider_open_calls,
            unknown_unpersisted=unknown_unpersisted,
            submitted_unknown=self._submitted_unknown,
        )


class InstalledChannelClaimTracker:
    """Bind durable queue claims to one process's drain generation.

    The fence lock covers SQLite COMMIT, so closing ingress and acquiring new
    work have a single ordering. Only a proven durable finish releases a claim.
    A lost finish response can also be released after ClaimLeaseSession's exact
    read-back confirms it. No configured fence preserves source-runtime behavior.
    """

    def __init__(self, role: str) -> None:
        if role not in _CHANNEL_ROLES:
            raise InstalledChannelDrainContractError("claim tracker role is invalid")
        self._role = role
        self._fence: InstalledChildDrainFence | None = None
        self._active: dict[tuple, tuple[InstalledChildDrainFence, InstalledDrainPermit]] = {}
        self._lock = threading.RLock()

    def bind(self, fence: InstalledChildDrainFence) -> None:
        if not isinstance(fence, InstalledChildDrainFence) or fence._role != self._role:
            raise InstalledChannelDrainContractError("claim tracker fence is invalid")
        with self._lock:
            if self._fence is not None and self._fence is not fence:
                raise InstalledChannelDrainContractError("claim tracker generation is bound")
            self._fence = fence

    def commit(self, key: tuple, commit_transaction: Callable[[], object]) -> bool:
        if not isinstance(key, tuple) or not callable(commit_transaction):
            raise InstalledChannelDrainContractError("claim commit input is invalid")
        with self._lock:
            fence = self._fence
            if fence is None:
                commit_transaction()
                return True
            if key in self._active:
                raise InstalledChannelDrainContractError("claim identity is already active")
            with fence._lock:
                permit = fence.try_begin_claim()
                if permit is None or not fence.commit_claim(permit):
                    return False
                try:
                    commit_transaction()
                except BaseException:
                    # The worker has not received the claim, so no business
                    # side effect can have started. The queue owns DB recovery.
                    fence.finish_claim(permit)
                    raise
                self._active[key] = (fence, permit)
                return True

    def wait_for_close(self, timeout: float, *, stop_event=None) -> bool:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 <= timeout <= 30
        ):
            raise InstalledChannelDrainContractError("claim wait timeout is invalid")
        with self._lock:
            fence = self._fence
        if stop_event is not None:
            if not callable(getattr(stop_event, "is_set", None)) or not callable(
                getattr(stop_event, "wait", None)
            ):
                raise InstalledChannelDrainContractError("claim stop event is invalid")
            deadline = time.monotonic() + timeout
            while True:
                if stop_event.is_set():
                    return True
                if fence is not None and fence._closing_event.is_set():
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if stop_event.wait(min(remaining, 0.25)):
                    return True
        if fence is not None:
            return fence._closing_event.wait(timeout)
        if timeout:
            time.sleep(timeout)
        return False

    def finish(self, key: tuple) -> None:
        with self._lock:
            active = self._active.get(key)
            if active is None:
                return
            fence, permit = active
            fence.finish_claim(permit)
            del self._active[key]

    def finishes(self, key_for_call):
        def decorate(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                result = function(*args, **kwargs)
                if result is True:
                    self.finish(key_for_call(*args, **kwargs))
                return result
            return wrapped
        return decorate


class InstalledParentDrainCoordinator:
    """Order channel claim closure before Gateway admission closure."""

    def __init__(
        self,
        *,
        operation: InstalledDrainOperation,
        processes: Mapping[str, InstalledChannelProcessReceipt],
        endpoints: Mapping[str, object],
        monotonic_clock: Callable[[], float] = time.monotonic,
        utc_ns_clock: Callable[[], int] = time.time_ns,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            not isinstance(operation, InstalledDrainOperation)
            or not isinstance(processes, Mapping)
            or set(processes) != set(_ROLES)
            or any(
                not isinstance(processes[role], InstalledChannelProcessReceipt)
                for role in _ROLES
            )
            or not isinstance(endpoints, Mapping)
            or set(endpoints) != set(_ROLES)
            or any(
                not callable(getattr(endpoints[role], "request", None))
                or not callable(getattr(endpoints[role], "snapshot", None))
                for role in _ROLES
            )
            or not callable(monotonic_clock)
            or not callable(utc_ns_clock)
            or not callable(sleeper)
        ):
            raise InstalledChannelDrainContractError("parent drain input is invalid")
        self._operation = operation
        self._processes = dict(processes)
        self._endpoints = dict(endpoints)
        self._clock = monotonic_clock
        self._utc_ns_clock = utc_ns_clock
        self._sleep = sleeper
        self._lock = threading.Lock()
        self._result: InstalledDrainSummary | None = None
        self._last_monotonic: float | None = None

    @property
    def operation(self) -> InstalledDrainOperation:
        return self._operation

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except Exception as exc:
            raise InstalledChannelDrainContractError(
                "drain monotonic clock is unavailable"
            ) from exc
        if not math.isfinite(value):
            raise InstalledChannelDrainContractError("drain monotonic clock is invalid")
        if self._last_monotonic is not None and value < self._last_monotonic:
            raise InstalledChannelDrainContractError("drain monotonic clock moved backwards")
        self._last_monotonic = value
        return value

    def _utc_now_ns(self) -> int:
        try:
            value = self._utc_ns_clock()
        except Exception as exc:
            raise InstalledChannelDrainContractError(
                "drain UTC clock is unavailable"
            ) from exc
        return _positive_int(value, "drain UTC clock")

    def _request(self, role: str, action: str, sequence: list[str]) -> None:
        command = InstalledDrainCommand(operation=self._operation, action=action)
        try:
            result = self._endpoints[role].request(command)
        except Exception as exc:
            raise InstalledChannelDrainContractError(
                f"{role} drain command failed"
            ) from exc
        if result is not None:
            raise InstalledChannelDrainContractError(
                f"{role} drain command receipt is invalid"
            )
        sequence.append(f"{role}:{action}")

    def _snapshot(self, role: str) -> InstalledDrainRoleReceipt:
        try:
            receipt = self._endpoints[role].snapshot(self._operation)
        except Exception as exc:
            raise InstalledChannelDrainContractError(
                f"{role} drain snapshot failed"
            ) from exc
        if (
            not isinstance(receipt, InstalledDrainRoleReceipt)
            or receipt.operation != self._operation
            or receipt.role != role
            or receipt.process != self._processes[role]
        ):
            raise InstalledChannelDrainContractError(
                f"{role} drain process receipt is invalid"
            )
        return receipt

    def _wait_roles(
        self,
        roles: tuple[str, ...],
        *,
        deadline: float,
        final: dict[str, InstalledDrainRoleReceipt],
        expected_phase: str,
    ) -> None:
        pending = set(roles)
        while pending:
            if self._now() >= deadline:
                raise InstalledChannelDrainTimeout("installed channel drain timed out")
            for role in roles:
                if role not in pending:
                    continue
                receipt = self._snapshot(role)
                final[role] = receipt
                if receipt.phase == expected_phase:
                    pending.remove(role)
            if pending:
                remaining = deadline - self._now()
                if remaining <= 0:
                    raise InstalledChannelDrainTimeout(
                        "installed channel drain timed out"
                    )
                try:
                    self._sleep(min(0.05, remaining))
                except Exception as exc:
                    raise InstalledChannelDrainContractError(
                        "drain wait is unavailable"
                    ) from exc

    def drain(self, *, timeout_ms: int) -> InstalledDrainSummary:
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or not 1 <= timeout_ms <= 30_000
        ):
            raise InstalledChannelDrainContractError("drain timeout is invalid")
        with self._lock:
            if self._result is not None:
                return self._result
            now = self._now()
            utc_remaining_ns = self._operation.deadline_utc_ns - self._utc_now_ns()
            if utc_remaining_ns <= 0:
                raise InstalledChannelDrainTimeout("installed channel drain timed out")
            deadline = min(
                now + timeout_ms / 1000.0,
                now + utc_remaining_ns / 1_000_000_000.0,
            )
            sequence: list[str] = []
            final: dict[str, InstalledDrainRoleReceipt] = {}

            for role in _CHANNEL_ROLES:
                self._request(role, "close_claims", sequence)
            self._wait_roles(
                _CHANNEL_ROLES,
                deadline=deadline,
                final=final,
                expected_phase="drained",
            )

            self._request("engine", "close_admission", sequence)
            self._wait_roles(
                ("engine",),
                deadline=deadline,
                final=final,
                expected_phase="drained",
            )

            for role in (*_CHANNEL_ROLES, "engine"):
                self._request(role, "exit", sequence)
            self._wait_roles(
                _ROLES,
                deadline=deadline,
                final=final,
                expected_phase="exit_requested",
            )

            submitted_unknown = sum(
                receipt.submitted_unknown for receipt in final.values()
            )
            self._result = InstalledDrainSummary(
                operation=self._operation,
                business_drained=True,
                exit_acknowledged=True,
                submitted_unknown=submitted_unknown,
                action_sequence=tuple(sequence),
                role_receipts=MappingProxyType(dict(final)),
            )
            return self._result


__all__ = [
    "InstalledChannelDrainContractError",
    "InstalledChannelDrainTimeout",
    "InstalledChannelClaimTracker",
    "InstalledChildDrainFence",
    "InstalledDrainBinding",
    "InstalledDrainCommand",
    "InstalledDrainOperation",
    "InstalledDrainPermit",
    "InstalledDrainProtocol",
    "InstalledDrainRoleReceipt",
    "InstalledDrainSummary",
    "InstalledDrainUnknownPersistenceReceipt",
    "InstalledParentDrainCoordinator",
    "derive_installed_drain_role_key",
]
