"""Strict service-neutral boundaries for one restricted installation capture.

The adapter methods are operation-scoped and idempotent.  A platform adapter
must durably reconcile an ambiguous return/crash before repeating an external
effect.  Release calls are also operation-scoped, but the coordinator calls
them only for holds present in the append-only journal.

Nothing here proves a Windows service identity, ACL, named pipe, pinned handle,
boot clock, backup readiness, or restore readiness.  Those remain production
adapter and deployment gates.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Literal, Protocol


_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_INT64_MAX = (1 << 63) - 1

CapturePhase = Literal[
    "claimed",
    "fencing",
    "quiescent",
    "root_locked",
    "staging",
    "staged_verified",
    "published",
    "resuming",
    "completed",
    "failed_clean",
    "recovery_required",
]

RecoveryTargetPhase = Literal[
    "staging",
    "staged_verified",
    "published",
    "resuming",
    "failed_clean",
]

CAPTURE_COMPONENT_ORDER = (
    "desktop",
    "gateway",
    "gateway_assets",
    "channel_media",
)


def require_digest(value: object, label: str = "restricted capture digest") -> str:
    if (
        not isinstance(value, str)
        or _DIGEST_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ValueError(f"{label} is invalid")
    return value


def require_counter(value: object, label: str, *, minimum: int = 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= _INT64_MAX
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _derived_digest(domain: bytes, operation_digest: str) -> str:
    return sha256(domain + bytes.fromhex(operation_digest)).hexdigest()


@dataclass(frozen=True, slots=True)
class RestrictedCaptureRequest:
    requester_sid_digest: str
    installation_id: str
    epoch: int
    root_revision: int
    operation_digest: str

    def __post_init__(self) -> None:
        require_digest(self.requester_sid_digest, "requester SID digest")
        require_digest(self.installation_id, "installation id")
        require_counter(self.epoch, "installation epoch")
        require_counter(self.root_revision, "installation root revision")
        require_digest(self.operation_digest, "restricted capture operation")

    @property
    def snapshot_id(self) -> str:
        return "snapshot-" + _derived_digest(
            b"nachuan.restricted-capture.snapshot-id.v1\0",
            self.operation_digest,
        )

    @property
    def maintenance_reason_digest(self) -> str:
        return _derived_digest(
            b"nachuan.restricted-capture.maintenance-reason.v1\0",
            self.operation_digest,
        )


@dataclass(frozen=True, slots=True)
class RestrictedCaptureRootLockResult:
    locked_root_revision: int
    root_snapshot_digest: str
    root_lock_evidence_digest: str

    def __post_init__(self) -> None:
        require_counter(self.locked_root_revision, "locked Root revision")
        require_digest(self.root_snapshot_digest, "Root snapshot digest")
        require_digest(self.root_lock_evidence_digest, "Root lock evidence")


@dataclass(frozen=True, slots=True)
class RestrictedCaptureStageResult:
    artifact_set_digest: str
    staging_evidence_digest: str

    def __post_init__(self) -> None:
        require_digest(self.artifact_set_digest, "artifact set digest")
        require_digest(self.staging_evidence_digest, "staging evidence")


@dataclass(frozen=True, slots=True)
class RestrictedCaptureVerifiedStageResult:
    artifact_set_digest: str
    manifest_sha256: str
    verification_evidence_digest: str

    def __post_init__(self) -> None:
        require_digest(self.artifact_set_digest, "artifact set digest")
        require_digest(self.manifest_sha256, "manifest digest")
        require_digest(self.verification_evidence_digest, "verification evidence")


@dataclass(frozen=True, slots=True)
class RestrictedCapturePublishedResult:
    artifact_set_digest: str
    manifest_sha256: str
    publication_evidence_digest: str

    def __post_init__(self) -> None:
        require_digest(self.artifact_set_digest, "artifact set digest")
        require_digest(self.manifest_sha256, "manifest digest")
        require_digest(self.publication_evidence_digest, "publication evidence")


@dataclass(frozen=True, slots=True)
class RestrictedCaptureRecoveryDecision:
    """A service-only adapter decision backed by a fully re-verified checkpoint."""

    target_phase: RecoveryTargetPhase
    checkpoint: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.target_phase not in {
            "staging",
            "staged_verified",
            "published",
            "resuming",
            "failed_clean",
        }:
            raise ValueError("restricted capture recovery target is invalid")
        if not isinstance(self.checkpoint, Mapping):
            raise ValueError("restricted capture recovery checkpoint is invalid")


class MaintenanceTicketAuthority(Protocol):
    def claim(
        self,
        secret: str,
        *,
        requester_sid_digest: str,
        installation_id: str,
        epoch: int,
        root_revision: int,
        operation_digest: str,
    ) -> bool: ...

    def finish(self, secret: str, *, success: bool) -> bool: ...


class RestrictedCaptureRecoveryAuthority(Protocol):
    """Internal service authority; it must never be exposed as a public caller API."""

    def authorize_recovery(
        self,
        request: RestrictedCaptureRequest,
        *,
        journal_revision: int,
        last_receipt_digest: str,
    ) -> str: ...


class RestrictedCaptureTicketFinalizationAuthority(Protocol):
    """Service-only exact-binding reconciliation for an already claimed ticket.

    Implementations must update only the still-``claimed`` ticket whose full
    binding matches the request.  They must be idempotent for the requested
    terminal value and must never revive prepared, consumed, failed, expired,
    foreign-boot, or differently-bound tickets.
    """

    def is_claimed_operation(self, request: RestrictedCaptureRequest) -> bool:
        """Confirm one unambiguous, active-boot claimed ticket for ``request``."""

        ...

    def finalize_claimed_operation(
        self,
        request: RestrictedCaptureRequest,
        *,
        success: bool,
    ) -> bool: ...


class RestrictedCaptureAdapter(Protocol):
    """Operation-scoped, idempotent external-effect boundary.

    ``begin_drain`` must be called for every component in fixed order before
    any ``await_quiescent`` call.  Each returned digest is a durable,
    re-verifiable adapter receipt.  Repeating a method for the same operation
    must reconcile and return the same semantic result rather than duplicate
    an effect.

    ``resume_root``, ``release_component``, and ``release_global`` are also
    conservative recovery primitives: they must be idempotent and safe when
    the named hold may never have been acquired or may already have been
    released.  This permits crash-replay of an outcome-unknown hold before its
    evidence receipt existed; success must still return a stable, re-verifiable
    digest.
    """

    def fence_global(self, request: RestrictedCaptureRequest) -> str: ...

    def begin_drain(
        self,
        request: RestrictedCaptureRequest,
        component: str,
    ) -> str: ...

    def await_quiescent(
        self,
        request: RestrictedCaptureRequest,
        component: str,
    ) -> str: ...

    def reread_root_revision(self, request: RestrictedCaptureRequest) -> int: ...

    def lock_root(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureRootLockResult: ...

    def stage(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureStageResult: ...

    def verify_stage(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureVerifiedStageResult: ...

    def publish(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCapturePublishedResult: ...

    def resume_root(self, request: RestrictedCaptureRequest) -> str: ...

    def release_component(
        self,
        request: RestrictedCaptureRequest,
        component: str,
    ) -> str: ...

    def release_global(self, request: RestrictedCaptureRequest) -> str: ...

    def reconcile_artifacts_for_failed_clean(
        self,
        request: RestrictedCaptureRequest,
        *,
        failed_phase: CapturePhase,
        journal_revision: int,
        last_receipt_digest: str,
    ) -> str:
        """Idempotently clean/reverify partial staging or publication state.

        This is a typed mutation-and-attestation effect, not an arbitrary
        status digest.  A crash may repeat it for the same operation and chain
        binding; it must return stable evidence only after no partial artifact
        can remain active.  Invalid or uncertain output forbids failed_clean.
        """
        ...

    def inspect_recovery(
        self,
        request: RestrictedCaptureRequest,
        *,
        failed_phase: CapturePhase,
        journal_revision: int,
        last_receipt_digest: str,
    ) -> RestrictedCaptureRecoveryDecision: ...


__all__ = [
    "CAPTURE_COMPONENT_ORDER",
    "CapturePhase",
    "MaintenanceTicketAuthority",
    "RecoveryTargetPhase",
    "RestrictedCaptureAdapter",
    "RestrictedCapturePublishedResult",
    "RestrictedCaptureRecoveryAuthority",
    "RestrictedCaptureRecoveryDecision",
    "RestrictedCaptureRequest",
    "RestrictedCaptureRootLockResult",
    "RestrictedCaptureStageResult",
    "RestrictedCaptureTicketFinalizationAuthority",
    "RestrictedCaptureVerifiedStageResult",
    "require_counter",
    "require_digest",
]
