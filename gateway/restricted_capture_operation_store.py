"""Bounded durable journal for the service-neutral restricted capture core.

The mutable operation row is a CAS index over an append-only receipt chain.
Receipts contain a strict, phase-specific canonical checkpoint envelope so a
recovery adapter can re-verify the exact Root, quiescence, artifact, manifest,
and publication evidence.  Ticket secrets and raw SIDs have no storage field.

This module intentionally makes no Windows service, ACL, named-pipe, pinned
handle, backup-readiness, or restore-readiness claim.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from gateway.restricted_capture_contract import (
    CAPTURE_COMPONENT_ORDER,
    CapturePhase,
    RestrictedCaptureRequest,
    require_counter,
    require_digest,
)


_APPLICATION_ID = 0x4E435243  # NCRC
_SCHEMA_VERSION = 1
_ZERO_DIGEST = "0" * 64
_INT64_MAX = (1 << 63) - 1
_RECEIPT_DOMAIN = b"nachuan.restricted-capture.operation-receipt.v2\0"
_CHECKPOINT_DOMAIN = b"nachuan.restricted-capture.checkpoint.v1\0"

MAX_CAPTURE_OPERATIONS = 128
MAX_CAPTURE_RECEIPTS_PER_OPERATION = 32
MAX_CAPTURE_RECEIPTS = MAX_CAPTURE_OPERATIONS * MAX_CAPTURE_RECEIPTS_PER_OPERATION
MAX_CAPTURE_CHECKPOINT_BYTES = 2048
MAX_CAPTURE_RECEIPT_PHYSICAL_BUDGET_BYTES = 12 * 1024
MAX_CAPTURE_STORE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_STORE_FAMILY_BYTES = MAX_CAPTURE_STORE_BYTES * 2
MAX_CAPTURE_WAL_BYTES = MAX_CAPTURE_STORE_BYTES
MAX_CAPTURE_SHM_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_JOURNAL_BYTES = MAX_CAPTURE_STORE_BYTES
CAPTURE_STORE_PAGE_SIZE = 4096
CAPTURE_STORE_MAX_PAGES = MAX_CAPTURE_STORE_BYTES // CAPTURE_STORE_PAGE_SIZE
MIN_EXECUTION_LEASE_MS = 1_000
MAX_EXECUTION_LEASE_MS = 300_000
# The coordinator supplies a phase/action-specific convergence reserve.  One
# is the schema-level minimum, not a fixed policy floor.
MIN_EFFECT_RECEIPT_RESERVE = 1
_ROLLBACK_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

if (
    MAX_CAPTURE_RECEIPTS * MAX_CAPTURE_RECEIPT_PHYSICAL_BUDGET_BYTES
    + MAX_CAPTURE_OPERATIONS * CAPTURE_STORE_PAGE_SIZE
    > MAX_CAPTURE_STORE_BYTES
):  # pragma: no cover - import-time invariant
    raise RuntimeError("restricted capture physical capacity proof is invalid")

_PHASES: tuple[CapturePhase, ...] = (
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
)
_NONTERMINAL_PHASES = frozenset(
    {
        "claimed",
        "fencing",
        "quiescent",
        "root_locked",
        "staging",
        "staged_verified",
        "published",
        "resuming",
    }
)
_NORMAL_TRANSITIONS: dict[CapturePhase, frozenset[CapturePhase]] = {
    "claimed": frozenset({"fencing", "failed_clean", "recovery_required"}),
    "fencing": frozenset({"quiescent", "failed_clean", "recovery_required"}),
    "quiescent": frozenset({"root_locked", "failed_clean", "recovery_required"}),
    "root_locked": frozenset({"staging", "recovery_required"}),
    "staging": frozenset({"staged_verified", "recovery_required"}),
    "staged_verified": frozenset({"published", "recovery_required"}),
    "published": frozenset({"resuming", "recovery_required"}),
    "resuming": frozenset({"completed", "recovery_required"}),
    "completed": frozenset(),
    "failed_clean": frozenset(),
    "recovery_required": frozenset(),
}
_RECOVERY_TRANSITIONS = frozenset(
    {
        "staging",
        "staged_verified",
        "published",
        "resuming",
        "failed_clean",
    }
)

_TRANSITION_CHECKPOINT_KINDS = frozenset(_PHASES)
_HAPPY_PROGRESS_CHECKPOINT_KINDS = frozenset(
    {
        "drain_begun",
        "drain_quiescent",
        "root_resumed",
        "component_released",
        "global_released",
    }
)
_CLEANUP_PROGRESS_CHECKPOINT_KINDS = frozenset(
    {
        "cleanup_root_resumed",
        "cleanup_component_released",
        "cleanup_global_released",
    }
)
_PROGRESS_CHECKPOINT_KINDS = (
    _HAPPY_PROGRESS_CHECKPOINT_KINDS | _CLEANUP_PROGRESS_CHECKPOINT_KINDS
)
_CHECKPOINT_KINDS = _TRANSITION_CHECKPOINT_KINDS | _PROGRESS_CHECKPOINT_KINDS
_CHECKPOINT_KIND_SQL = ",".join(f"'{kind}'" for kind in sorted(_CHECKPOINT_KINDS))

_DIGEST_CHECKPOINT_FIELDS: dict[str, frozenset[str]] = {
    "claimed": frozenset({"claimBindingDigest"}),
    "fencing": frozenset({"globalFenceDigest"}),
    "quiescent": frozenset(
        {
            "quiescenceDigest",
            "desktopEvidenceDigest",
            "gatewayEvidenceDigest",
            "gatewayAssetsEvidenceDigest",
            "channelMediaEvidenceDigest",
        }
    ),
    "root_locked": frozenset(
        {"rootSnapshotDigest", "rootLockEvidenceDigest", "quiescenceDigest"}
    ),
    "staging": frozenset(
        {
            "artifactSetDigest",
            "stagingEvidenceDigest",
            "rootSnapshotDigest",
            "quiescenceDigest",
            "desktopEvidenceDigest",
        }
    ),
    "staged_verified": frozenset(
        {
            "artifactSetDigest",
            "manifestSha256",
            "verificationEvidenceDigest",
            "rootSnapshotDigest",
            "quiescenceDigest",
            "desktopEvidenceDigest",
        }
    ),
    "published": frozenset(
        {
            "artifactSetDigest",
            "manifestSha256",
            "publicationEvidenceDigest",
            "rootSnapshotDigest",
            "quiescenceDigest",
            "desktopEvidenceDigest",
        }
    ),
    "resuming": frozenset({"resumeIntentDigest"}),
    "completed": frozenset({"resumeEvidenceDigest"}),
    "failed_clean": frozenset({"cleanupEvidenceDigest"}),
    "recovery_required": frozenset({"failureDigest"}),
    "drain_begun": frozenset({"beginEvidenceDigest"}),
    "drain_quiescent": frozenset({"quiescenceEvidenceDigest"}),
    "root_resumed": frozenset({"rootResumeEvidenceDigest"}),
    "component_released": frozenset({"releaseEvidenceDigest"}),
    "global_released": frozenset({"globalReleaseEvidenceDigest"}),
    "cleanup_component_released": frozenset({"releaseEvidenceDigest"}),
    "cleanup_global_released": frozenset({"globalReleaseEvidenceDigest"}),
    "cleanup_root_resumed": frozenset({"rootResumeEvidenceDigest"}),
}
_COUNTER_CHECKPOINT_FIELDS: dict[str, frozenset[str]] = {
    "quiescent": frozenset({"observedRootRevision"}),
    "root_locked": frozenset({"lockedRootRevision"}),
    "staging": frozenset({"lockedRootRevision"}),
    "staged_verified": frozenset({"lockedRootRevision"}),
    "published": frozenset({"lockedRootRevision"}),
}
_SNAPSHOT_CHECKPOINT_PHASES = frozenset({"staging", "staged_verified", "published"})

_PHASE_SQL = ",".join(f"'{phase}'" for phase in _PHASES)
_HEX_CHECK = (
    "length({0})=64 AND {0}<>'" + _ZERO_DIGEST + "' "
    "AND {0} NOT GLOB '*[^0-9a-f]*'"
)

_OPERATIONS_DDL = f"""
CREATE TABLE capture_operations (
    operation_digest TEXT PRIMARY KEY
        CHECK({_HEX_CHECK.format('operation_digest')}),
    requester_sid_digest TEXT NOT NULL
        CHECK({_HEX_CHECK.format('requester_sid_digest')}),
    installation_id TEXT NOT NULL
        CHECK({_HEX_CHECK.format('installation_id')}),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    source_root_revision INTEGER NOT NULL CHECK(source_root_revision>=1),
    snapshot_id TEXT NOT NULL UNIQUE
        CHECK(length(snapshot_id)=73 AND substr(snapshot_id,1,9)='snapshot-'),
    maintenance_reason_digest TEXT NOT NULL UNIQUE
        CHECK({_HEX_CHECK.format('maintenance_reason_digest')}),
    phase TEXT NOT NULL CHECK(phase IN ({_PHASE_SQL})),
    revision INTEGER NOT NULL
        CHECK(revision>=1 AND revision<={MAX_CAPTURE_RECEIPTS_PER_OPERATION}),
    receipt_count INTEGER NOT NULL CHECK(receipt_count=revision),
    last_receipt_digest TEXT NOT NULL
        CHECK({_HEX_CHECK.format('last_receipt_digest')})
) WITHOUT ROWID
"""

_RECEIPTS_DDL = f"""
CREATE TABLE capture_operation_receipts (
    operation_digest TEXT NOT NULL
        REFERENCES capture_operations(operation_digest),
    sequence INTEGER NOT NULL
        CHECK(sequence>=1 AND sequence<={MAX_CAPTURE_RECEIPTS_PER_OPERATION}),
    from_phase TEXT CHECK(from_phase IS NULL OR from_phase IN ({_PHASE_SQL})),
    to_phase TEXT NOT NULL CHECK(to_phase IN ({_PHASE_SQL})),
    checkpoint_kind TEXT NOT NULL CHECK(checkpoint_kind IN ({_CHECKPOINT_KIND_SQL})),
    recovery_authority_digest TEXT
        CHECK(recovery_authority_digest IS NULL OR
              {_HEX_CHECK.format('recovery_authority_digest')}),
    authority_authorized_revision INTEGER
        CHECK(authority_authorized_revision IS NULL OR
              authority_authorized_revision>=1),
    authority_authorized_last_receipt_digest TEXT
        CHECK(authority_authorized_last_receipt_digest IS NULL OR
              {_HEX_CHECK.format('authority_authorized_last_receipt_digest')}),
    checkpoint_json TEXT NOT NULL
        CHECK(length(checkpoint_json)>=2 AND
              length(checkpoint_json)<={MAX_CAPTURE_CHECKPOINT_BYTES}),
    checkpoint_digest TEXT NOT NULL
        CHECK({_HEX_CHECK.format('checkpoint_digest')}),
    previous_receipt_digest TEXT NOT NULL
        CHECK({_HEX_CHECK.format('previous_receipt_digest')} OR
              previous_receipt_digest='{_ZERO_DIGEST}'),
    receipt_digest TEXT NOT NULL UNIQUE
        CHECK({_HEX_CHECK.format('receipt_digest')}),
    PRIMARY KEY(operation_digest,sequence),
    CHECK(
        (sequence=1 AND from_phase IS NULL AND to_phase='claimed' AND
         previous_receipt_digest='{_ZERO_DIGEST}') OR
        (sequence>1 AND from_phase IS NOT NULL)
    )
) WITHOUT ROWID
"""

_LEASES_DDL = f"""
CREATE TABLE capture_operation_leases (
    operation_digest TEXT PRIMARY KEY
        REFERENCES capture_operations(operation_digest),
    owner_digest TEXT NOT NULL CHECK({_HEX_CHECK.format('owner_digest')}),
    generation INTEGER NOT NULL CHECK(generation>=1),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>=1)
) WITHOUT ROWID
"""

_RECEIPT_NO_UPDATE_DDL = """
CREATE TRIGGER capture_operation_receipts_no_update
BEFORE UPDATE ON capture_operation_receipts
BEGIN
    SELECT RAISE(ABORT,'capture operation receipts are append-only');
END
"""

_RECEIPT_NO_DELETE_DDL = """
CREATE TRIGGER capture_operation_receipts_no_delete
BEFORE DELETE ON capture_operation_receipts
BEGIN
    SELECT RAISE(ABORT,'capture operation receipts are append-only');
END
"""

_RECEIPT_NO_REPLACE_DDL = """
CREATE TRIGGER capture_operation_receipts_no_replace
BEFORE INSERT ON capture_operation_receipts
WHEN EXISTS(
    SELECT 1 FROM capture_operation_receipts
    WHERE operation_digest=NEW.operation_digest AND sequence=NEW.sequence
) OR EXISTS(
    SELECT 1 FROM capture_operation_receipts
    WHERE receipt_digest=NEW.receipt_digest
)
BEGIN
    SELECT RAISE(ABORT,'capture operation receipt replacement is forbidden');
END
"""

_OPERATION_BINDING_IMMUTABLE_DDL = """
CREATE TRIGGER capture_operation_binding_immutable
BEFORE UPDATE OF operation_digest,requester_sid_digest,installation_id,epoch,
                 source_root_revision,snapshot_id,maintenance_reason_digest
ON capture_operations
BEGIN
    SELECT RAISE(ABORT,'capture operation binding is immutable');
END
"""

_OPERATION_NO_DELETE_DDL = """
CREATE TRIGGER capture_operations_no_delete
BEFORE DELETE ON capture_operations
BEGIN
    SELECT RAISE(ABORT,'capture operations are retained');
END
"""

_SCHEMA_DDL = (
    _OPERATIONS_DDL,
    _RECEIPTS_DDL,
    _LEASES_DDL,
    _RECEIPT_NO_UPDATE_DDL,
    _RECEIPT_NO_DELETE_DDL,
    _RECEIPT_NO_REPLACE_DDL,
    _OPERATION_BINDING_IMMUTABLE_DDL,
    _OPERATION_NO_DELETE_DDL,
)


class RestrictedCaptureOperationError(RuntimeError):
    pass


class RestrictedCaptureOperationConflict(RestrictedCaptureOperationError):
    pass


class RestrictedCaptureOperationCapacityError(RestrictedCaptureOperationError):
    pass


class RestrictedCaptureOperationUnavailable(RestrictedCaptureOperationError):
    pass


@dataclass(frozen=True, slots=True)
class RestrictedCaptureReceipt:
    operation_digest: str
    sequence: int
    from_phase: CapturePhase | None
    to_phase: CapturePhase
    checkpoint_kind: str
    recovery_authority_digest: str | None
    authority_authorized_revision: int | None
    authority_authorized_last_receipt_digest: str | None
    checkpoint_json: str
    checkpoint_digest: str
    previous_receipt_digest: str
    receipt_digest: str

    @property
    def checkpoint(self) -> dict[str, object]:
        value = json.loads(self.checkpoint_json)
        if not isinstance(value, dict):  # defensive; validated on construction
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture checkpoint is invalid"
            )
        return value


@dataclass(frozen=True, slots=True)
class RestrictedCaptureOperation:
    request: RestrictedCaptureRequest
    snapshot_id: str
    maintenance_reason_digest: str
    phase: CapturePhase
    revision: int
    receipt_count: int
    last_receipt_digest: str
    first_receipt: RestrictedCaptureReceipt
    last_receipt: RestrictedCaptureReceipt


@dataclass(frozen=True, slots=True)
class RestrictedCaptureOperationDiscoveryPage:
    """One bounded, deterministic page of durable nonterminal operations."""

    items: tuple[RestrictedCaptureOperation, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class RestrictedCaptureExecutionLease:
    operation_digest: str
    owner_digest: str
    generation: int
    expires_at_ms: int


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _checkpoint_values(
    checkpoint_kind: str,
    checkpoint: Mapping[str, object],
    *,
    phase: CapturePhase,
    request: RestrictedCaptureRequest | None = None,
    from_phase: CapturePhase | None = None,
) -> tuple[str, str]:
    if (
        phase not in _PHASES
        or checkpoint_kind not in _CHECKPOINT_KINDS
        or not isinstance(checkpoint, Mapping)
    ):
        raise ValueError("restricted capture checkpoint is invalid")
    digest_fields = _DIGEST_CHECKPOINT_FIELDS[checkpoint_kind]
    counter_fields = _COUNTER_CHECKPOINT_FIELDS.get(checkpoint_kind, frozenset())
    expected_fields = set(digest_fields | counter_fields)
    if checkpoint_kind in _SNAPSHOT_CHECKPOINT_PHASES:
        expected_fields.add("snapshotId")
    if checkpoint_kind == "recovery_required":
        expected_fields.add("failedPhase")
    if checkpoint_kind in {
        "drain_begun",
        "drain_quiescent",
        "component_released",
        "cleanup_component_released",
    }:
        expected_fields.add("component")
    if set(checkpoint) != expected_fields:
        raise ValueError("restricted capture checkpoint fields are invalid")

    normalized: dict[str, object] = {}
    for field in sorted(digest_fields):
        normalized[field] = require_digest(
            checkpoint[field], f"restricted capture checkpoint {field}"
        )
    for field in sorted(counter_fields):
        normalized[field] = require_counter(
            checkpoint[field], f"restricted capture checkpoint {field}"
        )
    if checkpoint_kind in _SNAPSHOT_CHECKPOINT_PHASES:
        snapshot_id = checkpoint["snapshotId"]
        if (
            not isinstance(snapshot_id, str)
            or len(snapshot_id) != 73
            or not snapshot_id.startswith("snapshot-")
        ):
            raise ValueError("restricted capture checkpoint snapshot is invalid")
        normalized["snapshotId"] = snapshot_id
    if checkpoint_kind == "recovery_required":
        failed_phase = checkpoint["failedPhase"]
        if failed_phase not in _NONTERMINAL_PHASES or failed_phase != from_phase:
            raise ValueError("restricted capture recovery checkpoint is invalid")
        normalized["failedPhase"] = failed_phase
    if checkpoint_kind in {
        "drain_begun",
        "drain_quiescent",
        "component_released",
        "cleanup_component_released",
    }:
        component = checkpoint["component"]
        if component not in (
            "desktop",
            "gateway",
            "gateway_assets",
            "channel_media",
        ):
            raise ValueError("restricted capture checkpoint component is invalid")
        normalized["component"] = component

    if request is not None:
        if checkpoint_kind == "quiescent" and normalized["observedRootRevision"] != request.root_revision:
            raise ValueError("restricted capture Root revision changed")
        if checkpoint_kind == "root_locked":
            if request.root_revision >= _INT64_MAX:
                raise ValueError("restricted capture Root revision cannot advance")
            if normalized["lockedRootRevision"] != request.root_revision + 1:
                raise ValueError("restricted capture locked Root revision changed")
        if checkpoint_kind in {"staging", "staged_verified", "published"}:
            if request.root_revision >= _INT64_MAX:
                raise ValueError("restricted capture Root revision cannot advance")
            if normalized["lockedRootRevision"] != request.root_revision + 1:
                raise ValueError("restricted capture staged Root revision changed")
        if checkpoint_kind in _SNAPSHOT_CHECKPOINT_PHASES and normalized["snapshotId"] != request.snapshot_id:
            raise ValueError("restricted capture snapshot binding changed")

    encoded = _canonical_bytes(normalized)
    if len(encoded) > MAX_CAPTURE_CHECKPOINT_BYTES:
        raise ValueError("restricted capture checkpoint is too large")
    checkpoint_json = encoded.decode("ascii")
    checkpoint_digest = sha256(_CHECKPOINT_DOMAIN + encoded).hexdigest()
    return checkpoint_json, checkpoint_digest


def _receipt_digest(
    *,
    operation_digest: str,
    sequence: int,
    from_phase: CapturePhase | None,
    to_phase: CapturePhase,
    checkpoint_kind: str,
    recovery_authority_digest: str | None,
    authority_authorized_revision: int | None,
    authority_authorized_last_receipt_digest: str | None,
    checkpoint_json: str,
    checkpoint_digest: str,
    previous_receipt_digest: str,
) -> str:
    return sha256(
        _RECEIPT_DOMAIN
        + _canonical_bytes(
            {
                "operationDigest": operation_digest,
                "sequence": sequence,
                "fromPhase": from_phase,
                "toPhase": to_phase,
                "checkpointKind": checkpoint_kind,
                "recoveryAuthorityDigest": recovery_authority_digest,
                "authorityAuthorizedRevision": authority_authorized_revision,
                "authorityAuthorizedLastReceiptDigest": (
                    authority_authorized_last_receipt_digest
                ),
                "checkpoint": json.loads(checkpoint_json),
                "checkpointDigest": checkpoint_digest,
                "previousReceiptDigest": previous_receipt_digest,
            }
        )
    ).hexdigest()


def _progress_plan(phase: CapturePhase) -> tuple[tuple[str, str | None], ...]:
    if phase == "fencing":
        return tuple(("drain_begun", component) for component in CAPTURE_COMPONENT_ORDER) + tuple(
            ("drain_quiescent", component) for component in CAPTURE_COMPONENT_ORDER
        )
    if phase == "resuming":
        return (
            ("root_resumed", None),
            *tuple(
                ("component_released", component)
                for component in reversed(CAPTURE_COMPONENT_ORDER)
            ),
            ("global_released", None),
        )
    return ()


def _progress_receipts(
    receipts: tuple[RestrictedCaptureReceipt, ...],
    phase: CapturePhase,
) -> tuple[RestrictedCaptureReceipt, ...]:
    return tuple(
        receipt
        for receipt in receipts
        if receipt.from_phase == phase
        and receipt.to_phase == phase
        and receipt.checkpoint_kind in _HAPPY_PROGRESS_CHECKPOINT_KINDS
    )


def _validate_progress_step(
    receipts: tuple[RestrictedCaptureReceipt, ...],
    phase: CapturePhase,
    checkpoint_kind: str,
    checkpoint: Mapping[str, object],
) -> None:
    completed = _progress_receipts(receipts, phase)
    plan = _progress_plan(phase)
    if len(completed) >= len(plan):
        raise RestrictedCaptureOperationConflict(
            "restricted capture progress is already complete"
        )
    expected_kind, expected_component = plan[len(completed)]
    if checkpoint_kind != expected_kind:
        raise RestrictedCaptureOperationConflict(
            "restricted capture progress order is invalid"
        )
    if expected_component is not None and checkpoint.get("component") != expected_component:
        raise RestrictedCaptureOperationConflict(
            "restricted capture component order is invalid"
        )


def _resource_holds(
    receipts: tuple[RestrictedCaptureReceipt, ...],
) -> tuple[bool, tuple[str, ...], bool]:
    global_held = any(receipt.to_phase == "fencing" for receipt in receipts)
    root_held = any(receipt.to_phase == "root_locked" for receipt in receipts)
    components: list[str] = []
    for receipt in receipts:
        if receipt.checkpoint_kind == "drain_begun":
            component = str(receipt.checkpoint["component"])
            if component not in components:
                components.append(component)
        elif receipt.checkpoint_kind in {
            "component_released",
            "cleanup_component_released",
        }:
            component = str(receipt.checkpoint["component"])
            if component in components:
                components.remove(component)
        elif receipt.checkpoint_kind in {"root_resumed", "cleanup_root_resumed"}:
            root_held = False
        elif receipt.checkpoint_kind in {
            "global_released",
            "cleanup_global_released",
        }:
            global_held = False
    return root_held, tuple(components), global_held


def _next_cleanup_requirement(
    receipts: tuple[RestrictedCaptureReceipt, ...],
) -> tuple[str, str | None] | None:
    root_held, components, global_held = _resource_holds(receipts)
    if root_held:
        return "cleanup_root_resumed", None
    if components:
        return "cleanup_component_released", components[-1]
    if global_held:
        return "cleanup_global_released", None
    return None


def _validate_cleanup_step(
    receipts: tuple[RestrictedCaptureReceipt, ...],
    phase: CapturePhase,
    checkpoint_kind: str,
    checkpoint: Mapping[str, object],
) -> None:
    requirement = _next_cleanup_requirement(receipts)
    if requirement is None:
        raise RestrictedCaptureOperationConflict(
            "restricted capture cleanup is already complete"
        )
    expected_kind, expected_component = requirement
    if checkpoint_kind != expected_kind:
        raise RestrictedCaptureOperationConflict(
            "restricted capture cleanup order is invalid"
        )
    if expected_component is not None and checkpoint.get("component") != expected_component:
        raise RestrictedCaptureOperationConflict(
            "restricted capture cleanup component order is invalid"
        )


def _install_schema(connection: sqlite3.Connection) -> None:
    for ddl in _SCHEMA_DDL:
        connection.execute(ddl)


def _schema_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "ORDER BY type,name,tbl_name"
        )
    )


def _expected_schema_rows() -> tuple[tuple[object, ...], ...]:
    with closing(sqlite3.connect(":memory:")) as connection:
        _install_schema(connection)
        return _schema_rows(connection)


_EXPECTED_SCHEMA_ROWS = _expected_schema_rows()


class RestrictedCaptureOperationStore:
    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        allow_unleased_test_mutations: bool = False,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._allow_unleased_test_mutations = allow_unleased_test_mutations

    @classmethod
    def provision(
        cls,
        path: str | os.PathLike[str],
        *,
        allow_unleased_test_mutations: bool = False,
    ) -> "RestrictedCaptureOperationStore":
        store = cls(
            path,
            allow_unleased_test_mutations=allow_unleased_test_mutations,
        )
        store.path.parent.mkdir(parents=True, exist_ok=True)
        created = False
        try:
            descriptor = os.open(store.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
            created = True
            with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
                connection.execute(f"PRAGMA page_size={CAPTURE_STORE_PAGE_SIZE}")
                mode = str(
                    connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0]
                ).lower()
                if mode != "persist":
                    raise sqlite3.DatabaseError("operation store journal mode is invalid")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA foreign_keys=ON")
                max_pages = int(
                    connection.execute(
                        f"PRAGMA max_page_count={CAPTURE_STORE_MAX_PAGES}"
                    ).fetchone()[0]
                )
                if max_pages != CAPTURE_STORE_MAX_PAGES:
                    raise sqlite3.DatabaseError("operation store page limit is invalid")
                connection.execute("BEGIN IMMEDIATE")
                _install_schema(connection)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                connection.commit()
            store._validate_store()
            return store
        except Exception as exc:
            if created:
                for candidate in (store.path, Path(f"{store.path}-journal")):
                    try:
                        candidate.unlink(missing_ok=True)
                    except OSError:
                        pass
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        allow_unleased_test_mutations: bool = False,
    ) -> "RestrictedCaptureOperationStore":
        store = cls(
            path,
            allow_unleased_test_mutations=allow_unleased_test_mutations,
        )
        store._validate_store()
        return store

    def _check_file_capacity(self) -> None:
        self._database_family_presence()

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & flag
        )

    def _database_family_presence(self) -> dict[str, bool]:
        limits = {
            "": MAX_CAPTURE_STORE_BYTES,
            "-journal": MAX_CAPTURE_JOURNAL_BYTES,
            "-wal": MAX_CAPTURE_WAL_BYTES,
            "-shm": MAX_CAPTURE_SHM_BYTES,
        }
        presence: dict[str, bool] = {}
        total = 0
        for suffix, limit in limits.items():
            candidate = Path(f"{self.path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                presence[suffix] = False
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or self._is_reparse(info)
                or int(info.st_size) > limit
            ):
                raise sqlite3.DatabaseError(
                    "operation store family exceeds its bounded profile"
                )
            presence[suffix] = True
            total += int(info.st_size)
        if not presence[""] or total > MAX_CAPTURE_STORE_FAMILY_BYTES:
            raise sqlite3.DatabaseError(
                "operation store family exceeds its bounded profile"
            )
        return presence

    def _database_path_identity(self) -> tuple[int, int]:
        info = os.lstat(self.path)
        if not stat.S_ISREG(info.st_mode) or self._is_reparse(info):
            raise sqlite3.DatabaseError("operation store path is unsafe")
        return int(info.st_dev), int(info.st_ino)

    def _database_header_mode(self) -> str:
        with self.path.open("rb") as handle:
            header = handle.read(20)
        if len(header) < 20 or not header.startswith(b"SQLite format 3\x00"):
            raise sqlite3.DatabaseError("operation store header is invalid")
        if header[18:20] == b"\x01\x01":
            return "rollback"
        if header[18:20] == b"\x02\x02":
            return "wal"
        raise sqlite3.DatabaseError("operation store journal header is invalid")

    def _rollback_journal_state(self) -> str:
        journal = Path(f"{self.path}-journal")
        if not journal.exists():
            return "absent"
        with journal.open("rb") as handle:
            header = handle.read(8)
        if not header or header == b"\x00" * len(header):
            return "clean"
        if header == _ROLLBACK_JOURNAL_MAGIC:
            return "hot"
        raise sqlite3.DatabaseError(
            "operation store rollback journal requires explicit recovery"
        )

    def _preflight_read_family(self) -> tuple[dict[str, bool], tuple[int, int]]:
        presence = self._database_family_presence()
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "operation store WAL and SHM sidecars must be present together"
            )
        header_mode = self._database_header_mode()
        if presence["-wal"]:
            if header_mode != "wal":
                raise sqlite3.DatabaseError(
                    "operation store WAL sidecars do not match its header"
                )
        elif header_mode != "rollback":
            raise sqlite3.DatabaseError(
                "operation store WAL header is missing complete sidecars"
            )
        if self._rollback_journal_state() not in {"absent", "clean"}:
            raise sqlite3.DatabaseError(
                "operation store requires read-write recovery before discovery"
            )
        identity = self._database_path_identity()
        if self._database_family_presence() != presence:
            raise sqlite3.DatabaseError(
                "operation store family changed during read-only preflight"
            )
        if self._database_path_identity() != identity:
            raise sqlite3.DatabaseError(
                "operation store path changed during read-only preflight"
            )
        return presence, identity

    @contextmanager
    def _read_connection(self):  # noqa: ANN202
        presence, identity = self._preflight_read_family()
        suffix = "?mode=ro" if presence["-wal"] else "?mode=ro&immutable=1"
        connection = sqlite3.connect(
            f"{self.path.as_uri()}{suffix}",
            uri=True,
            isolation_level=None,
            timeout=10,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "operation store path changed before read-only open"
                )
            self._validate_identity_and_schema(connection)
            self._validate_connection_contents(connection)
            yield connection
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "operation store path changed during read-only snapshot"
                )
            if self._database_family_presence() != presence:
                raise sqlite3.DatabaseError(
                    "operation store family changed during read-only snapshot"
                )
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    def _raw_connect(self, *, mode: str) -> sqlite3.Connection:
        self._check_file_capacity()
        connection = sqlite3.connect(
            f"file:{self.path.as_posix()}?mode={mode}",
            uri=True,
            isolation_level=None,
            timeout=10,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            if mode == "ro":
                connection.execute("PRAGMA query_only=ON")
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _validate_identity_and_schema(connection: sqlite3.Connection) -> None:
        if int(connection.execute("PRAGMA application_id").fetchone()[0]) != _APPLICATION_ID:
            raise sqlite3.DatabaseError("operation store identity is invalid")
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("operation store version is invalid")
        if int(connection.execute("PRAGMA page_size").fetchone()[0]) != CAPTURE_STORE_PAGE_SIZE:
            raise sqlite3.DatabaseError("operation store page size is invalid")
        if _schema_rows(connection) != _EXPECTED_SCHEMA_ROWS:
            raise sqlite3.DatabaseError("operation store schema is invalid")

    def _connect(self) -> sqlite3.Connection:
        presence = self._database_family_presence()
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "operation store WAL and SHM sidecars must be present together"
            )
        identity = self._database_path_identity()
        connection = self._raw_connect(mode="rw")
        try:
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "operation store path changed before read-write open"
                )
            # Do not apply a persistent/profile PRAGMA until the already-open
            # file descriptor has passed the identity and exact-schema gate.
            self._validate_identity_and_schema(connection)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            mode = str(
                connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0]
            ).lower()
            if mode != "persist":
                raise sqlite3.DatabaseError("operation store journal mode is invalid")
            if int(connection.execute("PRAGMA page_size").fetchone()[0]) != CAPTURE_STORE_PAGE_SIZE:
                raise sqlite3.DatabaseError("operation store page size is invalid")
            max_pages = int(
                connection.execute(
                    f"PRAGMA max_page_count={CAPTURE_STORE_MAX_PAGES}"
                ).fetchone()[0]
            )
            if max_pages != CAPTURE_STORE_MAX_PAGES:
                raise sqlite3.DatabaseError("operation store page limit is invalid")
            self._validate_identity_and_schema(connection)
            return connection
        except Exception:
            connection.close()
            raise

    def _validate_store(self) -> None:
        try:
            # First pass is read-only: rejecting an unknown/incompatible file
            # must not change its bytes, profile, or sidecar set.
            with self._read_connection():
                pass
            # Second pass applies the accepted profile, takes a writer lock,
            # and repeats all source-of-truth validation on the same handle.
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_identity_and_schema(connection)
                self._validate_connection_contents(connection)
                connection.rollback()
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc

    def _validate_connection_contents(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise sqlite3.DatabaseError("operation store quick check failed")
        operation_count = int(
            connection.execute("SELECT count(*) FROM capture_operations").fetchone()[0]
        )
        receipt_count = int(
            connection.execute(
                "SELECT count(*) FROM capture_operation_receipts"
            ).fetchone()[0]
        )
        if operation_count > MAX_CAPTURE_OPERATIONS or receipt_count > MAX_CAPTURE_RECEIPTS:
            raise sqlite3.DatabaseError("operation store row capacity exceeded")
        orphan_count = int(
            connection.execute(
                "SELECT count(*) FROM capture_operation_receipts r "
                "LEFT JOIN capture_operations o USING(operation_digest) "
                "WHERE o.operation_digest IS NULL"
            ).fetchone()[0]
        )
        if orphan_count:
            raise sqlite3.DatabaseError("operation store has orphan receipts")
        for row in connection.execute(
            "SELECT * FROM capture_operations ORDER BY operation_digest"
        ).fetchall():
            self._operation_from_row(connection, row)
        for row in connection.execute(
            "SELECT operation_digest,owner_digest,generation,expires_at_ms "
            "FROM capture_operation_leases"
        ):
            require_digest(row["operation_digest"], "lease operation")
            require_digest(row["owner_digest"], "lease owner")
            require_counter(row["generation"], "lease generation")
            require_counter(row["expires_at_ms"], "lease expiry")

    def create_claimed(
        self,
        request: RestrictedCaptureRequest,
        *,
        checkpoint: Mapping[str, object],
    ) -> RestrictedCaptureOperation:
        if not isinstance(request, RestrictedCaptureRequest):
            raise ValueError("restricted capture request is invalid")
        checkpoint_json, checkpoint_digest = _checkpoint_values(
            "claimed", checkpoint, phase="claimed", request=request
        )
        receipt_digest = _receipt_digest(
            operation_digest=request.operation_digest,
            sequence=1,
            from_phase=None,
            to_phase="claimed",
            checkpoint_kind="claimed",
            recovery_authority_digest=None,
            authority_authorized_revision=None,
            authority_authorized_last_receipt_digest=None,
            checkpoint_json=checkpoint_json,
            checkpoint_digest=checkpoint_digest,
            previous_receipt_digest=_ZERO_DIGEST,
        )
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing_row = connection.execute(
                    "SELECT * FROM capture_operations WHERE operation_digest=?",
                    (request.operation_digest,),
                ).fetchone()
                if existing_row is not None:
                    existing = self._operation_from_row(connection, existing_row)
                    connection.rollback()
                    if (
                        existing.request == request
                        and existing.snapshot_id == request.snapshot_id
                        and existing.maintenance_reason_digest == request.maintenance_reason_digest
                        and existing.first_receipt.checkpoint_json == checkpoint_json
                        and existing.first_receipt.checkpoint_digest == checkpoint_digest
                    ):
                        return existing
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation already exists with different binding"
                    )
                counts = connection.execute(
                    "SELECT (SELECT count(*) FROM capture_operations),"
                    "(SELECT count(*) FROM capture_operation_receipts)"
                ).fetchone()
                if int(counts[0]) >= MAX_CAPTURE_OPERATIONS or int(counts[1]) >= MAX_CAPTURE_RECEIPTS:
                    connection.rollback()
                    raise RestrictedCaptureOperationCapacityError(
                        "restricted capture operation store capacity is exhausted"
                    )
                connection.execute(
                    "INSERT INTO capture_operations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        request.operation_digest,
                        request.requester_sid_digest,
                        request.installation_id,
                        request.epoch,
                        request.root_revision,
                        request.snapshot_id,
                        request.maintenance_reason_digest,
                        "claimed",
                        1,
                        1,
                        receipt_digest,
                    ),
                )
                connection.execute(
                    "INSERT INTO capture_operation_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        request.operation_digest,
                        1,
                        None,
                        "claimed",
                        "claimed",
                        None,
                        None,
                        None,
                        checkpoint_json,
                        checkpoint_digest,
                        _ZERO_DIGEST,
                        receipt_digest,
                    ),
                )
                connection.commit()
        except (RestrictedCaptureOperationError, ValueError):
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc
        operation = self.get(request.operation_digest)
        if operation is None:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            )
        return operation

    def create_claimed_and_acquire_lease(
        self,
        request: RestrictedCaptureRequest,
        *,
        checkpoint: Mapping[str, object],
        owner_digest: str,
        now_ms: int,
        lease_ms: int,
    ) -> tuple[RestrictedCaptureOperation, RestrictedCaptureExecutionLease]:
        """Atomically publish receipt one and generation-one execution lease."""

        if not isinstance(request, RestrictedCaptureRequest):
            raise ValueError("restricted capture request is invalid")
        owner = require_digest(owner_digest, "lease owner")
        now = require_counter(now_ms, "lease clock")
        duration = require_counter(lease_ms, "lease duration")
        if not MIN_EXECUTION_LEASE_MS <= duration <= MAX_EXECUTION_LEASE_MS:
            raise ValueError("restricted capture lease duration is invalid")
        expires = now + duration
        if expires > _INT64_MAX:
            raise ValueError("restricted capture lease expiry is invalid")
        checkpoint_json, checkpoint_digest = _checkpoint_values(
            "claimed",
            checkpoint,
            phase="claimed",
            request=request,
        )
        receipt_digest = _receipt_digest(
            operation_digest=request.operation_digest,
            sequence=1,
            from_phase=None,
            to_phase="claimed",
            checkpoint_kind="claimed",
            recovery_authority_digest=None,
            authority_authorized_revision=None,
            authority_authorized_last_receipt_digest=None,
            checkpoint_json=checkpoint_json,
            checkpoint_digest=checkpoint_digest,
            previous_receipt_digest=_ZERO_DIGEST,
        )
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM capture_operations WHERE operation_digest=?",
                    (request.operation_digest,),
                ).fetchone()
                if row is None:
                    counts = connection.execute(
                        "SELECT (SELECT count(*) FROM capture_operations),"
                        "(SELECT count(*) FROM capture_operation_receipts)"
                    ).fetchone()
                    if (
                        int(counts[0]) >= MAX_CAPTURE_OPERATIONS
                        or int(counts[1]) >= MAX_CAPTURE_RECEIPTS
                    ):
                        connection.rollback()
                        raise RestrictedCaptureOperationCapacityError(
                            "restricted capture operation store capacity is exhausted"
                        )
                    connection.execute(
                        "INSERT INTO capture_operations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            request.operation_digest,
                            request.requester_sid_digest,
                            request.installation_id,
                            request.epoch,
                            request.root_revision,
                            request.snapshot_id,
                            request.maintenance_reason_digest,
                            "claimed",
                            1,
                            1,
                            receipt_digest,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO capture_operation_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            request.operation_digest,
                            1,
                            None,
                            "claimed",
                            "claimed",
                            None,
                            None,
                            None,
                            checkpoint_json,
                            checkpoint_digest,
                            _ZERO_DIGEST,
                            receipt_digest,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM capture_operations WHERE operation_digest=?",
                        (request.operation_digest,),
                    ).fetchone()
                operation = self._operation_from_row(connection, row)
                if (
                    operation.request != request
                    or operation.first_receipt.checkpoint_json != checkpoint_json
                    or operation.first_receipt.checkpoint_digest != checkpoint_digest
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation already exists with different binding"
                    )
                lease_row = connection.execute(
                    "SELECT * FROM capture_operation_leases WHERE operation_digest=?",
                    (request.operation_digest,),
                ).fetchone()
                if lease_row is None:
                    generation = 1
                    connection.execute(
                        "INSERT INTO capture_operation_leases VALUES(?,?,?,?)",
                        (request.operation_digest, owner, generation, expires),
                    )
                elif (
                    str(lease_row["owner_digest"]) == owner
                    and int(lease_row["expires_at_ms"]) >= now
                ):
                    generation = int(lease_row["generation"])
                    expires = int(lease_row["expires_at_ms"])
                elif int(lease_row["expires_at_ms"]) < now:
                    generation = int(lease_row["generation"]) + 1
                    connection.execute(
                        "UPDATE capture_operation_leases SET owner_digest=?,generation=?,"
                        "expires_at_ms=? WHERE operation_digest=?",
                        (owner, generation, expires, request.operation_digest),
                    )
                else:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation execution lease is held"
                    )
                connection.commit()
                return operation, RestrictedCaptureExecutionLease(
                    request.operation_digest,
                    owner,
                    generation,
                    expires,
                )
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture claimed operation lease is unavailable"
            ) from exc

    def get(self, operation_digest: str) -> RestrictedCaptureOperation | None:
        operation_id = require_digest(operation_digest, "restricted capture operation")
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM capture_operations WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    return None
                return self._operation_from_row(connection, row)
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc

    def discover_recoverable_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int = 32,
    ) -> RestrictedCaptureOperationDiscoveryPage:
        """Read one bounded page without taking a writer-capable SQLite handle.

        The cursor is the last operation digest returned by the previous page.
        Terminal rows are retained by the journal but deliberately excluded:
        active claimed-ticket discovery is responsible for any terminal ticket
        reconciliation still required by the current service boot.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_CAPTURE_OPERATIONS
        ):
            raise ValueError("restricted capture discovery request is invalid")
        if after_operation_digest is not None:
            try:
                cursor = require_digest(
                    after_operation_digest,
                    "restricted capture discovery cursor",
                )
            except ValueError as exc:
                raise ValueError(
                    "restricted capture discovery request is invalid"
                ) from exc
        else:
            cursor = None

        try:
            with self._read_connection() as connection:
                query = (
                    "SELECT * FROM capture_operations "
                    "WHERE phase NOT IN ('completed','failed_clean')"
                )
                parameters: tuple[object, ...]
                if cursor is None:
                    parameters = (limit + 1,)
                else:
                    query += " AND operation_digest>?"
                    parameters = (cursor, limit + 1)
                query += " ORDER BY operation_digest LIMIT ?"
                rows = connection.execute(query, parameters).fetchall()
                page_rows = rows[:limit]
                items = tuple(
                    self._operation_from_row(connection, row) for row in page_rows
                )
                next_cursor = (
                    items[-1].request.operation_digest
                    if len(rows) > limit and items
                    else None
                )
                return RestrictedCaptureOperationDiscoveryPage(
                    items=items,
                    next_cursor=next_cursor,
                )
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation discovery is unavailable"
            ) from exc

    def transition(
        self,
        operation_digest: str,
        *,
        expected_phase: CapturePhase,
        expected_revision: int,
        to_phase: CapturePhase,
        checkpoint: Mapping[str, object],
        lease: RestrictedCaptureExecutionLease | None = None,
        now_ms: int | None = None,
    ) -> RestrictedCaptureOperation:
        if expected_phase not in _NORMAL_TRANSITIONS or to_phase not in _PHASES:
            raise ValueError("restricted capture phase is invalid")
        if to_phase not in _NORMAL_TRANSITIONS[expected_phase]:
            raise RestrictedCaptureOperationConflict(
                "restricted capture phase transition is invalid"
            )
        return self._append_transition(
            operation_digest,
            expected_phase=expected_phase,
            expected_revision=expected_revision,
            to_phase=to_phase,
            checkpoint_kind=to_phase,
            checkpoint=checkpoint,
            recovery=False,
            recovery_authority_digest=None,
            authority_authorized_revision=None,
            authority_authorized_last_receipt_digest=None,
            lease=lease,
            now_ms=now_ms,
        )

    def resolve_recovery(
        self,
        operation_digest: str,
        *,
        expected_revision: int,
        to_phase: CapturePhase,
        checkpoint: Mapping[str, object],
        recovery_authority_digest: str,
        authority_authorized_revision: int,
        authority_authorized_last_receipt_digest: str,
        lease: RestrictedCaptureExecutionLease | None = None,
        now_ms: int | None = None,
    ) -> RestrictedCaptureOperation:
        if to_phase not in _RECOVERY_TRANSITIONS:
            raise RestrictedCaptureOperationConflict(
                "restricted capture recovery transition is invalid"
            )
        return self._append_transition(
            operation_digest,
            expected_phase="recovery_required",
            expected_revision=expected_revision,
            to_phase=to_phase,
            checkpoint_kind=to_phase,
            checkpoint=checkpoint,
            recovery=True,
            recovery_authority_digest=require_digest(
                recovery_authority_digest,
                "restricted capture recovery authority evidence",
            ),
            authority_authorized_revision=require_counter(
                authority_authorized_revision,
                "restricted capture recovery authorized revision",
            ),
            authority_authorized_last_receipt_digest=require_digest(
                authority_authorized_last_receipt_digest,
                "restricted capture recovery authorized last receipt",
            ),
            lease=lease,
            now_ms=now_ms,
        )

    def record_progress(
        self,
        operation_digest: str,
        *,
        expected_phase: CapturePhase,
        expected_revision: int,
        checkpoint_kind: str,
        checkpoint: Mapping[str, object],
        lease: RestrictedCaptureExecutionLease | None = None,
        now_ms: int | None = None,
    ) -> RestrictedCaptureOperation:
        if expected_phase not in {"fencing", "resuming"}:
            raise RestrictedCaptureOperationConflict(
                "restricted capture phase has no component progress"
            )
        if checkpoint_kind not in _PROGRESS_CHECKPOINT_KINDS:
            raise ValueError("restricted capture checkpoint kind is invalid")
        return self._append_transition(
            operation_digest,
            expected_phase=expected_phase,
            expected_revision=expected_revision,
            to_phase=expected_phase,
            checkpoint_kind=checkpoint_kind,
            checkpoint=checkpoint,
            recovery=False,
            recovery_authority_digest=None,
            authority_authorized_revision=None,
            authority_authorized_last_receipt_digest=None,
            lease=lease,
            now_ms=now_ms,
        )

    def record_cleanup_progress(
        self,
        operation_digest: str,
        *,
        expected_phase: CapturePhase,
        expected_revision: int,
        checkpoint_kind: str,
        checkpoint: Mapping[str, object],
        lease: RestrictedCaptureExecutionLease | None = None,
        now_ms: int | None = None,
    ) -> RestrictedCaptureOperation:
        if expected_phase not in _NONTERMINAL_PHASES | {"recovery_required"}:
            raise RestrictedCaptureOperationConflict(
                "restricted capture phase has no clean-release progress"
            )
        if checkpoint_kind not in _CLEANUP_PROGRESS_CHECKPOINT_KINDS:
            raise ValueError("restricted capture cleanup checkpoint kind is invalid")
        return self._append_transition(
            operation_digest,
            expected_phase=expected_phase,
            expected_revision=expected_revision,
            to_phase=expected_phase,
            checkpoint_kind=checkpoint_kind,
            checkpoint=checkpoint,
            recovery=False,
            recovery_authority_digest=None,
            authority_authorized_revision=None,
            authority_authorized_last_receipt_digest=None,
            lease=lease,
            now_ms=now_ms,
        )

    def _append_transition(
        self,
        operation_digest: str,
        *,
        expected_phase: CapturePhase,
        expected_revision: int,
        to_phase: CapturePhase,
        checkpoint_kind: str,
        checkpoint: Mapping[str, object],
        recovery: bool,
        recovery_authority_digest: str | None,
        authority_authorized_revision: int | None,
        authority_authorized_last_receipt_digest: str | None,
        lease: RestrictedCaptureExecutionLease | None,
        now_ms: int | None,
    ) -> RestrictedCaptureOperation:
        operation_id = require_digest(operation_digest, "restricted capture operation")
        revision = require_counter(expected_revision, "expected operation revision")
        authority_present = (
            recovery_authority_digest is not None
            and authority_authorized_revision is not None
            and authority_authorized_last_receipt_digest is not None
        )
        if recovery != authority_present:
            raise ValueError("restricted capture recovery authority binding is invalid")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_mutation_lease(
                    connection,
                    operation_id,
                    lease=lease,
                    now_ms=now_ms,
                )
                row = connection.execute(
                    "SELECT * FROM capture_operations WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation CAS changed"
                    )
                operation = self._operation_from_row(connection, row)
                checkpoint_json, checkpoint_digest = _checkpoint_values(
                    checkpoint_kind,
                    checkpoint,
                    phase=to_phase,
                    request=operation.request,
                    from_phase=expected_phase,
                )
                if operation.phase != expected_phase or operation.revision != revision:
                    if operation.revision == revision + 1:
                        candidate = operation.last_receipt
                        if (
                            candidate.from_phase == expected_phase
                            and candidate.to_phase == to_phase
                            and candidate.checkpoint_kind == checkpoint_kind
                            and candidate.recovery_authority_digest
                            == recovery_authority_digest
                            and candidate.authority_authorized_revision
                            == authority_authorized_revision
                            and candidate.authority_authorized_last_receipt_digest
                            == authority_authorized_last_receipt_digest
                            and candidate.checkpoint_json == checkpoint_json
                            and candidate.checkpoint_digest == checkpoint_digest
                        ):
                            connection.rollback()
                            return operation
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation CAS changed"
                    )
                if recovery and (
                    operation.revision != authority_authorized_revision
                    or operation.last_receipt_digest
                    != authority_authorized_last_receipt_digest
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture recovery authority is stale"
                    )
                existing_receipts = self._receipts_from_connection(
                    connection, operation.request
                )
                if (
                    recovery
                    and to_phase == "resuming"
                    and not any(
                        receipt.checkpoint_kind == "published"
                        for receipt in existing_receipts
                    )
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture recovery cannot resume before publication"
                    )
                if to_phase == expected_phase:
                    if checkpoint_kind in _CLEANUP_PROGRESS_CHECKPOINT_KINDS:
                        _validate_cleanup_step(
                            existing_receipts,
                            expected_phase,
                            checkpoint_kind,
                            json.loads(checkpoint_json),
                        )
                    else:
                        _validate_progress_step(
                            existing_receipts,
                            expected_phase,
                            checkpoint_kind,
                            json.loads(checkpoint_json),
                        )
                elif expected_phase in {"fencing", "resuming"} and to_phase in {
                    "quiescent",
                    "completed",
                }:
                    if len(_progress_receipts(existing_receipts, expected_phase)) != len(
                        _progress_plan(expected_phase)
                    ):
                        connection.rollback()
                        raise RestrictedCaptureOperationConflict(
                            "restricted capture component progress is incomplete"
                        )
                if to_phase == "failed_clean" and any(
                    _resource_holds(existing_receipts)
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture cleanup progress is incomplete"
                    )
                if revision >= MAX_CAPTURE_RECEIPTS_PER_OPERATION:
                    connection.rollback()
                    raise RestrictedCaptureOperationCapacityError(
                        "restricted capture receipt capacity is exhausted"
                    )
                total_receipts = int(
                    connection.execute(
                        "SELECT count(*) FROM capture_operation_receipts"
                    ).fetchone()[0]
                )
                if total_receipts >= MAX_CAPTURE_RECEIPTS:
                    connection.rollback()
                    raise RestrictedCaptureOperationCapacityError(
                        "restricted capture operation store capacity is exhausted"
                    )
                previous = operation.last_receipt_digest
                sequence = revision + 1
                receipt_digest = _receipt_digest(
                    operation_digest=operation_id,
                    sequence=sequence,
                    from_phase=expected_phase,
                    to_phase=to_phase,
                    checkpoint_kind=checkpoint_kind,
                    recovery_authority_digest=recovery_authority_digest,
                    authority_authorized_revision=authority_authorized_revision,
                    authority_authorized_last_receipt_digest=(
                        authority_authorized_last_receipt_digest
                    ),
                    checkpoint_json=checkpoint_json,
                    checkpoint_digest=checkpoint_digest,
                    previous_receipt_digest=previous,
                )
                connection.execute(
                    "INSERT INTO capture_operation_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        operation_id,
                        sequence,
                        expected_phase,
                        to_phase,
                        checkpoint_kind,
                        recovery_authority_digest,
                        authority_authorized_revision,
                        authority_authorized_last_receipt_digest,
                        checkpoint_json,
                        checkpoint_digest,
                        previous,
                        receipt_digest,
                    ),
                )
                # Validate the complete existing+candidate chain while the
                # candidate is still uncommitted.  Cross-phase Root,
                # quiescence, artifact, manifest, recovery, and progress
                # bindings must fail by rollback, never poison the CAS index.
                try:
                    candidate_chain = self._receipts_from_connection(
                        connection, operation.request
                    )
                except RestrictedCaptureOperationUnavailable as exc:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture candidate checkpoint binding is invalid"
                    ) from exc
                if (
                    len(candidate_chain) != sequence
                    or candidate_chain[-1].receipt_digest != receipt_digest
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture candidate receipt is invalid"
                    )
                cursor = connection.execute(
                    "UPDATE capture_operations SET phase=?,revision=?,receipt_count=?,"
                    "last_receipt_digest=? WHERE operation_digest=? AND phase=? AND revision=?",
                    (
                        to_phase,
                        sequence,
                        sequence,
                        receipt_digest,
                        operation_id,
                        expected_phase,
                        revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError("operation CAS update was lost")
                connection.commit()
        except (RestrictedCaptureOperationError, ValueError):
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc
        result = self.get(operation_id)
        if result is None:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            )
        return result

    def receipts(self, operation_digest: str) -> tuple[RestrictedCaptureReceipt, ...]:
        operation_id = require_digest(operation_digest, "restricted capture operation")
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM capture_operations WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    return ()
                request = self._request_from_row(row)
                return self._receipts_from_connection(connection, request)
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation store is unavailable"
            ) from exc

    def _validate_mutation_lease(
        self,
        connection: sqlite3.Connection,
        operation_digest: str,
        *,
        lease: RestrictedCaptureExecutionLease | None,
        now_ms: int | None,
    ) -> None:
        if lease is None and now_ms is None:
            if self._allow_unleased_test_mutations:
                return
            raise RestrictedCaptureOperationConflict(
                "restricted capture mutation execution lease is required"
            )
        if lease is None or now_ms is None or not isinstance(
            lease, RestrictedCaptureExecutionLease
        ):
            raise ValueError("restricted capture mutation lease is invalid")
        now = require_counter(now_ms, "restricted capture mutation lease clock")
        if lease.operation_digest != operation_digest:
            raise RestrictedCaptureOperationConflict(
                "restricted capture mutation lease binding changed"
            )
        row = connection.execute(
            "SELECT owner_digest,generation,expires_at_ms "
            "FROM capture_operation_leases WHERE operation_digest=?",
            (operation_digest,),
        ).fetchone()
        if (
            row is None
            or str(row["owner_digest"]) != lease.owner_digest
            or int(row["generation"]) != lease.generation
            or int(row["expires_at_ms"]) < now
            or lease.expires_at_ms < now
        ):
            raise RestrictedCaptureOperationConflict(
                "restricted capture mutation execution lease was lost"
            )

    def acquire_execution_lease(
        self,
        operation_digest: str,
        *,
        owner_digest: str,
        now_ms: int,
        lease_ms: int,
    ) -> RestrictedCaptureExecutionLease:
        operation_id = require_digest(operation_digest, "lease operation")
        owner = require_digest(owner_digest, "lease owner")
        now = require_counter(now_ms, "lease clock")
        duration = require_counter(lease_ms, "lease duration")
        if not MIN_EXECUTION_LEASE_MS <= duration <= MAX_EXECUTION_LEASE_MS:
            raise ValueError("restricted capture lease duration is invalid")
        expires = now + duration
        if expires > (1 << 63) - 1:
            raise ValueError("restricted capture lease expiry is invalid")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                operation = connection.execute(
                    "SELECT 1 FROM capture_operations WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                if operation is None:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation does not exist"
                    )
                row = connection.execute(
                    "SELECT * FROM capture_operation_leases WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    generation = 1
                    connection.execute(
                        "INSERT INTO capture_operation_leases VALUES(?,?,?,?)",
                        (operation_id, owner, generation, expires),
                    )
                elif str(row["owner_digest"]) == owner and int(row["expires_at_ms"]) >= now:
                    generation = int(row["generation"])
                    expires = int(row["expires_at_ms"])
                elif int(row["expires_at_ms"]) < now:
                    generation = int(row["generation"]) + 1
                    connection.execute(
                        "UPDATE capture_operation_leases SET owner_digest=?,generation=?,"
                        "expires_at_ms=? WHERE operation_digest=?",
                        (owner, generation, expires, operation_id),
                    )
                else:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture operation execution lease is held"
                    )
                connection.commit()
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation lease is unavailable"
            ) from exc
        return RestrictedCaptureExecutionLease(operation_id, owner, generation, expires)

    def assert_effect_capacity(
        self,
        operation_digest: str,
        *,
        lease: RestrictedCaptureExecutionLease,
        now_ms: int,
        reserve_receipts: int = MIN_EFFECT_RECEIPT_RESERVE,
    ) -> None:
        """Fence an external effect unless its worst-case convergence is reserved."""

        operation_id = require_digest(operation_digest, "capacity operation")
        reserve = require_counter(reserve_receipts, "effect receipt reserve")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_mutation_lease(
                    connection,
                    operation_id,
                    lease=lease,
                    now_ms=now_ms,
                )
                row = connection.execute(
                    "SELECT revision FROM capture_operations WHERE operation_digest=?",
                    (operation_id,),
                ).fetchone()
                total = int(
                    connection.execute(
                        "SELECT count(*) FROM capture_operation_receipts"
                    ).fetchone()[0]
                )
                if (
                    row is None
                    or MAX_CAPTURE_RECEIPTS_PER_OPERATION - int(row["revision"])
                    < reserve
                    or MAX_CAPTURE_RECEIPTS - total < reserve
                ):
                    connection.rollback()
                    raise RestrictedCaptureOperationCapacityError(
                        "restricted capture convergence receipt reserve is unavailable"
                    )
                connection.rollback()
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture capacity reservation is unavailable"
            ) from exc

    def renew_execution_lease(
        self,
        lease: RestrictedCaptureExecutionLease,
        *,
        now_ms: int,
        lease_ms: int,
    ) -> RestrictedCaptureExecutionLease:
        if not isinstance(lease, RestrictedCaptureExecutionLease):
            raise ValueError("restricted capture execution lease is invalid")
        now = require_counter(now_ms, "lease clock")
        duration = require_counter(lease_ms, "lease duration")
        if not MIN_EXECUTION_LEASE_MS <= duration <= MAX_EXECUTION_LEASE_MS:
            raise ValueError("restricted capture lease duration is invalid")
        expires = now + duration
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE capture_operation_leases SET expires_at_ms=? "
                    "WHERE operation_digest=? AND owner_digest=? AND generation=? "
                    "AND expires_at_ms>=?",
                    (
                        expires,
                        lease.operation_digest,
                        lease.owner_digest,
                        lease.generation,
                        now,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise RestrictedCaptureOperationConflict(
                        "restricted capture execution lease was lost"
                    )
                connection.commit()
        except RestrictedCaptureOperationError:
            raise
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation lease is unavailable"
            ) from exc
        return RestrictedCaptureExecutionLease(
            lease.operation_digest,
            lease.owner_digest,
            lease.generation,
            expires,
        )

    def release_execution_lease(self, lease: RestrictedCaptureExecutionLease) -> bool:
        if not isinstance(lease, RestrictedCaptureExecutionLease):
            raise ValueError("restricted capture execution lease is invalid")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "DELETE FROM capture_operation_leases WHERE operation_digest=? "
                    "AND owner_digest=? AND generation=?",
                    (lease.operation_digest, lease.owner_digest, lease.generation),
                )
                connection.commit()
                return cursor.rowcount == 1
        except Exception as exc:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation lease is unavailable"
            ) from exc

    @staticmethod
    def _request_from_row(row: sqlite3.Row) -> RestrictedCaptureRequest:
        return RestrictedCaptureRequest(
            requester_sid_digest=str(row["requester_sid_digest"]),
            installation_id=str(row["installation_id"]),
            epoch=int(row["epoch"]),
            root_revision=int(row["source_root_revision"]),
            operation_digest=str(row["operation_digest"]),
        )

    @classmethod
    def _operation_from_row(
        cls,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> RestrictedCaptureOperation:
        request = cls._request_from_row(row)
        if str(row["snapshot_id"]) != request.snapshot_id:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture snapshot index is invalid"
            )
        if str(row["maintenance_reason_digest"]) != request.maintenance_reason_digest:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture maintenance index is invalid"
            )
        receipts = cls._receipts_from_connection(connection, request)
        if not receipts:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation receipt chain is missing"
            )
        revision = require_counter(row["revision"], "operation revision")
        receipt_count = require_counter(row["receipt_count"], "operation receipt count")
        last_receipt_digest = require_digest(row["last_receipt_digest"], "last receipt")
        phase = str(row["phase"])
        if phase not in _PHASES:
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation phase is invalid"
            )
        if (
            len(receipts) != receipt_count
            or receipts[-1].sequence != revision
            or receipts[-1].receipt_digest != last_receipt_digest
            or receipts[-1].to_phase != phase
        ):
            raise RestrictedCaptureOperationUnavailable(
                "restricted capture operation receipt index is invalid"
            )
        return RestrictedCaptureOperation(
            request=request,
            snapshot_id=request.snapshot_id,
            maintenance_reason_digest=request.maintenance_reason_digest,
            phase=phase,  # type: ignore[arg-type]
            revision=revision,
            receipt_count=receipt_count,
            last_receipt_digest=last_receipt_digest,
            first_receipt=receipts[0],
            last_receipt=receipts[-1],
        )

    @classmethod
    def _receipts_from_connection(
        cls,
        connection: sqlite3.Connection,
        request: RestrictedCaptureRequest,
    ) -> tuple[RestrictedCaptureReceipt, ...]:
        values: list[RestrictedCaptureReceipt] = []
        previous_digest = _ZERO_DIGEST
        previous_phase: CapturePhase | None = None
        checkpoints: dict[CapturePhase, dict[str, object]] = {}
        for row in connection.execute(
            "SELECT * FROM capture_operation_receipts WHERE operation_digest=? "
            "ORDER BY sequence",
            (request.operation_digest,),
        ):
            sequence = require_counter(row["sequence"], "receipt sequence")
            if sequence != len(values) + 1:
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture receipt sequence is discontinuous"
                )
            raw_from_phase = row["from_phase"]
            from_phase = None if raw_from_phase is None else str(raw_from_phase)
            to_phase = str(row["to_phase"])
            checkpoint_kind = str(row["checkpoint_kind"])
            raw_recovery_authority = row["recovery_authority_digest"]
            recovery_authority_digest = (
                None
                if raw_recovery_authority is None
                else require_digest(
                    raw_recovery_authority,
                    "restricted capture recovery authority evidence",
                )
            )
            raw_authority_revision = row["authority_authorized_revision"]
            authority_authorized_revision = (
                None
                if raw_authority_revision is None
                else require_counter(
                    raw_authority_revision,
                    "restricted capture recovery authorized revision",
                )
            )
            raw_authority_last_receipt = row[
                "authority_authorized_last_receipt_digest"
            ]
            authority_authorized_last_receipt_digest = (
                None
                if raw_authority_last_receipt is None
                else require_digest(
                    raw_authority_last_receipt,
                    "restricted capture recovery authorized last receipt",
                )
            )
            if to_phase not in _PHASES or (from_phase is not None and from_phase not in _PHASES):
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture receipt phase is invalid"
                )
            if sequence == 1:
                legal = (
                    from_phase is None
                    and to_phase == "claimed"
                    and checkpoint_kind == "claimed"
                )
            else:
                legal = (
                    from_phase == previous_phase
                    and (
                        (
                            to_phase in _NORMAL_TRANSITIONS[from_phase]  # type: ignore[index]
                            and checkpoint_kind == to_phase
                        )
                        or (
                            from_phase == "recovery_required"
                            and to_phase in _RECOVERY_TRANSITIONS
                            and checkpoint_kind == to_phase
                        )
                        or (
                            from_phase == to_phase
                            and checkpoint_kind in _PROGRESS_CHECKPOINT_KINDS
                        )
                    )
                )
            if not legal:
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture receipt transition is invalid"
                )
            is_recovery_resolution = (
                from_phase == "recovery_required" and to_phase != "recovery_required"
            )
            authority_binding_present = (
                recovery_authority_digest is not None
                and authority_authorized_revision is not None
                and authority_authorized_last_receipt_digest is not None
            )
            authority_binding_absent = (
                recovery_authority_digest is None
                and authority_authorized_revision is None
                and authority_authorized_last_receipt_digest is None
            )
            if not (
                (is_recovery_resolution and authority_binding_present)
                or (not is_recovery_resolution and authority_binding_absent)
            ):
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture recovery authority binding is invalid"
                )
            if is_recovery_resolution and (
                authority_authorized_revision != sequence - 1
                or authority_authorized_last_receipt_digest != previous_digest
            ):
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture recovery authority is stale"
                )
            checkpoint_json = str(row["checkpoint_json"])
            try:
                decoded: Any = json.loads(checkpoint_json)
            except (TypeError, ValueError) as exc:
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture checkpoint is invalid"
                ) from exc
            if not isinstance(decoded, dict):
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture checkpoint is invalid"
                )
            expected_json, expected_checkpoint_digest = _checkpoint_values(
                checkpoint_kind,
                decoded,
                phase=to_phase,  # type: ignore[arg-type]
                request=request,
                from_phase=from_phase,  # type: ignore[arg-type]
            )
            stored_checkpoint_digest = str(row["checkpoint_digest"])
            stored_previous = str(row["previous_receipt_digest"])
            stored_receipt_digest = str(row["receipt_digest"])
            expected_receipt_digest = _receipt_digest(
                operation_digest=request.operation_digest,
                sequence=sequence,
                from_phase=from_phase,  # type: ignore[arg-type]
                to_phase=to_phase,  # type: ignore[arg-type]
                checkpoint_kind=checkpoint_kind,
                recovery_authority_digest=recovery_authority_digest,
                authority_authorized_revision=authority_authorized_revision,
                authority_authorized_last_receipt_digest=(
                    authority_authorized_last_receipt_digest
                ),
                checkpoint_json=expected_json,
                checkpoint_digest=expected_checkpoint_digest,
                previous_receipt_digest=stored_previous,
            )
            if (
                checkpoint_json != expected_json
                or stored_checkpoint_digest != expected_checkpoint_digest
                or stored_previous != previous_digest
                or stored_receipt_digest != expected_receipt_digest
            ):
                raise RestrictedCaptureOperationUnavailable(
                    "restricted capture operation receipt chain is invalid"
                )

            checkpoint = decoded
            if from_phase == to_phase:
                try:
                    if checkpoint_kind in _CLEANUP_PROGRESS_CHECKPOINT_KINDS:
                        _validate_cleanup_step(
                            tuple(values),
                            to_phase,  # type: ignore[arg-type]
                            checkpoint_kind,
                            checkpoint,
                        )
                    else:
                        _validate_progress_step(
                            tuple(values),
                            to_phase,  # type: ignore[arg-type]
                            checkpoint_kind,
                            checkpoint,
                        )
                except RestrictedCaptureOperationConflict as exc:
                    raise RestrictedCaptureOperationUnavailable(
                        "restricted capture progress chain is invalid"
                    ) from exc
            if checkpoint_kind == "quiescent":
                drains = {
                    item.checkpoint["component"]: item.checkpoint[
                        "quiescenceEvidenceDigest"
                    ]
                    for item in values
                    if item.checkpoint_kind == "drain_quiescent"
                }
                for component in CAPTURE_COMPONENT_ORDER:
                    field = {
                        "desktop": "desktopEvidenceDigest",
                        "gateway": "gatewayEvidenceDigest",
                        "gateway_assets": "gatewayAssetsEvidenceDigest",
                        "channel_media": "channelMediaEvidenceDigest",
                    }[component]
                    if checkpoint[field] != drains.get(component):
                        raise RestrictedCaptureOperationUnavailable(
                            "restricted capture component evidence binding is invalid"
                        )
            if checkpoint_kind == "root_locked":
                prior = checkpoints.get("quiescent")
                if prior is None or checkpoint["quiescenceDigest"] != prior["quiescenceDigest"]:
                    raise RestrictedCaptureOperationUnavailable(
                        "restricted capture quiescence binding is invalid"
                    )
            elif checkpoint_kind == "staging":
                prior = checkpoints.get("root_locked")
                quiescent = checkpoints.get("quiescent")
                if (
                    prior is None
                    or quiescent is None
                    or checkpoint["lockedRootRevision"]
                    != prior["lockedRootRevision"]
                    or checkpoint["rootSnapshotDigest"]
                    != prior["rootSnapshotDigest"]
                    or checkpoint["quiescenceDigest"]
                    != prior["quiescenceDigest"]
                    or checkpoint["desktopEvidenceDigest"]
                    != quiescent["desktopEvidenceDigest"]
                ):
                    raise RestrictedCaptureOperationUnavailable(
                        "restricted capture staged Root binding is invalid"
                    )
            elif checkpoint_kind == "staged_verified":
                prior = checkpoints.get("staging")
                root = checkpoints.get("root_locked")
                quiescent = checkpoints.get("quiescent")
                direct_recovery_valid = (
                    prior is None
                    and from_phase == "recovery_required"
                    and root is not None
                    and quiescent is not None
                    and checkpoint["lockedRootRevision"]
                    == root["lockedRootRevision"]
                    and checkpoint["rootSnapshotDigest"]
                    == root["rootSnapshotDigest"]
                    and checkpoint["quiescenceDigest"]
                    == root["quiescenceDigest"]
                    and checkpoint["desktopEvidenceDigest"]
                    == quiescent["desktopEvidenceDigest"]
                    and checkpoint["snapshotId"] == request.snapshot_id
                )
                prior_valid = prior is not None and not any(
                    checkpoint[field] != prior[field]
                    for field in (
                        "lockedRootRevision",
                        "rootSnapshotDigest",
                        "quiescenceDigest",
                        "desktopEvidenceDigest",
                        "artifactSetDigest",
                        "snapshotId",
                    )
                )
                if not (direct_recovery_valid or prior_valid):
                    raise RestrictedCaptureOperationUnavailable(
                        "restricted capture artifact binding is invalid"
                    )
            elif checkpoint_kind == "published":
                prior = checkpoints.get("staged_verified")
                root = checkpoints.get("root_locked")
                quiescent = checkpoints.get("quiescent")
                direct_recovery_valid = (
                    prior is None
                    and from_phase == "recovery_required"
                    and root is not None
                    and quiescent is not None
                    and checkpoint["lockedRootRevision"]
                    == root["lockedRootRevision"]
                    and checkpoint["rootSnapshotDigest"]
                    == root["rootSnapshotDigest"]
                    and checkpoint["quiescenceDigest"]
                    == root["quiescenceDigest"]
                    and checkpoint["desktopEvidenceDigest"]
                    == quiescent["desktopEvidenceDigest"]
                    and checkpoint["snapshotId"] == request.snapshot_id
                )
                prior_valid = prior is not None and not any(
                    checkpoint[field] != prior[field]
                    for field in (
                        "lockedRootRevision",
                        "rootSnapshotDigest",
                        "quiescenceDigest",
                        "desktopEvidenceDigest",
                        "artifactSetDigest",
                        "manifestSha256",
                        "snapshotId",
                    )
                )
                if not (direct_recovery_valid or prior_valid):
                    raise RestrictedCaptureOperationUnavailable(
                        "restricted capture publication binding is invalid"
                    )
            if checkpoint_kind in _TRANSITION_CHECKPOINT_KINDS:
                checkpoints[to_phase] = checkpoint  # type: ignore[index]
            values.append(
                RestrictedCaptureReceipt(
                    operation_digest=request.operation_digest,
                    sequence=sequence,
                    from_phase=from_phase,  # type: ignore[arg-type]
                    to_phase=to_phase,  # type: ignore[arg-type]
                    checkpoint_kind=checkpoint_kind,
                    recovery_authority_digest=recovery_authority_digest,
                    authority_authorized_revision=authority_authorized_revision,
                    authority_authorized_last_receipt_digest=(
                        authority_authorized_last_receipt_digest
                    ),
                    checkpoint_json=checkpoint_json,
                    checkpoint_digest=stored_checkpoint_digest,
                    previous_receipt_digest=stored_previous,
                    receipt_digest=stored_receipt_digest,
                )
            )
            previous_digest = stored_receipt_digest
            previous_phase = to_phase  # type: ignore[assignment]
        return tuple(values)


__all__ = [
    "CAPTURE_STORE_MAX_PAGES",
    "CAPTURE_STORE_PAGE_SIZE",
    "MAX_CAPTURE_CHECKPOINT_BYTES",
    "MAX_CAPTURE_OPERATIONS",
    "MAX_CAPTURE_RECEIPTS",
    "MAX_CAPTURE_RECEIPTS_PER_OPERATION",
    "MAX_CAPTURE_STORE_BYTES",
    "MAX_CAPTURE_STORE_FAMILY_BYTES",
    "MAX_EXECUTION_LEASE_MS",
    "MIN_EXECUTION_LEASE_MS",
    "RestrictedCaptureExecutionLease",
    "RestrictedCaptureOperation",
    "RestrictedCaptureOperationCapacityError",
    "RestrictedCaptureOperationConflict",
    "RestrictedCaptureOperationError",
    "RestrictedCaptureOperationStore",
    "RestrictedCaptureOperationUnavailable",
    "RestrictedCaptureReceipt",
]
