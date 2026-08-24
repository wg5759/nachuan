from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

import gateway.restricted_capture_operation_store as operation_store_module
from gateway.restricted_capture_contract import (
    CAPTURE_COMPONENT_ORDER,
    RestrictedCaptureRequest,
)
from gateway.restricted_capture_operation_store import (
    RestrictedCaptureExecutionLease,
    RestrictedCaptureOperationCapacityError,
    RestrictedCaptureOperationConflict,
    RestrictedCaptureOperationError,
    RestrictedCaptureOperationStore,
    RestrictedCaptureOperationUnavailable,
)


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _request() -> RestrictedCaptureRequest:
    return RestrictedCaptureRequest(
        requester_sid_digest=_digest("requester-sid"),
        installation_id=_digest("installation"),
        epoch=3,
        root_revision=19,
        operation_digest=_digest("capture-operation"),
    )


def _request_named(label: str) -> RestrictedCaptureRequest:
    return RestrictedCaptureRequest(
        requester_sid_digest=_digest(f"requester-sid:{label}"),
        installation_id=_digest("installation"),
        epoch=3,
        root_revision=19,
        operation_digest=_digest(f"capture-operation:{label}"),
    )


def _database_family(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-journal", "-wal", "-shm")
        for candidate in (Path(f"{path}{suffix}"),)
    }


def _create_abandoned_operation_wal(path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute('BEGIN IMMEDIATE')
connection.execute('UPDATE capture_operations SET revision=revision')
connection.commit()
os._exit(0)
""",
            os.fspath(path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _provision(path: Path) -> RestrictedCaptureOperationStore:
    return RestrictedCaptureOperationStore.provision(
        path,
        allow_unleased_test_mutations=True,
    )


def _advance_to_quiescent(
    store: RestrictedCaptureOperationStore,
    request: RestrictedCaptureRequest,
):
    state = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    state = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=state.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence")},
    )
    for component in CAPTURE_COMPONENT_ORDER:
        state = store.record_progress(
            request.operation_digest,
            expected_phase="fencing",
            expected_revision=state.revision,
            checkpoint_kind="drain_begun",
            checkpoint={
                "component": component,
                "beginEvidenceDigest": _digest(f"begin:{component}"),
            },
        )
    quiescence_evidence = {}
    for component in CAPTURE_COMPONENT_ORDER:
        evidence = _digest(f"quiescent:{component}")
        quiescence_evidence[component] = evidence
        state = store.record_progress(
            request.operation_digest,
            expected_phase="fencing",
            expected_revision=state.revision,
            checkpoint_kind="drain_quiescent",
            checkpoint={
                "component": component,
                "quiescenceEvidenceDigest": evidence,
            },
        )
    return store.transition(
        request.operation_digest,
        expected_phase="fencing",
        expected_revision=state.revision,
        to_phase="quiescent",
        checkpoint={
            "observedRootRevision": request.root_revision,
            "quiescenceDigest": _digest("all-quiescent"),
            "desktopEvidenceDigest": quiescence_evidence["desktop"],
            "gatewayEvidenceDigest": quiescence_evidence["gateway"],
            "gatewayAssetsEvidenceDigest": quiescence_evidence["gateway_assets"],
            "channelMediaEvidenceDigest": quiescence_evidence["channel_media"],
        },
    )


def test_claimed_operation_and_first_receipt_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "restricted-capture-operations.db"
    request = _request()
    store = _provision(path)

    created = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("ticket-claim-evidence")},
    )
    reopened = RestrictedCaptureOperationStore.open(path)

    assert reopened.get(request.operation_digest) == created
    assert reopened.receipts(request.operation_digest) == (
        created.first_receipt,
    )
    assert created.phase == "claimed"
    assert created.revision == 1
    assert created.first_receipt.previous_receipt_digest == "0" * 64
    assert created.first_receipt.to_phase == "claimed"


def test_recoverable_discovery_is_bounded_ordered_and_read_only(tmp_path: Path) -> None:
    path = tmp_path / "restricted-capture-operations.db"
    store = _provision(path)
    requests = sorted(
        (_request_named("c"), _request_named("a"), _request_named("b")),
        key=lambda item: item.operation_digest,
    )
    for request in requests:
        store.create_claimed(
            request,
            checkpoint={"claimBindingDigest": _digest(f"claim:{request.operation_digest}")},
        )
    terminal = requests[1]
    terminal_state = store.get(terminal.operation_digest)
    assert terminal_state is not None
    store.transition(
        terminal.operation_digest,
        expected_phase="claimed",
        expected_revision=terminal_state.revision,
        to_phase="failed_clean",
        checkpoint={"cleanupEvidenceDigest": _digest("terminal-clean")},
    )

    before = _database_family(path)
    first = store.discover_recoverable_operations(limit=1)
    second = store.discover_recoverable_operations(
        after_operation_digest=first.next_cursor,
        limit=1,
    )
    after = _database_family(path)

    expected = [
        request.operation_digest
        for request in requests
        if request.operation_digest != terminal.operation_digest
    ]
    assert [item.request.operation_digest for item in first.items] == expected[:1]
    assert first.next_cursor == expected[0]
    assert [item.request.operation_digest for item in second.items] == expected[1:]
    assert second.next_cursor is None
    assert before == after


def test_recoverable_discovery_rejects_unbounded_or_malformed_requests(
    tmp_path: Path,
) -> None:
    store = _provision(tmp_path / "restricted-capture-operations.db")

    with pytest.raises(ValueError, match="discovery request is invalid"):
        store.discover_recoverable_operations(limit=0)
    with pytest.raises(ValueError, match="discovery request is invalid"):
        store.discover_recoverable_operations(limit=129)
    with pytest.raises(ValueError, match="discovery request is invalid"):
        store.discover_recoverable_operations(
            after_operation_digest="not-a-digest",
            limit=1,
        )


def test_recoverable_discovery_rejects_incomplete_wal_without_creating_shm(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restricted-capture-operations.db"
    request = _request()
    store = _provision(path)
    store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    _create_abandoned_operation_wal(path)
    Path(f"{path}-shm").unlink()
    before = _database_family(path)

    with pytest.raises(
        RestrictedCaptureOperationUnavailable,
        match="operation discovery is unavailable",
    ):
        store.discover_recoverable_operations(limit=8)

    assert _database_family(path) == before
    assert not Path(f"{path}-shm").exists()


def test_recoverable_discovery_reads_complete_wal_without_writing_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restricted-capture-operations.db"
    request = _request()
    store = _provision(path)
    store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    _create_abandoned_operation_wal(path)
    before = _database_family(path)

    page = store.discover_recoverable_operations(limit=8)
    after = _database_family(path)

    assert [item.request.operation_digest for item in page.items] == [
        request.operation_digest
    ]
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-journal"] == before["-journal"]


def test_phase_cas_appends_receipt_and_rejects_stale_revision(tmp_path: Path) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    claimed = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("ticket-claim-evidence")},
    )

    fencing = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence-evidence")},
    )

    receipts = store.receipts(request.operation_digest)
    assert fencing.phase == "fencing"
    assert fencing.revision == 2
    assert receipts[0] == claimed.first_receipt
    assert receipts[1].from_phase == "claimed"
    assert receipts[1].to_phase == "fencing"
    assert receipts[1].previous_receipt_digest == receipts[0].receipt_digest
    with pytest.raises(RestrictedCaptureOperationConflict, match="CAS"):
        store.transition(
            request.operation_digest,
            expected_phase="claimed",
            expected_revision=claimed.revision,
            to_phase="fencing",
            checkpoint={"globalFenceDigest": _digest("stale-fence-evidence")},
        )


def test_exact_create_and_transition_retries_are_idempotent(tmp_path: Path) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    claim_evidence = _digest("ticket-claim-evidence")

    claimed = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": claim_evidence},
    )
    retried_claim = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": claim_evidence},
    )
    fencing = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence-evidence")},
    )
    retried_fencing = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence-evidence")},
    )

    assert retried_claim == claimed
    assert retried_fencing == fencing
    assert len(store.receipts(request.operation_digest)) == 2

    with pytest.raises(RestrictedCaptureOperationConflict):
        store.create_claimed(
            request,
            checkpoint={"claimBindingDigest": _digest("different-claim-evidence")},
        )
    with pytest.raises(RestrictedCaptureOperationConflict):
        store.transition(
            request.operation_digest,
            expected_phase="claimed",
            expected_revision=claimed.revision,
            to_phase="fencing",
            checkpoint={"globalFenceDigest": _digest("different-fence-evidence")},
        )


def test_receipt_persists_strict_phase_specific_canonical_checkpoint(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    claim_checkpoint = {"claimBindingDigest": _digest("claim-binding")}

    claimed = store.create_claimed(request, checkpoint=claim_checkpoint)
    fencing = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence")},
    )

    receipts = store.receipts(request.operation_digest)
    assert receipts[0].checkpoint == claim_checkpoint
    assert receipts[0].checkpoint_json == (
        '{"claimBindingDigest":"' + _digest("claim-binding") + '"}'
    )
    assert receipts[1].checkpoint == {
        "globalFenceDigest": _digest("global-fence")
    }
    assert fencing.phase == "fencing"

    with pytest.raises(ValueError, match="checkpoint"):
        store.transition(
            request.operation_digest,
            expected_phase="fencing",
            expected_revision=fencing.revision,
            to_phase="quiescent",
            checkpoint={"ticketSecret": "must-never-be-persisted"},
        )


def test_same_phase_component_progress_is_append_only_and_idempotent(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    claimed = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    fencing = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence")},
    )

    begun = store.record_progress(
        request.operation_digest,
        expected_phase="fencing",
        expected_revision=fencing.revision,
        checkpoint_kind="drain_begun",
        checkpoint={
            "component": "desktop",
            "beginEvidenceDigest": _digest("desktop-begin"),
        },
    )
    retried = store.record_progress(
        request.operation_digest,
        expected_phase="fencing",
        expected_revision=fencing.revision,
        checkpoint_kind="drain_begun",
        checkpoint={
            "component": "desktop",
            "beginEvidenceDigest": _digest("desktop-begin"),
        },
    )

    assert begun == retried
    assert begun.phase == "fencing"
    assert begun.revision == fencing.revision + 1
    assert begun.last_receipt.from_phase == "fencing"
    assert begun.last_receipt.to_phase == "fencing"
    assert begun.last_receipt.checkpoint_kind == "drain_begun"
    assert begun.last_receipt.checkpoint["component"] == "desktop"


def test_root_lock_checkpoint_requires_enter_maintenance_cas_revision(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    quiescent = _advance_to_quiescent(store, request)

    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": _digest("root-snapshot"),
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": _digest("all-quiescent"),
        },
    )

    assert locked.phase == "root_locked"
    assert locked.last_receipt.checkpoint["lockedRootRevision"] == 20


def test_verified_checkpoint_binds_locked_root_quiescence_and_desktop_evidence(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    quiescent = _advance_to_quiescent(store, request)
    root_snapshot = _digest("root-snapshot")
    quiescence = _digest("all-quiescent")
    desktop = _digest("quiescent:desktop")
    artifact_set = _digest("artifact-set")
    manifest = _digest("manifest")
    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": quiescence,
        },
    )

    staging = store.transition(
        request.operation_digest,
        expected_phase="root_locked",
        expected_revision=locked.revision,
        to_phase="staging",
        checkpoint={
            "snapshotId": request.snapshot_id,
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "quiescenceDigest": quiescence,
            "desktopEvidenceDigest": desktop,
            "artifactSetDigest": artifact_set,
            "stagingEvidenceDigest": _digest("staging"),
        },
    )
    verified = store.transition(
        request.operation_digest,
        expected_phase="staging",
        expected_revision=staging.revision,
        to_phase="staged_verified",
        checkpoint={
            "snapshotId": request.snapshot_id,
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "quiescenceDigest": quiescence,
            "desktopEvidenceDigest": desktop,
            "artifactSetDigest": artifact_set,
            "manifestSha256": manifest,
            "verificationEvidenceDigest": _digest("verification"),
        },
    )

    assert verified.last_receipt.checkpoint["manifestSha256"] == manifest
    assert verified.last_receipt.checkpoint["rootSnapshotDigest"] == root_snapshot


def test_open_rejects_unknown_database_without_changing_bytes_or_journal_mode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unknown.db"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before_bytes = path.read_bytes()
    before_names = sorted(item.name for item in tmp_path.iterdir())
    with sqlite3.connect(path) as connection:
        before_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]

    with pytest.raises(RestrictedCaptureOperationUnavailable):
        RestrictedCaptureOperationStore.open(path)

    assert path.read_bytes() == before_bytes
    assert sorted(item.name for item in tmp_path.iterdir()) == before_names
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == before_mode


def test_unknown_database_is_rejected_before_any_mutating_pragma(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unknown.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
    original_connect = sqlite3.connect
    statements: list[str] = []

    class _ConnectionSpy:
        def __init__(self, inner: sqlite3.Connection) -> None:
            self._inner = inner

        @property
        def row_factory(self):  # noqa: ANN201
            return self._inner.row_factory

        @row_factory.setter
        def row_factory(self, value) -> None:  # noqa: ANN001
            self._inner.row_factory = value

        def execute(self, statement: str, *args):  # noqa: ANN002, ANN201
            statements.append(statement)
            return self._inner.execute(statement, *args)

        def close(self) -> None:
            self._inner.close()

        def __getattr__(self, name: str):  # noqa: ANN204
            return getattr(self._inner, name)

    def _connect(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        return _ConnectionSpy(original_connect(*args, **kwargs))

    monkeypatch.setattr(operation_store_module.sqlite3, "connect", _connect)

    with pytest.raises(RestrictedCaptureOperationUnavailable):
        RestrictedCaptureOperationStore.open(path)

    mutating_pragmas = [
        statement
        for statement in statements
        if statement.upper().startswith("PRAGMA JOURNAL_MODE=")
        or statement.upper().startswith("PRAGMA MAX_PAGE_COUNT=")
    ]
    assert mutating_pragmas == []


def test_recovery_resolution_can_resume_from_verified_partial_checkpoint(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    quiescent = _advance_to_quiescent(store, request)
    root_snapshot = _digest("root-snapshot")
    quiescence = _digest("all-quiescent")
    desktop = _digest("quiescent:desktop")
    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": quiescence,
        },
    )
    recovery_required = store.transition(
        request.operation_digest,
        expected_phase="root_locked",
        expected_revision=locked.revision,
        to_phase="recovery_required",
        checkpoint={
            "failedPhase": "root_locked",
            "failureDigest": _digest("stage-outcome-unknown"),
        },
    )

    staging = store.resolve_recovery(
        request.operation_digest,
        expected_revision=recovery_required.revision,
        to_phase="staging",
        recovery_authority_digest=_digest("recovery-authority"),
        authority_authorized_revision=recovery_required.revision,
        authority_authorized_last_receipt_digest=(
            recovery_required.last_receipt_digest
        ),
        checkpoint={
            "snapshotId": request.snapshot_id,
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "quiescenceDigest": quiescence,
            "desktopEvidenceDigest": desktop,
            "artifactSetDigest": _digest("inspected-artifact-set"),
            "stagingEvidenceDigest": _digest("partial-inspection"),
        },
    )

    assert staging.phase == "staging"
    recovery_receipts = store.receipts(request.operation_digest)
    assert [receipt.to_phase for receipt in recovery_receipts][-2:] == [
        "recovery_required",
        "staging",
    ]
    assert recovery_receipts[-1].recovery_authority_digest == _digest(
        "recovery-authority"
    )
    assert (
        recovery_receipts[-1].authority_authorized_revision
        == recovery_required.revision
    )
    assert (
        recovery_receipts[-1].authority_authorized_last_receipt_digest
        == recovery_required.last_receipt_digest
    )


def test_recovery_resolution_rejects_authority_for_a_stale_chain_head(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    quiescent = _advance_to_quiescent(store, request)
    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": _digest("root-snapshot"),
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": _digest("all-quiescent"),
        },
    )
    recovery = store.transition(
        request.operation_digest,
        expected_phase="root_locked",
        expected_revision=locked.revision,
        to_phase="recovery_required",
        checkpoint={
            "failedPhase": "root_locked",
            "failureDigest": _digest("stage-outcome-unknown"),
        },
    )

    with pytest.raises(RestrictedCaptureOperationConflict, match="authority is stale"):
        store.resolve_recovery(
            request.operation_digest,
            expected_revision=recovery.revision,
            to_phase="staging",
            recovery_authority_digest=_digest("stale-recovery-authority"),
            authority_authorized_revision=locked.revision,
            authority_authorized_last_receipt_digest=locked.last_receipt_digest,
            checkpoint={
                "snapshotId": request.snapshot_id,
                "lockedRootRevision": request.root_revision + 1,
                "rootSnapshotDigest": _digest("root-snapshot"),
                "quiescenceDigest": _digest("all-quiescent"),
                "desktopEvidenceDigest": _digest("quiescent:desktop"),
                "artifactSetDigest": _digest("inspected-artifact-set"),
                "stagingEvidenceDigest": _digest("partial-inspection"),
            },
        )

    unchanged = store.get(request.operation_digest)
    assert unchanged == recovery
    assert len(store.receipts(request.operation_digest)) == recovery.revision


def test_receipt_rows_cannot_be_updated_deleted_or_replaced(tmp_path: Path) -> None:
    path = tmp_path / "operations.db"
    request = _request()
    store = _provision(path)
    store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT * FROM capture_operation_receipts"
        ).fetchone()
        assert row is not None
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "UPDATE capture_operation_receipts SET checkpoint_json='{}'"
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("DELETE FROM capture_operation_receipts")
        with pytest.raises(sqlite3.DatabaseError, match="replacement"):
            connection.execute(
                "INSERT OR REPLACE INTO capture_operation_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )


def test_open_rejects_unknown_schema_object_and_tampered_receipt_chain(
    tmp_path: Path,
) -> None:
    unknown_path = tmp_path / "unknown-object.db"
    _provision(unknown_path)
    with sqlite3.connect(unknown_path) as connection:
        connection.execute("CREATE VIEW unexpected_view AS SELECT 1 AS value")
    with pytest.raises(RestrictedCaptureOperationUnavailable):
        RestrictedCaptureOperationStore.open(unknown_path)

    tampered_path = tmp_path / "tampered-chain.db"
    request = _request()
    store = _provision(tampered_path)
    store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    with sqlite3.connect(tampered_path) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='capture_operation_receipts_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER capture_operation_receipts_no_update")
        connection.execute(
            "UPDATE capture_operation_receipts SET checkpoint_json=?",
            ('{"claimBindingDigest":"' + _digest("tampered") + '"}',),
        )
        connection.execute(trigger_sql)
    with pytest.raises(RestrictedCaptureOperationUnavailable):
        RestrictedCaptureOperationStore.open(tampered_path)


def test_fixed_row_capacity_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _provision(tmp_path / "operations.db")
    first = _request()
    store.create_claimed(
        first,
        checkpoint={"claimBindingDigest": _digest("first-binding")},
    )
    monkeypatch.setattr(operation_store_module, "MAX_CAPTURE_OPERATIONS", 1)
    second = RestrictedCaptureRequest(
        requester_sid_digest=first.requester_sid_digest,
        installation_id=first.installation_id,
        epoch=first.epoch,
        root_revision=first.root_revision,
        operation_digest=_digest("second-operation"),
    )

    with pytest.raises(RestrictedCaptureOperationCapacityError, match="capacity"):
        store.create_claimed(
            second,
            checkpoint={"claimBindingDigest": _digest("second-binding")},
        )

    monkeypatch.setattr(operation_store_module, "MAX_CAPTURE_OPERATIONS", 128)
    monkeypatch.setattr(operation_store_module, "MAX_CAPTURE_RECEIPTS", 1)
    with pytest.raises(RestrictedCaptureOperationCapacityError, match="capacity"):
        store.transition(
            first.operation_digest,
            expected_phase="claimed",
            expected_revision=1,
            to_phase="fencing",
            checkpoint={"globalFenceDigest": _digest("global-fence")},
        )


def test_execution_lease_fences_honest_concurrent_core_calls(tmp_path: Path) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    owner_a = _digest("lease-owner-a")
    owner_b = _digest("lease-owner-b")

    first = store.acquire_execution_lease(
        request.operation_digest,
        owner_digest=owner_a,
        now_ms=1_000,
        lease_ms=1_000,
    )
    exact_retry = store.acquire_execution_lease(
        request.operation_digest,
        owner_digest=owner_a,
        now_ms=1_100,
        lease_ms=1_000,
    )
    with pytest.raises(RestrictedCaptureOperationConflict, match="held"):
        store.acquire_execution_lease(
            request.operation_digest,
            owner_digest=owner_b,
            now_ms=1_500,
            lease_ms=1_000,
        )
    successor = store.acquire_execution_lease(
        request.operation_digest,
        owner_digest=owner_b,
        now_ms=2_001,
        lease_ms=1_000,
    )

    assert isinstance(first, RestrictedCaptureExecutionLease)
    assert exact_retry == first
    assert successor.generation == first.generation + 1
    with pytest.raises(RestrictedCaptureOperationConflict, match="lost"):
        store.renew_execution_lease(first, now_ms=2_001, lease_ms=1_000)


def test_cleanup_progress_releases_only_persisted_holds_in_reverse_order(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    state = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    state = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=state.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence")},
    )
    for component in ("desktop", "gateway"):
        state = store.record_progress(
            request.operation_digest,
            expected_phase="fencing",
            expected_revision=state.revision,
            checkpoint_kind="drain_begun",
            checkpoint={
                "component": component,
                "beginEvidenceDigest": _digest(f"begin:{component}"),
            },
        )

    for component in ("gateway", "desktop"):
        state = store.record_cleanup_progress(
            request.operation_digest,
            expected_phase="fencing",
            expected_revision=state.revision,
            checkpoint_kind="cleanup_component_released",
            checkpoint={
                "component": component,
                "releaseEvidenceDigest": _digest(f"release:{component}"),
            },
        )
    state = store.record_cleanup_progress(
        request.operation_digest,
        expected_phase="fencing",
        expected_revision=state.revision,
        checkpoint_kind="cleanup_global_released",
        checkpoint={"globalReleaseEvidenceDigest": _digest("release:global")},
    )
    failed = store.transition(
        request.operation_digest,
        expected_phase="fencing",
        expected_revision=state.revision,
        to_phase="failed_clean",
        checkpoint={"cleanupEvidenceDigest": _digest("cleanup-complete")},
    )

    assert failed.phase == "failed_clean"
    assert [
        receipt.checkpoint.get("component")
        for receipt in store.receipts(request.operation_digest)
        if receipt.checkpoint_kind == "cleanup_component_released"
    ] == ["gateway", "desktop"]


def test_recovery_cannot_skip_held_resource_release_to_a_terminal_phase(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _provision(tmp_path / "operations.db")
    quiescent = _advance_to_quiescent(store, request)
    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": _digest("root-snapshot"),
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": _digest("all-quiescent"),
        },
    )
    recovery = store.transition(
        request.operation_digest,
        expected_phase="root_locked",
        expected_revision=locked.revision,
        to_phase="recovery_required",
        checkpoint={
            "failedPhase": "root_locked",
            "failureDigest": _digest("stage-failure"),
        },
    )

    with pytest.raises(RestrictedCaptureOperationConflict):
        store.resolve_recovery(
            request.operation_digest,
            expected_revision=recovery.revision,
            to_phase="completed",
            recovery_authority_digest=_digest("recovery-authority"),
            authority_authorized_revision=recovery.revision,
            authority_authorized_last_receipt_digest=recovery.last_receipt_digest,
            checkpoint={"resumeEvidenceDigest": _digest("unproven-completion")},
        )
    with pytest.raises(RestrictedCaptureOperationConflict, match="publication"):
        store.resolve_recovery(
            request.operation_digest,
            expected_revision=recovery.revision,
            to_phase="resuming",
            recovery_authority_digest=_digest("recovery-authority"),
            authority_authorized_revision=recovery.revision,
            authority_authorized_last_receipt_digest=recovery.last_receipt_digest,
            checkpoint={"resumeIntentDigest": _digest("unpublished-resume")},
        )
    with pytest.raises(RestrictedCaptureOperationConflict, match="cleanup"):
        store.resolve_recovery(
            request.operation_digest,
            expected_revision=recovery.revision,
            to_phase="failed_clean",
            recovery_authority_digest=_digest("recovery-authority"),
            authority_authorized_revision=recovery.revision,
            authority_authorized_last_receipt_digest=recovery.last_receipt_digest,
            checkpoint={"cleanupEvidenceDigest": _digest("unproven-cleanup")},
        )


def test_cross_binding_mismatch_rolls_back_candidate_receipt_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operations.db"
    request = _request()
    store = _provision(path)
    quiescent = _advance_to_quiescent(store, request)
    root_snapshot = _digest("root-snapshot")
    quiescence = _digest("all-quiescent")
    locked = store.transition(
        request.operation_digest,
        expected_phase="quiescent",
        expected_revision=quiescent.revision,
        to_phase="root_locked",
        checkpoint={
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "rootLockEvidenceDigest": _digest("root-lock"),
            "quiescenceDigest": quiescence,
        },
    )
    staging = store.transition(
        request.operation_digest,
        expected_phase="root_locked",
        expected_revision=locked.revision,
        to_phase="staging",
        checkpoint={
            "snapshotId": request.snapshot_id,
            "lockedRootRevision": request.root_revision + 1,
            "rootSnapshotDigest": root_snapshot,
            "quiescenceDigest": quiescence,
            "desktopEvidenceDigest": _digest("quiescent:desktop"),
            "artifactSetDigest": _digest("artifact-set"),
            "stagingEvidenceDigest": _digest("staging"),
        },
    )
    before_receipts = store.receipts(request.operation_digest)

    with pytest.raises(RestrictedCaptureOperationError):
        store.transition(
            request.operation_digest,
            expected_phase="staging",
            expected_revision=staging.revision,
            to_phase="staged_verified",
            checkpoint={
                "snapshotId": request.snapshot_id,
                "lockedRootRevision": request.root_revision + 1,
                "rootSnapshotDigest": root_snapshot,
                "quiescenceDigest": quiescence,
                "desktopEvidenceDigest": _digest("quiescent:desktop"),
                "artifactSetDigest": _digest("different-artifact-set"),
                "manifestSha256": _digest("manifest"),
                "verificationEvidenceDigest": _digest("verification"),
            },
        )

    reopened = RestrictedCaptureOperationStore.open(path)
    assert reopened.get(request.operation_digest) == staging
    assert reopened.receipts(request.operation_digest) == before_receipts


def test_default_store_rejects_unleased_mutation_and_stale_owner_commit(
    tmp_path: Path,
) -> None:
    request = _request()
    store = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    claimed = store.create_claimed(
        request,
        checkpoint={"claimBindingDigest": _digest("claim-binding")},
    )
    with pytest.raises(RestrictedCaptureOperationConflict, match="lease is required"):
        store.transition(
            request.operation_digest,
            expected_phase="claimed",
            expected_revision=claimed.revision,
            to_phase="fencing",
            checkpoint={"globalFenceDigest": _digest("global-fence")},
        )

    owner_a = store.acquire_execution_lease(
        request.operation_digest,
        owner_digest=_digest("owner-a"),
        now_ms=1_000,
        lease_ms=1_000,
    )
    owner_b = store.acquire_execution_lease(
        request.operation_digest,
        owner_digest=_digest("owner-b"),
        now_ms=2_001,
        lease_ms=1_000,
    )
    before = store.receipts(request.operation_digest)
    with pytest.raises(RestrictedCaptureOperationConflict, match="lease was lost"):
        store.transition(
            request.operation_digest,
            expected_phase="claimed",
            expected_revision=claimed.revision,
            to_phase="fencing",
            checkpoint={"globalFenceDigest": _digest("global-fence")},
            lease=owner_a,
            now_ms=2_001,
        )
    assert store.receipts(request.operation_digest) == before
    advanced = store.transition(
        request.operation_digest,
        expected_phase="claimed",
        expected_revision=claimed.revision,
        to_phase="fencing",
        checkpoint={"globalFenceDigest": _digest("global-fence")},
        lease=owner_b,
        now_ms=2_001,
    )
    assert advanced.phase == "fencing"


def test_claimed_receipt_and_first_lease_are_one_atomic_race_winner(
    tmp_path: Path,
) -> None:
    request = _request()
    store = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")

    def _attempt(owner: str):  # noqa: ANN202
        return store.create_claimed_and_acquire_lease(
            request,
            checkpoint={"claimBindingDigest": _digest("claim-binding")},
            owner_digest=_digest(owner),
            now_ms=1_000,
            lease_ms=60_000,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_attempt, owner) for owner in ("owner-a", "owner-b")]
    successes = []
    conflicts = []
    for future in futures:
        try:
            successes.append(future.result())
        except RestrictedCaptureOperationConflict as exc:
            conflicts.append(exc)

    assert len(successes) == 1
    assert len(conflicts) == 1
    assert store.get(request.operation_digest) is not None
    assert len(store.receipts(request.operation_digest)) == 1
