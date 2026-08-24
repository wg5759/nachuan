from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from threading import Barrier

import pytest

from gateway import privacy_rights as privacy_rights_module
from gateway.privacy_rights import (
    PrivacyRightsCapacity,
    PrivacyRightsConflict,
    PrivacyRightsIncomplete,
    PrivacyRightsLedger,
    PrivacyRightsUnavailable,
    PrivacyRightsValidationError,
    RightsScopeStep,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request_id(label: str = "request") -> str:
    return "dsr-v1:" + _digest(label)


def _receipt_id(label: str) -> str:
    return "receipt-v1:" + _digest(label)


def _sqlite_family_artifacts(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    }


def _create_abandoned_foreign_hot_wal(path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute('BEGIN IMMEDIATE')
connection.execute('CREATE TABLE alien(value TEXT NOT NULL)')
connection.execute("INSERT INTO alien(value) VALUES('foreign-hot-wal')")
connection.commit()
os._exit(0)
""",
            os.fspath(path),
        ],
        cwd=os.fspath(path.parent),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _create_abandoned_supported_privacy_wal(path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
from gateway import privacy_rights as module
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
connection.execute(module._REQUESTS_DDL)
connection.execute(module._STEPS_DDL)
connection.execute(module._RECEIPTS_DDL)
connection.commit()
os._exit(0)
""",
            os.fspath(path),
        ],
        cwd=os.fspath(Path(__file__).resolve().parents[1]),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def test_abandoned_foreign_hot_wal_is_rejected_without_checkpointing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "foreign-hot-wal.db"
    _create_abandoned_foreign_hot_wal(path)
    main_before = path.read_bytes()
    wal = Path(f"{path}-wal")
    wal_before = wal.read_bytes()

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(path)

    assert path.read_bytes() == main_before
    assert wal.read_bytes() == wal_before
    assert Path(f"{path}-shm").is_file()
    assert not Path(f"{path}-journal").exists()


def test_missing_main_with_orphan_sidecars_is_rejected_without_provisioning(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-sidecars.db"
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    wal.write_bytes(b"orphan-wal-evidence")
    shm.write_bytes(b"orphan-shm-evidence")

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(path)

    assert not path.exists()
    assert wal.read_bytes() == b"orphan-wal-evidence"
    assert shm.read_bytes() == b"orphan-shm-evidence"


def test_supported_privacy_generation_committed_only_in_wal_is_recovered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supported-generation-in-wal.db"
    _create_abandoned_supported_privacy_wal(path)

    with sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True
    ) as immutable:
        assert immutable.execute("SELECT COUNT(*) FROM sqlite_master").fetchone() == (0,)
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as wal_aware:
        assert wal_aware.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'privacy_rights_%'"
        ).fetchone() == (3,)

    PrivacyRightsLedger(path)
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as recovered:
        assert recovered.execute("PRAGMA application_id").fetchone() == (
            privacy_rights_module._APPLICATION_ID,
        )
        assert recovered.execute("PRAGMA user_version").fetchone() == (1,)


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_privacy_wal_pair_is_rejected_without_mutation(
    tmp_path: Path,
    missing_suffix: str,
) -> None:
    path = tmp_path / f"incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_foreign_hot_wal(path)
    Path(f"{path}{missing_suffix}").unlink()
    before = {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    }

    with pytest.raises(PrivacyRightsUnavailable):
        PrivacyRightsLedger(path)

    after = {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    }
    assert after == before


def test_privacy_rollback_journal_is_preserved_and_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rollback-journal.db"
    sqlite3.connect(path).close()
    journal = Path(f"{path}-journal")
    journal.write_bytes(b"unresolved-rollback-evidence")
    main_before = path.read_bytes()

    with pytest.raises(PrivacyRightsUnavailable):
        PrivacyRightsLedger(path)

    assert path.read_bytes() == main_before
    assert journal.read_bytes() == b"unresolved-rollback-evidence"


def _inject_reserved_prefix_view(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) "
            "VALUES('view','sqlite_nachuan_unauthorized',"
            "'sqlite_nachuan_unauthorized',0,"
            "'CREATE VIEW sqlite_nachuan_unauthorized AS SELECT 1 AS injected_value')"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")


def _tamper_internal_tbl_name(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        name, original = connection.execute(
            "SELECT name,tbl_name FROM sqlite_master "
            "WHERE name LIKE 'sqlite_autoindex_%' ORDER BY name LIMIT 1"
        ).fetchone()
        replacement = (
            "privacy_rights_scope_steps"
            if original != "privacy_rights_scope_steps"
            else "privacy_rights_receipts"
        )
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name=? WHERE name=?",
            (replacement, name),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")


def test_delete_saga_requires_dependency_receipts_and_survives_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    ledger = PrivacyRightsLedger(database)
    request_id = _request_id()

    submitted = ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("tenant-a/subject-a"),
    )
    assert submitted.state == "identity_pending"
    assert ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("verified-owner-session"),
    ).state == "identity_pending"

    scoped = ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="revoke-provider-key",
                store_id="connections_and_provider_credentials",
                operation="revoke_upstream",
            ),
            RightsScopeStep(
                step_id="erase-local-key",
                store_id="connections_and_provider_credentials",
                operation="erase_local_secret",
                depends_on=("revoke-provider-key",),
            ),
            RightsScopeStep(
                step_id="conversation-tombstone",
                store_id="conversations_and_summaries",
                operation="tombstone",
            ),
        ),
    )
    assert scoped.state == "scoped"
    assert scoped.total_steps == 3
    ledger.start(request_id=request_id)

    with pytest.raises(PrivacyRightsIncomplete, match="dependency"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="erase-local-key",
            receipt_id=_receipt_id("erase-too-early"),
            outcome="completed",
            evidence_sha256=_digest("local-key-erased"),
            affected_count=1,
        )

    ledger.record_receipt(
        request_id=request_id,
        step_id="revoke-provider-key",
        receipt_id=_receipt_id("provider-revoked"),
        outcome="completed",
        evidence_sha256=_digest("upstream-revocation-receipt"),
        affected_count=1,
    )
    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-local-key",
        receipt_id=_receipt_id("local-erased"),
        outcome="completed",
        evidence_sha256=_digest("local-key-erased"),
        affected_count=1,
    )
    ledger.record_receipt(
        request_id=request_id,
        step_id="conversation-tombstone",
        receipt_id=_receipt_id("tombstone-unknown"),
        outcome="unknown",
        evidence_sha256=_digest("worker-disconnected"),
        error_code="worker_result_unknown",
    )

    with pytest.raises(PrivacyRightsIncomplete, match="not complete"):
        ledger.finalize(request_id=request_id)

    restarted = PrivacyRightsLedger(database)
    recovered = restarted.snapshot(request_id=request_id)
    assert recovered.state == "partially_completed"
    assert recovered.completed_steps == 2
    assert recovered.unknown_steps == 1

    restarted.record_receipt(
        request_id=request_id,
        step_id="conversation-tombstone",
        receipt_id=_receipt_id("tombstone-retry"),
        outcome="completed",
        evidence_sha256=_digest("durable-tombstone"),
        affected_count=4,
    )
    completed = restarted.finalize(request_id=request_id)
    assert completed.state == "completed"
    assert completed.completed_steps == completed.total_steps == 3

    second_restart = PrivacyRightsLedger(database)
    assert second_restart.snapshot(request_id=request_id) == completed


def test_request_scope_and_receipt_idempotency_reject_semantic_conflicts(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("idempotent")
    submitted = ledger.submit(
        request_id=request_id,
        action="export",
        subject_digest=_digest("subject"),
    )
    assert ledger.submit(
        request_id=request_id,
        action="export",
        subject_digest=_digest("subject"),
    ) == submitted

    with pytest.raises(PrivacyRightsConflict, match="request_id"):
        ledger.submit(
            request_id=request_id,
            action="delete",
            subject_digest=_digest("subject"),
        )

    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    scope = (
        RightsScopeStep(
            step_id="export-conversations",
            store_id="conversations_and_summaries",
            operation="export",
        ),
    )
    frozen = ledger.freeze_scope(request_id=request_id, steps=scope)
    assert ledger.freeze_scope(request_id=request_id, steps=scope) == frozen

    with pytest.raises(PrivacyRightsConflict, match="scope"):
        ledger.freeze_scope(
            request_id=request_id,
            steps=(
                RightsScopeStep(
                    step_id="export-knowledge",
                    store_id="knowledge_memory_and_cases",
                    operation="export",
                ),
            ),
        )

    ledger.start(request_id=request_id)
    receipt_id = _receipt_id("exported")
    first = ledger.record_receipt(
        request_id=request_id,
        step_id="export-conversations",
        receipt_id=receipt_id,
        outcome="completed",
        evidence_sha256=_digest("export-manifest"),
        affected_count=2,
    )
    assert ledger.record_receipt(
        request_id=request_id,
        step_id="export-conversations",
        receipt_id=receipt_id,
        outcome="completed",
        evidence_sha256=_digest("export-manifest"),
        affected_count=2,
    ) == first

    with pytest.raises(PrivacyRightsConflict, match="receipt_id"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="export-conversations",
            receipt_id=receipt_id,
            outcome="unknown",
            evidence_sha256=_digest("different"),
            error_code="worker_result_unknown",
        )


def test_unknown_missing_and_retryable_results_never_finalize(tmp_path: Path) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("incomplete")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="erase-conversations",
                store_id="conversations_and_summaries",
                operation="erase",
            ),
            RightsScopeStep(
                step_id="notify-provider",
                store_id="conversations_and_summaries",
                operation="notify_processor",
                depends_on=("erase-conversations",),
            ),
        ),
    )
    ledger.start(request_id=request_id)

    with pytest.raises(PrivacyRightsIncomplete, match="not complete"):
        ledger.finalize(request_id=request_id)

    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-conversations",
        receipt_id=_receipt_id("retryable"),
        outcome="retryable_error",
        evidence_sha256=_digest("locked"),
        error_code="store_busy",
    )
    snapshot = ledger.snapshot(request_id=request_id)
    assert snapshot.state == "partially_completed"
    assert snapshot.completed_steps == 0
    assert snapshot.retryable_steps == 1

    with pytest.raises(PrivacyRightsIncomplete, match="not complete"):
        ledger.finalize(request_id=request_id)


def test_restore_unlock_requires_completed_tombstone_reapplication(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("restore")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )

    with pytest.raises(PrivacyRightsValidationError, match="unlock_restore"):
        ledger.freeze_scope(
            request_id=request_id,
            steps=(
                RightsScopeStep(
                    step_id="unlock",
                    store_id="backups_and_restore_evidence",
                    operation="unlock_restore",
                ),
            ),
        )

    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="reapply-deletion",
                store_id="backups_and_restore_evidence",
                operation="reapply_tombstone",
            ),
            RightsScopeStep(
                step_id="unlock",
                store_id="backups_and_restore_evidence",
                operation="unlock_restore",
                depends_on=("reapply-deletion",),
            ),
        ),
    )
    ledger.start(request_id=request_id)

    with pytest.raises(PrivacyRightsIncomplete, match="dependency"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="unlock",
            receipt_id=_receipt_id("unlock-too-early"),
            outcome="completed",
            evidence_sha256=_digest("restore-ready"),
        )


def test_database_retains_digests_not_raw_identity_or_customer_content(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    secret = "customer-secret-prompt-never-persist"
    ledger = PrivacyRightsLedger(database)
    ledger.submit(
        request_id=_request_id("redaction"),
        action="restrict",
        subject_digest=_digest(secret),
    )

    raw = database.read_bytes()
    assert secret.encode("utf-8") not in raw
    assert b"customer-secret" not in raw


def test_non_digest_identity_and_evidence_are_rejected(tmp_path: Path) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("invalid")
    with pytest.raises(PrivacyRightsValidationError, match="subject_digest"):
        ledger.submit(
            request_id=request_id,
            action="delete",
            subject_digest="alice@example.com",
        )

    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("alice@example.com"),
    )
    with pytest.raises(PrivacyRightsValidationError, match="evidence_sha256"):
        ledger.verify_identity(
            request_id=request_id,
            evidence_sha256="Bearer live-secret",
        )


def test_lookalike_schema_without_constraints_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE privacy_rights_requests (
                request_id TEXT PRIMARY KEY,
                semantic_sha256 TEXT NOT NULL,
                action TEXT NOT NULL,
                subject_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                identity_evidence_sha256 TEXT,
                scope_sha256 TEXT,
                rejection_code TEXT,
                rejection_evidence_sha256 TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            ) WITHOUT ROWID
            """
        )

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)

    with sqlite3.connect(database) as connection:
        objects = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'privacy_rights_%'
            ORDER BY name
            """
        ).fetchall()
    assert objects == [("privacy_rights_requests",)]


def test_unexpected_trigger_on_rights_tables_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights.db"
    PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER capture_rights_state
            AFTER UPDATE ON privacy_rights_requests
            BEGIN
                SELECT NEW.state;
            END
            """
        )

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)


def test_schema_authority_rejects_quoted_literal_case_collision(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    PrivacyRightsLedger(database)

    with sqlite3.connect(database) as connection:
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='privacy_rights_requests'",
            ("'rejected_with_reason'", "'REJECTED_WITH_REASON'"),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)


def test_unexpected_explicit_index_on_rights_tables_is_rejected(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE UNIQUE INDEX unexpected_subject_unique
            ON privacy_rights_requests(subject_digest)
            """
        )

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)


def test_database_identity_is_stamped_and_versioned_corruption_is_not_healed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            privacy_rights_module._APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        connection.execute("DROP TABLE privacy_rights_receipts")

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "privacy_rights_receipts" not in tables


@pytest.mark.parametrize("generation", ("current", "legacy_empty"))
def test_privacy_schema_generations_reject_reserved_prefix_object(
    tmp_path: Path, generation: str
) -> None:
    database = tmp_path / f"privacy-rights-{generation}.db"
    PrivacyRightsLedger(database)
    if generation == "legacy_empty":
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA application_id=0")
            connection.execute("PRAGMA user_version=0")
    _inject_reserved_prefix_view(database)
    before = database.read_bytes()

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    assert database.read_bytes() == before


def test_privacy_rejects_internal_tbl_name_drift_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights-internal-metadata.db"
    PrivacyRightsLedger(database)
    _tamper_internal_tbl_name(database)
    before = database.read_bytes()

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    assert database.read_bytes() == before


def test_unversioned_rogue_database_is_rejected_without_partial_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated_customer_data(value TEXT)")
        original_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert connection.execute("PRAGMA application_id").fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]) == original_mode
    assert tables == {"unrelated_customer_data"}


def test_concurrent_owner_claim_before_second_check_does_not_change_journal_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "privacy-rights.db"
    original_preflight = PrivacyRightsLedger._stabilized_database_preflight
    injected = False

    def interleaving_preflight(self):  # noqa: ANN001, ANN202
        nonlocal injected
        result = original_preflight(self)
        if not injected:
            injected = True
            with sqlite3.connect(database) as competing_owner:
                competing_owner.execute(
                    "CREATE TABLE concurrent_owner_data(value TEXT NOT NULL)"
                )
                competing_owner.execute(
                    "INSERT INTO concurrent_owner_data(value) VALUES ('preserve-me')"
                )
        return result

    monkeypatch.setattr(
        PrivacyRightsLedger,
        "_stabilized_database_preflight",
        interleaving_preflight,
    )
    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)

    with sqlite3.connect(database) as connection:
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]) == "delete"
        assert connection.execute("PRAGMA application_id").fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert connection.execute(
            "SELECT value FROM concurrent_owner_data"
        ).fetchone() == ("preserve-me",)


def test_runtime_schema_and_identity_drift_blocks_the_next_submission(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights-runtime-drift.db"
    ledger = PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE VIEW rogue_privacy_view AS "
            "SELECT request_id FROM privacy_rights_requests"
        )
        connection.execute("PRAGMA user_version=999")
        connection.commit()

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        ledger.submit(
            request_id=_request_id("runtime-drift"),
            action="delete",
            subject_digest=_digest("runtime-drift-subject"),
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM privacy_rights_requests"
        ).fetchone() == (0,)


def test_snapshot_rejects_replaced_same_table_database_with_wrong_authority_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights-snapshot-authority.db"
    replacement = tmp_path / "privacy-rights-snapshot-replacement.db"
    accepted_original = tmp_path / "privacy-rights-snapshot-accepted.db"
    request_id = _request_id("snapshot-wrong-authority")
    ledger = PrivacyRightsLedger(database)
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("snapshot-wrong-authority-subject"),
    )

    with closing(sqlite3.connect(database)) as source, closing(
        sqlite3.connect(replacement)
    ) as target:
        source.backup(target)
    with closing(sqlite3.connect(replacement)) as changed:
        changed.execute("PRAGMA application_id=0")
        changed.execute("PRAGMA user_version=0")
        changed.execute(
            "CREATE VIEW extra_privacy_view AS "
            "SELECT request_id FROM privacy_rights_requests"
        )
        changed.commit()
        assert changed.execute(
            "SELECT action,state FROM privacy_rights_requests WHERE request_id=?",
            (request_id,),
        ).fetchone() == ("delete", "identity_pending")

    os.replace(database, accepted_original)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{database}{suffix}")
        if sidecar.exists():
            os.replace(sidecar, Path(f"{accepted_original}{suffix}"))
    os.replace(replacement, database)
    before = _sqlite_family_artifacts(database)

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        ledger.snapshot(request_id=request_id)

    assert _sqlite_family_artifacts(database) == before


def test_concurrent_cold_start_all_instances_converge(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights-cold-start.db"
    barrier = Barrier(8)

    def open_ledger(_index: int) -> bool:
        barrier.wait(timeout=10)
        PrivacyRightsLedger(database, busy_timeout_ms=10_000)
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(open_ledger, range(8)))

    assert results == [True] * 8
    PrivacyRightsLedger(database)


def test_cold_start_preflight_uses_the_bounded_busy_budget(monkeypatch) -> None:
    """A peer journal lasting just over 2 s must not defeat a larger budget."""

    ledger = object.__new__(PrivacyRightsLedger)
    ledger.busy_timeout_ms = 1_000
    clock = [0.0]
    result = (
        "established",
        None,
        {"": True, "-wal": True, "-shm": True, "-journal": False},
    )

    def preflight():
        if clock[0] < 2.5:
            raise privacy_rights_module._PrivacyDatabaseFamilyChanged(
                "peer initialization is still committing"
            )
        return result

    monkeypatch.setattr(ledger, "_preflight_database_kind", preflight)
    monkeypatch.setattr(
        privacy_rights_module.time, "monotonic", lambda: clock[0]
    )
    monkeypatch.setattr(
        privacy_rights_module.time,
        "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    assert ledger._stabilized_database_preflight() == result
    assert 2.5 <= clock[0] < 5.0


def test_partial_unversioned_schema_is_rejected_without_self_healing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "privacy-rights.db"
    with sqlite3.connect(database) as connection:
        connection.execute(privacy_rights_module._REQUESTS_DDL)
        original_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        objects = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        }
        assert connection.execute("PRAGMA application_id").fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]) == original_mode
    assert objects == {"privacy_rights_requests"}


def test_complete_unversioned_schema_is_validated_then_adopted(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights.db"
    with sqlite3.connect(database) as connection:
        connection.execute(privacy_rights_module._REQUESTS_DDL)
        connection.execute(privacy_rights_module._STEPS_DDL)
        connection.execute(privacy_rights_module._RECEIPTS_DDL)

    PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            privacy_rights_module._APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]) == "wal"


def test_unversioned_schema_with_rows_requires_explicit_migration(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights.db"
    request_id = _request_id("legacy-row")
    with sqlite3.connect(database) as connection:
        connection.execute(privacy_rights_module._REQUESTS_DDL)
        connection.execute(privacy_rights_module._STEPS_DDL)
        connection.execute(privacy_rights_module._RECEIPTS_DDL)
        connection.execute(
            """
            INSERT INTO privacy_rights_requests(
                request_id, semantic_sha256, action, subject_digest, state,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, 'delete', ?, 'identity_pending', 1, 1)
            """,
            (request_id, _digest("legacy-semantic"), _digest("legacy-subject")),
        )
        original_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])

    with pytest.raises(PrivacyRightsUnavailable, match="unavailable"):
        PrivacyRightsLedger(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]) == original_mode
        assert connection.execute(
            "SELECT request_id FROM privacy_rights_requests"
        ).fetchone() == (request_id,)


def test_rejection_is_content_free_idempotent_and_terminal(tmp_path: Path) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("rejected")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    rejected = ledger.reject(
        request_id=request_id,
        reason_code="identity_not_verified",
        evidence_sha256=_digest("review-receipt"),
    )
    assert rejected.state == "rejected_with_reason"
    assert ledger.reject(
        request_id=request_id,
        reason_code="identity_not_verified",
        evidence_sha256=_digest("review-receipt"),
    ) == rejected
    with pytest.raises(PrivacyRightsConflict, match="different reason"):
        ledger.reject(
            request_id=request_id,
            reason_code="out_of_scope",
            evidence_sha256=_digest("other-review"),
        )


def test_snapshot_is_one_consistent_read_during_concurrent_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "privacy-rights.db"
    reader = PrivacyRightsLedger(database)
    writer = PrivacyRightsLedger(database)
    request_id = _request_id("snapshot-race")
    reader.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    reader.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    reader.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="erase-content",
                store_id="conversations_and_summaries",
                operation="erase",
            ),
        ),
    )
    reader.start(request_id=request_id)

    original_connection = reader._readonly_logical_snapshot
    injected = False

    class _InterleavingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, statement, parameters=()):  # noqa: ANN001, ANN201
            nonlocal injected
            cursor = self.connection.execute(statement, parameters)
            normalized = " ".join(str(statement).split())
            if (
                not injected
                and normalized.startswith("SELECT action, state, scope_sha256")
            ):
                injected = True
                writer.record_receipt(
                    request_id=request_id,
                    step_id="erase-content",
                    receipt_id=_receipt_id("concurrent-receipt"),
                    outcome="completed",
                    evidence_sha256=_digest("deleted"),
                    affected_count=1,
                )
            return cursor

    @contextmanager
    def interleaving_connection():
        with original_connection() as connection:
            yield _InterleavingConnection(connection)

    monkeypatch.setattr(
        reader,
        "_readonly_logical_snapshot",
        interleaving_connection,
    )
    snapshot = reader.snapshot(request_id=request_id)

    assert injected is True
    assert snapshot.state == "executing"
    assert snapshot.completed_steps == 0
    assert snapshot.ready_to_finalize is False
    committed = writer.snapshot(request_id=request_id)
    assert committed.state == "partially_completed"
    assert committed.completed_steps == 1


def test_wall_clock_rollback_does_not_break_valid_state_transitions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("clock-rollback")
    created = ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )

    monkeypatch.setattr(privacy_rights_module.time, "time_ns", lambda: 0)
    verified = ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    assert verified.updated_at_ms >= created.updated_at_ms

    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="erase-content",
                store_id="conversations_and_summaries",
                operation="erase",
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-content",
        receipt_id=_receipt_id("clock-receipt"),
        outcome="completed",
        evidence_sha256=_digest("deleted"),
        affected_count=1,
    )
    completed = ledger.finalize(request_id=request_id)
    assert completed.state == "completed"
    assert completed.updated_at_ms >= created.updated_at_ms
    with sqlite3.connect(ledger.path) as connection:
        receipt_times = [
            int(row[0])
            for row in connection.execute(
                """
                SELECT created_at_ms FROM privacy_rights_receipts
                WHERE request_id = ? ORDER BY attempt
                """,
                (request_id,),
            ).fetchall()
        ]
    assert receipt_times
    assert receipt_times == sorted(receipt_times)
    assert receipt_times[0] >= created.created_at_ms


def test_permanent_error_requires_reasoned_rejection_not_silent_retry(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("permanent-error")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="notify-processor",
                store_id="conversations_and_summaries",
                operation="notify_processor",
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="notify-processor",
        receipt_id=_receipt_id("processor-refused"),
        outcome="permanent_error",
        evidence_sha256=_digest("processor-refusal-receipt"),
        error_code="processor_refused_deletion",
    )

    with pytest.raises(PrivacyRightsConflict, match="permanent"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="notify-processor",
            receipt_id=_receipt_id("silent-retry"),
            outcome="completed",
            evidence_sha256=_digest("unreviewed-claim"),
        )

    rejected = ledger.reject(
        request_id=request_id,
        reason_code="processor_refused_deletion",
        evidence_sha256=_digest("human-review-decision"),
    )
    assert rejected.state == "rejected_with_reason"
    assert rejected.permanent_error_steps == 1


def test_partial_unknown_result_cannot_be_rejected_as_permanent(tmp_path: Path) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("unknown-not-rejected")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="erase-content",
                store_id="conversations_and_summaries",
                operation="erase",
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-content",
        receipt_id=_receipt_id("unknown"),
        outcome="unknown",
        evidence_sha256=_digest("worker-disconnected"),
        error_code="worker_result_unknown",
    )

    with pytest.raises(PrivacyRightsIncomplete, match="permanent"):
        ledger.reject(
            request_id=request_id,
            reason_code="cannot_confirm_deletion",
            evidence_sha256=_digest("premature-review"),
        )


@pytest.mark.parametrize(
    ("outcome", "error_code"),
    [
        ("completed", None),
        ("retryable_error", "store_busy"),
        ("permanent_error", "store_refused"),
        ("unknown", "worker_result_unknown"),
        ("not_applicable", "dependency_not_terminal"),
    ],
)
def test_dependency_fence_blocks_every_adapter_outcome_before_prerequisite(
    tmp_path: Path,
    outcome: str,
    error_code: str | None,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / f"privacy-rights-{outcome}.db")
    request_id = _request_id(f"dependency-{outcome}")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="revoke-upstream",
                store_id="connections_and_provider_credentials",
                operation="revoke_upstream",
            ),
            RightsScopeStep(
                step_id="erase-local-secret",
                store_id="connections_and_provider_credentials",
                operation="erase_local_secret",
                depends_on=("revoke-upstream",),
            ),
        ),
    )
    ledger.start(request_id=request_id)

    with pytest.raises(PrivacyRightsIncomplete, match="dependency"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="erase-local-secret",
            receipt_id=_receipt_id(f"too-early-{outcome}"),
            outcome=outcome,
            evidence_sha256=_digest("must-not-persist"),
            error_code=error_code,
        )
    snapshot = ledger.snapshot(request_id=request_id)
    assert snapshot.completed_steps == 0
    assert snapshot.unknown_steps == 0
    assert snapshot.retryable_steps == 0
    assert snapshot.permanent_error_steps == 0
    assert snapshot.not_applicable_steps == 0


def test_reasoned_rejection_requires_no_unknown_or_retryable_steps(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("mixed-permanent-unknown")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="processor-a",
                store_id="conversations_and_summaries",
                operation="notify_processor",
            ),
            RightsScopeStep(
                step_id="processor-b",
                store_id="knowledge_memory_and_cases",
                operation="notify_processor",
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="processor-a",
        receipt_id=_receipt_id("permanent-a"),
        outcome="permanent_error",
        evidence_sha256=_digest("refusal-a"),
        error_code="processor_refused_deletion",
    )
    ledger.record_receipt(
        request_id=request_id,
        step_id="processor-b",
        receipt_id=_receipt_id("unknown-b"),
        outcome="unknown",
        evidence_sha256=_digest("lost-b"),
        error_code="worker_result_unknown",
    )

    with pytest.raises(PrivacyRightsIncomplete, match="unresolved"):
        ledger.reject(
            request_id=request_id,
            reason_code="processor_refused_deletion",
            evidence_sha256=_digest("human-review"),
        )


def test_identity_verification_replay_after_rejection_is_idempotent(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("identity-replay-after-reject")
    evidence = _digest("identity")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(request_id=request_id, evidence_sha256=evidence)
    rejected = ledger.reject(
        request_id=request_id,
        reason_code="request_out_of_scope",
        evidence_sha256=_digest("review"),
    )

    assert ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=evidence,
    ) == rejected
    with pytest.raises(PrivacyRightsConflict, match="identity evidence"):
        ledger.verify_identity(
            request_id=request_id,
            evidence_sha256=_digest("different-identity"),
        )


def test_permanent_dependency_uses_explicit_not_applicable_before_rejection(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    request_id = _request_id("permanent-dependency")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="revoke-upstream",
                store_id="connections_and_provider_credentials",
                operation="revoke_upstream",
            ),
            RightsScopeStep(
                step_id="erase-local-secret",
                store_id="connections_and_provider_credentials",
                operation="erase_local_secret",
                depends_on=("revoke-upstream",),
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="revoke-upstream",
        receipt_id=_receipt_id("revocation-refused"),
        outcome="permanent_error",
        evidence_sha256=_digest("provider-refusal"),
        error_code="provider_refused_revocation",
    )

    with pytest.raises(PrivacyRightsIncomplete, match="unresolved"):
        ledger.reject(
            request_id=request_id,
            reason_code="provider_refused_revocation",
            evidence_sha256=_digest("review-before-skip"),
        )

    skipped = ledger.record_receipt(
        request_id=request_id,
        step_id="erase-local-secret",
        receipt_id=_receipt_id("local-erase-not-run"),
        outcome="not_applicable",
        evidence_sha256=_digest("dependency-blocked-no-local-action"),
        error_code="dependency_permanent_error",
    )
    assert skipped.not_applicable_steps == 1
    assert skipped.ready_to_finalize is False

    rejected = ledger.reject(
        request_id=request_id,
        reason_code="provider_refused_revocation",
        evidence_sha256=_digest("human-review"),
    )
    assert rejected.state == "rejected_with_reason"
    assert rejected.permanent_error_steps == 1
    assert rejected.not_applicable_steps == 1


def test_not_applicable_receipt_cannot_claim_affected_records(tmp_path: Path) -> None:
    ledger = PrivacyRightsLedger(tmp_path / "privacy-rights.db")
    with pytest.raises(PrivacyRightsValidationError, match="affected records"):
        ledger.record_receipt(
            request_id=_request_id("not-applicable-count"),
            step_id="blocked-step",
            receipt_id=_receipt_id("impossible-count"),
            outcome="not_applicable",
            evidence_sha256=_digest("no-action-taken"),
            affected_count=5,
            error_code="dependency_permanent_error",
        )


def test_request_capacity_preserves_existing_idempotent_replay(tmp_path: Path) -> None:
    database = tmp_path / "privacy-rights.db"
    ledger = PrivacyRightsLedger(
        database,
        max_requests=1,
        max_main_db_bytes=1024 * 1024,
    )
    first_id = _request_id("capacity-first")
    first = ledger.submit(
        request_id=first_id,
        action="delete",
        subject_digest=_digest("capacity-subject"),
    )
    assert ledger.submit(
        request_id=first_id,
        action="delete",
        subject_digest=_digest("capacity-subject"),
    ) == first
    with pytest.raises(PrivacyRightsCapacity, match="request capacity"):
        ledger.submit(
            request_id=_request_id("capacity-second"),
            action="delete",
            subject_digest=_digest("different-subject"),
        )
    assert ledger.snapshot(request_id=first_id) == first
    # max_page_count is enforced per SQLite connection, so inspect the ledger's
    # configured connection rather than an unrelated raw connection.
    with ledger._connection() as connection:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        max_pages = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
    assert max_pages * page_size <= 1024 * 1024


def test_retry_capacity_reserves_final_slot_for_terminal_receipt(
    tmp_path: Path,
) -> None:
    ledger = PrivacyRightsLedger(
        tmp_path / "privacy-rights.db",
        max_receipts_per_step=3,
    )
    request_id = _request_id("bounded-retries")
    ledger.submit(
        request_id=request_id,
        action="delete",
        subject_digest=_digest("subject"),
    )
    ledger.verify_identity(
        request_id=request_id,
        evidence_sha256=_digest("identity"),
    )
    ledger.freeze_scope(
        request_id=request_id,
        steps=(
            RightsScopeStep(
                step_id="erase-content",
                store_id="conversations_and_summaries",
                operation="erase",
            ),
        ),
    )
    ledger.start(request_id=request_id)
    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-content",
        receipt_id=_receipt_id("attempt-one"),
        outcome="unknown",
        evidence_sha256=_digest("unknown-one"),
        error_code="worker_result_unknown",
    )
    ledger.record_receipt(
        request_id=request_id,
        step_id="erase-content",
        receipt_id=_receipt_id("attempt-two"),
        outcome="retryable_error",
        evidence_sha256=_digest("retryable-two"),
        error_code="store_busy",
    )

    with pytest.raises(PrivacyRightsCapacity, match="reserved"):
        ledger.record_receipt(
            request_id=request_id,
            step_id="erase-content",
            receipt_id=_receipt_id("attempt-three-unknown"),
            outcome="unknown",
            evidence_sha256=_digest("unknown-three"),
            error_code="worker_result_unknown",
        )

    terminal = ledger.record_receipt(
        request_id=request_id,
        step_id="erase-content",
        receipt_id=_receipt_id("attempt-three-completed"),
        outcome="completed",
        evidence_sha256=_digest("deleted"),
        affected_count=1,
    )
    assert terminal.ready_to_finalize is True
    assert ledger.finalize(request_id=request_id).state == "completed"
