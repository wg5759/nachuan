"""Durable idempotency for paid image/video creation requests."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest

import gateway.durable_media_requests as durable_media_requests
from gateway.paid_media_asset_protocol import RESULT_SCHEMA, create_asset_token
from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRootCommitPending,
    DurableMediaRootState,
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_principal,
    hash_media_request,
)


def _create_legacy_v1_media_database(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(durable_media_requests._REQUEST_TABLE_DDL)
        connection.execute(durable_media_requests._LEGACY_META_TABLE_DDL)
        connection.execute(
            "INSERT INTO durable_media_requests_meta "
            "(singleton,schema_version,schema_fingerprint,record_count,"
            "response_bytes,reserved_bytes,max_records,max_response_bytes,"
            "max_total_response_bytes,max_database_bytes) "
            "VALUES(1,1,?,0,0,0,50000,25165824,536870912,1073741824)",
            (durable_media_requests._LEGACY_SCHEMA_FINGERPRINT,),
        )
        for ddl in durable_media_requests._BASE_SCHEMA_AUXILIARY_DDL.values():
            connection.execute(ddl)
        connection.execute(
            f"PRAGMA application_id={durable_media_requests._APPLICATION_ID}"
        )
        connection.execute("PRAGMA user_version=1")
        connection.commit()


def _create_legacy_v2_media_database(path: Path, identity: str) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(durable_media_requests._REQUEST_TABLE_DDL)
        connection.execute(durable_media_requests._V2_META_TABLE_DDL)
        connection.execute(
            "INSERT INTO durable_media_requests_meta "
            "(singleton,schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,record_count,response_bytes,reserved_bytes,max_records,"
            "max_response_bytes,max_total_response_bytes,max_database_bytes) "
            "VALUES(1,2,?,?,0,0,0,0,50000,134217728,536870912,1073741824)",
            (durable_media_requests._V2_SCHEMA_FINGERPRINT, identity),
        )
        for ddl in durable_media_requests._BASE_SCHEMA_AUXILIARY_DDL.values():
            connection.execute(ddl)
        connection.execute(
            f"PRAGMA application_id={durable_media_requests._APPLICATION_ID}"
        )
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    Path(f"{path}.rollback-anchor").write_text(
        json.dumps(
            {
                "database_identity": identity,
                "format": 1,
                "mutation_sequence": "0000000000000000",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )


def _inject_reserved_prefix_view(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
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
        connection.commit()


def _tamper_schema_tbl_name(path: Path, *, object_name: str, tbl_name: str) -> None:
    with closing(sqlite3.connect(path)) as connection:
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name=? WHERE name=?",
            (tbl_name, object_name),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()


def _media_db_artifacts(path: Path) -> dict[str, bytes]:
    return {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal", ".rollback-anchor")
        if (candidate := Path(f"{path}{suffix}")).exists()
    }


def _run_isolated_python(script: str, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script, os.fspath(path)],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _create_abandoned_media_wal(path: Path, statement: str) -> None:
    created = _run_isolated_python(
        f"""
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
connection.execute({statement!r})
connection.commit()
os._exit(0)
""",
        path,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


@pytest.mark.parametrize(
    "value",
    [
        1234567890123456,
        b"desktop-11111111-1111-4111-8111-111111111111",
    ],
)
def test_idempotency_key_rejects_non_string_values(value: object) -> None:
    with pytest.raises(ValueError, match="Idempotency-Key"):
        durable_media_requests.validate_media_idempotency_key(value)


def test_default_profile_remains_paid_v4_with_thirty_day_retention(tmp_path):
    path = tmp_path / "paid-default-profile.db"
    store = DurableMediaRequestStore(path)
    try:
        assert store.retention_seconds == 30 * 24 * 60 * 60
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            durable_media_requests._APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute(
            "SELECT schema_fingerprint FROM durable_media_requests_meta "
            "WHERE singleton=1"
        ).fetchone() == (durable_media_requests._SCHEMA_FINGERPRINT,)
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE name='durable_channel_media_admissions'"
        ).fetchone() == (0,)


def _asset_success(turn_id: str, *, kind: str = "image") -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "kind": kind,
        "created": 1_784_200_000,
        "turnId": turn_id,
        "assets": [
            {
                "token": create_asset_token(),
                "mediaType": "image/png" if kind == "image" else "video/mp4",
                "byteLength": 123,
                "sha256": "d" * 64,
                "validationReceiptSha256": "e" * 64,
            }
        ],
    }


def _commit_asset_success(
    store: DurableMediaRequestStore,
    *,
    principal: str,
    idempotency_key: str,
    request_sha256: str = "b" * 64,
    now: float = 10.0,
) -> tuple[object, dict[str, object]]:
    claim = store.claim(
        principal_hash=principal,
        operation="images.create",
        idempotency_key=idempotency_key,
        request_sha256=request_sha256,
        max_success_bytes=1024 * 1024,
        now=now,
    )
    assert store.reserve_asset_capacity(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=principal,
        operation="images.create",
        installation_epoch=7,
    )
    assert store.enter_provider_phase(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        max_success_bytes=1024 * 1024,
        now=now + 1,
    )
    response = _asset_success(claim.turn_id)
    assert store.succeed(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        response=response,
        now=now + 2,
    )
    return claim, response


def test_v2_claims_reserve_one_mib_metadata_not_legacy_response_ceiling(
    tmp_path: Path,
) -> None:
    one_mib = 1024 * 1024
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        max_response_bytes=2 * one_mib,
        max_total_response_bytes=2 * one_mib,
    )
    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-v2-capacity-0001",
            request_sha256="b" * 64,
            max_success_bytes=one_mib,
            now=1.0,
        )
        second = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-v2-capacity-0002",
            request_sha256="c" * 64,
            max_success_bytes=one_mib,
            now=1.0,
        )
        with pytest.raises(DurableMediaRequestUnavailable, match="capacity"):
            store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key="desktop-v2-capacity-0003",
                request_sha256="d" * 64,
                max_success_bytes=one_mib,
                now=1.0,
            )
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            max_success_bytes=one_mib,
            now=2.0,
        )
        assert store.enter_provider_phase(
            turn_id=second.turn_id,
            fencing_token=second.fencing_token,
            max_success_bytes=one_mib,
            now=2.0,
        )
        with closing(sqlite3.connect(store.path)) as connection:
            assert connection.execute(
                "SELECT reserved_bytes FROM durable_media_requests_meta WHERE singleton=1"
            ).fetchone() == (2 * one_mib,)
    finally:
        store.close()


def test_committed_asset_success_is_excluded_from_global_and_exact_ttl_prune(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    principal = "a" * 64
    key = "desktop-asset-prune-protected-0001"
    store = DurableMediaRequestStore(path)
    try:
        claim, response = _commit_asset_success(
            store,
            principal=principal,
            idempotency_key=key,
        )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "UPDATE durable_media_requests SET expires_at=0 WHERE turn_id=?",
                (claim.turn_id,),
            )
            connection.commit()
            before_capacity = connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone()
        store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-trigger-global-prune-0002",
            request_sha256="c" * 64,
            max_success_bytes=1024 * 1024,
            now=40 * 24 * 60 * 60.0,
        )
        replay = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key=key,
            request_sha256="b" * 64,
            max_success_bytes=1024 * 1024,
            now=40 * 24 * 60 * 60.0,
        )
        assert replay.state == "succeeded" and replay.response == response
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT state FROM durable_media_asset_authority WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == ("committed",)
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == before_capacity
    finally:
        store.close()


def test_acked_pending_cleanup_is_not_pruned_and_conflicting_ack_is_typed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    principal = "a" * 64
    store = DurableMediaRequestStore(path)
    try:
        claim, response = _commit_asset_success(
            store,
            principal=principal,
            idempotency_key="desktop-asset-pending-prune-0001",
        )
        tokens = [asset["token"] for asset in response["assets"]]  # type: ignore[index]
        store.ack_asset_success(
            turn_id=claim.turn_id,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
            tokens=tokens,
            archive_receipt_sha256="9" * 64,
            now=20.0,
        )
        with pytest.raises(DurableMediaAssetConflict):
            store.ack_asset_success(
                turn_id=claim.turn_id,
                principal_hash=principal,
                operation="images.create",
                installation_epoch=7,
                tokens=tokens,
                archive_receipt_sha256="8" * 64,
                now=21.0,
            )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "UPDATE durable_media_requests SET expires_at=0 WHERE turn_id=?",
                (claim.turn_id,),
            )
            connection.commit()
        store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-trigger-pending-prune-0002",
            request_sha256="c" * 64,
            max_success_bytes=1024 * 1024,
            now=40 * 24 * 60 * 60.0,
        )
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT state,reserved_bytes FROM durable_media_asset_authority "
                "WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == (
                "acked_pending_cleanup",
                durable_media_requests._ASSET_OPERATION_RESERVATION_BYTES,
            )
    finally:
        store.close()


def test_asset_success_is_exactly_reread_and_never_pruned_before_ack(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    principal = "a" * 64
    store = DurableMediaRequestStore(path)
    try:
        claim = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-asset-success-0001",
            request_sha256="b" * 64,
            now=10.0,
        )
        assert store.reserve_asset_capacity(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            now=11.0,
        )
        response = _asset_success(claim.turn_id)
        assert store.succeed(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response=response,
            now=12.0,
        )

        exact = store.read_success_document(
            turn_id=claim.turn_id,
            principal_hash=principal,
            operation="images.create",
        )
        assert exact is not None and exact.response == response
        assert (
            store.read_success_document(
                turn_id=claim.turn_id,
                principal_hash="c" * 64,
                operation="images.create",
            )
            is None
        )
        with closing(sqlite3.connect(path)) as connection:
            expires_at = connection.execute(
                "SELECT expires_at FROM durable_media_requests WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone()[0]
        assert expires_at == durable_media_requests._ASSET_SUCCESS_UNACKED_EXPIRES_AT

        # A far-future unrelated claim runs bounded pruning but must retain the
        # still-unacknowledged v2 success document.
        store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-asset-prune-0002",
            request_sha256="f" * 64,
            now=40 * 24 * 60 * 60.0,
        )
        assert (
            store.read_success_document(
                turn_id=claim.turn_id,
                principal_hash=principal,
                operation="images.create",
            )
            is not None
        )
    finally:
        store.close()


def test_exact_ack_housekeeping_releases_only_v2_success_retention(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    principal = "a" * 64
    store = DurableMediaRequestStore(path, retention_seconds=100.0)
    try:
        claim = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-asset-ack-0001",
            request_sha256="b" * 64,
            now=10.0,
        )
        assert store.reserve_asset_capacity(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            now=11.0,
        )
        response = _asset_success(claim.turn_id)
        assert store.succeed(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response=response,
            now=12.0,
        )
        tokens = [asset["token"] for asset in response["assets"]]  # type: ignore[index]
        receipt = store.ack_asset_success(
            turn_id=claim.turn_id,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
            tokens=tokens,
            archive_receipt_sha256="9" * 64,
            now=20.0,
        )
        assert receipt.replayed is False and receipt.cleanup_complete is False
        replay = store.ack_asset_success(
            turn_id=claim.turn_id,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
            tokens=tokens,
            archive_receipt_sha256="9" * 64,
            now=21.0,
        )
        assert replay.replayed is True and replay.cleanup_complete is False
        assert store.complete_asset_ack_cleanup(
            turn_id=claim.turn_id,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
            token_set_digest=receipt.token_set_digest,
            archive_receipt_sha256=receipt.archive_receipt_sha256,
            now=20.0,
        )
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT expires_at FROM durable_media_requests WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == (120.0,)
    finally:
        store.close()


def test_asset_success_kind_must_match_the_claim_operation(tmp_path: Path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    principal = "a" * 64
    try:
        claim = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-asset-kind-0001",
            request_sha256="b" * 64,
        )
        assert store.reserve_asset_capacity(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
        with pytest.raises(DurableMediaRequestUnavailable):
            store.succeed(
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
                response=_asset_success(claim.turn_id, kind="video"),
            )
        assert (
            store.read_success_document(
                turn_id=claim.turn_id,
                principal_hash=principal,
                operation="images.create",
            )
            is None
        )
    finally:
        store.close()


def test_reserved_asset_turn_rejects_legacy_success_without_leaking_capacity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    principal = "a" * 64
    try:
        claim = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="desktop-asset-no-legacy-0001",
            request_sha256="b" * 64,
            max_success_bytes=1024 * 1024,
            now=10.0,
        )
        assert store.reserve_asset_capacity(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            max_success_bytes=1024 * 1024,
            now=11.0,
        )
        with pytest.raises(DurableMediaRequestUnavailable):
            store.succeed(
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
                response={"created": 1, "data": [{"url": "https://example.test/a"}]},
                now=12.0,
            )
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT status,provider_phase FROM durable_media_requests WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == ("processing", 1)
            assert connection.execute(
                "SELECT state,reserved_bytes FROM durable_media_asset_authority "
                "WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == (
                "reserved",
                durable_media_requests._ASSET_OPERATION_RESERVATION_BYTES,
            )
        assert store.succeed(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response=_asset_success(claim.turn_id),
            now=13.0,
        )
    finally:
        store.close()


def test_foreign_keys_cascade_pre_provider_abandon_and_reopen_cleanly(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    try:
        assert store._keeper is not None  # noqa: SLF001
        assert store._keeper.execute("PRAGMA foreign_keys").fetchone() == (1,)  # noqa: SLF001
        with closing(store._connect()) as independent:  # noqa: SLF001
            assert independent.execute("PRAGMA foreign_keys").fetchone() == (1,)
        claim = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-fk-cascade-0001",
            request_sha256="b" * 64,
            max_success_bytes=1024 * 1024,
            now=1.0,
        )
        assert store.reserve_asset_capacity(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash="a" * 64,
            operation="images.create",
            installation_epoch=7,
        )
        assert store.abandon_pre_provider(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_asset_authority"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == (0,)
    finally:
        store.close()

    reopened = DurableMediaRequestStore(path)
    reopened.close()


def test_provider_recovery_keeps_asset_capacity_and_remains_reopenable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "media-requests.db"
    principal = "a" * 64
    key = "desktop-asset-recovery-0001"
    store = DurableMediaRequestStore(path)
    claim = store.claim(
        principal_hash=principal,
        operation="images.create",
        idempotency_key=key,
        request_sha256="b" * 64,
        max_success_bytes=1024 * 1024,
        now=1.0,
    )
    assert store.reserve_asset_capacity(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=principal,
        operation="images.create",
        installation_epoch=7,
    )
    assert store.enter_provider_phase(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        max_success_bytes=1024 * 1024,
        now=2.0,
    )
    assert store.mark_recovery_required(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        now=3.0,
    )
    store.close()

    reopened = DurableMediaRequestStore(path)
    try:
        replay = reopened.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key=key,
            request_sha256="b" * 64,
            max_success_bytes=1024 * 1024,
            now=4.0,
        )
        assert replay.state == "recovery_required"
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT state,reserved_bytes FROM durable_media_asset_authority "
                "WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone() == (
                "reserved",
                durable_media_requests._ASSET_OPERATION_RESERVATION_BYTES,
            )
    finally:
        reopened.close()


def test_same_request_has_only_one_active_executor(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-11111111-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
        )
        duplicate = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-11111111-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
        )

        assert first.state == "claimed"
        assert len(first.fencing_token) == 64
        assert len(first.turn_id) == 64
        assert duplicate.state == "processing"
        assert duplicate.fencing_token == ""
        assert duplicate.turn_id == first.turn_id
    finally:
        store.close()


def test_video_poll_registry_persists_owner_route_backoff_and_terminal_receipt(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    principal = "a" * 64
    try:
        created = store.claim(
            principal_hash=principal,
            operation="videos.create",
            idempotency_key="desktop-10101010-1111-4101-8101-101010101010",
            request_sha256="b" * 64,
            now=90.0,
        )
        assert store.enter_provider_phase(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=91.0,
        )
        persisted, public_create = store.succeed_video(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            principal_hash=principal,
            response={
                "task_id": "provider-task-7",
                "status": "queued",
                "data": {
                    "id": "provider-task-7",
                    "upstream_task_id": "provider-task-7",
                },
            },
            requested_model="video-model",
            provider_name="provider-a",
            provider_domain="c" * 64,
            provider_credential_domain="d" * 64,
            upstream_model="provider-video-v2",
            upstream_task_id="provider-task-7",
            terminal=False,
            now=92.0,
        )
        task_alias = f"nvt1_{created.turn_id}"
        assert persisted is True
        assert public_create == {
            "task_id": task_alias,
            "status": "queued",
            "data": {"id": task_alias},
        }
        assert store.list_active_video_leases(now=99.0) == (
            durable_media_requests.DurableVideoTaskLease(
                task_alias=task_alias,
                principal_hash=principal,
            ),
        )

        first = store.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=100.0
        )
        assert first.state == "claimed"
        assert first.upstream_task_id == "provider-task-7"
        assert first.provider_name == "provider-a"
        assert first.provider_domain == "c" * 64
        assert first.provider_credential_domain == "d" * 64
        saved, nonterminal = store.finish_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token=first.fencing_token,
            response={"status": "processing", "progress": 20},
            terminal=False,
            now=100.0,
        )
        assert saved is True
        assert nonterminal == {
            "task_id": task_alias,
            "status": "processing",
            "progress": 20,
        }

        deferred = store.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=101.0
        )
        assert deferred.state == "deferred"
        assert deferred.retry_after_seconds == 1
        assert deferred.response == nonterminal
        second = store.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=102.0
        )
        assert second.state == "claimed"
        assert second.attempt == 2
        assert store.fail_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token=second.fencing_token,
            now=102.0,
        )
        assert store.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=105.0
        ).state == "deferred"
        third = store.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=106.0
        )
        assert third.state == "claimed"
        saved, terminal = store.finish_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token=third.fencing_token,
            response={
                "status": "completed",
                "url": "https://media.invalid/provider-terminal.mp4",
            },
            terminal=True,
            now=106.0,
        )
        assert saved is True
        assert terminal["task_id"] == task_alias
        assert store.list_active_video_leases(now=106.0) == ()
    finally:
        store.close()

    restarted = DurableMediaRequestStore(path)
    try:
        cached = restarted.begin_video_poll(
            task_alias=task_alias, principal_hash=principal, now=107.0
        )
        assert cached.state == "terminal"
        assert cached.response == terminal
        assert restarted.begin_video_poll(
            task_alias=task_alias, principal_hash="d" * 64, now=107.0
        ).state == "not_found"
    finally:
        restarted.close()


def test_legacy_video_success_is_counted_but_replays_only_a_local_alias(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    principal = "e" * 64
    key = "desktop-legacy-video-1111-4111-8111-111111111111"
    request_digest = "f" * 64
    try:
        created = store.claim(
            principal_hash=principal,
            operation="videos.create",
            idempotency_key=key,
            request_sha256=request_digest,
            now=10.0,
        )
        assert store.enter_provider_phase(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=11.0,
        )
        assert store.succeed(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            response={
                "task_id": "SECRET-UPSTREAM-TASK",
                "status": "queued",
                "data": {"task_id": "SECRET-UPSTREAM-TASK"},
            },
            now=12.0,
        )

        alias = f"nvt1_{created.turn_id}"
        assert store.list_active_video_leases(now=13.0) == (
            durable_media_requests.DurableVideoTaskLease(
                task_alias=alias,
                principal_hash=principal,
            ),
        )
        replay = store.claim(
            principal_hash=principal,
            operation="videos.create",
            idempotency_key=key,
            request_sha256=request_digest,
            now=14.0,
        )
        assert replay.state == "succeeded"
        assert replay.response == {
            "task_id": alias,
            "status": "legacy_recovery_required",
        }
        assert "SECRET-UPSTREAM-TASK" not in json.dumps(replay.response)
    finally:
        store.close()


def test_ambiguous_provider_phase_video_keeps_capacity_across_restart_states(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    principal = "1" * 64
    try:
        created = store.claim(
            principal_hash=principal,
            operation="videos.create",
            idempotency_key="desktop-unknown-video-1111-4111-8111-111111111111",
            request_sha256="2" * 64,
            now=20.0,
        )
        assert store.enter_provider_phase(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=21.0,
        )
        expected = (
            durable_media_requests.DurableVideoTaskLease(
                task_alias=f"nvt1_{created.turn_id}",
                principal_hash=principal,
            ),
        )
        assert store.list_active_video_leases(now=22.0) == expected
        assert store.mark_recovery_required(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=23.0,
        )
        assert store.list_active_video_leases(now=24.0) == expected
    finally:
        store.close()


def test_malformed_video_provider_phase_fails_capacity_rebuild_closed(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    try:
        created = store.claim(
            principal_hash="3" * 64,
            operation="videos.create",
            idempotency_key="desktop-corrupt-video-1111-4111-8111-111111111111",
            request_sha256="4" * 64,
            now=30.0,
        )
        assert store.enter_provider_phase(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=31.0,
        )
        assert store.mark_recovery_required(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=32.0,
        )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE durable_media_requests SET provider_phase='corrupt' "
                "WHERE turn_id=?",
                (created.turn_id,),
            )
            connection.commit()

        with pytest.raises(
            DurableMediaRequestUnavailable,
            match="rebuild durable video capacity",
        ):
            store.list_active_video_leases(now=33.0)
    finally:
        store.close()


def test_expired_pre_provider_claim_can_be_reclaimed_with_a_new_fence(tmp_path) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        lease_seconds=5,
        retention_seconds=30 * 24 * 60 * 60,
    )
    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-22222222-2222-4222-8222-222222222222",
            request_sha256="c" * 64,
            now=100.0,
        )
        reclaimed = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-22222222-2222-4222-8222-222222222222",
            request_sha256="c" * 64,
            now=106.0,
        )

        assert first.state == "claimed"
        assert reclaimed.state == "claimed"
        assert reclaimed.attempt == 2
        assert reclaimed.turn_id == first.turn_id
        assert reclaimed.fencing_token != first.fencing_token
    finally:
        store.close()


def test_restart_after_provider_phase_never_reclaims_for_automatic_submission(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    first_store = DurableMediaRequestStore(path, lease_seconds=5)
    first = first_store.claim(
        principal_hash="d" * 64,
        operation="videos.create",
        idempotency_key="desktop-33333333-3333-4333-8333-333333333333",
        request_sha256="e" * 64,
        now=100.0,
    )
    assert first_store.enter_provider_phase(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        now=101.0,
    )
    first_store.close()

    restarted = DurableMediaRequestStore(path, lease_seconds=5)
    try:
        recovered = restarted.claim(
            principal_hash="d" * 64,
            operation="videos.create",
            idempotency_key="desktop-33333333-3333-4333-8333-333333333333",
            request_sha256="e" * 64,
            now=106.0,
        )

        assert recovered.state == "recovery_required"
        assert recovered.fencing_token == ""
        assert recovered.turn_id == first.turn_id
    finally:
        restarted.close()


def test_success_is_atomically_replayable_after_restart(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    first = store.claim(
        principal_hash="f" * 64,
        operation="images.create",
        idempotency_key="desktop-44444444-4444-4444-8444-444444444444",
        request_sha256="1" * 64,
        now=200.0,
    )
    assert store.enter_provider_phase(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        now=201.0,
    )
    assert store.succeed(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        response={"data": [{"url": "https://media.invalid/result.png"}]},
        now=202.0,
    )
    store.close()

    restarted = DurableMediaRequestStore(path)
    try:
        replay = restarted.claim(
            principal_hash="f" * 64,
            operation="images.create",
            idempotency_key="desktop-44444444-4444-4444-8444-444444444444",
            request_sha256="1" * 64,
            now=203.0,
        )

        assert replay.state == "succeeded"
        assert replay.response == {
            "data": [{"url": "https://media.invalid/result.png"}]
        }
        assert replay.turn_id == first.turn_id
    finally:
        restarted.close()


def test_replacing_with_older_database_snapshot_fails_closed(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    snapshot = tmp_path / "older-media-requests.db"
    store = DurableMediaRequestStore(path)
    first = store.claim(
        principal_hash="0" * 64,
        operation="images.create",
        idempotency_key="desktop-rollback-1111-4111-8111-111111111111",
        request_sha256="1" * 64,
        now=250.0,
    )
    with closing(sqlite3.connect(path)) as source, closing(
        sqlite3.connect(snapshot)
    ) as destination:
        source.backup(destination)
    assert store.enter_provider_phase(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        now=251.0,
    )
    store.close()

    with closing(sqlite3.connect(snapshot)) as source, closing(
        sqlite3.connect(path)
    ) as destination:
        source.backup(destination)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_replacing_database_with_a_different_identity_fails_closed(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    replacement_path = tmp_path / "replacement.db"
    original = DurableMediaRequestStore(path)
    original.close()
    replacement = DurableMediaRequestStore(replacement_path)
    replacement.close()

    with closing(sqlite3.connect(replacement_path)) as source, closing(
        sqlite3.connect(path)
    ) as destination:
        source.backup(destination)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_missing_rollback_anchor_fails_closed_for_initialized_database(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    anchor_path = store.anchor_path
    store.close()
    anchor_path.unlink()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_exact_legacy_v1_database_gets_one_safe_anchor_migration(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    _create_legacy_v1_media_database(path)
    idempotency_key = "desktop-migrate-8888-4888-8888-888888888888"
    principal_hash = "8" * 64
    key_hash = durable_media_requests._key_hash(idempotency_key)
    turn_id = durable_media_requests._turn_id(
        principal_hash, "images.create", key_hash
    )
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "INSERT INTO durable_media_requests "
            "(principal_hash,operation,key_hash,turn_id,request_sha256,status,"
            "fencing_token,lease_expires_at,attempt_count,provider_phase,"
            "response_json,reserved_response_bytes,created_at,updated_at,expires_at) "
            "VALUES(?,?,?,?,?,'processing',?,1200,1,0,NULL,25165824,290,290,2592290)",
            (
                principal_hash,
                "images.create",
                key_hash,
                turn_id,
                "9" * 64,
                "a" * 64,
            ),
        )
        connection.commit()

    store = DurableMediaRequestStore(path)
    try:
        claim = store.claim(
            principal_hash=principal_hash,
            operation="images.create",
            idempotency_key=idempotency_key,
            request_sha256="9" * 64,
            now=290.0,
        )
        assert claim.state == "processing"
        assert claim.turn_id == turn_id
        assert store.anchor_path.is_file()
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (
            durable_media_requests._SCHEMA_VERSION,
        )
        migrated = connection.execute(
            "SELECT schema_version,length(database_identity),mutation_sequence,"
            "max_response_bytes,length(authority_state_digest),authority_mode "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
    assert migrated == (
        durable_media_requests._SCHEMA_VERSION,
        64,
        1,
        128 * 1024 * 1024,
        64,
        "normal",
    )


def test_development_mode_migrates_one_exact_v2_database_and_anchor(tmp_path) -> None:
    path = tmp_path / "legacy-v2.db"
    identity = "a" * 64
    _create_legacy_v2_media_database(path, identity)

    store = DurableMediaRequestStore(path)
    try:
        state = store.inspect_root_state()
        assert state.database_identity == identity
        assert state.mutation_sequence == 0
        assert state.authority_mode == "normal"
        anchor = json.loads(store.anchor_path.read_text(encoding="ascii"))
        assert anchor == {
            "authority_state_digest": state.state_digest,
            "database_identity": identity,
            "format": 2,
            "mutation_sequence": "0000000000000000",
        }
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (
            durable_media_requests._SCHEMA_VERSION,
        )
        assert connection.execute(
            "SELECT schema_version,authority_mode FROM "
            "durable_media_requests_meta WHERE singleton=1"
        ).fetchone() == (durable_media_requests._SCHEMA_VERSION, "normal")


def test_previous_default_response_budget_upgrades_without_reopening_old_claim(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    previous = DurableMediaRequestStore(
        path,
        max_response_bytes=24 * 1024 * 1024,
    )
    claim = previous.claim(
        principal_hash="b" * 64,
        operation="images.create",
        idempotency_key="desktop-budget-1111-4111-8111-111111111111",
        request_sha256="c" * 64,
        now=100.0,
    )
    previous.close()

    upgraded = DurableMediaRequestStore(path)
    try:
        with closing(sqlite3.connect(path)) as connection:
            before_provider = connection.execute(
                "SELECT provider_phase,reserved_response_bytes FROM "
                "durable_media_requests WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone()
            metadata = connection.execute(
                "SELECT max_response_bytes,mutation_sequence FROM "
                "durable_media_requests_meta WHERE singleton=1"
            ).fetchone()
        assert before_provider == (0, 24 * 1024 * 1024)
        assert metadata == (128 * 1024 * 1024, 2)

        assert upgraded.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            now=101.0,
        )
        with closing(sqlite3.connect(path)) as connection:
            after_provider = connection.execute(
                "SELECT provider_phase,reserved_response_bytes FROM "
                "durable_media_requests WHERE turn_id=?",
                (claim.turn_id,),
            ).fetchone()
        assert after_provider == (1, 128 * 1024 * 1024)
    finally:
        upgraded.close()


def test_previous_small_reservations_fail_before_provider_when_expansion_is_full(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    previous = DurableMediaRequestStore(
        path,
        max_response_bytes=24 * 1024 * 1024,
    )
    claims = []
    try:
        for index in range(21):
            claims.append(
                previous.claim(
                    principal_hash="d" * 64,
                    operation="images.create",
                    idempotency_key=f"desktop-budget-{index:04d}-4000-8000-{index:012d}",
                    request_sha256=f"{index + 1:064x}",
                    now=200.0,
                )
            )
    finally:
        previous.close()

    upgraded = DurableMediaRequestStore(path)
    try:
        with pytest.raises(DurableMediaRequestUnavailable, match="provider phase"):
            upgraded.enter_provider_phase(
                turn_id=claims[0].turn_id,
                fencing_token=claims[0].fencing_token,
                now=201.0,
            )
        with closing(sqlite3.connect(path)) as connection:
            unchanged = connection.execute(
                "SELECT provider_phase,reserved_response_bytes FROM "
                "durable_media_requests WHERE turn_id=?",
                (claims[0].turn_id,),
            ).fetchone()
        assert unchanged == (0, 24 * 1024 * 1024)
    finally:
        upgraded.close()


def test_previous_default_expands_only_to_a_smaller_configured_total_budget(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    previous = DurableMediaRequestStore(
        path,
        max_response_bytes=24 * 1024 * 1024,
        max_total_response_bytes=64 * 1024 * 1024,
    )
    previous.close()

    upgraded = DurableMediaRequestStore(
        path,
        max_total_response_bytes=64 * 1024 * 1024,
    )
    try:
        with closing(sqlite3.connect(path)) as connection:
            configured = connection.execute(
                "SELECT max_response_bytes,max_total_response_bytes FROM "
                "durable_media_requests_meta WHERE singleton=1"
            ).fetchone()
        assert configured == (64 * 1024 * 1024, 64 * 1024 * 1024)
    finally:
        upgraded.close()


def test_legacy_v1_database_with_an_existing_anchor_is_not_remigrated(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    _create_legacy_v1_media_database(path)
    anchor_path = Path(f"{path}.rollback-anchor")
    anchor_path.write_text(
        '{"database_identity":"'
        + "a" * 64
        + '","format":1,"mutation_sequence":"0000000000000000"}',
        encoding="ascii",
    )

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_rollback_anchor_sequence_cannot_move_behind_database(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    first = store.claim(
        principal_hash="2" * 64,
        operation="videos.create",
        idempotency_key="desktop-anchor-2222-4222-8222-222222222222",
        request_sha256="3" * 64,
        now=275.0,
    )
    older_anchor = store.anchor_path.read_bytes()
    assert store.enter_provider_phase(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        now=276.0,
    )
    anchor_path = store.anchor_path
    store.close()
    anchor_path.write_bytes(older_anchor)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_anchor_durability_failure_never_commits_database_mutation(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)

    def fail_anchor_flush(_descriptor: int) -> None:
        raise OSError("simulated rollback anchor flush failure")

    with monkeypatch.context() as patch:
        patch.setattr(durable_media_requests.os, "fsync", fail_anchor_flush)
        with pytest.raises(DurableMediaRequestUnavailable):
            store.claim(
                principal_hash="4" * 64,
                operation="images.create",
                idempotency_key="desktop-anchor-4444-4444-8444-444444444444",
                request_sha256="5" * 64,
                now=280.0,
            )
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT mutation_sequence FROM durable_media_requests_meta "
            "WHERE singleton=1"
        ).fetchone() == (0,)
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_rollback_anchor_contains_only_non_secret_identity_sequence_and_state_digest(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    secret_key = "desktop-secret-6666-4666-8666-666666666666"
    store = DurableMediaRequestStore(path)
    try:
        store.claim(
            principal_hash="6" * 64,
            operation="images.create",
            idempotency_key=secret_key,
            request_sha256="7" * 64,
            now=285.0,
        )
        raw = store.anchor_path.read_text(encoding="ascii")
    finally:
        store.close()

    anchor = json.loads(raw)
    assert set(anchor) == {
        "authority_state_digest",
        "database_identity",
        "format",
        "mutation_sequence",
    }
    assert len(anchor["database_identity"]) == 64
    assert len(anchor["authority_state_digest"]) == 64
    assert anchor["format"] == 2
    assert anchor["mutation_sequence"] == "0000000000000001"
    assert secret_key not in raw
    assert "images.create" not in raw


def test_every_transaction_connection_forces_full_synchronous_durability(
    tmp_path, monkeypatch
) -> None:
    real_connect = sqlite3.connect

    def connect_with_unsafe_default(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connection.execute("PRAGMA synchronous=OFF")
        return connection

    monkeypatch.setattr(
        durable_media_requests.sqlite3,
        "connect",
        connect_with_unsafe_default,
    )
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        with closing(store._connect()) as connection:
            assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
    finally:
        store.close()


def test_corrupt_success_state_fails_closed_instead_of_replaying(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    first = store.claim(
        principal_hash="2" * 64,
        operation="images.create",
        idempotency_key="desktop-55555555-5555-4555-8555-555555555555",
        request_sha256="3" * 64,
        now=300.0,
    )
    assert store.enter_provider_phase(
        turn_id=first.turn_id,
        fencing_token=first.fencing_token,
        now=301.0,
    )
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE durable_media_requests SET status='succeeded',response_json=NULL"
        )
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        restarted = DurableMediaRequestStore(path)
        try:
            restarted.claim(
                principal_hash="2" * 64,
                operation="images.create",
                idempotency_key="desktop-55555555-5555-4555-8555-555555555555",
                request_sha256="3" * 64,
                now=302.0,
            )
        finally:
            restarted.close()


def test_success_response_must_fit_the_durable_replay_byte_limit(tmp_path) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        max_response_bytes=64,
    )
    try:
        first = store.claim(
            principal_hash="4" * 64,
            operation="videos.create",
            idempotency_key="desktop-66666666-6666-4666-8666-666666666666",
            request_sha256="5" * 64,
            now=400.0,
        )
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=401.0,
        )

        with pytest.raises(ValueError, match="storage limit"):
            store.succeed(
                turn_id=first.turn_id,
                fencing_token=first.fencing_token,
                response={"data": [{"url": "https://media.invalid/" + "x" * 100}]},
                now=402.0,
            )
    finally:
        store.close()


def test_provider_phase_failure_is_terminal_until_manual_recovery(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        first = store.claim(
            principal_hash="6" * 64,
            operation="videos.create",
            idempotency_key="desktop-77777777-7777-4777-8777-777777777777",
            request_sha256="7" * 64,
            now=500.0,
        )
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=501.0,
        )
        assert store.mark_recovery_required(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=502.0,
        )

        replay = store.claim(
            principal_hash="6" * 64,
            operation="videos.create",
            idempotency_key="desktop-77777777-7777-4777-8777-777777777777",
            request_sha256="7" * 64,
            now=503.0,
        )
        assert replay.state == "recovery_required"
        assert replay.turn_id == first.turn_id
        assert replay.fencing_token == ""
    finally:
        store.close()


def test_same_key_with_different_request_is_a_conflict(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        first = store.claim(
            principal_hash="8" * 64,
            operation="images.create",
            idempotency_key="desktop-88888888-8888-4888-8888-888888888888",
            request_sha256="9" * 64,
        )
        conflict = store.claim(
            principal_hash="8" * 64,
            operation="images.create",
            idempotency_key="desktop-88888888-8888-4888-8888-888888888888",
            request_sha256="a" * 64,
        )

        assert first.state == "claimed"
        assert conflict.state == "conflict"
        assert conflict.turn_id == first.turn_id
    finally:
        store.close()


def test_new_key_is_a_new_generation_even_when_the_payload_is_identical(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        first = store.claim(
            principal_hash="b" * 64,
            operation="images.create",
            idempotency_key="desktop-99999999-9999-4999-8999-999999999999",
            request_sha256="c" * 64,
        )
        intentional_new_generation = store.claim(
            principal_hash="b" * 64,
            operation="images.create",
            idempotency_key="desktop-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            request_sha256="c" * 64,
        )

        assert first.state == "claimed"
        assert intentional_new_generation.state == "claimed"
        assert intentional_new_generation.turn_id != first.turn_id
    finally:
        store.close()


def test_reclaimed_attempt_fences_the_expired_owner_from_provider_entry(tmp_path) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        lease_seconds=5,
    )
    try:
        first = store.claim(
            principal_hash="d" * 64,
            operation="videos.create",
            idempotency_key="desktop-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            request_sha256="e" * 64,
            now=700.0,
        )
        reclaimed = store.claim(
            principal_hash="d" * 64,
            operation="videos.create",
            idempotency_key="desktop-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            request_sha256="e" * 64,
            now=706.0,
        )

        assert not store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=707.0,
        )
        assert store.enter_provider_phase(
            turn_id=reclaimed.turn_id,
            fencing_token=reclaimed.fencing_token,
            now=707.0,
        )
    finally:
        store.close()


def test_provider_phase_samples_deadline_after_waiting_for_write_lock(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "media-requests.db"
    reached_write_gate = Event()
    gate_enabled = False

    def observe_write_gate() -> None:
        if gate_enabled:
            reached_write_gate.set()

    store = DurableMediaRequestStore(
        path,
        lease_seconds=5,
        pre_mutation_hook=observe_write_gate,
    )
    blocker = sqlite3.connect(path, timeout=5.0)
    try:
        claim = store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key="desktop-lock-clock-1111-4111-8111-111111111111",
            request_sha256="2" * 64,
            now=100.0,
        )
        clock = {"now": 104.9}
        monkeypatch.setattr(
            durable_media_requests.time,
            "time",
            lambda: clock["now"],
        )
        blocker.execute("BEGIN IMMEDIATE")
        gate_enabled = True

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                store.enter_provider_phase,
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
            )
            assert reached_write_gate.wait(5)
            clock["now"] = 105.0
            blocker.commit()
            assert future.result(timeout=5) is False
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
        store.close()


def test_success_samples_deadline_after_waiting_for_write_lock(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "media-requests.db"
    reached_write_gate = Event()
    gate_enabled = False

    def observe_write_gate() -> None:
        if gate_enabled:
            reached_write_gate.set()

    store = DurableMediaRequestStore(
        path,
        lease_seconds=5,
        pre_mutation_hook=observe_write_gate,
    )
    blocker = sqlite3.connect(path, timeout=5.0)
    try:
        claim = store.claim(
            principal_hash="3" * 64,
            operation="images.create",
            idempotency_key="desktop-lock-clock-3333-4333-8333-333333333333",
            request_sha256="4" * 64,
            now=200.0,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            now=201.0,
        )
        clock = {"now": 204.9}
        monkeypatch.setattr(
            durable_media_requests.time,
            "time",
            lambda: clock["now"],
        )
        blocker.execute("BEGIN IMMEDIATE")
        gate_enabled = True

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                store.succeed,
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
                response={"ok": True},
            )
            assert reached_write_gate.wait(5)
            clock["now"] = 205.0
            blocker.commit()
            assert future.result(timeout=5) is False

        replay = store.claim(
            principal_hash="3" * 64,
            operation="images.create",
            idempotency_key="desktop-lock-clock-3333-4333-8333-333333333333",
            request_sha256="4" * 64,
            now=205.0,
        )
        assert replay.state == "recovery_required"
        assert replay.response is None
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
        store.close()


def test_two_store_instances_atomically_admit_only_one_executor(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    first_store = DurableMediaRequestStore(path)
    second_store = DurableMediaRequestStore(path)
    barrier = Barrier(2)

    def claim(store: DurableMediaRequestStore):
        barrier.wait()
        return store.claim(
            principal_hash="f" * 64,
            operation="videos.create",
            idempotency_key="desktop-cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            request_sha256="0" * 64,
            now=800.0,
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(claim, (first_store, second_store)))

        assert sorted(result.state for result in claims) == ["claimed", "processing"]
        assert len({result.turn_id for result in claims}) == 1
        assert first_store.inspect_root_state().mutation_sequence == 1
        assert second_store.inspect_root_state().mutation_sequence == 1
    finally:
        second_store.close()
        first_store.close()


def test_reader_waits_for_an_active_anchor_first_writer_before_failing_closed(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "media-requests.db"
    first_store = DurableMediaRequestStore(path)
    second_store = DurableMediaRequestStore(path)
    anchor_written = Event()
    second_observed_anchor = Event()
    release_writer = Event()
    real_write_anchor = first_store._write_anchor
    real_read_anchor = second_store._read_anchor

    def pause_after_anchor(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        real_write_anchor(*args, **kwargs)
        anchor_written.set()
        assert release_writer.wait(5)

    def observe_anchor():  # noqa: ANN202
        value = real_read_anchor()
        if anchor_written.is_set():
            second_observed_anchor.set()
        return value

    monkeypatch.setattr(first_store, "_write_anchor", pause_after_anchor)
    monkeypatch.setattr(second_store, "_read_anchor", observe_anchor)

    def claim(store: DurableMediaRequestStore):
        return store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-anchor-race-cccc-4ccc-8ccc-cccccccccccc",
            request_sha256="b" * 64,
            now=810.0,
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(claim, first_store)
            assert anchor_written.wait(5)
            second_future = pool.submit(claim, second_store)
            assert second_observed_anchor.wait(5)
            release_writer.set()
            claims = [first_future.result(timeout=5), second_future.result(timeout=5)]

        assert sorted(result.state for result in claims) == ["claimed", "processing"]
        assert len({result.turn_id for result in claims}) == 1
    finally:
        release_writer.set()
        second_store.close()
        first_store.close()


def test_reader_does_not_accept_an_anchor_ahead_without_an_active_writer(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    writer = DurableMediaRequestStore(path)
    reader = DurableMediaRequestStore(path)
    try:
        before = writer.inspect_root_state()
        next_sequence = before.mutation_sequence + 1
        writer._write_anchor(
            before.database_identity,
            next_sequence,
            durable_media_requests._next_authority_state_digest(
                before.state_digest,
                before.database_identity,
                next_sequence,
            ),
        )

        with pytest.raises(DurableMediaRequestUnavailable):
            reader.claim(
                principal_hash="c" * 64,
                operation="images.create",
                idempotency_key="desktop-crash-anchor-dddd-4ddd-8ddd-dddddddddddd",
                request_sha256="d" * 64,
                now=820.0,
            )
    finally:
        reader.close()
        writer.close()


def test_close_waits_for_inflight_keeper_transaction_and_is_idempotent(
    tmp_path, monkeypatch
) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    entered = Event()
    release = Event()
    close_started = Event()
    close_finished = Event()
    real_prune = store._prune

    def blocking_prune(connection, current) -> None:
        entered.set()
        assert release.wait(5)
        real_prune(connection, current)

    def close_store() -> None:
        close_started.set()
        store.close()
        close_finished.set()

    monkeypatch.setattr(store, "_prune", blocking_prune)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claim_future = pool.submit(
            store.claim,
            principal_hash="7" * 64,
            operation="images.create",
            idempotency_key="desktop-77777777-abcd-4777-8777-777777777777",
            request_sha256="8" * 64,
        )
        assert entered.wait(5)
        close_future = pool.submit(close_store)
        assert close_started.wait(5)
        assert not close_finished.wait(0.1)
        release.set()
        assert claim_future.result(timeout=5).state == "claimed"
        close_future.result(timeout=5)

    assert close_finished.is_set()
    assert store._keeper is None
    store.close()


def test_keeper_own_commits_do_not_trigger_full_runtime_schema_scan(
    tmp_path, monkeypatch
) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    validations = 0
    real_validate = store._validate_schema

    def counted_validate(connection) -> None:
        nonlocal validations
        validations += 1
        real_validate(connection)

    monkeypatch.setattr(store, "_validate_schema", counted_validate)
    try:
        claim = store.claim(
            principal_hash="9" * 64,
            operation="images.create",
            idempotency_key="desktop-99999999-abcd-4999-8999-999999999999",
            request_sha256="a" * 64,
        )
        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
        assert store.succeed(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response={"ok": True},
        )
        replay = store.claim(
            principal_hash="9" * 64,
            operation="images.create",
            idempotency_key="desktop-99999999-abcd-4999-8999-999999999999",
            request_sha256="a" * 64,
        )
        assert replay.state == "succeeded"
        assert validations == 0
    finally:
        store.close()


def test_terminal_result_is_retained_for_30_days_then_capacity_can_reuse_it(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        max_records=1,
        max_response_bytes=128,
        max_total_response_bytes=128,
    )
    first_key = "desktop-dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    second_key = "desktop-eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    try:
        first = store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key=first_key,
            request_sha256="2" * 64,
            now=1_000.0,
        )
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=1_001.0,
        )
        assert store.succeed(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            response={"data": [{"url": "https://media.invalid/a"}]},
            now=1_002.0,
        )

        replay = store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key=first_key,
            request_sha256="2" * 64,
            now=1_002.0 + 30 * 24 * 60 * 60 - 0.001,
        )
        assert replay.state == "succeeded"
        with pytest.raises(DurableMediaRequestUnavailable, match="capacity"):
            store.claim(
                principal_hash="1" * 64,
                operation="images.create",
                idempotency_key=second_key,
                request_sha256="3" * 64,
                now=1_002.0 + 30 * 24 * 60 * 60 - 0.001,
            )

        after_retention = store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key=second_key,
            request_sha256="3" * 64,
            now=1_002.0 + 30 * 24 * 60 * 60,
        )
        assert after_retention.state == "claimed"
    finally:
        store.close()


def test_processing_claim_reserves_response_budget_before_provider_entry(tmp_path) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "media-requests.db",
        max_records=2,
        max_response_bytes=64,
        max_total_response_bytes=64,
    )
    try:
        first = store.claim(
            principal_hash="3" * 64,
            operation="videos.create",
            idempotency_key="desktop-ffffffff-ffff-4fff-8fff-ffffffffffff",
            request_sha256="4" * 64,
            now=2_000.0,
        )
        with pytest.raises(DurableMediaRequestUnavailable, match="capacity"):
            store.claim(
                principal_hash="3" * 64,
                operation="videos.create",
                idempotency_key="desktop-00000000-0000-4000-8000-000000000000",
                request_sha256="5" * 64,
                now=2_001.0,
            )

        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=2_002.0,
        )
        assert store.mark_recovery_required(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=2_003.0,
        )
        admitted = store.claim(
            principal_hash="3" * 64,
            operation="videos.create",
            idempotency_key="desktop-00000000-0000-4000-8000-000000000000",
            request_sha256="5" * 64,
            now=2_004.0,
        )
        assert admitted.state == "claimed"
    finally:
        store.close()


@pytest.mark.parametrize("invalid_now", [-1.0, float("inf"), float("-inf"), float("nan")])
def test_non_finite_or_negative_time_is_rejected(tmp_path, invalid_now: float) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        with pytest.raises(ValueError, match="now"):
            store.claim(
                principal_hash="5" * 64,
                operation="images.create",
                idempotency_key="desktop-12121212-1212-4212-8212-121212121212",
                request_sha256="6" * 64,
                now=invalid_now,
            )
    finally:
        store.close()


def test_default_database_page_budget_is_at_most_one_gibibyte(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        with closing(store._connect()) as connection:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            max_pages = int(
                connection.execute("PRAGMA max_page_count").fetchone()[0]
            )
        assert max_pages * page_size <= 1024 * 1024 * 1024
        assert (max_pages + 1) * page_size > 1024 * 1024 * 1024
    finally:
        store.close()


def test_existing_database_larger_than_page_budget_fails_closed(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE filler(payload BLOB NOT NULL)")
        connection.execute("INSERT INTO filler(payload) VALUES(zeroblob(524288))")
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path, max_database_bytes=256 * 1024)


def test_existing_lookalike_schema_without_contract_marker_fails_closed(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            """
            CREATE TABLE durable_media_requests (
                principal_hash TEXT NOT NULL,
                operation TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                fencing_token TEXT NOT NULL,
                lease_expires_at REAL NOT NULL,
                attempt_count INTEGER NOT NULL,
                provider_phase INTEGER NOT NULL,
                response_json TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY(principal_hash,operation,key_hash)
            ) WITHOUT ROWID
            """
        )
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_database_path_rejects_symbolic_link_components(tmp_path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable on this Windows host")

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(Path(linked_directory) / "media-requests.db")


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_database_sidecars_must_be_regular_files(tmp_path, suffix) -> None:
    path = tmp_path / "media-requests.db"
    initialized = DurableMediaRequestStore(path)
    initialized.close()
    Path(f"{path}{suffix}").mkdir()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_live_store_rejects_external_closed_set_schema_tampering_before_mutation(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(
        path,
        max_records=2,
        max_response_bytes=64,
        max_total_response_bytes=128,
    )
    try:
        store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key="desktop-11111111-abcd-4111-8111-111111111111",
            request_sha256="2" * 64,
        )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE unauthorized_runtime_table(value TEXT)")
            connection.commit()

        with pytest.raises(DurableMediaRequestUnavailable):
            store.claim(
                principal_hash="1" * 64,
                operation="images.create",
                idempotency_key="desktop-22222222-abcd-4222-8222-222222222222",
                request_sha256="3" * 64,
            )

        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (1,)
    finally:
        store.close()


@pytest.mark.parametrize(
    "action",
    ["claim", "enter_provider_phase", "abandon", "succeed", "recovery"],
)
def test_every_live_mutation_reconciles_external_capacity_tampering_before_write(
    tmp_path, action
) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(
        path,
        max_records=2,
        max_response_bytes=64,
        max_total_response_bytes=128,
    )
    try:
        first = store.claim(
            principal_hash="4" * 64,
            operation="videos.create",
            idempotency_key="desktop-33333333-abcd-4333-8333-333333333333",
            request_sha256="5" * 64,
        )
        if action in {"succeed", "recovery"}:
            assert store.enter_provider_phase(
                turn_id=first.turn_id,
                fencing_token=first.fencing_token,
            )
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "UPDATE durable_media_requests_meta SET "
                "record_count=0,response_bytes=0,reserved_bytes=0 "
                "WHERE singleton=1"
            )
            connection.commit()

        with pytest.raises(DurableMediaRequestUnavailable):
            if action == "claim":
                store.claim(
                    principal_hash="4" * 64,
                    operation="videos.create",
                    idempotency_key="desktop-44444444-abcd-4444-8444-444444444444",
                    request_sha256="6" * 64,
                )
            elif action == "enter_provider_phase":
                store.enter_provider_phase(
                    turn_id=first.turn_id,
                    fencing_token=first.fencing_token,
                )
            elif action == "abandon":
                store.abandon_pre_provider(
                    turn_id=first.turn_id,
                    fencing_token=first.fencing_token,
                )
            elif action == "succeed":
                store.succeed(
                    turn_id=first.turn_id,
                    fencing_token=first.fencing_token,
                    response={"ok": True},
                )
            else:
                store.mark_recovery_required(
                    turn_id=first.turn_id,
                    fencing_token=first.fencing_token,
                )

        with closing(sqlite3.connect(path)) as connection:
            row = connection.execute(
                "SELECT status,provider_phase,response_json "
                "FROM durable_media_requests WHERE turn_id=?",
                (first.turn_id,),
            ).fetchone()
            meta = connection.execute(
                "SELECT record_count,response_bytes,reserved_bytes "
                "FROM durable_media_requests_meta WHERE singleton=1"
            ).fetchone()
        assert row == (
            "processing",
            1 if action in {"succeed", "recovery"} else 0,
            None,
        )
        assert meta == (0, 0, 0)
    finally:
        store.close()


def test_same_named_noop_capacity_trigger_fails_schema_validation(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    store.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DROP TRIGGER durable_media_capacity_insert")
        connection.execute(
            """
            CREATE TRIGGER durable_media_capacity_insert
            AFTER INSERT ON durable_media_requests
            BEGIN
                SELECT 1;
            END
            """
        )
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_extra_trigger_fails_closed_set_schema_validation(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    store.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            """
            CREATE TRIGGER unauthorized_media_trigger
            AFTER INSERT ON durable_media_requests
            BEGIN
                SELECT 1;
            END
            """
        )
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_schema_authority_rejects_quoted_literal_case_collision(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='durable_media_requests'",
            ("'recovery_required'", "'RECOVERY_REQUIRED'"),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_schema_authority_preserves_sql_token_boundaries() -> None:
    assert DurableMediaRequestStore._canonical_sql(
        "CHECK(a IS NULL)"
    ) != DurableMediaRequestStore._canonical_sql("CHECK(aisnull)")


def test_extra_user_table_fails_closed_set_schema_validation(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    store = DurableMediaRequestStore(path)
    store.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE unauthorized_table(value TEXT)")
        connection.commit()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_extra_persistent_view_is_rejected_without_mutating_database(tmp_path) -> None:
    path = tmp_path / "media-requests.db"
    DurableMediaRequestStore(path).close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "CREATE VIEW unauthorized_schema_view AS SELECT 1 AS injected_value"
        )
        connection.commit()
    before = {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := Path(f"{path}{suffix}")).exists()
    }

    def reopen() -> None:
        store = DurableMediaRequestStore(path)
        store.close()

    with pytest.raises(DurableMediaRequestUnavailable):
        reopen()
    assert {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := Path(f"{path}{suffix}")).exists()
    } == before


def test_foreign_schema_only_in_abandoned_wal_is_rejected_without_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "foreign-hot-wal.db"
    _create_abandoned_media_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)

    after = _media_db_artifacts(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after.get("-journal") == before.get("-journal")
    assert after.get("-shm") is not None


def test_orphan_wal_family_is_rejected_without_recreating_main(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-hot-wal.db"
    _create_abandoned_media_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    path.unlink()
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)

    assert _media_db_artifacts(path) == before


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_wal_pair_is_rejected_without_mutation(
    tmp_path: Path, missing_suffix: str
) -> None:
    path = tmp_path / f"incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_media_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    Path(f"{path}{missing_suffix}").unlink()
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)

    assert _media_db_artifacts(path) == before


def test_exact_current_hot_wal_reopens_and_keeps_wal_profile(tmp_path: Path) -> None:
    path = tmp_path / "current-hot-wal.db"
    original = DurableMediaRequestStore(path)
    expected = original.inspect_root_state()
    original.close()
    _create_abandoned_media_wal(
        path,
        "UPDATE durable_media_requests_meta "
        "SET max_records=max_records WHERE singleton=1",
    )

    reopened = DurableMediaRequestStore(path)
    try:
        assert reopened.inspect_root_state() == expected
        assert reopened._keeper is not None
        assert reopened._keeper.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    finally:
        reopened.close()


def test_exact_v2_hot_wal_is_migrated_to_current_in_development_mode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-v2-hot-wal.db"
    identity = "a" * 64
    _create_legacy_v2_media_database(path, identity)
    _create_abandoned_media_wal(
        path,
        "UPDATE durable_media_requests_meta "
        "SET max_records=max_records WHERE singleton=1",
    )

    migrated = DurableMediaRequestStore(path)
    try:
        assert migrated.inspect_root_state().database_identity == identity
        assert migrated._keeper is not None
        assert migrated._keeper.execute("PRAGMA user_version").fetchone() == (4,)
    finally:
        migrated.close()


def test_unsupported_rollback_journal_is_preserved_without_read_write_open(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unsupported-rollback.db"
    DurableMediaRequestStore(path).close()
    Path(f"{path}-journal").write_bytes(b"forensic-rollback-evidence")
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)

    assert _media_db_artifacts(path) == before


def test_create_bound_rejects_orphan_sidecars_before_creating_main(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bound-orphan.db"
    _create_abandoned_media_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    path.unlink()
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            path,
            construction_policy="create_bound",
            expected_database_identity="b" * 64,
        )

    assert _media_db_artifacts(path) == before


@pytest.mark.parametrize("generation", ("current", "v1", "v2"))
def test_schema_generations_reject_reserved_prefix_object_without_mutation(
    tmp_path, generation
) -> None:
    path = tmp_path / f"media-requests-{generation}.db"
    if generation == "current":
        DurableMediaRequestStore(path).close()
    elif generation == "v1":
        _create_legacy_v1_media_database(path)
    else:
        _create_legacy_v2_media_database(path, "a" * 64)
    _inject_reserved_prefix_view(path)
    before = {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal", ".rollback-anchor")
        if (candidate := Path(f"{path}{suffix}")).exists()
    }

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)
    assert {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal", ".rollback-anchor")
        if (candidate := Path(f"{path}{suffix}")).exists()
    } == before


def test_paid_schema_rejects_trigger_tbl_name_drift_without_mutation(tmp_path) -> None:
    path = tmp_path / "media-requests-trigger-metadata.db"
    DurableMediaRequestStore(path).close()
    _tamper_schema_tbl_name(
        path,
        object_name="durable_media_capacity_insert",
        tbl_name="durable_media_requests_meta",
    )
    before = _media_db_artifacts(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)
    assert _media_db_artifacts(path) == before


def test_paid_capability_principal_and_request_digest_hide_raw_inputs() -> None:
    principal = hash_media_principal("sk-paid-media-" + ("c" * 64))
    first = hash_media_request(
        "images.create",
        {"prompt": "cat", "model": "image-model", "extra": {"b": 2, "a": 1}},
    )
    reordered = hash_media_request(
        "images.create",
        {"extra": {"a": 1, "b": 2}, "model": "image-model", "prompt": "cat"},
    )
    video = hash_media_request(
        "videos.create",
        {"prompt": "cat", "model": "image-model", "extra": {"a": 1, "b": 2}},
    )

    assert len(principal) == 64
    assert "secret" not in principal
    assert first == reordered
    assert first != video


def test_fenced_pre_provider_abandon_releases_claim_but_never_provider_phase(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "media-requests.db")
    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-cdcdcdcd-5555-4dcd-8dcd-cdcdcdcdcdcd",
            request_sha256="b" * 64,
        )
        assert store.abandon_pre_provider(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
        )
        assert not store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
        )
        reclaimed = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-cdcdcdcd-5555-4dcd-8dcd-cdcdcdcdcdcd",
            request_sha256="b" * 64,
        )
        assert reclaimed.state == "claimed"
        assert reclaimed.turn_id == first.turn_id
        assert reclaimed.fencing_token != first.fencing_token
        assert store.enter_provider_phase(
            turn_id=reclaimed.turn_id,
            fencing_token=reclaimed.fencing_token,
        )
        assert not store.abandon_pre_provider(
            turn_id=reclaimed.turn_id,
            fencing_token=reclaimed.fencing_token,
        )
    finally:
        store.close()


def test_bound_construction_creates_and_reopens_only_the_expected_identity(
    tmp_path,
) -> None:
    path = tmp_path / "media-requests.db"
    identity = "1" * 64

    created = DurableMediaRequestStore(
        path,
        construction_policy="create_bound",
        expected_database_identity=identity,
    )
    try:
        state = created.inspect_root_state()
        assert state.database_identity == identity
        assert state.mutation_sequence == 0
        assert len(state.state_digest) == 64
    finally:
        created.close()

    reopened = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        assert reopened.inspect_root_state() == state
    finally:
        reopened.close()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            path,
            construction_policy="open_bound",
            expected_database_identity="2" * 64,
        )


def test_bound_construction_never_creates_opens_or_migrates_implicitly(
    tmp_path,
) -> None:
    missing = tmp_path / "missing.db"
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            missing,
            construction_policy="open_bound",
            expected_database_identity="3" * 64,
        )
    assert not missing.exists()
    assert not Path(f"{missing}.rollback-anchor").exists()

    occupied = tmp_path / "occupied.db"
    occupied.write_bytes(b"operator-owned")
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            occupied,
            construction_policy="create_bound",
            expected_database_identity="4" * 64,
        )
    assert occupied.read_bytes() == b"operator-owned"

    legacy = tmp_path / "legacy.db"
    _create_legacy_v1_media_database(legacy)
    legacy_anchor = Path(f"{legacy}.rollback-anchor")
    legacy_anchor.write_bytes(b"not-a-current-anchor")
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            legacy,
            construction_policy="open_bound",
            expected_database_identity="5" * 64,
        )
    with closing(sqlite3.connect(legacy)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
    assert legacy_anchor.read_bytes() == b"not-a-current-anchor"


def test_bound_construction_policy_and_identity_are_closed_inputs(tmp_path) -> None:
    with pytest.raises(ValueError, match="construction policy"):
        DurableMediaRequestStore(
            tmp_path / "bad-policy.db",
            construction_policy="automatic",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="expected_database_identity"):
        DurableMediaRequestStore(
            tmp_path / "missing-identity.db",
            construction_policy="create_bound",
        )


def test_authority_digest_chain_is_deterministic_and_binds_identity_schema_and_sequence(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(
        tmp_path / "chain.db",
        construction_policy="create_bound",
        expected_database_identity="1" * 64,
    )
    try:
        initial = store.inspect_root_state()
        assert initial.state_digest == (
            "b871b6ccd0efa1aeeedf260b021539c6edbe9aa3b49d6af3cd33a0e2afa2e2c7"
        )
        store.claim(
            principal_hash="6" * 64,
            operation="images.create",
            idempotency_key="desktop-chain-1111-4111-8111-111111111111",
            request_sha256="7" * 64,
            now=1.0,
        )
        advanced = store.inspect_root_state()
        assert advanced.mutation_sequence == 1
        assert advanced.state_digest == (
            "2baed211b7c615f902ac3a5bd84443fd6bf80447aaae18fc5059ddfa49f947d7"
        )
        assert advanced.state_digest != initial.state_digest
    finally:
        store.close()


def test_anchor_authority_digest_tampering_fails_closed(tmp_path) -> None:
    path = tmp_path / "tampered-anchor.db"
    store = DurableMediaRequestStore(path)
    store.claim(
        principal_hash="8" * 64,
        operation="images.create",
        idempotency_key="desktop-anchor-digest-4111-8111-111111111111",
        request_sha256="9" * 64,
        now=2.0,
    )
    anchor_path = store.anchor_path
    store.close()

    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    anchor["authority_state_digest"] = "f" * 64
    anchor_path.write_text(
        json.dumps(anchor, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_local_replays_conflicts_and_stale_fences_do_not_advance_authority(
    tmp_path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "no-op.db")
    try:
        claimed = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-noop-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            now=10.0,
        )
        assert store.inspect_root_state().mutation_sequence == 1

        processing = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-noop-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            now=11.0,
        )
        conflict = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-noop-1111-4111-8111-111111111111",
            request_sha256="c" * 64,
            now=11.0,
        )
        assert processing.state == "processing"
        assert conflict.state == "conflict"
        assert not store.abandon_pre_provider(
            turn_id=claimed.turn_id,
            fencing_token="d" * 64,
        )
        assert store.inspect_root_state().mutation_sequence == 1

        assert store.enter_provider_phase(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
            now=12.0,
        )
        assert store.inspect_root_state().mutation_sequence == 2
        assert not store.enter_provider_phase(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
            now=12.0,
        )
        assert not store.abandon_pre_provider(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
        )
        assert store.inspect_root_state().mutation_sequence == 2

        assert store.succeed(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
            response={"ok": True},
            now=13.0,
        )
        assert store.inspect_root_state().mutation_sequence == 3
        assert not store.succeed(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
            response={"ok": True},
            now=13.0,
        )
        replay = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-noop-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            now=14.0,
        )
        assert replay.state == "succeeded"
        assert replay.response == {"ok": True}
        assert not store.mark_recovery_required(
            turn_id=claimed.turn_id,
            fencing_token=claimed.fencing_token,
            now=14.0,
        )
        assert store.inspect_root_state().mutation_sequence == 3

        ambiguous = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-noop-2222-4222-8222-222222222222",
            request_sha256="e" * 64,
            now=20.0,
        )
        assert store.enter_provider_phase(
            turn_id=ambiguous.turn_id,
            fencing_token=ambiguous.fencing_token,
            now=21.0,
        )
        assert store.mark_recovery_required(
            turn_id=ambiguous.turn_id,
            fencing_token=ambiguous.fencing_token,
            now=22.0,
        )
        recovery_sequence = store.inspect_root_state().mutation_sequence
        recovery = store.claim(
            principal_hash="a" * 64,
            operation="videos.create",
            idempotency_key="desktop-noop-2222-4222-8222-222222222222",
            request_sha256="e" * 64,
            now=23.0,
        )
        assert recovery.state == "recovery_required"
        assert not store.mark_recovery_required(
            turn_id=ambiguous.turn_id,
            fencing_token=ambiguous.fencing_token,
            now=23.0,
        )
        assert store.inspect_root_state().mutation_sequence == recovery_sequence
    finally:
        store.close()


def test_terminal_deferred_and_capacity_reads_never_advance_authority(tmp_path) -> None:
    store = DurableMediaRequestStore(tmp_path / "poll-no-op.db")
    principal = "1" * 64
    try:
        missing = store.begin_video_poll(
            task_alias="nvt1_" + "0" * 64,
            principal_hash=principal,
            now=90.0,
        )
        assert missing.state == "not_found"
        assert store.inspect_root_state().mutation_sequence == 0

        created = store.claim(
            principal_hash=principal,
            operation="videos.create",
            idempotency_key="desktop-poll-noop-1111-4111-8111-111111111111",
            request_sha256="2" * 64,
            now=91.0,
        )
        assert store.enter_provider_phase(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            now=92.0,
        )
        persisted, public = store.succeed_video(
            turn_id=created.turn_id,
            fencing_token=created.fencing_token,
            principal_hash=principal,
            response={"task_id": "upstream-secret", "status": "processing"},
            requested_model="requested-video",
            provider_name="provider",
            provider_domain="3" * 64,
            provider_credential_domain="4" * 64,
            upstream_model="served-video",
            upstream_task_id="upstream-secret",
            terminal=False,
            now=93.0,
        )
        assert persisted
        task_alias = str(public["task_id"])
        assert store.inspect_root_state().mutation_sequence == 3
        assert len(store.list_active_video_leases(now=94.0)) == 1
        assert store.inspect_root_state().mutation_sequence == 3

        poll = store.begin_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            now=100.0,
        )
        assert poll.state == "claimed"
        assert store.inspect_root_state().mutation_sequence == 4
        deferred = store.begin_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            now=101.0,
        )
        assert deferred.state == "deferred"
        assert not store.finish_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token="f" * 64,
            response={"status": "processing"},
            terminal=False,
            now=101.0,
        )[0]
        assert not store.fail_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token="f" * 64,
            now=101.0,
        )
        assert store.inspect_root_state().mutation_sequence == 4

        assert store.finish_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token=poll.fencing_token,
            response={"status": "processing"},
            terminal=False,
            now=102.0,
        )[0]
        assert store.inspect_root_state().mutation_sequence == 5
        assert store.begin_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            now=103.0,
        ).state == "deferred"
        assert store.inspect_root_state().mutation_sequence == 5

        final_poll = store.begin_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            now=105.0,
        )
        assert final_poll.state == "claimed"
        assert store.finish_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            fencing_token=final_poll.fencing_token,
            response={"status": "succeeded", "url": "https://media.invalid/v.mp4"},
            terminal=True,
            now=106.0,
        )[0]
        assert store.inspect_root_state().mutation_sequence == 7
        terminal = store.begin_video_poll(
            task_alias=task_alias,
            principal_hash=principal,
            now=107.0,
        )
        assert terminal.state == "terminal"
        assert store.list_active_video_leases(now=107.0) == ()
        assert store.inspect_root_state().mutation_sequence == 7
    finally:
        store.close()


def test_real_mutation_commits_anchor_and_sqlite_before_one_root_hook(tmp_path) -> None:
    path = tmp_path / "hook-order.db"
    transitions = []

    def confirm_root(transition) -> None:
        anchor = json.loads(
            Path(f"{path}.rollback-anchor").read_text(encoding="ascii")
        )
        with closing(sqlite3.connect(path)) as connection:
            committed = connection.execute(
                "SELECT mutation_sequence,authority_state_digest "
                "FROM durable_media_requests_meta WHERE singleton=1"
            ).fetchone()
        assert committed == (
            transition.after.mutation_sequence,
            transition.after.state_digest,
        )
        assert int(anchor["mutation_sequence"], 16) == transition.after.mutation_sequence
        assert anchor["authority_state_digest"] == transition.after.state_digest
        transitions.append(transition)

    store = DurableMediaRequestStore(path, root_commit_hook=confirm_root)
    try:
        claim = store.claim(
            principal_hash="5" * 64,
            operation="images.create",
            idempotency_key="desktop-root-hook-1111-4111-8111-111111111111",
            request_sha256="6" * 64,
            now=200.0,
        )
        assert len(transitions) == 1
        assert transitions[0].before.mutation_sequence == 0
        assert transitions[0].after.mutation_sequence == 1
        assert transitions[0].after == store.inspect_root_state()

        replay = store.claim(
            principal_hash="5" * 64,
            operation="images.create",
            idempotency_key="desktop-root-hook-1111-4111-8111-111111111111",
            request_sha256="6" * 64,
            now=201.0,
        )
        assert replay.state == "processing"
        assert len(transitions) == 1

        assert store.enter_provider_phase(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            now=202.0,
        )
        assert len(transitions) == 2
        assert transitions[1].before == transitions[0].after
        assert transitions[1].after.mutation_sequence == 2
    finally:
        store.close()


def test_root_hook_failure_keeps_local_commit_fuses_writes_and_resumes_explicitly(
    tmp_path,
) -> None:
    path = tmp_path / "hook-failure.db"
    fail = True
    calls = []

    def confirm_root(transition) -> None:
        calls.append(transition)
        if fail:
            raise RuntimeError("provider-secret-must-not-escape")

    store = DurableMediaRequestStore(path, root_commit_hook=confirm_root)
    try:
        with pytest.raises(
            DurableMediaRootCommitPending,
            match="installation-root commit confirmation is pending",
        ) as pending:
            store.claim(
                principal_hash="7" * 64,
                operation="images.create",
                idempotency_key="desktop-root-fail-1111-4111-8111-111111111111",
                request_sha256="8" * 64,
                now=210.0,
            )
        assert "provider-secret" not in str(pending.value)
        current = store.inspect_root_state()
        assert current.mutation_sequence == 1
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (1,)

        replay = store.claim(
            principal_hash="7" * 64,
            operation="images.create",
            idempotency_key="desktop-root-fail-1111-4111-8111-111111111111",
            request_sha256="8" * 64,
            now=211.0,
        )
        assert replay.state == "processing"
        with pytest.raises(DurableMediaRootCommitPending):
            store.claim(
                principal_hash="7" * 64,
                operation="images.create",
                idempotency_key="desktop-root-fail-2222-4222-8222-222222222222",
                request_sha256="9" * 64,
                now=211.0,
            )
        assert len(calls) == 1

        stale = DurableMediaRootState(
            database_identity=current.database_identity,
            mutation_sequence=0,
            state_digest=current.state_digest,
            authority_mode="normal",
        )
        with pytest.raises(DurableMediaRequestUnavailable, match="does not match"):
            store.resume_after_root_reconcile(stale)

        fail = False
        assert store.resume_after_root_reconcile(current) == current
        second = store.claim(
            principal_hash="7" * 64,
            operation="images.create",
            idempotency_key="desktop-root-fail-2222-4222-8222-222222222222",
            request_sha256="9" * 64,
            now=212.0,
        )
        assert second.state == "claimed"
        assert store.inspect_root_state().mutation_sequence == 2
        assert len(calls) == 2
    finally:
        store.close()


def test_manual_only_receipt_is_floor_plus_one_idempotent_and_persistent(
    tmp_path,
) -> None:
    path = tmp_path / "manual-only.db"
    store = DurableMediaRequestStore(path)
    replay_key = "desktop-manual-1111-4111-8111-111111111111"
    try:
        existing = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key=replay_key,
            request_sha256="b" * 64,
            now=300.0,
        )
        recovery = store.inspect_root_state()
        transition = store.enter_authority_manual_only(
            installation_id="c" * 64,
            epoch=7,
            recovery_floor=recovery.mutation_sequence,
            recovery_state_digest=recovery.state_digest,
        )
        assert transition.before == recovery
        assert transition.after.mutation_sequence == recovery.mutation_sequence + 1
        assert transition.after.authority_mode == "manual_only"
        assert transition.after.installation_id == "c" * 64
        assert transition.after.epoch == 7
        assert transition.after.recovery_floor == recovery.mutation_sequence
        assert transition.after.recovery_state_digest == recovery.state_digest

        retried = store.enter_authority_manual_only(
            installation_id="c" * 64,
            epoch=7,
            recovery_floor=recovery.mutation_sequence,
            recovery_state_digest=recovery.state_digest,
        )
        assert retried == transition
        assert store.inspect_root_state() == transition.after

        local_replay = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key=replay_key,
            request_sha256="b" * 64,
            now=301.0,
        )
        assert local_replay.state == "processing"
        assert store.list_active_video_leases(now=301.0) == ()
        with pytest.raises(DurableMediaRequestUnavailable, match="manual recovery"):
            store.enter_provider_phase(
                turn_id=existing.turn_id,
                fencing_token=existing.fencing_token,
                now=301.0,
            )
        with pytest.raises(DurableMediaRequestUnavailable, match="manual recovery"):
            store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key="desktop-manual-2222-4222-8222-222222222222",
                request_sha256="d" * 64,
                now=301.0,
            )
        assert store.inspect_root_state() == transition.after
    finally:
        store.close()

    reopened = DurableMediaRequestStore(path)
    try:
        assert reopened.inspect_root_state() == transition.after
        assert reopened.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key=replay_key,
            request_sha256="b" * 64,
            now=302.0,
        ).state == "processing"
        with pytest.raises(DurableMediaRequestUnavailable, match="manual recovery"):
            reopened.abandon_pre_provider(
                turn_id=existing.turn_id,
                fencing_token=existing.fencing_token,
            )
        with pytest.raises(DurableMediaRequestUnavailable, match="conflicts"):
            reopened.enter_authority_manual_only(
                installation_id="e" * 64,
                epoch=7,
                recovery_floor=recovery.mutation_sequence,
                recovery_state_digest=recovery.state_digest,
            )
    finally:
        reopened.close()


def test_manual_only_acknowledgement_bypasses_but_never_reinvokes_failed_hook(
    tmp_path,
) -> None:
    calls = []

    def unavailable_root(transition) -> None:
        calls.append(transition)
        raise RuntimeError("root response was lost")

    store = DurableMediaRequestStore(
        tmp_path / "manual-after-pending.db",
        root_commit_hook=unavailable_root,
    )
    try:
        with pytest.raises(DurableMediaRootCommitPending):
            store.claim(
                principal_hash="1" * 64,
                operation="images.create",
                idempotency_key="desktop-manual-pending-4111-8111-111111111111",
                request_sha256="2" * 64,
                now=400.0,
            )
        recovery = store.inspect_root_state()
        manual = store.enter_authority_manual_only(
            installation_id="3" * 64,
            epoch=4,
            recovery_floor=recovery.mutation_sequence,
            recovery_state_digest=recovery.state_digest,
        )
        assert manual.after.mutation_sequence == recovery.mutation_sequence + 1
        assert manual.after.authority_mode == "manual_only"
        assert len(calls) == 1
    finally:
        store.close()


def test_pre_mutation_hook_rejects_before_sqlite_or_anchor_change_but_allows_replay(
    tmp_path,
) -> None:
    allowed = True
    calls = 0

    def gate() -> None:
        nonlocal calls
        calls += 1
        if not allowed:
            raise DurableMediaRequestUnavailable("authority is not ready")

    path = tmp_path / "pre-mutation-gate.db"
    store = DurableMediaRequestStore(path, pre_mutation_hook=gate)
    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-pre-gate-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            now=600.0,
        )
        assert first.state == "claimed"
        before = store.inspect_root_state()
        anchor_before = store.anchor_path.read_bytes()
        assert calls == 1

        allowed = False
        replay = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-pre-gate-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            now=601.0,
        )
        assert replay.state == "processing"
        assert calls == 1

        with pytest.raises(DurableMediaRequestUnavailable, match="not ready"):
            store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key="desktop-pre-gate-2222-4222-8222-222222222222",
                request_sha256="c" * 64,
                now=601.0,
            )
        assert calls == 2
        assert store.inspect_root_state() == before
        assert store.anchor_path.read_bytes() == anchor_before
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (1,)
    finally:
        store.close()


def test_claim_admission_hook_runs_only_for_a_real_new_write(tmp_path) -> None:
    path = tmp_path / "claim-admission-hook.db"
    store = DurableMediaRequestStore(path)
    calls: list[str] = []

    def allow() -> None:
        calls.append("allow")

    try:
        first = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-admission-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            admission_hook=allow,
            now=700.0,
        )
        assert first.state == "claimed"
        assert calls == ["allow"]
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=700.5,
        )
        assert store.succeed(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            response={"ok": True},
            now=701.0,
        )
        before = store.inspect_root_state()
        anchor_before = store.anchor_path.read_bytes()

        def reject() -> None:
            calls.append("reject")
            raise DurableMediaRequestUnavailable("peer authority is manual only")

        replay = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-admission-1111-4111-8111-111111111111",
            request_sha256="b" * 64,
            admission_hook=reject,
            now=702.0,
        )
        conflict = store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key="desktop-admission-1111-4111-8111-111111111111",
            request_sha256="c" * 64,
            admission_hook=reject,
            now=702.0,
        )
        assert replay.state == "succeeded" and replay.response == {"ok": True}
        assert conflict.state == "conflict"
        assert calls == ["allow"]

        with pytest.raises(DurableMediaRequestUnavailable, match="manual only"):
            store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key="desktop-admission-2222-4222-8222-222222222222",
                request_sha256="d" * 64,
                admission_hook=reject,
                now=702.0,
            )
        assert calls == ["allow", "reject"]
        assert store.inspect_root_state() == before
        assert store.anchor_path.read_bytes() == anchor_before
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (1,)
    finally:
        store.close()


def test_pre_mutation_hook_must_be_callable(tmp_path) -> None:
    with pytest.raises(ValueError, match="pre_mutation_hook"):
        DurableMediaRequestStore(
            tmp_path / "bad-pre-mutation-hook.db",
            pre_mutation_hook="not-callable",  # type: ignore[arg-type]
        )


def test_manual_only_receipt_is_a_closed_fail_closed_tuple(tmp_path) -> None:
    path = tmp_path / "manual-closed.db"
    store = DurableMediaRequestStore(path)
    recovery = store.inspect_root_state()
    store.enter_authority_manual_only(
        installation_id="6" * 64,
        epoch=9,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE durable_media_requests_meta "
            "SET authority_installation_id=NULL WHERE singleton=1"
        )
        connection.commit()
    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(path)


def test_root_hook_runs_before_this_store_releases_its_write_lock(tmp_path) -> None:
    hook_entered = Event()
    hook_release = Event()
    close_started = Event()
    close_finished = Event()

    def blocking_root(_transition) -> None:
        hook_entered.set()
        assert hook_release.wait(5)

    store = DurableMediaRequestStore(
        tmp_path / "hook-lock.db",
        root_commit_hook=blocking_root,
    )

    def mutate():
        return store.claim(
            principal_hash="4" * 64,
            operation="images.create",
            idempotency_key="desktop-hook-lock-1111-4111-8111-111111111111",
            request_sha256="5" * 64,
            now=500.0,
        )

    def close_store() -> None:
        close_started.set()
        store.close()
        close_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        mutation = pool.submit(mutate)
        assert hook_entered.wait(5)
        closing_future = pool.submit(close_store)
        assert close_started.wait(15)
        assert not close_finished.wait(0.1)
        hook_release.set()
        assert mutation.result(timeout=15).state == "claimed"
        closing_future.result(timeout=15)
    assert close_finished.is_set()


@pytest.mark.parametrize(
    ("requested_digest", "expected_state", "concurrent_terminal", "expected_sequence"),
    [
        ("b" * 64, "processing", None, 1),
        ("c" * 64, "conflict", None, 1),
        ("b" * 64, "succeeded", "success", 3),
        ("b" * 64, "recovery_required", "recovery", 3),
    ],
)
def test_claim_concurrent_exact_result_is_rechecked_before_any_prune(
    tmp_path,
    monkeypatch,
    requested_digest: str,
    expected_state: str,
    concurrent_terminal: str | None,
    expected_sequence: int,
) -> None:
    path = tmp_path / f"claim-race-{expected_state}.db"
    first_store = DurableMediaRequestStore(path)
    second_store = DurableMediaRequestStore(path)
    real_token_hex = durable_media_requests.secrets.token_hex
    inserted = False
    key = "desktop-claim-race-1111-4111-8111-111111111111"

    def inject_concurrent_claim(length: int) -> str:
        nonlocal inserted
        if not inserted:
            inserted = True
            concurrent = second_store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key=key,
                request_sha256="b" * 64,
                now=600.0,
            )
            assert concurrent.state == "claimed"
            if concurrent_terminal is not None:
                assert second_store.enter_provider_phase(
                    turn_id=concurrent.turn_id,
                    fencing_token=concurrent.fencing_token,
                    now=601.0,
                )
                if concurrent_terminal == "success":
                    assert second_store.succeed(
                        turn_id=concurrent.turn_id,
                        fencing_token=concurrent.fencing_token,
                        response={"ok": True},
                        now=602.0,
                    )
                else:
                    assert second_store.mark_recovery_required(
                        turn_id=concurrent.turn_id,
                        fencing_token=concurrent.fencing_token,
                        now=602.0,
                    )
        return real_token_hex(length)

    def forbidden_prune(_connection, _current) -> None:
        raise AssertionError("exact local result must return before global prune")

    monkeypatch.setattr(
        durable_media_requests.secrets,
        "token_hex",
        inject_concurrent_claim,
    )
    monkeypatch.setattr(first_store, "_prune", forbidden_prune)
    try:
        result = first_store.claim(
            principal_hash="a" * 64,
            operation="images.create",
            idempotency_key=key,
            request_sha256=requested_digest,
            now=600.0,
        )
        assert result.state == expected_state
        assert first_store.inspect_root_state().mutation_sequence == expected_sequence
        assert second_store.inspect_root_state().mutation_sequence == expected_sequence
    finally:
        second_store.close()
        first_store.close()


def test_video_poll_concurrent_deferred_result_is_rechecked_before_any_prune(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "poll-race.db"
    first_store = DurableMediaRequestStore(path)
    principal = "d" * 64
    created = first_store.claim(
        principal_hash=principal,
        operation="videos.create",
        idempotency_key="desktop-poll-race-1111-4111-8111-111111111111",
        request_sha256="e" * 64,
        now=700.0,
    )
    assert first_store.enter_provider_phase(
        turn_id=created.turn_id,
        fencing_token=created.fencing_token,
        now=701.0,
    )
    persisted, public = first_store.succeed_video(
        turn_id=created.turn_id,
        fencing_token=created.fencing_token,
        principal_hash=principal,
        response={"task_id": "upstream-race", "status": "processing"},
        requested_model="requested-video",
        provider_name="provider",
        provider_domain="1" * 64,
        provider_credential_domain="2" * 64,
        upstream_model="served-video",
        upstream_task_id="upstream-race",
        terminal=False,
        now=702.0,
    )
    assert persisted
    task_alias = str(public["task_id"])
    second_store = DurableMediaRequestStore(path)
    first_read = Event()
    release_first = Event()
    real_read_result = first_store._video_poll_read_result
    read_count = 0

    def pause_after_first_eligible_read(row, **kwargs):
        nonlocal read_count
        result = real_read_result(row, **kwargs)
        read_count += 1
        if read_count == 1 and result is None:
            first_read.set()
            assert release_first.wait(5)
        return result

    def forbidden_prune(_connection, _current) -> None:
        raise AssertionError("concurrent deferred poll must return before prune")

    monkeypatch.setattr(
        first_store,
        "_video_poll_read_result",
        pause_after_first_eligible_read,
    )
    monkeypatch.setattr(first_store, "_prune", forbidden_prune)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            raced = pool.submit(
                first_store.begin_video_poll,
                task_alias=task_alias,
                principal_hash=principal,
                now=710.0,
            )
            assert first_read.wait(5)
            winner = second_store.begin_video_poll(
                task_alias=task_alias,
                principal_hash=principal,
                now=710.0,
            )
            assert winner.state == "claimed"
            release_first.set()
            assert raced.result(timeout=5).state == "deferred"
        assert first_store.inspect_root_state().mutation_sequence == 4
        assert second_store.inspect_root_state().mutation_sequence == 4
    finally:
        release_first.set()
        second_store.close()
        first_store.close()


def test_phase0_request_with_asset_authority_is_never_aged_out_by_prune(
    tmp_path: Path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "phase0-asset-prune.db")
    principal = "9" * 64
    first_key = "phase0-asset-prune-1111111111111111"
    first_request = hash_media_request(
        "images.create", {"model": "paid", "prompt": "first"}
    )
    try:
        first = store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key=first_key,
            request_sha256=first_request,
            now=1.0,
        )
        assert first.state == "claimed"
        assert store.reserve_asset_capacity(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            principal_hash=principal,
            operation="images.create",
            installation_epoch=7,
        )
        stale_now = 1.0 + store.lease_seconds + store.retention_seconds + 100.0
        store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key="phase0-asset-prune-other-11111111111",
            request_sha256=hash_media_request(
                "images.create", {"model": "paid", "prompt": "other"}
            ),
            now=stale_now,
        )
        # Exercise the exact-key prune branch as well.  It may fence a fresh
        # owner, but it must not delete the Root authority via FK cascade.
        store.claim(
            principal_hash=principal,
            operation="images.create",
            idempotency_key=first_key,
            request_sha256=first_request,
            now=stale_now + 1.0,
        )
        with sqlite3.connect(store.path) as connection:
            assert connection.execute(
                "SELECT status,provider_phase FROM durable_media_requests "
                "WHERE turn_id=?",
                (first.turn_id,),
            ).fetchone() == ("processing", 0)
            assert connection.execute(
                "SELECT state,reserved_bytes FROM durable_media_asset_authority "
                "WHERE turn_id=?",
                (first.turn_id,),
            ).fetchone() == ("reserved", 192 * 1024 * 1024)
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == (192 * 1024 * 1024,)
    finally:
        store.close()
