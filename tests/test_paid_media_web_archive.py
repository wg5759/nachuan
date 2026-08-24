from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import gateway.paid_media_web_archive as archivemod
from gateway.paid_media_asset_protocol import MAX_ASSET_BYTES, parse_asset_result
from gateway.paid_media_web_archive import (
    _LEGACY_META_DDL,
    _LEGACY_SCHEMA_FINGERPRINT,
    _V2_META_DDL,
    _V2_SCHEMA_FINGERPRINT,
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebAssetArchive,
)


PRINCIPAL = "a" * 64
INSTALLATION_ID = "b" * 64


def _result(*, turn: str, payloads: tuple[bytes, ...]):
    return parse_asset_result(
        {
            "schema": "nachuan.paid-media-result.v2",
            "kind": "image",
            "created": 1,
            "turnId": turn,
            "assets": [
                {
                    "token": "nma1_" + chr(ord("A") + ordinal) * 43,
                    "mediaType": "image/png",
                    "byteLength": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "validationReceiptSha256": str(ordinal + 1) * 64,
                }
                for ordinal, payload in enumerate(payloads)
            ],
        }
    )


def _store(archive, result, payloads):
    return archive.store_document_payloads(
        principal_hash=PRINCIPAL,
        result=result,
        payloads=payloads,
        installation_id=INSTALLATION_ID,
        installation_epoch=7,
        now_ms=1,
    )


def _rewrite_archive_meta_as_exact_v1(root: Path) -> None:
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute("BEGIN IMMEDIATE")
        stored_bytes, max_capacity_bytes = connection.execute(
            "SELECT stored_bytes,max_capacity_bytes "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
        connection.execute(
            "ALTER TABLE web_asset_archive_meta "
            "RENAME TO web_asset_archive_meta_v2"
        )
        connection.execute(_LEGACY_META_DDL)
        connection.execute(
            "INSERT INTO web_asset_archive_meta VALUES(1,1,?,?,?)",
            (_LEGACY_SCHEMA_FINGERPRINT, stored_bytes, max_capacity_bytes),
        )
        connection.execute("DROP TABLE web_asset_archive_meta_v2")
        connection.execute("PRAGMA user_version=1")


def _rewrite_archive_meta_as_exact_v2(root: Path) -> None:
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute("BEGIN IMMEDIATE")
        stored_bytes, max_capacity_bytes, cleanup_pending = connection.execute(
            "SELECT stored_bytes,max_capacity_bytes,cleanup_pending "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
        connection.execute(
            "ALTER TABLE web_asset_archive_meta "
            "RENAME TO web_asset_archive_meta_v3"
        )
        connection.execute(_V2_META_DDL)
        connection.execute(
            "INSERT INTO web_asset_archive_meta VALUES(1,2,?,?,?,?)",
            (
                _V2_SCHEMA_FINGERPRINT,
                stored_bytes,
                max_capacity_bytes,
                cleanup_pending,
            ),
        )
        connection.execute("DROP TABLE web_asset_archive_meta_v3")
        connection.execute("PRAGMA user_version=2")


def test_reused_one_byte_digest_cannot_grow_document_metadata_past_cap(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    payload = b"x"
    archive = PaidMediaWebAssetArchive(
        root,
        max_documents=2,
        max_members=2,
    )
    first = _result(turn="1" * 64, payloads=(payload,))
    second = _result(turn="2" * 64, payloads=(payload,))
    rejected = _result(turn="3" * 64, payloads=(payload,))

    _store(archive, first, (payload,))
    _store(archive, first, (payload,))  # replay consumes no additional slot
    _store(archive, second, (payload,))
    with pytest.raises(PaidMediaWebArchiveUnavailable, match="metadata capacity"):
        _store(archive, rejected, (payload,))
    archive.close()

    reopened = PaidMediaWebAssetArchive(
        root,
        max_documents=2,
        max_members=2,
    )
    with sqlite3.connect(root / "archive.db") as connection:
        meta = connection.execute(
            "SELECT document_count,max_documents,member_count,max_members "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
        actual = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM web_asset_archive_documents),"
            "(SELECT COUNT(*) FROM web_asset_archive_members)"
        ).fetchone()
    assert meta == (2, 2, 2, 2)
    assert actual == (2, 2)
    reopened.close()


def test_two_instances_competing_for_last_document_slot_admit_exactly_one(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    archive_a = PaidMediaWebAssetArchive(root, max_documents=1, max_members=1)
    archive_b = PaidMediaWebAssetArchive(root, max_documents=1, max_members=1)
    payload = b"shared-one-byte-budget-object"
    candidates = (
        _result(turn="6" * 64, payloads=(payload,)),
        _result(turn="7" * 64, payloads=(payload,)),
    )
    barrier = threading.Barrier(2)
    receipts: list[str] = []
    errors: list[BaseException] = []

    def compete(archive, result) -> None:
        try:
            barrier.wait(timeout=10)
            receipts.append(_store(archive, result, (payload,)))
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=compete, args=(archive_a, candidates[0])),
        threading.Thread(target=compete, args=(archive_b, candidates[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert all(not thread.is_alive() for thread in threads)
    assert len(receipts) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], PaidMediaWebArchiveUnavailable)
    assert "metadata capacity" in str(errors[0])
    with sqlite3.connect(root / "archive.db") as connection:
        counts = connection.execute(
            "SELECT document_count,member_count FROM web_asset_archive_meta "
            "WHERE singleton=1"
        ).fetchone()
        actual = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM web_asset_archive_documents),"
            "(SELECT COUNT(*) FROM web_asset_archive_members)"
        ).fetchone()
    assert counts == actual == (1, 1)
    archive_a.close()
    archive_b.close()


def test_document_capacity_is_checked_before_a_new_object_file_is_created(
    tmp_path,
) -> None:
    archive = PaidMediaWebAssetArchive(
        tmp_path / "archive", max_documents=1, max_members=4
    )
    admitted_payload = b"admitted-before-cap"
    rejected_payload = b"must-never-reach-object-directory"
    _store(
        archive,
        _result(turn="8" * 64, payloads=(admitted_payload,)),
        (admitted_payload,),
    )
    rejected = _result(turn="9" * 64, payloads=(rejected_payload,))
    rejected_path = archive.object_directory / archive._object_leaf(
        PRINCIPAL, rejected.assets[0].sha256
    )

    with pytest.raises(PaidMediaWebArchiveUnavailable, match="metadata capacity"):
        _store(archive, rejected, (rejected_payload,))

    assert not archive._entry_exists(rejected_path)
    assert len(list(archive.object_directory.iterdir())) == 1
    archive.close()


def test_sqlite_main_database_page_cap_is_reapplied_and_full_is_atomic(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    with sqlite3.connect(root / "archive.db") as connection:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        assert connection.execute("PRAGMA page_size").fetchone() == (4096,)
        connection.execute("PRAGMA max_page_count=2147483646")
    monkeypatch.setattr(archivemod, "_SQLITE_MAX_PAGE_COUNT", page_count)

    limited = PaidMediaWebAssetArchive(root)
    with limited._connect() as connection:
        assert connection.execute("PRAGMA max_page_count").fetchone() == (page_count,)
    payload = b"one-shared-page-cap-object"
    successes = 0
    rejected_turn: str | None = None
    for ordinal in range(1_000):
        turn = hashlib.sha256(f"page-cap-{ordinal}".encode("ascii")).hexdigest()
        try:
            _store(limited, _result(turn=turn, payloads=(payload,)), (payload,))
            successes += 1
        except PaidMediaWebArchiveUnavailable:
            rejected_turn = turn
            break
    assert rejected_turn is not None
    with sqlite3.connect(root / "archive.db") as connection:
        meta = connection.execute(
            "SELECT document_count,member_count FROM web_asset_archive_meta "
            "WHERE singleton=1"
        ).fetchone()
        actual = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM web_asset_archive_documents),"
            "(SELECT COUNT(*) FROM web_asset_archive_members)"
        ).fetchone()
        rejected_rows = connection.execute(
            "SELECT COUNT(*) FROM web_asset_archive_documents WHERE turn_id=?",
            (rejected_turn,),
        ).fetchone()
    assert meta == actual == (successes, successes)
    assert rejected_rows == (0,)
    limited.close()


def test_existing_database_above_page_or_page_size_cap_fails_closed(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    with sqlite3.connect(root / "archive.db") as connection:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    monkeypatch.setattr(archivemod, "_SQLITE_MAX_PAGE_COUNT", page_count - 1)
    with pytest.raises(PaidMediaWebArchiveUnavailable, match="page capacity"):
        PaidMediaWebAssetArchive(root)

    monkeypatch.setattr(archivemod, "_SQLITE_MAX_PAGE_COUNT", 131_072)
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute("PRAGMA page_size=8192")
        connection.execute("VACUUM")
    with pytest.raises(PaidMediaWebArchiveUnavailable, match="page size"):
        PaidMediaWebAssetArchive(root)


def test_partial_document_failure_does_not_consume_archive_capacity(
    tmp_path, monkeypatch
) -> None:
    archive = PaidMediaWebAssetArchive(
        tmp_path / "archive", max_capacity_bytes=MAX_ASSET_BYTES
    )
    partial_payloads = (b"first-partial", b"second-partial")
    partial = _result(turn="1" * 64, payloads=partial_payloads)
    original_store = archivemod._PaidMediaWebDocumentBatch.store_asset
    calls = 0

    def fail_second_asset(batch, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PaidMediaWebArchiveUnavailable("injected second asset failure")
        return original_store(batch, **kwargs)

    monkeypatch.setattr(
        archivemod._PaidMediaWebDocumentBatch, "store_asset", fail_second_asset
    )
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, partial, partial_payloads)

    monkeypatch.setattr(
        archivemod._PaidMediaWebDocumentBatch, "store_asset", original_store
    )
    full_payload = b"x" * MAX_ASSET_BYTES
    full = _result(turn="2" * 64, payloads=(full_payload,))
    _store(archive, full, (full_payload,))
    restored = archive.read(
        principal_hash=PRINCIPAL,
        asset_sha256=hashlib.sha256(full_payload).hexdigest(),
    )
    assert restored is not None
    assert restored.payload == full_payload
    archive.close()


def test_post_replace_failure_removes_the_unindexed_object_in_process(
    tmp_path, monkeypatch
) -> None:
    archive = PaidMediaWebAssetArchive(tmp_path / "archive")
    payload = b"post-replace-unindexed-bytes"
    result = _result(turn="4" * 64, payloads=(payload,))
    digest = hashlib.sha256(payload).hexdigest()
    destination = archive.object_directory / archive._object_leaf(PRINCIPAL, digest)
    original_harden = archive._harden_file

    def fail_destination_harden(path: Path):
        if path == destination:
            raise PaidMediaWebArchiveUnavailable("injected post-replace failure")
        return original_harden(path)

    monkeypatch.setattr(archive, "_harden_file", fail_destination_harden)
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, result, (payload,))

    assert not archive._entry_exists(destination)
    assert list(archive.object_directory.iterdir()) == []
    archive.close()


def test_failed_orphan_unlink_blocks_new_admission_until_cleanup_succeeds(
    tmp_path, monkeypatch
) -> None:
    archive = PaidMediaWebAssetArchive(tmp_path / "archive")
    failed_payload = b"cleanup-debt-object"
    failed_result = _result(turn="a" * 64, payloads=(failed_payload,))
    failed_digest = hashlib.sha256(failed_payload).hexdigest()
    failed_destination = (
        archive.object_directory / archive._object_leaf(PRINCIPAL, failed_digest)
    )
    original_harden = archive._harden_file
    original_unlink = Path.unlink

    def fail_destination_harden(path: Path):
        if path == failed_destination:
            raise PaidMediaWebArchiveUnavailable("injected post-replace failure")
        return original_harden(path)

    def fail_orphan_unlink(path: Path, *args, **kwargs):
        if path == failed_destination:
            raise PermissionError("injected orphan unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(archive, "_harden_file", fail_destination_harden)
    monkeypatch.setattr(Path, "unlink", fail_orphan_unlink)
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, failed_result, (failed_payload,))
    assert archive._entry_exists(failed_destination)

    monkeypatch.setattr(archive, "_harden_file", original_harden)
    next_payload = b"must-not-admit-before-cleanup"
    next_result = _result(turn="b" * 64, payloads=(next_payload,))
    next_destination = archive.object_directory / archive._object_leaf(
        PRINCIPAL, hashlib.sha256(next_payload).hexdigest()
    )
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, next_result, (next_payload,))
    assert not archive._entry_exists(next_destination)

    monkeypatch.setattr(Path, "unlink", original_unlink)
    _store(archive, next_result, (next_payload,))
    assert not archive._entry_exists(failed_destination)
    restored = archive.read(
        principal_hash=PRINCIPAL,
        asset_sha256=hashlib.sha256(next_payload).hexdigest(),
    )
    assert restored is not None
    assert restored.payload == next_payload
    archive.close()


def test_prune_unlink_failure_blocks_new_admission_until_cleanup_succeeds(
    tmp_path, monkeypatch
) -> None:
    archive = PaidMediaWebAssetArchive(
        tmp_path / "archive", max_capacity_bytes=MAX_ASSET_BYTES
    )
    partial_payloads = (b"p" * 400, b"second")
    partial = _result(turn="c" * 64, payloads=partial_payloads)
    orphan_digest = hashlib.sha256(partial_payloads[0]).hexdigest()
    orphan_path = archive.object_directory / archive._object_leaf(
        PRINCIPAL, orphan_digest
    )
    original_store = archivemod._PaidMediaWebDocumentBatch.store_asset
    original_unlink = Path.unlink
    calls = 0

    def fail_second_asset(batch, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PaidMediaWebArchiveUnavailable("injected second asset failure")
        return original_store(batch, **kwargs)

    def fail_orphan_unlink(path: Path, *args, **kwargs):
        if path == orphan_path:
            raise PermissionError("injected prune unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        archivemod._PaidMediaWebDocumentBatch, "store_asset", fail_second_asset
    )
    monkeypatch.setattr(Path, "unlink", fail_orphan_unlink)
    with pytest.raises(
        PaidMediaWebArchiveUnavailable,
        match="cleanup debt could not be recovered",
    ):
        _store(archive, partial, partial_payloads)
    assert archive._entry_exists(orphan_path)

    monkeypatch.setattr(
        archivemod._PaidMediaWebDocumentBatch, "store_asset", original_store
    )
    full_payload = b"f" * MAX_ASSET_BYTES
    full = _result(turn="d" * 64, payloads=(full_payload,))
    full_path = archive.object_directory / archive._object_leaf(
        PRINCIPAL, hashlib.sha256(full_payload).hexdigest()
    )
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, full, (full_payload,))
    assert not archive._entry_exists(full_path)

    monkeypatch.setattr(Path, "unlink", original_unlink)
    _store(archive, full, (full_payload,))
    assert not archive._entry_exists(orphan_path)
    assert (
        sum(path.stat().st_size for path in archive.object_directory.iterdir())
        == MAX_ASSET_BYTES
    )
    archive.close()


def test_other_open_instance_recovers_shared_orphan_before_admission(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    archive_a = PaidMediaWebAssetArchive(root, max_capacity_bytes=MAX_ASSET_BYTES)
    archive_b = PaidMediaWebAssetArchive(root, max_capacity_bytes=MAX_ASSET_BYTES)
    orphan_payload = b"o" * 400
    orphan = _result(turn="e" * 64, payloads=(orphan_payload,))
    orphan_digest = hashlib.sha256(orphan_payload).hexdigest()
    orphan_path = archive_a.object_directory / archive_a._object_leaf(
        PRINCIPAL, orphan_digest
    )
    original_harden = archive_a._harden_file
    original_unlink = Path.unlink

    def fail_destination_harden(path: Path):
        if path == orphan_path:
            raise PaidMediaWebArchiveUnavailable("injected post-replace failure")
        return original_harden(path)

    def fail_orphan_unlink(path: Path, *args, **kwargs):
        if path == orphan_path:
            raise PermissionError("injected orphan unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(archive_a, "_harden_file", fail_destination_harden)
    monkeypatch.setattr(Path, "unlink", fail_orphan_unlink)
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive_a, orphan, (orphan_payload,))
    assert archive_a._entry_exists(orphan_path)

    monkeypatch.setattr(Path, "unlink", original_unlink)
    full_payload = b"z" * MAX_ASSET_BYTES
    full = _result(turn="f" * 64, payloads=(full_payload,))
    _store(archive_b, full, (full_payload,))

    assert not archive_b._entry_exists(orphan_path)
    disk_bytes = sum(
        path.stat().st_size for path in archive_b.object_directory.iterdir()
    )
    with sqlite3.connect(root / "archive.db") as connection:
        stored_bytes = connection.execute(
            "SELECT stored_bytes FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()[0]
    assert disk_bytes == stored_bytes == MAX_ASSET_BYTES
    archive_a.close()
    archive_b.close()


def test_other_open_instance_recovers_a_crashed_document_batch_before_admission(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    archive_b = PaidMediaWebAssetArchive(root)
    abandoned_payload = b"abandoned-document-batch"
    abandoned = _result(turn="4" * 64, payloads=(abandoned_payload,))
    abandoned_asset = abandoned.assets[0]
    abandoned_path = archive_b.object_directory / archive_b._object_leaf(
        PRINCIPAL, abandoned_asset.sha256
    )

    # Use the production batch API and terminate without __exit__: the OS
    # releases the authority fence while the durable dirty receipt remains.
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "\n".join(
                (
                    "import os, sys",
                    "from gateway.paid_media_asset_protocol import parse_asset_result",
                    "from gateway.paid_media_web_archive import PaidMediaWebAssetArchive",
                    f"document = {repr({**{'schema': 'nachuan.paid-media-result.v2', 'kind': 'image', 'created': 1, 'turnId': '4' * 64}, 'assets': [{'token': abandoned_asset.token, 'mediaType': abandoned_asset.media_type, 'byteLength': abandoned_asset.byte_length, 'sha256': abandoned_asset.sha256, 'validationReceiptSha256': abandoned_asset.validation_receipt_sha256}]})}",
                    "archive = PaidMediaWebAssetArchive(sys.argv[1])",
                    f"batch_context = archive.document_batch(principal_hash={'a' * 64!r}, result=parse_asset_result(document), installation_id={'b' * 64!r}, installation_epoch=7, now_ms=1)",
                    "batch = batch_context.__enter__()",
                    f"batch.store_asset(asset=parse_asset_result(document).assets[0], payload={abandoned_payload!r})",
                    "os._exit(0)",
                )
            ),
            str(root),
        ],
        cwd=Path(__file__).parents[1],
        check=False,
        timeout=30,
    )
    assert child.returncode == 0
    assert archive_b._entry_exists(abandoned_path)
    with sqlite3.connect(root / "archive.db") as connection:
        assert connection.execute(
            "SELECT cleanup_pending FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone() == (1,)

    admitted_payload = b"next-batch-after-recovery"
    admitted = _result(turn="5" * 64, payloads=(admitted_payload,))
    _store(archive_b, admitted, (admitted_payload,))

    assert not archive_b._entry_exists(abandoned_path)
    with sqlite3.connect(root / "archive.db") as connection:
        counts = connection.execute(
            "SELECT document_count,member_count,cleanup_pending "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
    assert counts == (1, 1, 0)
    archive_b.close()


def test_other_open_instance_recovers_failed_temporary_cleanup_before_admission(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    archive_a = PaidMediaWebAssetArchive(root, max_capacity_bytes=MAX_ASSET_BYTES)
    archive_b = PaidMediaWebAssetArchive(root, max_capacity_bytes=MAX_ASSET_BYTES)
    orphan_payload = b"t" * 400
    orphan = _result(turn="8" * 64, payloads=(orphan_payload,))
    destination = archive_a.object_directory / archive_a._object_leaf(
        PRINCIPAL, hashlib.sha256(orphan_payload).hexdigest()
    )
    original_harden = archive_a._harden_file
    original_unlink = Path.unlink
    temporary_path: Path | None = None

    def fail_temporary_harden(path: Path):
        nonlocal temporary_path
        if path.parent == archive_a.object_directory and path != destination:
            temporary_path = path
            raise PaidMediaWebArchiveUnavailable("injected temporary harden failure")
        return original_harden(path)

    def fail_temporary_unlink(path: Path, *args, **kwargs):
        if temporary_path is not None and path == temporary_path:
            raise PermissionError("injected temporary unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(archive_a, "_harden_file", fail_temporary_harden)
    monkeypatch.setattr(Path, "unlink", fail_temporary_unlink)
    with pytest.raises(
        PaidMediaWebArchiveUnavailable,
        match="cleanup debt could not be recovered",
    ):
        _store(archive_a, orphan, (orphan_payload,))
    assert temporary_path is not None
    assert archive_a._entry_exists(temporary_path)

    monkeypatch.setattr(Path, "unlink", original_unlink)
    full_payload = b"v" * MAX_ASSET_BYTES
    full = _result(turn="9" * 64, payloads=(full_payload,))
    _store(archive_b, full, (full_payload,))

    assert not archive_b._entry_exists(temporary_path)
    disk_bytes = sum(
        path.stat().st_size for path in archive_b.object_directory.iterdir()
    )
    with sqlite3.connect(root / "archive.db") as connection:
        stored_bytes = connection.execute(
            "SELECT stored_bytes FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()[0]
    assert disk_bytes == stored_bytes == MAX_ASSET_BYTES
    archive_a.close()
    archive_b.close()


def test_clean_admission_does_not_rescan_and_rehash_the_archive(
    tmp_path, monkeypatch
) -> None:
    archive = PaidMediaWebAssetArchive(tmp_path / "archive")
    first_payload = b"already-verified-object"
    first = _result(turn="7" * 64, payloads=(first_payload,))
    _store(archive, first, (first_payload,))

    def fail_if_full_recovery_runs():
        raise AssertionError("clean admission performed a full archive scan")

    monkeypatch.setattr(
        archive, "_recover_uncommitted_objects_once", fail_if_full_recovery_runs
    )
    second_payload = b"new-object-on-clean-path"
    second = _result(turn="6" * 64, payloads=(second_payload,))
    _store(archive, second, (second_payload,))
    archive.close()


def test_exact_v1_archive_migrates_and_preserves_historical_bytes(tmp_path) -> None:
    root = tmp_path / "archive"
    payload = b"historical-v1-archive-object"
    result = _result(turn="5" * 64, payloads=(payload,))
    archive = PaidMediaWebAssetArchive(root)
    _store(archive, result, (payload,))
    archive.close()
    _rewrite_archive_meta_as_exact_v1(root)

    migrated = PaidMediaWebAssetArchive(root)
    restored = migrated.read(
        principal_hash=PRINCIPAL,
        asset_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert restored is not None
    assert restored.payload == payload
    with sqlite3.connect(root / "archive.db") as connection:
        meta = connection.execute(
            "SELECT schema_version,stored_bytes,max_capacity_bytes,"
            "document_count,max_documents,member_count,max_members,cleanup_pending "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
        object_count = connection.execute(
            "SELECT COUNT(*) FROM web_asset_archive_objects"
        ).fetchone()[0]
        document_count = connection.execute(
            "SELECT COUNT(*) FROM web_asset_archive_documents"
        ).fetchone()[0]
    assert meta == (
        3,
        len(payload),
        8 * 1024 * 1024 * 1024,
        1,
        100_000,
        1,
        400_000,
        0,
    )
    assert object_count == document_count == 1
    migrated.close()


def test_exact_v2_archive_migrates_with_persistent_metadata_counts(tmp_path) -> None:
    root = tmp_path / "archive"
    payload = b"historical-v2-archive-object"
    result = _result(turn="8" * 64, payloads=(payload,))
    archive = PaidMediaWebAssetArchive(root, max_documents=3, max_members=7)
    _store(archive, result, (payload,))
    archive.close()
    _rewrite_archive_meta_as_exact_v2(root)

    migrated = PaidMediaWebAssetArchive(root, max_documents=3, max_members=7)
    with sqlite3.connect(root / "archive.db") as connection:
        meta = connection.execute(
            "SELECT schema_version,document_count,max_documents,"
            "member_count,max_members,cleanup_pending "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
    assert meta == (3, 1, 3, 1, 7, 0)
    migrated.close()


def test_drifted_v1_archive_is_rejected_instead_of_migrated(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    _rewrite_archive_meta_as_exact_v1(root)
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute(
            "UPDATE web_asset_archive_meta SET schema_fingerprint=? WHERE singleton=1",
            ("f" * 64,),
        )

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def test_two_openers_converge_while_migrating_exact_v1_archive(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    _rewrite_archive_meta_as_exact_v1(root)
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []
    opened: list[PaidMediaWebAssetArchive] = []

    def migrate() -> None:
        try:
            barrier.wait(timeout=10)
            opened.append(PaidMediaWebAssetArchive(root))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=migrate) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert len(opened) == 2
    with sqlite3.connect(root / "archive.db") as connection:
        meta = connection.execute(
            "SELECT schema_version,cleanup_pending FROM web_asset_archive_meta "
            "WHERE singleton=1"
        ).fetchone()
    assert meta == (3, 0)
    for item in opened:
        item.close()


def test_archive_is_principal_bound_and_corruption_fails_closed(tmp_path) -> None:
    archive = PaidMediaWebAssetArchive(tmp_path / "archive")
    payload = b"principal-private"
    result = _result(turn="3" * 64, payloads=(payload,))
    _store(archive, result, (payload,))
    digest = hashlib.sha256(payload).hexdigest()

    assert archive.read(principal_hash="c" * 64, asset_sha256=digest) is None
    object_path = next(archive.object_directory.iterdir())
    object_path.write_bytes(b"corrupt")
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        archive.read(principal_hash=PRINCIPAL, asset_sha256=digest)
    archive.close()


def test_concurrent_fresh_initializers_converge_to_one_exact_archive(tmp_path) -> None:
    root = tmp_path / "archive"
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def initialize() -> None:
        try:
            barrier.wait(timeout=10)
            archive = PaidMediaWebAssetArchive(root)
            archive.close()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=initialize) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []


def test_fresh_concurrent_bootstrap_is_stable_across_twenty_rounds(tmp_path) -> None:
    for attempt in range(20):
        root = tmp_path / f"archive-{attempt}"
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []
        opened: list[PaidMediaWebAssetArchive] = []

        def initialize() -> None:
            try:
                barrier.wait(timeout=20)
                opened.append(PaidMediaWebAssetArchive(root))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=initialize) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert all(not thread.is_alive() for thread in threads), attempt
        assert errors == [], (attempt, errors)
        assert len(opened) == 2
        for archive in opened:
            archive.close()


def test_recovery_snapshot_cannot_delete_another_instance_new_commit(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    writer = PaidMediaWebAssetArchive(root)
    recovery_scanning = threading.Event()
    release_recovery = threading.Event()
    writer_finished = threading.Event()
    errors: list[BaseException] = []
    opened: list[PaidMediaWebAssetArchive] = []
    original_iterdir = Path.iterdir
    paused_once = False

    def paused_iterdir(path: Path):
        nonlocal paused_once
        if path == writer.object_directory and not paused_once:
            paused_once = True
            recovery_scanning.set()
            assert release_recovery.wait(timeout=20)
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", paused_iterdir)

    def reopen_for_recovery() -> None:
        try:
            opened.append(PaidMediaWebAssetArchive(root))
        except BaseException as exc:
            errors.append(exc)

    payload = b"new-commit-during-recovery"
    result = _result(turn="9" * 64, payloads=(payload,))

    def commit_from_other_instance() -> None:
        try:
            _store(writer, result, (payload,))
        except BaseException as exc:
            errors.append(exc)
        finally:
            writer_finished.set()

    recovery_thread = threading.Thread(target=reopen_for_recovery)
    recovery_thread.start()
    assert recovery_scanning.wait(timeout=20)
    writer_thread = threading.Thread(target=commit_from_other_instance)
    writer_thread.start()
    time.sleep(0.1)
    assert not writer_finished.is_set()

    release_recovery.set()
    recovery_thread.join(timeout=20)
    writer_thread.join(timeout=20)
    assert not recovery_thread.is_alive()
    assert not writer_thread.is_alive()
    assert errors == []
    restored = writer.read(
        principal_hash=PRINCIPAL,
        asset_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert restored is not None
    assert restored.payload == payload
    for archive in opened:
        archive.close()
    writer.close()


def test_partial_prune_cannot_unlink_another_instance_same_digest_commit(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    failing = PaidMediaWebAssetArchive(root)
    writer = PaidMediaWebAssetArchive(root)
    payloads = (b"shared-first-object", b"failing-second-object")
    failing_result = _result(turn="7" * 64, payloads=payloads)
    winning_result = _result(turn="8" * 64, payloads=(payloads[0],))
    original_store = archivemod._PaidMediaWebDocumentBatch.store_asset
    store_calls = 0

    def fail_second_asset(batch, **kwargs):
        if batch.archive is not failing:
            return original_store(batch, **kwargs)
        nonlocal store_calls
        store_calls += 1
        if store_calls == 2:
            raise PaidMediaWebArchiveUnavailable("injected partial document")
        return original_store(batch, **kwargs)

    monkeypatch.setattr(
        archivemod._PaidMediaWebDocumentBatch, "store_asset", fail_second_asset
    )
    original_unlink = Path.unlink
    prune_at_unlink = threading.Event()
    release_prune = threading.Event()
    winner_finished = threading.Event()
    failing_errors: list[BaseException] = []
    winner_errors: list[BaseException] = []

    def paused_unlink(path: Path, *args, **kwargs):
        if (
            threading.current_thread().name == "failing-prune"
            and path.parent == failing.object_directory
            and path.exists()
        ):
            prune_at_unlink.set()
            assert release_prune.wait(timeout=20)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", paused_unlink)

    def run_failing_document() -> None:
        try:
            _store(failing, failing_result, payloads)
        except BaseException as exc:
            failing_errors.append(exc)

    def run_winning_document() -> None:
        try:
            _store(writer, winning_result, (payloads[0],))
        except BaseException as exc:
            winner_errors.append(exc)
        finally:
            winner_finished.set()

    failing_thread = threading.Thread(
        target=run_failing_document, name="failing-prune"
    )
    failing_thread.start()
    assert prune_at_unlink.wait(timeout=20)
    winner_thread = threading.Thread(target=run_winning_document)
    winner_thread.start()
    time.sleep(0.1)
    assert not winner_finished.is_set()

    release_prune.set()
    failing_thread.join(timeout=20)
    winner_thread.join(timeout=20)
    assert not failing_thread.is_alive()
    assert not winner_thread.is_alive()
    assert len(failing_errors) == 1
    assert isinstance(failing_errors[0], PaidMediaWebArchiveUnavailable)
    assert winner_errors == []
    restored = writer.read(
        principal_hash=PRINCIPAL,
        asset_sha256=hashlib.sha256(payloads[0]).hexdigest(),
    )
    assert restored is not None
    assert restored.payload == payloads[0]
    failing.close()
    writer.close()


def test_constructor_waits_for_another_instance_fence_then_reads_archive(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    owner = PaidMediaWebAssetArchive(root)
    payload = b"constructor-waits-for-authority"
    result = _result(turn="6" * 64, payloads=(payload,))
    _store(owner, result, (payload,))
    digest = hashlib.sha256(payload).hexdigest()
    fence_held = threading.Event()
    release_fence = threading.Event()
    constructor_started = threading.Event()
    constructor_finished = threading.Event()
    errors: list[BaseException] = []
    opened: list[PaidMediaWebAssetArchive] = []

    def hold_fence() -> None:
        with owner._authority_fence():
            fence_held.set()
            assert release_fence.wait(timeout=20)

    def construct_waiter() -> None:
        constructor_started.set()
        try:
            opened.append(PaidMediaWebAssetArchive(root))
        except BaseException as exc:
            errors.append(exc)
        finally:
            constructor_finished.set()

    owner_thread = threading.Thread(target=hold_fence)
    owner_thread.start()
    assert fence_held.wait(timeout=20)
    waiter_thread = threading.Thread(target=construct_waiter)
    waiter_thread.start()
    assert constructor_started.wait(timeout=20)
    time.sleep(0.1)
    assert not constructor_finished.is_set()

    release_fence.set()
    owner_thread.join(timeout=20)
    waiter_thread.join(timeout=20)
    assert not owner_thread.is_alive()
    assert not waiter_thread.is_alive()
    assert errors == []
    assert len(opened) == 1
    restored = opened[0].read(
        principal_hash=PRINCIPAL,
        asset_sha256=digest,
    )
    assert restored is not None
    assert restored.payload == payload
    opened[0].close()
    owner.close()


def test_archive_rejects_an_off_prefix_trigger(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute(
            "CREATE TRIGGER evil AFTER INSERT ON web_asset_archive_objects "
            "BEGIN UPDATE web_asset_archive_meta SET stored_bytes=0 WHERE singleton=1; END"
        )
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def test_archive_rejects_a_foreign_key_violation_on_reopen(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    with sqlite3.connect(root / "archive.db") as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO web_asset_archive_members VALUES(?,?,0,?)",
            (PRINCIPAL, "d" * 64, "e" * 64),
        )
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def test_archive_rejects_a_hardlinked_database(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    try:
        os.link(root / "archive.db", tmp_path / "archive-copy.db")
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def test_archive_rejects_a_hardlinked_authority_lock(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    try:
        os.link(
            root / ".archive-authority.lock",
            tmp_path / "archive-authority-copy.lock",
        )
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def test_empty_first_create_torn_lock_is_repaired_before_authority_exists(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    (root / ".archive-authority.lock").write_bytes(b"")

    archive = PaidMediaWebAssetArchive(root)
    try:
        assert (root / ".archive-authority.lock").read_bytes() == (
            b"nachuan-paid-media-web-archive-lock-v1\r\n"
        )
    finally:
        archive.close()


def test_torn_lock_with_existing_archive_authority_fails_closed(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    archive.close()
    (root / ".archive-authority.lock").write_bytes(b"torn")

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=False)
    except OSError:
        pytest.skip("file symlinks are unavailable on this Windows installation")


def test_reparse_ancestor_is_rejected_without_creating_under_physical_target(
    tmp_path,
) -> None:
    physical = tmp_path / "physical"
    physical.mkdir()
    alias = tmp_path / "alias"
    try:
        os.symlink(physical, alias, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this Windows installation")

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(alias / "archive")

    assert not (physical / "archive").exists()


def test_dangling_database_link_is_rejected_without_external_write(tmp_path) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    external = tmp_path / "outside-database.db"
    _symlink_or_skip(root / "archive.db", external)

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)
    assert not external.exists()


def test_dangling_sqlite_journal_link_is_rejected_without_external_write(
    tmp_path,
) -> None:
    root = tmp_path / "archive"
    root.mkdir()
    external = tmp_path / "outside-journal.db"
    _symlink_or_skip(root / "archive.db-journal", external)

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        PaidMediaWebAssetArchive(root)
    assert not external.exists()


def test_dangling_object_link_is_rejected_without_external_write(tmp_path) -> None:
    root = tmp_path / "archive"
    archive = PaidMediaWebAssetArchive(root)
    payload = b"object-link-payload"
    result = _result(turn="5" * 64, payloads=(payload,))
    digest = hashlib.sha256(payload).hexdigest()
    external = tmp_path / "outside-object.asset"
    leaf = archive._object_leaf(PRINCIPAL, digest)
    _symlink_or_skip(archive.object_directory / leaf, external)

    with pytest.raises(PaidMediaWebArchiveUnavailable):
        _store(archive, result, (payload,))
    assert not external.exists()
    archive.close()
