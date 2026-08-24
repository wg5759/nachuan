from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from pathlib import Path

import pytest

from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _database_family(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal", ".rollback-anchor")
        for candidate in (Path(f"{path}{suffix}"),)
    }


def _create_abandoned_channel_wal(path: Path, statement: str) -> None:
    created = subprocess.run(
        [
            sys.executable,
            "-c",
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
            os.fspath(path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


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


def _tamper_channel_internal_tbl_name(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE name LIKE 'sqlite_autoindex_durable_channel_media_admissions_%'"
        ).fetchone()
        assert row is not None
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name='durable_media_requests' WHERE name=?",
            (row[0],),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()


def _claim(
    store: DurableChannelMediaRequestStore,
    *,
    channel: str = "feishu",
    operation: str = "vision.describe",
    message_key: str = "fsmsg-v1:" + ("1" * 64),
    principal_hash: str | None = None,
    request_sha256: str | None = None,
    max_success_bytes: int = 256,
    now: float = 10.0,
):
    return store.claim(
        channel=channel,
        operation=operation,
        message_key=message_key,
        principal_hash=principal_hash or _digest("principal-a"),
        request_sha256=request_sha256 or _digest("request-a"),
        max_success_bytes=max_success_bytes,
        now=now,
    )


def test_operations_share_capacity_but_never_share_one_turn(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        max_response_bytes=1024,
        max_total_response_bytes=4096,
        max_database_bytes=256 * 1024,
    )
    try:
        vision = _claim(store, operation="vision.describe")
        lapian = _claim(
            store,
            operation="lapian.analyze",
            request_sha256=_digest("request-lapian"),
        )

        assert vision.state == lapian.state == "claimed"
        assert vision.turn_id != lapian.turn_id
    finally:
        store.close()


def test_principal_scope_prevents_cross_customer_replay(tmp_path):
    store = DurableChannelMediaRequestStore(tmp_path / "channel-media.db")
    try:
        first = _claim(store, principal_hash=_digest("principal-a"))
        second = _claim(store, principal_hash=_digest("principal-b"))

        assert first.state == second.state == "claimed"
        assert first.turn_id != second.turn_id
    finally:
        store.close()


def test_same_key_different_semantics_is_conflict(tmp_path):
    store = DurableChannelMediaRequestStore(tmp_path / "channel-media.db")
    try:
        assert _claim(store).state == "claimed"
        conflict = _claim(store, request_sha256=_digest("different-request"))

        assert conflict.state == "conflict"
    finally:
        store.close()


def test_concurrent_claim_executes_once_and_replays_exact_result(tmp_path):
    store = DurableChannelMediaRequestStore(tmp_path / "channel-media.db")
    barrier = threading.Barrier(2)
    claims = []

    def run() -> None:
        barrier.wait()
        claims.append(_claim(store))

    threads = [threading.Thread(target=run), threading.Thread(target=run)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        assert all(not thread.is_alive() for thread in threads)
        assert sorted(claim.state for claim in claims) == ["claimed", "processing"]
        owner = next(claim for claim in claims if claim.state == "claimed")
        assert owner.fencing_token
        assert store.enter_provider_phase(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            max_success_bytes=256,
            now=10.1,
        )
        result = {"text": "one paid result"}
        assert store.succeed(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            response=result,
            now=10.2,
        )

        replay = _claim(store, now=10.3)
        assert replay.state == "succeeded"
        assert replay.response == result
    finally:
        store.close()


def test_expired_provider_phase_fails_closed_without_new_claim(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        lease_seconds=1,
    )
    try:
        owner = _claim(store, now=10.0)
        assert store.enter_provider_phase(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            max_success_bytes=256,
            now=10.1,
        )

        recovery = _claim(store, now=11.1)
        assert recovery.state == "recovery_required"
        assert recovery.attempt == 1
    finally:
        store.close()


def test_expired_success_returns_result_expired_without_new_claim(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        lease_seconds=1,
        retention_seconds=1,
    )
    try:
        owner = _claim(store, now=10.0)
        assert owner.state == "claimed"
        assert store.enter_provider_phase(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            max_success_bytes=256,
            now=10.1,
        )
        assert store.succeed(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            response={"text": "short-lived replay body"},
            now=10.2,
        )

        expired = _claim(store, now=11.2)

        assert expired.state == "result_expired"
        assert expired.turn_id == owner.turn_id
        assert expired.attempt == 1
        assert expired.response is None
    finally:
        store.close()


def test_recovery_required_remains_permanent_after_short_receipt_ttl(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        lease_seconds=1,
        retention_seconds=1,
    )
    try:
        owner = _claim(store, now=10.0)
        assert store.enter_provider_phase(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            max_success_bytes=256,
            now=10.1,
        )
        assert _claim(store, now=11.1).state == "recovery_required"

        permanent = _claim(store, now=12.1)

        assert permanent.state == "recovery_required"
        assert permanent.turn_id == owner.turn_id
        assert permanent.attempt == 1
    finally:
        store.close()


def test_permanent_admission_keeps_same_key_different_request_conflict(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        retention_seconds=1,
    )
    try:
        owner = _claim(store, now=10.0)
        assert store.enter_provider_phase(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            max_success_bytes=256,
            now=10.1,
        )
        assert store.succeed(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            response={"text": "done"},
            now=10.2,
        )

        conflict = _claim(
            store,
            request_sha256=_digest("different-after-expiry"),
            now=11.2,
        )

        assert conflict.state == "conflict"
        assert conflict.turn_id == owner.turn_id
    finally:
        store.close()


def test_phase_zero_abandon_releases_identity_without_permanent_tombstone(tmp_path):
    store = DurableChannelMediaRequestStore(tmp_path / "channel-media.db")
    try:
        first = _claim(store, now=10.0)
        assert first.state == "claimed"
        assert store.abandon_pre_provider(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
        )

        retry = _claim(store, now=10.1)

        assert retry.state == "claimed"
        assert retry.turn_id == first.turn_id
        assert retry.fencing_token != first.fencing_token
        assert retry.attempt == 1
    finally:
        store.close()


def test_permanent_admission_capacity_fails_before_provider_phase(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        retention_seconds=1,
        max_records=1,
    )
    try:
        first = _claim(store, now=10.0)
        assert store.enter_provider_phase(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            now=10.1,
        )
        assert store.succeed(
            turn_id=first.turn_id,
            fencing_token=first.fencing_token,
            response={"text": "first"},
            now=10.2,
        )
        second = _claim(
            store,
            message_key="fsmsg-v1:" + ("2" * 64),
            request_sha256=_digest("request-b"),
            now=11.2,
        )
        assert second.state == "claimed"

        with pytest.raises(
            DurableMediaRequestUnavailable,
            match="admission capacity reached",
        ):
            store.enter_provider_phase(
                turn_id=second.turn_id,
                fencing_token=second.fencing_token,
                now=11.3,
            )

        assert _claim(store, now=11.4).state == "result_expired"
        assert _claim(
            store,
            message_key="fsmsg-v1:" + ("2" * 64),
            request_sha256=_digest("request-b"),
            now=11.4,
        ).state == "processing"
    finally:
        store.close()


def test_paid_and_channel_schema_profiles_reject_cross_open(tmp_path):
    channel_path = tmp_path / "channel-media.db"
    channel = DurableChannelMediaRequestStore(
        channel_path,
        max_response_bytes=8 * 1024 * 1024,
        max_total_response_bytes=256 * 1024 * 1024,
        max_database_bytes=512 * 1024 * 1024,
    )
    channel.close()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableMediaRequestStore(
            channel_path,
            max_response_bytes=8 * 1024 * 1024,
            max_total_response_bytes=256 * 1024 * 1024,
            max_database_bytes=512 * 1024 * 1024,
        )

    paid_path = tmp_path / "paid-media.db"
    paid = DurableMediaRequestStore(
        paid_path,
        max_response_bytes=8 * 1024 * 1024,
        max_total_response_bytes=256 * 1024 * 1024,
        max_database_bytes=512 * 1024 * 1024,
    )
    paid.close()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(
            paid_path,
            max_response_bytes=8 * 1024 * 1024,
            max_total_response_bytes=256 * 1024 * 1024,
            max_database_bytes=512 * 1024 * 1024,
        )


def test_channel_schema_rejects_unexpected_objects(tmp_path):
    path = tmp_path / "channel-media.db"
    store = DurableChannelMediaRequestStore(path)
    store.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE injected_schema_object(value TEXT)")

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)


def test_channel_schema_rejects_extra_view_without_mutating_database(tmp_path):
    path = tmp_path / "channel-media.db"
    DurableChannelMediaRequestStore(path).close()
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
        store = DurableChannelMediaRequestStore(path)
        store.close()

    with pytest.raises(DurableMediaRequestUnavailable):
        reopen()
    assert {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := Path(f"{path}{suffix}")).exists()
    } == before


def test_channel_foreign_schema_only_in_abandoned_wal_is_rejected_without_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "channel-foreign-hot-wal.db"
    _create_abandoned_channel_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    before = _database_family(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)

    after = _database_family(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after.get("-journal") == before.get("-journal")
    assert after.get("-shm") is not None


def test_channel_orphan_wal_family_is_rejected_without_recreating_main(
    tmp_path: Path,
) -> None:
    path = tmp_path / "channel-orphan-hot-wal.db"
    _create_abandoned_channel_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    path.unlink()
    before = _database_family(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)

    assert _database_family(path) == before


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_channel_incomplete_wal_pair_is_rejected_without_mutation(
    tmp_path: Path, missing_suffix: str
) -> None:
    path = tmp_path / f"channel-incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_channel_wal(path, "CREATE TABLE alien(value TEXT NOT NULL)")
    Path(f"{path}{missing_suffix}").unlink()
    before = _database_family(path)

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)

    assert _database_family(path) == before


def test_channel_exact_current_hot_wal_reopens_with_channel_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "channel-current-hot-wal.db"
    original = DurableChannelMediaRequestStore(path)
    expected = original.inspect_root_state()
    original.close()
    _create_abandoned_channel_wal(
        path,
        "UPDATE durable_media_requests_meta "
        "SET max_records=max_records WHERE singleton=1",
    )

    reopened = DurableChannelMediaRequestStore(path)
    try:
        assert reopened.inspect_root_state() == expected
        assert _claim(reopened).state == "claimed"
    finally:
        reopened.close()


def test_channel_schema_rejects_reserved_prefix_object_without_mutation(tmp_path):
    path = tmp_path / "channel-media-reserved-prefix.db"
    DurableChannelMediaRequestStore(path).close()
    _inject_reserved_prefix_view(path)
    before = path.read_bytes()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)
    assert path.read_bytes() == before


def test_channel_schema_rejects_internal_tbl_name_drift_without_mutation(tmp_path):
    path = tmp_path / "channel-media-internal-metadata.db"
    DurableChannelMediaRequestStore(path).close()
    _tamper_channel_internal_tbl_name(path)
    before = path.read_bytes()

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)
    assert path.read_bytes() == before


def test_channel_schema_rejects_quoted_literal_case_collision(tmp_path):
    path = tmp_path / "channel-media.db"
    store = DurableChannelMediaRequestStore(path)
    store.close()

    with sqlite3.connect(path) as connection:
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
        DurableChannelMediaRequestStore(path)


def test_channel_schema_rejects_orphan_provider_phase_admission(tmp_path):
    path = tmp_path / "channel-media.db"
    store = DurableChannelMediaRequestStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO durable_channel_media_admissions "
            "(principal_hash,operation,key_hash,turn_id,request_sha256,state,"
            "attempt_count,provider_entered_at,updated_at) "
            "VALUES(?,?,?,?,?,'provider_phase',1,10,10)",
            (
                _digest("orphan-principal"),
                "images.create",
                _digest("orphan-key"),
                _digest("orphan-turn"),
                _digest("orphan-request"),
            ),
        )

    with pytest.raises(DurableMediaRequestUnavailable):
        DurableChannelMediaRequestStore(path)


def test_permanent_success_admission_survives_restart_after_result_expiry(tmp_path):
    path = tmp_path / "channel-media.db"
    first_store = DurableChannelMediaRequestStore(path, retention_seconds=1)
    owner = _claim(first_store, now=10.0)
    assert first_store.enter_provider_phase(
        turn_id=owner.turn_id,
        fencing_token=owner.fencing_token,
        now=10.1,
    )
    assert first_store.succeed(
        turn_id=owner.turn_id,
        fencing_token=owner.fencing_token,
        response={"text": "restart-safe"},
        now=10.2,
    )
    first_store.close()

    reopened = DurableChannelMediaRequestStore(path, retention_seconds=1)
    try:
        replay = _claim(reopened, now=11.2)
        assert replay.state == "result_expired"
        assert replay.turn_id == owner.turn_id
    finally:
        reopened.close()


def test_expired_provider_phase_persists_terminal_recovery_and_releases_bytes(
    tmp_path,
):
    path = tmp_path / "channel-media.db"
    store = DurableChannelMediaRequestStore(
        path,
        lease_seconds=1,
        retention_seconds=10,
    )
    owner = _claim(store, max_success_bytes=256, now=10.0)
    assert store.enter_provider_phase(
        turn_id=owner.turn_id,
        fencing_token=owner.fencing_token,
        max_success_bytes=256,
        now=10.1,
    )
    assert _claim(store, max_success_bytes=256, now=11.1).state == (
        "recovery_required"
    )
    store.close()

    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT state FROM durable_channel_media_admissions WHERE turn_id=?",
            (owner.turn_id,),
        ).fetchone() == ("recovery_required",)
        assert connection.execute(
            "SELECT status,reserved_response_bytes FROM durable_media_requests "
            "WHERE turn_id=?",
            (owner.turn_id,),
        ).fetchone() == ("recovery_required", 0)


def test_heartbeat_is_strict_at_deadline_and_extends_live_claim(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        lease_seconds=2,
    )
    try:
        owner = _claim(store, now=10.0)
        assert store.heartbeat(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            now=11.9,
        )
        assert not store.heartbeat(
            turn_id=owner.turn_id,
            fencing_token=owner.fencing_token,
            now=13.9,
        )
    finally:
        store.close()


def test_response_reservations_fail_before_any_provider_call(tmp_path):
    store = DurableChannelMediaRequestStore(
        tmp_path / "channel-media.db",
        max_response_bytes=256,
        max_total_response_bytes=300,
        max_database_bytes=256 * 1024,
    )
    try:
        assert _claim(store, max_success_bytes=200).state == "claimed"
        with pytest.raises(
            DurableMediaRequestUnavailable,
            match="capacity reached",
        ):
            _claim(
                store,
                message_key="fsmsg-v1:" + ("2" * 64),
                request_sha256=_digest("request-b"),
                max_success_bytes=200,
            )
    finally:
        store.close()
