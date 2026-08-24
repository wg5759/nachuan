from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

import gateway.bridge_protocol as bridge_protocol
from gateway.bridge_protocol import (
    BridgeReplayError,
    BridgeReplayStoreUnavailable,
    PersistentNonceReplayGuard,
)


def _artifact_snapshot(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    }


def _create_legacy(path: Path, *, nonce: str = "a" * 32) -> None:
    with closing(sqlite3.connect(path)) as connection:
        for statement in bridge_protocol._BRIDGE_REPLAY_LEGACY_DDL:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO bridge_nonce_replay(channel,nonce,valid_until) "
            "VALUES('weixin',?,2000000091)",
            (nonce,),
        )
        connection.execute(
            "INSERT INTO bridge_nonce_replay_meta(singleton,row_count) "
            "VALUES(1,1)"
        )
        connection.commit()


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


def _create_abandoned_supported_bridge_wal(path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
from gateway import bridge_protocol as module
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
for statement in module._BRIDGE_REPLAY_LEGACY_DDL:
    connection.execute(statement)
connection.execute(
    "INSERT INTO bridge_nonce_replay(channel,nonce,valid_until) "
    "VALUES('weixin',?,2000000091)",
    ('a' * 32,),
)
connection.execute(
    'INSERT INTO bridge_nonce_replay_meta(singleton,row_count) VALUES(1,1)'
)
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

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

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

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

    assert not path.exists()
    assert wal.read_bytes() == b"orphan-wal-evidence"
    assert shm.read_bytes() == b"orphan-shm-evidence"


def test_supported_bridge_generation_committed_only_in_wal_is_recovered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supported-generation-in-wal.db"
    _create_abandoned_supported_bridge_wal(path)

    with sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True
    ) as immutable:
        assert immutable.execute("SELECT COUNT(*) FROM sqlite_master").fetchone() == (0,)
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as wal_aware:
        assert wal_aware.execute(
            "SELECT nonce FROM bridge_nonce_replay"
        ).fetchone() == ("a" * 32,)

    store = PersistentNonceReplayGuard(path)
    store.close()
    reopened = PersistentNonceReplayGuard(path)
    reopened.close()
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as recovered:
        assert recovered.execute("PRAGMA application_id").fetchone() == (
            bridge_protocol._BRIDGE_REPLAY_APPLICATION_ID,
        )
        assert recovered.execute("PRAGMA user_version").fetchone() == (
            bridge_protocol._BRIDGE_REPLAY_SCHEMA_VERSION,
        )


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_bridge_wal_pair_is_rejected_without_mutation(
    tmp_path: Path,
    missing_suffix: str,
) -> None:
    path = tmp_path / f"incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_foreign_hot_wal(path)
    Path(f"{path}{missing_suffix}").unlink()
    before = _artifact_snapshot(path)

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

    assert _artifact_snapshot(path) == before


def test_bridge_rollback_journal_is_preserved_and_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rollback-journal.db"
    sqlite3.connect(path).close()
    journal = Path(f"{path}-journal")
    journal.write_bytes(b"unresolved-rollback-evidence")
    before = _artifact_snapshot(path)

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

    assert _artifact_snapshot(path) == before


def test_unknown_database_is_rejected_without_mutating_main_or_sidecars(
    tmp_path,
) -> None:
    path = tmp_path / "foreign.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES('keep-me')")
        connection.commit()
    Path(f"{path}-wal").write_bytes(b"foreign-wal-sentinel")
    Path(f"{path}-shm").write_bytes(b"foreign-shm-sentinel")
    before = _artifact_snapshot(path)

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

    after = _artifact_snapshot(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-shm"] is not None


def test_exact_schema_with_wrong_identity_is_rejected_without_mutation(
    tmp_path,
) -> None:
    path = tmp_path / "wrong-identity.db"
    with closing(sqlite3.connect(path)) as connection:
        for statement in bridge_protocol._BRIDGE_REPLAY_SCHEMA_DDL:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO bridge_nonce_replay_meta("
            "singleton,row_count,max_entries,main_db_max_bytes,"
            "wal_max_bytes,shm_max_bytes) VALUES(1,0,50000,16777216,"
            "4194304,2097152)"
        )
        connection.execute("PRAGMA application_id=12345")
        connection.execute(
            f"PRAGMA user_version={bridge_protocol._BRIDGE_REPLAY_SCHEMA_VERSION}"
        )
        connection.commit()
    before = _artifact_snapshot(path)

    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(path)

    assert _artifact_snapshot(path) == before


def test_fresh_database_has_exact_identity_schema_and_runtime_profile(
    tmp_path,
) -> None:
    path = tmp_path / "fresh.db"
    guard = PersistentNonceReplayGuard(
        path,
        main_db_max_bytes=2 * 1024 * 1024,
        wal_max_bytes=1024 * 1024,
        shm_max_bytes=1024 * 1024,
    )
    connection = guard._connection
    assert connection is not None
    assert connection.execute("PRAGMA application_id").fetchone() == (
        bridge_protocol._BRIDGE_REPLAY_APPLICATION_ID,
    )
    assert connection.execute("PRAGMA user_version").fetchone() == (
        bridge_protocol._BRIDGE_REPLAY_SCHEMA_VERSION,
    )
    assert bridge_protocol._bridge_replay_schema_rows(connection) == (
        bridge_protocol._materialized_bridge_replay_schema(
            bridge_protocol._BRIDGE_REPLAY_SCHEMA_DDL
        )
    )
    assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    assert int(connection.execute("PRAGMA max_page_count").fetchone()[0]) <= (
        2 * 1024 * 1024 // page_size
    )
    guard.close()


def test_exact_legacy_generation_migrates_without_losing_replay_rows(
    tmp_path,
) -> None:
    path = tmp_path / "legacy.db"
    _create_legacy(path)

    guard = PersistentNonceReplayGuard(path)
    with pytest.raises(BridgeReplayError, match="replay rejected"):
        guard.consume(
            "weixin",
            "a" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
    guard.close()
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            bridge_protocol._BRIDGE_REPLAY_APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            bridge_protocol._BRIDGE_REPLAY_SCHEMA_VERSION,
        )


def test_installed_legacy_database_migrates_only_in_private_copy(tmp_path) -> None:
    source = Path(__file__).resolve().parents[1] / "data" / "bridge_protocol_replay.db"
    if not source.exists():
        pytest.skip("installed legacy database is unavailable")
    if any(Path(f"{source}{suffix}").exists() for suffix in ("-wal", "-shm")):
        pytest.skip("installed fixture has live sidecars and cannot be copied safely")
    source_before = source.read_bytes()
    private_copy = tmp_path / "installed-private-copy.db"
    shutil.copyfile(source, private_copy)

    guard = PersistentNonceReplayGuard(private_copy)
    guard.close()

    assert source.read_bytes() == source_before
    with closing(sqlite3.connect(private_copy)) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            bridge_protocol._BRIDGE_REPLAY_APPLICATION_ID,
        )


@pytest.mark.parametrize("tamper", ["extra_view", "trigger_sql", "counter"])
def test_external_runtime_drift_blocks_the_next_consume(tmp_path, tamper) -> None:
    path = tmp_path / "runtime-drift.db"
    guard = PersistentNonceReplayGuard(path)
    with closing(sqlite3.connect(path)) as connection:
        if tamper == "extra_view":
            connection.execute(
                "CREATE VIEW injected_view AS SELECT channel FROM bridge_nonce_replay"
            )
        elif tamper == "trigger_sql":
            connection.execute("DROP TRIGGER bridge_nonce_replay_capacity")
            connection.execute(
                "CREATE TRIGGER bridge_nonce_replay_capacity "
                "BEFORE INSERT ON bridge_nonce_replay BEGIN "
                "SELECT RAISE(ABORT, 'bridge replay capacity reached') "
                "WHERE (SELECT row_count>=max_entries FROM "
                "bridge_nonce_replay_meta WHERE singleton=1); END"
            )
        else:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE bridge_nonce_replay_meta SET row_count=7 WHERE singleton=1"
            )
        connection.commit()

    with pytest.raises(BridgeReplayStoreUnavailable):
        guard.consume(
            "weixin",
            "b" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
    guard.close()


def test_persisted_tighter_capacity_fences_an_already_open_wider_guard(
    tmp_path,
) -> None:
    path = tmp_path / "shared-limits.db"
    wider = PersistentNonceReplayGuard(path, max_entries=10)
    tighter = PersistentNonceReplayGuard(path, max_entries=2)
    tighter.close()

    for nonce in ("1" * 32, "2" * 32):
        wider.consume(
            "weixin",
            nonce,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
    with pytest.raises(BridgeReplayError, match="store is full"):
        wider.consume(
            "weixin",
            "3" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
    assert wider.max_entries == 2
    wider.close()


def test_concurrent_cold_start_converges_on_one_current_database(tmp_path) -> None:
    path = tmp_path / "cold-start.db"
    barrier = threading.Barrier(2)

    def open_guard() -> PersistentNonceReplayGuard:
        barrier.wait(timeout=5)
        return PersistentNonceReplayGuard(path, busy_timeout_ms=2_000)

    with ThreadPoolExecutor(max_workers=2) as pool:
        guards = list(pool.map(lambda _index: open_guard(), range(2)))
    try:
        guards[0].consume(
            "feishu",
            "c" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
        with pytest.raises(BridgeReplayError, match="replay rejected"):
            guards[1].consume(
                "feishu",
                "c" * 32,
                now=2_000_000_001,
                valid_until=2_000_000_091,
            )
    finally:
        for guard in guards:
            guard.close()


def test_close_is_idempotent_and_fences_future_consumes(tmp_path) -> None:
    guard = PersistentNonceReplayGuard(tmp_path / "closed.db")
    guard.close()
    guard.close()
    with pytest.raises(BridgeReplayStoreUnavailable, match="closed"):
        guard.consume(
            "weixin",
            "d" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not the boundary")
def test_database_parent_must_remain_a_real_directory(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-parent"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(link / "replay.db")
