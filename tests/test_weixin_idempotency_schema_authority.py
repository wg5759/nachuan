from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from urllib.parse import quote

import pytest

from gateway.weixin_idempotency import (
    WeixinIdempotencyStore,
    WeixinIdempotencyUnavailable,
    _APPLICATION_ID,
    _CURRENT_SCHEMA_DDL,
    _SCHEMA_VERSION,
    _installed_generation_statements,
    _materialized_schema_rows,
    _persistent_schema_rows,
    _previous_current_generation_statements,
    hash_channel_principal,
    hash_weixin_request,
)


KEY = "wxmsg-v1:" + ("a" * 64)


def _principal() -> str:
    return hash_channel_principal(
        channel="weixin",
        user_id="schema-authority-user",
        chat_id="schema-authority-chat",
    )


def _request_hash(label: str = "hello") -> str:
    return hash_weixin_request(
        channel="weixin",
        chat_id="schema-authority-chat",
        user_id="schema-authority-user",
        message=label,
        model="model-a",
        system=None,
        video_async=False,
    )


def _artifact_snapshot(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: (candidate.read_bytes() if candidate.exists() else None)
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := Path(f"{path}{suffix}"))
    }


def _immutable_connection(path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(path.resolve().as_posix(), safe="/:")
    return sqlite3.connect(uri + "?mode=ro&immutable=1", uri=True)


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


def _create_abandoned_supported_weixin_wal(path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
from gateway import weixin_idempotency as module
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
for statement in module._previous_current_generation_statements():
    connection.execute(statement)
connection.execute(
    'INSERT INTO weixin_agent_idempotency_meta'
    '(singleton,record_count,response_bytes) VALUES(1,0,0)'
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

    with pytest.raises(WeixinIdempotencyUnavailable):
        WeixinIdempotencyStore(path)

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

    with pytest.raises(WeixinIdempotencyUnavailable):
        WeixinIdempotencyStore(path)

    assert not path.exists()
    assert wal.read_bytes() == b"orphan-wal-evidence"
    assert shm.read_bytes() == b"orphan-shm-evidence"


def test_supported_weixin_generation_committed_only_in_wal_is_recovered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supported-generation-in-wal.db"
    _create_abandoned_supported_weixin_wal(path)

    with _immutable_connection(path) as immutable:
        assert immutable.execute("SELECT COUNT(*) FROM sqlite_master").fetchone() == (0,)
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as wal_aware:
        assert wal_aware.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'weixin_agent_idempotency%'"
        ).fetchone()[0] >= 2

    store = WeixinIdempotencyStore(path)
    store.close()
    reopened = WeixinIdempotencyStore(path)
    reopened.close()
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as recovered:
        assert recovered.execute("PRAGMA application_id").fetchone() == (
            _APPLICATION_ID,
        )
        assert recovered.execute("PRAGMA user_version").fetchone() == (
            _SCHEMA_VERSION,
        )


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_weixin_wal_pair_is_rejected_without_mutation(
    tmp_path: Path,
    missing_suffix: str,
) -> None:
    path = tmp_path / f"incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_foreign_hot_wal(path)
    Path(f"{path}{missing_suffix}").unlink()
    before = _artifact_snapshot(path)

    with pytest.raises(WeixinIdempotencyUnavailable):
        WeixinIdempotencyStore(path)

    assert _artifact_snapshot(path) == before


def test_weixin_rollback_journal_is_preserved_and_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rollback-journal.db"
    sqlite3.connect(path).close()
    journal = Path(f"{path}-journal")
    journal.write_bytes(b"unresolved-rollback-evidence")
    before = _artifact_snapshot(path)

    with pytest.raises(WeixinIdempotencyUnavailable):
        WeixinIdempotencyStore(path)

    assert _artifact_snapshot(path) == before


def test_unknown_database_is_rejected_without_source_or_sidecar_change(tmp_path):
    path = tmp_path / "outside.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE outside_marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO outside_marker VALUES('sentinel')")
        connection.commit()
    before = _artifact_snapshot(path)
    before_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(
        WeixinIdempotencyUnavailable,
        match="cannot initialize idempotency ledger",
    ):
        WeixinIdempotencyStore(path)

    assert _artifact_snapshot(path) == before
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before_sha256
    with _immutable_connection(path) as connection:
        assert connection.execute(
            "SELECT value FROM outside_marker"
        ).fetchone() == ("sentinel",)
        assert [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master ORDER BY name"
        )] == ["outside_marker"]


def test_fresh_database_has_explicit_identity_exact_schema_and_page_cap(tmp_path):
    path = tmp_path / "turns.db"
    max_database_bytes = 8 * 1024 * 1024
    store = WeixinIdempotencyStore(
        path,
        max_database_bytes=max_database_bytes,
    )
    assert store._keeper is not None
    keeper_page_size = int(store._keeper.execute("PRAGMA page_size").fetchone()[0])
    keeper_max_pages = int(
        store._keeper.execute("PRAGMA max_page_count").fetchone()[0]
    )
    assert keeper_max_pages * keeper_page_size <= max_database_bytes

    with _immutable_connection(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            _APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            _SCHEMA_VERSION,
        )
        assert _persistent_schema_rows(connection) == _materialized_schema_rows(
            _CURRENT_SCHEMA_DDL
        )
    store.close()


@pytest.mark.parametrize(
    "statements",
    [
        _installed_generation_statements(),
        _previous_current_generation_statements(),
    ],
    ids=["installed-altered", "previous-fresh"],
)
def test_known_unversioned_generation_is_migrated_to_current_exact_schema(
    tmp_path,
    statements,
):
    path = tmp_path / "installed-copy.db"
    with sqlite3.connect(path) as connection:
        for statement in statements:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO weixin_agent_idempotency_meta"
            "(singleton,record_count,response_bytes) VALUES(1,0,0)"
        )
        connection.commit()

    store = WeixinIdempotencyStore(path)
    store.close()
    with _immutable_connection(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            _APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            _SCHEMA_VERSION,
        )
        assert _persistent_schema_rows(connection) == _materialized_schema_rows(
            _CURRENT_SCHEMA_DDL
        )


def test_wrong_identity_is_rejected_without_additional_file_change(tmp_path):
    path = tmp_path / "wrong-identity.db"
    store = WeixinIdempotencyStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA application_id=12345")
        connection.commit()
    before = _artifact_snapshot(path)

    with pytest.raises(WeixinIdempotencyUnavailable):
        WeixinIdempotencyStore(path)

    after = _artifact_snapshot(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert {key for key, value in after.items() if value is not None} == {
        key for key, value in before.items() if value is not None
    }


def test_external_schema_drift_blocks_next_write(tmp_path):
    path = tmp_path / "external-schema.db"
    store = WeixinIdempotencyStore(path, lease_seconds=60)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE VIEW outside_projection AS SELECT 1 AS value")
        connection.commit()

    with pytest.raises(
        WeixinIdempotencyUnavailable,
        match="cannot claim idempotency record",
    ):
        store.claim(_principal(), KEY, _request_hash(), now=100.0)
    store.close()


def test_external_counter_drift_blocks_next_write(tmp_path):
    path = tmp_path / "external-counter.db"
    store = WeixinIdempotencyStore(path, lease_seconds=60)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE weixin_agent_idempotency_meta SET record_count=1 "
            "WHERE singleton=1"
        )
        connection.commit()

    with pytest.raises(
        WeixinIdempotencyUnavailable,
        match="cannot claim idempotency record",
    ):
        store.claim(_principal(), KEY, _request_hash(), now=100.0)
    store.close()


def test_concurrent_cold_start_provisions_one_exact_generation(tmp_path):
    path = tmp_path / "cold-start.db"
    barrier = Barrier(8)

    def open_store(_index: int) -> WeixinIdempotencyStore:
        barrier.wait(timeout=10)
        return WeixinIdempotencyStore(path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        stores = list(pool.map(open_store, range(8)))
    for store in stores:
        store.close()

    with _immutable_connection(path) as connection:
        assert _persistent_schema_rows(connection) == _materialized_schema_rows(
            _CURRENT_SCHEMA_DDL
        )
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)


def test_persisted_tighter_limit_fences_an_existing_wider_store(tmp_path):
    path = tmp_path / "shared-limits.db"
    wide = WeixinIdempotencyStore(path, lease_seconds=60, max_records=10)
    principal = _principal()
    for index in range(2):
        claim = wide.claim(
            principal,
            "wxmsg-v1:" + f"{index + 1:064x}",
            _request_hash(f"reserved-{index}"),
            now=100.0,
        )
        assert claim.state == "claimed"

    tight = WeixinIdempotencyStore(path, lease_seconds=60, max_records=2)
    with pytest.raises(
        WeixinIdempotencyUnavailable,
        match="capacity reached",
    ):
        wide.claim(
            principal,
            "wxmsg-v1:" + f"{3:064x}",
            _request_hash("must-not-exceed-shared-limit"),
            now=100.0,
        )
    tight.close()
    wide.close()

    with _immutable_connection(path) as connection:
        assert connection.execute(
            "SELECT record_count,max_records "
            "FROM weixin_agent_idempotency_meta WHERE singleton=1"
        ).fetchone() == (2, 2)


@pytest.mark.skipif(os.name != "nt", reason="Windows replacement semantics")
def test_close_is_idempotent_and_prevents_reuse(tmp_path):
    store = WeixinIdempotencyStore(tmp_path / "closed.db")
    store.close()
    store.close()
    with pytest.raises(WeixinIdempotencyUnavailable, match="closed"):
        store.claim(_principal(), KEY, _request_hash(), now=100.0)
