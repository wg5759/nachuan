from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

import gateway.maintenance_ticket_store as maintenance_ticket_store
from gateway.maintenance_ticket_store import (
    MaintenanceTicketCapacity,
    MaintenanceTicketUnavailable,
    MaintenanceTicketStore,
    MaintenanceTicketStoreDependencies,
    MaintenanceTicketValidationError,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _database_family(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
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


def _create_abandoned_ticket_wal(path: Path, *, foreign: bool) -> None:
    journal_path = Path(f"{path}-journal")
    pinned_journal = journal_path.read_bytes() if journal_path.is_file() else None
    statement = (
        "CREATE TABLE alien(value TEXT NOT NULL)"
        if foreign
        else "UPDATE maintenance_ticket_meta SET last_wall_time_ms=last_wall_time_ms "
        "WHERE singleton=1"
    )
    created = _run_isolated_python(
        f"""
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=PERSIST').fetchone()[0].lower() == 'persist'
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
    if pinned_journal is not None:
        journal_path.write_bytes(pinned_journal)


def _create_abandoned_hot_persist_journal(path: Path) -> None:
    crashed = _run_isolated_python(
        """
import hashlib, os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=PERSIST').fetchone()[0].lower() == 'persist'
connection.execute('PRAGMA synchronous=FULL')
connection.execute('PRAGMA cache_size=1')
connection.execute('BEGIN IMMEDIATE')
for index in range(256):
    digest = hashlib.sha256(f'ticket-{index}'.encode()).hexdigest()
    connection.execute(
        "INSERT INTO maintenance_tickets VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (digest, '1'*64, '2'*64, 1, 1, '3'*64, '4'*64,
         'prepared', 1, 2, None, None),
    )
os._exit(0)
""",
        path,
    )
    assert crashed.returncode == 0, (crashed.stdout, crashed.stderr)
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8] != b"\x00" * 8


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


def _tamper_table_tbl_name(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone() == (
            "persist",
        )
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name='maintenance_ticket_meta' "
            "WHERE type='table' AND name='maintenance_tickets'"
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")


class _Clock:
    def __init__(self, value: float = 2_000_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _Random:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, size: int) -> bytes:
        self.counter += 1
        return self.counter.to_bytes(size, "big")


def _dependencies(
    clock: _Clock,
    *,
    random_bytes=None,
    assert_acl=None,
    harden_acl=None,
) -> MaintenanceTicketStoreDependencies:
    return MaintenanceTicketStoreDependencies(
        wall_clock=clock,
        random_bytes=random_bytes or _Random(),
        assert_acl=assert_acl or (lambda _path, _directory: None),
        harden_acl=harden_acl or (lambda _path, _directory: None),
        trusted_boundary=lambda path: path.parent,
    )


def _bindings() -> dict[str, object]:
    return {
        "requester_sid_digest": _digest("S-1-5-21-1000"),
        "installation_id": _digest("installation"),
        "epoch": 7,
        "root_revision": 19,
        "operation_digest": _digest("capture-v1"),
    }


def _bindings_named(label: str) -> dict[str, object]:
    bindings = _bindings()
    bindings["operation_digest"] = _digest(f"capture:{label}")
    return bindings


def test_ticket_is_claimed_exactly_once_with_exact_bindings(tmp_path: Path) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )

    ticket = store.issue(ttl_seconds=600, **_bindings())

    assert store.claim(ticket.secret, **_bindings()) is True
    assert store.claim(ticket.secret, **_bindings()) is False
    assert store.state(ticket.secret) == "claimed"


def test_claimed_operation_discovery_is_bounded_ordered_and_read_only(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    path = tmp_path / "maintenance-tickets.db"
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    bindings = sorted(
        (_bindings_named("c"), _bindings_named("a"), _bindings_named("b")),
        key=lambda item: str(item["operation_digest"]),
    )
    for item in bindings:
        ticket = store.issue(ttl_seconds=600, **item)
        assert store.claim(ticket.secret, **item) is True

    before = _database_family(path)
    first = store.discover_claimed_operations(limit=2)
    second = store.discover_claimed_operations(
        after_operation_digest=first.next_cursor,
        limit=2,
    )
    after = _database_family(path)

    expected = [str(item["operation_digest"]) for item in bindings]
    assert [item.operation_digest for item in first.items] == expected[:2]
    assert first.ambiguous_operation_digests == ()
    assert first.next_cursor == expected[1]
    assert [item.operation_digest for item in second.items] == expected[2:]
    assert second.next_cursor is None
    assert before == after


def test_claimed_operation_discovery_fails_closed_per_ambiguous_digest(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    unique = _bindings_named("unique")
    ambiguous = _bindings_named("ambiguous")
    for item in (unique, ambiguous, ambiguous):
        ticket = store.issue(ttl_seconds=600, **item)
        assert store.claim(ticket.secret, **item) is True

    page = store.discover_claimed_operations(limit=8)

    assert [item.operation_digest for item in page.items] == [
        str(unique["operation_digest"])
    ]
    assert page.ambiguous_operation_digests == (
        str(ambiguous["operation_digest"]),
    )


def test_claimed_operation_discovery_excludes_prepared_and_terminal_tickets(
    tmp_path: Path,
) -> None:
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )
    prepared = _bindings_named("prepared")
    terminal = _bindings_named("terminal")
    active = _bindings_named("active")
    store.issue(ttl_seconds=600, **prepared)
    terminal_ticket = store.issue(ttl_seconds=600, **terminal)
    active_ticket = store.issue(ttl_seconds=600, **active)
    assert store.claim(terminal_ticket.secret, **terminal) is True
    assert store.finish(terminal_ticket.secret, success=True) is True
    assert store.claim(active_ticket.secret, **active) is True

    page = store.discover_claimed_operations(limit=8)

    assert [item.operation_digest for item in page.items] == [
        str(active["operation_digest"])
    ]
    assert page.ambiguous_operation_digests == ()


def test_claimed_operation_discovery_reads_complete_wal_without_writing_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "maintenance-tickets.db"
    bindings = _bindings_named("wal")
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )
    ticket = store.issue(ttl_seconds=600, **bindings)
    assert store.claim(ticket.secret, **bindings) is True
    _create_abandoned_ticket_wal(path, foreign=False)
    before = _database_family(path)

    page = store.discover_claimed_operations(limit=8)
    after = _database_family(path)

    assert [item.operation_digest for item in page.items] == [
        str(bindings["operation_digest"])
    ]
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-journal"] == before["-journal"]


def test_claimed_operation_discovery_rejects_unbounded_or_malformed_requests(
    tmp_path: Path,
) -> None:
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )

    with pytest.raises(
        MaintenanceTicketValidationError,
        match="maintenance ticket request is invalid",
    ):
        store.discover_claimed_operations(limit=0)
    with pytest.raises(
        MaintenanceTicketValidationError,
        match="maintenance ticket request is invalid",
    ):
        store.discover_claimed_operations(limit=257)
    with pytest.raises(
        MaintenanceTicketValidationError,
        match="maintenance ticket request is invalid",
    ):
        store.discover_claimed_operations(
            after_operation_digest="not-a-digest",
            limit=1,
        )


def test_claimed_operation_discovery_rejects_schema_valid_row_capacity_tamper(
    tmp_path: Path,
) -> None:
    path = tmp_path / "maintenance-tickets.db"
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone() == (
            "persist",
        )
        boot_digest = str(
            connection.execute(
                "SELECT active_boot_digest FROM maintenance_ticket_meta WHERE singleton=1"
            ).fetchone()[0]
        )
        connection.executemany(
            "INSERT INTO maintenance_tickets VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    _digest(f"ticket:{index}"),
                    _digest(f"sid:{index}"),
                    _digest("installation"),
                    1,
                    1,
                    _digest(f"operation:{index}"),
                    boot_digest,
                    "claimed",
                    1,
                    2,
                    1,
                    None,
                )
                for index in range(257)
            ],
        )
        connection.commit()
    before = _database_family(path)

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="maintenance ticket store is unavailable",
    ):
        store.discover_claimed_operations(limit=8)

    assert _database_family(path) == before


def test_unclaimed_ticket_survives_reopen_with_same_service_boot(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    writer = MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    ticket = writer.issue(ttl_seconds=600, **_bindings())

    reopened = MaintenanceTicketStore.open(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    assert reopened.claim(ticket.secret, **_bindings()) is True


def test_new_service_boot_invalidates_unclaimed_tickets(tmp_path: Path) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    first = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=dependencies,
    )
    old_ticket = first.issue(ttl_seconds=600, **_bindings())

    restarted = MaintenanceTicketStore.open(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-b')}",
        dependencies=dependencies,
    )

    assert restarted.state(old_ticket.secret) is None
    assert restarted.claim(old_ticket.secret, **_bindings()) is False
    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        first.issue(ttl_seconds=600, **_bindings())


def test_successfully_finished_ticket_is_consumed_and_never_reusable(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())
    assert store.claim(ticket.secret, **_bindings()) is True

    assert store.finish(ticket.secret, success=True) is True

    assert store.state(ticket.secret) == "consumed"
    assert store.finish(ticket.secret, success=True) is False
    assert store.claim(ticket.secret, **_bindings()) is False


def test_wall_clock_rollback_is_durably_fail_closed(tmp_path: Path) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())
    clock.value -= 1

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        store.state(ticket.secret)

    clock.value += 2
    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        store.state(ticket.secret)


def test_ttl_is_capped_at_ten_minutes_and_expires_at_the_boundary(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    with pytest.raises(
        MaintenanceTicketValidationError,
        match="^maintenance ticket request is invalid$",
    ):
        store.issue(ttl_seconds=601, **_bindings())

    ticket = store.issue(ttl_seconds=600, **_bindings())
    assert ticket.expires_at_ms == 2_000_000_600_000
    clock.value += 600

    assert store.claim(ticket.secret, **_bindings()) is False
    assert store.state(ticket.secret) == "expired"


def test_failed_claim_is_terminal_and_never_reusable(tmp_path: Path) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())
    assert store.claim(ticket.secret, **_bindings()) is True

    assert store.finish(ticket.secret, success=False) is True

    assert store.state(ticket.secret) == "failed"
    assert store.finish(ticket.secret, success=False) is False
    assert store.claim(ticket.secret, **_bindings()) is False


def test_concurrent_claim_has_exactly_one_winner(tmp_path: Path) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())
    barrier = threading.Barrier(8)

    def claim() -> bool:
        barrier.wait()
        return store.claim(ticket.secret, **_bindings())

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _index: claim(), range(8)))

    assert sorted(results) == [False] * 7 + [True]


@pytest.mark.parametrize(
    ("field", "different"),
    (
        ("requester_sid_digest", _digest("S-1-5-21-2000")),
        ("installation_id", _digest("other-installation")),
        ("epoch", 8),
        ("root_revision", 20),
        ("operation_digest", _digest("other-operation")),
    ),
)
def test_claim_requires_every_exact_binding(
    tmp_path: Path,
    field: str,
    different: object,
) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())
    mismatched = _bindings()
    mismatched[field] = different

    assert store.claim(ticket.secret, **mismatched) is False
    assert store.claim(ticket.secret, **_bindings()) is True


def test_database_has_exact_identity_and_closed_schema(tmp_path: Path) -> None:
    path = tmp_path / "maintenance-tickets.db"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            0x4E434D54,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT type,name FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        } == {
            ("table", "maintenance_ticket_meta"),
            ("table", "maintenance_tickets"),
        }
        assert [
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(maintenance_ticket_meta)"
            ).fetchall()
        ] == [
            "singleton",
            "schema_version",
            "active_boot_digest",
            "last_wall_time_ms",
            "clock_state",
        ]
        assert [
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(maintenance_tickets)"
            ).fetchall()
        ] == [
            "ticket_digest",
            "requester_sid_digest",
            "installation_id",
            "epoch",
            "root_revision",
            "operation_digest",
            "service_boot_digest",
            "state",
            "issued_at_ms",
            "expires_at_ms",
            "claimed_at_ms",
            "finished_at_ms",
        ]


def test_schema_tamper_is_rejected_before_later_mutation_without_read_write_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "maintenance-tickets.db"
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(_Clock()),
    )
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE attacker_payload(secret TEXT)")
    real_connect = sqlite3.connect
    read_write_attempts: list[str] = []

    def guarded_connect(
        database: object, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        target = (
            os.fspath(database)
            if isinstance(database, (str, os.PathLike))
            else str(database)
        )
        if not (kwargs.get("uri") is True and "mode=ro" in target):
            read_write_attempts.append(target)
            raise AssertionError("drifted schema reached a read-write SQLite open")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(maintenance_ticket_store.sqlite3, "connect", guarded_connect)

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        store.issue(ttl_seconds=600, **_bindings())
    assert read_write_attempts == []


def test_open_rejects_quoted_schema_literal_case_collision_without_read_write_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    with sqlite3.connect(path) as connection:
        assert str(
            connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0]
        ).casefold() == "persist"
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='maintenance_ticket_meta'",
            ("'rollback'", "'ROLLBACK'"),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()
    assert Path(f"{path}-journal").is_file()
    real_connect = sqlite3.connect
    read_write_attempts: list[str] = []

    def guarded_connect(
        database: object, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        target = (
            os.fspath(database)
            if isinstance(database, (str, os.PathLike))
            else str(database)
        )
        if not (kwargs.get("uri") is True and "mode=ro" in target):
            read_write_attempts.append(target)
            raise AssertionError("foreign schema reached a read-write SQLite open")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(maintenance_ticket_store.sqlite3, "connect", guarded_connect)

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )
    assert read_write_attempts == []


def test_open_rejects_foreign_schema_only_in_abandoned_wal_without_recovery(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _create_abandoned_ticket_wal(path, foreign=True)
    before = _database_family(path)

    with pytest.raises(MaintenanceTicketUnavailable):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )

    after = _database_family(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-journal"] == before["-journal"]
    assert after["-shm"] is not None


def test_open_recovers_exact_current_wal_and_restores_pinned_journal(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _create_abandoned_ticket_wal(path, foreign=False)

    reopened = MaintenanceTicketStore.open(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    issued = reopened.issue(ttl_seconds=600, **_bindings())
    assert reopened.state(issued.secret) == "prepared"
    assert Path(f"{path}-journal").is_file()
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()


def test_open_recovers_supported_hot_persist_journal_without_losing_contract(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-hot-journal.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _create_abandoned_hot_persist_journal(path)

    reopened = MaintenanceTicketStore.open(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    issued = reopened.issue(ttl_seconds=600, **_bindings())
    assert reopened.state(issued.secret) == "prepared"
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM maintenance_tickets"
        ).fetchone() == (1,)
    assert Path(f"{path}-journal").is_file()


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_open_rejects_incomplete_wal_pair_without_mutating_pinned_journal(
    tmp_path: Path, missing_suffix: str
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _create_abandoned_ticket_wal(path, foreign=True)
    Path(f"{path}{missing_suffix}").unlink()
    before = _database_family(path)

    with pytest.raises(MaintenanceTicketUnavailable):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )

    assert _database_family(path) == before


def test_provision_rejects_orphan_wal_family_without_creating_main(
    tmp_path: Path,
) -> None:
    path = tmp_path / "maintenance-tickets.db"
    _create_abandoned_ticket_wal(path, foreign=True)
    path.unlink()
    before = _database_family(path)

    with pytest.raises(MaintenanceTicketUnavailable):
        MaintenanceTicketStore.provision(
            path,
            service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
            dependencies=_dependencies(_Clock()),
        )

    assert _database_family(path) == before


def test_missing_pinned_journal_is_rejected(tmp_path: Path) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    journal.unlink()

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )


@pytest.mark.parametrize(
    "statement",
    (
        "PRAGMA application_id=7",
        "PRAGMA user_version=7",
        "CREATE VIEW attacker_view AS SELECT * FROM maintenance_tickets",
    ),
)
def test_open_rejects_database_identity_or_schema_tamper(
    tmp_path: Path,
    statement: str,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(statement)

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )


def test_open_rejects_reserved_prefix_schema_object_without_mutation(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _inject_reserved_prefix_view(path)
    before = path.read_bytes()

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )
    assert path.read_bytes() == before


def test_open_rejects_table_tbl_name_drift_without_mutation(tmp_path: Path) -> None:
    clock = _Clock()
    dependencies = _dependencies(clock)
    path = tmp_path / "maintenance-tickets-metadata.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )
    _tamper_table_tbl_name(path)
    before = path.read_bytes()

    with pytest.raises(MaintenanceTicketUnavailable):
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=dependencies,
        )
    assert path.read_bytes() == before


def test_acl_hardening_is_provision_only_and_runtime_is_assert_only(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    hardened: list[tuple[Path, bool]] = []
    asserted: list[tuple[Path, bool]] = []
    dependencies = _dependencies(
        clock,
        harden_acl=lambda path, directory: hardened.append(
            (Path(path), directory)
        ),
        assert_acl=lambda path, directory: asserted.append(
            (Path(path), directory)
        ),
    )
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"

    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    assert (tmp_path, True) in hardened
    assert (path, False) in hardened
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    assert (journal, False) in hardened
    hardened.clear()
    asserted.clear()

    MaintenanceTicketStore.open(
        path,
        service_boot_id=boot_id,
        dependencies=dependencies,
    )

    assert hardened == []
    assert (tmp_path, True) in asserted
    assert (path, False) in asserted
    assert (journal, False) in asserted
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            assert (sidecar, False) in asserted


def test_acl_and_storage_failures_have_one_content_free_error(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    path = tmp_path / "sensitive-customer-name.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=_dependencies(clock),
    )
    hardened: list[Path] = []

    def reject_acl(candidate: Path, _directory: bool) -> None:
        raise PermissionError(f"broad ACL at {candidate}: synthetic-secret")

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ) as failure:
        MaintenanceTicketStore.open(
            path,
            service_boot_id=boot_id,
            dependencies=_dependencies(
                clock,
                assert_acl=reject_acl,
                harden_acl=lambda candidate, _directory: hardened.append(
                    Path(candidate)
                ),
            ),
        )

    assert "sensitive-customer-name" not in str(failure.value)
    assert "synthetic-secret" not in str(failure.value)
    assert hardened == []


def test_database_never_stores_raw_sid_boot_id_or_ticket_secret(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    path = tmp_path / "maintenance-tickets.db"
    raw_sid = "S-1-5-21-1000"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=_dependencies(clock),
    )
    ticket = store.issue(ttl_seconds=600, **_bindings())

    persisted = path.read_bytes()
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            persisted += sidecar.read_bytes()

    assert raw_sid.encode("ascii") not in persisted
    assert boot_id.encode("ascii") not in persisted
    assert ticket.secret.encode("ascii") not in persisted
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT ticket_digest,requester_sid_digest,service_boot_digest
            FROM maintenance_tickets
            """
        ).fetchone()
    assert row is not None
    assert row[0] != ticket.secret
    assert row[1] == _digest(raw_sid)
    assert row[2] != boot_id


def test_per_boot_capacity_is_fixed_and_fails_closed(tmp_path: Path) -> None:
    clock = _Clock()
    path = tmp_path / "maintenance-tickets.db"
    boot_id = f"service-boot-v1:{_digest('boot-a')}"
    store = MaintenanceTicketStore.provision(
        path,
        service_boot_id=boot_id,
        dependencies=_dependencies(clock),
    )
    for _index in range(256):
        store.issue(ttl_seconds=600, **_bindings())

    with pytest.raises(
        MaintenanceTicketCapacity,
        match="^maintenance ticket capacity is exhausted$",
    ):
        store.issue(ttl_seconds=600, **_bindings())

    restarted = MaintenanceTicketStore.open(
        path,
        service_boot_id=f"service-boot-v1:{_digest('boot-b')}",
        dependencies=_dependencies(clock),
    )
    assert restarted.issue(ttl_seconds=600, **_bindings()).secret.startswith(
        "maintenance-ticket-v1:"
    )


def test_dependency_exceptions_are_strictly_normalized(tmp_path: Path) -> None:
    clock = _Clock()

    def broken_random(_size: int) -> bytes:
        raise RuntimeError("synthetic-rng-secret")

    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock, random_bytes=broken_random),
    )

    with pytest.raises(
        MaintenanceTicketUnavailable,
        match="^maintenance ticket store is unavailable$",
    ) as failure:
        store.issue(ttl_seconds=600, **_bindings())

    assert "synthetic-rng-secret" not in str(failure.value)


def test_raw_sid_and_malformed_contract_values_are_rejected(tmp_path: Path) -> None:
    clock = _Clock()
    store = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('boot-a')}",
        dependencies=_dependencies(clock),
    )
    raw_sid_bindings = _bindings()
    raw_sid_bindings["requester_sid_digest"] = "S-1-5-21-1000"

    with pytest.raises(
        MaintenanceTicketValidationError,
        match="^maintenance ticket request is invalid$",
    ):
        store.issue(ttl_seconds=600, **raw_sid_bindings)
    with pytest.raises(
        MaintenanceTicketValidationError,
        match="^maintenance ticket request is invalid$",
    ):
        store.issue(ttl_seconds=0, **_bindings())
    with pytest.raises(
        MaintenanceTicketValidationError,
        match="^maintenance ticket request is invalid$",
    ):
        store.claim("plaintext-secret", **_bindings())
