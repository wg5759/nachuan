"""TaskLedger SQLite authority, migration, and bounded-capacity contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

import pytest

import orchestrator.ledger as ledger_module
from orchestrator.ledger import TaskLedger


_TASK_LEDGER_APPLICATION_ID = 0x4E43544C  # "NCTL"
_TASK_LEDGER_SCHEMA_VERSION = 3

_AA0025A_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planning',
  user_id TEXT DEFAULT '',
  result TEXT DEFAULT '',
  created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  kind TEXT DEFAULT 'action',
  deps TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',
  output TEXT DEFAULT '',
  error TEXT DEFAULT '',
  attempts INTEGER DEFAULT 0,
  updated REAL
);
CREATE INDEX IF NOT EXISTS ix_steps_job ON steps(job_id, idx);
"""

# Literal complete DDL present in each of these three committed generations:
# 1cbc955, 72ea2a3, and 2821cc4.  This fixture intentionally does not import
# the current module's schema constants.
_LEASE_GENERATION_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planning',
  user_id TEXT DEFAULT '',
  result TEXT DEFAULT '',
  execution_spec TEXT NOT NULL DEFAULT '{}',
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_until REAL NOT NULL DEFAULT 0,
  lease_epoch INTEGER NOT NULL DEFAULT 0,
  created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  kind TEXT DEFAULT 'action',
  deps TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',
  output TEXT DEFAULT '',
  error TEXT DEFAULT '',
  attempts INTEGER DEFAULT 0,
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_until REAL NOT NULL DEFAULT 0,
  claim_token TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL DEFAULT '',
  updated REAL
);
CREATE INDEX IF NOT EXISTS ix_steps_job ON steps(job_id, idx);
"""


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


def _create_abandoned_foreign_hot_wal(path: Path) -> None:
    created = _run_isolated_python(
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
        path,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _create_crashed_committed_v2_to_v3_wal(path: Path) -> None:
    created = _run_isolated_python(
        """
import os, sqlite3, sys
from orchestrator import ledger as ledger_module
from orchestrator.ledger import TaskLedger

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute('BEGIN IMMEDIATE')
for ddl in ledger_module._V2_SCHEMA_DDLS:
    connection.execute(ddl)
connection.execute(
    'INSERT INTO ledger_capacity(singleton,job_rows,step_rows,payload_bytes) '
    'VALUES(1,0,0,0)'
)
connection.execute(
    "INSERT INTO jobs(id,goal,status,user_id,result,execution_spec,lease_owner,"
    "lease_until,lease_epoch,created,updated,result_reservation) "
    "VALUES('job-crash','committed migration','running','','','{}','worker',"
    "4000000000,7,1,2,zeroblob(?))",
    (ledger_module._JOB_RESULT_RESERVATION_BYTES,),
)
connection.execute(
    "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,"
    "attempts,lease_owner,lease_until,claim_token,idempotency_key,updated,terminal_reservation) "
    "VALUES('step-crash','job-crash',0,'resume','','action','[]','running','','',1,"
    "'worker',4000000000,'token-crash','stable-crash',2,zeroblob(?))",
    (ledger_module._STEP_TERMINAL_RESERVATION_BYTES,),
)
connection.execute(f'PRAGMA application_id={ledger_module._APPLICATION_ID}')
connection.execute(f'PRAGMA user_version={ledger_module._PREVIOUS_SCHEMA_VERSION}')
connection.commit()
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert tuple(connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone())[0] == 0
connection.execute('BEGIN IMMEDIATE')
TaskLedger._migrate_current_v2_database(object.__new__(TaskLedger), connection)
connection.commit()
assert connection.execute('PRAGMA user_version').fetchone()[0] == 3
os._exit(0)
""",
        path,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _attempt_task_ledger_open_in_subprocess(path: Path) -> subprocess.CompletedProcess[str]:
    return _run_isolated_python(
        """
import sqlite3, sys
from orchestrator.ledger import TaskLedger
try:
    ledger = TaskLedger(sys.argv[1])
except sqlite3.DatabaseError as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(0)
except BaseException as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(2)
else:
    ledger.close()
    print('unexpectedly-opened')
    raise SystemExit(3)
""",
        path,
    )


def _journal_mode_read_only(path: Path) -> str:
    # SQLite's ordinary read-only open of a WAL database may create -wal/-shm.
    # Header bytes 18/19 are the persistent read/write format and make this
    # rejection probe itself side-effect free.
    header = path.read_bytes()[:20]
    if len(header) < 20 or not header.startswith(b"SQLite format 3\x00"):
        return "unknown"
    return "wal" if header[18:20] == b"\x02\x02" else "rollback"


def _mutate_database(path: Path, action: Callable[[sqlite3.Connection], None]) -> None:
    connection = sqlite3.connect(path)
    try:
        action(connection)
        connection.commit()
    finally:
        connection.close()


def _assert_rejected_without_mutation(path: Path) -> None:
    before_family = _database_family(path)
    before_mode = _journal_mode_read_only(path)
    with pytest.raises(sqlite3.DatabaseError):
        TaskLedger(path)
    assert _database_family(path) == before_family
    assert _journal_mode_read_only(path) == before_mode


def test_unknown_database_is_rejected_without_mutating_files_or_journal_mode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE alien(value TEXT NOT NULL)")
        connection.execute("INSERT INTO alien(value) VALUES ('foreign authority')")
        connection.commit()
    finally:
        connection.close()

    before_family = _database_family(path)
    before_mode = _journal_mode_read_only(path)
    opened: TaskLedger | None = None
    try:
        with pytest.raises(sqlite3.DatabaseError, match="incompatible|partial|mixed"):
            opened = TaskLedger(path)
    finally:
        if opened is not None:
            opened.close()

    assert _database_family(path) == before_family
    assert _journal_mode_read_only(path) == before_mode


def test_foreign_schema_only_in_abandoned_hot_wal_is_rejected_without_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "foreign-hot-wal.db"
    _create_abandoned_foreign_hot_wal(path)
    before = _database_family(path)

    attempted = _attempt_task_ledger_open_in_subprocess(path)

    assert attempted.returncode == 0, (attempted.stdout, attempted.stderr)
    assert "DatabaseError:" in attempted.stdout
    after = _database_family(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-journal"] == before["-journal"]
    assert after["-shm"] is not None


def test_orphan_wal_and_shm_without_main_are_rejected_without_provisioning(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-sidecars.db"
    _create_abandoned_foreign_hot_wal(path)
    path.unlink()
    before = _database_family(path)
    assert before[""] is None
    assert before["-wal"] is not None and before["-shm"] is not None

    attempted = _attempt_task_ledger_open_in_subprocess(path)

    assert attempted.returncode == 0, (attempted.stdout, attempted.stderr)
    assert "DatabaseError:" in attempted.stdout
    assert _database_family(path) == before


def test_orphan_rollback_journal_without_main_is_preserved_as_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-journal.db"
    Path(f"{path}-journal").write_bytes(b"unresolved-rollback-evidence")
    before = _database_family(path)

    with pytest.raises(sqlite3.DatabaseError, match="orphan sidecars"):
        TaskLedger(path)

    assert _database_family(path) == before


def test_legacy_main_with_any_sidecar_is_not_migrated_or_recovered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-with-sidecar.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_AA0025A_DDL)
        connection.commit()
    finally:
        connection.close()
    Path(f"{path}-journal").write_bytes(b"ambiguous-legacy-sidecar")
    before = _database_family(path)

    with pytest.raises(sqlite3.DatabaseError, match="rollback journal"):
        TaskLedger(path)

    assert _database_family(path) == before


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_wal_shm_pair_is_rejected_before_read_write_open(
    tmp_path: Path, missing_suffix: str
) -> None:
    path = tmp_path / f"incomplete-pair-{missing_suffix[1:]}.db"
    _create_abandoned_foreign_hot_wal(path)
    Path(f"{path}{missing_suffix}").unlink()
    before = _database_family(path)

    attempted = _attempt_task_ledger_open_in_subprocess(path)

    assert attempted.returncode == 0, (attempted.stdout, attempted.stderr)
    assert "WAL and SHM sidecars must be present together" in attempted.stdout
    assert _database_family(path) == before


def test_committed_v2_to_v3_wal_migration_survives_crash_and_reopens(
    tmp_path: Path,
) -> None:
    path = tmp_path / "committed-v3-in-wal.db"
    _create_crashed_committed_v2_to_v3_wal(path)
    main_before = path.read_bytes()
    wal_before = Path(f"{path}-wal").read_bytes()

    immutable = sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True, isolation_level=None
    )
    try:
        assert immutable.execute("PRAGMA application_id").fetchone()[0] == (
            _TASK_LEDGER_APPLICATION_ID
        )
        assert immutable.execute("PRAGMA user_version").fetchone()[0] == 2
        assert immutable.execute(
            "SELECT 1 FROM sqlite_master WHERE name='ledger_terminal_headroom'"
        ).fetchone() is None
    finally:
        immutable.close()

    wal_aware = sqlite3.connect(
        f"{path.as_uri()}?mode=ro", uri=True, isolation_level=None
    )
    try:
        assert wal_aware.execute("PRAGMA user_version").fetchone()[0] == 3
        assert wal_aware.execute(
            "SELECT kind,owner_id FROM ledger_terminal_headroom "
            "ORDER BY kind,owner_id"
        ).fetchall() == [("job", "job-crash"), ("step", "step-crash")]
    finally:
        wal_aware.close()
    assert path.read_bytes() == main_before
    assert Path(f"{path}-wal").read_bytes() == wal_before

    reopened = TaskLedger(path)
    try:
        assert reopened.to_dict("job-crash")["steps"][0]["status"] == "running"
        assert int(reopened._db.execute("PRAGMA user_version").fetchone()[0]) == 3
    finally:
        reopened.close()


def test_sidecar_arriving_during_immutable_preflight_blocks_writer_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "preflight-race.db"
    sqlite3.connect(path).close()
    main_before = path.read_bytes()
    journal = Path(f"{path}-journal")
    original_presence = TaskLedger._database_family_presence
    calls = 0

    def racing_presence(self: TaskLedger) -> dict[str, bool]:
        nonlocal calls
        calls += 1
        if self.path == os.path.abspath(path) and calls == 2:
            journal.write_bytes(b"arrived-during-immutable-preflight")
        return original_presence(self)

    monkeypatch.setattr(TaskLedger, "_database_family_presence", racing_presence)
    with pytest.raises(sqlite3.DatabaseError, match="rollback journal|did not stabilize"):
        TaskLedger(path)

    assert path.read_bytes() == main_before
    assert journal.read_bytes() == b"arrived-during-immutable-preflight"


def test_orphan_sidecars_arriving_after_missing_preflight_block_writer_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "missing-race.db"
    wal = Path(f"{path}-wal")
    shm = Path(f"{path}-shm")
    original_preflight = TaskLedger._preflight_database_kind
    injected = False

    def racing_preflight(self: TaskLedger):  # noqa: ANN202
        nonlocal injected
        result = original_preflight(self)
        if self.path == os.path.abspath(path) and result[0] == "missing" and not injected:
            wal.write_bytes(b"arrived-after-missing-preflight")
            shm.write_bytes(b"orphan-shm-evidence")
            injected = True
        return result

    monkeypatch.setattr(TaskLedger, "_preflight_database_kind", racing_preflight)
    with pytest.raises(sqlite3.DatabaseError, match="orphan sidecars"):
        TaskLedger(path)

    assert injected
    assert not path.exists()
    assert wal.read_bytes() == b"arrived-after-missing-preflight"
    assert shm.read_bytes() == b"orphan-shm-evidence"


def test_missing_database_is_provisioned_with_an_explicit_identity(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.close()

    uri = f"file:{path.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            _TASK_LEDGER_APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            _TASK_LEDGER_SCHEMA_VERSION,
        )
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
    finally:
        connection.close()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda db: db.execute("CREATE VIEW extra_view AS SELECT id FROM jobs"),
        lambda db: db.execute("CREATE TABLE nachuan_reserved_shadow(value TEXT)"),
        lambda db: db.execute("DROP INDEX ix_steps_job"),
        lambda db: db.execute("DROP TRIGGER trg_steps_definition_immutable"),
        lambda db: db.execute("DROP TABLE ledger_capacity"),
        lambda db: db.execute("PRAGMA user_version=99"),
    ],
    ids=[
        "extra-view",
        "reserved-prefix-object",
        "missing-index",
        "missing-trigger",
        "partial-schema",
        "wrong-version",
    ],
)
def test_current_database_drift_is_rejected_without_repair(
    tmp_path: Path, mutation: Callable[[sqlite3.Connection], None]
) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.close()
    _mutate_database(path, mutation)
    _assert_rejected_without_mutation(path)


@pytest.mark.parametrize(
    ("object_type", "object_name", "old", "new"),
    [
        (
            "table",
            "jobs",
            "typeof(id)='text'",
            "typeof(id)='TEXT'",
        ),
        (
            "trigger",
            "trg_jobs_capacity_before_insert",
            "job_rows FROM ledger_capacity",
            "job_rowsFROM ledger_capacity",
        ),
    ],
    ids=["quoted-literal-case", "token-boundary-collision"],
)
def test_exact_sql_rejects_quoted_literal_and_token_boundary_collisions(
    tmp_path: Path,
    object_type: str,
    object_name: str,
    old: str,
    new: str,
) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    ledger.close()

    def mutate(connection: sqlite3.Connection) -> None:
        original = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type=? AND name=?",
            (object_type, object_name),
        ).fetchone()[0]
        assert old in original
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET sql=? WHERE type=? AND name=?",
            (original.replace(old, new, 1), object_type, object_name),
        )
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.execute("PRAGMA writable_schema=OFF")

    _mutate_database(path, mutate)
    _assert_rejected_without_mutation(path)


def test_committed_aa0025a_generation_migrates_atomically_and_preserves_semantics(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_AA0025A_DDL)
        connection.execute(
            "INSERT INTO jobs(id,goal,status,user_id,result,created,updated) "
            "VALUES('legacy-job','year-long goal','failed','owner','partial',10,20)"
        )
        connection.execute(
            "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,attempts,updated) "
            "VALUES('legacy-step','legacy-job',0,'first','details','action','[]','done','kept output','',1,20)"
        )
        connection.commit()
    finally:
        connection.close()

    ledger = TaskLedger(path)
    try:
        assert ledger.get_execution_spec("legacy-job") is None
        migrated = ledger.to_dict("legacy-job")
        assert migrated["goal"] == "year-long goal"
        assert migrated["status"] == "failed"
        assert migrated["result"] == "partial"
        assert migrated["steps"][0]["output"] == "kept output"
        assert migrated["steps"][0]["idempotency_key"] == "legacy-job:legacy-step"
    finally:
        ledger.close()

    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            _TASK_LEDGER_APPLICATION_ID,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (
            _TASK_LEDGER_SCHEMA_VERSION,
        )
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM steps").fetchone() == (1,)
        assert not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE '%legacy%'"
        ).fetchone()
    finally:
        connection.close()


@pytest.mark.parametrize("commit", ["1cbc955", "72ea2a3", "2821cc4"])
def test_committed_lease_generations_preserve_execution_and_fencing_fields(
    tmp_path: Path, commit: str
) -> None:
    path = tmp_path / f"ledger-{commit}.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_LEASE_GENERATION_DDL)
        connection.execute(
            "INSERT INTO jobs(id,goal,status,user_id,result,execution_spec,lease_owner,"
            "lease_until,lease_epoch,created,updated) "
            "VALUES('job-v1','durable goal','running','user','', '{}','worker-a',4000000000,7,10,20)"
        )
        connection.execute(
            "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,"
            "attempts,lease_owner,lease_until,claim_token,idempotency_key,updated) "
            "VALUES('step-v1','job-v1',0,'first','detail','action','[]','running','','',2,"
            "'worker-a',4000000000,'claim-v1','stable-key',20)"
        )
        connection.commit()
    finally:
        connection.close()

    ledger = TaskLedger(path)
    ledger.close()

    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        job = connection.execute(
            "SELECT goal,status,user_id,result,execution_spec,lease_owner,lease_until,lease_epoch,created,updated "
            "FROM jobs WHERE id='job-v1'"
        ).fetchone()
        assert job == (
            "durable goal",
            "running",
            "user",
            "",
            "{}",
            "worker-a",
            4_000_000_000.0,
            7,
            10.0,
            20.0,
        )
        step = connection.execute(
            "SELECT status,attempts,lease_owner,lease_until,claim_token,idempotency_key "
            "FROM steps WHERE id='step-v1'"
        ).fetchone()
        assert step == (
            "running",
            2,
            "worker-a",
            4_000_000_000.0,
            "claim-v1",
            "stable-key",
        )
    finally:
        connection.close()


def test_v2_same_row_reservations_migrate_to_independent_restart_safe_headroom(
    tmp_path: Path,
) -> None:
    from orchestrator import ledger as ledger_module

    path = tmp_path / "ledger-v2.db"
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        for ddl in ledger_module._V2_SCHEMA_DDLS:
            connection.execute(ddl)
        connection.execute(
            "INSERT INTO ledger_capacity(singleton,job_rows,step_rows,payload_bytes) "
            "VALUES(1,0,0,0)"
        )
        connection.execute(
            "INSERT INTO jobs(id,goal,status,user_id,result,execution_spec,lease_owner,"
            "lease_until,lease_epoch,created,updated,result_reservation) "
            "VALUES('job-v2','resume safely','running','','','{}','worker',4000000000,7,1,2,zeroblob(?))",
            (ledger_module._JOB_RESULT_RESERVATION_BYTES,),
        )
        connection.execute(
            "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,"
            "attempts,lease_owner,lease_until,claim_token,idempotency_key,updated,terminal_reservation) "
            "VALUES('step-v2','job-v2',0,'step','','action','[]','running','','',1,"
            "'worker',4000000000,'token-v2','stable-v2',2,zeroblob(?))",
            (ledger_module._STEP_TERMINAL_RESERVATION_BYTES,),
        )
        connection.execute(f"PRAGMA application_id={_TASK_LEDGER_APPLICATION_ID}")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    finally:
        connection.close()

    migrated = TaskLedger(path)
    migrated.close()
    reopened = TaskLedger(path)
    try:
        assert int(reopened._db.execute("PRAGMA user_version").fetchone()[0]) == 3
        headroom_rows = reopened._db.execute(
            "SELECT kind,owner_id FROM ledger_terminal_headroom ORDER BY kind,owner_id"
        ).fetchall()
        assert [tuple(row) for row in headroom_rows] == [
            ("job", "job-v2"),
            ("step", "step-v2"),
        ]
        assert int(reopened._db.execute(
            "SELECT length(result_reservation) FROM jobs WHERE id='job-v2'"
        ).fetchone()[0]) == 0
        assert int(reopened._db.execute(
            "SELECT length(terminal_reservation) FROM steps WHERE id='step-v2'"
        ).fetchone()[0]) == 0
        assert reopened.to_dict("job-v2")["steps"][0]["status"] == "running"
    finally:
        reopened.close()


def test_partial_committed_generation_is_rejected_without_self_healing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_LEASE_GENERATION_DDL)
        connection.execute("DROP INDEX ix_steps_job")
        connection.commit()
    finally:
        connection.close()
    _assert_rejected_without_mutation(path)


def test_legacy_migration_failure_rolls_back_all_schema_changes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_AA0025A_DDL)
        connection.execute(
            "INSERT INTO jobs(id,goal,status,user_id,result,created,updated) "
            "VALUES('oversized',?,'running','','',1,1)",
            ("x" * 128_001,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError):
        TaskLedger(path)

    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        assert connection.execute("PRAGMA application_id").fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        job_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
        ]
        assert job_columns == [
            "id",
            "goal",
            "status",
            "user_id",
            "result",
            "created",
            "updated",
        ]
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper",
    [
        lambda db: db.execute("CREATE VIEW runtime_rogue AS SELECT id FROM jobs"),
        lambda db: db.execute(
            "UPDATE ledger_capacity SET payload_bytes=payload_bytes+1 WHERE singleton=1"
        ),
    ],
    ids=["rogue-object", "counter-drift"],
)
def test_external_authority_drift_blocks_the_next_write_before_requested_mutation(
    tmp_path: Path, tamper: Callable[[sqlite3.Connection], None]
) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    try:
        _mutate_database(path, tamper)
        with pytest.raises(sqlite3.DatabaseError):
            ledger.create_job("must not be inserted", [{"title": "step"}])
        probe = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            assert probe.execute("SELECT COUNT(*) FROM jobs").fetchone() == (0,)
        finally:
            probe.close()
    finally:
        ledger.close()


def test_reader_rejects_post_open_schema_drift(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    try:
        job_id = ledger.create_job("read authority", [{"title": "step"}])
        _mutate_database(
            path, lambda db: db.execute("CREATE VIEW reader_rogue AS SELECT id FROM jobs")
        )
        with pytest.raises(sqlite3.DatabaseError):
            ledger.to_dict(job_id)
    finally:
        ledger.close()


def test_existing_database_file_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    sqlite3.connect(target).close()
    link = tmp_path / "ledger.db"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    with pytest.raises(OSError, match="regular non-reparse"):
        TaskLedger(link)


def test_existing_parent_directory_link_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        os.symlink(real_parent, linked_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory-link creation is unavailable: {exc}")
    with pytest.raises(OSError, match="real directories"):
        TaskLedger(linked_parent / "ledger.db")


def test_post_preflight_pathname_swap_to_an_exact_database_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ledger.db"
    replacement = tmp_path / "replacement.db"
    original_ledger = TaskLedger(path)
    original_ledger.close()
    replacement_ledger = TaskLedger(replacement)
    replacement_ledger.close()
    original_preflight = TaskLedger._preflight_database_kind
    swapped = False

    def swapping_preflight(self: TaskLedger):  # noqa: ANN202
        nonlocal swapped
        result = original_preflight(self)
        if self.path == os.path.abspath(path) and not swapped:
            os.replace(replacement, path)
            swapped = True
        return result

    monkeypatch.setattr(TaskLedger, "_preflight_database_kind", swapping_preflight)

    with pytest.raises(sqlite3.DatabaseError, match="between preflight"):
        TaskLedger(path)
    assert swapped


def test_claims_physically_reserve_terminal_capacity_before_execution(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    try:
        job_id = ledger.create_job("reserved completion", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        job_headroom = ledger._db.execute(
            "SELECT reserved_pages,length(payload) FROM ledger_terminal_headroom "
            "WHERE kind='job' AND owner_id=?",
            (job_id,),
        ).fetchone()
        assert job_headroom is not None
        assert int(job_headroom[0]) > 0 and int(job_headroom[1]) > 0
        assert ledger._db.execute(
            "SELECT length(result_reservation) FROM jobs WHERE id=?", (job_id,)
        ).fetchone()[0] == 0

        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None
        step_headroom = ledger._db.execute(
            "SELECT reserved_pages,length(payload) FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (step["id"],),
        ).fetchone()
        assert step_headroom is not None
        assert int(step_headroom[0]) > 0 and int(step_headroom[1]) > 0

        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="durable output",
        )
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (step["id"],),
        ).fetchone() is None
        assert ledger.set_claimed_job(
            job_id, "worker", epoch, "done", result="durable result"
        )
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='job' AND owner_id=?",
            (job_id,),
        ).fetchone() is None
    finally:
        ledger.close()


def test_unclaimed_failure_uses_precommitted_physical_headroom_when_main_is_full(
    tmp_path: Path,
) -> None:
    """A pre-worker failure must still reach a durable terminal row at page cap."""
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("fail before worker", [{"title": "step"}])
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        assert int(
            ledger._db.execute(f"PRAGMA max_page_count={page_count}").fetchone()[0]
        ) == page_count

        assert ledger.fail_unclaimed_job(job_id, result="x" * (192 * 1024))
        terminal = ledger.to_dict(job_id)
        assert terminal["status"] == "failed"
        assert terminal["result"] == "x" * (192 * 1024)
    finally:
        ledger.close()


@pytest.mark.parametrize("page_size", [512, 4_096, 65_536])
def test_terminal_headroom_is_page_accurate_across_supported_sqlite_page_sizes(
    tmp_path: Path, page_size: int
) -> None:
    path = tmp_path / f"ledger-{page_size}.db"
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute(f"PRAGMA page_size={page_size}")
        connection.execute("VACUUM")
        assert int(connection.execute("PRAGMA page_size").fetchone()[0]) == page_size
    finally:
        connection.close()

    ledger = TaskLedger(path)
    try:
        job_id = ledger.create_job("page-size terminal", [{"title": "step"}])
        before_pages = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        ledger._db.execute(f"PRAGMA max_page_count={before_pages}")
        assert ledger.fail_unclaimed_job(job_id, result="p" * (192 * 1024))
        assert int(ledger._db.execute("PRAGMA page_count").fetchone()[0]) <= before_pages
    finally:
        ledger.close()


def test_claimed_job_completion_consumes_owned_pages_when_main_is_full(
    tmp_path: Path,
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("claimed terminal", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None
        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="done",
        )
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        assert int(
            ledger._db.execute(f"PRAGMA max_page_count={page_count}").fetchone()[0]
        ) == page_count

        assert ledger.set_claimed_job(
            job_id,
            "worker",
            epoch,
            "done",
            result="y" * (192 * 1024),
        )
        terminal = ledger.to_dict(job_id)
        assert terminal["status"] == "done"
        assert terminal["result"] == "y" * (192 * 1024)
    finally:
        ledger.close()


def test_claimed_job_headroom_covers_the_complete_maximum_terminal_record(
    tmp_path: Path,
) -> None:
    from orchestrator.ledger import freeze_execution_spec

    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        execution_spec = freeze_execution_spec(
            goal="g" * 32_000,
            steps=[{"title": "step", "detail": "d" * 2_000}],
            workdir="C:\\" + "w" * 210_000,
            backend="auto",
            mode="plan",
        )
        job_id = ledger.create_job(
            "g" * 32_000,
            [{"title": "step", "detail": "d" * 2_000}],
            execution_spec=execution_spec,
        )
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None
        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="done",
        )
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        ledger._db.execute(f"PRAGMA max_page_count={page_count}")

        assert ledger.set_claimed_job(
            job_id,
            "worker",
            epoch,
            "done",
            result="z" * (192 * 1024),
        )
        assert ledger.to_dict(job_id)["status"] == "done"
    finally:
        ledger.close()


def test_claimed_step_completion_consumes_owned_pages_when_main_is_full(
    tmp_path: Path,
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("step terminal", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        assert int(
            ledger._db.execute(f"PRAGMA max_page_count={page_count}").fetchone()[0]
        ) == page_count

        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="o" * 32_000,
            error="e" * 8_000,
        )
        terminal_step = ledger.to_dict(job_id)["steps"][0]
        assert terminal_step["status"] == "done"
        assert terminal_step["output"] == "o" * 32_000
        assert terminal_step["error"] == "e" * 8_000
    finally:
        ledger.close()


def test_restart_preserves_claimed_headroom_and_terminal_writes_need_no_growth(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    first = TaskLedger(path)
    job_id = first.create_job("restart terminal", [{"title": "step"}])
    epoch = first.claim_job(job_id, "worker", lease_seconds=600)
    assert epoch == 1
    step = first.claim_next_step(job_id, "worker", epoch, lease_seconds=600)
    assert step is not None
    first.close()

    resumed = TaskLedger(path)
    try:
        assert int(
            resumed._db.execute(
                "SELECT COUNT(*) FROM ledger_terminal_headroom"
            ).fetchone()[0]
        ) == 2
        page_count = int(resumed._db.execute("PRAGMA page_count").fetchone()[0])
        assert int(
            resumed._db.execute(f"PRAGMA max_page_count={page_count}").fetchone()[0]
        ) == page_count
        assert resumed.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="r" * 32_000,
            error="e" * 8_000,
        )
        assert resumed.set_claimed_job(
            job_id,
            "worker",
            epoch,
            "done",
            result="j" * (192 * 1024),
        )
    finally:
        resumed.close()

    verified = TaskLedger(path)
    try:
        terminal = verified.to_dict(job_id)
        assert terminal["status"] == "done"
        assert terminal["steps"][0]["status"] == "done"
        assert int(
            verified._db.execute(
                "SELECT COUNT(*) FROM ledger_terminal_headroom"
            ).fetchone()[0]
        ) == 0
    finally:
        verified.close()


def test_failed_step_atomically_consumes_step_and_job_headroom_at_page_cap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    ledger = TaskLedger(path)
    try:
        job_id = ledger.create_job("failed terminal", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        ledger._db.execute(f"PRAGMA max_page_count={page_count}")

        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "failed",
            owner="worker",
            epoch=epoch,
            output="o" * 32_000,
            error="e" * 8_000,
        )
        terminal = ledger.to_dict(job_id)
        assert terminal["status"] == "failed"
        assert terminal["steps"][0]["status"] == "failed"
        assert int(
            ledger._db.execute(
                "SELECT COUNT(*) FROM ledger_terminal_headroom"
            ).fetchone()[0]
        ) == 0
    finally:
        ledger.close()

    reopened = TaskLedger(path)
    try:
        assert reopened.to_dict(job_id)["status"] == "failed"
    finally:
        reopened.close()


def test_concurrent_terminal_writers_have_one_headroom_consumer(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    first = TaskLedger(path)
    second = TaskLedger(path)
    barrier = threading.Barrier(2)
    try:
        job_id = first.create_job("one terminal writer", [{"title": "step"}])
        epoch = first.claim_job(job_id, "worker", lease_seconds=600)
        assert epoch == 1
        step = first.claim_next_step(job_id, "worker", epoch, lease_seconds=600)
        assert step is not None

        def finish(ledger: TaskLedger, output: str) -> bool:
            barrier.wait(timeout=5)
            return ledger.finish_claimed_step(
                step["id"],
                step["claim_token"],
                "done",
                owner="worker",
                epoch=epoch,
                output=output,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda item: finish(*item),
                    ((first, "first"), (second, "second")),
                )
            )
        assert sorted(results) == [False, True]
        terminal_step = first.to_dict(job_id)["steps"][0]
        assert terminal_step["output"] in {"first", "second"}
        assert first._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (step["id"],),
        ).fetchone() is None
    finally:
        second.close()
        first.close()


def test_retry_release_and_reclaim_keep_only_current_inflight_headroom(
    tmp_path: Path,
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("retry ownership", [{"title": "step"}])
        epoch1 = ledger.claim_job(job_id, "worker-1", lease_seconds=600)
        assert epoch1 == 1
        first = ledger.claim_next_step(
            job_id, "worker-1", epoch1, lease_seconds=600
        )
        assert first is not None
        assert not ledger.release_job(job_id, "worker-1", epoch1)

        assert ledger.finish_claimed_step(
            first["id"],
            first["claim_token"],
            "pending",
            owner="worker-1",
            epoch=epoch1,
            error="retry",
        )
        assert ledger.release_job(job_id, "worker-1", epoch1)
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='job' AND owner_id=?",
            (job_id,),
        ).fetchone() is not None
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (first["id"],),
        ).fetchone() is None

        epoch2 = ledger.claim_job(job_id, "worker-2", lease_seconds=600)
        assert epoch2 == 2
        second = ledger.claim_next_step(
            job_id, "worker-2", epoch2, lease_seconds=600
        )
        assert second is not None
        assert second["id"] == first["id"]
        assert second["claim_token"] != first["claim_token"]
        assert ledger.finish_claimed_step(
            second["id"],
            second["claim_token"],
            "failed",
            owner="worker-2",
            epoch=epoch2,
            error="terminal",
        )
        assert int(
            ledger._db.execute(
                "SELECT COUNT(*) FROM ledger_terminal_headroom"
            ).fetchone()[0]
        ) == 0
    finally:
        ledger.close()


def test_repeated_reads_skip_full_database_reconciliation_without_external_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("fast polling", [{"title": "step"}])
        full_validations = 0

        def forbidden_full_scan(_connection: sqlite3.Connection) -> None:
            nonlocal full_validations
            full_validations += 1
            raise AssertionError("ordinary read performed a full authority scan")

        monkeypatch.setattr(ledger, "_validate_current_database", forbidden_full_scan)
        for _ in range(8):
            assert ledger.to_dict(job_id)["id"] == job_id
        assert full_validations == 0
    finally:
        ledger.close()


def test_close_is_idempotent_and_waits_for_an_inflight_reader(tmp_path: Path) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    reader = ledger._reader()
    close_started = threading.Event()
    close_finished = threading.Event()

    def close_ledger() -> None:
        close_started.set()
        ledger.close()
        close_finished.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(close_ledger)
        assert close_started.wait(timeout=5)
        assert not close_finished.wait(timeout=0.1)
        reader.close()
        future.result(timeout=5)
    assert close_finished.is_set()
    ledger.close()


def test_pinned_reader_does_not_block_an_independent_writer(tmp_path: Path) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    first_job = ledger.create_job("snapshot before write", [{"title": "step"}])
    reader = ledger._reader()
    writer_finished = threading.Event()

    def create_second_job() -> str:
        job_id = ledger.create_job("write beside snapshot", [{"title": "step"}])
        writer_finished.set()
        return job_id

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(create_second_job)
            # FULL-sync commits may take several seconds under Windows Defender;
            # this is a deadlock watchdog, not a latency SLA.
            completed_while_reader_open = writer_finished.wait(timeout=15)
            reader_rows = reader.execute(
                "SELECT id FROM jobs ORDER BY id"
            ).fetchall()
            reader.close()
            second_job = future.result(timeout=15)

        assert completed_while_reader_open
        assert {row["id"] for row in reader_rows} == {first_job}
        assert ledger.to_dict(second_job)["goal"] == "write beside snapshot"
    finally:
        reader.close()
        ledger.close()


def test_close_waits_for_an_inflight_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    writer_entered = threading.Event()
    allow_writer = threading.Event()
    close_finished = threading.Event()
    original_begin = ledger._begin_authoritative_write

    def blocked_begin() -> None:
        original_begin()
        writer_entered.set()
        assert allow_writer.wait(timeout=5)

    monkeypatch.setattr(ledger, "_begin_authoritative_write", blocked_begin)
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(
            ledger.create_job, "inflight writer", [{"title": "step"}]
        )
        assert writer_entered.wait(timeout=5)
        closer = pool.submit(lambda: (ledger.close(), close_finished.set()))
        assert not close_finished.wait(timeout=0.1)
        allow_writer.set()
        assert writer.result(timeout=5)
        closer.result(timeout=5)
    assert close_finished.is_set()
    ledger.close()


def test_terminal_text_limits_fail_before_consuming_the_reserved_claim(
    tmp_path: Path,
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("bounded terminal", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        assert step is not None

        with pytest.raises(ValueError, match="UTF-8 byte limit"):
            ledger.finish_claimed_step(
                step["id"],
                step["claim_token"],
                "done",
                owner="worker",
                epoch=epoch,
                output="🚀" * 8_001,
            )
        still_claimed = ledger._db.execute(
            "SELECT status FROM steps WHERE id=?",
            (step["id"],),
        ).fetchone()
        assert still_claimed["status"] == "running"
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (step["id"],),
        ).fetchone() is not None

        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "done",
            owner="worker",
            epoch=epoch,
            output="fits",
        )
        with pytest.raises(ValueError, match="UTF-8 byte limit"):
            ledger.set_claimed_job(
                job_id,
                "worker",
                epoch,
                "done",
                result="x" * (192 * 1024 + 1),
            )
        assert ledger.set_claimed_job(
            job_id, "worker", epoch, "done", result="fits"
        )
    finally:
        ledger.close()


def test_terminal_reservation_capacity_rejects_before_job_claim(tmp_path: Path) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("capacity gate", [{"title": "step"}])
        ledger._db.execute(
            "UPDATE ledger_capacity SET payload_bytes=? WHERE singleton=1",
            (192 * 1024 * 1024 - 1,),
        )
        ledger._db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="capacity"):
            ledger.claim_job(job_id, "worker", lease_seconds=60)
        row = ledger._db.execute(
            "SELECT lease_epoch,length(result_reservation) FROM jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        assert tuple(row) == (0, 0)
    finally:
        ledger.close()


def test_step_claim_rolls_back_when_physical_headroom_cannot_materialize(
    tmp_path: Path,
) -> None:
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("claim capacity gate", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker", lease_seconds=60)
        assert epoch == 1
        page_count = int(ledger._db.execute("PRAGMA page_count").fetchone()[0])
        ledger._db.execute(f"PRAGMA max_page_count={page_count}")

        with pytest.raises(sqlite3.OperationalError, match="full"):
            ledger.claim_next_step(job_id, "worker", epoch, lease_seconds=60)
        step = ledger._db.execute(
            "SELECT id,status,attempts,claim_token FROM steps WHERE job_id=?",
            (job_id,),
        ).fetchone()
        assert tuple(step)[1:] == ("pending", 0, "")
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='step' AND owner_id=?",
            (step["id"],),
        ).fetchone() is None
        assert ledger._db.execute(
            "SELECT 1 FROM ledger_terminal_headroom "
            "WHERE kind='job' AND owner_id=?",
            (job_id,),
        ).fetchone() is not None
    finally:
        ledger.close()


def test_nonempty_hot_wal_is_rechecked_on_the_locked_handle(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    first = TaskLedger(path)
    second: TaskLedger | None = None
    try:
        job_id = first.create_job("committed in WAL", [{"title": "step"}])
        assert Path(f"{path}-wal").stat().st_size > 0
        second = TaskLedger(path)
        assert second.to_dict(job_id)["goal"] == "committed in WAL"
    finally:
        if second is not None:
            second.close()
        first.close()


def test_two_concurrent_cold_starts_converge_on_one_provisioned_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.db"
    barrier = threading.Barrier(2)

    def open_ledger() -> TaskLedger:
        barrier.wait(timeout=5)
        return TaskLedger(path)

    with ThreadPoolExecutor(max_workers=2) as pool:
        ledgers = list(pool.map(lambda _index: open_ledger(), range(2)))
    try:
        job_id = ledgers[0].create_job("one authority", [{"title": "step"}])
        assert ledgers[1].to_dict(job_id)["goal"] == "one authority"
    finally:
        for ledger in ledgers:
            ledger.close()


def test_transient_peer_rollback_journal_is_retried_without_consuming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ledger.db"
    sqlite3.connect(path).close()
    journal = Path(f"{path}-journal")
    journal_bytes = b"peer-owned-transient-journal"
    journal.write_bytes(journal_bytes)
    observed: list[bytes] = []

    def finish_peer_transaction(_seconds: float) -> None:
        observed.append(journal.read_bytes())
        journal.unlink()

    monkeypatch.setattr(ledger_module.time, "sleep", finish_peer_transaction)

    ledger = TaskLedger(path)
    try:
        assert observed == [journal_bytes]
        assert not journal.exists()
        version = ledger._db.execute("PRAGMA user_version").fetchone()  # noqa: SLF001
        assert version is not None
        assert int(version[0]) == _TASK_LEDGER_SCHEMA_VERSION
    finally:
        ledger.close()


def _legacy_semantic_digest(connection: sqlite3.Connection) -> tuple[int, int, str]:
    jobs = connection.execute(
        "SELECT id,goal,status,user_id,result,created,updated FROM jobs ORDER BY id"
    ).fetchall()
    steps = connection.execute(
        "SELECT id,job_id,idx,title,detail,kind,deps,status,output,error,attempts,updated "
        "FROM steps ORDER BY job_id,idx,id"
    ).fetchall()
    payload = json.dumps(
        {"jobs": jobs, "steps": steps},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return len(jobs), len(steps), hashlib.sha256(payload).hexdigest()


def test_installed_legacy_fixture_migrates_only_on_a_private_copy(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "data" / "ledger.db"
    if not source.is_file():
        pytest.skip("installed development ledger fixture is absent")
    if any(Path(f"{source}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        pytest.skip("installed fixture has live sidecars and cannot be copied safely")
    source_bytes_before = source.read_bytes()
    source_uri = f"{source.as_uri()}?mode=ro&immutable=1"
    source_connection = sqlite3.connect(source_uri, uri=True)
    try:
        before_semantics = _legacy_semantic_digest(source_connection)
    finally:
        source_connection.close()

    private_copy = tmp_path / "ledger-copy.db"
    shutil.copyfile(source, private_copy)
    migrated = TaskLedger(private_copy)
    migrated.close()
    migrated_uri = f"{private_copy.as_uri()}?mode=ro&immutable=1"
    migrated_connection = sqlite3.connect(migrated_uri, uri=True)
    try:
        after_semantics = _legacy_semantic_digest(migrated_connection)
    finally:
        migrated_connection.close()

    assert after_semantics == before_semantics
    assert before_semantics[:2] == (1, 2)
    assert source.read_bytes() == source_bytes_before
