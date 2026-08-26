"""短期对话记忆持久化：引擎重启（=同库新实例）后上下文还在，不再"失忆"。"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

import pytest

import orchestrator.agent as agent_module
from gateway import sqlite_runtime
from orchestrator.agent import (
    BufferedConversationStore,
    ConversationReceiptUnavailable,
    ConversationStore,
)


def _seed_conversations(db: str, *, key: str, count: int) -> None:
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key TEXT NOT NULL, role TEXT, content TEXT, ts REAL)"
        )
        conn.executemany(
            "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
            [
                (key, "user" if i % 2 == 0 else "assistant", f"message-{i}", float(i))
                for i in range(count)
            ],
        )
        conn.commit()


def _sqlite_artifacts(path) -> dict[str, bytes]:  # noqa: ANN001
    return {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := path.parent / f"{path.name}{suffix}").exists()
    }


def test_conversation_wal_transition_uses_one_total_busy_budget(monkeypatch) -> None:
    clock = {"now": 100.0}

    class _Cursor:
        def __init__(self, row=None):  # noqa: ANN001
            self._row = row

        def fetchone(self):  # noqa: ANN201
            return self._row

    class _AlwaysLockedConnection:
        def __init__(self) -> None:
            self.busy_timeout_ms = 5000
            self.applied_timeouts: list[int] = []

        def execute(self, statement: str):  # noqa: ANN201
            if statement == "PRAGMA busy_timeout":
                return _Cursor((self.busy_timeout_ms,))
            if statement.startswith("PRAGMA busy_timeout="):
                self.busy_timeout_ms = int(statement.rsplit("=", 1)[1])
                self.applied_timeouts.append(self.busy_timeout_ms)
                return _Cursor()
            if statement == "PRAGMA journal_mode=WAL":
                clock["now"] += self.busy_timeout_ms / 1000.0
                raise sqlite3.OperationalError("database is locked")
            raise AssertionError(statement)

    connection = _AlwaysLockedConnection()
    monkeypatch.setattr(sqlite_runtime.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        sqlite_runtime.time,
        "sleep",
        lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
    )

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        ConversationStore._ensure_initialization_wal_mode(connection)  # type: ignore[arg-type]

    attempted = connection.applied_timeouts[:-1]
    assert attempted
    assert sum(attempted) <= 5000
    assert clock["now"] <= 105.01
    assert connection.applied_timeouts[-1] == 5000
    assert connection.busy_timeout_ms == 5000


def test_conversation_wal_transition_real_reader_obeys_one_wall_budget(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "wal-transition-reader.db"
    ConversationStore(db_path=str(path)).close()
    with closing(sqlite3.connect(path)) as reset:
        assert reset.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)

    original = ConversationStore._ensure_initialization_wal_mode
    wal_elapsed: dict[str, float] = {}

    def hold_reader(_cls, connection):  # noqa: ANN001, ANN202
        connection.execute("PRAGMA busy_timeout=200")
        with closing(sqlite3.connect(path, timeout=0.0)) as blocker:
            blocker.execute("BEGIN")
            blocker.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            wal_started = time.monotonic()
            try:
                return original(connection)
            finally:
                wal_elapsed["seconds"] = time.monotonic() - wal_started

    monkeypatch.setattr(
        ConversationStore,
        "_ensure_initialization_wal_mode",
        classmethod(hold_reader),
    )
    started = time.monotonic()
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))
    elapsed = time.monotonic() - started

    assert wal_elapsed["seconds"] < 0.45
    assert elapsed < 2.0
    with closing(sqlite3.connect(path)) as check:
        assert check.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert agent_module._conversation_database_generation(check) == "current"


def _create_abandoned_foreign_hot_wal(path) -> None:  # noqa: ANN001
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
    assert (path.parent / f"{path.name}-wal").is_file()
    assert (path.parent / f"{path.name}-shm").is_file()


def _create_abandoned_supported_conversation_wal(path) -> None:  # noqa: ANN001
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
from orchestrator import agent as agent_module
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
connection.execute(agent_module._CONV_LEGACY_SCHEMA_SQL)
connection.execute(
    "INSERT INTO conv(key,role,content,ts) VALUES('weixin:wal','user','recover-me',1.0)"
)
connection.commit()
os._exit(0)
""",
            os.fspath(path),
        ],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert path.is_file()
    assert (path.parent / f"{path.name}-wal").is_file()
    assert (path.parent / f"{path.name}-shm").is_file()


def test_abandoned_foreign_hot_wal_is_rejected_without_checkpointing(
    tmp_path,
) -> None:
    path = tmp_path / "foreign-hot-wal.db"
    _create_abandoned_foreign_hot_wal(path)
    before = _sqlite_artifacts(path)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    after = _sqlite_artifacts(path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert "-shm" in after
    assert "-journal" not in after


def test_missing_main_with_orphan_sidecars_is_rejected_without_provisioning(
    tmp_path,
) -> None:
    path = tmp_path / "orphan-sidecars.db"
    wal = path.parent / f"{path.name}-wal"
    shm = path.parent / f"{path.name}-shm"
    wal.write_bytes(b"orphan-wal-evidence")
    shm.write_bytes(b"orphan-shm-evidence")

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    assert not path.exists()
    assert wal.read_bytes() == b"orphan-wal-evidence"
    assert shm.read_bytes() == b"orphan-shm-evidence"


def test_concurrent_cold_start_converges_on_one_exact_conversation_database(
    tmp_path,
) -> None:
    path = tmp_path / "concurrent-cold-start.db"
    barrier = Barrier(8)

    def open_store(_index):  # noqa: ANN001, ANN202
        barrier.wait(timeout=10)
        store = ConversationStore(db_path=str(path))
        store.close()
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(open_store, range(8))) == [True] * 8

    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
        assert agent_module._conversation_database_generation(connection) == "current"


def test_supported_conversation_generation_committed_only_in_wal_is_recovered(
    tmp_path,
) -> None:
    path = tmp_path / "supported-generation-in-wal.db"
    _create_abandoned_supported_conversation_wal(path)

    with closing(
        sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    ) as immutable:
        assert immutable.execute(
            "SELECT COUNT(*) FROM sqlite_master"
        ).fetchone() == (0,)
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as wal_aware:
        assert wal_aware.execute(
            "SELECT content FROM conv WHERE key='weixin:wal'"
        ).fetchone() == ("recover-me",)

    store = ConversationStore(db_path=str(path))
    assert store.get("weixin:wal") == [{"role": "user", "content": "recover-me"}]
    store.close()


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_incomplete_conversation_wal_pair_is_rejected_without_mutation(
    tmp_path,
    missing_suffix,
) -> None:
    path = tmp_path / f"incomplete-{missing_suffix[1:]}.db"
    _create_abandoned_foreign_hot_wal(path)
    (path.parent / f"{path.name}{missing_suffix}").unlink()
    before = _sqlite_artifacts(path)

    with pytest.raises(ConversationReceiptUnavailable):
        ConversationStore(db_path=str(path))

    assert _sqlite_artifacts(path) == before


def test_conversation_rollback_journal_is_preserved_and_rejected(tmp_path) -> None:
    path = tmp_path / "rollback-journal.db"
    with closing(sqlite3.connect(path)):
        pass
    journal = path.parent / f"{path.name}-journal"
    journal.write_bytes(b"unresolved-rollback-evidence")
    before = _sqlite_artifacts(path)

    with pytest.raises(ConversationReceiptUnavailable):
        ConversationStore(db_path=str(path))

    assert _sqlite_artifacts(path) == before


def test_unknown_database_is_classified_read_only_before_runtime_profile(tmp_path):
    path = tmp_path / "unrelated.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("CREATE TABLE unrelated(value TEXT NOT NULL)")
        conn.execute("INSERT INTO unrelated VALUES('byte-exact')")
        conn.commit()
    before = _sqlite_artifacts(path)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    assert _sqlite_artifacts(path) == before
    with closing(
        sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    ) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert conn.execute("SELECT value FROM unrelated").fetchone() == ("byte-exact",)


def test_conversation_database_identity_is_not_accepted_from_schema_alone(
    tmp_path,
):
    path = tmp_path / "wrong-identity.db"
    ConversationStore(db_path=str(path)).close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA application_id=19088743")
        connection.execute("PRAGMA user_version=999")
        connection.commit()
    before = _sqlite_artifacts(path)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    assert _sqlite_artifacts(path) == before


def test_external_conversation_identity_change_blocks_the_next_write(tmp_path):
    path = tmp_path / "runtime-identity.db"
    store = ConversationStore(db_path=str(path))
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA application_id=19088743")
        connection.execute("PRAGMA user_version=999")
        connection.commit()

    with pytest.raises(ConversationReceiptUnavailable):
        store.append("weixin:user", "user", "must not be written")
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM conv").fetchone() == (0,)


@pytest.mark.parametrize("tamper", ("sql", "tbl_name"))
def test_current_sqlite_sequence_requires_exact_materialized_metadata(
    tmp_path, tamper
):
    path = tmp_path / f"sqlite-sequence-{tamper}.db"
    ConversationStore(db_path=str(path)).close()
    with closing(sqlite3.connect(path)) as conn:
        schema_version = int(conn.execute("PRAGMA schema_version").fetchone()[0])
        conn.execute("PRAGMA writable_schema=ON")
        if tamper == "sql":
            original = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='sqlite_sequence'"
            ).fetchone()[0]
            changed = str(original).replace("(name,seq)", "(name, seq)")
            assert changed != original
            cursor = conn.execute(
                "UPDATE sqlite_master SET sql=? WHERE name='sqlite_sequence'",
                (changed,),
            )
        else:
            cursor = conn.execute(
                "UPDATE sqlite_master SET tbl_name='conv' "
                "WHERE name='sqlite_sequence'"
            )
        assert cursor.rowcount == 1
        conn.execute("PRAGMA writable_schema=OFF")
        conn.execute(f"PRAGMA schema_version={schema_version + 1}")
        conn.commit()
    before = _sqlite_artifacts(path)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))
    assert _sqlite_artifacts(path) == before


def test_conversation_store_persists(tmp_path):
    db = str(tmp_path / "conv.db")
    s = ConversationStore(db_path=db)
    s.append("feishu:c1", "user", "做个视频")
    s.append("feishu:c1", "assistant", "好的在做了")
    s.close()
    # 模拟引擎重启：同一个库新建实例，上下文应还在
    s2 = ConversationStore(db_path=db)
    assert s2.last_pair("feishu:c1") == ("做个视频", "好的在做了")
    assert [m["content"] for m in s2.get("feishu:c1")] == ["做个视频", "好的在做了"]
    s2.close()


def test_conversation_schema_rejects_quoted_literal_case_collision(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(db_path=str(path))
    store.close()

    with closing(sqlite3.connect(path)) as connection:
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='conv'",
            ("'assistant'", "'ASSISTANT'"),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))


def test_conversation_schema_authority_preserves_sql_token_boundaries():
    assert agent_module._normalized_schema_sql(
        "CHECK(a IS NULL)"
    ) != agent_module._normalized_schema_sql("CHECK(aisnull)")


def test_conversation_store_prunes_old(tmp_path):
    db = str(tmp_path / "conv.db")
    s = ConversationStore(max_turns=2, db_path=db)  # 只留最近 2 轮 = 4 条
    for i in range(10):
        s.append("k", "user", f"u{i}")
        s.append("k", "assistant", f"a{i}")
    s.close()
    s2 = ConversationStore(max_turns=2, db_path=db)
    h = s2.get("k")
    assert len(h) == 4 and h[-1]["content"] == "a9"  # 老的被截断，最近的还在
    s2.close()


def test_first_append_after_restart_keeps_existing_recent_history(tmp_path):
    db = str(tmp_path / "conv.db")
    first = ConversationStore(db_path=db)
    first.append("feishu:c1", "user", "第一问")
    first.append("feishu:c1", "assistant", "第一答")
    first.close()

    restarted = ConversationStore(db_path=db)
    restarted.append("feishu:c1", "user", "第二问")
    assert [item["content"] for item in restarted.get("feishu:c1")] == [
        "第一问",
        "第一答",
        "第二问",
    ]
    restarted.close()


def test_conversation_store_inmemory_default():
    s = ConversationStore()  # 不传 db_path → 纯内存（旧行为/测试）
    s.append("k", "user", "hi")
    assert s.get("k") == [{"role": "user", "content": "hi"}]


def test_conversation_store_lazily_loads_only_the_requested_session(
    tmp_path, monkeypatch
):
    db = str(tmp_path / "conv.db")
    _seed_conversations(db, key="target", count=40)
    statements: list[str] = []
    real_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(agent_module.sqlite3, "connect", traced_connect)
    store = ConversationStore(max_turns=2, db_path=db)

    constructor_statements = tuple(statements)
    assert not any(
        "FROM conv ORDER BY id" in statement for statement in constructor_statements
    )

    assert [item["content"] for item in store.get("target")] == [
        "message-36",
        "message-37",
        "message-38",
        "message-39",
    ]
    session_reads = [
        statement
        for statement in statements[len(constructor_statements) :]
        if statement.lstrip().upper().startswith("SELECT")
    ]
    assert any(
        "WHERE key=" in statement and "LIMIT 4" in statement
        for statement in session_reads
    )
    store.close()


def test_conversation_store_bounds_cached_sessions_with_lru(tmp_path, monkeypatch):
    db = str(tmp_path / "conv.db")
    for key in ("a", "b", "c"):
        _seed_conversations(db, key=key, count=2)
    statements: list[str] = []
    real_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(agent_module.sqlite3, "connect", traced_connect)
    store = ConversationStore(
        max_turns=1,
        max_cached_sessions=2,
        db_path=db,
    )

    assert store.get("a")[-1]["content"] == "message-1"
    assert store.get("b")[-1]["content"] == "message-1"
    assert store.get("a")[-1]["content"] == "message-1"  # a becomes most recent
    assert store.get("c")[-1]["content"] == "message-1"  # evicts b
    assert store.get("b")[-1]["content"] == "message-1"  # reloads evicted b

    reads = [
        statement
        for statement in statements
        if "SELECT role,content FROM conv WHERE key=" in statement
    ]
    assert sum("WHERE key='a'" in statement for statement in reads) == 1
    assert sum("WHERE key='b'" in statement for statement in reads) == 2
    assert sum("WHERE key='c'" in statement for statement in reads) == 1
    store.close()


def test_conversation_store_enforces_configured_database_byte_ceiling(tmp_path):
    db = str(tmp_path / "conv.db")
    ceiling = 128 * 1024

    store = ConversationStore(db_path=db, max_database_bytes=ceiling)
    assert store._conn is not None  # noqa: SLF001 - capacity is connection-scoped
    page_size = int(store._conn.execute("PRAGMA page_size").fetchone()[0])
    max_page_count = int(store._conn.execute("PRAGMA max_page_count").fetchone()[0])
    assert page_size * max_page_count <= ceiling
    assert max_page_count == ceiling // page_size
    store.close()


def test_conversation_store_rejects_an_existing_database_over_the_ceiling(tmp_path):
    db = str(tmp_path / "conv.db")
    _seed_conversations(db, key="oversized", count=1)
    with closing(sqlite3.connect(db)) as conn:
        conn.execute(
            "UPDATE conv SET content=? WHERE key='oversized'",
            ("x" * (256 * 1024),),
        )
        conn.commit()
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    assert page_size * page_count > 128 * 1024

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=db, max_database_bytes=128 * 1024)


def test_conversation_store_bounds_each_content_value_by_utf8_bytes():
    store = ConversationStore(max_content_bytes=8)

    store.append("k", "user", "汉字ab")  # 2 CJK chars (6 bytes) + 2 ASCII bytes
    with pytest.raises(ValueError, match="content exceeds 8 UTF-8 bytes"):
        store.append("k", "assistant", "汉字abc")

    assert store.get("k") == [{"role": "user", "content": "汉字ab"}]


def test_oversized_durable_turn_is_rejected_before_any_atomic_commit(tmp_path):
    db = str(tmp_path / "conv.db")
    store = ConversationStore(db_path=db, max_content_bytes=8)
    turn_key = "a" * 64
    request_hash = "b" * 64

    with pytest.raises(ValueError, match="content exceeds 8 UTF-8 bytes"):
        store.commit_idempotent_turn(
            turn_key=turn_key,
            request_sha256=request_hash,
            entries=[("weixin:chat", "user", "汉字abc")],
            result={"reply": "not committed"},
        )

    assert store.get("weixin:chat") == []
    assert store.idempotent_result(turn_key, request_hash) is None
    store.close()

    restarted = ConversationStore(db_path=db, max_content_bytes=8)
    assert restarted.get("weixin:chat") == []
    assert restarted.idempotent_result(turn_key, request_hash) is None
    restarted.close()


def test_database_capacity_failure_cannot_half_commit_a_durable_turn(tmp_path):
    db = str(tmp_path / "conv.db")
    store = ConversationStore(
        db_path=db,
        max_database_bytes=64 * 1024,
        max_content_bytes=16 * 1024,
        max_conversation_bytes=64 * 1024,
        max_turn_receipt_bytes=64 * 1024,
    )
    failed: tuple[str, str, str] | None = None

    for i in range(32):
        turn_key = f"{i:064x}"
        request_hash = f"{i + 1000:064x}"
        session = f"weixin:capacity-{i}"
        try:
            store.commit_idempotent_turn(
                turn_key=turn_key,
                request_sha256=request_hash,
                entries=[(session, "user", "x" * (8 * 1024))],
                result={"reply": "y" * (8 * 1024)},
            )
        except ConversationReceiptUnavailable:
            failed = (turn_key, request_hash, session)
            break

    assert failed is not None, "the configured 64 KiB ceiling was not enforced"
    failed_turn, failed_request, failed_session = failed
    assert store.idempotent_result(failed_turn, failed_request) is None
    assert store.get(failed_session) == []
    store.close()

    restarted = ConversationStore(
        db_path=db,
        max_database_bytes=64 * 1024,
        max_content_bytes=16 * 1024,
        max_conversation_bytes=64 * 1024,
        max_turn_receipt_bytes=64 * 1024,
    )
    assert restarted.idempotent_result(failed_turn, failed_request) is None
    assert restarted.get(failed_session) == []
    restarted.close()


def test_plain_append_fails_closed_without_memory_only_history_at_capacity(tmp_path):
    db = str(tmp_path / "conv.db")
    store = ConversationStore(
        db_path=db,
        max_turns=1,
        max_database_bytes=64 * 1024,
        max_content_bytes=16 * 1024,
        max_conversation_bytes=64 * 1024,
    )
    failed_key: str | None = None

    for i in range(32):
        key = f"weixin:plain-capacity-{i}"
        try:
            store.append(key, "user", "x" * (8 * 1024))
        except ConversationReceiptUnavailable:
            failed_key = key
            break

    assert failed_key is not None, "the configured 64 KiB ceiling was not enforced"
    assert store.get(failed_key) == []
    store.close()

    restarted = ConversationStore(
        db_path=db,
        max_turns=1,
        max_database_bytes=64 * 1024,
        max_content_bytes=16 * 1024,
        max_conversation_bytes=64 * 1024,
    )
    assert restarted.get(failed_key) == []
    restarted.close()


def test_clear_fails_closed_when_sqlite_cannot_commit(tmp_path):
    db = str(tmp_path / "conv.db")
    store = ConversationStore(db_path=db)
    store.append("weixin:locked", "user", "must survive")

    with closing(sqlite3.connect(db, timeout=0)) as blocker:
        blocker.execute("BEGIN EXCLUSIVE")
        with pytest.raises(
            ConversationReceiptUnavailable,
            match="cannot persist conversation history",
        ):
            store.clear("weixin:locked")
        blocker.rollback()

    assert store.get("weixin:locked") == [
        {"role": "user", "content": "must survive"}
    ]
    store.close()


def test_lookalike_conversation_schema_fails_closed_and_releases_handle(tmp_path):
    path = tmp_path / "conv.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key TEXT NOT NULL, role TEXT, content TEXT, ts REAL, shadow TEXT)"
        )
        conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    moved = tmp_path / "released.db"
    os.replace(path, moved)
    moved.unlink()


def test_lookalike_receipt_schema_rolls_back_legacy_conversation_migration(tmp_path):
    path = tmp_path / "conv.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key TEXT NOT NULL, role TEXT, content TEXT, ts REAL)"
        )
        conn.execute(
            "CREATE TABLE agent_turn_receipt ("
            "turn_key TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, "
            "response_json TEXT NOT NULL, created_at REAL NOT NULL, shadow TEXT"
            ") WITHOUT ROWID"
        )
        conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    with closing(sqlite3.connect(path)) as conn:
        role_column = next(
            row for row in conn.execute("PRAGMA table_xinfo('conv')") if row[1] == "role"
        )
        assert role_column[3] == 0  # exact legacy schema survived the rollback


@pytest.mark.parametrize(
    ("role", "content", "max_content_bytes"),
    [
        (None, "answer", 32),
        ("assistant", None, 32),
        ("assistant", "x" * 9, 8),
    ],
)
def test_exact_legacy_schema_with_corrupt_rows_fails_closed(
    tmp_path, role, content, max_content_bytes
):
    path = tmp_path / "conv.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key TEXT NOT NULL, role TEXT, content TEXT, ts REAL)"
        )
        conn.execute(
            "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
            ("weixin:legacy", role, content, 1.0),
        )
        conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(
            db_path=str(path),
            max_content_bytes=max_content_bytes,
        )


def test_exact_legacy_schema_migrates_atomically_to_strict_constraints(tmp_path):
    path = tmp_path / "conv.db"
    _seed_conversations(str(path), key="weixin:legacy", count=2)

    store = ConversationStore(db_path=str(path))
    assert store.last_pair("weixin:legacy") == ("message-0", "message-1")
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
                ("weixin:bad", None, "answer", 1.0),
            )
        conn.rollback()


def test_committed_legacy_conversation_and_v1_receipt_generation_migrates_atomically(
    tmp_path,
):
    """Historical DDL from commits 1cbc955, 72ea2a3 and 2821cc4 stays readable."""

    path = tmp_path / "committed-legacy-conv-receipt.db"
    turn_key = "a" * 64
    request_sha256 = "b" * 64
    with closing(sqlite3.connect(path)) as conn:
        # Exact committed generation: legacy conv + its index + v1 receipt;
        # there was no receipt index, reservation, capacity meta, or trigger.
        conn.execute(agent_module._CONV_LEGACY_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_V1_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(
            "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
            ("weixin:committed-legacy", "user", "historical message", 1.0),
        )
        conn.execute(
            "INSERT INTO agent_turn_receipt VALUES(?,?,?,?)",
            (turn_key, request_sha256, '{"reply":"historical receipt"}', 2.0),
        )
        conn.commit()

    store = ConversationStore(db_path=str(path))
    assert store.get("weixin:committed-legacy") == [
        {"role": "user", "content": "historical message"}
    ]
    assert store.idempotent_result(turn_key, request_sha256) == {
        "reply": "historical receipt"
    }
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_receipt WHERE turn_key=?",
            (turn_key,),
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT receipt_rows,reservation_rows FROM conversation_capacity_meta"
        ).fetchone() == (1, 0)


@pytest.mark.parametrize(
    ("partial_state", "missing_object"),
    [
        ("conversation_only", "agent_turn_receipt"),
        ("without_capacity_contract", "conversation_capacity_meta"),
        ("without_receipt_index", "idx_agent_turn_receipt_created_at"),
    ],
)
def test_current_partial_schema_fails_closed_without_silent_repair(
    tmp_path, partial_state, missing_object
):
    path = tmp_path / f"{partial_state}.db"
    if partial_state == "without_receipt_index":
        store = ConversationStore(db_path=str(path))
        store.close()
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("DROP INDEX idx_agent_turn_receipt_created_at")
            conn.commit()
    else:
        with closing(sqlite3.connect(path)) as conn:
            conn.execute(agent_module._CONV_SCHEMA_SQL)  # noqa: SLF001
            conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
            if partial_state == "without_capacity_contract":
                conn.execute(agent_module._TURN_RECEIPT_SCHEMA_SQL)  # noqa: SLF001
                conn.execute(agent_module._TURN_RECEIPT_INDEX_SQL)  # noqa: SLF001
            conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))

    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name=?", (missing_object,)
        ).fetchone() is None


def test_lazy_load_rejects_non_text_content_in_strict_schema(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(db_path=str(path), max_content_bytes=32)
    store.append("weixin:corrupt", "assistant", "valid")
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            "UPDATE conv SET content=? WHERE key=?",
            (sqlite3.Binary(b"not-text"), "weixin:corrupt"),
        )
        conn.commit()

    reopened = ConversationStore(db_path=str(path), max_content_bytes=32)
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot load trusted conversation history",
    ):
        reopened.get("weixin:corrupt")
    reopened.close()


def test_distinct_sessions_reclaim_oldest_conversation_before_page_ceiling(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(
        db_path=str(path),
        max_turns=1,
        max_cached_sessions=1,
        max_database_bytes=1024 * 1024,
        max_conversation_rows=4,
        max_conversation_bytes=128 * 1024,
    )

    for i in range(6):
        store.append(f"weixin:{i}", "user", f"message-{i}")

    assert store.get("weixin:0") == []
    assert store.get("weixin:1") == []
    for i in range(2, 6):
        assert store.get(f"weixin:{i}") == [
            {"role": "user", "content": f"message-{i}"}
        ]
    store.close()


def test_conversation_utf8_byte_budget_reclaims_oldest_whole_session(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(
        db_path=str(path),
        max_turns=1,
        max_database_bytes=1024 * 1024,
        max_conversation_rows=100,
        max_conversation_bytes=100,
    )
    for key in ("a", "b", "c"):
        store.append(key, "user", "汉" * 10)

    assert store.get("a") == []
    assert store.get("b") == [{"role": "user", "content": "汉" * 10}]
    assert store.get("c") == [{"role": "user", "content": "汉" * 10}]
    store.close()


def test_turn_receipt_reservation_survives_restart_without_becoming_a_replay(
    tmp_path,
):
    path = tmp_path / "turn-reservation.db"
    turn_key = "a" * 64
    request_hash = "b" * 64
    conflicting_hash = "c" * 64
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=2,
        max_turn_receipt_bytes=2 * 1024 * 1024,
    )

    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=100.0,
    ) == "reserved"
    assert store.idempotent_result(turn_key, request_hash) is None
    store.close()

    restarted = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=2,
        max_turn_receipt_bytes=2 * 1024 * 1024,
    )
    assert restarted.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=101.0,
    ) == "reserved"
    assert restarted.idempotent_result(turn_key, request_hash) is None
    with pytest.raises(ValueError, match="turn idempotency semantic conflict"):
        restarted.reserve_turn_receipt(
            turn_key=turn_key,
            request_sha256=conflicting_hash,
            now=101.0,
        )
    with pytest.raises(ValueError, match="turn idempotency semantic conflict"):
        restarted.idempotent_result(turn_key, conflicting_hash)
    restarted.close()


def test_committing_reserved_turn_consumes_reservation_atomically(tmp_path):
    path = tmp_path / "reserved-commit.db"
    turn_key = "d" * 64
    request_hash = "e" * 64
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=2 * 1024 * 1024,
    )
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=200.0,
    ) == "reserved"

    assert store.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_hash,
        entries=[
            ("weixin:reserved", "user", "hello"),
            ("weixin:reserved", "assistant", "world"),
        ],
        result={"reply": "world"},
        now=201.0,
    ) == {"reply": "world"}
    assert store.get("weixin:reserved") == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "world"},
    ]
    assert store.idempotent_result(turn_key, request_hash) == {"reply": "world"}
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_reservation"
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_receipt"
        ).fetchone() == (1,)

    restarted = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=2 * 1024 * 1024,
    )
    assert restarted.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=202.0,
    ) == "committed"
    restarted.close()


def test_strict_provider_commit_requires_provider_started_and_keeps_compatibility(
    tmp_path,
):
    path = tmp_path / "strict-provider-commit.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=4 * 1024 * 1024,
        max_turn_receipts=3,
        max_turn_receipt_bytes=3
        * agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    )
    provider_turn, provider_request = "f" * 64, "e" * 64
    assert store.reserve_turn_receipt(
        turn_key=provider_turn,
        request_sha256=provider_request,
        now=210.0,
    ) == "reserved"
    provider_buffer = BufferedConversationStore(store)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="provider_started reservation",
    ):
        provider_buffer.commit(
            turn_key=provider_turn,
            request_sha256=provider_request,
            result={"reply": "too early"},
            require_provider_started=True,
        )
    assert store.reserve_turn_receipt(
        turn_key=provider_turn,
        request_sha256=provider_request,
        now=212.0,
    ) == "reserved"

    assert store.enter_turn_provider_phase(
        turn_key=provider_turn,
        request_sha256=provider_request,
        now=213.0,
    ) == "provider_started"
    assert provider_buffer.commit(
        turn_key=provider_turn,
        request_sha256=provider_request,
        result={"reply": "provider result"},
        require_provider_started=True,
    ) == {"reply": "provider result"}

    local_turn, local_request = "d" * 64, "c" * 64
    assert store.commit_idempotent_turn(
        turn_key=local_turn,
        request_sha256=local_request,
        entries=[],
        result={"reply": "local result"},
        now=215.0,
    ) == {"reply": "local result"}
    store.close()


def test_concurrent_turn_reservations_cannot_oversell_one_durable_slot(tmp_path):
    path = tmp_path / "concurrent-reservations.db"
    settings = {
        "db_path": str(path),
        "max_database_bytes": 2 * 1024 * 1024,
        "max_turn_receipts": 1,
        "max_turn_receipt_bytes": agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    }
    first = ConversationStore(**settings)
    second = ConversationStore(**settings)
    barrier = Barrier(2)

    def reserve(store, turn_key, request_hash):
        barrier.wait()
        try:
            return store.reserve_turn_receipt(
                turn_key=turn_key,
                request_sha256=request_hash,
                now=300.0,
            )
        except ConversationReceiptUnavailable:
            return "full"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                reserve,
                (first, second),
                ("1" * 64, "2" * 64),
                ("3" * 64, "4" * 64),
            )
        )

    assert sorted(outcomes) == ["full", "reserved"]
    first.close()
    second.close()
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT reservation_rows,reservation_payload_bytes "
            "FROM conversation_capacity_meta WHERE singleton=1"
        ).fetchone() == (1, agent_module._TURN_RESERVATION_PAYLOAD_BYTES)
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_reservation"
        ).fetchone() == (1,)


def test_turn_receipt_capacity_contract_is_database_authority(tmp_path):
    path = tmp_path / "capacity-contract.db"
    authoritative = {
        "db_path": str(path),
        "max_database_bytes": 4 * 1024 * 1024,
        "max_turn_receipts": 2,
        "max_turn_receipt_bytes": 2
        * agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    }
    incompatible = {
        **authoritative,
        "max_turn_receipts": 1,
        "max_turn_receipt_bytes": agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    }
    first = ConversationStore(**authoritative)

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(**incompatible)

    first.close()
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(**incompatible)

    reopened = ConversationStore(**authoritative)
    reopened.close()


def test_reservation_can_only_be_abandoned_before_provider_phase(tmp_path):
    path = tmp_path / "provider-phase.db"
    settings = {
        "db_path": str(path),
        "max_database_bytes": 2 * 1024 * 1024,
        "max_turn_receipts": 1,
        "max_turn_receipt_bytes": agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    }
    before_key, before_request = "5" * 64, "6" * 64
    paid_key, paid_request = "7" * 64, "8" * 64
    store = ConversationStore(**settings)
    assert store.reserve_turn_receipt(
        turn_key=before_key,
        request_sha256=before_request,
        now=400.0,
    ) == "reserved"
    assert store.abandon_turn_before_provider(
        turn_key=before_key,
        request_sha256=before_request,
    ) is True
    assert store.abandon_turn_before_provider(
        turn_key=before_key,
        request_sha256=before_request,
    ) is False

    assert store.reserve_turn_receipt(
        turn_key=paid_key,
        request_sha256=paid_request,
        now=401.0,
    ) == "reserved"
    assert store.enter_turn_provider_phase(
        turn_key=paid_key,
        request_sha256=paid_request,
        now=402.0,
    ) == "provider_started"
    assert store.enter_turn_provider_phase(
        turn_key=paid_key,
        request_sha256=paid_request,
        now=403.0,
    ) == "provider_started"
    assert store.abandon_turn_before_provider(
        turn_key=paid_key,
        request_sha256=paid_request,
    ) is False
    with pytest.raises(ValueError, match="turn idempotency semantic conflict"):
        store.abandon_turn_before_provider(
            turn_key=paid_key,
            request_sha256="9" * 64,
        )
    store.close()

    restarted = ConversationStore(**settings)
    assert restarted.reserve_turn_receipt(
        turn_key=paid_key,
        request_sha256=paid_request,
        now=404.0,
    ) == "provider_started"
    assert restarted.abandon_turn_before_provider(
        turn_key=paid_key,
        request_sha256=paid_request,
    ) is False
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="protected durable Turn receipt capacity is fully reserved",
    ):
        restarted.reserve_turn_receipt(
            turn_key="a" * 64,
            request_sha256="b" * 64,
            now=405.0,
        )
    restarted.close()


def test_abandoned_turn_keeps_digest_binding_while_releasing_capacity(tmp_path):
    path = tmp_path / "abandoned-binding.db"
    settings = {
        "db_path": str(path),
        "max_database_bytes": 2 * 1024 * 1024,
        "max_turn_receipts": 1,
        "max_turn_receipt_bytes": agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    }
    turn_key, request_hash = "a" * 64, "b" * 64
    other_turn, other_request = "c" * 64, "d" * 64
    store = ConversationStore(**settings)

    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=410.0,
    ) == "reserved"
    assert store.abandon_turn_before_provider(
        turn_key=turn_key,
        request_sha256=request_hash,
    ) is True
    store.close()
    store = ConversationStore(**settings)

    with pytest.raises(ValueError, match="turn idempotency semantic conflict"):
        store.reserve_turn_receipt(
            turn_key=turn_key,
            request_sha256="e" * 64,
            now=411.0,
        )

    assert store.reserve_turn_receipt(
        turn_key=other_turn,
        request_sha256=other_request,
        now=412.0,
    ) == "reserved"
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="abandoned durable Turn cannot be committed",
    ):
        store.commit_idempotent_turn(
            turn_key=turn_key,
            request_sha256=request_hash,
            entries=[],
            result={"reply": "late"},
            now=413.0,
        )

    assert store.abandon_turn_before_provider(
        turn_key=other_turn,
        request_sha256=other_request,
    ) is True
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=414.0,
    ) == "reserved"
    store.close()


def test_reserved_turn_commit_failure_restores_reservation_and_pair(tmp_path, monkeypatch):
    path = tmp_path / "reserved-rollback.db"
    real_connect = sqlite3.connect

    class ReceiptInsertFailureConnection(sqlite3.Connection):
        fail_receipt_insert = False

        def execute(self, sql, parameters=()):
            if self.fail_receipt_insert and sql.startswith(
                "INSERT INTO agent_turn_receipt"
            ):
                raise sqlite3.OperationalError("simulated receipt insert failure")
            return super().execute(sql, parameters)

    def connect_with_failure_hook(*args, **kwargs):
        kwargs["factory"] = ReceiptInsertFailureConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(agent_module.sqlite3, "connect", connect_with_failure_hook)
    turn_key, request_hash = "c" * 64, "d" * 64
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    )
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=500.0,
    ) == "reserved"
    assert store.enter_turn_provider_phase(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=501.0,
    ) == "provider_started"
    assert isinstance(store._conn, ReceiptInsertFailureConnection)  # noqa: SLF001
    store._conn.fail_receipt_insert = True  # noqa: SLF001

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot atomically persist durable Turn result",
    ):
        store.commit_idempotent_turn(
            turn_key=turn_key,
            request_sha256=request_hash,
            entries=[
                ("weixin:rollback", "user", "hello"),
                ("weixin:rollback", "assistant", "world"),
            ],
            result={"reply": "world"},
            now=502.0,
        )

    store._conn.fail_receipt_insert = False  # noqa: SLF001
    assert store.get("weixin:rollback") == []
    assert store.idempotent_result(turn_key, request_hash) is None
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=503.0,
    ) == "provider_started"
    store.close()

    with closing(real_connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM conv").fetchone() == (0,)
        assert conn.execute(
            "SELECT state FROM agent_turn_reservation WHERE turn_key=?",
            (turn_key,),
        ).fetchone() == ("provider_started",)
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_receipt"
        ).fetchone() == (0,)


def test_receipt_capacity_never_evicts_results_inside_thirty_day_window(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=1024 * 1024,
        max_turn_receipts=2,
        max_turn_receipt_bytes=128 * 1024,
    )
    request_hashes: list[str] = []
    for i in range(2):
        request_hash = f"{100 + i:064x}"
        request_hashes.append(request_hash)
        store.commit_idempotent_turn(
            turn_key=f"{i:064x}",
            request_sha256=request_hash,
            entries=[],
            result={"reply": f"protected-{i}"},
            now=1_000.0 + i,
        )

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="protected durable Turn receipt window is full",
    ):
        store.commit_idempotent_turn(
            turn_key=f"{2:064x}",
            request_sha256=f"{102:064x}",
            entries=[],
            result={"reply": "must-not-evict"},
            now=1_002.0,
        )

    for i, request_hash in enumerate(request_hashes):
        assert store.idempotent_result(f"{i:064x}", request_hash) == {
            "reply": f"protected-{i}"
        }
    assert store.idempotent_result(f"{2:064x}", f"{102:064x}") is None
    store.close()


def test_expired_receipts_are_reclaimed_before_admitting_a_new_result(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=1024 * 1024,
        max_turn_receipts=2,
        max_turn_receipt_bytes=128 * 1024,
    )
    for i in range(2):
        store.commit_idempotent_turn(
            turn_key=f"{i:064x}",
            request_sha256=f"{200 + i:064x}",
            entries=[],
            result={"reply": f"expired-{i}"},
            now=0.0,
        )

    fresh = store.commit_idempotent_turn(
        turn_key=f"{2:064x}",
        request_sha256=f"{202:064x}",
        entries=[],
        result={"reply": "fresh"},
        now=30 * 24 * 60 * 60 + 1.0,
    )

    assert fresh == {"reply": "fresh"}
    for i in range(2):
        assert store.idempotent_result(f"{i:064x}", f"{200 + i:064x}") is None
    assert store.idempotent_result(f"{2:064x}", f"{202:064x}") == {
        "reply": "fresh"
    }
    store.close()


def test_large_receipts_use_exact_utf8_byte_budget_without_deleting_fresh_result(
    tmp_path,
):
    path = tmp_path / "conv.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=1024 * 1024,
        max_turn_receipts=10,
        max_turn_receipt_bytes=1024,
    )
    first_key = "a" * 64
    first_request = "b" * 64
    first = {"reply": "汉" * 250}
    store.commit_idempotent_turn(
        turn_key=first_key,
        request_sha256=first_request,
        entries=[],
        result=first,
        now=100.0,
    )

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="protected durable Turn receipt window is full",
    ):
        store.commit_idempotent_turn(
            turn_key="c" * 64,
            request_sha256="d" * 64,
            entries=[],
            result={"reply": "x" * 250},
            now=101.0,
        )

    assert store.idempotent_result(first_key, first_request) == first
    store.close()


def test_reserved_receipt_accepts_exactly_one_mib_and_rejects_one_byte_more(
    tmp_path,
):
    path = tmp_path / "exact-receipt-limit.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=4 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=1_048_704,
    )
    turn_key, request_hash = "8" * 64, "9" * 64
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=900.0,
    ) == "reserved"

    # Compact JSON for {"reply":""} is 12 ASCII bytes, leaving 1,048,564
    # payload bytes at the exact 1 MiB response_json boundary.
    exact_result = {"reply": "x" * 1_048_564}
    assert store.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_hash,
        entries=[],
        result=exact_result,
        now=901.0,
    ) == exact_result

    with pytest.raises(ValueError, match="turn result exceeds receipt limit"):
        store.commit_idempotent_turn(
            turn_key="a" * 64,
            request_sha256="b" * 64,
            entries=[],
            result={"reply": "x" * 1_048_565},
            now=902.0,
        )
    store.close()


def test_capacity_trigger_lookalike_schema_fails_closed(tmp_path):
    path = tmp_path / "conv.db"
    store = ConversationStore(db_path=str(path))
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        conn.execute("DROP TRIGGER conversation_capacity_conv_insert")
        conn.execute(
            "CREATE TRIGGER conversation_capacity_conv_insert "
            "AFTER INSERT ON conv BEGIN SELECT 1; END"
        )
        conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))


@pytest.mark.parametrize(
    ("key", "role"),
    [
        ("", "user"),
        ("k", "system"),
        ("k" * 4097, "user"),
        ("bad\ud800", "assistant"),
    ],
)
def test_plain_append_rejects_invalid_key_or_role_before_mutation(key, role):
    store = ConversationStore()
    with pytest.raises(ValueError):
        store.append(key, role, "content")
    assert store.get("k") == []


@pytest.mark.parametrize(
    "operation",
    [
        lambda store: store.get(""),
        lambda store: store.clear(""),
        lambda store: store.last_pair(""),
        lambda store: store.set_last_model("", "model"),
        lambda store: store.last_model(""),
        lambda store: store.get(b"bytes-key"),
    ],
)
def test_all_public_conversation_key_entries_reject_invalid_keys(operation):
    store = ConversationStore()
    with pytest.raises(ValueError):
        operation(store)


def test_buffered_store_validates_without_string_coercion():
    buffered = BufferedConversationStore(ConversationStore(max_content_bytes=8))
    with pytest.raises(ValueError):
        buffered.append(b"key", "user", "ok")
    with pytest.raises(ValueError):
        buffered.append("key", "system", "ok")
    with pytest.raises(ValueError, match="content exceeds"):
        buffered.append("key", "user", "汉字abc")
    with pytest.raises(ValueError):
        buffered.set_last_model("key", object())
    assert buffered.entries == []


def test_buffered_local_turn_clears_previous_model_only_after_atomic_commit():
    base = ConversationStore()
    key = "weixin:local-turn"
    base.set_last_model(key, "previous-provider")
    buffered = BufferedConversationStore(base)
    buffered.append(key, "user", "blocked")
    buffered.append(key, "assistant", "local response")
    buffered.clear_last_model(key)

    assert base.last_model(key) == "previous-provider"
    buffered.commit(
        turn_key="a" * 64,
        request_sha256="b" * 64,
        result={"reply": "local response"},
    )
    assert base.last_model(key) is None


def test_any_new_assistant_row_invalidates_previous_model_until_rebound():
    store = ConversationStore()
    key = "api:author-invariant"
    store.append(key, "user", "first")
    store.append(key, "assistant", "provider answer")
    store.set_last_model(key, "verified-provider")
    assert store.last_model(key) == "verified-provider"

    store.append(key, "user", "second")
    assert store.last_model(key) == "verified-provider"
    store.append(key, "assistant", "local answer")
    assert store.last_model(key) is None


def test_get_returns_detached_message_objects():
    store = ConversationStore()
    store.append("k", "user", "original")
    leaked = store.get("k")
    leaked[0]["content"] = "tampered"
    assert store.get("k") == [{"role": "user", "content": "original"}]


def test_inmemory_turn_replays_return_deeply_detached_results():
    store = ConversationStore()
    turn_key, request_hash = "a" * 64, "b" * 64
    first = store.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_hash,
        entries=[],
        result={"nested": {"items": ["original"]}},
    )
    first["nested"]["items"][0] = "tampered"
    replay = store.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_hash,
        entries=[],
        result={"ignored": True},
    )
    replay["nested"]["items"][0] = "tampered-again"
    assert store.idempotent_result(turn_key, request_hash) == {
        "nested": {"items": ["original"]}
    }


def test_database_configuration_cannot_exceed_one_gibibyte():
    with pytest.raises(ValueError, match="1 GiB"):
        ConversationStore(max_database_bytes=1024**3 + 4096)


def test_external_capacity_counter_tampering_fails_closed(tmp_path):
    path = tmp_path / "counter.db"
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=1024 * 1024,
        max_conversation_rows=2,
        max_conversation_bytes=128 * 1024,
    )
    store.append("a", "user", "one")
    store.append("b", "user", "two")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "UPDATE conversation_capacity_meta SET conv_rows=0,"
            "conv_payload_bytes=0 WHERE singleton=1"
        )
        conn.commit()

    with pytest.raises(ConversationReceiptUnavailable):
        store.append("c", "user", "three")
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM conv").fetchone()[0] == 2


def test_external_reservation_counter_tampering_fails_closed(tmp_path):
    path = tmp_path / "reservation-counter.db"
    turn_key, request_hash = "1" * 64, "2" * 64
    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    )
    assert store.reserve_turn_receipt(
        turn_key=turn_key,
        request_sha256=request_hash,
        now=700.0,
    ) == "reserved"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "UPDATE conversation_capacity_meta SET reservation_rows=0,"
            "reservation_payload_bytes=0 WHERE singleton=1"
        )
        conn.commit()

    with pytest.raises(ConversationReceiptUnavailable):
        store.idempotent_result(turn_key, request_hash)
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM agent_turn_reservation"
        ).fetchone() == (1,)


def test_external_valid_writer_invalidates_cached_sessions_and_model(tmp_path):
    path = tmp_path / "two-writers.db"
    first = ConversationStore(db_path=str(path))
    first.append("shared", "user", "one")
    first.set_last_model("shared", "model-one")
    assert first.get("shared")[-1]["content"] == "one"  # warm the LRU

    second = ConversationStore(db_path=str(path))
    second.append("shared", "assistant", "two")
    assert [item["content"] for item in first.get("shared")] == ["one", "two"]
    assert first.last_model("shared") is None

    second.clear("shared")
    assert first.get("shared") == []
    second.close()
    first.close()


def test_last_model_alone_revalidates_an_external_commit(tmp_path):
    path = tmp_path / "last-model-external-writer.db"
    first = ConversationStore(db_path=str(path))
    first.set_last_model("shared", "model-one")

    second = ConversationStore(db_path=str(path))
    second.append("shared", "assistant", "external turn")

    assert first.last_model("shared") is None

    second.close()
    first.close()


def test_initial_data_version_baseline_cannot_absorb_post_commit_tampering(
    tmp_path, monkeypatch
):
    path = tmp_path / "initial-baseline.db"
    real_connect = sqlite3.connect
    injected = False

    class PostCommitTamperConnection(sqlite3.Connection):
        def commit(self):
            nonlocal injected
            super().commit()
            if injected:
                return
            injected = True
            with closing(real_connect(path, timeout=5.0)) as intruder:
                intruder.execute("CREATE TABLE rogue_payload(x BLOB)")
                intruder.commit()

    def connect_with_post_commit_tamper(*args, **kwargs):
        kwargs["factory"] = PostCommitTamperConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(agent_module.sqlite3, "connect", connect_with_post_commit_tamper)
    store = ConversationStore(db_path=str(path))
    try:
        assert injected is True
        with pytest.raises(ConversationReceiptUnavailable):
            store.get("shared")
    finally:
        store.close()


def test_unknown_sqlite_schema_object_fails_closed(tmp_path):
    path = tmp_path / "closed-set.db"
    store = ConversationStore(db_path=str(path))
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE rogue_payload(x BLOB)")
        conn.commit()
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))


def test_corrupt_receipt_blob_raises_uniform_unavailable(tmp_path):
    path = tmp_path / "receipt-blob.db"
    turn_key, request_hash = "a" * 64, "b" * 64
    store = ConversationStore(db_path=str(path))
    store.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_hash,
        entries=[],
        result={"reply": "ok"},
    )
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            "UPDATE agent_turn_receipt SET response_json=? WHERE turn_key=?",
            (sqlite3.Binary(b"not-json"), turn_key),
        )
        conn.commit()
    reopened = ConversationStore(db_path=str(path))
    with pytest.raises(ConversationReceiptUnavailable):
        reopened.idempotent_result(turn_key, request_hash)
    reopened.close()


def test_database_symlink_path_is_rejected(tmp_path):
    target = tmp_path / "real.db"
    store = ConversationStore(db_path=str(target))
    store.close()
    link = tmp_path / "alias.db"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Windows process cannot create symlinks")
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(link))


def test_database_sidecar_symlink_is_rejected_before_open(tmp_path):
    path = tmp_path / "sidecar.db"
    store = ConversationStore(db_path=str(path))
    store.close()
    target = tmp_path / "outside-wal"
    target.write_bytes(b"not a sqlite wal")
    sidecar = tmp_path / "sidecar.db-wal"
    try:
        sidecar.symlink_to(target)
    except OSError:
        pytest.skip("Windows process cannot create symlinks")
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))


def test_previous_reservation_schema_migrates_data_and_capacity_contract(tmp_path):
    path = tmp_path / "previous-reservation-schema.db"
    committed_turn, committed_request = "1" * 64, "2" * 64
    active_turn, active_request = "3" * 64, "4" * 64
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(agent_module._CONV_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RESERVATION_V1_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CAPACITY_META_V3_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(
            "INSERT INTO conversation_capacity_meta VALUES(1,0,0,0,0,0,0)"
        )
        for sql in agent_module._CAPACITY_TRIGGER_V3_SQL.values():  # noqa: SLF001
            conn.execute(sql)
        conn.execute(
            "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
            ("weixin:migrated", "user", "hello", 1.0),
        )
        conn.execute(
            "INSERT INTO agent_turn_receipt VALUES(?,?,?,?)",
            (committed_turn, committed_request, '{"reply":"old"}', 2.0),
        )
        conn.execute(
            "INSERT INTO agent_turn_reservation VALUES(?,?,?,?,?,?)",
            (
                active_turn,
                active_request,
                "provider_started",
                1_048_704,
                3.0,
                4.0,
            ),
        )
        conn.commit()

    settings = {
        "db_path": str(path),
        "max_database_bytes": 4 * 1024 * 1024,
        "max_turn_receipts": 2,
        "max_turn_receipt_bytes": 2 * 1_048_704,
    }
    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(
            **{
                **settings,
                "max_turn_receipts": 1,
            }
        )

    store = ConversationStore(**settings)
    assert store.get("weixin:migrated") == [{"role": "user", "content": "hello"}]
    assert store.idempotent_result(committed_turn, committed_request) == {
        "reply": "old"
    }
    assert store.reserve_turn_receipt(
        turn_key=active_turn,
        request_sha256=active_request,
        now=5.0,
    ) == "provider_started"
    assert store.commit_idempotent_turn(
        turn_key=active_turn,
        request_sha256=active_request,
        entries=[],
        result={"reply": "new"},
        now=6.0,
        require_provider_started=True,
    ) == {"reply": "new"}
    store.close()

    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT receipt_contract_version,max_turn_receipts,"
            "max_turn_receipt_bytes FROM conversation_capacity_meta"
        ).fetchone() == (1, 2, 2_097_408)


def test_pre_reservation_strict_schema_migrates_to_reserved_capacity_contract(
    tmp_path,
):
    path = tmp_path / "pre-reservation-schema.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(agent_module._CONV_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._CAPACITY_META_V2_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(
            "INSERT INTO conversation_capacity_meta VALUES(1,0,0,0,0)"
        )
        for sql in agent_module._CAPACITY_TRIGGER_V2_SQL.values():  # noqa: SLF001
            conn.execute(sql)
        conn.commit()

    store = ConversationStore(
        db_path=str(path),
        max_database_bytes=2 * 1024 * 1024,
        max_turn_receipts=1,
        max_turn_receipt_bytes=agent_module._TURN_RESERVATION_PAYLOAD_BYTES,
    )
    assert store.reserve_turn_receipt(
        turn_key="e" * 64,
        request_sha256="f" * 64,
        now=600.0,
    ) == "reserved"
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute(
            "SELECT reservation_rows,reservation_payload_bytes "
            "FROM conversation_capacity_meta WHERE singleton=1"
        ).fetchone() == (1, agent_module._TURN_RESERVATION_PAYLOAD_BYTES)
        triggers = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        assert triggers == set(agent_module._CAPACITY_TRIGGER_SQL)  # noqa: SLF001


def test_partial_reservation_schema_upgrade_fails_closed(tmp_path):
    path = tmp_path / "partial-reservation-schema.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(agent_module._CONV_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RESERVATION_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CAPACITY_META_V2_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(
            "INSERT INTO conversation_capacity_meta VALUES(1,0,0,0,0)"
        )
        for sql in agent_module._CAPACITY_TRIGGER_V2_SQL.values():  # noqa: SLF001
            conn.execute(sql)
        conn.commit()

    with pytest.raises(
        ConversationReceiptUnavailable,
        match="cannot initialize bounded conversation database",
    ):
        ConversationStore(db_path=str(path))


def test_previous_strict_schema_migrates_to_type_enforced_contract(tmp_path):
    path = tmp_path / "previous-schema.db"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(agent_module._CONV_V2_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._CONV_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_V1_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(agent_module._TURN_RECEIPT_INDEX_SQL)  # noqa: SLF001
        conn.execute(agent_module._CAPACITY_META_V1_SCHEMA_SQL)  # noqa: SLF001
        conn.execute(
            "INSERT INTO conversation_capacity_meta VALUES(1,0,0,0,0)"
        )
        for sql in agent_module._CAPACITY_TRIGGER_V2_SQL.values():  # noqa: SLF001
            conn.execute(sql)
        conn.execute(
            "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
            ("weixin:old", "user", "hello", 1.0),
        )
        conn.execute(
            "INSERT INTO agent_turn_receipt VALUES(?,?,?,?)",
            ("a" * 64, "b" * 64, '{"reply":"ok"}', 1.0),
        )
        conn.commit()

    store = ConversationStore(db_path=str(path))
    assert store.get("weixin:old") == [{"role": "user", "content": "hello"}]
    assert store.idempotent_result("a" * 64, "b" * 64) == {"reply": "ok"}
    store.close()
    with closing(sqlite3.connect(path)) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO conv(key,role,content,ts) VALUES(?,?,?,?)",
                (sqlite3.Binary(b"blob"), "user", "hidden", 2.0),
            )
