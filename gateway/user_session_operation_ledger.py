"""Durable idempotency and unknown-outcome ledger for user-session agents.

Only authenticated identity fields, state and content digests are stored.  This
ledger deliberately has no prompt, result body, credential or process-command
column.
"""

from __future__ import annotations

import functools
import os
import re
import sqlite3
import stat
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from gateway.user_session_agent_protocol import VerifiedUserSessionOperationScope


_FILENAME = "user-session-operations.db"
_APPLICATION_ID = 0x4E435541  # "NCUA"
_SCHEMA_VERSION = 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONNECTORS = {"codex", "kimi_code"}
_STATES = {
    "prepared",
    "dispatch_authorized",
    "provider_phase",
    "failed_pre_submit",
    "submitted_unknown",
    "succeeded",
}
_TERMINAL = {"failed_pre_submit", "submitted_unknown", "succeeded"}
_LOCK = threading.RLock()
_MAX_BYTES = 4 * 1024 * 1024
_MAX_COUNTER = 2**63 - 1

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE ledger_meta (
      singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      installation_id TEXT NOT NULL,
      root_epoch INTEGER NOT NULL CHECK(root_epoch BETWEEN 1 AND 9223372036854775807),
      row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1000000),
      mutation_sequence INTEGER NOT NULL
        CHECK(mutation_sequence BETWEEN 0 AND 9223372036854775807),
      CHECK(length(installation_id)=64),
      CHECK(installation_id=lower(installation_id)),
      CHECK(installation_id NOT GLOB '*[^0-9a-f]*'),
      CHECK(installation_id<>'0000000000000000000000000000000000000000000000000000000000000000')
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE operations (
      installation_id TEXT NOT NULL,
      root_epoch INTEGER NOT NULL CHECK(root_epoch BETWEEN 1 AND 9223372036854775807),
      service_boot_id TEXT NOT NULL,
      principal_hash TEXT NOT NULL,
      session_id INTEGER NOT NULL CHECK(session_id BETWEEN 1 AND 9223372036854775807),
      agent_generation INTEGER NOT NULL
        CHECK(agent_generation BETWEEN 1 AND 9223372036854775807),
      connector TEXT NOT NULL,
      operation_id TEXT NOT NULL,
      request_digest TEXT NOT NULL,
      fence TEXT NOT NULL,
      state TEXT NOT NULL,
      retry_safe INTEGER NOT NULL CHECK(retry_safe IN (0,1)),
      result_digest TEXT,
      state_sequence INTEGER NOT NULL
        CHECK(state_sequence BETWEEN 1 AND 9223372036854775807),
      PRIMARY KEY(installation_id,principal_hash,connector,operation_id),
      CHECK(connector IN ('codex','kimi_code')),
      CHECK(state IN ('prepared','dispatch_authorized','provider_phase',
                      'failed_pre_submit','submitted_unknown','succeeded')),
      CHECK(length(installation_id)=64 AND installation_id=lower(installation_id)
            AND installation_id NOT GLOB '*[^0-9a-f]*'),
      CHECK(length(service_boot_id)=64 AND service_boot_id=lower(service_boot_id)
            AND service_boot_id NOT GLOB '*[^0-9a-f]*'),
      CHECK(length(principal_hash)=64 AND principal_hash=lower(principal_hash)
            AND principal_hash NOT GLOB '*[^0-9a-f]*'),
      CHECK(length(request_digest)=64 AND request_digest=lower(request_digest)
            AND request_digest NOT GLOB '*[^0-9a-f]*'),
      CHECK(length(fence)=64 AND fence=lower(fence)
            AND fence NOT GLOB '*[^0-9a-f]*'),
      CHECK(result_digest IS NULL OR
            (length(result_digest)=64 AND result_digest=lower(result_digest)
             AND result_digest NOT GLOB '*[^0-9a-f]*')),
      CHECK(length(operation_id)=36
            AND substr(operation_id,9,1)='-'
            AND substr(operation_id,14,1)='-'
            AND substr(operation_id,19,1)='-'
            AND substr(operation_id,24,1)='-'
            AND operation_id=lower(operation_id)),
      CHECK(
        (state='prepared' AND retry_safe=1 AND result_digest IS NULL
         AND state_sequence=1)
        OR (state='dispatch_authorized' AND retry_safe=0 AND result_digest IS NULL
            AND state_sequence>=2)
        OR (state='provider_phase' AND retry_safe=0 AND result_digest IS NULL
            AND state_sequence>=3)
        OR (state='failed_pre_submit' AND retry_safe=1 AND result_digest IS NULL
            AND state_sequence>=2)
        OR (state='submitted_unknown' AND retry_safe=0 AND result_digest IS NULL
            AND state_sequence>=2)
        OR (state='succeeded' AND retry_safe=0 AND result_digest IS NOT NULL
            AND state_sequence>=4)
      )
    ) WITHOUT ROWID
    """,
    """
    CREATE TRIGGER operations_identity_immutable
    BEFORE UPDATE ON operations
    WHEN NEW.installation_id<>OLD.installation_id
      OR NEW.root_epoch<>OLD.root_epoch
      OR NEW.service_boot_id<>OLD.service_boot_id
      OR NEW.principal_hash<>OLD.principal_hash
      OR NEW.session_id<>OLD.session_id
      OR NEW.agent_generation<>OLD.agent_generation
      OR NEW.connector<>OLD.connector
      OR NEW.operation_id<>OLD.operation_id
      OR NEW.request_digest<>OLD.request_digest
      OR NEW.fence<>OLD.fence
      OR NEW.state_sequence<>OLD.state_sequence+1
    BEGIN
      SELECT RAISE(ABORT,'operation identity or sequence changed');
    END
    """,
    """
    CREATE TRIGGER operations_insert_meta
    AFTER INSERT ON operations
    BEGIN
      UPDATE ledger_meta
      SET row_count=row_count+1,mutation_sequence=mutation_sequence+1
      WHERE singleton=1
        AND installation_id=NEW.installation_id
        AND root_epoch=NEW.root_epoch;
      SELECT CASE WHEN changes()<>1
        THEN RAISE(ABORT,'operation installation authority mismatch') END;
    END
    """,
    """
    CREATE TRIGGER operations_update_meta
    AFTER UPDATE ON operations
    BEGIN
      UPDATE ledger_meta
      SET mutation_sequence=mutation_sequence+1
      WHERE singleton=1
        AND installation_id=NEW.installation_id
        AND root_epoch=NEW.root_epoch;
      SELECT CASE WHEN changes()<>1
        THEN RAISE(ABORT,'operation installation authority mismatch') END;
    END
    """,
    """
    CREATE TRIGGER operations_no_delete
    BEFORE DELETE ON operations
    BEGIN
      SELECT RAISE(ABORT,'operation history is append-only');
    END
    """,
)


class UserSessionOperationLedgerError(RuntimeError):
    pass


class UserSessionOperationConflict(UserSessionOperationLedgerError):
    pass


@dataclass(frozen=True, slots=True)
class UserSessionOperation:
    installation_id: str
    root_epoch: int
    service_boot_id: str
    principal_hash: str
    session_id: int
    agent_generation: int
    connector: str
    operation_id: str
    request_digest: str
    fence: str
    state: str
    retry_safe: bool
    result_digest: str | None
    state_sequence: int


def _hex(value: object, name: str) -> str:
    normalized = str(value or "").casefold()
    if _HEX64.fullmatch(normalized) is None or normalized == "0" * 64:
        raise UserSessionOperationLedgerError(f"{name} is invalid")
    return normalized


def _counter(value: object, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_COUNTER
    ):
        raise UserSessionOperationLedgerError(f"{name} is invalid")
    return value


def _operation_id(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
        normalized = str(parsed).lower()
    except (ValueError, AttributeError) as exc:
        raise UserSessionOperationLedgerError("operation id is invalid") from exc
    if normalized != str(value) or parsed.int == 0:
        raise UserSessionOperationLedgerError("operation id is invalid")
    return normalized


def _validated_scope(value: object) -> VerifiedUserSessionOperationScope:
    if not isinstance(value, VerifiedUserSessionOperationScope):
        raise UserSessionOperationLedgerError(
            "authenticated operation scope is required"
        )
    _hex(value.installation_id, "installation id")
    _counter(value.root_epoch, "root epoch")
    _hex(value.service_boot_id, "service boot id")
    _hex(value.principal_hash, "principal hash")
    _counter(value.session_id, "session id")
    _counter(value.agent_generation, "agent generation")
    if value.connector not in _CONNECTORS:
        raise UserSessionOperationLedgerError("connector is invalid")
    _operation_id(value.operation_id)
    _hex(value.request_digest, "request digest")
    _hex(value.fence, "fence")
    if (
        value.direction != "agent_to_service"
        or value.capability != "subscription.status"
        or _counter(value.sequence, "frame sequence") != value.sequence
    ):
        raise UserSessionOperationLedgerError(
            "authenticated agent request scope is required"
        )
    return value


def _row(row: sqlite3.Row) -> UserSessionOperation:
    raw_retry = row["retry_safe"]
    if type(raw_retry) is not int or raw_retry not in {0, 1}:
        raise UserSessionOperationLedgerError("operation row is invalid")
    value = UserSessionOperation(
        installation_id=str(row["installation_id"]),
        root_epoch=int(row["root_epoch"]),
        service_boot_id=str(row["service_boot_id"]),
        principal_hash=str(row["principal_hash"]),
        session_id=int(row["session_id"]),
        agent_generation=int(row["agent_generation"]),
        connector=str(row["connector"]),
        operation_id=str(row["operation_id"]),
        request_digest=str(row["request_digest"]),
        fence=str(row["fence"]),
        state=str(row["state"]),
        retry_safe=bool(raw_retry),
        result_digest=(
            None if row["result_digest"] is None else str(row["result_digest"])
        ),
        state_sequence=int(row["state_sequence"]),
    )
    valid_state = (
        (value.state == "prepared" and value.retry_safe and value.result_digest is None
         and value.state_sequence == 1)
        or (value.state == "dispatch_authorized" and not value.retry_safe
            and value.result_digest is None and value.state_sequence >= 2)
        or (value.state == "provider_phase" and not value.retry_safe
            and value.result_digest is None and value.state_sequence >= 3)
        or (value.state == "failed_pre_submit" and value.retry_safe
            and value.result_digest is None and value.state_sequence >= 2)
        or (value.state == "submitted_unknown" and not value.retry_safe
            and value.result_digest is None and value.state_sequence >= 2)
        or (value.state == "succeeded" and not value.retry_safe
            and value.result_digest is not None and value.state_sequence >= 4)
    )
    if (
        value.connector not in _CONNECTORS
        or value.state not in _STATES
        or not valid_state
        or _operation_id(value.operation_id) != value.operation_id
        or _hex(value.installation_id, "installation id") != value.installation_id
        or _counter(value.root_epoch, "root epoch") != value.root_epoch
        or _hex(value.service_boot_id, "service boot id") != value.service_boot_id
        or _hex(value.principal_hash, "principal hash") != value.principal_hash
        or _counter(value.session_id, "session id") != value.session_id
        or _counter(value.agent_generation, "agent generation") != value.agent_generation
        or _hex(value.request_digest, "request digest") != value.request_digest
        or _hex(value.fence, "fence") != value.fence
        or (
            value.result_digest is not None
            and _hex(value.result_digest, "result digest") != value.result_digest
        )
        or not 1 <= value.state_sequence <= _MAX_COUNTER
    ):
        raise UserSessionOperationLedgerError("operation row is invalid")
    return value


@functools.lru_cache(maxsize=1)
def _expected_schema_rows() -> tuple[tuple[object, ...], ...]:
    with closing(sqlite3.connect(":memory:")) as connection:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        return tuple(
            connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
            ).fetchall()
        )


def _plain(path: Path, *, directory: bool) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise UserSessionOperationLedgerError(
            "operation ledger path is unavailable"
        ) from exc
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    ):
        raise UserSessionOperationLedgerError("operation ledger path is unsafe")
    return metadata


class UserSessionOperationLedger:
    def __init__(
        self,
        path: str | Path,
        *,
        installation_id: str,
        root_epoch: int,
    ) -> None:
        from storage.unified_db import is_unified_db_path

        target = Path(os.path.abspath(os.fspath(path)))
        self._unified = is_unified_db_path(target)
        if not Path(path).is_absolute() or (
            not self._unified and target.name.casefold() != _FILENAME
        ):
            raise UserSessionOperationLedgerError("operation ledger path is invalid")
        _plain(target.parent, directory=True)
        self.path = target
        self.installation_id = _hex(installation_id, "installation id")
        self.root_epoch = _counter(root_epoch, "root epoch")
        with _LOCK:
            try:
                if target.exists():
                    _plain(target, directory=False)
                    with closing(self._connect(create=False)) as connection:
                        if self._unified and not self._owned_schema_rows(connection):
                            self._create(connection)
                        self._validate(connection)
                else:
                    with closing(self._connect(create=True)) as connection:
                        self._create(connection)
                        self._validate(connection)
            except UserSessionOperationLedgerError:
                raise
            except (OSError, sqlite3.Error, ValueError) as exc:
                raise UserSessionOperationLedgerError(
                    "operation ledger is unavailable"
                ) from exc
        self._check_size()

    @staticmethod
    def _owned_schema_rows(
        connection: sqlite3.Connection,
    ) -> tuple[tuple[Any, ...], ...]:
        owned_tables = frozenset({"ledger_meta", "operations"})
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
            ).fetchall()
            if str(row[2]) in owned_tables
        )

    def _check_size(self) -> None:
        metadata = _plain(self.path, directory=False)
        if not self._unified and not 1 <= int(metadata.st_size) <= _MAX_BYTES:
            raise UserSessionOperationLedgerError(
                "operation ledger exceeds its byte limit"
            )

    def _connect(self, *, create: bool) -> sqlite3.Connection:
        mode = "rwc" if create else "rw"
        connection = sqlite3.connect(
            f"{self.path.as_uri()}?mode={mode}",
            uri=True,
            timeout=5.0 if self._unified else 1.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={5000 if self._unified else 1000}")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA foreign_keys=ON")
        if self._unified:
            from storage.unified_db import ensure_unified_wal

            ensure_unified_wal(connection, busy_timeout_ms=5000)
        else:
            mode_row = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
            if mode_row is None or str(mode_row[0]).casefold() != "delete":
                connection.close()
                raise UserSessionOperationLedgerError(
                    "operation ledger journal mode is invalid"
                )
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _create(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            if not self._unified:
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO ledger_meta(singleton,installation_id,root_epoch,"
                "row_count,mutation_sequence) VALUES(1,?,?,0,0)",
                (self.installation_id, self.root_epoch),
            )
            self._check_capacity(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _validate(self, connection: sqlite3.Connection) -> None:
        quick = tuple(
            str(row[0]) for row in connection.execute("PRAGMA quick_check").fetchall()
        )
        if self._unified:
            schema = self._owned_schema_rows(connection)
            identity_ok = True
        else:
            application = connection.execute("PRAGMA application_id").fetchone()
            version = connection.execute("PRAGMA user_version").fetchone()
            identity_ok = (
                application is not None
                and int(application[0]) == _APPLICATION_ID
                and version is not None
                and int(version[0]) == _SCHEMA_VERSION
            )
            schema = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
                ).fetchall()
            )
        meta = connection.execute(
            "SELECT installation_id,root_epoch,row_count,mutation_sequence "
            "FROM ledger_meta WHERE singleton=1"
        ).fetchall()
        if (
            not identity_ok
            or quick != ("ok",)
            or schema != _expected_schema_rows()
            or len(meta) != 1
        ):
            raise UserSessionOperationLedgerError(
                "operation ledger schema or integrity is invalid"
            )
        installation, epoch, row_count, mutation_sequence = tuple(meta[0])
        actual_count = int(
            connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        )
        if (
            str(installation) != self.installation_id
            or int(epoch) != self.root_epoch
            or isinstance(row_count, bool)
            or not isinstance(row_count, int)
            or int(row_count) != actual_count
            or isinstance(mutation_sequence, bool)
            or not isinstance(mutation_sequence, int)
            or not 0 <= int(mutation_sequence) <= _MAX_COUNTER
        ):
            raise UserSessionOperationLedgerError(
                "operation ledger authority is invalid"
            )
        for row in connection.execute("SELECT * FROM operations").fetchall():
            value = _row(row)
            if (
                value.installation_id != self.installation_id
                or value.root_epoch != self.root_epoch
            ):
                raise UserSessionOperationLedgerError(
                    "operation ledger row authority is invalid"
                )
        self._check_capacity(connection)

    @staticmethod
    def _check_capacity(connection: sqlite3.Connection) -> None:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size < 512 or page_count < 1 or page_size * page_count > _MAX_BYTES:
            raise UserSessionOperationLedgerError(
                "operation ledger exceeds its byte limit"
            )

    def _scope(self, scope: object) -> VerifiedUserSessionOperationScope:
        value = _validated_scope(scope)
        if (
            value.installation_id != self.installation_id
            or value.root_epoch != self.root_epoch
        ):
            raise UserSessionOperationLedgerError(
                "operation scope authority is unavailable"
            )
        return value

    @staticmethod
    def _scope_values(scope: VerifiedUserSessionOperationScope) -> tuple[object, ...]:
        return (
            scope.installation_id,
            scope.root_epoch,
            scope.service_boot_id,
            scope.principal_hash,
            scope.session_id,
            scope.agent_generation,
            scope.connector,
            scope.operation_id,
            scope.request_digest,
            scope.fence,
        )

    @classmethod
    def _select(
        cls,
        connection: sqlite3.Connection,
        scope: VerifiedUserSessionOperationScope,
    ):
        return connection.execute(
            "SELECT * FROM operations WHERE installation_id=? AND root_epoch=? "
            "AND service_boot_id=? AND principal_hash=? AND session_id=? "
            "AND agent_generation=? AND connector=? AND operation_id=? "
            "AND request_digest=? AND fence=?",
            cls._scope_values(scope),
        ).fetchone()

    @staticmethod
    def _collision(
        connection: sqlite3.Connection,
        scope: VerifiedUserSessionOperationScope,
    ):
        return connection.execute(
            "SELECT 1 FROM operations WHERE installation_id=? AND principal_hash=? "
            "AND connector=? AND operation_id=?",
            (
                scope.installation_id,
                scope.principal_hash,
                scope.connector,
                scope.operation_id,
            ),
        ).fetchone()

    def _open_validated(self) -> sqlite3.Connection:
        _plain(self.path, directory=False)
        connection = self._connect(create=False)
        try:
            self._validate(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def get(self, scope: VerifiedUserSessionOperationScope) -> UserSessionOperation:
        bound = self._scope(scope)
        with _LOCK, closing(self._open_validated()) as connection:
            row = self._select(connection, bound)
        if row is None:
            raise UserSessionOperationLedgerError("operation is unavailable")
        return _row(row)

    def prepare(
        self, scope: VerifiedUserSessionOperationScope
    ) -> UserSessionOperation:
        bound = self._scope(scope)
        with _LOCK, closing(self._open_validated()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._select(connection, bound)
                if existing is not None:
                    current = _row(existing)
                    connection.commit()
                    return current
                if self._collision(connection, bound) is not None:
                    raise UserSessionOperationConflict(
                        "operation id differs from its original authenticated scope"
                    )
                connection.execute(
                    "INSERT INTO operations(installation_id,root_epoch,service_boot_id,"
                    "principal_hash,session_id,agent_generation,connector,operation_id,"
                    "request_digest,fence,state,retry_safe,result_digest,state_sequence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,'prepared',1,NULL,1)",
                    self._scope_values(bound),
                )
                self._check_capacity(connection)
                row = self._select(connection, bound)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._check_size()
        if row is None:
            raise UserSessionOperationLedgerError("operation write was not durable")
        return _row(row)

    def _transition(
        self,
        *,
        scope: VerifiedUserSessionOperationScope,
        from_state: str,
        to_state: str,
        retry_safe: bool,
        result_digest: str | None = None,
        idempotent_terminal: bool = False,
    ) -> UserSessionOperation:
        bound = self._scope(scope)
        result = None if result_digest is None else _hex(result_digest, "result digest")
        with _LOCK, closing(self._open_validated()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = self._select(connection, bound)
                if row is None:
                    raise UserSessionOperationLedgerError("operation is unavailable")
                current = _row(row)
                if current.state == to_state:
                    if idempotent_terminal and current.result_digest == result:
                        connection.commit()
                        return current
                    raise UserSessionOperationConflict("operation state changed")
                if current.state != from_state:
                    raise UserSessionOperationConflict("operation state changed")
                connection.execute(
                    "UPDATE operations SET state=?,retry_safe=?,result_digest=?,"
                    "state_sequence=state_sequence+1 WHERE installation_id=? "
                    "AND root_epoch=? AND service_boot_id=? AND principal_hash=? "
                    "AND session_id=? AND agent_generation=? AND connector=? "
                    "AND operation_id=? AND request_digest=? AND fence=? AND state=?",
                    (
                        to_state,
                        int(retry_safe),
                        result,
                        *self._scope_values(bound),
                        from_state,
                    ),
                )
                if int(connection.execute("SELECT changes()").fetchone()[0]) != 1:
                    raise UserSessionOperationConflict("operation state changed")
                self._check_capacity(connection)
                updated = self._select(connection, bound)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._check_size()
        if updated is None:
            raise UserSessionOperationLedgerError("operation write was not durable")
        return _row(updated)

    def authorize_dispatch(
        self, scope: VerifiedUserSessionOperationScope
    ) -> UserSessionOperation:
        return self._transition(
            scope=scope,
            from_state="prepared",
            to_state="dispatch_authorized",
            retry_safe=False,
        )

    def mark_provider_phase(
        self, scope: VerifiedUserSessionOperationScope
    ) -> UserSessionOperation:
        return self._transition(
            scope=scope,
            from_state="dispatch_authorized",
            to_state="provider_phase",
            retry_safe=False,
        )

    def mark_succeeded(
        self,
        scope: VerifiedUserSessionOperationScope,
        *,
        result_digest: str,
    ) -> UserSessionOperation:
        return self._transition(
            scope=scope,
            from_state="provider_phase",
            to_state="succeeded",
            retry_safe=False,
            result_digest=result_digest,
            idempotent_terminal=True,
        )

    def mark_disconnect(
        self, scope: VerifiedUserSessionOperationScope
    ) -> UserSessionOperation:
        bound = self._scope(scope)
        with _LOCK, closing(self._open_validated()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = self._select(connection, bound)
                if row is None:
                    raise UserSessionOperationLedgerError("operation is unavailable")
                current = _row(row)
                if current.state in _TERMINAL:
                    connection.commit()
                    return current
                if current.state == "prepared":
                    next_state, retry_safe = "failed_pre_submit", True
                elif current.state in {"dispatch_authorized", "provider_phase"}:
                    next_state, retry_safe = "submitted_unknown", False
                else:
                    raise UserSessionOperationConflict("operation state changed")
                connection.execute(
                    "UPDATE operations SET state=?,retry_safe=?,result_digest=NULL,"
                    "state_sequence=state_sequence+1 WHERE installation_id=? "
                    "AND root_epoch=? AND service_boot_id=? AND principal_hash=? "
                    "AND session_id=? AND agent_generation=? AND connector=? "
                    "AND operation_id=? AND request_digest=? AND fence=? AND state=?",
                    (
                        next_state,
                        int(retry_safe),
                        *self._scope_values(bound),
                        current.state,
                    ),
                )
                if int(connection.execute("SELECT changes()").fetchone()[0]) != 1:
                    raise UserSessionOperationConflict("operation state changed")
                self._check_capacity(connection)
                updated = self._select(connection, bound)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._check_size()
        if updated is None:
            raise UserSessionOperationLedgerError("operation write was not durable")
        return _row(updated)


__all__ = [
    "UserSessionOperation",
    "UserSessionOperationConflict",
    "UserSessionOperationLedger",
    "UserSessionOperationLedgerError",
]
