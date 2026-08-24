"""Durable, content-free orchestration for privacy rights requests.

This first production slice deliberately stores only irreversible subject and
evidence digests.  Store-specific adapters remain separate: they execute the
frozen steps and return durable receipts, while this ledger decides whether the
overall request is actually complete after crashes and retries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Literal, Sequence


RightsAction = Literal["export", "delete", "restrict"]
RightsState = Literal[
    "received",
    "identity_pending",
    "scoped",
    "executing",
    "partially_completed",
    "completed",
    "rejected_with_reason",
]
RightsOperation = Literal[
    "export",
    "notify_processor",
    "erase",
    "tombstone",
    "restrict",
    "revoke_upstream",
    "erase_local_secret",
    "reapply_tombstone",
    "unlock_restore",
]
ReceiptOutcome = Literal[
    "completed",
    "retryable_error",
    "permanent_error",
    "unknown",
    "not_applicable",
]


_REQUEST_ID_RE = re.compile(r"\Adsr-v1:[0-9a-f]{64}\Z")
_RECEIPT_ID_RE = re.compile(r"\Areceipt-v1:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9_.-]{0,127}\Z")
_ERROR_CODE_RE = re.compile(r"\A[a-z0-9][a-z0-9_.:-]{0,95}\Z")
_ACTIONS = frozenset({"export", "delete", "restrict"})
_OPERATIONS = frozenset(
    {
        "export",
        "notify_processor",
        "erase",
        "tombstone",
        "restrict",
        "revoke_upstream",
        "erase_local_secret",
        "reapply_tombstone",
        "unlock_restore",
    }
)
_OUTCOMES = frozenset(
    {
        "completed",
        "retryable_error",
        "permanent_error",
        "unknown",
        "not_applicable",
    }
)
_ACTION_OPERATIONS = {
    "export": frozenset({"export"}),
    "restrict": frozenset({"restrict", "notify_processor"}),
    "delete": _OPERATIONS - {"export"},
}
_MAX_SCOPE_STEPS = 256
_MAX_RECEIPTS_PER_STEP = 128
_MAX_REQUESTS = 100_000
_DEFAULT_MAX_MAIN_DB_BYTES = 512 * 1024 * 1024
_MIN_MAX_MAIN_DB_BYTES = 1024 * 1024
_MAX_MAX_MAIN_DB_BYTES = 8 * 1024 * 1024 * 1024
_JOURNAL_SIZE_LIMIT_BYTES = 8 * 1024 * 1024
_APPLICATION_ID = 0x4E435052  # "NCPR"
_SCHEMA_VERSION = 1
_SQLITE_INT64_MAX = (1 << 63) - 1


class PrivacyRightsUnavailable(RuntimeError):
    """The rights ledger or supplied durable contract cannot be trusted."""


class PrivacyRightsValidationError(PrivacyRightsUnavailable):
    """A caller supplied an invalid closed-schema request."""


class PrivacyRightsNotFound(PrivacyRightsUnavailable):
    """The stable rights request does not exist."""


class PrivacyRightsConflict(PrivacyRightsUnavailable):
    """A stable identifier was replayed with different semantics."""


class PrivacyRightsCapacity(PrivacyRightsConflict):
    """Bounded retry capacity is reserved for a truthful terminal receipt."""


class PrivacyRightsIncomplete(PrivacyRightsUnavailable):
    """A dependency or required receipt has not been proven complete."""


class _PrivacyDatabaseFamilyChanged(sqlite3.DatabaseError):
    """A read-only SQLite-family snapshot changed before it could be trusted."""


@dataclass(frozen=True, slots=True)
class RightsScopeStep:
    step_id: str
    store_id: str
    operation: RightsOperation
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RightsRequestSnapshot:
    request_id: str
    action: RightsAction
    state: RightsState
    scope_sha256: str | None
    total_steps: int
    completed_steps: int
    unknown_steps: int
    retryable_steps: int
    permanent_error_steps: int
    not_applicable_steps: int
    ready_to_finalize: bool
    created_at_ms: int
    updated_at_ms: int


_REQUESTS_DDL = """
CREATE TABLE IF NOT EXISTS privacy_rights_requests (
    request_id TEXT PRIMARY KEY,
    semantic_sha256 TEXT NOT NULL CHECK(length(semantic_sha256) = 64),
    action TEXT NOT NULL CHECK(action IN ('export','delete','restrict')),
    subject_digest TEXT NOT NULL CHECK(length(subject_digest) = 64),
    state TEXT NOT NULL CHECK(state IN (
        'received','identity_pending','scoped','executing',
        'partially_completed','completed','rejected_with_reason'
    )),
    identity_evidence_sha256 TEXT CHECK(
        identity_evidence_sha256 IS NULL OR length(identity_evidence_sha256) = 64
    ),
    scope_sha256 TEXT CHECK(scope_sha256 IS NULL OR length(scope_sha256) = 64),
    rejection_code TEXT CHECK(rejection_code IS NULL OR length(rejection_code) <= 96),
    rejection_evidence_sha256 TEXT CHECK(
        rejection_evidence_sha256 IS NULL OR length(rejection_evidence_sha256) = 64
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms)
) WITHOUT ROWID
"""

_STEPS_DDL = """
CREATE TABLE IF NOT EXISTS privacy_rights_scope_steps (
    request_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    store_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN (
        'export','notify_processor','erase','tombstone','restrict',
        'revoke_upstream','erase_local_secret','reapply_tombstone','unlock_restore'
    )),
    depends_on_json TEXT NOT NULL,
    PRIMARY KEY(request_id, step_id),
    UNIQUE(request_id, ordinal),
    FOREIGN KEY(request_id) REFERENCES privacy_rights_requests(request_id)
        ON DELETE RESTRICT
) WITHOUT ROWID
"""

_RECEIPTS_DDL = """
CREATE TABLE IF NOT EXISTS privacy_rights_receipts (
    request_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK(attempt >= 1),
    receipt_id TEXT NOT NULL,
    semantic_sha256 TEXT NOT NULL CHECK(length(semantic_sha256) = 64),
    outcome TEXT NOT NULL CHECK(outcome IN (
        'completed','retryable_error','permanent_error','unknown','not_applicable'
    )),
    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
    affected_count INTEGER CHECK(affected_count IS NULL OR affected_count >= 0),
    error_code TEXT,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    PRIMARY KEY(request_id, step_id, attempt),
    UNIQUE(request_id, receipt_id),
    FOREIGN KEY(request_id, step_id)
        REFERENCES privacy_rights_scope_steps(request_id, step_id)
        ON DELETE RESTRICT
) WITHOUT ROWID
"""

_EXPECTED_COLUMNS = {
    "privacy_rights_requests": [
        ("request_id", "TEXT", 1),
        ("semantic_sha256", "TEXT", 0),
        ("action", "TEXT", 0),
        ("subject_digest", "TEXT", 0),
        ("state", "TEXT", 0),
        ("identity_evidence_sha256", "TEXT", 0),
        ("scope_sha256", "TEXT", 0),
        ("rejection_code", "TEXT", 0),
        ("rejection_evidence_sha256", "TEXT", 0),
        ("created_at_ms", "INTEGER", 0),
        ("updated_at_ms", "INTEGER", 0),
    ],
    "privacy_rights_scope_steps": [
        ("request_id", "TEXT", 1),
        ("step_id", "TEXT", 2),
        ("ordinal", "INTEGER", 0),
        ("store_id", "TEXT", 0),
        ("operation", "TEXT", 0),
        ("depends_on_json", "TEXT", 0),
    ],
    "privacy_rights_receipts": [
        ("request_id", "TEXT", 1),
        ("step_id", "TEXT", 2),
        ("attempt", "INTEGER", 3),
        ("receipt_id", "TEXT", 0),
        ("semantic_sha256", "TEXT", 0),
        ("outcome", "TEXT", 0),
        ("evidence_sha256", "TEXT", 0),
        ("affected_count", "INTEGER", 0),
        ("error_code", "TEXT", 0),
        ("created_at_ms", "INTEGER", 0),
    ],
}


def _normalized_schema_sql(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise sqlite3.DatabaseError("privacy rights schema SQL is missing")
    return value


def _schema_entry_sql(value: object) -> str | None:
    return None if value is None else _normalized_schema_sql(value)


@lru_cache(maxsize=1)
def _expected_schema_sql() -> dict[tuple[str, str], tuple[str, str | None]]:
    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        reference.execute("PRAGMA foreign_keys=ON")
        reference.execute(_REQUESTS_DDL)
        reference.execute(_STEPS_DDL)
        reference.execute(_RECEIPTS_DDL)
        return {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_entry_sql(row[3]),
            )
            for row in reference.execute(
                """
                SELECT type, name, tbl_name, sql FROM sqlite_master
                ORDER BY type, name
                """
            ).fetchall()
        }
    finally:
        reference.close()


def _now_ms() -> int:
    return max(0, time.time_ns() // 1_000_000)


def _canonical_sha256(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _required_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise PrivacyRightsValidationError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _required_safe_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise PrivacyRightsValidationError(
            f"{field} must be a bounded lowercase identifier"
        )
    return value


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse_flag
    )


def _assert_non_reparse_path(path: Path) -> None:
    lexical = Path(os.path.abspath(os.fspath(path)))
    for component in reversed([lexical, *lexical.parents]):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        if _is_reparse_or_symlink(info):
            raise OSError("reparse points are forbidden in the rights-ledger path")


class PrivacyRightsLedger:
    """Content-free, SQLite-backed rights-request state machine."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 10_000,
        max_receipts_per_step: int = _MAX_RECEIPTS_PER_STEP,
        max_requests: int = _MAX_REQUESTS,
        max_main_db_bytes: int = _DEFAULT_MAX_MAIN_DB_BYTES,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.busy_timeout_ms = max(100, min(int(busy_timeout_ms), 30_000))
        self.max_receipts_per_step = max(
            2, min(int(max_receipts_per_step), _MAX_RECEIPTS_PER_STEP)
        )
        self.max_requests = max(1, min(int(max_requests), _MAX_REQUESTS))
        self.max_main_db_bytes = max(
            _MIN_MAX_MAIN_DB_BYTES,
            min(int(max_main_db_bytes), _MAX_MAX_MAIN_DB_BYTES),
        )
        try:
            self._assert_database_path()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_database_path()
            # Classify through a genuinely read-only handle.  immutable=1 is
            # safe only when no SQLite sidecar exists because it deliberately
            # ignores committed WAL frames.  A complete WAL+SHM pair is read
            # through mode=ro so rejecting a foreign logical schema never
            # opens a writer that could checkpoint or delete its evidence.
            (
                preflight_kind,
                preflight_identity,
                preflight_family,
            ) = self._stabilized_database_preflight()
            if self._database_family_presence() != preflight_family:
                (
                    preflight_kind,
                    preflight_identity,
                    preflight_family,
                ) = self._stabilized_database_preflight()
            with self._connection(apply_storage_profile=False) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    database_kind = self._classify_database(connection)
                    opened_identity = os.lstat(self.path)
                    if preflight_identity is not None and not os.path.samestat(
                        preflight_identity, opened_identity
                    ):
                        raise sqlite3.DatabaseError(
                            "privacy rights database identity changed before locked open"
                        )
                    converged_by_peer = (
                        preflight_kind in {"empty", "legacy_empty"}
                        and database_kind == "established"
                    )
                    if database_kind != preflight_kind and not converged_by_peer:
                        raise sqlite3.DatabaseError(
                            "privacy rights database changed during initialization"
                        )
                    if database_kind == "empty":
                        connection.execute(_REQUESTS_DDL)
                        connection.execute(_STEPS_DDL)
                        connection.execute(_RECEIPTS_DDL)
                        self._validate_schema(connection)
                    if database_kind in {"empty", "legacy_empty"}:
                        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                # WAL is persistent and cannot be rolled back.  Change it only
                # after the write-lock recheck has atomically accepted/claimed
                # the database.  A crash here leaves a valid NCPR/v1 database
                # in its old mode; the next open safely retries this step.
                self._ensure_wal_mode(connection)
                self._apply_storage_profile(connection)
                if self._classify_database(connection) != "established":
                    raise sqlite3.DatabaseError(
                        "privacy rights database authority changed during setup"
                    )
        except PrivacyRightsUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PrivacyRightsUnavailable("privacy rights ledger is unavailable") from exc

    def _assert_database_path(self) -> None:
        _assert_non_reparse_path(self.path)
        for candidate in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
            Path(str(self.path) + "-journal"),
        ):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if _is_reparse_or_symlink(info) or not stat.S_ISREG(info.st_mode):
                raise OSError("rights-ledger files must be regular non-reparse files")

    def _database_family_presence(self) -> dict[str, bool]:
        self._assert_database_path()
        return {
            suffix: Path(f"{self.path}{suffix}").is_file()
            for suffix in ("", "-wal", "-shm", "-journal")
        }

    def _preflight_database_kind(
        self,
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        presence = self._database_family_presence()
        if not presence[""]:
            if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
                raise _PrivacyDatabaseFamilyChanged(
                    "privacy rights main database is missing beside unstable sidecars"
                )
            return "empty", None, presence
        if presence["-journal"]:
            raise _PrivacyDatabaseFamilyChanged(
                "privacy rights rollback journal has not stabilized"
            )
        if presence["-wal"] != presence["-shm"]:
            raise _PrivacyDatabaseFamilyChanged(
                "privacy rights WAL and SHM sidecars have not stabilized"
            )
        identity = os.lstat(self.path)
        uri = self.path.as_uri() + (
            "?mode=ro" if presence["-wal"] else "?mode=ro&immutable=1"
        )
        with closing(
            sqlite3.connect(
                uri,
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        ) as connection:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            try:
                kind = self._classify_database(connection)
            finally:
                connection.rollback()
        if self._database_family_presence() != presence:
            raise _PrivacyDatabaseFamilyChanged(
                "privacy rights database family changed during read-only preflight"
            )
        try:
            current_identity = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise _PrivacyDatabaseFamilyChanged(
                "privacy rights database disappeared during read-only preflight"
            ) from exc
        if not os.path.samestat(identity, current_identity):
            raise _PrivacyDatabaseFamilyChanged(
                "privacy rights database identity changed during read-only preflight"
            )
        return kind, identity, presence

    def _stabilized_database_preflight(
        self,
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        last_change: _PrivacyDatabaseFamilyChanged | None = None
        # Concurrent first-open owners can legitimately expose SQLite's
        # rollback journal while one peer materializes and versions the exact
        # schema.  Keep the wait bounded and read-only, but scale it like the
        # Weixin cold-start contract instead of truncating a caller's 10 s
        # busy budget to 2 s.  A stable foreign journal still fails closed at
        # the deadline.
        stabilization_seconds = max(
            2.0,
            min(10.0, (self.busy_timeout_ms / 1000) * 5.0),
        )
        deadline = time.monotonic() + stabilization_seconds
        while True:
            try:
                return self._preflight_database_kind()
            except _PrivacyDatabaseFamilyChanged as exc:
                last_change = exc
                if time.monotonic() < deadline:
                    time.sleep(0.025)
                    continue
                break
        raise sqlite3.DatabaseError(
            "privacy rights database family did not stabilize during preflight"
        ) from last_change

    @contextmanager
    def _readonly_logical_snapshot(self) -> Iterator[sqlite3.Connection]:
        presence = self._database_family_presence()
        if not presence[""]:
            raise sqlite3.DatabaseError("privacy rights database is unavailable")
        if presence["-journal"]:
            raise sqlite3.DatabaseError(
                "privacy rights rollback journal is unresolved"
            )
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "privacy rights WAL and SHM sidecars are incomplete"
            )
        identity = os.lstat(self.path)
        uri = self.path.as_uri() + (
            "?mode=ro" if presence["-wal"] else "?mode=ro&immutable=1"
        )
        with closing(
            sqlite3.connect(
                uri,
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        ) as connection:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            try:
                yield connection
            finally:
                connection.rollback()
        if self._database_family_presence() != presence:
            raise sqlite3.DatabaseError(
                "privacy rights database family changed during snapshot"
            )
        try:
            current_identity = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise sqlite3.DatabaseError(
                "privacy rights database disappeared during snapshot"
            ) from exc
        if not os.path.samestat(identity, current_identity):
            raise sqlite3.DatabaseError(
                "privacy rights database identity changed during snapshot"
            )

    @contextmanager
    def _connection(
        self,
        *,
        apply_storage_profile: bool = True,
    ) -> Iterator[sqlite3.Connection]:
        self._assert_database_path()
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            self._assert_database_path()
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            if apply_storage_profile:
                self._apply_storage_profile(connection)
            yield connection
        finally:
            connection.close()

    def _apply_storage_profile(self, connection: sqlite3.Connection) -> None:
        mode_row = connection.execute("PRAGMA journal_mode").fetchone()
        if not mode_row or str(mode_row[0]).casefold() != "wal":
            raise sqlite3.DatabaseError(
                "privacy rights database requires WAL journal mode"
            )
        connection.execute(
            f"PRAGMA journal_size_limit={_JOURNAL_SIZE_LIMIT_BYTES}"
        )
        connection.execute("PRAGMA wal_autocheckpoint=1000")
        page_size_row = connection.execute("PRAGMA page_size").fetchone()
        if not page_size_row or int(page_size_row[0]) <= 0:
            raise sqlite3.DatabaseError("privacy rights page size is invalid")
        page_size = int(page_size_row[0])
        max_pages = max(1, self.max_main_db_bytes // page_size)
        actual_row = connection.execute(
            f"PRAGMA max_page_count={max_pages}"
        ).fetchone()
        if not actual_row or int(actual_row[0]) > max_pages:
            raise sqlite3.DatabaseError(
                "privacy rights main database exceeds its page limit"
            )

    @staticmethod
    def _is_transient_lock(exc: sqlite3.OperationalError) -> bool:
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int) and (code & 0xFF) in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return True
        rendered = str(exc).casefold()
        return "locked" in rendered or "busy" in rendered

    def _ensure_wal_mode(self, connection: sqlite3.Connection) -> None:
        for attempt in range(8):
            try:
                mode_row = connection.execute("PRAGMA journal_mode=WAL").fetchone()
                if mode_row and str(mode_row[0]).casefold() == "wal":
                    return
            except sqlite3.OperationalError as exc:
                if not self._is_transient_lock(exc) or attempt >= 7:
                    raise
            if attempt >= 7:
                break
            time.sleep(min(0.5, 0.01 * (2**attempt)))
        raise sqlite3.DatabaseError(
            "privacy rights database requires WAL journal mode"
        )

    def _classify_database(self, connection: sqlite3.Connection) -> str:
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        objects = {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_entry_sql(row[3]),
            )
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql FROM sqlite_master
                ORDER BY type, name
                """
            ).fetchall()
        }
        expected = _expected_schema_sql()
        if application_id == 0 and user_version == 0:
            if not objects:
                return "empty"
            if objects == expected:
                self._validate_schema(connection)
                if any(
                    connection.execute(
                        f"SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)"
                    ).fetchone()[0]
                    for table in _EXPECTED_COLUMNS
                ):
                    raise sqlite3.DatabaseError(
                        "unversioned privacy rights data requires explicit migration"
                    )
                return "legacy_empty"
            raise sqlite3.DatabaseError(
                "unversioned privacy rights database is partial or mixed"
            )
        if (
            application_id == _APPLICATION_ID
            and user_version == _SCHEMA_VERSION
        ):
            self._validate_schema(connection)
            return "established"
        raise sqlite3.DatabaseError("privacy rights database identity is incompatible")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            # Persistent profile PRAGMAs are allowed only after the locked
            # exact-family recheck.  A runtime identity/schema replacement is
            # rejected before max_page_count or journal controls can touch it.
            with self._connection(apply_storage_profile=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    if self._classify_database(connection) != "established":
                        raise sqlite3.DatabaseError(
                            "privacy rights runtime authority changed"
                        )
                    self._apply_storage_profile(connection)
                    yield connection
                    connection.commit()
                except PrivacyRightsUnavailable:
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        pass
                    raise
                except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                    try:
                        connection.rollback()
                    except sqlite3.Error:
                        pass
                    raise PrivacyRightsUnavailable(
                        "privacy rights ledger is unavailable"
                    ) from exc
        except PrivacyRightsUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PrivacyRightsUnavailable("privacy rights ledger is unavailable") from exc

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        check = connection.execute("PRAGMA quick_check").fetchone()
        if not check or check[0] != "ok":
            raise sqlite3.DatabaseError("privacy rights integrity check failed")
        foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign:
            raise sqlite3.DatabaseError("privacy rights foreign-key check failed")
        actual_schema = {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_entry_sql(row[3]),
            )
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql FROM sqlite_master
                ORDER BY type, name
                """
            ).fetchall()
        }
        if actual_schema != _expected_schema_sql():
            raise sqlite3.DatabaseError("unexpected privacy rights schema objects")
        for table, expected in _EXPECTED_COLUMNS.items():
            actual = [
                (str(row[1]), str(row[2]).upper(), int(row[5]))
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            if actual != expected:
                raise sqlite3.DatabaseError(f"unexpected privacy rights schema: {table}")

    @staticmethod
    def _request_id(value: object) -> str:
        if not isinstance(value, str) or _REQUEST_ID_RE.fullmatch(value) is None:
            raise PrivacyRightsValidationError(
                "request_id must be dsr-v1 followed by 64 lowercase hex digits"
            )
        return value

    @staticmethod
    def _receipt_id(value: object) -> str:
        if not isinstance(value, str) or _RECEIPT_ID_RE.fullmatch(value) is None:
            raise PrivacyRightsValidationError(
                "receipt_id must be receipt-v1 followed by 64 lowercase hex digits"
            )
        return value

    @staticmethod
    def _action(value: object) -> RightsAction:
        if not isinstance(value, str) or value not in _ACTIONS:
            raise PrivacyRightsValidationError(
                "action must be export, delete, or restrict"
            )
        return value  # type: ignore[return-value]

    def submit(
        self,
        *,
        request_id: str,
        action: RightsAction,
        subject_digest: str,
    ) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        action = self._action(action)
        subject_digest = _required_digest(subject_digest, "subject_digest")
        semantic_sha256 = _canonical_sha256(
            b"nachuan-privacy-rights-request-v1\0",
            {"action": action, "subject_digest": subject_digest},
        )
        now = _now_ms()
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT semantic_sha256 FROM privacy_rights_requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != semantic_sha256:
                    raise PrivacyRightsConflict(
                        "request_id was already used for different semantics"
                    )
                return self._snapshot(connection, request_id)
            request_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM privacy_rights_requests"
                ).fetchone()[0]
            )
            if request_count >= self.max_requests:
                raise PrivacyRightsCapacity("privacy rights request capacity is full")
            connection.execute(
                """
                INSERT INTO privacy_rights_requests(
                    request_id, semantic_sha256, action, subject_digest, state,
                    created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, ?, 'identity_pending', ?, ?)
                """,
                (request_id, semantic_sha256, action, subject_digest, now, now),
            )
            return self._snapshot(connection, request_id)

    def verify_identity(
        self,
        *,
        request_id: str,
        evidence_sha256: str,
    ) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        evidence_sha256 = _required_digest(evidence_sha256, "evidence_sha256")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT identity_evidence_sha256, state
                FROM privacy_rights_requests WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None:
                raise PrivacyRightsNotFound("rights request not found")
            existing, state = row
            if existing is not None:
                if str(existing) != evidence_sha256:
                    raise PrivacyRightsConflict(
                        "identity evidence conflicts with the frozen request"
                    )
                return self._snapshot(connection, request_id)
            if str(state) == "rejected_with_reason":
                raise PrivacyRightsConflict("rejected request cannot be re-verified")
            connection.execute(
                """
                UPDATE privacy_rights_requests
                SET identity_evidence_sha256 = ?,
                    updated_at_ms = MAX(updated_at_ms, ?)
                WHERE request_id = ?
                """,
                (evidence_sha256, _now_ms(), request_id),
            )
            return self._snapshot(connection, request_id)

    def _normalize_scope(
        self,
        *,
        action: RightsAction,
        steps: Sequence[RightsScopeStep],
    ) -> list[RightsScopeStep]:
        if isinstance(steps, (str, bytes)) or not 1 <= len(steps) <= _MAX_SCOPE_STEPS:
            raise PrivacyRightsValidationError("scope must contain 1 to 256 steps")
        normalized: dict[str, RightsScopeStep] = {}
        for candidate in steps:
            if not isinstance(candidate, RightsScopeStep):
                raise PrivacyRightsValidationError("scope contains an invalid step")
            step_id = _required_safe_id(candidate.step_id, "step_id")
            store_id = _required_safe_id(candidate.store_id, "store_id")
            operation = str(candidate.operation)
            if operation not in _ACTION_OPERATIONS[action]:
                raise PrivacyRightsValidationError(
                    f"scope operation is invalid for {action}"
                )
            if isinstance(candidate.depends_on, (str, bytes)):
                raise PrivacyRightsValidationError(
                    "depends_on must be a list of step ids"
                )
            dependencies = tuple(
                sorted({_required_safe_id(value, "dependency") for value in candidate.depends_on})
            )
            if step_id in normalized:
                raise PrivacyRightsValidationError(
                    "scope step_id values must be unique"
                )
            normalized[step_id] = RightsScopeStep(
                step_id=step_id,
                store_id=store_id,
                operation=operation,  # type: ignore[arg-type]
                depends_on=dependencies,
            )

        for step in normalized.values():
            if step.step_id in step.depends_on:
                raise PrivacyRightsValidationError(
                    "scope step cannot depend on itself"
                )
            missing = [value for value in step.depends_on if value not in normalized]
            if missing:
                raise PrivacyRightsValidationError(
                    "scope dependency is not in the frozen scope"
                )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise PrivacyRightsValidationError(
                    "scope dependency cycle is forbidden"
                )
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in normalized[step_id].depends_on:
                visit(dependency)
            visiting.remove(step_id)
            visited.add(step_id)

        for step_id in normalized:
            visit(step_id)

        for step in normalized.values():
            dependency_steps = [normalized[value] for value in step.depends_on]
            if step.operation == "erase_local_secret" and not any(
                value.store_id == step.store_id
                and value.operation == "revoke_upstream"
                for value in dependency_steps
            ):
                raise PrivacyRightsValidationError(
                    "erase_local_secret requires an upstream revocation dependency"
                )
            if step.operation == "unlock_restore" and not any(
                value.store_id == step.store_id
                and value.operation == "reapply_tombstone"
                for value in dependency_steps
            ):
                raise PrivacyRightsValidationError(
                    "unlock_restore requires a tombstone reapplication dependency"
                )

        return [normalized[step_id] for step_id in sorted(normalized)]

    def freeze_scope(
        self,
        *,
        request_id: str,
        steps: Sequence[RightsScopeStep],
    ) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        with self._transaction() as connection:
            request = connection.execute(
                """
                SELECT action, state, identity_evidence_sha256, scope_sha256
                FROM privacy_rights_requests WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if request is None:
                raise PrivacyRightsNotFound("rights request not found")
            action = self._action(str(request[0]))
            normalized = self._normalize_scope(action=action, steps=steps)
            document = [
                {
                    "step_id": step.step_id,
                    "store_id": step.store_id,
                    "operation": step.operation,
                    "depends_on": list(step.depends_on),
                }
                for step in normalized
            ]
            scope_sha256 = _canonical_sha256(
                b"nachuan-privacy-rights-scope-v1\0",
                {"action": action, "steps": document},
            )
            existing_scope = request[3]
            if existing_scope is not None:
                if str(existing_scope) != scope_sha256:
                    raise PrivacyRightsConflict(
                        "scope is already frozen with different semantics"
                    )
                return self._snapshot(connection, request_id)
            if request[2] is None:
                raise PrivacyRightsIncomplete(
                    "identity evidence is required before scope enumeration"
                )
            if str(request[1]) != "identity_pending":
                raise PrivacyRightsConflict("request state cannot accept a new scope")
            for ordinal, step in enumerate(normalized):
                connection.execute(
                    """
                    INSERT INTO privacy_rights_scope_steps(
                        request_id, step_id, ordinal, store_id, operation,
                        depends_on_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_id,
                        step.step_id,
                        ordinal,
                        step.store_id,
                        step.operation,
                        json.dumps(
                            list(step.depends_on),
                            ensure_ascii=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
            connection.execute(
                """
                UPDATE privacy_rights_requests
                SET scope_sha256 = ?, state = 'scoped',
                    updated_at_ms = MAX(updated_at_ms, ?)
                WHERE request_id = ?
                """,
                (scope_sha256, _now_ms(), request_id),
            )
            return self._snapshot(connection, request_id)

    def start(self, *, request_id: str) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state FROM privacy_rights_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise PrivacyRightsNotFound("rights request not found")
            state = str(row[0])
            if state == "scoped":
                connection.execute(
                    """
                    UPDATE privacy_rights_requests
                    SET state = 'executing',
                        updated_at_ms = MAX(updated_at_ms, ?)
                    WHERE request_id = ?
                    """,
                    (_now_ms(), request_id),
                )
            elif state not in {"executing", "partially_completed", "completed"}:
                raise PrivacyRightsIncomplete("request is not ready to execute")
            return self._snapshot(connection, request_id)

    def record_receipt(
        self,
        *,
        request_id: str,
        step_id: str,
        receipt_id: str,
        outcome: ReceiptOutcome,
        evidence_sha256: str,
        affected_count: int | None = None,
        error_code: str | None = None,
    ) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        step_id = _required_safe_id(step_id, "step_id")
        receipt_id = self._receipt_id(receipt_id)
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise PrivacyRightsValidationError("receipt outcome is invalid")
        evidence_sha256 = _required_digest(evidence_sha256, "evidence_sha256")
        if affected_count is not None:
            if (
                isinstance(affected_count, bool)
                or not isinstance(affected_count, int)
                or not 0 <= affected_count <= _SQLITE_INT64_MAX
            ):
                raise PrivacyRightsValidationError("affected_count is invalid")
        if outcome == "not_applicable" and affected_count not in (None, 0):
            raise PrivacyRightsValidationError(
                "not_applicable receipt cannot report affected records"
            )
        if outcome == "completed":
            if error_code not in (None, ""):
                raise PrivacyRightsValidationError(
                    "completed receipt cannot contain an error_code"
                )
            normalized_error = None
        else:
            if not isinstance(error_code, str) or _ERROR_CODE_RE.fullmatch(error_code) is None:
                raise PrivacyRightsValidationError(
                    "non-completed receipt requires a bounded error_code"
                )
            normalized_error = error_code

        semantic_sha256 = _canonical_sha256(
            b"nachuan-privacy-rights-receipt-v1\0",
            {
                "request_id": request_id,
                "step_id": step_id,
                "receipt_id": receipt_id,
                "outcome": outcome,
                "evidence_sha256": evidence_sha256,
                "affected_count": affected_count,
                "error_code": normalized_error,
            },
        )
        with self._transaction() as connection:
            replay = connection.execute(
                """
                SELECT semantic_sha256 FROM privacy_rights_receipts
                WHERE request_id = ? AND receipt_id = ?
                """,
                (request_id, receipt_id),
            ).fetchone()
            if replay is not None:
                if str(replay[0]) != semantic_sha256:
                    raise PrivacyRightsConflict(
                        "receipt_id was already used for different semantics"
                    )
                return self._snapshot(connection, request_id)

            request = connection.execute(
                """
                SELECT state, updated_at_ms FROM privacy_rights_requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if request is None:
                raise PrivacyRightsNotFound("rights request not found")
            if str(request[0]) not in {"executing", "partially_completed"}:
                raise PrivacyRightsConflict("request is not accepting receipts")
            step = connection.execute(
                """
                SELECT depends_on_json FROM privacy_rights_scope_steps
                WHERE request_id = ? AND step_id = ?
                """,
                (request_id, step_id),
            ).fetchone()
            if step is None:
                raise PrivacyRightsConflict("receipt step is outside frozen scope")
            latest = connection.execute(
                """
                SELECT attempt, outcome, created_at_ms
                FROM privacy_rights_receipts
                WHERE request_id = ? AND step_id = ?
                ORDER BY attempt DESC LIMIT 1
                """,
                (request_id, step_id),
            ).fetchone()
            if latest is not None and str(latest[1]) == "completed":
                raise PrivacyRightsConflict("step already has a completed receipt")
            if latest is not None and str(latest[1]) == "permanent_error":
                raise PrivacyRightsConflict(
                    "step has a permanent error and requires reasoned request rejection"
                )
            if latest is not None and str(latest[1]) == "not_applicable":
                raise PrivacyRightsConflict("step is terminally not applicable")
            next_attempt = 1 if latest is None else int(latest[0]) + 1
            if next_attempt > self.max_receipts_per_step:
                raise PrivacyRightsCapacity("receipt retry capacity is exhausted")
            if (
                next_attempt == self.max_receipts_per_step
                and outcome in {"retryable_error", "unknown"}
            ):
                raise PrivacyRightsCapacity(
                    "final receipt slot is reserved for a truthful terminal outcome"
                )

            dependencies = json.loads(str(step[0]))
            dependency_outcomes: list[str | None] = []
            for dependency in dependencies:
                dependency_receipt = connection.execute(
                    """
                    SELECT outcome FROM privacy_rights_receipts
                    WHERE request_id = ? AND step_id = ?
                    ORDER BY attempt DESC LIMIT 1
                    """,
                    (request_id, dependency),
                ).fetchone()
                dependency_outcomes.append(
                    None if dependency_receipt is None else str(dependency_receipt[0])
                )
            if outcome == "not_applicable":
                if (
                    not dependencies
                    or any(
                        value not in {"completed", "permanent_error", "not_applicable"}
                        for value in dependency_outcomes
                    )
                    or not any(
                        value in {"permanent_error", "not_applicable"}
                        for value in dependency_outcomes
                    )
                ):
                    raise PrivacyRightsIncomplete(
                        "not_applicable requires terminal dependency evidence"
                    )
            elif any(value != "completed" for value in dependency_outcomes):
                raise PrivacyRightsIncomplete(
                    "step dependency has no completed durable receipt"
                )

            now = max(
                _now_ms(),
                int(request[1]),
                0 if latest is None else int(latest[2]),
            )
            connection.execute(
                """
                INSERT INTO privacy_rights_receipts(
                    request_id, step_id, attempt, receipt_id, semantic_sha256,
                    outcome, evidence_sha256, affected_count, error_code,
                    created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    step_id,
                    next_attempt,
                    receipt_id,
                    semantic_sha256,
                    outcome,
                    evidence_sha256,
                    affected_count,
                    normalized_error,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE privacy_rights_requests
                SET state = 'partially_completed',
                    updated_at_ms = MAX(updated_at_ms, ?)
                WHERE request_id = ?
                """,
                (now, request_id),
            )
            return self._snapshot(connection, request_id)

    def finalize(self, *, request_id: str) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        with self._transaction() as connection:
            snapshot = self._snapshot(connection, request_id)
            if snapshot.state == "completed":
                return snapshot
            if snapshot.state not in {"executing", "partially_completed"}:
                raise PrivacyRightsIncomplete("request is not ready to finalize")
            if not snapshot.ready_to_finalize:
                raise PrivacyRightsIncomplete(
                    "rights request is not complete; durable receipts are missing or non-terminal"
                )
            connection.execute(
                """
                UPDATE privacy_rights_requests
                SET state = 'completed',
                    updated_at_ms = MAX(updated_at_ms, ?)
                WHERE request_id = ?
                """,
                (_now_ms(), request_id),
            )
            return self._snapshot(connection, request_id)

    def reject(
        self,
        *,
        request_id: str,
        reason_code: str,
        evidence_sha256: str,
    ) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        if not isinstance(reason_code, str) or _ERROR_CODE_RE.fullmatch(reason_code) is None:
            raise PrivacyRightsValidationError("rejection reason_code is invalid")
        evidence_sha256 = _required_digest(evidence_sha256, "evidence_sha256")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT state, rejection_code, rejection_evidence_sha256
                FROM privacy_rights_requests WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None:
                raise PrivacyRightsNotFound("rights request not found")
            if str(row[0]) == "rejected_with_reason":
                if str(row[1]) != reason_code or str(row[2]) != evidence_sha256:
                    raise PrivacyRightsConflict(
                        "rejected request was replayed with a different reason"
                    )
                return self._snapshot(connection, request_id)
            state = str(row[0])
            if state in {"executing", "partially_completed"}:
                latest_outcomes = [
                    None if value[0] is None else str(value[0])
                    for value in connection.execute(
                        """
                        SELECT latest.outcome
                        FROM privacy_rights_scope_steps AS scope
                        LEFT JOIN privacy_rights_receipts AS latest
                            ON latest.request_id = scope.request_id
                            AND latest.step_id = scope.step_id
                            AND latest.attempt = (
                                SELECT MAX(candidate.attempt)
                                FROM privacy_rights_receipts AS candidate
                                WHERE candidate.request_id = scope.request_id
                                    AND candidate.step_id = scope.step_id
                            )
                        WHERE scope.request_id = ?
                        ORDER BY scope.ordinal
                        """,
                        (request_id,),
                    ).fetchall()
                ]
                if "permanent_error" not in latest_outcomes:
                    raise PrivacyRightsIncomplete(
                        "executing request needs a permanent error before reasoned rejection"
                    )
                if any(
                    value not in {"completed", "permanent_error", "not_applicable"}
                    for value in latest_outcomes
                ):
                    raise PrivacyRightsIncomplete(
                        "request has unresolved steps and cannot be rejected"
                    )
            elif state not in {"identity_pending", "scoped"}:
                raise PrivacyRightsConflict("request state cannot be rejected")
            connection.execute(
                """
                UPDATE privacy_rights_requests
                SET state = 'rejected_with_reason', rejection_code = ?,
                    rejection_evidence_sha256 = ?,
                    updated_at_ms = MAX(updated_at_ms, ?)
                WHERE request_id = ?
                """,
                (reason_code, evidence_sha256, _now_ms(), request_id),
            )
            return self._snapshot(connection, request_id)

    def snapshot(self, *, request_id: str) -> RightsRequestSnapshot:
        request_id = self._request_id(request_id)
        try:
            with self._readonly_logical_snapshot() as connection:
                if self._classify_database(connection) != "established":
                    raise sqlite3.DatabaseError(
                        "privacy rights snapshot authority changed"
                    )
                return self._snapshot(connection, request_id)
        except PrivacyRightsUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PrivacyRightsUnavailable("privacy rights ledger is unavailable") from exc

    def subject_digest_for_execution(self, *, request_id: str) -> str:
        """Return the stored opaque subject digest for the execution layer.

        The digest is not customer content and never leaves the process; the
        execution layer needs it to hash-match store owner columns.
        """

        request_id = self._request_id(request_id)
        try:
            with self._readonly_logical_snapshot() as connection:
                if self._classify_database(connection) != "established":
                    raise sqlite3.DatabaseError(
                        "privacy rights snapshot authority changed"
                    )
                row = connection.execute(
                    "SELECT subject_digest FROM privacy_rights_requests "
                    "WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise PrivacyRightsNotFound("rights request not found")
                return str(row[0])
        except PrivacyRightsUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PrivacyRightsUnavailable("privacy rights ledger is unavailable") from exc

    def list_scope_status(
        self, *, request_id: str
    ) -> list[tuple[RightsScopeStep, str | None]]:
        """Frozen scope steps in ordinal order with their latest receipt outcome.

        The execution layer reads this to drive store adapters; it is a
        read-only projection and never mutates request state.
        """

        request_id = self._request_id(request_id)
        try:
            with self._readonly_logical_snapshot() as connection:
                if self._classify_database(connection) != "established":
                    raise sqlite3.DatabaseError(
                        "privacy rights snapshot authority changed"
                    )
                rows = connection.execute(
                    """
                    SELECT scope.step_id, scope.store_id, scope.operation,
                           scope.depends_on_json, latest.outcome
                    FROM privacy_rights_scope_steps AS scope
                    LEFT JOIN privacy_rights_receipts AS latest
                        ON latest.request_id = scope.request_id
                        AND latest.step_id = scope.step_id
                        AND latest.attempt = (
                            SELECT MAX(candidate.attempt)
                            FROM privacy_rights_receipts AS candidate
                            WHERE candidate.request_id = scope.request_id
                                AND candidate.step_id = scope.step_id
                        )
                    WHERE scope.request_id = ?
                    ORDER BY scope.ordinal
                    """,
                    (request_id,),
                ).fetchall()
                request_row = connection.execute(
                    "SELECT 1 FROM privacy_rights_requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if request_row is None:
                    raise PrivacyRightsNotFound("rights request not found")
                return [
                    (
                        RightsScopeStep(
                            step_id=str(step_id),
                            store_id=str(store_id),
                            operation=str(operation),  # type: ignore[arg-type]
                            depends_on=tuple(
                                str(value) for value in json.loads(str(depends_on))
                            ),
                        ),
                        None if outcome is None else str(outcome),
                    )
                    for step_id, store_id, operation, depends_on, outcome in rows
                ]
        except PrivacyRightsUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PrivacyRightsUnavailable("privacy rights ledger is unavailable") from exc

    @staticmethod
    def _snapshot(
        connection: sqlite3.Connection,
        request_id: str,
    ) -> RightsRequestSnapshot:
        row = connection.execute(
            """
            SELECT action, state, scope_sha256, created_at_ms, updated_at_ms
            FROM privacy_rights_requests WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            raise PrivacyRightsNotFound("rights request not found")
        outcomes = [
            str(value[0])
            for value in connection.execute(
                """
                SELECT latest.outcome
                FROM privacy_rights_scope_steps AS scope
                LEFT JOIN privacy_rights_receipts AS latest
                    ON latest.request_id = scope.request_id
                    AND latest.step_id = scope.step_id
                    AND latest.attempt = (
                        SELECT MAX(candidate.attempt)
                        FROM privacy_rights_receipts AS candidate
                        WHERE candidate.request_id = scope.request_id
                            AND candidate.step_id = scope.step_id
                    )
                WHERE scope.request_id = ?
                ORDER BY scope.ordinal
                """,
                (request_id,),
            ).fetchall()
            if value[0] is not None
        ]
        total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM privacy_rights_scope_steps
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()[0]
        )
        completed = outcomes.count("completed")
        return RightsRequestSnapshot(
            request_id=request_id,
            action=str(row[0]),  # type: ignore[arg-type]
            state=str(row[1]),  # type: ignore[arg-type]
            scope_sha256=None if row[2] is None else str(row[2]),
            total_steps=total,
            completed_steps=completed,
            unknown_steps=outcomes.count("unknown"),
            retryable_steps=outcomes.count("retryable_error"),
            permanent_error_steps=outcomes.count("permanent_error"),
            not_applicable_steps=outcomes.count("not_applicable"),
            ready_to_finalize=total > 0 and completed == total,
            created_at_ms=int(row[3]),
            updated_at_ms=int(row[4]),
        )
