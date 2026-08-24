"""Execution layer for privacy rights on the four customer-content stores.

``gateway/privacy_rights.py`` is the durable control plane; this module is the
execution plane for the ``conversations``/``memory``/``knowledge``/``cases``
databases from ``docs/data-lifecycle.v1.json``.  Store adapters execute the
frozen scope steps and return honest outcomes — ``completed`` only with
durable proof, ``retryable_error`` for transient store contention,
``permanent_error`` for schema/authority mismatch, and ``unknown`` when the
outcome cannot be proven.  Every executed step is recorded back into the
NCPR ledger as a receipt; nothing is ever reported complete without one.

Deletion is tombstone-first: digest-only tombstones are committed to the
dedicated ``privacy_tombstones.db`` before any row is erased, so a crash can
never leave erased rows without their deletion evidence.  Backup-restore
reapplication of tombstones and external processor notification are not
closed by this slice (see the delivery report).

Subject binding follows the existing ledger convention: the opaque
``subject_digest`` is ``sha256`` of the store's owner value (``user_id`` for
memory/knowledge/cases, the ``channel:chat_id`` session key for
conversations).  The ledger stays content-free; raw owner values are only
matched in-memory during execution and returned to the caller solely for
runtime cache invalidation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal, Sequence

from gateway.privacy_rights import (
    PrivacyRightsIncomplete,
    PrivacyRightsLedger,
    RightsRequestSnapshot,
    RightsScopeStep,
)


Outcome = Literal["completed", "retryable_error", "permanent_error", "unknown"]

_REQUEST_ID_RE = re.compile(r"\Adsr-v1:([0-9a-f]{64})\Z")
_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_STORE_IDS = frozenset({"conversations", "memory", "knowledge", "cases"})
_CONVERSATIONS_APPLICATION_ID = 0x4E434356  # "NCCV" (owned by ConversationStore)
_CONVERSATIONS_USER_VERSION = 1
_MAX_OWNERS_SCAN = 100_000
_MAX_EXPORT_ROWS = 50_000
_MAX_EXPORT_BYTES = 256 * 1024 * 1024
_MAX_RETENTION_AGE_SECONDS = 100 * 365 * 86400
_TOMBSTONE_APPLICATION_ID = 0x4E435054  # "NCPT"
_TOMBSTONE_SCHEMA_VERSION = 1
_TOMBSTONE_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-privacy-tombstone-schema-v1"
).hexdigest()
_ROW_DOMAIN = b"nachuan-privacy-tombstone-row-v1\x00"
_TOMBSTONE_DOMAIN = b"nachuan-privacy-tombstone-v1\x00"
_RUN_DOMAIN = b"nachuan-privacy-tombstone-run-v1\x00"
_EVIDENCE_DOMAIN = b"nachuan-privacy-execution-evidence-v1\x00"


def subject_digest_for(owner: str) -> str:
    """Derive the irreversible subject digest for a store owner value."""

    if not isinstance(owner, str) or not owner:
        raise ValueError("owner must be a non-empty string")
    return hashlib.sha256(owner.encode("utf-8")).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _evidence_digest(document: Any) -> str:
    return hashlib.sha256(_EVIDENCE_DOMAIN + _canonical_bytes(document)).hexdigest()


def _row_identity(store_id: str, table: str, primary_key: object) -> str:
    return hashlib.sha256(
        _ROW_DOMAIN
        + store_id.encode("utf-8")
        + b"\x00"
        + table.encode("utf-8")
        + b"\x00"
        + str(primary_key).encode("utf-8")
    ).hexdigest()


class PrivacyExecutionError(RuntimeError):
    """Base class for adapter-level execution failures."""


class PrivacyStoreLocked(PrivacyExecutionError):
    """The target store is write-locked by another connection."""


class PrivacyStoreUnavailable(PrivacyExecutionError):
    """The target store file exists but cannot be opened safely."""


class PrivacyStoreSchemaMismatch(PrivacyExecutionError):
    """The target store schema is not the exact expected generation."""


class PrivacyStoreCorrupt(PrivacyExecutionError):
    """The target store bytes failed SQLite integrity reads."""


class PrivacyExportConflict(PrivacyExecutionError):
    """An export bundle for this request already exists with other bytes."""


class PrivacyExportTooLarge(PrivacyExecutionError):
    """The subject scope exceeds the bounded export contract."""


def _map_sqlite_error(exc: sqlite3.Error) -> PrivacyExecutionError:
    message = str(exc).lower()
    if "locked" in message or "busy" in message:
        return PrivacyStoreLocked(str(exc))
    if "malformed" in message or "not a database" in message or "corrupt" in message:
        return PrivacyStoreCorrupt(str(exc))
    if "unable to open" in message or "disk i/o" in message:
        return PrivacyStoreUnavailable(str(exc))
    return PrivacyStoreUnavailable(str(exc))


@dataclass(frozen=True, slots=True)
class StoreStepResult:
    """One adapter execution outcome; ``affected_keys`` stays in-memory only."""

    outcome: Outcome
    evidence_sha256: str
    affected_count: int | None
    error_code: str | None
    affected_keys: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutedStep:
    step_id: str
    outcome: Outcome
    evidence_sha256: str
    affected_count: int | None
    error_code: str | None
    affected_keys: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SkippedStep:
    step_id: str
    reason: Literal["already_terminal", "no_adapter", "dependency_pending"]


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    snapshot: RightsRequestSnapshot
    executed: tuple[ExecutedStep, ...]
    skipped: tuple[SkippedStep, ...]


# ── tombstone store ──────────────────────────────────────────────────

_TOMBSTONES_DDL = """
CREATE TABLE privacy_delete_tombstones (
    tombstone_id TEXT PRIMARY KEY CHECK(length(tombstone_id)=71),
    store_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    row_identity_sha256 TEXT NOT NULL CHECK(length(row_identity_sha256)=64),
    subject_digest TEXT CHECK(subject_digest IS NULL OR length(subject_digest)=64),
    kind TEXT NOT NULL CHECK(kind IN ('rights_request','retention')),
    source_id TEXT NOT NULL CHECK(length(CAST(source_id AS BLOB)) BETWEEN 1 AND 512),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) WITHOUT ROWID
"""

_RUNS_DDL = """
CREATE TABLE privacy_tombstone_runs (
    run_id TEXT PRIMARY KEY CHECK(length(run_id)<=96),
    store_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('rights_request','retention')),
    source_id TEXT NOT NULL CHECK(length(CAST(source_id AS BLOB)) BETWEEN 1 AND 512),
    row_count INTEGER NOT NULL CHECK(row_count>=0),
    rows_sha256 TEXT NOT NULL CHECK(length(rows_sha256)=64),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
) WITHOUT ROWID
"""

_META_DDL = """
CREATE TABLE privacy_tombstone_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64)
) WITHOUT ROWID
"""

_TOMBSTONE_OBJECTS = frozenset(
    {
        "privacy_delete_tombstones",
        "privacy_tombstone_runs",
        "privacy_tombstone_meta",
    }
)


class PrivacyTombstoneStore:
    """Digest-only deletion tombstones in one dedicated, exactly-typed store."""

    def __init__(
        self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 10_000
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.busy_timeout_ms = max(100, min(int(busy_timeout_ms), 30_000))
        self._lock = threading.RLock()
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._closed:
            raise PrivacyStoreUnavailable("privacy tombstone store is closed")
        try:
            connection = sqlite3.connect(
                str(self.path), timeout=self.busy_timeout_ms / 1000
            )
        except sqlite3.Error as exc:
            raise _map_sqlite_error(exc) from exc
        try:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
            connection.commit()
        except PrivacyExecutionError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _map_sqlite_error(exc) from exc
        finally:
            connection.close()

    def _initialize(self, connection: sqlite3.Connection) -> None:
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        objects = {
            str(name)
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','index',"
                "'trigger','view')"
            ).fetchall()
            if not str(name).startswith("sqlite_")
        }
        if not objects:
            if application_id != 0 or user_version != 0:
                raise PrivacyStoreSchemaMismatch(
                    "privacy tombstone file identity conflicts"
                )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_META_DDL)
            connection.execute(_TOMBSTONES_DDL)
            connection.execute(_RUNS_DDL)
            connection.execute(
                "INSERT INTO privacy_tombstone_meta VALUES(1,?,?)",
                (_TOMBSTONE_SCHEMA_VERSION, _TOMBSTONE_SCHEMA_FINGERPRINT),
            )
            connection.execute(f"PRAGMA application_id={_TOMBSTONE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_TOMBSTONE_SCHEMA_VERSION}")
            return
        if (
            application_id != _TOMBSTONE_APPLICATION_ID
            or user_version != _TOMBSTONE_SCHEMA_VERSION
            or objects != _TOMBSTONE_OBJECTS
        ):
            raise PrivacyStoreSchemaMismatch(
                "privacy tombstone store schema is not the exact v1 generation"
            )
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint "
            "FROM privacy_tombstone_meta WHERE singleton=1"
        ).fetchone()
        if meta != (_TOMBSTONE_SCHEMA_VERSION, _TOMBSTONE_SCHEMA_FINGERPRINT):
            raise PrivacyStoreSchemaMismatch(
                "privacy tombstone store fingerprint mismatch"
            )

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def count_tombstones(self) -> int:
        """Test/inspection helper: total durable tombstone rows."""

        with self._lock, self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM privacy_delete_tombstones"
                ).fetchone()[0]
            )

    def find_run(
        self, *, store_id: str, kind: str, source_id: str
    ) -> tuple[str, int] | None:
        """Return the newest (run_id, row_count) for one source, if present."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT run_id,row_count FROM privacy_tombstone_runs "
                "WHERE store_id=? AND kind=? AND source_id=? "
                "ORDER BY created_at_ms DESC,run_id DESC LIMIT 1",
                (store_id, kind, source_id),
            ).fetchone()
            if row is None:
                return None
            return str(row[0]), int(row[1])

    def write_tombstones(
        self,
        rows: Sequence[tuple[str, object]],
        *,
        store_id: str,
        kind: Literal["rights_request", "retention"],
        source_id: str,
        subject_digest: str | None,
        now_ms: int,
    ) -> tuple[str, str]:
        """Commit per-row digest tombstones plus a run seal, idempotently.

        Returns ``(run_id, rows_sha256)``.  An exact replay (same source,
        store, row identities) reuses the durable run; a conflicting run id
        fails closed instead of overwriting evidence.
        """

        if kind not in ("rights_request", "retention"):
            raise ValueError("tombstone kind is invalid")
        if subject_digest is not None and _DIGEST_RE.fullmatch(subject_digest) is None:
            raise ValueError("tombstone subject digest is invalid")
        if not source_id or len(source_id.encode("utf-8")) > 512:
            raise ValueError("tombstone source id is invalid")
        identities = sorted(
            _row_identity(store_id, table, primary_key)
            for table, primary_key in rows
        )
        rows_sha256 = (
            hashlib.sha256(
                _ROW_DOMAIN + "\x00".join(identities).encode("ascii")
            ).hexdigest()
            if identities
            else hashlib.sha256(_ROW_DOMAIN).hexdigest()
        )
        run_id = "tmb-run-v1:" + hashlib.sha256(
            _RUN_DOMAIN
            + source_id.encode("utf-8")
            + b"\x00"
            + store_id.encode("utf-8")
            + b"\x00"
            + kind.encode("ascii")
            + b"\x00"
            + rows_sha256.encode("ascii")
        ).hexdigest()
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT row_count,rows_sha256 FROM privacy_tombstone_runs "
                "WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if existing is not None:
                if (int(existing[0]), str(existing[1])) != (len(rows), rows_sha256):
                    raise PrivacyExecutionError(
                        "tombstone run id conflicts with durable evidence"
                    )
                return run_id, rows_sha256
            connection.execute("BEGIN IMMEDIATE")
            for table, primary_key in rows:
                identity = _row_identity(store_id, table, primary_key)
                tombstone_id = "tmb-v1:" + hashlib.sha256(
                    _TOMBSTONE_DOMAIN
                    + source_id.encode("utf-8")
                    + b"\x00"
                    + identity.encode("ascii")
                ).hexdigest()
                try:
                    connection.execute(
                        "INSERT INTO privacy_delete_tombstones "
                        "(tombstone_id,store_id,table_name,row_identity_sha256,"
                        "subject_digest,kind,source_id,created_at_ms) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (
                            tombstone_id,
                            store_id,
                            table,
                            identity,
                            subject_digest,
                            kind,
                            source_id,
                            now_ms,
                        ),
                    )
                except sqlite3.IntegrityError:
                    # Exact replays are the only tolerable conflict; anything
                    # else means the durable evidence diverged.
                    existing_row = connection.execute(
                        "SELECT store_id,table_name,row_identity_sha256,"
                        "subject_digest,kind,source_id FROM privacy_delete_tombstones "
                        "WHERE tombstone_id=?",
                        (tombstone_id,),
                    ).fetchone()
                    if existing_row != (
                        store_id,
                        table,
                        identity,
                        subject_digest,
                        kind,
                        source_id,
                    ):
                        raise PrivacyExecutionError(
                            "tombstone id conflicts with durable evidence"
                        )
            connection.execute(
                "INSERT INTO privacy_tombstone_runs "
                "(run_id,store_id,kind,source_id,row_count,rows_sha256,"
                "created_at_ms) VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    store_id,
                    kind,
                    source_id,
                    len(rows),
                    rows_sha256,
                    now_ms,
                ),
            )
        return run_id, rows_sha256


# ── store adapters ───────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class _StoreSpec:
    store_id: str
    filename: str
    owner_table: str
    owner_column: str
    tables: dict[str, frozenset[str]]
    application_id: int | None
    user_version: int | None
    age_expression: str  # nullable-age SQL expression on the owner table


_STORE_SPECS: dict[str, _StoreSpec] = {
    "conversations": _StoreSpec(
        store_id="conversations",
        filename="conversations.db",
        owner_table="conv",
        owner_column="key",
        tables={"conv": frozenset({"id", "key", "role", "content", "ts"})},
        application_id=_CONVERSATIONS_APPLICATION_ID,
        user_version=_CONVERSATIONS_USER_VERSION,
        age_expression="ts",
    ),
    "memory": _StoreSpec(
        store_id="memory",
        filename="memory.db",
        owner_table="user_memory",
        owner_column="user_id",
        tables={
            "user_memory": frozenset(
                {
                    "id",
                    "user_id",
                    "text",
                    "kind",
                    "status",
                    "source",
                    "vec",
                    "created_at",
                    "updated_at",
                }
            )
        },
        application_id=None,
        user_version=None,
        age_expression="COALESCE(updated_at, created_at)",
    ),
    "knowledge": _StoreSpec(
        store_id="knowledge",
        filename="knowledge.db",
        owner_table="kb_docs",
        owner_column="user_id",
        tables={
            "kb_docs": frozenset(
                {
                    "id",
                    "user_id",
                    "title",
                    "source",
                    "chunks",
                    "created_at",
                    "status",
                    "text_hash",
                }
            ),
            "kb_chunks": frozenset(
                {"id", "user_id", "doc_id", "title", "text", "vec"}
            ),
        },
        application_id=None,
        user_version=None,
        age_expression="created_at",
    ),
    "cases": _StoreSpec(
        store_id="cases",
        filename="cases.db",
        owner_table="cases",
        owner_column="user_id",
        tables={
            "cases": frozenset(
                {"id", "user_id", "problem", "solution", "model", "created_at"}
            )
        },
        application_id=None,
        user_version=None,
        age_expression="created_at",
    ),
}


def export_scope_steps(
    store_ids: Sequence[str] = tuple(sorted(_STORE_IDS))
) -> tuple[RightsScopeStep, ...]:
    """Standard export scope: one ``export`` step per named store."""

    steps = []
    for store_id in store_ids:
        if store_id not in _STORE_IDS:
            raise ValueError(f"unknown privacy store: {store_id}")
        steps.append(
            RightsScopeStep(
                step_id=f"export-{store_id}",
                store_id=store_id,
                operation="export",
            )
        )
    return tuple(steps)


def delete_scope_steps(
    store_ids: Sequence[str] = tuple(sorted(_STORE_IDS))
) -> tuple[RightsScopeStep, ...]:
    """Standard delete scope: one ``erase`` step per named store."""

    steps = []
    for store_id in store_ids:
        if store_id not in _STORE_IDS:
            raise ValueError(f"unknown privacy store: {store_id}")
        steps.append(
            RightsScopeStep(
                step_id=f"erase-{store_id}",
                store_id=store_id,
                operation="erase",
            )
        )
    return tuple(steps)


class PrivacyExecutionEngine:
    """Drive the four customer-content store adapters for the rights ledger."""

    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        export_root: str | os.PathLike[str] | None = None,
        tombstone_path: str | os.PathLike[str] | None = None,
        batch_size: int = 256,
        busy_timeout_ms: int = 10_000,
        max_export_rows: int = _MAX_EXPORT_ROWS,
        max_export_bytes: int = _MAX_EXPORT_BYTES,
    ) -> None:
        self._data_dir = Path(os.path.abspath(os.fspath(data_dir)))
        self._export_root = (
            Path(os.path.abspath(os.fspath(export_root)))
            if export_root is not None
            else self._data_dir / "privacy-exports"
        )
        self._batch_size = max(1, min(int(batch_size), 4096))
        self._busy_timeout_ms = max(100, min(int(busy_timeout_ms), 30_000))
        self._max_export_rows = max(1, min(int(max_export_rows), _MAX_EXPORT_ROWS))
        self._max_export_bytes = max(
            1024, min(int(max_export_bytes), _MAX_EXPORT_BYTES)
        )
        self._tombstones = PrivacyTombstoneStore(
            tombstone_path
            if tombstone_path is not None
            else self._data_dir / "privacy_tombstones.db",
            busy_timeout_ms=self._busy_timeout_ms,
        )

    def close(self) -> None:
        self._tombstones.close()

    # ── store plumbing ───────────────────────────────────────────────

    def _spec(self, store_id: object) -> _StoreSpec:
        spec = _STORE_SPECS.get(str(store_id or ""))
        if spec is None:
            raise ValueError(f"unknown privacy store: {store_id}")
        return spec

    def _open_store(self, spec: _StoreSpec) -> sqlite3.Connection | None:
        path = self._data_dir / spec.filename
        try:
            if not path.is_file():
                return None
        except OSError as exc:
            raise PrivacyStoreUnavailable(str(exc)) from exc
        try:
            connection = sqlite3.connect(
                str(path), timeout=self._busy_timeout_ms / 1000
            )
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema=OFF")
        except sqlite3.Error as exc:
            raise _map_sqlite_error(exc) from exc
        try:
            if spec.application_id is not None:
                application_id = int(
                    connection.execute("PRAGMA application_id").fetchone()[0]
                )
                user_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                if (
                    application_id != spec.application_id
                    or user_version != spec.user_version
                ):
                    raise PrivacyStoreSchemaMismatch(
                        f"{spec.store_id} database identity is not the expected generation"
                    )
            for table, expected_columns in spec.tables.items():
                columns = frozenset(
                    str(row[1])
                    for row in connection.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()
                )
                if columns != expected_columns:
                    raise PrivacyStoreSchemaMismatch(
                        f"{spec.store_id}.{table} columns are not the expected closed set"
                    )
        except PrivacyExecutionError:
            connection.close()
            raise
        except sqlite3.Error as exc:
            connection.close()
            raise _map_sqlite_error(exc) from exc
        return connection

    def _matched_owners(
        self, connection: sqlite3.Connection, spec: _StoreSpec, subject_digest: str
    ) -> list[str]:
        rows = connection.execute(
            f"SELECT DISTINCT {spec.owner_column} FROM {spec.owner_table}"  # noqa: S608 — spec columns are closed constants
        ).fetchall()
        if len(rows) > _MAX_OWNERS_SCAN:
            raise PrivacyExportTooLarge("owner scan exceeds the bounded contract")
        matched = []
        for (owner,) in rows:
            if isinstance(owner, str) and subject_digest_for(owner) == subject_digest:
                matched.append(owner)
        return sorted(matched)

    # ── adapter error mapping ────────────────────────────────────────

    @staticmethod
    def _error_result(store_id: str, exc: Exception) -> StoreStepResult:
        """Map store failures to honest outcomes; never disguise as done."""

        if isinstance(exc, PrivacyStoreLocked):
            outcome: Outcome = "retryable_error"
            error_code = "store_locked"
        elif isinstance(exc, PrivacyStoreUnavailable):
            outcome = "retryable_error"
            error_code = "store_unavailable"
        elif isinstance(exc, PrivacyStoreSchemaMismatch):
            outcome = "permanent_error"
            error_code = "schema_mismatch"
        elif isinstance(exc, PrivacyStoreCorrupt):
            outcome = "permanent_error"
            error_code = "store_corrupt"
        elif isinstance(exc, PrivacyExportConflict):
            outcome = "permanent_error"
            error_code = "export_conflict"
        elif isinstance(exc, PrivacyExportTooLarge):
            outcome = "permanent_error"
            error_code = "export_too_large"
        else:
            outcome = "unknown"
            error_code = "adapter_internal_error"
        return StoreStepResult(
            outcome=outcome,
            evidence_sha256=_evidence_digest(
                {
                    "kind": "adapter_error",
                    "store_id": store_id,
                    "error_code": error_code,
                }
            ),
            affected_count=None,
            error_code=error_code,
        )

    # ── export adapter ───────────────────────────────────────────────

    def _subject_rows(
        self, connection: sqlite3.Connection, spec: _StoreSpec, owners: list[str]
    ) -> list[dict[str, Any]]:
        if not owners:
            return []
        placeholders = ",".join("?" for _ in owners)
        store_id = spec.store_id
        if store_id == "conversations":
            rows = connection.execute(
                f"SELECT id,key,role,content,ts FROM conv "  # noqa: S608
                f"WHERE key IN ({placeholders}) ORDER BY id",
                owners,
            ).fetchall()
            return [
                {"id": int(i), "key": str(k), "role": str(r), "content": str(c), "ts": float(t)}
                for i, k, r, c, t in rows
            ]
        if store_id == "memory":
            rows = connection.execute(
                f"SELECT id,text,kind,status,source,vec,created_at,updated_at "
                f"FROM user_memory WHERE user_id IN ({placeholders}) ORDER BY id",
                owners,
            ).fetchall()
            return [
                {
                    "id": int(i),
                    "text": str(text),
                    "kind": None if kind is None else str(kind),
                    "status": None if status is None else str(status),
                    "source": None if source is None else str(source),
                    "created_at": created,
                    "updated_at": updated,
                    "vec_b64": None if vec is None else base64.b64encode(bytes(vec)).decode("ascii"),
                }
                for i, text, kind, status, source, vec, created, updated in rows
            ]
        if store_id == "cases":
            rows = connection.execute(
                f"SELECT id,problem,solution,model,created_at FROM cases "
                f"WHERE user_id IN ({placeholders}) ORDER BY id",
                owners,
            ).fetchall()
            return [
                {
                    "id": int(i),
                    "problem": str(p),
                    "solution": str(s),
                    "model": None if m is None else str(m),
                    "created_at": created,
                }
                for i, p, s, m, created in rows
            ]
        # knowledge: documents with their chunks embedded
        docs = connection.execute(
            f"SELECT id,title,source,chunks,created_at,status,text_hash FROM kb_docs "
            f"WHERE user_id IN ({placeholders}) ORDER BY id",
            owners,
        ).fetchall()
        doc_ids = [int(doc[0]) for doc in docs]
        chunks_by_doc: dict[int, list[dict[str, Any]]] = {doc_id: [] for doc_id in doc_ids}
        if doc_ids:
            chunk_placeholders = ",".join("?" for _ in doc_ids)
            chunk_rows = connection.execute(
                f"SELECT id,doc_id,title,text,vec FROM kb_chunks "
                f"WHERE doc_id IN ({chunk_placeholders}) ORDER BY id",
                doc_ids,
            ).fetchall()
            for chunk_id, doc_id, title, text, vec in chunk_rows:
                chunks_by_doc.setdefault(int(doc_id), []).append(
                    {
                        "id": int(chunk_id),
                        "doc_id": int(doc_id),
                        "title": None if title is None else str(title),
                        "text": str(text),
                        "vec_b64": None if vec is None else base64.b64encode(bytes(vec)).decode("ascii"),
                    }
                )
        return [
            {
                "id": int(doc_id),
                "title": str(title),
                "source": None if source is None else str(source),
                "chunks": int(chunk_count) if chunk_count is not None else None,
                "created_at": created,
                "status": None if status is None else str(status),
                "text_hash": None if text_hash is None else str(text_hash),
                "chunk_rows": chunks_by_doc.get(int(doc_id), []),
            }
            for doc_id, title, source, chunk_count, created, status, text_hash in docs
        ]

    def export_store(
        self, *, store_id: str, subject_digest: str, request_id: str
    ) -> StoreStepResult:
        """Export one subject's rows into a deterministic, content-hashed bundle."""

        spec = self._spec(store_id)
        if _DIGEST_RE.fullmatch(str(subject_digest or "")) is None:
            raise ValueError("subject_digest must be a lowercase SHA-256 digest")
        match = _REQUEST_ID_RE.fullmatch(str(request_id or ""))
        if match is None:
            raise ValueError("request_id must be a dsr-v1 digest id")
        try:
            return self._export_impl(
                spec, subject_digest=subject_digest, request_hex=match.group(1),
                request_id=request_id,
            )
        except PrivacyExecutionError as exc:
            return self._error_result(spec.store_id, exc)

    def _export_impl(
        self,
        spec: _StoreSpec,
        *,
        subject_digest: str,
        request_hex: str,
        request_id: str,
    ) -> StoreStepResult:
        connection = self._open_store(spec)
        store_absent = connection is None
        if store_absent:
            rows: list[dict[str, Any]] = []
        else:
            assert connection is not None
            try:
                owners = self._matched_owners(connection, spec, subject_digest)
                rows = self._subject_rows(connection, spec, owners)
            except PrivacyExecutionError:
                raise
            except sqlite3.Error as exc:
                raise _map_sqlite_error(exc) from exc
            finally:
                connection.close()
        if len(rows) > self._max_export_rows:
            raise PrivacyExportTooLarge("subject export exceeds the row budget")
        document = {
            "schema": "nachuan.privacy-export.v1",
            "request_id": request_id,
            "store_id": spec.store_id,
            "subject_digest": subject_digest,
            "store_absent": store_absent,
            "row_count": len(rows),
            "rows": rows,
        }
        encoded = _canonical_bytes(document)
        if len(encoded) > self._max_export_bytes:
            raise PrivacyExportTooLarge("subject export exceeds the byte budget")
        target_dir = self._export_root / request_hex
        target = target_dir / f"{spec.store_id}.json"
        if target.is_file():
            existing = target.read_bytes()
            if existing == encoded:
                return StoreStepResult(
                    outcome="completed",
                    evidence_sha256=hashlib.sha256(existing).hexdigest(),
                    affected_count=len(rows),
                    error_code=None,
                )
            raise PrivacyExportConflict(
                "an export bundle with different bytes already exists for this request"
            )
        target_dir.mkdir(parents=True, exist_ok=True)
        temporary = target_dir / f"{spec.store_id}.json.tmp-{os.getpid()}"
        with open(temporary, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        return StoreStepResult(
            outcome="completed",
            evidence_sha256=hashlib.sha256(encoded).hexdigest(),
            affected_count=len(rows),
            error_code=None,
        )

    # ── erase adapter ────────────────────────────────────────────────

    def _subject_row_ids(
        self, connection: sqlite3.Connection, spec: _StoreSpec, owners: list[str]
    ) -> dict[str, list[int]]:
        """Row primary keys per table for the matched owners."""

        if not owners:
            return {}
        placeholders = ",".join("?" for _ in owners)
        if spec.store_id == "knowledge":
            doc_ids = [
                int(row[0])
                for row in connection.execute(
                    f"SELECT id FROM kb_docs WHERE user_id IN ({placeholders})",
                    owners,
                ).fetchall()
            ]
            chunk_ids = [
                int(row[0])
                for row in connection.execute(
                    f"SELECT id FROM kb_chunks WHERE user_id IN ({placeholders})",
                    owners,
                ).fetchall()
            ]
            result: dict[str, list[int]] = {}
            if chunk_ids:
                result["kb_chunks"] = chunk_ids
            if doc_ids:
                result["kb_docs"] = doc_ids
            return result
        ids = [
            int(row[0])
            for row in connection.execute(
                f"SELECT id FROM {spec.owner_table} "  # noqa: S608
                f"WHERE {spec.owner_column} IN ({placeholders})",
                owners,
            ).fetchall()
        ]
        return {spec.owner_table: ids} if ids else {}

    def _delete_rows(
        self,
        connection: sqlite3.Connection,
        rows_by_table: dict[str, list[int]],
    ) -> int:
        erased = 0
        order = ("kb_chunks", "kb_docs")  # children before parents
        for table in sorted(rows_by_table, key=lambda name: order.index(name) if name in order else len(order)):
            ids = rows_by_table[table]
            for start in range(0, len(ids), self._batch_size):
                batch = ids[start : start + self._batch_size]
                placeholders = ",".join("?" for _ in batch)
                cursor = connection.execute(
                    f"DELETE FROM {table} WHERE id IN ({placeholders})",  # noqa: S608 — table names are closed constants
                    batch,
                )
                erased += max(0, int(cursor.rowcount))
        return erased

    def erase_subject(
        self, *, store_id: str, subject_digest: str, request_id: str
    ) -> StoreStepResult:
        """Tombstone-first, then erase the subject's rows; prove both."""

        spec = self._spec(store_id)
        if _DIGEST_RE.fullmatch(str(subject_digest or "")) is None:
            raise ValueError("subject_digest must be a lowercase SHA-256 digest")
        if _REQUEST_ID_RE.fullmatch(str(request_id or "")) is None:
            raise ValueError("request_id must be a dsr-v1 digest id")
        try:
            return self._erase_impl(
                spec, subject_digest=subject_digest, request_id=request_id
            )
        except PrivacyExecutionError as exc:
            return self._error_result(spec.store_id, exc)

    def _erase_impl(
        self, spec: _StoreSpec, *, subject_digest: str, request_id: str
    ) -> StoreStepResult:
        connection = self._open_store(spec)
        if connection is None:
            evidence = _evidence_digest(
                {
                    "kind": "erase",
                    "store_id": spec.store_id,
                    "subject_digest": subject_digest,
                    "store_absent": True,
                    "erased": 0,
                }
            )
            return StoreStepResult(
                outcome="completed",
                evidence_sha256=evidence,
                affected_count=0,
                error_code=None,
            )
        try:
            owners = self._matched_owners(connection, spec, subject_digest)
            rows_by_table = self._subject_row_ids(connection, spec, owners)
        except PrivacyExecutionError:
            connection.close()
            raise
        except sqlite3.Error as exc:
            connection.close()
            raise _map_sqlite_error(exc) from exc
        if not rows_by_table:
            connection.close()
            prior = self._tombstones.find_run(
                store_id=spec.store_id, kind="rights_request", source_id=request_id
            )
            evidence = _evidence_digest(
                {
                    "kind": "erase",
                    "store_id": spec.store_id,
                    "subject_digest": subject_digest,
                    "erased": 0,
                    "prior_run": None if prior is None else prior[0],
                }
            )
            return StoreStepResult(
                outcome="completed",
                evidence_sha256=evidence,
                affected_count=0,
                error_code=None,
                affected_keys=tuple(owners),
            )
        flat_rows = [
            (table, primary_key)
            for table, ids in rows_by_table.items()
            for primary_key in ids
        ]
        run_id, rows_sha256 = self._tombstones.write_tombstones(
            flat_rows,
            store_id=spec.store_id,
            kind="rights_request",
            source_id=request_id,
            subject_digest=subject_digest,
            now_ms=int(time.time() * 1000),
        )
        try:
            connection.execute("BEGIN IMMEDIATE")
            erased = self._delete_rows(connection, rows_by_table)
            remaining = self._subject_row_ids(connection, spec, owners)
            if remaining:
                raise PrivacyExecutionError(
                    "subject rows remain after erase; outcome is unknown"
                )
            connection.commit()
        except PrivacyExecutionError:
            connection.rollback()
            raise PrivacyExecutionError(
                "erase post-check failed; outcome is unknown"
            )
        except sqlite3.Error as exc:
            connection.rollback()
            raise _map_sqlite_error(exc) from exc
        finally:
            connection.close()
        if self._tombstones.find_run(
            store_id=spec.store_id, kind="rights_request", source_id=request_id
        ) is None:
            raise PrivacyExecutionError("tombstone run seal is not durable")
        evidence = _evidence_digest(
            {
                "kind": "erase",
                "store_id": spec.store_id,
                "subject_digest": subject_digest,
                "erased": erased,
                "run_id": run_id,
                "rows_sha256": rows_sha256,
            }
        )
        return StoreStepResult(
            outcome="completed",
            evidence_sha256=evidence,
            affected_count=erased,
            error_code=None,
            affected_keys=tuple(owners),
        )

    # ── retention executor ───────────────────────────────────────────

    def run_retention(
        self, *, store_id: str, max_age_seconds: int, now: float | None = None
    ) -> StoreStepResult:
        """Erase rows past the retention cutoff, tombstoning every batch."""

        spec = self._spec(store_id)
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or not 1 <= max_age_seconds <= _MAX_RETENTION_AGE_SECONDS
        ):
            raise ValueError("max_age_seconds is outside the bounded contract")
        try:
            return self._retention_impl(
                spec, max_age_seconds=max_age_seconds, now=now
            )
        except PrivacyExecutionError as exc:
            return self._error_result(spec.store_id, exc)

    def _retention_impl(
        self, spec: _StoreSpec, *, max_age_seconds: int, now: float | None
    ) -> StoreStepResult:
        current = time.time() if now is None else float(now)
        cutoff = current - max_age_seconds
        connection = self._open_store(spec)
        if connection is None:
            evidence = _evidence_digest(
                {
                    "kind": "retention",
                    "store_id": spec.store_id,
                    "cutoff": cutoff,
                    "store_absent": True,
                    "erased": 0,
                }
            )
            return StoreStepResult(
                outcome="completed",
                evidence_sha256=evidence,
                affected_count=0,
                error_code=None,
            )
        erased_total = 0
        run_ids: list[str] = []
        source_label = f"retention:{spec.store_id}:{int(cutoff)}"
        try:
            while True:
                if spec.store_id == "knowledge":
                    batch_docs = [
                        int(row[0])
                        for row in connection.execute(
                            "SELECT id FROM kb_docs WHERE created_at IS NOT NULL "
                            "AND created_at < ? ORDER BY id LIMIT ?",
                            (cutoff, self._batch_size),
                        ).fetchall()
                    ]
                    if not batch_docs:
                        break
                    placeholders = ",".join("?" for _ in batch_docs)
                    chunk_ids = [
                        int(row[0])
                        for row in connection.execute(
                            f"SELECT id FROM kb_chunks WHERE doc_id IN ({placeholders})",
                            batch_docs,
                        ).fetchall()
                    ]
                    rows_by_table: dict[str, list[int]] = {}
                    if chunk_ids:
                        rows_by_table["kb_chunks"] = chunk_ids
                    rows_by_table["kb_docs"] = batch_docs
                else:
                    batch_ids = [
                        int(row[0])
                        for row in connection.execute(
                            f"SELECT id FROM {spec.owner_table} "  # noqa: S608
                            f"WHERE {spec.age_expression} IS NOT NULL "
                            f"AND {spec.age_expression} < ? "
                            f"ORDER BY id LIMIT ?",
                            (cutoff, self._batch_size),
                        ).fetchall()
                    ]
                    if not batch_ids:
                        break
                    rows_by_table = {spec.owner_table: batch_ids}
                flat_rows = [
                    (table, primary_key)
                    for table, ids in rows_by_table.items()
                    for primary_key in ids
                ]
                run_id, _rows_digest = self._tombstones.write_tombstones(
                    flat_rows,
                    store_id=spec.store_id,
                    kind="retention",
                    source_id=source_label,
                    subject_digest=None,
                    now_ms=int(time.time() * 1000),
                )
                run_ids.append(run_id)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    erased_total += self._delete_rows(connection, rows_by_table)
                    connection.commit()
                except sqlite3.Error as exc:
                    connection.rollback()
                    raise _map_sqlite_error(exc) from exc
        except PrivacyExecutionError:
            raise
        except sqlite3.Error as exc:
            raise _map_sqlite_error(exc) from exc
        finally:
            connection.close()
        evidence = _evidence_digest(
            {
                "kind": "retention",
                "store_id": spec.store_id,
                "cutoff": cutoff,
                "erased": erased_total,
                "run_ids": run_ids,
            }
        )
        return StoreStepResult(
            outcome="completed",
            evidence_sha256=evidence,
            affected_count=erased_total,
            error_code=None,
        )

    # ── rights-request execution ─────────────────────────────────────

    def _execute_step(
        self, *, step: RightsScopeStep, subject_digest: str, request_id: str
    ) -> StoreStepResult:
        if step.operation == "export":
            return self.export_store(
                store_id=step.store_id,
                subject_digest=subject_digest,
                request_id=request_id,
            )
        if step.operation == "erase":
            return self.erase_subject(
                store_id=step.store_id,
                subject_digest=subject_digest,
                request_id=request_id,
            )
        raise PrivacyExecutionError("no adapter for the frozen operation")

    def execute_request(
        self, ledger: PrivacyRightsLedger, *, request_id: str
    ) -> ExecutionReport:
        """Execute every frozen step that has an adapter; record NCPR receipts.

        Steps without an adapter, with pending dependencies or with a terminal
        receipt are reported as skipped and never receive a fabricated receipt.
        The request is never finalized here; finalization stays an explicit
        operator action gated by the ledger.
        """

        snapshot = ledger.snapshot(request_id=request_id)
        if snapshot.state not in {"executing", "partially_completed"}:
            raise PrivacyRightsIncomplete("request is not ready to execute")
        # The subject digest is stored opaque in the ledger; execution needs
        # it to match rows, so it is read back from the request row — it is a
        # digest, not content, and never leaves the process.
        subject_digest = ledger.subject_digest_for_execution(request_id=request_id)
        initial_status = ledger.list_scope_status(request_id=request_id)
        initial_outcomes = {step.step_id: outcome for step, outcome in initial_status}
        executed: list[ExecutedStep] = []
        executed_ids: set[str] = set()
        skipped_reasons: dict[str, str] = {}
        passes = 0
        while True:
            passes += 1
            progressed = False
            status = ledger.list_scope_status(request_id=request_id)
            outcomes = {step.step_id: outcome for step, outcome in status}
            for step, latest in status:
                if step.step_id in executed_ids:
                    continue
                if initial_outcomes.get(step.step_id) in {
                    "completed",
                    "permanent_error",
                    "not_applicable",
                }:
                    skipped_reasons.setdefault(step.step_id, "already_terminal")
                    continue
                if step.operation not in {"export", "erase"} or (
                    step.store_id not in _STORE_IDS
                ):
                    skipped_reasons.setdefault(step.step_id, "no_adapter")
                    continue
                dependencies_done = all(
                    outcomes.get(dependency) == "completed"
                    for dependency in step.depends_on
                )
                if not dependencies_done:
                    skipped_reasons.setdefault(step.step_id, "dependency_pending")
                    continue
                skipped_reasons.pop(step.step_id, None)
                try:
                    result = self._execute_step(
                        step=step,
                        subject_digest=subject_digest,
                        request_id=request_id,
                    )
                except Exception:  # noqa: BLE001 — unknown must never claim done
                    result = StoreStepResult(
                        outcome="unknown",
                        evidence_sha256=_evidence_digest(
                            {
                                "kind": "adapter_error",
                                "step_id": step.step_id,
                                "error_code": "adapter_internal_error",
                            }
                        ),
                        affected_count=None,
                        error_code="adapter_internal_error",
                    )
                ledger.record_receipt(
                    request_id=request_id,
                    step_id=step.step_id,
                    receipt_id=f"receipt-v1:{result.evidence_sha256}",
                    outcome=result.outcome,
                    evidence_sha256=result.evidence_sha256,
                    affected_count=result.affected_count,
                    error_code=result.error_code,
                )
                executed.append(
                    ExecutedStep(
                        step_id=step.step_id,
                        outcome=result.outcome,
                        evidence_sha256=result.evidence_sha256,
                        affected_count=result.affected_count,
                        error_code=result.error_code,
                        affected_keys=result.affected_keys,
                    )
                )
                executed_ids.add(step.step_id)
                # A completed dependency can unblock later steps in the same
                # request; retryable/unknown steps stay for the operator's
                # next execute call instead of being retried in a tight loop.
                progressed = progressed or result.outcome == "completed"
            if not progressed or passes > len(status) + 1:
                break
        return ExecutionReport(
            snapshot=ledger.snapshot(request_id=request_id),
            executed=tuple(executed),
            skipped=tuple(
                SkippedStep(step_id=step_id, reason=reason)  # type: ignore[arg-type]
                for step_id, reason in skipped_reasons.items()
            ),
        )


__all__ = [
    "ExecutedStep",
    "ExecutionReport",
    "PrivacyExecutionEngine",
    "PrivacyExecutionError",
    "PrivacyExportConflict",
    "PrivacyExportTooLarge",
    "PrivacyStoreCorrupt",
    "PrivacyStoreLocked",
    "PrivacyStoreSchemaMismatch",
    "PrivacyStoreUnavailable",
    "PrivacyTombstoneStore",
    "SkippedStep",
    "StoreStepResult",
    "delete_scope_steps",
    "export_scope_steps",
    "subject_digest_for",
]
