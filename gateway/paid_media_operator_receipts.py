"""Durable, provider-free receipts for prepared paid-media recovery.

This module is deliberately transport and provider agnostic.  It records only
public operation identifiers and SHA-256 bindings supplied by a separately
authenticated local operator boundary.  It has no import or callback capable
of reaching a paid-media provider.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Callable, Iterator, Literal


_APPLICATION_ID = 0x4E434F52  # "NCOR"
_SCHEMA_VERSION = 1
_BUSY_TIMEOUT_MS = 10_000
_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_OPERATION_ID_RE = re.compile(
    r"\Adesktop-op-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_DECISION_ID_RE = re.compile(
    r"\Aoperator-recovery-decision-v1:[0-9a-f]{64}\Z"
)
_CHALLENGE_RE = re.compile(r"\A[0-9A-F]{12}\Z")
_CONFIRMATION_PREFIX = "RECOVER PREPARED "

RecoveryDecisionState = Literal["pending", "executing", "completed"]


class PaidMediaOperatorReceiptError(RuntimeError):
    """Base class for the intentionally small, sanitized error surface."""


class PaidMediaOperatorReceiptValidationError(PaidMediaOperatorReceiptError):
    """A caller supplied a value outside the closed recovery contract."""


class PaidMediaOperatorReceiptConflict(PaidMediaOperatorReceiptError):
    """A prior decision or durable binding conflicts with this request."""


class PaidMediaOperatorReceiptUnavailable(PaidMediaOperatorReceiptError):
    """The receipt database cannot be trusted or opened."""


@dataclass(frozen=True, slots=True)
class PreparedRecoveryCandidate:
    """Digest-only binding supplied by the local recovery adjudicator."""

    operation_id: str
    candidate_sha256: str
    consent_sha256: str
    request_sha256: str
    prepared_sha256: str


@dataclass(frozen=True, slots=True)
class PreparedRecoveryDecision:
    operation_id: str
    decision_id: str
    candidate_sha256: str
    consent_sha256: str
    request_sha256: str
    prepared_sha256: str
    challenge: str
    state: RecoveryDecisionState
    created_at_ms: int
    authorized_at_ms: int | None
    completed_at_ms: int | None

    @property
    def confirmation_text(self) -> str:
        return f"{_CONFIRMATION_PREFIX}{self.challenge}"


@dataclass(frozen=True, slots=True)
class CompletedPreparedRecoveryReceipt:
    operation_id: str
    decision_id: str
    candidate_sha256: str
    result_sha256: str
    archive_receipt_sha256: str
    ack_receipt_sha256: str
    receipt_sha256: str
    created_at_ms: int
    authorized_at_ms: int
    completed_at_ms: int


_META_DDL = """
CREATE TABLE paid_media_operator_recovery_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    database_identity TEXT NOT NULL CHECK(length(database_identity) = 64)
) WITHOUT ROWID
"""

_DECISIONS_DDL = """
CREATE TABLE paid_media_operator_recovery_decisions (
    operation_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL UNIQUE,
    candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256) = 64),
    consent_sha256 TEXT NOT NULL CHECK(length(consent_sha256) = 64),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
    prepared_sha256 TEXT NOT NULL CHECK(length(prepared_sha256) = 64),
    challenge TEXT NOT NULL CHECK(length(challenge) = 12),
    state TEXT NOT NULL CHECK(state IN ('pending','executing','completed')),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    authorized_at_ms INTEGER,
    completed_at_ms INTEGER,
    result_sha256 TEXT,
    archive_receipt_sha256 TEXT,
    ack_receipt_sha256 TEXT,
    receipt_sha256 TEXT,
    CHECK(
        (state = 'pending'
         AND authorized_at_ms IS NULL
         AND completed_at_ms IS NULL
         AND result_sha256 IS NULL
         AND archive_receipt_sha256 IS NULL
         AND ack_receipt_sha256 IS NULL
         AND receipt_sha256 IS NULL)
        OR
        (state = 'executing'
         AND authorized_at_ms IS NOT NULL
         AND completed_at_ms IS NULL
         AND result_sha256 IS NULL
         AND archive_receipt_sha256 IS NULL
         AND ack_receipt_sha256 IS NULL
         AND receipt_sha256 IS NULL)
        OR
        (state = 'completed'
         AND authorized_at_ms IS NOT NULL
         AND completed_at_ms IS NOT NULL
         AND result_sha256 IS NOT NULL
         AND archive_receipt_sha256 IS NOT NULL
         AND ack_receipt_sha256 IS NOT NULL
         AND receipt_sha256 IS NOT NULL)
    )
) WITHOUT ROWID
"""

_IMMUTABLE_BINDINGS_TRIGGER_DDL = """
CREATE TRIGGER paid_media_operator_recovery_bindings_immutable
BEFORE UPDATE OF
    operation_id,
    decision_id,
    candidate_sha256,
    consent_sha256,
    request_sha256,
    prepared_sha256,
    challenge,
    created_at_ms
ON paid_media_operator_recovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'operator recovery bindings are immutable');
END
"""

_NO_DELETE_TRIGGER_DDL = """
CREATE TRIGGER paid_media_operator_recovery_no_delete
BEFORE DELETE ON paid_media_operator_recovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'operator recovery receipts are immutable');
END
"""

_SCHEMA_DDL = (
    _META_DDL,
    _DECISIONS_DDL,
    _IMMUTABLE_BINDINGS_TRIGGER_DDL,
    _NO_DELETE_TRIGGER_DDL,
)


def _schema_sql(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise sqlite3.DatabaseError("schema SQL is invalid")
    return value


@lru_cache(maxsize=1)
def _expected_schema() -> dict[tuple[str, str], tuple[str, str | None]]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for statement in _SCHEMA_DDL:
            connection.execute(statement)
        return {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_sql(row[3]),
            )
            for row in connection.execute(
                """
                SELECT type,name,tbl_name,sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type,name
                """
            ).fetchall()
        }
    finally:
        connection.close()


def _required_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise PaidMediaOperatorReceiptValidationError(
            "operator recovery request is invalid"
        )
    return value


def _required_candidate(value: object) -> PreparedRecoveryCandidate:
    if not isinstance(value, PreparedRecoveryCandidate):
        raise PaidMediaOperatorReceiptValidationError(
            "operator recovery request is invalid"
        )
    if (
        not isinstance(value.operation_id, str)
        or _OPERATION_ID_RE.fullmatch(value.operation_id) is None
    ):
        raise PaidMediaOperatorReceiptValidationError(
            "operator recovery request is invalid"
        )
    _required_digest(value.candidate_sha256)
    _required_digest(value.consent_sha256)
    _required_digest(value.request_sha256)
    _required_digest(value.prepared_sha256)
    return value


def _required_operation_id(value: object) -> str:
    if not isinstance(value, str) or _OPERATION_ID_RE.fullmatch(value) is None:
        raise PaidMediaOperatorReceiptValidationError(
            "operator recovery request is invalid"
        )
    return value


def _required_decision_id(value: object) -> str:
    if not isinstance(value, str) or _DECISION_ID_RE.fullmatch(value) is None:
        raise PaidMediaOperatorReceiptValidationError(
            "operator recovery request is invalid"
        )
    return value


def _wall_time_ms(clock: Callable[[], float]) -> int:
    value = clock()
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    milliseconds = int(value * 1000)
    if milliseconds < 0 or milliseconds > (1 << 63) - 1:
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    return milliseconds


def _random_bytes(factory: Callable[[int], bytes], size: int) -> bytes:
    value = factory(size)
    if not isinstance(value, bytes) or len(value) != size:
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    return value


def _decision_from_row(row: sqlite3.Row) -> PreparedRecoveryDecision:
    _validate_stored_row(row)
    return PreparedRecoveryDecision(
        operation_id=str(row["operation_id"]),
        decision_id=str(row["decision_id"]),
        candidate_sha256=str(row["candidate_sha256"]),
        consent_sha256=str(row["consent_sha256"]),
        request_sha256=str(row["request_sha256"]),
        prepared_sha256=str(row["prepared_sha256"]),
        challenge=str(row["challenge"]),
        state=str(row["state"]),  # type: ignore[arg-type]
        created_at_ms=int(row["created_at_ms"]),
        authorized_at_ms=(
            None
            if row["authorized_at_ms"] is None
            else int(row["authorized_at_ms"])
        ),
        completed_at_ms=(
            None if row["completed_at_ms"] is None else int(row["completed_at_ms"])
        ),
    )


def _candidate_matches(
    row: sqlite3.Row,
    candidate: PreparedRecoveryCandidate,
) -> bool:
    return all(
        hmac.compare_digest(str(row[column]), expected)
        for column, expected in (
            ("operation_id", candidate.operation_id),
            ("candidate_sha256", candidate.candidate_sha256),
            ("consent_sha256", candidate.consent_sha256),
            ("request_sha256", candidate.request_sha256),
            ("prepared_sha256", candidate.prepared_sha256),
        )
    )


def _completion_receipt_digest(
    row: sqlite3.Row,
    *,
    result_sha256: str,
    archive_receipt_sha256: str,
    ack_receipt_sha256: str,
    completed_at_ms: int,
) -> str:
    document = {
        "ackReceiptSha256": ack_receipt_sha256,
        "archiveReceiptSha256": archive_receipt_sha256,
        "authorizedAtMs": int(row["authorized_at_ms"]),
        "candidateSha256": str(row["candidate_sha256"]),
        "completedAtMs": completed_at_ms,
        "createdAtMs": int(row["created_at_ms"]),
        "decisionId": str(row["decision_id"]),
        "operationId": str(row["operation_id"]),
        "preparedSha256": str(row["prepared_sha256"]),
        "requestSha256": str(row["request_sha256"]),
        "resultSha256": result_sha256,
        "schema": "nachuan.paid-media.operator-recovery-receipt.v1",
        "consentSha256": str(row["consent_sha256"]),
    }
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _validate_stored_row(row: sqlite3.Row) -> None:
    try:
        operation_id = str(row["operation_id"])
        decision_id = str(row["decision_id"])
        challenge = str(row["challenge"])
        state = str(row["state"])
        created_at_ms = int(row["created_at_ms"])
        authorized_at_ms = (
            None
            if row["authorized_at_ms"] is None
            else int(row["authorized_at_ms"])
        )
        completed_at_ms = (
            None
            if row["completed_at_ms"] is None
            else int(row["completed_at_ms"])
        )
    except (IndexError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        ) from exc
    if (
        _OPERATION_ID_RE.fullmatch(operation_id) is None
        or _DECISION_ID_RE.fullmatch(decision_id) is None
        or _CHALLENGE_RE.fullmatch(challenge) is None
        or state not in {"pending", "executing", "completed"}
        or created_at_ms < 0
    ):
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    for column in (
        "candidate_sha256",
        "consent_sha256",
        "request_sha256",
        "prepared_sha256",
    ):
        if _DIGEST_RE.fullmatch(str(row[column])) is None:
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )
    if authorized_at_ms is not None and authorized_at_ms < created_at_ms:
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    if (
        completed_at_ms is not None
        and (
            authorized_at_ms is None
            or completed_at_ms < authorized_at_ms
        )
    ):
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    if state == "completed":
        for column in (
            "result_sha256",
            "archive_receipt_sha256",
            "ack_receipt_sha256",
            "receipt_sha256",
        ):
            if _DIGEST_RE.fullmatch(str(row[column])) is None:
                raise PaidMediaOperatorReceiptUnavailable(
                    "operator recovery receipt store is unavailable"
                )
        if completed_at_ms is None:
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )
        expected_receipt = _completion_receipt_digest(
            row,
            result_sha256=str(row["result_sha256"]),
            archive_receipt_sha256=str(row["archive_receipt_sha256"]),
            ack_receipt_sha256=str(row["ack_receipt_sha256"]),
            completed_at_ms=completed_at_ms,
        )
        if not hmac.compare_digest(expected_receipt, str(row["receipt_sha256"])):
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )


def _completed_receipt_from_row(
    row: sqlite3.Row,
) -> CompletedPreparedRecoveryReceipt:
    _validate_stored_row(row)
    required = (
        "authorized_at_ms",
        "completed_at_ms",
        "result_sha256",
        "archive_receipt_sha256",
        "ack_receipt_sha256",
        "receipt_sha256",
    )
    if str(row["state"]) != "completed" or any(
        row[column] is None for column in required
    ):
        raise PaidMediaOperatorReceiptConflict(
            "operator recovery decision is not completed"
        )
    expected_receipt = _completion_receipt_digest(
        row,
        result_sha256=str(row["result_sha256"]),
        archive_receipt_sha256=str(row["archive_receipt_sha256"]),
        ack_receipt_sha256=str(row["ack_receipt_sha256"]),
        completed_at_ms=int(row["completed_at_ms"]),
    )
    if not hmac.compare_digest(expected_receipt, str(row["receipt_sha256"])):
        raise PaidMediaOperatorReceiptUnavailable(
            "operator recovery receipt store is unavailable"
        )
    return CompletedPreparedRecoveryReceipt(
        operation_id=str(row["operation_id"]),
        decision_id=str(row["decision_id"]),
        candidate_sha256=str(row["candidate_sha256"]),
        result_sha256=str(row["result_sha256"]),
        archive_receipt_sha256=str(row["archive_receipt_sha256"]),
        ack_receipt_sha256=str(row["ack_receipt_sha256"]),
        receipt_sha256=str(row["receipt_sha256"]),
        created_at_ms=int(row["created_at_ms"]),
        authorized_at_ms=int(row["authorized_at_ms"]),
        completed_at_ms=int(row["completed_at_ms"]),
    )


class PaidMediaOperatorReceiptStore:
    """SQLite authority for one prepared-recovery decision per operation."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        wall_clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self.path = Path(path)
        self._wall_clock = wall_clock
        self._random_bytes = random_bytes
        self._provision()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            os.fspath(self.path),
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _provision(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.execute("BEGIN EXCLUSIVE")
                try:
                    application_id = int(
                        connection.execute("PRAGMA application_id").fetchone()[0]
                    )
                    user_version = int(
                        connection.execute("PRAGMA user_version").fetchone()[0]
                    )
                    objects = connection.execute(
                        """
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE name NOT LIKE 'sqlite_%'
                        """
                    ).fetchone()
                    object_count = int(objects[0]) if objects is not None else -1
                    if application_id == 0 and user_version == 0:
                        if object_count != 0:
                            raise sqlite3.DatabaseError(
                                "unidentified database is not empty"
                            )
                        for statement in _SCHEMA_DDL:
                            connection.execute(statement)
                        identity = hashlib.sha256(
                            b"nachuan-operator-recovery-database-v1\0"
                            + _random_bytes(self._random_bytes, 32)
                        ).hexdigest()
                        connection.execute(
                            """
                            INSERT INTO paid_media_operator_recovery_meta
                                (singleton,schema_version,database_identity)
                            VALUES(1,?,?)
                            """,
                            (_SCHEMA_VERSION, identity),
                        )
                        connection.execute(
                            f"PRAGMA application_id={_APPLICATION_ID}"
                        )
                        connection.execute(
                            f"PRAGMA user_version={_SCHEMA_VERSION}"
                        )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                self._validate_database(connection)
        except PaidMediaOperatorReceiptError:
            raise
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            ) from exc

    def _validate_database(self, connection: sqlite3.Connection) -> None:
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if (
            application_id != _APPLICATION_ID
            or user_version != _SCHEMA_VERSION
        ):
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )
        actual_schema = {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_sql(row[3]),
            )
            for row in connection.execute(
                """
                SELECT type,name,tbl_name,sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type,name
                """
            ).fetchall()
        }
        if actual_schema != _expected_schema():
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )
        meta = connection.execute(
            """
            SELECT schema_version,database_identity
            FROM paid_media_operator_recovery_meta
            WHERE singleton=1
            """
        ).fetchone()
        if (
            meta is None
            or int(meta["schema_version"]) != _SCHEMA_VERSION
            or _DIGEST_RE.fullmatch(str(meta["database_identity"])) is None
        ):
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )
        check = connection.execute("PRAGMA quick_check(1)").fetchone()
        if check is None or str(check[0]).lower() != "ok":
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            )

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._validate_database(connection)
                    yield connection
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        except PaidMediaOperatorReceiptError:
            raise
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise PaidMediaOperatorReceiptUnavailable(
                "operator recovery receipt store is unavailable"
            ) from exc

    def inspect(
        self,
        candidate: PreparedRecoveryCandidate,
    ) -> PreparedRecoveryDecision:
        """Create or exactly replay the sole decision for one public operation."""

        candidate = _required_candidate(candidate)
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (candidate.operation_id,),
            ).fetchone()
            if row is not None:
                if not _candidate_matches(row, candidate):
                    raise PaidMediaOperatorReceiptConflict(
                        "operator recovery decision conflicts with durable state"
                    )
                return _decision_from_row(row)

            entropy = _random_bytes(self._random_bytes, 32)
            decision_id = (
                "operator-recovery-decision-v1:"
                + hashlib.sha256(
                    b"nachuan-operator-recovery-decision-v1\0" + entropy
                ).hexdigest()
            )
            challenge = hashlib.sha256(
                b"nachuan-operator-recovery-challenge-v1\0" + entropy
            ).hexdigest()[:12].upper()
            created_at_ms = _wall_time_ms(self._wall_clock)
            connection.execute(
                """
                INSERT INTO paid_media_operator_recovery_decisions(
                    operation_id,decision_id,candidate_sha256,consent_sha256,
                    request_sha256,prepared_sha256,challenge,state,
                    created_at_ms,authorized_at_ms,completed_at_ms,
                    result_sha256,archive_receipt_sha256,ack_receipt_sha256,
                    receipt_sha256
                ) VALUES(?,?,?,?,?,?,?,'pending',?,NULL,NULL,NULL,NULL,NULL,NULL)
                """,
                (
                    candidate.operation_id,
                    decision_id,
                    candidate.candidate_sha256,
                    candidate.consent_sha256,
                    candidate.request_sha256,
                    candidate.prepared_sha256,
                    challenge,
                    created_at_ms,
                ),
            )
            inserted = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (candidate.operation_id,),
            ).fetchone()
            if inserted is None:
                raise PaidMediaOperatorReceiptUnavailable(
                    "operator recovery receipt store is unavailable"
                )
            return _decision_from_row(inserted)

    def read_decision(
        self,
        operation_id: str,
    ) -> PreparedRecoveryDecision | None:
        """Read the public decision state without creating or mutating it."""

        operation = _required_operation_id(operation_id)
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (operation,),
            ).fetchone()
            return _decision_from_row(row) if row is not None else None

    def read_completed(
        self,
        operation_id: str,
    ) -> CompletedPreparedRecoveryReceipt | None:
        """Read only a completed digest receipt for exact provider-free replay."""

        operation = _required_operation_id(operation_id)
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=? AND state='completed'
                """,
                (operation,),
            ).fetchone()
            return (
                _completed_receipt_from_row(row)
                if row is not None
                else None
            )

    def authorize(
        self,
        candidate: PreparedRecoveryCandidate,
        *,
        decision_id: str,
        confirmation_text: str,
    ) -> PreparedRecoveryDecision:
        """Consume the explicit challenge and enter the replayable execution state."""

        candidate = _required_candidate(candidate)
        decision_id = _required_decision_id(decision_id)
        if (
            not isinstance(confirmation_text, str)
            or len(confirmation_text) > 128
        ):
            raise PaidMediaOperatorReceiptValidationError(
                "operator recovery confirmation is invalid"
            )
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (candidate.operation_id,),
            ).fetchone()
            if (
                row is None
                or not _candidate_matches(row, candidate)
                or not hmac.compare_digest(str(row["decision_id"]), decision_id)
            ):
                raise PaidMediaOperatorReceiptConflict(
                    "operator recovery decision conflicts with durable state"
                )
            expected_confirmation = (
                f"{_CONFIRMATION_PREFIX}{str(row['challenge'])}"
            )
            if not hmac.compare_digest(
                expected_confirmation,
                confirmation_text,
            ):
                raise PaidMediaOperatorReceiptValidationError(
                    "operator recovery confirmation is invalid"
                )
            if str(row["state"]) == "pending":
                authorized_at_ms = max(
                    int(row["created_at_ms"]),
                    _wall_time_ms(self._wall_clock),
                )
                updated = connection.execute(
                    """
                    UPDATE paid_media_operator_recovery_decisions
                    SET state='executing',authorized_at_ms=?
                    WHERE operation_id=? AND decision_id=? AND state='pending'
                    """,
                    (
                        authorized_at_ms,
                        candidate.operation_id,
                        decision_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise PaidMediaOperatorReceiptConflict(
                        "operator recovery decision conflicts with durable state"
                    )
                row = connection.execute(
                    """
                    SELECT * FROM paid_media_operator_recovery_decisions
                    WHERE operation_id=?
                    """,
                    (candidate.operation_id,),
                ).fetchone()
            if row is None:
                raise PaidMediaOperatorReceiptUnavailable(
                    "operator recovery receipt store is unavailable"
                )
            return _decision_from_row(row)

    def complete(
        self,
        candidate: PreparedRecoveryCandidate,
        *,
        decision_id: str,
        result_sha256: str,
        archive_receipt_sha256: str,
        ack_receipt_sha256: str,
    ) -> CompletedPreparedRecoveryReceipt:
        """Commit proof digests after the local asset/archive/ACK chain succeeds."""

        candidate = _required_candidate(candidate)
        decision_id = _required_decision_id(decision_id)
        result_sha256 = _required_digest(result_sha256)
        archive_receipt_sha256 = _required_digest(archive_receipt_sha256)
        ack_receipt_sha256 = _required_digest(ack_receipt_sha256)
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (candidate.operation_id,),
            ).fetchone()
            if (
                row is None
                or not _candidate_matches(row, candidate)
                or not hmac.compare_digest(str(row["decision_id"]), decision_id)
            ):
                raise PaidMediaOperatorReceiptConflict(
                    "operator recovery decision conflicts with durable state"
                )
            state = str(row["state"])
            if state == "completed":
                if not all(
                    hmac.compare_digest(str(row[column]), expected)
                    for column, expected in (
                        ("result_sha256", result_sha256),
                        ("archive_receipt_sha256", archive_receipt_sha256),
                        ("ack_receipt_sha256", ack_receipt_sha256),
                    )
                ):
                    raise PaidMediaOperatorReceiptConflict(
                        "operator recovery completion conflicts with durable state"
                    )
                return _completed_receipt_from_row(row)
            if state != "executing" or row["authorized_at_ms"] is None:
                raise PaidMediaOperatorReceiptConflict(
                    "operator recovery decision is not authorized"
                )
            completed_at_ms = max(
                int(row["authorized_at_ms"]),
                _wall_time_ms(self._wall_clock),
            )
            receipt_sha256 = _completion_receipt_digest(
                row,
                result_sha256=result_sha256,
                archive_receipt_sha256=archive_receipt_sha256,
                ack_receipt_sha256=ack_receipt_sha256,
                completed_at_ms=completed_at_ms,
            )
            updated = connection.execute(
                """
                UPDATE paid_media_operator_recovery_decisions
                SET state='completed',completed_at_ms=?,result_sha256=?,
                    archive_receipt_sha256=?,ack_receipt_sha256=?,
                    receipt_sha256=?
                WHERE operation_id=? AND decision_id=? AND state='executing'
                """,
                (
                    completed_at_ms,
                    result_sha256,
                    archive_receipt_sha256,
                    ack_receipt_sha256,
                    receipt_sha256,
                    candidate.operation_id,
                    decision_id,
                ),
            )
            if updated.rowcount != 1:
                raise PaidMediaOperatorReceiptConflict(
                    "operator recovery decision conflicts with durable state"
                )
            completed = connection.execute(
                """
                SELECT * FROM paid_media_operator_recovery_decisions
                WHERE operation_id=?
                """,
                (candidate.operation_id,),
            ).fetchone()
            if completed is None:
                raise PaidMediaOperatorReceiptUnavailable(
                    "operator recovery receipt store is unavailable"
                )
            return _completed_receipt_from_row(completed)
