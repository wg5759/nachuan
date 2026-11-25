"""Content-free append-only audit truth for enterprise RAG queries."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gateway.sqlite_runtime import enable_wal_with_deadline


_APPLICATION_ID = 0x4E435241  # "NCRA"
_SCHEMA_VERSION = 1
_MAX_RECORDS = 1_000_000
_MAX_CITATION_BYTES = 8 * 1024
_MAX_DATABASE_BYTES = 512 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = frozenset({"ok", "insufficient_authorized_context", "blocked", "unavailable"})


class EnterpriseRagAuditUnavailable(RuntimeError):
    pass


def _identifier(value: object, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseRagAuditUnavailable(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EnterpriseRagAuditUnavailable(f"{field} is invalid")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True, slots=True)
class EnterpriseRagAuditEvent:
    tenant_id: str
    subject_scope_fingerprint: str
    status: Literal["ok", "insufficient_authorized_context", "blocked", "unavailable"]
    policy_epoch: int
    session_epoch: int
    query_digest: str
    requested_k: int
    authorized_chunk_count: int
    cited_chunk_ids: tuple[str, ...]
    model_id: str
    receipt_id: str
    error_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self,
            "subject_scope_fingerprint",
            _digest(self.subject_scope_fingerprint, "subject_scope_fingerprint"),
        )
        if self.status not in _STATUSES:
            raise EnterpriseRagAuditUnavailable("status is invalid")
        for name in ("policy_epoch", "session_epoch"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise EnterpriseRagAuditUnavailable(f"{name} is invalid")
        object.__setattr__(self, "query_digest", _digest(self.query_digest, "query_digest"))
        if (
            isinstance(self.requested_k, bool)
            or not isinstance(self.requested_k, int)
            or not 1 <= self.requested_k <= 20
        ):
            raise EnterpriseRagAuditUnavailable("requested_k is invalid")
        if (
            isinstance(self.authorized_chunk_count, bool)
            or not isinstance(self.authorized_chunk_count, int)
            or not 0 <= self.authorized_chunk_count <= 20
        ):
            raise EnterpriseRagAuditUnavailable("authorized_chunk_count is invalid")
        if not isinstance(self.cited_chunk_ids, tuple):
            raise EnterpriseRagAuditUnavailable("cited_chunk_ids are invalid")
        citations = tuple(_identifier(value, "cited_chunk_id") for value in self.cited_chunk_ids)
        if len(set(citations)) != len(citations) or len(citations) > self.authorized_chunk_count:
            raise EnterpriseRagAuditUnavailable("cited_chunk_ids are invalid")
        citations_json = _canonical_json(citations)
        if len(citations_json.encode("utf-8")) > _MAX_CITATION_BYTES:
            raise EnterpriseRagAuditUnavailable("cited_chunk_ids are invalid")
        object.__setattr__(self, "cited_chunk_ids", citations)
        object.__setattr__(
            self, "model_id", _identifier(self.model_id, "model_id", allow_empty=True)
        )
        object.__setattr__(self, "receipt_id", _digest(self.receipt_id, "receipt_id"))
        object.__setattr__(
            self, "error_code", _identifier(self.error_code, "error_code", allow_empty=True)
        )
        if self.status == "ok" and (
            self.authorized_chunk_count < 1 or not self.model_id or self.error_code
        ):
            raise EnterpriseRagAuditUnavailable("successful audit event is invalid")
        if self.status == "insufficient_authorized_context" and (
            self.authorized_chunk_count != 0
            or self.cited_chunk_ids
            or self.model_id
            or self.error_code not in {"", "insufficient_authorized_context"}
        ):
            raise EnterpriseRagAuditUnavailable("insufficient audit event is invalid")


_SCHEMA_DDL = f"""
CREATE TABLE enterprise_rag_audit_meta (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  record_count INTEGER NOT NULL CHECK(record_count>=0),
  max_records INTEGER NOT NULL CHECK(max_records={_MAX_RECORDS})
) WITHOUT ROWID;
INSERT INTO enterprise_rag_audit_meta VALUES(1,0,{_MAX_RECORDS});
CREATE TABLE enterprise_rag_audit_records (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL UNIQUE CHECK(length(record_id)=32 AND record_id NOT GLOB '*[^0-9a-f]*'),
  tenant_id TEXT NOT NULL CHECK(length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 128),
  subject_scope_fingerprint TEXT NOT NULL CHECK(length(subject_scope_fingerprint)=64 AND subject_scope_fingerprint NOT GLOB '*[^0-9a-f]*'),
  status TEXT NOT NULL CHECK(status IN ('ok','insufficient_authorized_context','blocked','unavailable')),
  policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=1),
  session_epoch INTEGER NOT NULL CHECK(session_epoch>=1),
  query_digest TEXT NOT NULL CHECK(length(query_digest)=64 AND query_digest NOT GLOB '*[^0-9a-f]*'),
  requested_k INTEGER NOT NULL CHECK(requested_k BETWEEN 1 AND 20),
  authorized_chunk_count INTEGER NOT NULL CHECK(authorized_chunk_count BETWEEN 0 AND 20),
  cited_chunk_ids_json TEXT NOT NULL CHECK(typeof(cited_chunk_ids_json)='text' AND length(CAST(cited_chunk_ids_json AS BLOB))<={_MAX_CITATION_BYTES}),
  model_id TEXT NOT NULL CHECK(length(CAST(model_id AS BLOB))<=128),
  receipt_id TEXT NOT NULL CHECK(length(receipt_id)=64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  error_code TEXT NOT NULL CHECK(length(CAST(error_code AS BLOB))<=128),
  previous_hmac TEXT NOT NULL CHECK(length(previous_hmac)=64 AND previous_hmac NOT GLOB '*[^0-9a-f]*'),
  record_hmac TEXT NOT NULL UNIQUE CHECK(length(record_hmac)=64 AND record_hmac NOT GLOB '*[^0-9a-f]*'),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
);
CREATE INDEX idx_enterprise_rag_audit_tenant ON enterprise_rag_audit_records(tenant_id,sequence);
CREATE TRIGGER enterprise_rag_audit_capacity BEFORE INSERT ON enterprise_rag_audit_records
BEGIN
  SELECT CASE WHEN (SELECT record_count FROM enterprise_rag_audit_meta WHERE singleton=1)>={_MAX_RECORDS}
    THEN RAISE(ABORT,'enterprise RAG audit capacity exceeded') END;
END;
CREATE TRIGGER enterprise_rag_audit_count AFTER INSERT ON enterprise_rag_audit_records
BEGIN
  UPDATE enterprise_rag_audit_meta SET record_count=record_count+1 WHERE singleton=1;
END;
CREATE TRIGGER enterprise_rag_audit_no_update BEFORE UPDATE ON enterprise_rag_audit_records
BEGIN SELECT RAISE(ABORT,'enterprise RAG audit is append-only'); END;
CREATE TRIGGER enterprise_rag_audit_no_delete BEFORE DELETE ON enterprise_rag_audit_records
BEGIN SELECT RAISE(ABORT,'enterprise RAG audit is append-only'); END;
"""


def _schema_statements(script: str) -> tuple[str, ...]:
    statements: list[str] = []
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                statements.append(statement)
            pending = ""
    if pending.strip():
        raise RuntimeError("enterprise RAG audit schema is incomplete")
    return tuple(statements)


_SCHEMA_STATEMENTS = _schema_statements(_SCHEMA_DDL)


def _install_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)


def _schema_authority() -> dict[tuple[str, str, str], str | None]:
    connection = sqlite3.connect(":memory:")
    try:
        _install_schema(connection)
        return {
            (str(row[0]), str(row[1]), str(row[2])): (
                None if row[3] is None else str(row[3])
            )
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master"
            ).fetchall()
        }
    finally:
        connection.close()


_EXPECTED_SCHEMA = _schema_authority()


class EnterpriseRagAuditLog:
    def __init__(self, path: str | Path, *, audit_key: bytes) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise EnterpriseRagAuditUnavailable("audit key is invalid")
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._key = bytes(audit_key)
        self._lock = threading.RLock()
        self._closed = False
        self._conn: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and not self.path.is_file():
                raise OSError("enterprise RAG audit path is not a regular file")
            connection = sqlite3.connect(self.path, check_same_thread=False, timeout=5.0)
            self._conn = connection
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE")
            objects = {
                (str(row[0]), str(row[1]), str(row[2])): (
                    None if row[3] is None else str(row[3])
                )
                for row in connection.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master"
                ).fetchall()
            }
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if not objects and application_id == 0 and user_version == 0:
                _install_schema(connection)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            elif (
                objects != _EXPECTED_SCHEMA
                or application_id != _APPLICATION_ID
                or user_version != _SCHEMA_VERSION
            ):
                raise sqlite3.DatabaseError("enterprise RAG audit schema authority mismatch")
            self._verify_meta(connection)
            connection.commit()
            enable_wal_with_deadline(
                connection,
                error_message="enterprise RAG audit database requires WAL mode",
            )
            connection.execute("PRAGMA synchronous=FULL")
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            max_pages = max(1, _MAX_DATABASE_BYTES // page_size)
            if int(connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]) != max_pages:
                raise sqlite3.DatabaseError("enterprise RAG audit capacity is unavailable")
            self.verify_chain()
        except Exception as exc:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            raise EnterpriseRagAuditUnavailable(
                "cannot initialize enterprise RAG audit log"
            ) from exc

    @staticmethod
    def _verify_meta(connection: sqlite3.Connection) -> None:
        stored = connection.execute(
            "SELECT record_count,max_records FROM enterprise_rag_audit_meta WHERE singleton=1"
        ).fetchone()
        actual = int(
            connection.execute("SELECT COUNT(*) FROM enterprise_rag_audit_records").fetchone()[0]
        )
        if stored != (actual, _MAX_RECORDS):
            raise sqlite3.DatabaseError("enterprise RAG audit metadata mismatch")

    def append(self, event: EnterpriseRagAuditEvent) -> str:
        if not isinstance(event, EnterpriseRagAuditEvent):
            raise EnterpriseRagAuditUnavailable("audit event is invalid")
        citations_json = _canonical_json(event.cited_chunk_ids)
        with self._lock:
            if self._closed or self._conn is None:
                raise EnterpriseRagAuditUnavailable("enterprise RAG audit log is closed")
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                previous_row = connection.execute(
                    "SELECT record_hmac FROM enterprise_rag_audit_records ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous = str(previous_row[0]) if previous_row else "0" * 64
                record_id = secrets.token_hex(16)
                created_at_ms = max(0, time.time_ns() // 1_000_000)
                body = self._record_body(
                    record_id=record_id,
                    event=event,
                    citations_json=citations_json,
                    previous_hmac=previous,
                    created_at_ms=created_at_ms,
                )
                record_hmac = hmac.new(
                    self._key,
                    b"nachuan-enterprise-rag-audit-v1\0" + _canonical_json(body).encode("ascii"),
                    hashlib.sha256,
                ).hexdigest()
                connection.execute(
                    "INSERT INTO enterprise_rag_audit_records("
                    "record_id,tenant_id,subject_scope_fingerprint,status,policy_epoch,"
                    "session_epoch,query_digest,requested_k,authorized_chunk_count,"
                    "cited_chunk_ids_json,model_id,receipt_id,error_code,previous_hmac,"
                    "record_hmac,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        record_id,
                        event.tenant_id,
                        event.subject_scope_fingerprint,
                        event.status,
                        event.policy_epoch,
                        event.session_epoch,
                        event.query_digest,
                        event.requested_k,
                        event.authorized_chunk_count,
                        citations_json,
                        event.model_id,
                        event.receipt_id,
                        event.error_code,
                        previous,
                        record_hmac,
                        created_at_ms,
                    ),
                )
                connection.commit()
                return record_hmac
            except Exception as exc:
                connection.rollback()
                raise EnterpriseRagAuditUnavailable(
                    "cannot append enterprise RAG audit record"
                ) from exc

    @staticmethod
    def _record_body(*, record_id, event, citations_json, previous_hmac, created_at_ms):
        return {
            "record_id": record_id,
            "tenant_id": event.tenant_id,
            "subject_scope_fingerprint": event.subject_scope_fingerprint,
            "status": event.status,
            "policy_epoch": event.policy_epoch,
            "session_epoch": event.session_epoch,
            "query_digest": event.query_digest,
            "requested_k": event.requested_k,
            "authorized_chunk_count": event.authorized_chunk_count,
            "cited_chunk_ids_json": citations_json,
            "model_id": event.model_id,
            "receipt_id": event.receipt_id,
            "error_code": event.error_code,
            "previous_hmac": previous_hmac,
            "created_at_ms": created_at_ms,
        }

    def list_records(self, *, tenant_id: str) -> list[dict[str, object]]:
        tenant = _identifier(tenant_id, "tenant_id")
        with self._lock:
            if self._closed or self._conn is None:
                raise EnterpriseRagAuditUnavailable("enterprise RAG audit log is closed")
            rows = self._conn.execute(
                "SELECT sequence,record_id,subject_scope_fingerprint,status,policy_epoch,"
                "session_epoch,query_digest,requested_k,authorized_chunk_count,"
                "cited_chunk_ids_json,model_id,receipt_id,error_code,previous_hmac,"
                "record_hmac,created_at_ms FROM enterprise_rag_audit_records "
                "WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        return [
            {
                "sequence": int(row[0]),
                "record_id": str(row[1]),
                "subject_scope_fingerprint": str(row[2]),
                "status": str(row[3]),
                "policy_epoch": int(row[4]),
                "session_epoch": int(row[5]),
                "query_digest": str(row[6]),
                "requested_k": int(row[7]),
                "authorized_chunk_count": int(row[8]),
                "cited_chunk_ids": list(json.loads(str(row[9]))),
                "model_id": str(row[10]),
                "receipt_id": str(row[11]),
                "error_code": str(row[12]),
                "previous_hmac": str(row[13]),
                "record_hmac": str(row[14]),
                "created_at_ms": int(row[15]),
            }
            for row in rows
        ]

    def verify_chain(self) -> int:
        with self._lock:
            if self._closed or self._conn is None:
                raise EnterpriseRagAuditUnavailable("enterprise RAG audit log is closed")
            rows = self._conn.execute(
                "SELECT record_id,tenant_id,subject_scope_fingerprint,status,policy_epoch,"
                "session_epoch,query_digest,requested_k,authorized_chunk_count,"
                "cited_chunk_ids_json,model_id,receipt_id,error_code,previous_hmac,"
                "record_hmac,created_at_ms FROM enterprise_rag_audit_records ORDER BY sequence"
            ).fetchall()
            self._verify_meta(self._conn)
        previous = "0" * 64
        for row in rows:
            if str(row[13]) != previous:
                raise EnterpriseRagAuditUnavailable("enterprise RAG audit chain is invalid")
            event = EnterpriseRagAuditEvent(
                tenant_id=str(row[1]),
                subject_scope_fingerprint=str(row[2]),
                status=str(row[3]),  # type: ignore[arg-type]
                policy_epoch=int(row[4]),
                session_epoch=int(row[5]),
                query_digest=str(row[6]),
                requested_k=int(row[7]),
                authorized_chunk_count=int(row[8]),
                cited_chunk_ids=tuple(json.loads(str(row[9]))),
                model_id=str(row[10]),
                receipt_id=str(row[11]),
                error_code=str(row[12]),
            )
            body = self._record_body(
                record_id=str(row[0]),
                event=event,
                citations_json=str(row[9]),
                previous_hmac=str(row[13]),
                created_at_ms=int(row[15]),
            )
            expected = hmac.new(
                self._key,
                b"nachuan-enterprise-rag-audit-v1\0" + _canonical_json(body).encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, str(row[14])):
                raise EnterpriseRagAuditUnavailable("enterprise RAG audit chain is invalid")
            previous = expected
        return len(rows)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connection, self._conn = self._conn, None
            if connection is not None:
                connection.close()


__all__ = [
    "EnterpriseRagAuditEvent",
    "EnterpriseRagAuditLog",
    "EnterpriseRagAuditUnavailable",
]
