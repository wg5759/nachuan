"""Content-free durable event truth for capability-plugin workflows."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from gateway.sqlite_runtime import enable_wal_with_deadline

_APPLICATION_ID = 0x4E435745  # "NCWE"
_SCHEMA_VERSION = 1
_MAX_EVENT_BYTES = 64 * 1024
_MAX_EVENTS = 200_000
_MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
_MAX_DATABASE_BYTES = 384 * 1024 * 1024
_EVENT_NAME_RE = re.compile(r"^fact/[a-z0-9][a-z0-9._/-]{1,126}$")
_WORKFLOW_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PHASES = frozenset({"started", "completed", "failed", "skipped"})
_FORBIDDEN_RAW_KEYS = frozenset({"prompt", "instruction", "output", "content"})

_SCHEMA_DDL = f"""
CREATE TABLE workflow_event_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    event_count INTEGER NOT NULL CHECK(event_count>=0),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0),
    max_events INTEGER NOT NULL CHECK(max_events={_MAX_EVENTS}),
    max_payload_bytes INTEGER NOT NULL CHECK(max_payload_bytes={_MAX_PAYLOAD_BYTES})
) WITHOUT ROWID;
INSERT INTO workflow_event_meta VALUES(1,0,0,{_MAX_EVENTS},{_MAX_PAYLOAD_BYTES});
CREATE TABLE workflow_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)=32 AND event_id NOT GLOB '*[^0-9a-f]*'),
    workflow_id TEXT NOT NULL CHECK(length(workflow_id)=32 AND workflow_id NOT GLOB '*[^0-9a-f]*'),
    event_name TEXT NOT NULL CHECK(length(CAST(event_name AS BLOB)) BETWEEN 6 AND 128),
    phase TEXT NOT NULL CHECK(phase IN ('started','completed','failed','skipped')),
    payload_json TEXT NOT NULL CHECK(typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB))<={_MAX_EVENT_BYTES}),
    previous_sha256 TEXT NOT NULL CHECK(length(previous_sha256)=64 AND previous_sha256 NOT GLOB '*[^0-9a-f]*'),
    event_sha256 TEXT NOT NULL UNIQUE CHECK(length(event_sha256)=64 AND event_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0)
);
CREATE INDEX idx_workflow_events_workflow ON workflow_events(workflow_id,sequence);
CREATE TRIGGER workflow_events_capacity_before_insert BEFORE INSERT ON workflow_events
BEGIN
  SELECT CASE WHEN (SELECT event_count FROM workflow_event_meta WHERE singleton=1)>={_MAX_EVENTS}
    THEN RAISE(ABORT,'workflow event count capacity exceeded') END;
  SELECT CASE WHEN (SELECT payload_bytes FROM workflow_event_meta WHERE singleton=1)+length(CAST(NEW.payload_json AS BLOB))>{_MAX_PAYLOAD_BYTES}
    THEN RAISE(ABORT,'workflow event payload capacity exceeded') END;
END;
CREATE TRIGGER workflow_events_capacity_after_insert AFTER INSERT ON workflow_events
BEGIN
  UPDATE workflow_event_meta SET event_count=event_count+1,
    payload_bytes=payload_bytes+length(CAST(NEW.payload_json AS BLOB)) WHERE singleton=1;
END;
CREATE TRIGGER workflow_events_no_update BEFORE UPDATE ON workflow_events
BEGIN SELECT RAISE(ABORT,'workflow events are append-only'); END;
CREATE TRIGGER workflow_events_no_delete BEFORE DELETE ON workflow_events
BEGIN SELECT RAISE(ABORT,'workflow events are append-only'); END;
"""


def _schema_statements(script: str) -> tuple[str, ...]:
    """Split a trusted SQLite script without losing trigger bodies."""
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
        raise RuntimeError("workflow event schema contains incomplete SQL")
    return tuple(statements)


_SCHEMA_STATEMENTS = _schema_statements(_SCHEMA_DDL)


def _install_schema(connection: sqlite3.Connection) -> None:
    # Individual execute calls preserve the caller's BEGIN IMMEDIATE.  In
    # contrast, sqlite3.executescript() implicitly commits first and could
    # expose a half-provisioned truth store after a crash.
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)


class DurableWorkflowEventUnavailable(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


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


def _contains_forbidden_raw_field(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).casefold() in _FORBIDDEN_RAW_KEYS:
                return True
            if _contains_forbidden_raw_field(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_raw_field(item) for item in value)
    return False


class DurableWorkflowEventLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._lock = threading.RLock()
        self._closed = False
        self._conn: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and not self.path.is_file():
                raise OSError("workflow event database path is not a regular file")
            connection = sqlite3.connect(
                self.path,
                check_same_thread=False,
                timeout=5.0,
            )
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
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
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
                raise sqlite3.DatabaseError("workflow event schema authority mismatch")
            self._verify_meta(connection)
            connection.commit()
            enable_wal_with_deadline(
                connection,
                error_message="workflow event database requires WAL mode",
            )
            connection.execute("PRAGMA synchronous=FULL")
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            max_pages = max(1, _MAX_DATABASE_BYTES // page_size)
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            configured = int(
                connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
            )
            if page_count > max_pages or configured != max_pages:
                raise sqlite3.DatabaseError("workflow event database exceeds capacity")
            self.verify_chain()
        except Exception as exc:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            raise DurableWorkflowEventUnavailable(
                "cannot initialize durable workflow event log"
            ) from exc

    @staticmethod
    def _verify_meta(connection: sqlite3.Connection) -> None:
        stored = connection.execute(
            "SELECT event_count,payload_bytes,max_events,max_payload_bytes "
            "FROM workflow_event_meta WHERE singleton=1"
        ).fetchone()
        actual = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) "
            "FROM workflow_events"
        ).fetchone()
        if stored != (actual[0], actual[1], _MAX_EVENTS, _MAX_PAYLOAD_BYTES):
            raise sqlite3.DatabaseError("workflow event capacity metadata mismatch")

    @staticmethod
    def _validate_payload(event_name: str, payload: object) -> tuple[str, str, str]:
        if _EVENT_NAME_RE.fullmatch(str(event_name or "")) is None:
            raise DurableWorkflowEventUnavailable("workflow event name is invalid")
        if not isinstance(payload, Mapping) or _contains_forbidden_raw_field(payload):
            raise DurableWorkflowEventUnavailable("workflow event payload is invalid")
        workflow_id = str(payload.get("workflow_id") or "")
        phase = str(payload.get("phase") or "")
        if _WORKFLOW_ID_RE.fullmatch(workflow_id) is None or phase not in _PHASES:
            raise DurableWorkflowEventUnavailable("workflow event payload is invalid")
        payload_json = _canonical_json(dict(payload))
        if len(payload_json.encode("utf-8")) > _MAX_EVENT_BYTES:
            raise DurableWorkflowEventUnavailable("workflow event payload is invalid")
        return workflow_id, phase, payload_json

    async def append(self, event_name: str, payload: object) -> None:
        await asyncio.to_thread(self.append_sync, event_name, payload)

    def append_sync(self, event_name: str, payload: object) -> None:
        workflow_id, phase, payload_json = self._validate_payload(event_name, payload)
        with self._lock:
            if self._closed or self._conn is None:
                raise DurableWorkflowEventUnavailable("workflow event log is closed")
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                previous_row = connection.execute(
                    "SELECT event_sha256 FROM workflow_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous = str(previous_row[0]) if previous_row else "0" * 64
                event_id = secrets.token_hex(16)
                created_at_ms = max(0, time.time_ns() // 1_000_000)
                canonical = _canonical_json(
                    {
                        "created_at_ms": created_at_ms,
                        "event_id": event_id,
                        "event_name": event_name,
                        "payload_json": payload_json,
                        "phase": phase,
                        "previous_sha256": previous,
                        "workflow_id": workflow_id,
                    }
                ).encode("ascii")
                event_sha256 = hashlib.sha256(
                    b"nachuan-workflow-event-v1\0" + canonical
                ).hexdigest()
                connection.execute(
                    "INSERT INTO workflow_events(event_id,workflow_id,event_name,phase,"
                    "payload_json,previous_sha256,event_sha256,created_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (
                        event_id,
                        workflow_id,
                        event_name,
                        phase,
                        payload_json,
                        previous,
                        event_sha256,
                        created_at_ms,
                    ),
                )
                connection.commit()
            except Exception as exc:
                connection.rollback()
                raise DurableWorkflowEventUnavailable(
                    "cannot append durable workflow event"
                ) from exc

    def list_events(self, workflow_id: str) -> list[dict[str, Any]]:
        if _WORKFLOW_ID_RE.fullmatch(str(workflow_id or "")) is None:
            raise ValueError("workflow id is invalid")
        with self._lock:
            if self._closed or self._conn is None:
                raise DurableWorkflowEventUnavailable("workflow event log is closed")
            rows = self._conn.execute(
                "SELECT sequence,event_id,event_name,phase,payload_json,"
                "previous_sha256,event_sha256,created_at_ms FROM workflow_events "
                "WHERE workflow_id=? ORDER BY sequence",
                (workflow_id,),
            ).fetchall()
        return [
            {
                "sequence": int(row[0]),
                "event_id": str(row[1]),
                "event_name": str(row[2]),
                "phase": str(row[3]),
                "payload": json.loads(str(row[4])),
                "previous_sha256": str(row[5]),
                "event_sha256": str(row[6]),
                "created_at_ms": int(row[7]),
            }
            for row in rows
        ]

    def verify_chain(self) -> int:
        with self._lock:
            if self._closed or self._conn is None:
                raise DurableWorkflowEventUnavailable("workflow event log is closed")
            rows = self._conn.execute(
                "SELECT event_id,workflow_id,event_name,phase,payload_json,"
                "previous_sha256,event_sha256,created_at_ms FROM workflow_events "
                "ORDER BY sequence"
            ).fetchall()
            self._verify_meta(self._conn)
        previous = "0" * 64
        for row in rows:
            if str(row[5]) != previous or _SHA256_RE.fullmatch(str(row[6])) is None:
                raise DurableWorkflowEventUnavailable("workflow event chain is invalid")
            canonical = _canonical_json(
                {
                    "created_at_ms": int(row[7]),
                    "event_id": str(row[0]),
                    "event_name": str(row[2]),
                    "payload_json": str(row[4]),
                    "phase": str(row[3]),
                    "previous_sha256": str(row[5]),
                    "workflow_id": str(row[1]),
                }
            ).encode("ascii")
            expected = hashlib.sha256(
                b"nachuan-workflow-event-v1\0" + canonical
            ).hexdigest()
            if expected != str(row[6]):
                raise DurableWorkflowEventUnavailable("workflow event chain is invalid")
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


__all__ = ["DurableWorkflowEventLog", "DurableWorkflowEventUnavailable"]
