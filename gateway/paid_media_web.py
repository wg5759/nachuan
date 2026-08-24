"""ADR-0013 §4 web paid-media confirmation chain (``POST /v1/paid-media/web/*``).

The pure-web frontend (``desktop/src/web-shim``) drives the complete paid-media
operation lifecycle through this route family.  The browser never holds the
paid capability key: the gateway derives the paid principal from its own
server-side configuration, while write verbs additionally require the
independent approval trust domain and a durable user-consent record.

Financial safety is unchanged in substance:

* Every provider dispatch crosses the exact same choke point as
  ``/v1/images/generations`` and ``/v1/videos/generations`` (durable claim,
  fencing token, asset reservation, fresh Root proof) — this module only
  re-orchestrates the operation journal around it.
* Idempotency keys are server-generated per operation and persisted in the
  journal; replaying an operation returns the durable result instead of
  calling the provider again.
* A new operation cannot be claimed while another one is unresolved, matching
  the Desktop one-unresolved gate.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from gateway.auth import (
    _PAID_MEDIA_KEY_RE,
    require_api_key,
    require_approval_admin_key,
)
from gateway.config import desktop_engine_keys, get_settings
from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRequestUnavailable,
    hash_media_principal,
    hash_media_request,
)
from gateway.paid_media_asset_protocol import (
    RESULT_SCHEMA as PAID_MEDIA_RESULT_SCHEMA,
    PaidMediaAssetProtocolError,
    canonical_asset_result,
    parse_asset_result,
)
from gateway.paid_media_asset_delivery import (
    PaidMediaAssetDeliveryUnavailable,
    archive_paid_media_document_for_web,
)
from gateway.paid_media_asset_store import (
    PaidMediaAssetAuthorizationError,
    PaidMediaAssetStoreError,
)
from gateway.paid_media_web_archive import (
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebAssetArchive,
    paid_media_web_archive_receipt_sha256,
)
from gateway.schemas import ImageGenerationRequest, VideoGenerationRequest


_SCHEMA_VERSION = 2
_APPLICATION_ID = 0x4E435057  # "NCPW"
_SCHEMA_V1_FINGERPRINT = hashlib.sha256(
    b"nachuan-paid-media-web-operations-schema-v1"
).hexdigest()
_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-paid-media-web-operations-schema-v2"
).hexdigest()

IMAGE_PATH = "/v1/images/generations"
VIDEO_PATH = "/v1/videos/generations"
_PATHS = frozenset({IMAGE_PATH, VIDEO_PATH})
_OPERATIONS = {IMAGE_PATH: "images.create", VIDEO_PATH: "videos.create"}
_OPERATION_ID_RE = re.compile(r"^desktop-op-[0-9a-f-]{36}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_VIDEO_ALIAS_RE = re.compile(r"^nvt1_[0-9a-f]{64}$")
_ASSET_REFERENCE_RE = re.compile(r"^nachuan-paid-media://sha256/([0-9a-f]{64})$")
_ASSET_TOKEN_RE = re.compile(r"^nma1_[A-Za-z0-9_-]{43}$")
_ARCHIVE_CURSOR_RE = re.compile(r"^[0-9]{16}_desktop-op-[0-9a-f-]{36}$")
_OPERATOR_DECISION_ID_RE = re.compile(
    r"^operator-recovery-decision-v1:[0-9a-f]{64}$"
)
_MAX_REQUEST_BYTES = 24 * 1024 * 1024
_MAX_MODEL_CODE_POINTS = 256
_MAX_REASON_BYTES = 512
_MAX_EVIDENCE_BYTES = 4096
_MAX_ARCHIVE_PAGE = 100
_DEFAULT_ARCHIVE_PAGE = 20
_AUTOMATIC_RETRY_MAX_AGE_MS = 27 * 24 * 60 * 60 * 1000
_CONFIRM_DOMAIN = b"nachuan-paid-media-web-confirm-v1\x00"
_RESULT_DOMAIN = b"nachuan-paid-media-web-result-v1\x00"
_RECEIPT_DOMAIN = b"nachuan-paid-media-web-archive-receipt-v1\x00"
_UNRESOLVED_STATES = ("claimed", "dispatching", "recoverable", "result_ready")

_TABLE_DDL = """
CREATE TABLE paid_media_web_operations (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=47),
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    path TEXT NOT NULL CHECK(
        path IN ('/v1/images/generations','/v1/videos/generations')
    ),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    idempotency_key TEXT NOT NULL CHECK(
        length(idempotency_key) BETWEEN 16 AND 128
    ),
    request_sha256 TEXT NOT NULL CHECK(
        length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    request_body_json TEXT,
    consent_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'claimed','dispatching','recoverable','result_ready',
        'delivered','reconciled'
    )),
    dispatch_count INTEGER NOT NULL CHECK(dispatch_count>=0),
    last_status INTEGER,
    retry_after_seconds INTEGER,
    result_json TEXT,
    asset_document_json TEXT,
    result_sha256 TEXT,
    archive_receipt_sha256 TEXT,
    archived_at_ms INTEGER,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    reconcile_json TEXT,
    import_source TEXT,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0),
    CHECK(
        (state='claimed' AND dispatch_count=0 AND result_json IS NULL)
        OR state<>'claimed'
    )
) WITHOUT ROWID
"""

_META_V1_DDL = """
CREATE TABLE paid_media_web_operations_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64)
) WITHOUT ROWID
"""

_META_DDL = """
CREATE TABLE paid_media_web_operations_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=2),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64)
) WITHOUT ROWID
"""

_ASSET_INDEX_DDL = """
CREATE TABLE paid_media_web_asset_references (
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    asset_sha256 TEXT NOT NULL CHECK(
        length(asset_sha256)=64 AND asset_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    asset_document_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0),
    PRIMARY KEY(principal_hash,asset_sha256)
) WITHOUT ROWID
"""


def _normalized_schema_sql(value: object) -> str:
    return " ".join(str(value or "").split())


def _schema_objects_match(
    objects: list[tuple[object, object, object]],
    expected: dict[tuple[str, str], str],
) -> bool:
    actual = {
        (str(object_type), str(name)): _normalized_schema_sql(sql)
        for object_type, name, sql in objects
    }
    normalized_expected = {
        key: _normalized_schema_sql(sql) for key, sql in expected.items()
    }
    return len(actual) == len(objects) and actual == normalized_expected


_V1_SCHEMA_OBJECTS = {
    ("table", "paid_media_web_operations"): _TABLE_DDL,
    ("table", "paid_media_web_operations_meta"): _META_V1_DDL,
}
_V2_SCHEMA_OBJECTS = {
    ("table", "paid_media_web_asset_references"): _ASSET_INDEX_DDL,
    ("table", "paid_media_web_operations"): _TABLE_DDL,
    ("table", "paid_media_web_operations_meta"): _META_DDL,
}


class PaidMediaWebLedgerUnavailable(RuntimeError):
    """The web operation journal cannot be used safely."""


class PaidMediaWebConflict(RuntimeError):
    """A requested transition deterministically conflicts with the journal."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _now_ms() -> int:
    return int(time.time() * 1000)


def _validated_digest(value: object, label: str) -> str:
    digest = str(value or "")
    if _DIGEST_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


class PaidMediaWebLedger:
    """SQLite web paid-media operation journal with forward-only states.

    This journal is the web-facing lifecycle record (claim → dispatch →
    result → delivered/reconciled).  It is deliberately *not* the execution
    authority: provider dispatch always re-enters
    ``gateway.durable_media_requests`` through the shared choke point with the
    persisted idempotency key, so a journal/authority divergence fails closed
    instead of double-charging.
    """

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.path = Path(os.path.abspath(os.fspath(db_path)))
        self._lock = threading.RLock()
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._initialize(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._closed:
            raise PaidMediaWebLedgerUnavailable("paid-media web ledger is closed")
        try:
            connection = sqlite3.connect(str(self.path), timeout=10.0)
        except sqlite3.Error as exc:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web ledger cannot be opened"
            ) from exc
        try:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
            connection.commit()
        except PaidMediaWebConflict:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web ledger write failed"
            ) from exc
        finally:
            connection.close()

    def _initialize(self, connection: sqlite3.Connection) -> None:
        try:
            # Serialize the complete schema snapshot and any migration.  Reading
            # v1 before taking the write lock lets a competing initializer win
            # the migration and makes the loser misclassify the now-valid v2
            # database as corrupt.
            connection.execute("BEGIN IMMEDIATE")
            application_id = connection.execute(
                "PRAGMA application_id"
            ).fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            objects = connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE name LIKE 'paid_media_web_%' ORDER BY type,name"
            ).fetchall()
        except sqlite3.Error as exc:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web ledger metadata is unreadable"
            ) from exc
        if not objects:
            if application_id != 0 or user_version != 0:
                raise PaidMediaWebLedgerUnavailable(
                    "paid-media web ledger file identity conflicts"
                )
            connection.execute(_META_DDL)
            connection.execute(_TABLE_DDL)
            connection.execute(_ASSET_INDEX_DDL)
            connection.execute(
                "INSERT INTO paid_media_web_operations_meta VALUES(1,?,?)",
                (_SCHEMA_VERSION, _SCHEMA_FINGERPRINT),
            )
            connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            return
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint "
            "FROM paid_media_web_operations_meta WHERE singleton=1"
        ).fetchone()
        if (
            application_id == _APPLICATION_ID
            and user_version == 1
            and _schema_objects_match(objects, _V1_SCHEMA_OBJECTS)
            and meta == (1, _SCHEMA_V1_FINGERPRINT)
        ):
            connection.execute(_ASSET_INDEX_DDL)
            self._backfill_asset_index(connection)
            connection.execute(
                "ALTER TABLE paid_media_web_operations_meta "
                "RENAME TO paid_media_web_operations_meta_v1"
            )
            connection.execute(_META_DDL)
            connection.execute(
                "INSERT INTO paid_media_web_operations_meta VALUES(1,?,?)",
                (_SCHEMA_VERSION, _SCHEMA_FINGERPRINT),
            )
            connection.execute("DROP TABLE paid_media_web_operations_meta_v1")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            return
        if (
            application_id != _APPLICATION_ID
            or user_version != _SCHEMA_VERSION
            or not _schema_objects_match(objects, _V2_SCHEMA_OBJECTS)
        ):
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web ledger schema is not the exact v2 generation"
            )
        if meta != (_SCHEMA_VERSION, _SCHEMA_FINGERPRINT):
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web ledger schema fingerprint mismatch"
            )

    @staticmethod
    def _asset_rows(asset_document: object) -> tuple[str, list[str]]:
        try:
            canonical_asset_result(asset_document)
        except PaidMediaAssetProtocolError as exc:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media Web asset document is invalid"
            ) from exc
        if not isinstance(asset_document, dict) or not isinstance(
            asset_document.get("assets"), list
        ):
            raise PaidMediaWebLedgerUnavailable(
                "paid-media Web asset document is invalid"
            )
        digests: list[str] = []
        for asset in asset_document["assets"]:
            if not isinstance(asset, dict):
                raise PaidMediaWebLedgerUnavailable(
                    "paid-media Web asset descriptor is invalid"
                )
            digest = str(asset.get("sha256") or "")
            token = str(asset.get("token") or "")
            if _DIGEST_RE.fullmatch(digest) is None or _ASSET_TOKEN_RE.fullmatch(token) is None:
                raise PaidMediaWebLedgerUnavailable(
                    "paid-media Web asset descriptor is invalid"
                )
            digests.append(digest)
        encoded = json.dumps(
            asset_document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        return encoded, digests

    @classmethod
    def _write_asset_index(
        cls,
        connection: sqlite3.Connection,
        *,
        principal_hash: str,
        asset_document: object,
        now_ms: int,
    ) -> None:
        encoded, digests = cls._asset_rows(asset_document)
        for digest in digests:
            connection.execute(
                "INSERT INTO paid_media_web_asset_references "
                "(principal_hash,asset_sha256,asset_document_json,updated_at_ms) "
                "VALUES(?,?,?,?) ON CONFLICT(principal_hash,asset_sha256) DO UPDATE SET "
                "asset_document_json=excluded.asset_document_json,"
                "updated_at_ms=excluded.updated_at_ms",
                (principal_hash, digest, encoded, now_ms),
            )

    @classmethod
    def _backfill_asset_index(cls, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT principal_hash,asset_document_json,COALESCE(archived_at_ms,updated_at_ms) "
            "FROM paid_media_web_operations WHERE asset_document_json IS NOT NULL"
        ).fetchall()
        for principal_hash, encoded, updated_at_ms in rows:
            try:
                document = json.loads(str(encoded))
            except json.JSONDecodeError as exc:
                raise PaidMediaWebLedgerUnavailable(
                    "paid-media Web asset archive is invalid"
                ) from exc
            cls._write_asset_index(
                connection,
                principal_hash=str(principal_hash),
                asset_document=document,
                now_ms=int(updated_at_ms),
            )

    def close(self) -> None:
        with self._lock:
            self._closed = True

    # ── test/inspection helpers ──────────────────────────────────────

    def count_operations(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM paid_media_web_operations"
            ).fetchone()
            return int(row[0])

    def read_operation(self, operation_id: object) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "SELECT * FROM paid_media_web_operations WHERE operation_id=?",
                (str(operation_id or ""),),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            columns = [
                description[0] for description in cursor.description or ()
            ]
            return dict(zip(columns, row))

    # ── mutations ────────────────────────────────────────────────────

    def create_claim(
        self,
        *,
        principal_hash: str,
        path: str,
        operation: str,
        idempotency_key: str,
        request_sha256: str,
        request_body_json: str,
        consent_json: str,
        now_ms: int,
    ) -> dict[str, Any]:
        operation_id = f"desktop-op-{uuid.uuid4()}"
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            unresolved = connection.execute(
                "SELECT 1 FROM paid_media_web_operations "
                "WHERE principal_hash=? AND state IN "
                "('claimed','dispatching','recoverable','result_ready') LIMIT 1",
                (principal_hash,),
            ).fetchone()
            if unresolved is not None:
                raise PaidMediaWebConflict(
                    "unresolved",
                    "Another paid media operation is unresolved",
                )
            connection.execute(
                "INSERT INTO paid_media_web_operations "
                "(operation_id,principal_hash,path,operation,idempotency_key,"
                "request_sha256,request_body_json,consent_json,state,"
                "dispatch_count,cancel_requested,created_at_ms,updated_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,'claimed',0,0,?,?)",
                (
                    operation_id,
                    principal_hash,
                    path,
                    operation,
                    idempotency_key,
                    request_sha256,
                    request_body_json,
                    consent_json,
                    now_ms,
                    now_ms,
                ),
            )
        row = self.read_operation(operation_id)
        if row is None:
            raise PaidMediaWebLedgerUnavailable("paid-media web claim was not persisted")
        return row

    def retry_claim(
        self,
        *,
        principal_hash: str,
        operation_id: str,
        path: str,
        request_sha256: str,
        now_ms: int,
    ) -> dict[str, Any] | None:
        """Re-read an existing operation for an exact retry; never mutates."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT principal_hash,path,request_sha256,state,created_at_ms "
                "FROM paid_media_web_operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None or row[0] != principal_hash:
                return None
            if row[1] != path or row[2] != request_sha256:
                raise PaidMediaWebConflict(
                    "operation_mismatch",
                    "Paid media retry does not match its original operation",
                )
            if row[3] == "reconciled":
                raise PaidMediaWebConflict(
                    "operation_reconciled",
                    "Paid media operation was reconciled manually",
                )
            if now_ms - int(row[4]) >= _AUTOMATIC_RETRY_MAX_AGE_MS:
                raise PaidMediaWebConflict(
                    "operation_expired",
                    "Paid media operation is too old for an automatic retry; "
                    "reconcile it manually",
                )
        return self.read_operation(operation_id)

    def get_for_principal(
        self, operation_id: object, principal_hash: str
    ) -> dict[str, Any] | None:
        row = self.read_operation(operation_id)
        if row is None or row["principal_hash"] != principal_hash:
            return None
        return row

    def consume_cancel_or_dispatch(
        self, operation_id: str, *, now_ms: int
    ) -> Literal["cancelled", "dispatching", "not_dispatchable"]:
        """Atomically consume a pre-dispatch cancel or fence the dispatch."""

        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,cancel_requested FROM paid_media_web_operations "
                "WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None or row[0] not in ("claimed", "recoverable"):
                return "not_dispatchable"
            if int(row[1]):
                cursor = connection.execute(
                    "UPDATE paid_media_web_operations SET state='recoverable',"
                    "cancel_requested=0,last_status=0,updated_at_ms=? "
                    "WHERE operation_id=? AND state IN ('claimed','recoverable') "
                    "AND cancel_requested=1",
                    (now_ms, operation_id),
                )
                return "cancelled" if cursor.rowcount == 1 else "not_dispatchable"
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET state='dispatching',"
                "dispatch_count=dispatch_count+1,updated_at_ms=? "
                "WHERE operation_id=? AND state IN ('claimed','recoverable') "
                "AND cancel_requested=0",
                (now_ms, operation_id),
            )
            return "dispatching" if cursor.rowcount == 1 else "not_dispatchable"

    def mark_result_ready(
        self,
        operation_id: str,
        *,
        last_status: int,
        result_json: str,
        asset_document_json: str | None,
        result_sha256: str,
        archive_receipt_sha256: str,
        now_ms: int,
    ) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Strictly monotone archival clock: two results committed in the
            # same millisecond still order deterministically (oldest first).
            latest = connection.execute(
                "SELECT COALESCE(MAX(archived_at_ms),0) FROM paid_media_web_operations"
            ).fetchone()[0]
            archived_at = max(now_ms, int(latest) + 1)
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET state='result_ready',"
                "last_status=?,retry_after_seconds=NULL,result_json=?,"
                "asset_document_json=?,result_sha256=?,archive_receipt_sha256=?,"
                "archived_at_ms=?,cancel_requested=0,updated_at_ms=? "
                "WHERE operation_id=? AND state='dispatching'",
                (
                    last_status,
                    result_json,
                    asset_document_json,
                    result_sha256,
                    archive_receipt_sha256,
                    archived_at,
                    max(now_ms, archived_at),
                    operation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise PaidMediaWebConflict(
                    "operation_state_conflict",
                    "Paid media operation state changed during archival",
                )
        row = self.read_operation(operation_id)
        if row is None:
            raise PaidMediaWebLedgerUnavailable("paid-media web result was not persisted")
        return row

    def mark_recoverable(
        self,
        operation_id: str,
        *,
        last_status: int | None,
        retry_after_seconds: int | None,
        now_ms: int,
    ) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET state='recoverable',"
                "last_status=?,retry_after_seconds=?,cancel_requested=0,"
                "updated_at_ms=? WHERE operation_id=? "
                "AND state IN ('claimed','dispatching','recoverable')",
                (last_status, retry_after_seconds, now_ms, operation_id),
            )
            if cursor.rowcount != 1:
                raise PaidMediaWebConflict(
                    "operation_state_conflict",
                    "Paid media operation state changed during failure handling",
                )
        row = self.read_operation(operation_id)
        if row is None:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web failure state was not persisted"
            )
        return row

    def mark_delivered(
        self,
        operation_id: str,
        *,
        result_sha256: str,
        archive_receipt_sha256: str,
        now_ms: int,
    ) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT state,result_sha256,archive_receipt_sha256 "
                "FROM paid_media_web_operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise PaidMediaWebConflict(
                    "operation_proof_conflict",
                    "Paid media delivery proof is unknown",
                )
            if row[0] == "delivered":
                if row[1] == result_sha256 and row[2] == archive_receipt_sha256:
                    current = self.read_operation(operation_id)
                    if current is None:
                        raise PaidMediaWebLedgerUnavailable(
                            "paid-media web operation vanished"
                        )
                    return current
                raise PaidMediaWebConflict(
                    "operation_proof_conflict",
                    "Paid media delivery proof does not match the archive receipt",
                )
            if row[0] != "result_ready":
                raise PaidMediaWebConflict(
                    "operation_proof_conflict",
                    "Paid media operation has no archived result to acknowledge",
                )
            if row[1] != result_sha256 or row[2] != archive_receipt_sha256:
                raise PaidMediaWebConflict(
                    "operation_proof_conflict",
                    "Paid media delivery proof does not match the archive receipt",
                )
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET state='delivered',"
                "updated_at_ms=? WHERE operation_id=? AND state='result_ready' "
                "AND result_sha256=? AND archive_receipt_sha256=?",
                (now_ms, operation_id, result_sha256, archive_receipt_sha256),
            )
            if cursor.rowcount != 1:
                raise PaidMediaWebConflict(
                    "operation_state_conflict",
                    "Paid media operation state changed during acknowledgement",
                )
        current = self.read_operation(operation_id)
        if current is None:
            raise PaidMediaWebLedgerUnavailable("paid-media web operation vanished")
        return current

    def complete_prepared_operator_recovery(
        self,
        operation_id: str,
        *,
        source_principal_hash: str,
        recipient_principal_hash: str,
        expected_request_sha256: str,
        expected_consent_sha256: str,
        expected_processing_result_sha256: str,
        renderer_result: object,
        asset_document: object,
        archive_receipt_sha256: str,
        decision_id: str,
        candidate_sha256: str,
        ack_receipt_sha256: str,
        now_ms: int,
    ) -> dict[str, Any]:
        """CAS one delivered processing row to an operator-adjudicated terminal row."""

        source_principal = _validated_digest(
            source_principal_hash, "source_principal_hash"
        )
        recipient_principal = _validated_digest(
            recipient_principal_hash, "recipient_principal_hash"
        )
        if hmac.compare_digest(source_principal, recipient_principal):
            raise PaidMediaWebConflict(
                "operator_recovery_principal_conflict",
                "Operator recovery recipient must be a different capability.",
            )
        request_digest = _validated_digest(
            expected_request_sha256, "expected_request_sha256"
        )
        consent_digest = _validated_digest(
            expected_consent_sha256, "expected_consent_sha256"
        )
        processing_digest = _validated_digest(
            expected_processing_result_sha256,
            "expected_processing_result_sha256",
        )
        archive_digest = _validated_digest(
            archive_receipt_sha256, "archive_receipt_sha256"
        )
        candidate_digest = _validated_digest(
            candidate_sha256, "candidate_sha256"
        )
        ack_digest = _validated_digest(
            ack_receipt_sha256, "ack_receipt_sha256"
        )
        if (
            not isinstance(decision_id, str)
            or _OPERATOR_DECISION_ID_RE.fullmatch(decision_id) is None
        ):
            raise PaidMediaWebConflict(
                "operator_recovery_decision_conflict",
                "Operator recovery decision is invalid.",
            )
        audit_json = json.dumps(
            {
                "schema": "nachuan.local-paid-media-operator-transfer.v1",
                "decisionId": decision_id,
                "candidateSha256": candidate_digest,
                "ackReceiptSha256": ack_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if not isinstance(renderer_result, dict):
            raise PaidMediaWebConflict(
                "operator_recovery_result_conflict",
                "Operator recovery result is invalid.",
            )
        try:
            parsed_asset = parse_asset_result(asset_document)
            encoded_asset, indexed_digests = self._asset_rows(asset_document)
            encoded_result = json.dumps(
                renderer_result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (
            PaidMediaAssetProtocolError,
            PaidMediaWebLedgerUnavailable,
            TypeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise PaidMediaWebConflict(
                "operator_recovery_result_conflict",
                "Operator recovery result is invalid.",
            ) from exc
        expected_reference = (
            f"nachuan-paid-media://sha256/{indexed_digests[0]}"
            if len(indexed_digests) == 1
            else ""
        )
        task_alias = str(renderer_result.get("task_id") or "")
        if (
            parsed_asset.kind != "video"
            or len(parsed_asset.assets) != 1
            or _VIDEO_ALIAS_RE.fullmatch(task_alias) is None
            or task_alias.removeprefix("nvt1_") != parsed_asset.turn_id
            or set(renderer_result) != {"task_id", "status", "video_url"}
            or renderer_result.get("status") != "completed"
            or renderer_result.get("video_url") != expected_reference
        ):
            raise PaidMediaWebConflict(
                "operator_recovery_result_conflict",
                "Operator recovery result is invalid.",
            )
        result_sha256 = hashlib.sha256(
            _RESULT_DOMAIN + encoded_result.encode("utf-8")
        ).hexdigest()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_hash,path,operation,request_sha256,consent_json,"
                "state,dispatch_count,result_json,asset_document_json,result_sha256,"
                "archive_receipt_sha256,reconcile_json "
                "FROM paid_media_web_operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise PaidMediaWebConflict(
                    "operator_recovery_operation_missing",
                    "Operator recovery operation is unavailable.",
                )
            if (
                row[0] == recipient_principal
                and row[1] == VIDEO_PATH
                and row[2] == "videos.create"
                and row[3] == request_digest
                and row[5] == "delivered"
                and int(row[6]) == 1
                and row[7] == encoded_result
                and row[8] == encoded_asset
                and row[9] == result_sha256
                and row[10] == archive_digest
                and row[11] == audit_json
                and hmac.compare_digest(
                    hashlib.sha256(str(row[4]).encode("utf-8")).hexdigest(),
                    consent_digest,
                )
            ):
                cursor = connection.execute(
                    "SELECT * FROM paid_media_web_operations "
                    "WHERE operation_id=?",
                    (operation_id,),
                )
                current_row = cursor.fetchone()
                if current_row is None:
                    raise PaidMediaWebLedgerUnavailable(
                        "paid-media web operation vanished"
                    )
                columns = [
                    description[0]
                    for description in cursor.description or ()
                ]
                return dict(zip(columns, current_row))
            try:
                prior_result = json.loads(str(row[7]))
            except (json.JSONDecodeError, TypeError) as exc:
                raise PaidMediaWebConflict(
                    "operator_recovery_state_conflict",
                    "Operator recovery operation changed.",
                ) from exc
            prior_alias = (
                str(prior_result.get("task_id") or "")
                if isinstance(prior_result, dict)
                else ""
            )
            if (
                row[0] != source_principal
                or row[1] != VIDEO_PATH
                or row[2] != "videos.create"
                or row[3] != request_digest
                or not hmac.compare_digest(
                    hashlib.sha256(str(row[4]).encode("utf-8")).hexdigest(),
                    consent_digest,
                )
                or row[5] != "delivered"
                or int(row[6]) != 1
                or not isinstance(prior_result, dict)
                or set(prior_result) != {"task_id", "status"}
                or prior_result.get("status") != "processing"
                or prior_alias != task_alias
                or row[8] is not None
                or row[9] != processing_digest
                or row[11] is not None
            ):
                raise PaidMediaWebConflict(
                    "operator_recovery_state_conflict",
                    "Operator recovery operation changed.",
                )
            latest = connection.execute(
                "SELECT COALESCE(MAX(archived_at_ms),0) "
                "FROM paid_media_web_operations"
            ).fetchone()[0]
            archived_at = max(int(now_ms), int(latest) + 1)
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET principal_hash=?,"
                "last_status=200,retry_after_seconds=NULL,result_json=?,"
                "asset_document_json=?,result_sha256=?,archive_receipt_sha256=?,"
                "reconcile_json=?,archived_at_ms=?,updated_at_ms=? "
                "WHERE operation_id=? "
                "AND principal_hash=? AND state='delivered' AND dispatch_count=1 "
                "AND request_sha256=? AND result_sha256=? "
                "AND asset_document_json IS NULL",
                (
                    recipient_principal,
                    encoded_result,
                    encoded_asset,
                    result_sha256,
                    archive_digest,
                    audit_json,
                    archived_at,
                    max(int(now_ms), archived_at),
                    operation_id,
                    source_principal,
                    request_digest,
                    processing_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise PaidMediaWebConflict(
                    "operator_recovery_state_conflict",
                    "Operator recovery operation changed.",
                )
            self._write_asset_index(
                connection,
                principal_hash=recipient_principal,
                asset_document=asset_document,
                now_ms=max(int(now_ms), archived_at),
            )
        current = self.read_operation(operation_id)
        if current is None:
            raise PaidMediaWebLedgerUnavailable("paid-media web operation vanished")
        return current

    def mark_reconciled(
        self,
        operation_id: str,
        *,
        reconcile_json: str,
        never_dispatched_only: bool,
        now_ms: int,
    ) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            if never_dispatched_only:
                cursor = connection.execute(
                    "UPDATE paid_media_web_operations SET state='reconciled',"
                    "reconcile_json=?,cancel_requested=0,updated_at_ms=? "
                    "WHERE operation_id=? AND state='claimed' AND dispatch_count=0",
                    (reconcile_json, now_ms, operation_id),
                )
            else:
                cursor = connection.execute(
                    "UPDATE paid_media_web_operations SET state='reconciled',"
                    "reconcile_json=?,cancel_requested=0,updated_at_ms=? "
                    "WHERE operation_id=? AND state IN "
                    "('claimed','dispatching','recoverable','result_ready')",
                    (reconcile_json, now_ms, operation_id),
                )
            if cursor.rowcount != 1:
                raise PaidMediaWebConflict(
                    "operation_state_conflict",
                    "Paid media operation cannot be reconciled from its state",
                )
        row = self.read_operation(operation_id)
        if row is None:
            raise PaidMediaWebLedgerUnavailable("paid-media web operation vanished")
        return row

    def request_cancel(self, operation_id: str, *, now_ms: int) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE paid_media_web_operations SET cancel_requested=1,"
                "updated_at_ms=? WHERE operation_id=? "
                "AND state IN ('claimed','dispatching','recoverable')",
                (now_ms, operation_id),
            )
            return cursor.rowcount == 1

    def list_unresolved(self, principal_hash: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "SELECT * FROM paid_media_web_operations "
                "WHERE principal_hash=? AND state IN "
                "('claimed','dispatching','recoverable','result_ready') "
                "ORDER BY created_at_ms,operation_id",
                (principal_hash,),
            )
            columns = [description[0] for description in cursor.description or ()]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def list_archives(
        self,
        principal_hash: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> tuple[list[dict[str, Any]], str | None]:
        cursor_bound: tuple[int, str] | None = None
        if cursor is not None:
            if _ARCHIVE_CURSOR_RE.fullmatch(cursor) is None:
                raise ValueError("archive cursor is invalid")
            cursor_bound = (int(cursor[:16]), cursor[17:])
        with self._lock, self._connect() as connection:
            cursor_obj = connection.execute(
                "SELECT * FROM paid_media_web_operations "
                "WHERE principal_hash=? AND archived_at_ms IS NOT NULL "
                "AND state IN ('result_ready','delivered') "
                "ORDER BY archived_at_ms DESC,operation_id ASC",
                (principal_hash,),
            )
            columns = [description[0] for description in cursor_obj.description or ()]
            rows = [dict(zip(columns, row)) for row in cursor_obj.fetchall()]
        if cursor_bound is not None:
            bound_ms, bound_id = cursor_bound
            rows = [
                row
                for row in rows
                if int(row["archived_at_ms"]) < bound_ms
                or (
                    int(row["archived_at_ms"]) == bound_ms
                    and str(row["operation_id"]) > bound_id
                )
            ]
        page = rows[: limit + 1]
        operations = page[:limit]
        next_cursor = None
        if len(page) > limit and operations:
            last = operations[-1]
            next_cursor = (
                f"{int(last['archived_at_ms']):016d}_{last['operation_id']}"
            )
        return operations, next_cursor

    def find_asset_token(
        self, principal_hash: str, asset_sha256: str
    ) -> str | None:
        """Resolve a content reference without exposing the raw asset token.

        The raw token stays inside the validated asset document and never
        crosses the Web route boundary.
        """

        digest = _validated_digest(asset_sha256, "asset_sha256")
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT asset_document_json FROM paid_media_web_asset_references "
                "WHERE principal_hash=? AND asset_sha256=?",
                (principal_hash, digest),
            ).fetchone()
        if row is None:
            return None
        try:
            document = json.loads(str(row[0]))
        except json.JSONDecodeError as exc:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web archive asset document is invalid"
            ) from exc
        _encoded, indexed_digests = self._asset_rows(document)
        if digest not in indexed_digests:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web archive index does not match its document"
            )
        for asset in document["assets"]:
            if asset.get("sha256") == digest:
                return str(asset["token"])
        raise PaidMediaWebLedgerUnavailable(
            "paid-media web archive index lost its asset descriptor"
        )

    def find_asset_document(
        self, principal_hash: str, asset_sha256: str
    ) -> dict[str, Any] | None:
        """Resolve the complete closed document behind one content reference."""

        digest = _validated_digest(asset_sha256, "asset_sha256")
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT asset_document_json FROM paid_media_web_asset_references "
                "WHERE principal_hash=? AND asset_sha256=?",
                (principal_hash, digest),
            ).fetchone()
        if row is None:
            return None
        try:
            document = json.loads(str(row[0]))
        except json.JSONDecodeError as exc:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web archive asset document is invalid"
            ) from exc
        _encoded, indexed_digests = self._asset_rows(document)
        if digest not in indexed_digests:
            raise PaidMediaWebLedgerUnavailable(
                "paid-media web archive index does not match its document"
            )
        return document

    def record_asset_document(
        self,
        principal_hash: str,
        asset_document: object,
        *,
        now_ms: int,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._write_asset_index(
                connection,
                principal_hash=principal_hash,
                asset_document=asset_document,
                now_ms=now_ms,
            )

    def import_legacy(
        self,
        record: dict[str, Any],
        *,
        principal_hash: str,
        path: str,
        operation: str,
        idempotency_key: str,
        consent_json: str,
        now_ms: int,
    ) -> dict[str, Any]:
        state = "claimed" if record["state"] == "pending" else "recoverable"
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM paid_media_web_operations WHERE operation_id=?",
                (record["operationId"],),
            ).fetchone()
            if existing is not None:
                raise PaidMediaWebConflict(
                    "legacy_import_conflict",
                    "Paid media legacy import was already consumed",
                )
            connection.execute(
                "INSERT INTO paid_media_web_operations "
                "(operation_id,principal_hash,path,operation,idempotency_key,"
                "request_sha256,request_body_json,consent_json,state,"
                "dispatch_count,last_status,retry_after_seconds,"
                "cancel_requested,import_source,created_at_ms,updated_at_ms) "
                "VALUES(?,?,?,?,?,?,NULL,?,?,0,?,?,0,'legacy',?,?)",
                (
                    record["operationId"],
                    principal_hash,
                    path,
                    operation,
                    idempotency_key,
                    record["requestSha256"],
                    consent_json,
                    state,
                    record.get("lastStatus"),
                    record.get("retryAfterSeconds"),
                    int(record["createdAt"]),
                    int(record["updatedAt"]),
                ),
            )
        row = self.read_operation(record["operationId"])
        if row is None:
            raise PaidMediaWebLedgerUnavailable("paid-media legacy import was not persisted")
        return row


# ── HTTP surface ─────────────────────────────────────────────────────

_EXECUTE_FLIGHTS: dict[tuple[int, int, str], asyncio.Task[JSONResponse]] = {}
_WEB_ARCHIVE_FLIGHTS: dict[
    tuple[int, int, str, str, str, int], asyncio.Task[str]
] = {}
_WEB_ARCHIVE_MATERIALIZATION_LIMIT = 2
_WEB_ARCHIVE_MATERIALIZATION_ACTIVE = 0
_WEB_ARCHIVE_MATERIALIZATION_COUNTS_LOCK = threading.Lock()
_WEB_ASSET_READ_LIMIT = 2
_WEB_ASSET_READ_ACTIVE = 0
_WEB_ASSET_READ_COUNTS_LOCK = threading.Lock()


class _WebArchiveMaterializationCapacityExhausted(RuntimeError):
    pass


class _WebArchiveReceiptDrift(PaidMediaWebArchiveUnavailable):
    pass


class _WebArchiveMaterializationLease:
    def __init__(self) -> None:
        self._released = False

    def release(self) -> None:
        global _WEB_ARCHIVE_MATERIALIZATION_ACTIVE
        with _WEB_ARCHIVE_MATERIALIZATION_COUNTS_LOCK:
            if self._released:
                return
            self._released = True
            _WEB_ARCHIVE_MATERIALIZATION_ACTIVE = max(
                0, _WEB_ARCHIVE_MATERIALIZATION_ACTIVE - 1
            )


def _try_acquire_web_archive_materialization(
) -> _WebArchiveMaterializationLease | None:
    global _WEB_ARCHIVE_MATERIALIZATION_ACTIVE
    with _WEB_ARCHIVE_MATERIALIZATION_COUNTS_LOCK:
        if (
            _WEB_ARCHIVE_MATERIALIZATION_ACTIVE
            >= _WEB_ARCHIVE_MATERIALIZATION_LIMIT
        ):
            return None
        _WEB_ARCHIVE_MATERIALIZATION_ACTIVE += 1
    return _WebArchiveMaterializationLease()


class _WebAssetReadLease:
    def __init__(self) -> None:
        self._released = False

    def release(self) -> None:
        global _WEB_ASSET_READ_ACTIVE
        with _WEB_ASSET_READ_COUNTS_LOCK:
            if self._released:
                return
            self._released = True
            _WEB_ASSET_READ_ACTIVE = max(0, _WEB_ASSET_READ_ACTIVE - 1)


def _try_acquire_web_asset_read() -> _WebAssetReadLease | None:
    global _WEB_ASSET_READ_ACTIVE
    with _WEB_ASSET_READ_COUNTS_LOCK:
        if _WEB_ASSET_READ_ACTIVE >= _WEB_ASSET_READ_LIMIT:
            return None
        _WEB_ASSET_READ_ACTIVE += 1
    return _WebAssetReadLease()


class _WebAssetReadResponse(Response):
    """Keep one server read slot until ASGI finishes or aborts the response."""

    def __init__(self, *, lease: _WebAssetReadLease, **kwargs: Any) -> None:
        self._read_lease = lease
        super().__init__(**kwargs)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._read_lease.release()


async def _run_web_asset_archive_materialization(
    state: Any,
    *,
    principal_hash: str,
    asset_document: object,
) -> str:
    """Own a process materialization permit for the entire flight lifetime."""

    lease = _try_acquire_web_archive_materialization()
    if lease is None:
        raise _WebArchiveMaterializationCapacityExhausted
    try:
        return await archive_paid_media_document_for_web(
            state,
            principal_hash=principal_hash,
            asset_document=asset_document,
            now_ms=_now_ms(),
        )
    finally:
        lease.release()


def _web_archive_receipt_authority(
    state: Any,
    *,
    principal_hash: str,
    asset_document: object,
) -> tuple[PaidMediaWebAssetArchive, object, str, int, str]:
    """Resolve one authority snapshot and its deterministic document receipt."""

    archive = getattr(state, "paid_media_web_archive", None)
    epoch = getattr(state, "paid_media_epoch", None)
    installation_id = getattr(state, "paid_media_installation_id", None)
    if (
        not isinstance(archive, PaidMediaWebAssetArchive)
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
        or not isinstance(installation_id, str)
    ):
        raise PaidMediaAssetDeliveryUnavailable(
            "paid-media Web archive authority is unavailable"
        )
    result = parse_asset_result(asset_document)
    receipt = paid_media_web_archive_receipt_sha256(
        principal_hash=principal_hash,
        result=result,
        installation_id=installation_id,
        installation_epoch=epoch,
    )
    return archive, result, installation_id, epoch, receipt


def _assert_web_archive_receipt(
    actual: str,
    expected: str,
) -> None:
    if not (
        isinstance(actual, str)
        and isinstance(expected, str)
        and hmac.compare_digest(actual, expected)
    ):
        raise _WebArchiveReceiptDrift(
            "paid-media Web archive receipt drifted from its authority"
        )


async def _ensure_web_asset_archive(
    request: Request,
    *,
    principal_hash: str,
    asset_document: object,
    expected_receipt_sha256: str | None = None,
) -> str:
    """Singleflight one complete Web archive/cleanup transition per turn."""

    archive, result, installation_id, epoch, deterministic_receipt = (
        _web_archive_receipt_authority(
            request.app.state,
            principal_hash=principal_hash,
            asset_document=asset_document,
        )
    )
    if expected_receipt_sha256 is not None:
        _assert_web_archive_receipt(
            expected_receipt_sha256,
            deterministic_receipt,
        )
    key = (
        id(asyncio.get_running_loop()),
        id(archive),
        principal_hash,
        result.turn_id,
        installation_id,
        epoch,
    )
    flight = _WEB_ARCHIVE_FLIGHTS.get(key)
    if flight is None:
        flight = asyncio.create_task(
            _run_web_asset_archive_materialization(
                request.app.state,
                principal_hash=principal_hash,
                asset_document=asset_document,
            )
        )
        _WEB_ARCHIVE_FLIGHTS[key] = flight

        def _cleanup(done: asyncio.Task[str]) -> None:
            if _WEB_ARCHIVE_FLIGHTS.get(key) is done:
                _WEB_ARCHIVE_FLIGHTS.pop(key, None)

        flight.add_done_callback(_cleanup)
    try:
        receipt = await asyncio.shield(flight)
        _assert_web_archive_receipt(receipt, deterministic_receipt)
        if expected_receipt_sha256 is not None:
            _assert_web_archive_receipt(receipt, expected_receipt_sha256)
        return receipt
    except _WebArchiveMaterializationCapacityExhausted as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "paid_media_web_asset_archive_capacity_exhausted",
                "message": (
                    "Paid media Web asset materialization capacity is exhausted."
                ),
                "retryable": True,
            },
            headers={"Cache-Control": "no-store", "Retry-After": "1"},
        ) from exc


async def _web_archive_receipt_if_complete(
    request: Request,
    *,
    principal_hash: str,
    asset_document: object,
    expected_receipt_sha256: str | None = None,
) -> str | None:
    archive, result, installation_id, epoch, deterministic_receipt = (
        _web_archive_receipt_authority(
            request.app.state,
            principal_hash=principal_hash,
            asset_document=asset_document,
        )
    )
    if expected_receipt_sha256 is not None:
        _assert_web_archive_receipt(
            expected_receipt_sha256,
            deterministic_receipt,
        )
    receipt = await asyncio.to_thread(
        archive.receipt_for_document,
        principal_hash=principal_hash,
        result=result,
        installation_id=installation_id,
        installation_epoch=epoch,
    )
    if receipt is not None:
        _assert_web_archive_receipt(receipt, deterministic_receipt)
        if expected_receipt_sha256 is not None:
            _assert_web_archive_receipt(receipt, expected_receipt_sha256)
    return receipt


def _web_error(
    status_code: int,
    *,
    code: str,
    message: str,
    retryable: bool = False,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, "retryable": retryable},
        headers={"Cache-Control": "no-store"},
    )


def _web_json(payload: Any, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


async def _require_web_paid_media_principal(request: Request) -> str:
    """Attach the paid capability gateway-side; browsers never hold the key."""

    if bool(getattr(sys, "frozen", False)):
        raise HTTPException(
            status_code=503,
            detail="Paid-media engine-session capability is unavailable.",
            headers={"Cache-Control": "no-store"},
        )
    settings = get_settings()
    configured = str(
        getattr(settings, "nachuan_paid_media_api_key", "") or ""
    ).strip()
    if not _PAID_MEDIA_KEY_RE.fullmatch(configured):
        raise HTTPException(
            status_code=503,
            detail="付费媒体 Key 未配置或格式无效；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    runtime_keys = set(getattr(settings, "api_keys", set()) or set()) | set(
        desktop_engine_keys()
    )
    if any(hmac.compare_digest(configured, str(key)) for key in runtime_keys):
        raise HTTPException(
            status_code=503,
            detail="付费媒体 Key 与运行时 API Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    approval_key = str(getattr(settings, "approval_admin_key", "") or "").strip()
    if approval_key and hmac.compare_digest(configured, approval_key):
        raise HTTPException(
            status_code=503,
            detail="付费媒体 Key 与审批管理员 Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    channel_keys = {
        str(getattr(settings, name, "") or "").strip()
        for name in (
            "bridge_api_key",
            "nachuan_weixin_bridge_api_key",
            "nachuan_feishu_bridge_api_key",
        )
    }
    channel_keys.discard("")
    if any(hmac.compare_digest(configured, key) for key in channel_keys):
        raise HTTPException(
            status_code=503,
            detail="付费媒体 Key 与渠道 Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    authority_mode = str(
        getattr(request.app.state, "paid_media_authority_mode", "") or ""
    )
    if authority_mode == "installation-root":
        principal = str(
            getattr(request.app.state, "paid_media_principal", "") or ""
        )
        if re.fullmatch(r"[0-9a-f]{64}", principal) is None or principal == "0" * 64:
            raise HTTPException(
                status_code=503,
                detail="付费媒体安装授权不可用；仅允许读取已确认的本地结果",
                headers={"Cache-Control": "no-store"},
            )
        return principal
    return hash_media_principal(configured)


def _web_ledger(request: Request) -> PaidMediaWebLedger:
    ledger = getattr(request.app.state, "paid_media_web_ledger", None)
    if not isinstance(ledger, PaidMediaWebLedger):
        raise _web_error(
            503,
            code="paid_media_web_ledger_unavailable",
            message="Paid media web operation journal is unavailable.",
        )
    return ledger


async def _read_json_object(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception as exc:  # malformed JSON never reaches the journal
        raise _web_error(
            422, code="invalid_paid_media_web_request", message="请求正文不是合法 JSON。"
        ) from exc
    if not isinstance(body, dict):
        raise _web_error(
            422, code="invalid_paid_media_web_request", message="请求正文必须是对象。"
        )
    return body


def _require_exact_keys(body: dict[str, Any], expected: set[str]) -> None:
    if set(body.keys()) != expected:
        raise _web_error(
            422, code="invalid_paid_media_web_request", message="请求字段闭集不匹配。"
        )


def _validated_operation_id(value: object) -> str:
    operation_id = str(value or "")
    if _OPERATION_ID_RE.fullmatch(operation_id) is None:
        raise _web_error(
            422, code="invalid_paid_media_web_request", message="operationId 格式无效。"
        )
    return operation_id


def _validated_bounded_text(value: object, label: str, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise _web_error(
            422, code="invalid_paid_media_web_request", message=f"{label} 必须是文本。"
        )
    text = value.strip()
    if (
        not text
        or len(text.encode("utf-8")) > max_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise _web_error(
            422, code="invalid_paid_media_web_request", message=f"{label} 无效。"
        )
    return text


def _confirm_digest(path: str, encoded_body: str) -> str:
    body_digest = hashlib.sha256(encoded_body.encode("utf-8")).hexdigest()
    return hashlib.sha256(
        _CONFIRM_DOMAIN + path.encode("utf-8") + b"\x00" + body_digest.encode("ascii")
    ).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _web_error(
            502,
            code="paid_media_web_result_invalid",
            message="Paid media result could not be canonically encoded.",
        ) from exc


def _result_digest(renderer_result: Any) -> str:
    return hashlib.sha256(
        _RESULT_DOMAIN + _canonical_json_bytes(renderer_result)
    ).hexdigest()


def _archive_receipt_digest(
    asset_document: dict[str, Any] | None, renderer_result: Any
) -> str:
    material = (
        canonical_asset_result(asset_document)
        if asset_document is not None
        else _canonical_json_bytes(renderer_result)
    )
    return hashlib.sha256(_RECEIPT_DOMAIN + material).hexdigest()


def _validated_request_payload(
    path: str, encoded_body: str
) -> tuple[str, dict[str, Any]]:
    """Parse and closed-set validate the body exactly like the paid routes."""

    from gateway.app import (  # deferred: app imports this module for routing
        _require_versioned_paid_media_body,
    )

    if not isinstance(encoded_body, str) or not encoded_body:
        raise _web_error(
            422, code="invalid_media_request", message="Paid media request body is invalid."
        )
    if len(encoded_body.encode("utf-8")) > _MAX_REQUEST_BYTES:
        raise _web_error(
            422, code="invalid_media_request", message="Paid media request body is invalid."
        )
    try:
        raw = json.loads(encoded_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _web_error(
            422, code="invalid_media_request", message="Paid media request body is invalid."
        ) from exc
    video = path == VIDEO_PATH
    try:
        _require_versioned_paid_media_body(raw, video=video)
        if video:
            request_model = VideoGenerationRequest(**raw)
        else:
            if isinstance(raw, dict) and raw.get("response_format") == "b64_json":
                raise ValueError("paid-media protocol v2 does not accept b64_json")
            request_model = ImageGenerationRequest(**raw)
            request_model = request_model.model_copy(
                update={"response_format": "url"}
            )
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise _web_error(
            422, code="invalid_media_request", message="Paid media request body is invalid."
        ) from exc
    operation = _OPERATIONS[path]
    payload = request_model.model_dump(mode="json", exclude_none=True)
    return operation, payload


def _public_operation(row: dict[str, Any]) -> dict[str, Any]:
    operation: dict[str, Any] = {
        "operationId": row["operation_id"],
        "path": row["path"],
        "state": row["state"],
        "createdAt": int(row["created_at_ms"]),
        "updatedAt": int(row["updated_at_ms"]),
        "dispatchCount": int(row["dispatch_count"]),
    }
    if row["last_status"] is not None:
        operation["lastStatus"] = int(row["last_status"])
    if row["retry_after_seconds"] is not None:
        operation["retryAfterSeconds"] = int(row["retry_after_seconds"])
    return operation


def _delivery_proof(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "operationId": row["operation_id"],
        "resultSha256": row["result_sha256"],
        "archiveReceiptSha256": row["archive_receipt_sha256"],
    }


def _archived_assets(asset_document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if asset_document is None:
        return []
    assets = asset_document.get("assets")
    if not isinstance(assets, list):
        return []
    return [
        {
            "reference": f"nachuan-paid-media://sha256/{asset['sha256']}",
            "mediaType": asset["mediaType"],
            "byteLength": asset["byteLength"],
            "sha256": asset["sha256"],
        }
        for asset in assets
        if isinstance(asset, dict) and _DIGEST_RE.fullmatch(str(asset.get("sha256") or ""))
    ]


def _renderer_image_result(asset_document: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": [
            {"url": asset["reference"]} for asset in _archived_assets(asset_document)
        ]
    }


def _ok_execution(row: dict[str, Any]) -> JSONResponse:
    return _web_json(
        {
            "ok": True,
            "status": int(row["last_status"] or 200),
            "result": json.loads(str(row["result_json"])),
            "operation": _public_operation(row),
            "deliveryProof": _delivery_proof(row),
        }
    )


def _failed_execution(
    row: dict[str, Any],
    *,
    status: int,
    detail: str,
    retry_after_seconds: int | None = None,
) -> JSONResponse:
    payload: dict[str, Any] = {
        "ok": False,
        "status": status,
        "recoverable": True,
        "detail": detail,
        "operation": _public_operation(row),
    }
    if retry_after_seconds is not None:
        payload["retryAfterSeconds"] = retry_after_seconds
    return _web_json(payload)


def _ledger_failure(exc: PaidMediaWebLedgerUnavailable) -> HTTPException:
    return _web_error(
        503,
        code="paid_media_web_ledger_unavailable",
        message="Paid media web operation journal is unavailable.",
    )


def _ledger_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Map journal failures to a fail-closed 503 for route handlers."""

    try:
        return fn(*args, **kwargs)
    except PaidMediaWebLedgerUnavailable as exc:
        raise _ledger_failure(exc) from exc


def register_paid_media_web_routes(app: FastAPI) -> None:
    """Register the ADR-0013 web paid-media route family on the FastAPI app."""

    @app.post("/v1/paid-media/web/claim")
    async def paid_media_web_claim(
        request: Request,
        _runtime: str = Depends(require_api_key),
        _approval: str = Depends(require_approval_admin_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        path = str(body.get("path") or "")
        if path not in _PATHS:
            raise _web_error(
                422, code="invalid_media_request", message="Paid media path is invalid."
            )
        encoded_body = body.get("encodedBody")
        if not isinstance(encoded_body, str):
            raise _web_error(
                422,
                code="invalid_media_request",
                message="Paid media request body is invalid.",
            )
        retry_operation_id = body.get("retryOperationId")
        if retry_operation_id is None:
            _require_exact_keys(
                body, {"path", "encodedBody", "user_confirmed", "confirm_summary_sha256"}
            )
        else:
            _require_exact_keys(body, {"path", "encodedBody", "retryOperationId"})
            retry_operation_id = _validated_operation_id(retry_operation_id)
        operation, payload = _validated_request_payload(path, encoded_body)
        request_sha256 = hash_media_request(operation, payload)
        if retry_operation_id is None:
            # Fail fast on models the router cannot resolve.  Retry claims
            # deliberately skip this check: a durable success replays before
            # any route resolution, so deleting a model must not block it.
            router = getattr(request.app.state, "router", None)
            try:
                resolved = (
                    router.resolve(str(payload.get("model") or ""))
                    if router is not None
                    else None
                )
            except Exception as exc:
                raise _web_error(
                    503,
                    code="media_route_unavailable",
                    message="Paid media routing is unavailable; no provider call was made.",
                ) from exc
            if resolved is None:
                raise _web_error(
                    404,
                    code="unknown_media_model",
                    message="Requested paid media model is unavailable.",
                )
        now_ms = _now_ms()
        try:
            if retry_operation_id is not None:
                row = ledger.retry_claim(
                    principal_hash=principal,
                    operation_id=retry_operation_id,
                    path=path,
                    request_sha256=request_sha256,
                    now_ms=now_ms,
                )
                if row is None:
                    raise _web_error(
                        404,
                        code="paid_media_operation_not_found",
                        message="Paid media operation was not found.",
                    )
                return _web_json(_public_operation(row))
            if body.get("user_confirmed") is not True:
                raise _web_error(
                    422,
                    code="paid_media_confirmation_required",
                    message="Paid media claim requires explicit user confirmation.",
                )
            confirm_digest = str(body.get("confirm_summary_sha256") or "")
            if _DIGEST_RE.fullmatch(confirm_digest) is None or not hmac.compare_digest(
                confirm_digest, _confirm_digest(path, encoded_body)
            ):
                raise _web_error(
                    422,
                    code="paid_media_confirmation_mismatch",
                    message="Paid media confirmation does not match the request.",
                )
            consent = {
                "user_confirmed": True,
                "confirm_summary_sha256": confirm_digest,
                "confirmed_at_ms": now_ms,
                "request_sha256": request_sha256,
            }
            row = ledger.create_claim(
                principal_hash=principal,
                path=path,
                operation=operation,
                idempotency_key=f"webop-{secrets.token_hex(24)}",
                request_sha256=request_sha256,
                request_body_json=json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                consent_json=json.dumps(consent, sort_keys=True, separators=(",", ":")),
                now_ms=now_ms,
            )
        except PaidMediaWebConflict as exc:
            raise _web_error(409, code=exc.code, message=exc.message) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        return _web_json(_public_operation(row))

    @app.post("/v1/paid-media/web/read-asset")
    async def paid_media_web_read_asset(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> Response:
        """Materialize one durable Web reference without revealing its token."""

        principal = await _require_web_paid_media_principal(request)
        if request.headers.get("range") is not None:
            raise _web_error(
                400,
                code="unsupported_paid_media_web_asset_transfer",
                message="Web asset materialization requires one complete transfer.",
            )
        body = await _read_json_object(request)
        _require_exact_keys(body, {"reference"})
        reference = body.get("reference")
        matched = (
            _ASSET_REFERENCE_RE.fullmatch(reference)
            if isinstance(reference, str)
            else None
        )
        if matched is None:
            raise _web_error(
                422,
                code="invalid_paid_media_web_asset_reference",
                message="Paid media asset reference is invalid.",
            )
        asset_sha256 = matched.group(1)
        ledger = _web_ledger(request)
        try:
            asset_document = ledger.find_asset_document(principal, asset_sha256)
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        if asset_document is None:
            raise _web_error(
                404,
                code="paid_media_web_asset_unavailable",
                message="Paid media asset is unavailable.",
            )
        archive = getattr(request.app.state, "paid_media_web_archive", None)
        if not isinstance(archive, PaidMediaWebAssetArchive):
            raise _web_error(
                503,
                code="paid_media_web_asset_authority_unavailable",
                message="Paid media asset authority could not be verified.",
            )
        read_lease = _try_acquire_web_asset_read()
        if read_lease is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "paid_media_web_asset_read_capacity_exhausted",
                    "message": "Paid media Web asset read capacity is exhausted.",
                    "retryable": True,
                },
                headers={"Cache-Control": "no-store", "Retry-After": "1"},
            )
        response_owns_lease = False
        try:
            try:
                archived = await asyncio.to_thread(
                    archive.read,
                    principal_hash=principal,
                    asset_sha256=asset_sha256,
                )
                if archived is None:
                    await _ensure_web_asset_archive(
                        request,
                        principal_hash=principal,
                        asset_document=asset_document,
                    )
                    archived = await asyncio.to_thread(
                        archive.read,
                        principal_hash=principal,
                        asset_sha256=asset_sha256,
                    )
                    if archived is None:
                        raise PaidMediaWebArchiveUnavailable(
                            "paid-media Web archive lost a committed asset"
                        )
                else:
                    # Archive bytes are already sufficient for durable historical
                    # reads.  Still attempt to converge a crash between archive
                    # commit and live-authority cleanup; a pruned/offline live
                    # store must not make verified history unreadable.
                    try:
                        await _ensure_web_asset_archive(
                            request,
                            principal_hash=principal,
                            asset_document=asset_document,
                        )
                    except _WebArchiveReceiptDrift:
                        raise
                    except (
                        PaidMediaAssetDeliveryUnavailable,
                        PaidMediaAssetStoreError,
                        PaidMediaWebArchiveUnavailable,
                        DurableMediaAssetConflict,
                        DurableMediaRequestUnavailable,
                        OSError,
                    ):
                        pass
            except (PaidMediaAssetAuthorizationError, PaidMediaAssetProtocolError) as exc:
                raise _web_error(
                    404,
                    code="paid_media_web_asset_unavailable",
                    message="Paid media asset is unavailable.",
                ) from exc
            except (
                PaidMediaAssetDeliveryUnavailable,
                PaidMediaAssetStoreError,
                PaidMediaWebArchiveUnavailable,
                DurableMediaAssetConflict,
                DurableMediaRequestUnavailable,
                OSError,
            ) as exc:
                raise _web_error(
                    503,
                    code="paid_media_web_asset_authority_unavailable",
                    message="Paid media asset authority could not be verified.",
                ) from exc
            response = _WebAssetReadResponse(
                lease=read_lease,
                content=archived.payload,
                media_type=archived.media_type,
                headers={
                    "Content-Length": str(archived.byte_length),
                    "Content-Type": archived.media_type,
                    "X-Content-SHA256": archived.sha256,
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
            )
            response_owns_lease = True
            return response
        finally:
            if not response_owns_lease:
                read_lease.release()

    async def _execute_fresh(
        request: Request,
        ledger: PaidMediaWebLedger,
        principal: str,
        runtime_key: str,
        row: dict[str, Any],
        encoded_body: str,
    ) -> JSONResponse:
        from gateway import app as appmod  # deferred import (routing circularity)

        operation_id = str(row["operation_id"])
        now_ms = _now_ms()
        try:
            outcome = ledger.consume_cancel_or_dispatch(operation_id, now_ms=now_ms)
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        if outcome == "cancelled":
            try:
                current = ledger.get_for_principal(operation_id, principal)
            except PaidMediaWebLedgerUnavailable as exc:
                raise _ledger_failure(exc) from exc
            return _failed_execution(
                current or row,
                status=0,
                detail="Paid media request was cancelled before dispatch",
            )
        if outcome != "dispatching":
            raise _web_error(
                409,
                code="operation_state_conflict",
                message="Paid media operation cannot be dispatched from its state.",
            )
        trace_id = str(getattr(request.state, "trace_id", "") or "") or None
        try:
            if row["path"] == IMAGE_PATH:
                public_result, _replayed = await appmod._execute_paid_image_generation(
                    principal_hash=principal,
                    idempotency_key=str(row["idempotency_key"]),
                    body=json.loads(encoded_body),
                    trace_id=trace_id,
                    runtime_api_key=runtime_key,
                )
            else:
                public_result, _replayed = await appmod._execute_paid_video_generation(
                    principal_hash=principal,
                    idempotency_key=str(row["idempotency_key"]),
                    body=json.loads(encoded_body),
                    trace_id=trace_id,
                )
        except HTTPException as exc:
            if exc.status_code == 425:
                # A peer attempt is still in flight; the durable fence owns the
                # outcome, so keep the journal in dispatching and ask the
                # caller to retry later.
                raise
            retry_after = None
            headers = getattr(exc, "headers", None) or {}
            try:
                if headers.get("Retry-After"):
                    retry_after = int(headers["Retry-After"])
            except (TypeError, ValueError):
                retry_after = None
            detail = exc.detail
            message = (
                str(detail.get("message"))
                if isinstance(detail, dict) and detail.get("message")
                else "Paid media execution failed."
            )
            status = exc.status_code if 100 <= exc.status_code <= 599 else 0
            current = ledger.mark_recoverable(
                operation_id,
                last_status=status,
                retry_after_seconds=retry_after,
                now_ms=_now_ms(),
            )
            return _failed_execution(
                current,
                status=status,
                detail=message,
                retry_after_seconds=retry_after,
            )
        except (PaidMediaWebLedgerUnavailable, PaidMediaWebConflict):
            raise
        except Exception:
            try:
                ledger.mark_recoverable(
                    operation_id, last_status=None, retry_after_seconds=None, now_ms=_now_ms()
                )
            finally:
                raise
        asset_document: dict[str, Any] | None = None
        if row["path"] == IMAGE_PATH:
            if (
                not isinstance(public_result, dict)
                or public_result.get("schema") != PAID_MEDIA_RESULT_SCHEMA
                or public_result.get("kind") != "image"
            ):
                current = ledger.mark_recoverable(
                    operation_id,
                    last_status=502,
                    retry_after_seconds=None,
                    now_ms=_now_ms(),
                )
                return _failed_execution(
                    current,
                    status=502,
                    detail="Paid media result is missing its verified asset document.",
                )
            asset_document = public_result
            renderer_result = _renderer_image_result(asset_document)
        elif (
            isinstance(public_result, dict)
            and public_result.get("schema") == PAID_MEDIA_RESULT_SCHEMA
            and public_result.get("kind") == "video"
        ):
            asset_document = public_result
            assets = _archived_assets(asset_document)
            if not assets:
                current = ledger.mark_recoverable(
                    operation_id,
                    last_status=502,
                    retry_after_seconds=None,
                    now_ms=_now_ms(),
                )
                return _failed_execution(
                    current,
                    status=502,
                    detail="Paid media result is missing its verified asset document.",
                )
            renderer_result = {
                "task_id": f"nvt1_{asset_document['turnId']}",
                "status": "completed",
                "video_url": assets[0]["reference"],
            }
        else:
            renderer_result = public_result
        if asset_document is not None:
            ledger.record_asset_document(
                principal,
                asset_document,
                now_ms=_now_ms(),
            )
        result_sha256 = _result_digest(renderer_result)
        archive_receipt = (
            _web_archive_receipt_authority(
                request.app.state,
                principal_hash=principal,
                asset_document=asset_document,
            )[4]
            if asset_document is not None
            else _archive_receipt_digest(None, renderer_result)
        )
        current = ledger.mark_result_ready(
            operation_id,
            last_status=200,
            result_json=json.dumps(
                renderer_result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
            asset_document_json=(
                json.dumps(asset_document, sort_keys=True, separators=(",", ":"))
                if asset_document is not None
                else None
            ),
            result_sha256=result_sha256,
            archive_receipt_sha256=archive_receipt,
            now_ms=_now_ms(),
        )
        return _ok_execution(current)

    @app.post("/v1/paid-media/web/execute")
    async def paid_media_web_execute(
        request: Request,
        _runtime: str = Depends(require_api_key),
        _approval: str = Depends(require_approval_admin_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, {"operationId", "path", "encodedBody"})
        operation_id = _validated_operation_id(body.get("operationId"))
        path = str(body.get("path") or "")
        if path not in _PATHS:
            raise _web_error(
                422, code="invalid_media_request", message="Paid media path is invalid."
            )
        encoded_body = body.get("encodedBody")
        if not isinstance(encoded_body, str):
            raise _web_error(
                422,
                code="invalid_media_request",
                message="Paid media request body is invalid.",
            )
        try:
            row = ledger.get_for_principal(operation_id, principal)
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        if row is None:
            raise _web_error(
                404,
                code="paid_media_operation_not_found",
                message="Paid media operation was not found.",
            )
        if row["path"] != path:
            raise _web_error(
                409,
                code="operation_mismatch",
                message="Paid media retry does not match its original operation",
            )
        operation, payload = _validated_request_payload(path, encoded_body)
        if not hmac.compare_digest(
            hash_media_request(operation, payload), str(row["request_sha256"])
        ):
            raise _web_error(
                409,
                code="operation_mismatch",
                message="Paid media retry does not match its original operation",
            )
        state = str(row["state"])
        if state == "reconciled":
            raise _web_error(
                409,
                code="operation_reconciled",
                message="Paid media operation was reconciled manually",
            )
        if row["request_body_json"] is None:
            raise _web_error(
                409,
                code="operation_not_dispatchable",
                message="Imported legacy operations cannot dispatch without their exact request.",
            )
        if state in ("result_ready", "delivered"):
            if row["asset_document_json"]:
                try:
                    ledger.record_asset_document(
                        principal,
                        json.loads(str(row["asset_document_json"])),
                        now_ms=_now_ms(),
                    )
                except json.JSONDecodeError as exc:
                    raise _ledger_failure(
                        PaidMediaWebLedgerUnavailable(
                            "paid-media web archive asset document is invalid"
                        )
                    ) from exc
            return _ok_execution(row)
        now_ms = _now_ms()
        if now_ms - int(row["created_at_ms"]) >= _AUTOMATIC_RETRY_MAX_AGE_MS:
            raise _web_error(
                409,
                code="operation_expired",
                message="Paid media operation is too old for an automatic retry; "
                "reconcile it manually",
            )
        execute_flight_key = (
            id(asyncio.get_running_loop()), id(ledger), operation_id
        )
        if state == "dispatching" and execute_flight_key not in _EXECUTE_FLIGHTS:
            # A previous attempt crashed or another process owns the fence;
            # the durable store re-admits only through a fresh claim.
            try:
                row = ledger.mark_recoverable(
                    operation_id,
                    last_status=None,
                    retry_after_seconds=None,
                    now_ms=now_ms,
                )
            except PaidMediaWebConflict as exc:
                raise _web_error(
                    409, code=exc.code, message=exc.message
                ) from exc
            except PaidMediaWebLedgerUnavailable as exc:
                raise _ledger_failure(exc) from exc
        flight = _EXECUTE_FLIGHTS.get(execute_flight_key)
        if flight is None:
            flight = asyncio.create_task(
                _execute_fresh(request, ledger, principal, _runtime, row, encoded_body)
            )
            _EXECUTE_FLIGHTS[execute_flight_key] = flight

            def _cleanup(done: asyncio.Task[JSONResponse]) -> None:
                if _EXECUTE_FLIGHTS.get(execute_flight_key) is done:
                    _EXECUTE_FLIGHTS.pop(execute_flight_key, None)

            flight.add_done_callback(_cleanup)
        try:
            return await asyncio.shield(flight)
        except PaidMediaWebConflict as exc:
            raise _web_error(409, code=exc.code, message=exc.message) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc

    @app.post("/v1/paid-media/web/poll-video")
    async def paid_media_web_poll_video(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        from gateway import app as appmod  # deferred import (routing circularity)

        principal = await _require_web_paid_media_principal(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, {"taskAlias", "model"})
        task_alias = str(body.get("taskAlias") or "")
        if _VIDEO_ALIAS_RE.fullmatch(task_alias) is None:
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="Paid video task alias is invalid.",
            )
        model = str(body.get("model") or "").strip()
        if (
            not model
            or len(model) > _MAX_MODEL_CODE_POINTS
            or any(ord(character) < 32 or ord(character) == 127 for character in model)
        ):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="Paid video model is invalid.",
            )
        response = await appmod._poll_paid_video_singleflight(
            principal_hash=principal,
            task_id=task_alias,
            model=model,
        )
        try:
            payload = json.loads(response.body)
        except Exception:
            return response
        if (
            isinstance(payload, dict)
            and payload.get("schema") == PAID_MEDIA_RESULT_SCHEMA
            and payload.get("kind") == "video"
        ):
            assets = _archived_assets(payload)
            if not assets:
                raise _web_error(
                    502,
                    code="paid_media_web_result_invalid",
                    message="Paid media terminal asset document is invalid.",
                )
            ledger = _web_ledger(request)
            try:
                ledger.record_asset_document(principal, payload, now_ms=_now_ms())
                await _ensure_web_asset_archive(
                    request,
                    principal_hash=principal,
                    asset_document=payload,
                )
            except PaidMediaWebLedgerUnavailable as exc:
                raise _ledger_failure(exc) from exc
            except (
                PaidMediaAssetDeliveryUnavailable,
                PaidMediaAssetStoreError,
                PaidMediaWebArchiveUnavailable,
                DurableMediaRequestUnavailable,
                OSError,
            ) as exc:
                raise _web_error(
                    503,
                    code="paid_media_web_asset_archive_unavailable",
                    message="Paid media terminal asset could not be archived safely.",
                ) from exc
            return appmod._paid_video_poll_response(
                {
                    "task_id": task_alias,
                    "status": "completed",
                    "video_url": assets[0]["reference"],
                }
            )
        return response

    @app.post("/v1/paid-media/web/recover-archive")
    async def paid_media_web_recover_archive(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, {"operationId"})
        operation_id = _validated_operation_id(body.get("operationId"))
        row = _ledger_call(ledger.get_for_principal, operation_id, principal)
        if row is None:
            raise _web_error(
                404,
                code="paid_media_operation_not_found",
                message="Paid media operation was not found.",
            )
        if row["result_json"] is None or row["result_sha256"] is None:
            raise _web_error(
                409,
                code="paid_media_archive_unavailable",
                message="Paid media operation has no archived result.",
            )
        renderer_result = json.loads(str(row["result_json"]))
        asset_document = (
            json.loads(str(row["asset_document_json"]))
            if row["asset_document_json"]
            else None
        )
        model = ""
        if row["request_body_json"]:
            try:
                model = str(json.loads(str(row["request_body_json"])).get("model") or "")
            except (json.JSONDecodeError, AttributeError):
                model = ""
        return _web_json(
            {
                "operationId": row["operation_id"],
                "path": row["path"],
                "model": model,
                "status": int(row["last_status"] or 200),
                "result": renderer_result,
                "deliveryProof": _delivery_proof(row),
                "archive": {
                    "receiptSha256": row["archive_receipt_sha256"],
                    "responseSha256": row["result_sha256"],
                    "responseByteLength": len(_canonical_json_bytes(renderer_result)),
                    "assets": _archived_assets(asset_document),
                },
            }
        )

    @app.post("/v1/paid-media/web/list-archives")
    async def paid_media_web_list_archives(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        allowed = {"cursor", "limit"}
        if any(key not in allowed for key in body):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="请求字段闭集不匹配。",
            )
        cursor = body.get("cursor")
        if cursor is not None and not isinstance(cursor, str):
            raise _web_error(
                422, code="invalid_paid_media_web_request", message="cursor 无效。"
            )
        limit = body.get("limit", _DEFAULT_ARCHIVE_PAGE)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_ARCHIVE_PAGE
        ):
            raise _web_error(
                422, code="invalid_paid_media_web_request", message="limit 无效。"
            )
        try:
            rows, next_cursor = _ledger_call(
                ledger.list_archives, principal, cursor=cursor, limit=limit
            )
        except ValueError as exc:
            raise _web_error(
                422, code="invalid_paid_media_web_request", message="cursor 无效。"
            ) from exc
        items = []
        for row in rows:
            asset_document = (
                json.loads(str(row["asset_document_json"]))
                if row["asset_document_json"]
                else None
            )
            model = ""
            if row["request_body_json"]:
                try:
                    model = str(
                        json.loads(str(row["request_body_json"])).get("model") or ""
                    )
                except (json.JSONDecodeError, AttributeError):
                    model = ""
            renderer_result = json.loads(str(row["result_json"]))
            items.append(
                {
                    "operationId": row["operation_id"],
                    "path": row["path"],
                    "model": model,
                    "status": int(row["last_status"] or 200),
                    "kind": (
                        "image"
                        if row["path"] == IMAGE_PATH
                        else "video_task"
                    ),
                    "archivedAt": int(row["archived_at_ms"]),
                    "receiptSha256": row["archive_receipt_sha256"],
                    "responseByteLength": len(_canonical_json_bytes(renderer_result)),
                    "assets": _archived_assets(asset_document),
                }
            )
        payload: dict[str, Any] = {"items": items}
        if next_cursor is not None:
            payload["nextCursor"] = next_cursor
        return _web_json(payload)

    @app.post("/v1/paid-media/web/cancel")
    async def paid_media_web_cancel(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, {"operationId"})
        operation_id = _validated_operation_id(body.get("operationId"))
        row = _ledger_call(ledger.get_for_principal, operation_id, principal)
        if row is None:
            return _web_json({"ok": False})
        return _web_json(
            {"ok": _ledger_call(ledger.request_cancel, operation_id, now_ms=_now_ms())}
        )

    @app.post("/v1/paid-media/web/list")
    async def paid_media_web_list(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, set())
        rows = _ledger_call(ledger.list_unresolved, principal)
        return _web_json([_public_operation(row) for row in rows])

    @app.post("/v1/paid-media/web/acknowledge")
    async def paid_media_web_acknowledge(
        request: Request,
        _runtime: str = Depends(require_api_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(
            body, {"operationId", "resultSha256", "archiveReceiptSha256"}
        )
        operation_id = _validated_operation_id(body.get("operationId"))
        try:
            result_sha256 = _validated_digest(
                body.get("resultSha256"), "resultSha256"
            )
            archive_receipt = _validated_digest(
                body.get("archiveReceiptSha256"), "archiveReceiptSha256"
            )
        except ValueError as exc:
            raise _web_error(
                422, code="invalid_paid_media_web_request", message=str(exc)
            ) from exc
        row = _ledger_call(ledger.get_for_principal, operation_id, principal)
        if row is None:
            raise _web_error(
                404,
                code="paid_media_operation_not_found",
                message="Paid media operation was not found.",
            )
        if str(row["state"]) not in {"result_ready", "delivered"} or not (
            isinstance(row["result_sha256"], str)
            and isinstance(row["archive_receipt_sha256"], str)
            and hmac.compare_digest(str(row["result_sha256"]), result_sha256)
            and hmac.compare_digest(
                str(row["archive_receipt_sha256"]), archive_receipt
            )
        ):
            raise _web_error(
                409,
                code="operation_proof_conflict",
                message="Paid media delivery proof does not match the archive receipt",
            )
        if row["asset_document_json"]:
            try:
                asset_document = json.loads(str(row["asset_document_json"]))
                deterministic_receipt = _web_archive_receipt_authority(
                    request.app.state,
                    principal_hash=principal,
                    asset_document=asset_document,
                )[4]
                if not hmac.compare_digest(
                    deterministic_receipt,
                    archive_receipt,
                ):
                    raise _web_error(
                        409,
                        code="operation_proof_conflict",
                        message=(
                            "Paid media delivery proof does not match the "
                            "archive receipt"
                        ),
                    )
                if str(row["state"]) == "result_ready":
                    await _ensure_web_asset_archive(
                        request,
                        principal_hash=principal,
                        asset_document=asset_document,
                        expected_receipt_sha256=archive_receipt,
                    )
                else:
                    complete_receipt = await _web_archive_receipt_if_complete(
                        request,
                        principal_hash=principal,
                        asset_document=asset_document,
                        expected_receipt_sha256=archive_receipt,
                    )
                    if complete_receipt is None:
                        await _ensure_web_asset_archive(
                            request,
                            principal_hash=principal,
                            asset_document=asset_document,
                            expected_receipt_sha256=archive_receipt,
                        )
            except json.JSONDecodeError as exc:
                raise _ledger_failure(
                    PaidMediaWebLedgerUnavailable(
                        "paid-media Web asset document is invalid"
                    )
                ) from exc
            except (
                PaidMediaAssetDeliveryUnavailable,
                PaidMediaAssetStoreError,
                PaidMediaWebArchiveUnavailable,
                DurableMediaRequestUnavailable,
                OSError,
            ) as exc:
                raise _web_error(
                    503,
                    code="paid_media_web_asset_archive_unavailable",
                    message="Paid media assets could not be archived safely.",
                ) from exc
        try:
            updated = ledger.mark_delivered(
                operation_id,
                result_sha256=result_sha256,
                archive_receipt_sha256=archive_receipt,
                now_ms=_now_ms(),
            )
        except PaidMediaWebConflict as exc:
            raise _web_error(409, code=exc.code, message=exc.message) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        return _web_json(_public_operation(updated))

    @app.post("/v1/paid-media/web/abandon")
    async def paid_media_web_abandon(
        request: Request,
        _runtime: str = Depends(require_api_key),
        _approval: str = Depends(require_approval_admin_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(body, {"operationId", "evidence"})
        operation_id = _validated_operation_id(body.get("operationId"))
        evidence = _validated_bounded_text(
            body.get("evidence"), "evidence", _MAX_EVIDENCE_BYTES
        )
        row = _ledger_call(ledger.get_for_principal, operation_id, principal)
        if row is None:
            raise _web_error(
                404,
                code="paid_media_operation_not_found",
                message="Paid media operation was not found.",
            )
        reconcile = {
            "kind": "abandon",
            "evidence": evidence,
            "at_ms": _now_ms(),
        }
        try:
            updated = ledger.mark_reconciled(
                operation_id,
                reconcile_json=json.dumps(reconcile, sort_keys=True, separators=(",", ":")),
                never_dispatched_only=True,
                now_ms=_now_ms(),
            )
        except PaidMediaWebConflict as exc:
            raise _web_error(
                409,
                code="operation_state_conflict",
                message="Only a never-dispatched paid media claim can be abandoned automatically",
            ) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        return _web_json(_public_operation(updated))

    @app.post("/v1/paid-media/web/reconcile")
    async def paid_media_web_reconcile(
        request: Request,
        _runtime: str = Depends(require_api_key),
        _approval: str = Depends(require_approval_admin_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        body = await _read_json_object(request)
        _require_exact_keys(
            body,
            {"operationId", "reason", "evidence", "user_confirmed", "confirm_final"},
        )
        operation_id = _validated_operation_id(body.get("operationId"))
        reason = _validated_bounded_text(body.get("reason"), "reason", _MAX_REASON_BYTES)
        evidence = _validated_bounded_text(
            body.get("evidence"), "evidence", _MAX_EVIDENCE_BYTES
        )
        if body.get("user_confirmed") is not True or body.get("confirm_final") is not True:
            raise _web_error(
                422,
                code="paid_media_confirmation_required",
                message="Paid media reconciliation requires double confirmation.",
            )
        row = _ledger_call(ledger.get_for_principal, operation_id, principal)
        if row is None:
            raise _web_error(
                404,
                code="paid_media_operation_not_found",
                message="Paid media operation was not found.",
            )
        reconcile = {
            "kind": "reconcile",
            "reason": reason,
            "evidence": evidence,
            "confirmed": True,
            "at_ms": _now_ms(),
        }
        try:
            updated = ledger.mark_reconciled(
                operation_id,
                reconcile_json=json.dumps(reconcile, sort_keys=True, separators=(",", ":")),
                never_dispatched_only=False,
                now_ms=_now_ms(),
            )
        except PaidMediaWebConflict as exc:
            raise _web_error(
                409,
                code="operation_state_conflict",
                message="Paid media operation cannot be reconciled from its state",
            ) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        return _web_json(_public_operation(updated))

    @app.post("/v1/paid-media/web/import-legacy")
    async def paid_media_web_import_legacy(
        request: Request,
        _runtime: str = Depends(require_api_key),
        _approval: str = Depends(require_approval_admin_key),
    ) -> JSONResponse:
        principal = await _require_web_paid_media_principal(request)
        ledger = _web_ledger(request)
        try:
            body = await request.json()
        except Exception as exc:
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="请求正文不是合法 JSON。",
            ) from exc
        if body is None or body == {"kind": "migrated"}:
            return _web_json({"ok": True})
        if not isinstance(body, dict):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="请求正文必须是对象。",
            )
        allowed = {
            "operationId",
            "path",
            "requestSha256",
            "createdAt",
            "updatedAt",
            "state",
            "lastStatus",
            "retryAfterSeconds",
        }
        required = {
            "operationId",
            "path",
            "requestSha256",
            "createdAt",
            "updatedAt",
            "state",
        }
        if not required.issubset(body.keys()) or any(
            key not in allowed for key in body
        ):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录字段闭集不匹配。",
            )
        operation_id = _validated_operation_id(body.get("operationId"))
        path = str(body.get("path") or "")
        if path not in _PATHS:
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录 path 无效。",
            )
        try:
            request_sha256 = _validated_digest(
                body.get("requestSha256"), "requestSha256"
            )
        except ValueError as exc:
            raise _web_error(
                422, code="invalid_paid_media_web_request", message=str(exc)
            ) from exc
        created_at = body.get("createdAt")
        updated_at = body.get("updatedAt")
        if (
            isinstance(created_at, bool)
            or not isinstance(created_at, (int, float))
            or isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float))
            or not 0 <= created_at <= updated_at < (1 << 53)
        ):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录时间戳无效。",
            )
        state = body.get("state")
        if state not in ("pending", "recoverable"):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录 state 无效。",
            )
        last_status = body.get("lastStatus")
        if last_status is not None and (
            isinstance(last_status, bool)
            or not isinstance(last_status, int)
            or not 100 <= last_status <= 599
        ):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录 lastStatus 无效。",
            )
        retry_after = body.get("retryAfterSeconds")
        if retry_after is not None and (
            isinstance(retry_after, bool)
            or not isinstance(retry_after, int)
            or not 0 <= retry_after <= 86400
        ):
            raise _web_error(
                422,
                code="invalid_paid_media_web_request",
                message="legacy 记录 retryAfterSeconds 无效。",
            )
        record = {
            "operationId": operation_id,
            "path": path,
            "requestSha256": request_sha256,
            "createdAt": int(created_at),
            "updatedAt": int(updated_at),
            "state": state,
            **({"lastStatus": last_status} if last_status is not None else {}),
            **({"retryAfterSeconds": retry_after} if retry_after is not None else {}),
        }
        consent = {
            "imported_legacy": True,
            "user_confirmed": True,
            "confirmed_at_ms": _now_ms(),
        }
        try:
            row = ledger.import_legacy(
                record,
                principal_hash=principal,
                path=path,
                operation=_OPERATIONS[path],
                idempotency_key=f"webop-legacy-{secrets.token_hex(20)}",
                consent_json=json.dumps(consent, sort_keys=True, separators=(",", ":")),
                now_ms=_now_ms(),
            )
        except PaidMediaWebConflict as exc:
            raise _web_error(409, code=exc.code, message=exc.message) from exc
        except PaidMediaWebLedgerUnavailable as exc:
            raise _ledger_failure(exc) from exc
        return _web_json({"ok": True, "operation": _public_operation(row)})


__all__ = [
    "PaidMediaWebConflict",
    "PaidMediaWebLedger",
    "PaidMediaWebLedgerUnavailable",
    "register_paid_media_web_routes",
]
