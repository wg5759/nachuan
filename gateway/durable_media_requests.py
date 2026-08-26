"""Durable, fenced admission for paid media creation requests.

The store owns request execution identity.  ``gateway.media_cache`` remains a
best-effort performance cache and is never an execution-authorisation source.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Literal

from gateway.paid_media_asset_protocol import (
    RESULT_SCHEMA as PAID_MEDIA_ASSET_RESULT_SCHEMA,
)
from gateway.paid_media_asset_protocol import (
    PaidMediaAssetProtocolError,
    asset_token_hash,
    canonical_asset_result,
    canonical_token_set_digest,
    create_asset_token,
    parse_asset_result,
)
from gateway.sqlite_runtime import enable_wal_with_deadline

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_VIDEO_ALIAS_RE = re.compile(r"^nvt1_[0-9a-f]{64}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
_OPERATIONS = frozenset({"images.create", "videos.create"})
_DEFAULT_LEASE_SECONDS = 15 * 60.0
_DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60.0
_PREVIOUS_DEFAULT_MAX_RESPONSE_BYTES = 24 * 1024 * 1024
_DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024 * 1024
_ABSOLUTE_MAX_RESPONSE_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_TOTAL_RESPONSE_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_RECORDS = 50_000
_DEFAULT_PRUNE_BATCH = 256
_DEFAULT_MAX_DATABASE_BYTES = 1024 * 1024 * 1024
_MAX_SHM_BYTES = 16 * 1024 * 1024
_LEGACY_SCHEMA_VERSION = 1
_V2_SCHEMA_VERSION = 2
_V3_SCHEMA_VERSION = 3
_SCHEMA_VERSION = 4
_APPLICATION_ID = 0x4E434D52  # "NCMR"
_LEGACY_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-durable-paid-media-request-schema-v1"
).hexdigest()
_V2_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-durable-paid-media-request-schema-v2-antirollback"
).hexdigest()
_V3_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-durable-paid-media-request-schema-v3-installation-authority"
).hexdigest()
_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-durable-paid-media-request-schema-v4-asset-authority"
).hexdigest()
_PAID_MEDIA_SCHEMA_PROFILE = "paid_media"
_CHANNEL_MEDIA_SCHEMA_PROFILE = "channel_media"
_SCHEMA_PROFILES = frozenset(
    {_PAID_MEDIA_SCHEMA_PROFILE, _CHANNEL_MEDIA_SCHEMA_PROFILE}
)
_CHANNEL_MEDIA_APPLICATION_ID = 0x4E43434D  # "NCCM"
_CHANNEL_MEDIA_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-durable-channel-media-request-schema-v1-core-v4-permanent-admission"
).hexdigest()
_LEGACY_ANCHOR_FORMAT = 1
_ANCHOR_FORMAT = 2
_ANCHOR_MAX_BYTES = 1024
_MAX_MUTATION_SEQUENCE = (1 << 63) - 1
_AUTHORITY_STATE_DOMAIN = b"nachuan-durable-media-authority-state-v1\x00"
_CONSTRUCTION_POLICIES = frozenset({"dev", "create_bound", "open_bound"})
_LEGACY_VIDEO_ENVELOPE_VERSION = 1
_VIDEO_ENVELOPE_VERSION = 2
_PREPARED_VIDEO_DOMAIN = b"nachuan-prepared-video-asset-v1\x00"
_PREPARED_VIDEO_OPERATOR_RECOVERY_DOMAIN = (
    b"nachuan-prepared-video-operator-recovery-v1\x00"
)
_VIDEO_POLL_LEASE_SECONDS = 5 * 60.0
_VIDEO_POLL_BACKOFF_BASE_SECONDS = 2.0
_VIDEO_POLL_BACKOFF_MAX_SECONDS = 60.0
_MAX_VIDEO_ROUTE_TEXT = 512
_MAX_VIDEO_POLL_RESPONSE_BYTES = 1024 * 1024
_ASSET_SUCCESS_UNACKED_EXPIRES_AT = 253402300799.0  # 9999-12-31T23:59:59Z
_DEFAULT_MAX_ASSET_RESERVATION_BYTES = 8 * 1024 * 1024 * 1024
_ASSET_OPERATION_RESERVATION_BYTES = 2 * 4 * 24 * 1024 * 1024

_REQUEST_TABLE_DDL = f"""
CREATE TABLE durable_media_requests (
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    key_hash TEXT NOT NULL CHECK(
        length(key_hash)=64 AND key_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_sha256 TEXT NOT NULL CHECK(
        length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK(status IN (
        'processing','succeeded','recovery_required'
    )),
    fencing_token TEXT NOT NULL,
    lease_expires_at REAL NOT NULL CHECK(lease_expires_at >= 0),
    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 1),
    provider_phase INTEGER NOT NULL DEFAULT 0 CHECK(provider_phase IN (0,1)),
    response_json TEXT CHECK(
        response_json IS NULL OR
        length(CAST(response_json AS BLOB)) <= {_ABSOLUTE_MAX_RESPONSE_BYTES}
    ),
    reserved_response_bytes INTEGER NOT NULL CHECK(reserved_response_bytes >= 0),
    created_at REAL NOT NULL CHECK(created_at >= 0),
    updated_at REAL NOT NULL CHECK(updated_at >= 0),
    expires_at REAL NOT NULL CHECK(expires_at >= 0),
    CHECK(
        (status='processing' AND response_json IS NULL
            AND reserved_response_bytes>0
            AND length(fencing_token)=64
            AND fencing_token NOT GLOB '*[^0-9a-f]*'
            AND lease_expires_at>0)
        OR
        (status='succeeded' AND provider_phase=1
            AND response_json IS NOT NULL AND reserved_response_bytes=0
            AND fencing_token='' AND lease_expires_at=0)
        OR
        (status='recovery_required' AND provider_phase=1
            AND response_json IS NULL AND reserved_response_bytes=0
            AND fencing_token='' AND lease_expires_at=0)
    ),
    PRIMARY KEY(principal_hash, operation, key_hash)
) WITHOUT ROWID
"""

_LEGACY_META_TABLE_DDL = """
CREATE TABLE durable_media_requests_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    record_count INTEGER NOT NULL CHECK(record_count>=0),
    response_bytes INTEGER NOT NULL CHECK(response_bytes>=0),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
    max_records INTEGER NOT NULL CHECK(max_records>=1),
    max_response_bytes INTEGER NOT NULL CHECK(max_response_bytes>=64),
    max_total_response_bytes INTEGER NOT NULL CHECK(max_total_response_bytes>=64),
    max_database_bytes INTEGER NOT NULL CHECK(max_database_bytes>=262144)
) WITHOUT ROWID
"""

_V2_META_TABLE_DDL = """
CREATE TABLE durable_media_requests_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=2),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    database_identity TEXT NOT NULL CHECK(
        length(database_identity)=64 AND
        database_identity NOT GLOB '*[^0-9a-f]*'
    ),
    mutation_sequence INTEGER NOT NULL CHECK(mutation_sequence>=0),
    record_count INTEGER NOT NULL CHECK(record_count>=0),
    response_bytes INTEGER NOT NULL CHECK(response_bytes>=0),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
    max_records INTEGER NOT NULL CHECK(max_records>=1),
    max_response_bytes INTEGER NOT NULL CHECK(max_response_bytes>=64),
    max_total_response_bytes INTEGER NOT NULL CHECK(max_total_response_bytes>=64),
    max_database_bytes INTEGER NOT NULL CHECK(max_database_bytes>=262144)
) WITHOUT ROWID
"""

_V3_META_TABLE_DDL = """
CREATE TABLE durable_media_requests_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=3),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    database_identity TEXT NOT NULL CHECK(
        length(database_identity)=64 AND
        database_identity NOT GLOB '*[^0-9a-f]*' AND
        database_identity<>'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    mutation_sequence INTEGER NOT NULL CHECK(mutation_sequence>=0),
    authority_state_digest TEXT NOT NULL CHECK(
        length(authority_state_digest)=64 AND
        authority_state_digest NOT GLOB '*[^0-9a-f]*' AND
        authority_state_digest<>'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    authority_mode TEXT NOT NULL CHECK(authority_mode IN ('normal','manual_only')),
    authority_installation_id TEXT,
    authority_epoch INTEGER,
    authority_recovery_floor INTEGER,
    authority_recovery_state_digest TEXT,
    record_count INTEGER NOT NULL CHECK(record_count>=0),
    response_bytes INTEGER NOT NULL CHECK(response_bytes>=0),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),
    max_records INTEGER NOT NULL CHECK(max_records>=1),
    max_response_bytes INTEGER NOT NULL CHECK(max_response_bytes>=64),
    max_total_response_bytes INTEGER NOT NULL CHECK(max_total_response_bytes>=64),
    max_database_bytes INTEGER NOT NULL CHECK(max_database_bytes>=262144),
    CHECK(
        (authority_mode='normal' AND authority_installation_id IS NULL
            AND authority_epoch IS NULL AND authority_recovery_floor IS NULL
            AND authority_recovery_state_digest IS NULL)
        OR
        (authority_mode='manual_only'
            AND length(authority_installation_id)=64
            AND authority_installation_id NOT GLOB '*[^0-9a-f]*'
            AND authority_installation_id<>'0000000000000000000000000000000000000000000000000000000000000000'
            AND authority_epoch>=1 AND authority_recovery_floor>=0
            AND length(authority_recovery_state_digest)=64
            AND authority_recovery_state_digest NOT GLOB '*[^0-9a-f]*'
            AND authority_recovery_state_digest<>'0000000000000000000000000000000000000000000000000000000000000000'
            AND mutation_sequence=authority_recovery_floor+1)
    )
) WITHOUT ROWID
"""

_META_TABLE_DDL = _V3_META_TABLE_DDL.replace(
    "CHECK(schema_version=3)", "CHECK(schema_version=4)"
)

_ASSET_CAPACITY_TABLE_DDL = f"""
CREATE TABLE durable_media_asset_capacity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    max_capacity_bytes INTEGER NOT NULL CHECK(
        max_capacity_bytes>={_ASSET_OPERATION_RESERVATION_BYTES}
    ),
    reserved_total_bytes INTEGER NOT NULL CHECK(reserved_total_bytes>=0)
) WITHOUT ROWID
"""

_ASSET_AUTHORITY_TABLE_DDL = f"""
CREATE TABLE durable_media_asset_authority (
    turn_id TEXT PRIMARY KEY REFERENCES durable_media_requests(turn_id)
        ON DELETE CASCADE,
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    installation_epoch INTEGER NOT NULL CHECK(installation_epoch>=1),
    state TEXT NOT NULL CHECK(state IN (
        'reserved','committed','acked_pending_cleanup','acked'
    )),
    reserved_bytes INTEGER NOT NULL CHECK(
        reserved_bytes IN (0,{_ASSET_OPERATION_RESERVATION_BYTES})
    ),
    token_set_digest TEXT,
    archive_receipt_sha256 TEXT,
    acked_at REAL,
    CHECK(
        (state='reserved' AND reserved_bytes={_ASSET_OPERATION_RESERVATION_BYTES}
            AND token_set_digest IS NULL AND archive_receipt_sha256 IS NULL
            AND acked_at IS NULL)
        OR
        (state='committed' AND reserved_bytes={_ASSET_OPERATION_RESERVATION_BYTES}
            AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*'
            AND archive_receipt_sha256 IS NULL AND acked_at IS NULL)
        OR
        (state='acked_pending_cleanup'
            AND reserved_bytes={_ASSET_OPERATION_RESERVATION_BYTES}
            AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*'
            AND length(archive_receipt_sha256)=64
            AND archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
            AND acked_at>=0)
        OR
        (state='acked' AND reserved_bytes=0
            AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*'
            AND length(archive_receipt_sha256)=64
            AND archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
            AND acked_at>=0)
    )
) WITHOUT ROWID
"""

_ASSET_CAPACITY_INSERT_DDL = """
CREATE TRIGGER durable_media_asset_capacity_insert
BEFORE INSERT ON durable_media_asset_authority
WHEN (SELECT reserved_total_bytes+NEW.reserved_bytes>max_capacity_bytes
    FROM durable_media_asset_capacity WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'durable paid-media asset capacity reached');
END
"""

_ASSET_CAPACITY_UPDATE_DDL = """
CREATE TRIGGER durable_media_asset_capacity_update
BEFORE UPDATE OF reserved_bytes ON durable_media_asset_authority
WHEN (SELECT reserved_total_bytes-OLD.reserved_bytes+NEW.reserved_bytes>
    max_capacity_bytes FROM durable_media_asset_capacity WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'durable paid-media asset capacity reached');
END
"""

_ASSET_COUNT_INSERT_DDL = """
CREATE TRIGGER durable_media_asset_count_insert
AFTER INSERT ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes+NEW.reserved_bytes
    WHERE singleton=1;
END
"""

_ASSET_COUNT_DELETE_DDL = """
CREATE TRIGGER durable_media_asset_count_delete
AFTER DELETE ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes-OLD.reserved_bytes
    WHERE singleton=1;
END
"""

_ASSET_COUNT_UPDATE_DDL = """
CREATE TRIGGER durable_media_asset_count_update
AFTER UPDATE OF reserved_bytes ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes-OLD.reserved_bytes+NEW.reserved_bytes
    WHERE singleton=1;
END
"""

_EXPECTED_REQUEST_COLUMNS = (
    "principal_hash",
    "operation",
    "key_hash",
    "turn_id",
    "request_sha256",
    "status",
    "fencing_token",
    "lease_expires_at",
    "attempt_count",
    "provider_phase",
    "response_json",
    "reserved_response_bytes",
    "created_at",
    "updated_at",
    "expires_at",
)
_EXPECTED_META_COLUMNS = (
    "singleton",
    "schema_version",
    "schema_fingerprint",
    "database_identity",
    "mutation_sequence",
    "authority_state_digest",
    "authority_mode",
    "authority_installation_id",
    "authority_epoch",
    "authority_recovery_floor",
    "authority_recovery_state_digest",
    "record_count",
    "response_bytes",
    "reserved_bytes",
    "max_records",
    "max_response_bytes",
    "max_total_response_bytes",
    "max_database_bytes",
)

_BASE_SCHEMA_AUXILIARY_DDL: dict[tuple[str, str], str] = {
    ("index", "durable_media_turn_idx"): """
        CREATE UNIQUE INDEX durable_media_turn_idx
        ON durable_media_requests(turn_id)
    """,
    ("index", "durable_media_expiry_idx"): """
        CREATE INDEX durable_media_expiry_idx
        ON durable_media_requests(expires_at)
    """,
    ("trigger", "durable_media_capacity_insert"): """
        CREATE TRIGGER durable_media_capacity_insert
        BEFORE INSERT ON durable_media_requests
        WHEN (SELECT record_count>=max_records OR
            response_bytes+reserved_bytes+
            COALESCE(length(CAST(NEW.response_json AS BLOB)),0)+
            NEW.reserved_response_bytes>max_total_response_bytes
            FROM durable_media_requests_meta WHERE singleton=1)
        BEGIN
            SELECT RAISE(ABORT, 'durable media capacity reached');
        END
    """,
    ("trigger", "durable_media_capacity_update"): """
        CREATE TRIGGER durable_media_capacity_update
        BEFORE UPDATE OF response_json,reserved_response_bytes
        ON durable_media_requests
        WHEN (SELECT response_bytes+reserved_bytes-
            COALESCE(length(CAST(OLD.response_json AS BLOB)),0)-
            OLD.reserved_response_bytes+
            COALESCE(length(CAST(NEW.response_json AS BLOB)),0)+
            NEW.reserved_response_bytes>max_total_response_bytes
            FROM durable_media_requests_meta WHERE singleton=1)
        BEGIN
            SELECT RAISE(ABORT, 'durable media response capacity reached');
        END
    """,
    ("trigger", "durable_media_count_insert"): """
        CREATE TRIGGER durable_media_count_insert
        AFTER INSERT ON durable_media_requests
        BEGIN
            UPDATE durable_media_requests_meta
            SET record_count=record_count+1,
                response_bytes=response_bytes+
                    COALESCE(length(CAST(NEW.response_json AS BLOB)),0),
                reserved_bytes=reserved_bytes+NEW.reserved_response_bytes
            WHERE singleton=1;
        END
    """,
    ("trigger", "durable_media_count_delete"): """
        CREATE TRIGGER durable_media_count_delete
        AFTER DELETE ON durable_media_requests
        BEGIN
            UPDATE durable_media_requests_meta
            SET record_count=record_count-1,
                response_bytes=response_bytes-
                    COALESCE(length(CAST(OLD.response_json AS BLOB)),0),
                reserved_bytes=reserved_bytes-OLD.reserved_response_bytes
            WHERE singleton=1;
        END
    """,
    ("trigger", "durable_media_count_update"): """
        CREATE TRIGGER durable_media_count_update
        AFTER UPDATE OF response_json,reserved_response_bytes
        ON durable_media_requests
        BEGIN
            UPDATE durable_media_requests_meta
            SET response_bytes=response_bytes-
                    COALESCE(length(CAST(OLD.response_json AS BLOB)),0)+
                    COALESCE(length(CAST(NEW.response_json AS BLOB)),0),
                reserved_bytes=reserved_bytes-
                    OLD.reserved_response_bytes+NEW.reserved_response_bytes
            WHERE singleton=1;
        END
    """,
}

_ASSET_SCHEMA_DDL: dict[tuple[str, str], str] = {
    ("table", "durable_media_asset_capacity"): _ASSET_CAPACITY_TABLE_DDL,
    ("table", "durable_media_asset_authority"): _ASSET_AUTHORITY_TABLE_DDL,
    ("trigger", "durable_media_asset_capacity_insert"): _ASSET_CAPACITY_INSERT_DDL,
    ("trigger", "durable_media_asset_capacity_update"): _ASSET_CAPACITY_UPDATE_DDL,
    ("trigger", "durable_media_asset_count_insert"): _ASSET_COUNT_INSERT_DDL,
    ("trigger", "durable_media_asset_count_delete"): _ASSET_COUNT_DELETE_DDL,
    ("trigger", "durable_media_asset_count_update"): _ASSET_COUNT_UPDATE_DDL,
}

_SCHEMA_AUXILIARY_DDL: dict[tuple[str, str], str] = {
    **_BASE_SCHEMA_AUXILIARY_DDL,
    **_ASSET_SCHEMA_DDL,
}

_CHANNEL_MEDIA_ADMISSION_TABLE_DDL = """
CREATE TABLE durable_channel_media_admissions (
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL CHECK(operation='images.create'),
    key_hash TEXT NOT NULL CHECK(
        length(key_hash)=64 AND key_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL UNIQUE CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_sha256 TEXT NOT NULL CHECK(
        length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK(state IN (
        'provider_phase','succeeded','recovery_required'
    )),
    attempt_count INTEGER NOT NULL CHECK(attempt_count>=1),
    provider_entered_at REAL NOT NULL CHECK(provider_entered_at>=0),
    updated_at REAL NOT NULL CHECK(updated_at>=provider_entered_at),
    PRIMARY KEY(principal_hash,operation,key_hash)
) WITHOUT ROWID
"""

_CHANNEL_MEDIA_ADMISSION_CAPACITY_DDL = """
CREATE TRIGGER durable_channel_media_admission_capacity
BEFORE INSERT ON durable_channel_media_admissions
WHEN (SELECT COUNT(*) FROM durable_channel_media_admissions)>=(
    SELECT max_records FROM durable_media_requests_meta WHERE singleton=1
)
BEGIN
    SELECT RAISE(ABORT, 'durable channel media admission capacity reached');
END
"""

_CHANNEL_MEDIA_ADMISSION_TERMINAL_DDL = """
CREATE TRIGGER durable_channel_media_admission_terminal
AFTER UPDATE OF status ON durable_media_requests
WHEN NEW.provider_phase=1 AND NEW.status IN ('succeeded','recovery_required')
BEGIN
    SELECT RAISE(ABORT, 'durable channel media admission is missing')
    WHERE NOT EXISTS(
        SELECT 1 FROM durable_channel_media_admissions
        WHERE principal_hash=NEW.principal_hash AND operation=NEW.operation
            AND key_hash=NEW.key_hash AND turn_id=NEW.turn_id
            AND request_sha256=NEW.request_sha256
    );
    UPDATE durable_channel_media_admissions
    SET state=NEW.status,attempt_count=NEW.attempt_count,updated_at=NEW.updated_at
    WHERE principal_hash=NEW.principal_hash AND operation=NEW.operation
        AND key_hash=NEW.key_hash AND turn_id=NEW.turn_id
        AND request_sha256=NEW.request_sha256;
END
"""

_CHANNEL_MEDIA_SCHEMA_AUXILIARY_DDL: dict[tuple[str, str], str] = {
    **_SCHEMA_AUXILIARY_DDL,
    (
        "table",
        "durable_channel_media_admissions",
    ): _CHANNEL_MEDIA_ADMISSION_TABLE_DDL,
    (
        "trigger",
        "durable_channel_media_admission_capacity",
    ): _CHANNEL_MEDIA_ADMISSION_CAPACITY_DDL,
    (
        "trigger",
        "durable_channel_media_admission_terminal",
    ): _CHANNEL_MEDIA_ADMISSION_TERMINAL_DDL,
}


def _persistent_schema_rows(
    connection: sqlite3.Connection,
) -> list[tuple[object, object, object, object]]:
    """Enumerate every non-internal persistent schema object.

    SQLite-owned objects such as ``sqlite_autoindex_*`` have reserved names and
    may have no DDL, but they are still part of the exact materialized
    generation.  Enumerating every row prevents an attacker-created
    ``sqlite_*`` object from hiding behind a prefix exemption.
    """

    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()


@lru_cache(maxsize=8)
def _materialized_schema_sql(
    declarations: tuple[tuple[str, str, str], ...],
) -> dict[tuple[str, str], tuple[str, object]]:
    """Return SQLite's exact stored SQL for DDL executed by this module."""

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        for _object_type, _name, ddl in declarations:
            connection.execute(ddl)
        actual = {
            (str(object_type), str(name)): (str(tbl_name), sql)
            for object_type, name, tbl_name, sql in _persistent_schema_rows(connection)
        }
    expected_identities = {
        (object_type, name) for object_type, name, _ddl in declarations
    }
    if not expected_identities.issubset(actual) or any(
        not isinstance(actual[identity][1], str) or not actual[identity][1]
        for identity in expected_identities
    ):
        raise sqlite3.DatabaseError(
            "durable media expected schema could not be materialized exactly"
        )
    return actual


def _expected_schema_sql(
    declarations: dict[tuple[str, str], str],
) -> dict[tuple[str, str], tuple[str, object]]:
    return _materialized_schema_sql(
        tuple(
            (object_type, name, ddl)
            for (object_type, name), ddl in declarations.items()
        )
    )


class DurableMediaRequestUnavailable(RuntimeError):
    """The required durable media request store cannot be used safely."""


class DurableMediaAuthorityCorruption(DurableMediaRequestUnavailable):
    """The local authority proof is deterministically malformed or replaced."""


class DurableMediaRootCommitPending(DurableMediaRequestUnavailable):
    """Local state committed, but the Installation Root has not confirmed it."""


class DurableMediaAssetConflict(RuntimeError):
    """A client ACK deterministically conflicts with immutable asset authority."""


class _DatabaseFamilyChanged(RuntimeError):
    """A read-only durable-media family snapshot changed."""


@dataclass(frozen=True, slots=True)
class DurableMediaRootState:
    """Minimal, non-secret proof mirrored by the Installation Epoch Root."""

    database_identity: str
    mutation_sequence: int
    state_digest: str
    authority_mode: Literal["normal", "manual_only"]
    installation_id: str | None = None
    epoch: int | None = None
    recovery_floor: int | None = None
    recovery_state_digest: str | None = None


@dataclass(frozen=True, slots=True)
class DurableMediaRootTransition:
    before: DurableMediaRootState
    after: DurableMediaRootState


@dataclass(frozen=True, slots=True)
class DurableMediaRequestClaim:
    state: Literal[
        "claimed",
        "processing",
        "succeeded",
        "conflict",
        "recovery_required",
        "result_expired",
    ]
    turn_id: str
    fencing_token: str = ""
    attempt: int = 0
    retry_after_seconds: int = 0
    response: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class DurableMediaSuccessDocument:
    """Exact immutable success authority re-read for private asset access."""

    principal_hash: str
    operation: str
    turn_id: str
    response: dict[str, object]


@dataclass(frozen=True, slots=True)
class DurableMediaAssetAckReceipt:
    turn_id: str
    principal_hash: str
    operation: str
    installation_epoch: int
    token_set_digest: str
    archive_receipt_sha256: str
    replayed: bool
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class DurablePreparedVideoAsset:
    """Private crash-recovery material; never return it from a public route."""

    task_alias: str
    token: str = field(repr=False)
    provider_response: dict[str, object] = field(repr=False)
    asset_response: dict[str, object] | None = field(repr=False)
    prepare_sha256: str


@dataclass(frozen=True, slots=True)
class DurableVideoPollClaim:
    state: Literal["claimed", "prepared", "deferred", "terminal", "not_found"]
    task_alias: str
    requested_model: str = ""
    provider_name: str = ""
    provider_domain: str = ""
    provider_credential_domain: str = ""
    upstream_model: str = ""
    upstream_task_id: str = ""
    fencing_token: str = ""
    attempt: int = 0
    retry_after_seconds: int = 0
    response: dict[str, object] | None = None
    prepared_token: str = field(default="", repr=False)
    prepared_provider_response: dict[str, object] | None = field(
        default=None, repr=False
    )
    prepared_asset_response: dict[str, object] | None = field(
        default=None, repr=False
    )
    prepare_sha256: str = ""


@dataclass(frozen=True, slots=True)
class DurablePreparedVideoRecoverySnapshot:
    """Digest-only read model for a local prepared-only adjudication."""

    candidate_sha256: str
    prepare_sha256: str


@dataclass(frozen=True, slots=True)
class DurablePreparedVideoRecoveryClaim:
    """Private prepared-only claim; it has no provider-dispatch state."""

    task_alias: str = field(repr=False)
    fencing_token: str = field(repr=False)
    prepared_token: str = field(repr=False)
    prepared_provider_response: dict[str, object] = field(repr=False)
    prepared_asset_response: dict[str, object] | None = field(
        default=None, repr=False
    )
    prepare_sha256: str = ""
    candidate_sha256: str = ""


@dataclass(frozen=True, slots=True)
class DurableVideoTaskLease:
    """Irreversible owner identity needed to rebuild one remote-job slot."""

    task_alias: str
    principal_hash: str


def validate_media_idempotency_key(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(
            "Idempotency-Key must be 16-128 ASCII token characters"
        )
    key = value
    if _KEY_RE.fullmatch(key) is None:
        raise ValueError(
            "Idempotency-Key must be 16-128 ASCII token characters"
        )
    return key


def _validated_digest(value: object, label: str) -> str:
    digest = str(value or "")
    if _DIGEST_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _validated_nonzero_digest(value: object, label: str) -> str:
    digest = _validated_digest(value, label)
    if digest == "0" * 64:
        raise ValueError(f"{label} must be a nonzero lowercase SHA-256 digest")
    return digest


def _initial_authority_state_digest(
    database_identity: object,
    *,
    schema_fingerprint: str = _SCHEMA_FINGERPRINT,
) -> str:
    identity = _validated_nonzero_digest(database_identity, "database_identity")
    fingerprint = _validated_nonzero_digest(
        schema_fingerprint,
        "schema_fingerprint",
    )
    return hashlib.sha256(
        _AUTHORITY_STATE_DOMAIN
        + b"initial\x00"
        + str(_SCHEMA_VERSION).encode("ascii")
        + b"\x00"
        + fingerprint.encode("ascii")
        + b"\x00"
        + identity.encode("ascii")
        + b"\x000000000000000000"
    ).hexdigest()


def _next_authority_state_digest(
    previous_digest: object,
    database_identity: object,
    next_sequence: object,
) -> str:
    previous = _validated_nonzero_digest(previous_digest, "previous state digest")
    identity = _validated_nonzero_digest(database_identity, "database_identity")
    if (
        not isinstance(next_sequence, int)
        or isinstance(next_sequence, bool)
        or not 1 <= next_sequence <= _MAX_MUTATION_SEQUENCE
    ):
        raise ValueError("next mutation sequence is invalid")
    return hashlib.sha256(
        _AUTHORITY_STATE_DOMAIN
        + b"next\x00"
        + previous.encode("ascii")
        + b"\x00"
        + identity.encode("ascii")
        + b"\x00"
        + f"{next_sequence:016x}".encode("ascii")
    ).hexdigest()


def _validated_operation(value: object) -> str:
    operation = str(value or "")
    if operation not in _OPERATIONS:
        raise ValueError("unsupported paid media operation")
    return operation


def hash_media_principal(paid_capability: object) -> str:
    """Derive recovery identity from the paid capability, never runtime Bearer."""

    if (
        not isinstance(paid_capability, str)
        or not paid_capability
        or len(paid_capability) > 4096
    ):
        raise ValueError("paid media capability principal is invalid")
    return hashlib.sha256(
        b"nachuan-paid-media-principal-v1\x00"
        + paid_capability.encode("utf-8")
    ).hexdigest()


def hash_media_request(operation: object, payload: object) -> str:
    """Hash one validated request with canonical JSON and operation binding."""

    normalized_operation = _validated_operation(operation)
    if not isinstance(payload, dict):
        raise ValueError("media request payload must be an object")
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("media request payload must be canonical JSON") from exc
    if len(encoded) > 32 * 1024 * 1024:
        raise ValueError("media request payload exceeds digest limit")
    return hashlib.sha256(
        b"nachuan-paid-media-request-v1\x00"
        + normalized_operation.encode("ascii")
        + b"\x00"
        + encoded
    ).hexdigest()


def _key_hash(key: str) -> str:
    return hashlib.sha256(
        b"nachuan-paid-media-idempotency-key-v1\x00" + key.encode("ascii")
    ).hexdigest()


def _turn_id(principal_hash: str, operation: str, key_hash: str) -> str:
    return hashlib.sha256(
        b"nachuan-paid-media-turn-v1\x00"
        + principal_hash.encode("ascii")
        + b"\x00"
        + operation.encode("ascii")
        + b"\x00"
        + key_hash.encode("ascii")
    ).hexdigest()


def _video_task_alias(turn_id: str) -> str:
    return f"nvt1_{_validated_digest(turn_id, 'turn_id')}"


def _video_turn_id(task_alias: object) -> str:
    alias = str(task_alias or "")
    if _VIDEO_ALIAS_RE.fullmatch(alias) is None:
        raise ValueError("video task alias is invalid")
    return alias.removeprefix("nvt1_")


def _validated_video_route_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if (
        not text
        or len(text) > _MAX_VIDEO_ROUTE_TEXT
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise ValueError(f"{label} is invalid")
    return text


def _video_poll_backoff(attempt: int) -> float:
    bounded_attempt = min(16, max(1, int(attempt)))
    return min(
        _VIDEO_POLL_BACKOFF_MAX_SECONDS,
        _VIDEO_POLL_BACKOFF_BASE_SECONDS * (2 ** (bounded_attempt - 1)),
    )


def _prepared_video_material(
    *,
    task_alias: object,
    token: object,
    provider_response: object,
    asset_response: object | None,
) -> tuple[dict[str, object], dict[str, object] | None, str]:
    """Canonicalize private prepared state and bind it to one task/token."""

    turn_id = _video_turn_id(task_alias)
    normalized_token = str(token or "")
    try:
        asset_token_hash(normalized_token)
    except PaidMediaAssetProtocolError as exc:
        raise ValueError("prepared video asset token is invalid") from exc
    if not isinstance(provider_response, dict):
        raise ValueError("prepared video provider response must be an object")
    try:
        provider_bytes = json.dumps(
            provider_response,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        normalized_provider = json.loads(provider_bytes)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("prepared video provider response must be bounded JSON") from exc
    if (
        len(provider_bytes) > _MAX_VIDEO_POLL_RESPONSE_BYTES
        or not isinstance(normalized_provider, dict)
    ):
        raise ValueError("prepared video provider response exceeds its size limit")

    normalized_asset: dict[str, object] | None = None
    asset_bytes = b"null"
    if asset_response is not None:
        try:
            parsed = parse_asset_result(asset_response)
        except PaidMediaAssetProtocolError as exc:
            raise ValueError("prepared video asset result is invalid") from exc
        if (
            parsed.kind != "video"
            or parsed.turn_id != turn_id
            or len(parsed.assets) != 1
            or parsed.assets[0].token != normalized_token
        ):
            raise ValueError("prepared video asset result does not match its task token")
        asset_bytes = canonical_asset_result(parsed)
        normalized_asset = json.loads(asset_bytes)

    digest = hashlib.sha256(
        _PREPARED_VIDEO_DOMAIN
        + str(task_alias).encode("ascii")
        + b"\x00"
        + normalized_token.encode("ascii")
        + b"\x00"
        + len(provider_bytes).to_bytes(8, "big")
        + provider_bytes
        + b"\x00"
        + len(asset_bytes).to_bytes(8, "big")
        + asset_bytes
    ).hexdigest()
    return normalized_provider, normalized_asset, digest


def _prepared_video_operator_candidate_digest(
    *,
    task_alias: str,
    principal_hash: str,
    installation_epoch: int,
    prepare_sha256: str,
) -> str:
    """Bind a prepared-only recovery candidate without exposing its material."""

    alias = str(task_alias or "")
    _video_turn_id(alias)
    principal = _validated_digest(principal_hash, "principal_hash")
    prepare_digest = _validated_digest(prepare_sha256, "prepare_sha256")
    if (
        isinstance(installation_epoch, bool)
        or not isinstance(installation_epoch, int)
        or installation_epoch < 1
    ):
        raise ValueError("installation_epoch must be a positive integer")
    return hashlib.sha256(
        _PREPARED_VIDEO_OPERATOR_RECOVERY_DOMAIN
        + alias.encode("ascii")
        + b"\x00"
        + principal.encode("ascii")
        + b"\x00"
        + f"{installation_epoch:016x}".encode("ascii")
        + b"\x00"
        + prepare_digest.encode("ascii")
    ).hexdigest()


def prepared_video_operator_recovery_candidate_sha256(
    *,
    task_alias: str,
    principal_hash: str,
    installation_epoch: int,
    prepare_sha256: str,
) -> str:
    """Reconstruct the digest-only prepared candidate after local commit."""

    return _prepared_video_operator_candidate_digest(
        task_alias=task_alias,
        principal_hash=principal_hash,
        installation_epoch=installation_epoch,
        prepare_sha256=prepare_sha256,
    )


def _aliased_video_response(
    response: dict[str, object], task_alias: str
) -> dict[str, object]:
    public = dict(response)
    public["task_id"] = task_alias
    for field in ("video_id", "id", "request_id"):
        if field in public:
            public[field] = task_alias
    public.pop("upstream_task_id", None)
    nested = public.get("data")
    if isinstance(nested, dict):
        public_nested = dict(nested)
        for field in ("video_id", "task_id", "id", "request_id"):
            if field in public_nested:
                public_nested[field] = task_alias
        public_nested.pop("upstream_task_id", None)
        public["data"] = public_nested
    return public


_VIDEO_TERMINAL_FAILURE_STATES = frozenset(
    {"failure", "failed", "error", "cancelled", "canceled"}
)


def _safe_video_status_response(
    response: dict[str, object], task_alias: str
) -> dict[str, object]:
    """Reduce untrusted poll metadata to the URL-free public status contract."""

    nested = response.get("data")
    nested_status = nested.get("status") if isinstance(nested, dict) else None
    status = str(response.get("status") or nested_status or "processing").strip().lower()
    if (
        not status
        or len(status) > 64
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", status) is None
    ):
        status = "processing"
    public: dict[str, object] = {"task_id": task_alias, "status": status}
    progress = response.get("progress")
    if (
        isinstance(progress, (int, float))
        and not isinstance(progress, bool)
        and math.isfinite(float(progress))
        and 0 <= float(progress) <= 100
    ):
        public["progress"] = int(progress) if float(progress).is_integer() else float(progress)
    return public


def _is_video_terminal_failure(response: dict[str, object]) -> bool:
    return str(_safe_video_status_response(response, "nvt1_" + "0" * 64)["status"]) in (
        _VIDEO_TERMINAL_FAILURE_STATES
    )


class DurableMediaRequestStore:
    """SQLite request authority with closed paid and channel schema profiles.

    ``dev`` preserves source-test creation and exact legacy migration.  Packaged
    callers must choose ``create_bound`` or ``open_bound`` with the identity
    preallocated by Installation Root.  The non-secret sidecar detects a
    database-only rollback.  The optional pre-mutation hook runs before SQLite
    begins a logical write; the synchronous root hook then mirrors each committed
    authority transition into the independent root.  The default ``paid_media``
    profile retains the v4 paid schema; ``channel_media`` adds a bounded,
    permanent admission identity without changing paid retention semantics.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        schema_profile: Literal["paid_media", "channel_media"] = "paid_media",
        construction_policy: Literal["dev", "create_bound", "open_bound"] = "dev",
        expected_database_identity: str | None = None,
        pre_mutation_hook: Callable[[], None] | None = None,
        root_commit_hook: Callable[[DurableMediaRootTransition], None] | None = None,
        lease_seconds: float = _DEFAULT_LEASE_SECONDS,
        retention_seconds: float = _DEFAULT_RETENTION_SECONDS,
        max_response_bytes: int | None = None,
        max_total_response_bytes: int | None = None,
        max_records: int = _DEFAULT_MAX_RECORDS,
        prune_batch: int = _DEFAULT_PRUNE_BATCH,
        max_database_bytes: int = _DEFAULT_MAX_DATABASE_BYTES,
        max_asset_reservation_bytes: int = _DEFAULT_MAX_ASSET_RESERVATION_BYTES,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(db_path)))
        self.anchor_path = Path(f"{self.path}.rollback-anchor")
        if schema_profile not in _SCHEMA_PROFILES:
            raise ValueError("durable media schema profile is invalid")
        self._schema_profile = schema_profile
        if schema_profile == _CHANNEL_MEDIA_SCHEMA_PROFILE:
            self._application_id = _CHANNEL_MEDIA_APPLICATION_ID
            self._schema_fingerprint = _CHANNEL_MEDIA_SCHEMA_FINGERPRINT
            self._schema_auxiliary_ddl = _CHANNEL_MEDIA_SCHEMA_AUXILIARY_DDL
        else:
            self._application_id = _APPLICATION_ID
            self._schema_fingerprint = _SCHEMA_FINGERPRINT
            self._schema_auxiliary_ddl = _SCHEMA_AUXILIARY_DDL
        if construction_policy not in _CONSTRUCTION_POLICIES:
            raise ValueError("durable media construction policy is invalid")
        self._construction_policy = construction_policy
        if construction_policy == "dev":
            if expected_database_identity is not None:
                raise ValueError("development construction cannot bind an identity")
            self._expected_database_identity: str | None = None
        else:
            self._expected_database_identity = _validated_nonzero_digest(
                expected_database_identity,
                "expected_database_identity",
            )
        if pre_mutation_hook is not None and not callable(pre_mutation_hook):
            raise ValueError("pre_mutation_hook must be callable")
        if root_commit_hook is not None and not callable(root_commit_hook):
            raise ValueError("root_commit_hook must be callable")
        self._pre_mutation_hook = pre_mutation_hook
        self._pre_mutation_hook_active = False
        self._root_commit_hook = root_commit_hook
        self._root_commit_pending: DurableMediaRootTransition | None = None
        self._commit_hook_active = False
        self.lease_seconds = float(lease_seconds)
        self.retention_seconds = float(retention_seconds)
        if (
            not math.isfinite(self.lease_seconds)
            or not 1 <= self.lease_seconds <= 24 * 60 * 60
        ):
            raise ValueError("media request lease must be between 1 second and 1 day")
        if (
            not math.isfinite(self.retention_seconds)
            or not 1 <= self.retention_seconds <= _DEFAULT_RETENTION_SECONDS
        ):
            raise ValueError("media request retention must be between 1 second and 30 days")
        self.max_database_bytes = int(max_database_bytes)
        if not 256 * 1024 <= self.max_database_bytes <= _DEFAULT_MAX_DATABASE_BYTES:
            raise ValueError("media request database limit must be 256 KiB to 1 GiB")
        total_default = min(
            _DEFAULT_MAX_TOTAL_RESPONSE_BYTES,
            self.max_database_bytes // 2,
        )
        self.max_total_response_bytes = int(
            total_default
            if max_total_response_bytes is None
            else max_total_response_bytes
        )
        if not 64 <= self.max_total_response_bytes <= self.max_database_bytes // 2:
            raise ValueError("total media response budget exceeds database safety budget")
        self._previous_default_response_limit = min(
            _PREVIOUS_DEFAULT_MAX_RESPONSE_BYTES,
            self.max_total_response_bytes,
        )
        response_default = min(
            _DEFAULT_MAX_RESPONSE_BYTES,
            self.max_total_response_bytes,
        )
        self._uses_default_response_limit = max_response_bytes is None
        self.max_response_bytes = int(
            response_default if max_response_bytes is None else max_response_bytes
        )
        if not 64 <= self.max_response_bytes <= _ABSOLUTE_MAX_RESPONSE_BYTES:
            raise ValueError("media response limit must be between 64 bytes and 128 MiB")
        if self.max_response_bytes > self.max_total_response_bytes:
            raise ValueError("single media response limit exceeds total response budget")
        self.max_records = int(max_records)
        self.prune_batch = int(prune_batch)
        if not 1 <= self.max_records <= 1_000_000:
            raise ValueError("media request record limit must be between 1 and 1000000")
        if not 1 <= self.prune_batch <= 2048:
            raise ValueError("media request prune batch must be between 1 and 2048")
        self.max_asset_reservation_bytes = int(max_asset_reservation_bytes)
        if not (
            _ASSET_OPERATION_RESERVATION_BYTES
            <= self.max_asset_reservation_bytes
            <= 1024 * 1024 * 1024 * 1024
        ):
            raise ValueError(
                "paid-media asset reservation capacity must be 192 MiB to 1 TiB"
            )
        self._transaction_lock = RLock()
        self._keeper: sqlite3.Connection | None = None
        self._trusted_data_version: int | None = None
        self._trusted_schema_version: int | None = None
        try:
            self._assert_database_path()
            if construction_policy != "open_bound":
                self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_database_path()
            if construction_policy == "create_bound":
                if (
                    any(self._database_family_presence().values())
                    or self.anchor_path.exists()
                ):
                    raise OSError("bound durable media state already exists")
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                flags |= int(getattr(os, "O_BINARY", 0))
                descriptor = os.open(self.path, flags, 0o600)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            elif construction_policy == "open_bound":
                if not self.path.is_file() or not self.anchor_path.is_file():
                    raise OSError("bound durable media state is missing")
            self._preflight_schema_generation()
            self._assert_preflight_still_current()
            with closing(self._connect(configure_page_budget=False)) as connection:
                if (
                    self._preflight_database_identity is not None
                    and self._database_path_identity()
                    != self._preflight_database_identity
                ):
                    raise sqlite3.DatabaseError(
                        "durable media path changed before read-write open"
                    )
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("BEGIN IMMEDIATE")
                if construction_policy == "open_bound":
                    self._validate_schema(connection)
                    identity, _sequence, _digest = self._database_anchor_state(connection)
                    if identity != self._expected_database_identity:
                        raise sqlite3.DatabaseError(
                            "bound durable media identity does not match"
                        )
                else:
                    self._initialize_schema(
                        connection,
                        expected_database_identity=self._expected_database_identity,
                        allow_migration=construction_policy == "dev",
                    )
                self._configure_page_budget(connection)
                connection.commit()
                enable_wal_with_deadline(
                    connection,
                    error_message="durable media request store requires WAL mode",
                )
                connection.execute("PRAGMA synchronous=FULL")
                check = connection.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError("durable media request database is corrupt")
            self._keeper = self._connect(check_same_thread=False)
            enable_wal_with_deadline(
                self._keeper,
                error_message="durable media request store requires WAL mode",
            )
            self._keeper.execute("BEGIN IMMEDIATE")
            try:
                self._validate_schema(self._keeper)
                (
                    self._trusted_data_version,
                    self._trusted_schema_version,
                ) = self._database_versions(self._keeper)
                self._keeper.commit()
            except BaseException:
                self._keeper.rollback()
                raise
        except (OSError, sqlite3.Error) as exc:
            if self._keeper is not None:
                self._keeper.close()
                self._keeper = None
            raise DurableMediaRequestUnavailable(
                "cannot initialize durable media request store"
            ) from exc

    @staticmethod
    def _canonical_sql(value: object) -> str:
        return value if isinstance(value, str) and value else ""

    def _classify_schema_generation(self, connection: sqlite3.Connection) -> str:
        actual = {
            (str(kind), str(name)): (str(tbl_name), sql)
            for kind, name, tbl_name, sql in _persistent_schema_rows(connection)
        }
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if not actual:
            if application_id == 0 and user_version == 0:
                return "empty"
            raise sqlite3.DatabaseError("durable media empty schema identity is invalid")
        if application_id == self._application_id and user_version == _SCHEMA_VERSION:
            declarations = {
                ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
                ("table", "durable_media_requests_meta"): _META_TABLE_DDL,
                **self._schema_auxiliary_ddl,
            }
            generation = "current"
        elif (
            self._schema_profile == _PAID_MEDIA_SCHEMA_PROFILE
            and application_id == _APPLICATION_ID
            and user_version == _LEGACY_SCHEMA_VERSION
        ):
            declarations = {
                ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
                ("table", "durable_media_requests_meta"): _LEGACY_META_TABLE_DDL,
                **_BASE_SCHEMA_AUXILIARY_DDL,
            }
            generation = "legacy:v1"
        elif (
            self._schema_profile == _PAID_MEDIA_SCHEMA_PROFILE
            and application_id == _APPLICATION_ID
            and user_version == _V2_SCHEMA_VERSION
        ):
            declarations = {
                ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
                ("table", "durable_media_requests_meta"): _V2_META_TABLE_DDL,
                **_BASE_SCHEMA_AUXILIARY_DDL,
            }
            generation = "legacy:v2"
        elif (
            self._schema_profile == _PAID_MEDIA_SCHEMA_PROFILE
            and application_id == _APPLICATION_ID
            and user_version == _V3_SCHEMA_VERSION
        ):
            declarations = {
                ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
                ("table", "durable_media_requests_meta"): _V3_META_TABLE_DDL,
                **_BASE_SCHEMA_AUXILIARY_DDL,
            }
            generation = "legacy:v3"
        else:
            raise sqlite3.DatabaseError(
                "durable media schema generation is unsupported"
            )
        expected = _expected_schema_sql(declarations)
        if set(actual) != set(expected) or any(
            actual[identity][0] != expected_table
            or self._canonical_sql(actual[identity][1])
            != self._canonical_sql(expected_sql)
            for identity, (expected_table, expected_sql) in expected.items()
        ):
            raise sqlite3.DatabaseError(
                "durable media schema generation is incompatible"
            )
        return generation

    def _validate_preflight_generation(
        self, connection: sqlite3.Connection, generation: str
    ) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        if generation == "current":
            self._validate_schema(
                connection,
                allow_previous_default=self._construction_policy == "dev",
            )
            if self._expected_database_identity is not None:
                identity, _sequence, _digest = self._database_anchor_state(connection)
                if identity != self._expected_database_identity:
                    raise sqlite3.DatabaseError(
                        "bound durable media identity does not match"
                    )
        elif generation == "legacy:v1":
            self._validate_legacy_schema(connection)
        elif generation == "legacy:v2":
            self._validate_v2_schema(connection)
        elif generation == "legacy:v3":
            self._validate_v3_schema(connection)
        elif generation != "empty":
            raise sqlite3.DatabaseError(
                "durable media schema generation is unsupported"
            )

    def _assert_generation_allowed_for_policy(self, generation: str) -> None:
        if self._construction_policy == "open_bound" and generation != "current":
            raise sqlite3.DatabaseError(
                "bound durable media open requires the current generation"
            )
        if self._construction_policy == "create_bound" and generation != "empty":
            raise sqlite3.DatabaseError(
                "bound durable media create requires an empty database"
            )

    def _preflight_schema_generation_once(self) -> None:
        presence = self._database_family_presence()
        if not presence[""]:
            if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
                raise sqlite3.DatabaseError(
                    "durable media main database is missing beside orphan sidecars"
                )
            self._preflight_family_presence = presence
            self._preflight_database_identity = None
            self._preflight_generation = "missing"
            return
        if presence["-journal"]:
            raise sqlite3.DatabaseError(
                "durable media rollback journal requires explicit recovery"
            )
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "durable media WAL and SHM sidecars must be present together"
            )
        identity = self._database_path_identity()
        self._assert_database_family_bounds()
        with closing(
            sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro&immutable=1",
                uri=True,
                isolation_level=None,
                timeout=5.0,
            )
        ) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            generation = self._classify_schema_generation(connection)
            if not presence["-wal"]:
                self._validate_preflight_generation(connection, generation)
        presence_after = self._database_family_presence()
        if presence_after != presence:
            raise _DatabaseFamilyChanged(
                "durable media family changed during immutable preflight"
            )
        if self._database_path_identity() != identity:
            raise sqlite3.DatabaseError(
                "durable media path changed during immutable preflight"
            )
        if presence_after["-wal"]:
            with closing(
                sqlite3.connect(
                    f"{self.path.as_uri()}?mode=ro",
                    uri=True,
                    isolation_level=None,
                    timeout=5.0,
                )
            ) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("BEGIN")
                try:
                    generation = self._classify_schema_generation(connection)
                    self._validate_preflight_generation(connection, generation)
                finally:
                    connection.rollback()
            wal_presence = self._database_family_presence()
            if wal_presence != presence_after:
                raise _DatabaseFamilyChanged(
                    "durable media family changed during WAL-aware preflight"
                )
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "durable media path changed during WAL-aware preflight"
                )
            presence_after = wal_presence
        self._assert_generation_allowed_for_policy(generation)
        self._preflight_family_presence = presence_after
        self._preflight_database_identity = identity
        self._preflight_generation = generation

    def _preflight_schema_generation(self) -> None:
        """Classify the complete SQLite family without opening it read-write."""

        last_change: _DatabaseFamilyChanged | None = None
        for _attempt in range(4):
            try:
                self._preflight_schema_generation_once()
                return
            except _DatabaseFamilyChanged as exc:
                last_change = exc
                time.sleep(0)
        raise sqlite3.DatabaseError(
            "durable media database family did not stabilize during preflight"
        ) from last_change

    def _assert_preflight_still_current(self) -> None:
        if self._database_family_presence() != self._preflight_family_presence:
            self._preflight_schema_generation()

    def _initialize_schema(
        self,
        connection: sqlite3.Connection,
        *,
        expected_database_identity: str | None,
        allow_migration: bool,
    ) -> None:
        existing_objects = _persistent_schema_rows(connection)
        existing_tables = {
            str(name)
            for object_type, name, _tbl_name, _sql in existing_objects
            if str(object_type) == "table"
        }
        request_exists = "durable_media_requests" in existing_tables
        meta_exists = "durable_media_requests_meta" in existing_tables
        if request_exists != meta_exists:
            raise sqlite3.DatabaseError("durable media schema marker is incomplete")
        if not request_exists:
            if existing_objects:
                raise sqlite3.DatabaseError(
                    "durable media database contains an unrelated schema"
                )
            database_identity = (
                secrets.token_hex(32)
                if expected_database_identity is None
                else expected_database_identity
            )
            authority_state_digest = _initial_authority_state_digest(
                database_identity,
                schema_fingerprint=self._schema_fingerprint,
            )
            self._write_anchor(
                database_identity,
                0,
                authority_state_digest,
                create_only=True,
            )
            connection.execute(_REQUEST_TABLE_DDL)
            connection.execute(_META_TABLE_DDL)
            connection.execute(
                "INSERT INTO durable_media_requests_meta "
                "(singleton,schema_version,schema_fingerprint,database_identity,"
                "mutation_sequence,authority_state_digest,authority_mode,"
                "authority_installation_id,authority_epoch,"
                "authority_recovery_floor,authority_recovery_state_digest,record_count,"
                "response_bytes,reserved_bytes,max_records,max_response_bytes,"
                "max_total_response_bytes,max_database_bytes) "
                "VALUES(1,?,?,?,?,?,'normal',NULL,NULL,NULL,NULL,?,?,?,?,?,?,?)",
                (
                    _SCHEMA_VERSION,
                    self._schema_fingerprint,
                    database_identity,
                    0,
                    authority_state_digest,
                    0,
                    0,
                    0,
                    self.max_records,
                    self.max_response_bytes,
                    self.max_total_response_bytes,
                    self.max_database_bytes,
                ),
            )
            for ddl in self._schema_auxiliary_ddl.values():
                connection.execute(ddl)
            connection.execute(
                "INSERT INTO durable_media_asset_capacity "
                "(singleton,max_capacity_bytes,reserved_total_bytes) VALUES(1,?,0)",
                (self.max_asset_reservation_bytes,),
            )
            connection.execute(f"PRAGMA application_id={self._application_id}")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        elif allow_migration and self._schema_profile == _PAID_MEDIA_SCHEMA_PROFILE:
            user_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if user_version == _LEGACY_SCHEMA_VERSION:
                self._migrate_legacy_schema(connection)
            elif user_version == _V2_SCHEMA_VERSION:
                self._migrate_v2_schema(connection)
            elif user_version == _V3_SCHEMA_VERSION:
                self._migrate_v3_schema(connection)
        if request_exists:
            if not allow_migration:
                raise sqlite3.DatabaseError(
                    "bound durable media create found an existing schema"
                )
            if self._schema_profile == _PAID_MEDIA_SCHEMA_PROFILE:
                self._upgrade_default_response_budget(connection)
        self._validate_schema(connection)

    def _compatible_response_limit(
        self, value: object, *, allow_previous_default: bool
    ) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and (
            int(value) == self.max_response_bytes
            or (
                allow_previous_default
                and self._uses_default_response_limit
                and int(value) == self._previous_default_response_limit
            )
        )

    def _validate_legacy_schema(self, connection: sqlite3.Connection) -> None:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if (
            application_id != _APPLICATION_ID
            or user_version != _LEGACY_SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("legacy durable media schema identity is invalid")
        request_columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_xinfo(durable_media_requests)")
        )
        legacy_meta_columns = (
            "singleton",
            "schema_version",
            "schema_fingerprint",
            "record_count",
            "response_bytes",
            "reserved_bytes",
            "max_records",
            "max_response_bytes",
            "max_total_response_bytes",
            "max_database_bytes",
        )
        meta_columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_xinfo(durable_media_requests_meta)"
            )
        )
        if request_columns != _EXPECTED_REQUEST_COLUMNS or meta_columns != legacy_meta_columns:
            raise sqlite3.DatabaseError("legacy durable media schema is incompatible")
        expected_objects = {
            ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
            ("table", "durable_media_requests_meta"): _LEGACY_META_TABLE_DDL,
            **_BASE_SCHEMA_AUXILIARY_DDL,
        }
        expected_sql_objects = _expected_schema_sql(expected_objects)
        actual_rows = _persistent_schema_rows(connection)
        actual_objects = {
            (str(object_type), str(name)): (str(tbl_name), sql)
            for object_type, name, tbl_name, sql in actual_rows
        }
        if set(actual_objects) != set(expected_sql_objects):
            raise sqlite3.DatabaseError(
                "legacy durable media schema object set is incompatible"
            )
        for identity, (expected_table, expected_sql) in expected_sql_objects.items():
            actual_table, actual_sql = actual_objects[identity]
            if actual_table != expected_table or self._canonical_sql(
                actual_sql
            ) != self._canonical_sql(expected_sql):
                raise sqlite3.DatabaseError(
                    f"legacy durable media schema object {identity[1]} is incompatible"
                )
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint,record_count,response_bytes,"
            "reserved_bytes,max_records,max_response_bytes,max_total_response_bytes,"
            "max_database_bytes FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if (
            meta is None
            or meta[0] != _LEGACY_SCHEMA_VERSION
            or meta[1] != _LEGACY_SCHEMA_FINGERPRINT
            or meta[5] != self.max_records
            or not self._compatible_response_limit(
                meta[6], allow_previous_default=True
            )
            or meta[7] != self.max_total_response_bytes
            or meta[8] != self.max_database_bytes
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in meta[2:]
            )
            or any(int(value) < 0 for value in meta[2:5])
        ):
            raise sqlite3.DatabaseError("legacy durable media metadata is invalid")
        actual_usage = connection.execute(
            "SELECT COUNT(*),"
            "COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
            "COALESCE(SUM(reserved_response_bytes),0) "
            "FROM durable_media_requests"
        ).fetchone()
        if (
            actual_usage != tuple(meta[2:5])
            or int(meta[2]) > self.max_records
            or int(meta[3]) + int(meta[4]) > self.max_total_response_bytes
        ):
            raise sqlite3.DatabaseError("legacy durable media counters are corrupt")

    def _migrate_legacy_schema(self, connection: sqlite3.Connection) -> None:
        """Bootstrap one exact v1 database in development mode only."""

        self._validate_legacy_schema(connection)
        try:
            os.lstat(self.anchor_path)
        except FileNotFoundError:
            pass
        else:
            raise sqlite3.DatabaseError(
                "legacy durable media database unexpectedly has a rollback anchor"
            )
        legacy_meta = connection.execute(
            "SELECT record_count,response_bytes,reserved_bytes,max_records,"
            "max_response_bytes,max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if legacy_meta is None:
            raise sqlite3.DatabaseError("legacy durable media metadata is missing")
        database_identity = secrets.token_hex(32)
        authority_state_digest = _initial_authority_state_digest(database_identity)
        # The anchor is deliberately durable first.  If the schema transaction
        # fails, the surviving anchor makes the old v1 database non-bootable
        # and requires explicit recovery instead of retrying migration.
        self._write_anchor(
            database_identity,
            0,
            authority_state_digest,
            create_only=True,
        )
        for object_type, name in _BASE_SCHEMA_AUXILIARY_DDL:
            if object_type == "trigger":
                connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "ALTER TABLE durable_media_requests_meta "
            "RENAME TO durable_media_requests_meta_v1"
        )
        connection.execute(_META_TABLE_DDL)
        connection.execute(
            "INSERT INTO durable_media_requests_meta "
            "(singleton,schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,authority_state_digest,authority_mode,"
            "authority_installation_id,authority_epoch,authority_recovery_floor,"
            "authority_recovery_state_digest,record_count,response_bytes,reserved_bytes,"
            "max_records,max_response_bytes,max_total_response_bytes,"
            "max_database_bytes) "
            "VALUES(1,?,?,?,?,?,'normal',NULL,NULL,NULL,NULL,?,?,?,?,?,?,?)",
            (
                _SCHEMA_VERSION,
                _SCHEMA_FINGERPRINT,
                database_identity,
                0,
                authority_state_digest,
                *legacy_meta,
            ),
        )
        connection.execute("DROP TABLE durable_media_requests_meta_v1")
        for (object_type, _name), ddl in _BASE_SCHEMA_AUXILIARY_DDL.items():
            if object_type == "trigger":
                connection.execute(ddl)
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "table":
                connection.execute(ddl)
        connection.execute(
            "INSERT INTO durable_media_asset_capacity VALUES(1,?,0)",
            (self.max_asset_reservation_bytes,),
        )
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "trigger":
                connection.execute(ddl)
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    @staticmethod
    def _legacy_anchor_bytes(database_identity: str, mutation_sequence: int) -> bytes:
        if (
            _DIGEST_RE.fullmatch(database_identity) is None
            or database_identity == "0" * 64
            or not isinstance(mutation_sequence, int)
            or isinstance(mutation_sequence, bool)
            or not 0 <= mutation_sequence <= _MAX_MUTATION_SEQUENCE
        ):
            raise sqlite3.DatabaseError("legacy rollback anchor state is invalid")
        return json.dumps(
            {
                "database_identity": database_identity,
                "format": _LEGACY_ANCHOR_FORMAT,
                "mutation_sequence": f"{mutation_sequence:016x}",
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _read_legacy_anchor(self) -> tuple[str, int]:
        try:
            self._assert_database_path()
            with self.anchor_path.open("rb") as stream:
                raw = stream.read(_ANCHOR_MAX_BYTES + 1)
            self._assert_database_path()
            if not raw or len(raw) > _ANCHOR_MAX_BYTES:
                raise ValueError("legacy rollback anchor size is invalid")
            decoded = json.loads(raw.decode("ascii"))
            if not isinstance(decoded, dict) or set(decoded) != {
                "database_identity",
                "format",
                "mutation_sequence",
            }:
                raise ValueError("legacy rollback anchor fields are invalid")
            identity = decoded.get("database_identity")
            sequence_text = decoded.get("mutation_sequence")
            if (
                decoded.get("format") != _LEGACY_ANCHOR_FORMAT
                or not isinstance(identity, str)
                or not isinstance(sequence_text, str)
                or re.fullmatch(r"[0-9a-f]{16}", sequence_text) is None
            ):
                raise ValueError("legacy rollback anchor is invalid")
            sequence = int(sequence_text, 16)
            if raw != self._legacy_anchor_bytes(identity, sequence):
                raise ValueError("legacy rollback anchor encoding is invalid")
            return identity, sequence
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise sqlite3.DatabaseError(
                "legacy durable media rollback anchor cannot be verified"
            ) from exc

    def _validate_v2_schema(
        self, connection: sqlite3.Connection
    ) -> tuple[str, int, tuple[int, ...]]:
        if (
            int(connection.execute("PRAGMA application_id").fetchone()[0])
            != _APPLICATION_ID
            or int(connection.execute("PRAGMA user_version").fetchone()[0])
            != _V2_SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("v2 durable media schema identity is invalid")
        request_columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_xinfo(durable_media_requests)")
        )
        v2_meta_columns = (
            "singleton",
            "schema_version",
            "schema_fingerprint",
            "database_identity",
            "mutation_sequence",
            "record_count",
            "response_bytes",
            "reserved_bytes",
            "max_records",
            "max_response_bytes",
            "max_total_response_bytes",
            "max_database_bytes",
        )
        meta_columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_xinfo(durable_media_requests_meta)"
            )
        )
        if request_columns != _EXPECTED_REQUEST_COLUMNS or meta_columns != v2_meta_columns:
            raise sqlite3.DatabaseError("v2 durable media schema is incompatible")
        expected_objects = {
            ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
            ("table", "durable_media_requests_meta"): _V2_META_TABLE_DDL,
            **_BASE_SCHEMA_AUXILIARY_DDL,
        }
        expected_sql_objects = _expected_schema_sql(expected_objects)
        actual_objects = {
            (str(object_type), str(name)): (str(tbl_name), sql)
            for object_type, name, tbl_name, sql in _persistent_schema_rows(connection)
        }
        if set(actual_objects) != set(expected_sql_objects):
            raise sqlite3.DatabaseError("v2 durable media object set is incompatible")
        for identity, (expected_table, expected_sql) in expected_sql_objects.items():
            actual_table, actual_sql = actual_objects[identity]
            if actual_table != expected_table or self._canonical_sql(
                actual_sql
            ) != self._canonical_sql(expected_sql):
                raise sqlite3.DatabaseError("v2 durable media object is incompatible")
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,record_count,response_bytes,reserved_bytes,max_records,"
            "max_response_bytes,max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if (
            meta is None
            or meta[0] != _V2_SCHEMA_VERSION
            or meta[1] != _V2_SCHEMA_FINGERPRINT
            or not isinstance(meta[2], str)
            or _DIGEST_RE.fullmatch(meta[2]) is None
            or meta[2] == "0" * 64
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in meta[3:]
            )
            or any(int(value) < 0 for value in meta[3:7])
            or int(meta[3]) > 1_000_000
            or int(meta[7]) != self.max_records
            or not self._compatible_response_limit(
                meta[8], allow_previous_default=True
            )
            or int(meta[9]) != self.max_total_response_bytes
            or int(meta[10]) != self.max_database_bytes
        ):
            raise sqlite3.DatabaseError("v2 durable media metadata is invalid")
        usage = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
            "COALESCE(SUM(reserved_response_bytes),0) FROM durable_media_requests"
        ).fetchone()
        if usage != tuple(meta[4:7]):
            raise sqlite3.DatabaseError("v2 durable media counters are corrupt")
        if (
            int(meta[4]) > self.max_records
            or int(meta[5]) + int(meta[6]) > self.max_total_response_bytes
        ):
            raise sqlite3.DatabaseError("v2 durable media capacity is invalid")
        anchor = self._read_legacy_anchor()
        if anchor != (str(meta[2]), int(meta[3])):
            raise sqlite3.DatabaseError("v2 durable media rollback detected")
        return str(meta[2]), int(meta[3]), tuple(int(value) for value in meta[4:])

    def _migrate_v2_schema(self, connection: sqlite3.Connection) -> None:
        """Upgrade one exact v2/anchor pair; strict bound opens never call this."""

        database_identity, mutation_sequence, legacy_meta = self._validate_v2_schema(
            connection
        )
        state_digest = _initial_authority_state_digest(database_identity)
        for sequence in range(1, mutation_sequence + 1):
            state_digest = _next_authority_state_digest(
                state_digest, database_identity, sequence
            )
        for object_type, name in _BASE_SCHEMA_AUXILIARY_DDL:
            if object_type == "trigger":
                connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "ALTER TABLE durable_media_requests_meta "
            "RENAME TO durable_media_requests_meta_v2"
        )
        connection.execute(_META_TABLE_DDL)
        connection.execute(
            "INSERT INTO durable_media_requests_meta "
            "(singleton,schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,authority_state_digest,authority_mode,"
            "authority_installation_id,authority_epoch,authority_recovery_floor,"
            "authority_recovery_state_digest,record_count,response_bytes,reserved_bytes,"
            "max_records,max_response_bytes,max_total_response_bytes,max_database_bytes) "
            "VALUES(1,?,?,?,?,?,'normal',NULL,NULL,NULL,NULL,?,?,?,?,?,?,?)",
            (
                _SCHEMA_VERSION,
                _SCHEMA_FINGERPRINT,
                database_identity,
                mutation_sequence,
                state_digest,
                *legacy_meta,
            ),
        )
        connection.execute("DROP TABLE durable_media_requests_meta_v2")
        for (object_type, _name), ddl in _BASE_SCHEMA_AUXILIARY_DDL.items():
            if object_type == "trigger":
                connection.execute(ddl)
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "table":
                connection.execute(ddl)
        connection.execute(
            "INSERT INTO durable_media_asset_capacity VALUES(1,?,0)",
            (self.max_asset_reservation_bytes,),
        )
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "trigger":
                connection.execute(ddl)
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        self._write_anchor(
            database_identity,
            mutation_sequence,
            state_digest,
            allow_resize=True,
        )

    def _validate_v3_schema(self, connection: sqlite3.Connection) -> None:
        """Validate the exact pre-asset-authority schema before dev migration."""

        if (
            int(connection.execute("PRAGMA application_id").fetchone()[0])
            != _APPLICATION_ID
            or int(connection.execute("PRAGMA user_version").fetchone()[0])
            != _V3_SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("v3 durable media schema identity is invalid")
        expected_objects = {
            ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
            ("table", "durable_media_requests_meta"): _V3_META_TABLE_DDL,
            **_BASE_SCHEMA_AUXILIARY_DDL,
        }
        expected_sql_objects = _expected_schema_sql(expected_objects)
        actual_objects = {
            (str(kind), str(name)): (str(tbl_name), sql)
            for kind, name, tbl_name, sql in _persistent_schema_rows(connection)
        }
        if set(actual_objects) != set(expected_sql_objects):
            raise sqlite3.DatabaseError("v3 durable media object set is incompatible")
        for identity, (expected_table, expected_sql) in expected_sql_objects.items():
            actual_table, actual_sql = actual_objects[identity]
            if actual_table != expected_table or self._canonical_sql(
                actual_sql
            ) != self._canonical_sql(expected_sql):
                raise sqlite3.DatabaseError("v3 durable media object is incompatible")
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,authority_state_digest,authority_mode,"
            "authority_installation_id,authority_epoch,authority_recovery_floor,"
            "authority_recovery_state_digest,record_count,response_bytes,reserved_bytes,"
            "max_records,max_response_bytes,max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if (
            meta is None
            or meta[0] != _V3_SCHEMA_VERSION
            or meta[1] != _V3_SCHEMA_FINGERPRINT
            or meta[13] != self.max_records
            or not self._compatible_response_limit(
                meta[14], allow_previous_default=True
            )
            or meta[15] != self.max_total_response_bytes
            or meta[16] != self.max_database_bytes
        ):
            raise sqlite3.DatabaseError("v3 durable media metadata is incompatible")
        actual_usage = connection.execute(
            "SELECT COUNT(*),"
            "COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
            "COALESCE(SUM(reserved_response_bytes),0) FROM durable_media_requests"
        ).fetchone()
        if actual_usage != tuple(meta[10:13]):
            raise sqlite3.DatabaseError("v3 durable media counters are corrupt")
        self._validate_anchor_against_database(connection)

    def _migrate_v3_schema(self, connection: sqlite3.Connection) -> None:
        """Add Root-anchored asset reservation/ACK authority in development only."""

        self._validate_v3_schema(connection)
        for identity in _BASE_SCHEMA_AUXILIARY_DDL:
            if identity[0] == "trigger":
                connection.execute(f'DROP TRIGGER "{identity[1]}"')
        connection.execute(
            "ALTER TABLE durable_media_requests_meta "
            "RENAME TO durable_media_requests_meta_v3"
        )
        connection.execute(_META_TABLE_DDL)
        connection.execute(
            "INSERT INTO durable_media_requests_meta "
            "SELECT singleton,?, ?,database_identity,mutation_sequence,"
            "authority_state_digest,authority_mode,authority_installation_id,"
            "authority_epoch,authority_recovery_floor,authority_recovery_state_digest,"
            "record_count,response_bytes,reserved_bytes,max_records,max_response_bytes,"
            "max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta_v3",
            (_SCHEMA_VERSION, _SCHEMA_FINGERPRINT),
        )
        connection.execute("DROP TABLE durable_media_requests_meta_v3")
        for identity, ddl in _BASE_SCHEMA_AUXILIARY_DDL.items():
            if identity[0] == "trigger":
                connection.execute(ddl)
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "table":
                connection.execute(ddl)
        connection.execute(
            "INSERT INTO durable_media_asset_capacity VALUES(1,?,0)",
            (self.max_asset_reservation_bytes,),
        )
        for identity, ddl in _ASSET_SCHEMA_DDL.items():
            if identity[0] == "trigger":
                connection.execute(ddl)
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _upgrade_default_response_budget(
        self, connection: sqlite3.Connection
    ) -> None:
        """Expand only the historical default; explicit operator limits stay exact.

        Existing processing rows keep their smaller reservation until the
        provider fence.  ``enter_provider_phase`` must expand that reservation
        transactionally or fail before any paid outbound call.
        """

        self._validate_schema(connection, allow_previous_default=True)
        row = connection.execute(
            "SELECT max_response_bytes FROM durable_media_requests_meta "
            "WHERE singleton=1"
        ).fetchone()
        if row is None or not self._compatible_response_limit(
            row[0], allow_previous_default=True
        ):
            raise sqlite3.DatabaseError("durable media response budget is invalid")
        if int(row[0]) == self.max_response_bytes:
            return
        if self._root_state_from_connection(connection).authority_mode != "normal":
            raise sqlite3.DatabaseError(
                "manual-only durable media authority cannot change runtime budgets"
            )
        (
            database_identity,
            mutation_sequence,
            state_digest,
        ) = self._validate_anchor_against_database(connection)
        if mutation_sequence >= _MAX_MUTATION_SEQUENCE:
            raise sqlite3.DatabaseError("durable media rollback sequence is exhausted")
        next_sequence = mutation_sequence + 1
        next_state_digest = _next_authority_state_digest(
            state_digest,
            database_identity,
            next_sequence,
        )
        # As with normal mutations, the external floor is durable first.  A
        # crash before SQLite commit locks the store rather than reopening the
        # old response ceiling and losing a provider result silently.
        self._write_anchor(
            database_identity,
            next_sequence,
            next_state_digest,
        )
        cursor = connection.execute(
            "UPDATE durable_media_requests_meta SET max_response_bytes=?,"
            "mutation_sequence=?,authority_state_digest=? "
            "WHERE singleton=1 AND database_identity=? "
            "AND mutation_sequence=? AND authority_state_digest=? "
            "AND max_response_bytes=?",
            (
                self.max_response_bytes,
                next_sequence,
                next_state_digest,
                database_identity,
                mutation_sequence,
                state_digest,
                self._previous_default_response_limit,
            ),
        )
        if cursor.rowcount != 1:
            raise sqlite3.DatabaseError(
                "durable media response budget changed concurrently"
            )

    def _validate_schema(
        self,
        connection: sqlite3.Connection,
        *,
        allow_previous_default: bool = False,
    ) -> None:
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise sqlite3.DatabaseError(
                "durable media foreign-key enforcement is disabled"
            )
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if application_id != self._application_id or user_version != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("durable media schema identity is invalid")

        request_columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_xinfo(durable_media_requests)")
        )
        meta_columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_xinfo(durable_media_requests_meta)"
            )
        )
        if request_columns != _EXPECTED_REQUEST_COLUMNS or meta_columns != _EXPECTED_META_COLUMNS:
            raise sqlite3.DatabaseError("durable media schema columns are incompatible")

        expected_objects = {
            ("table", "durable_media_requests"): _REQUEST_TABLE_DDL,
            ("table", "durable_media_requests_meta"): _META_TABLE_DDL,
            **self._schema_auxiliary_ddl,
        }
        expected_sql_objects = _expected_schema_sql(expected_objects)
        actual_rows = _persistent_schema_rows(connection)
        actual_objects = {
            (str(object_type), str(name)): (str(tbl_name), sql)
            for object_type, name, tbl_name, sql in actual_rows
        }
        if set(actual_objects) != set(expected_sql_objects):
            raise sqlite3.DatabaseError(
                "durable media schema object set is incompatible"
            )
        for identity, (expected_table, expected_sql) in expected_sql_objects.items():
            actual_table, actual_sql = actual_objects[identity]
            if actual_table != expected_table or self._canonical_sql(
                actual_sql
            ) != self._canonical_sql(expected_sql):
                raise sqlite3.DatabaseError(
                    f"durable media schema object {identity[1]} is incompatible"
                )

        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint,database_identity,"
            "mutation_sequence,authority_state_digest,authority_mode,"
            "authority_installation_id,authority_epoch,authority_recovery_floor,"
            "authority_recovery_state_digest,record_count,response_bytes,reserved_bytes,"
            "max_records,max_response_bytes,max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        expected_config = (
            _SCHEMA_VERSION,
            self._schema_fingerprint,
            self.max_records,
            self.max_response_bytes,
            self.max_total_response_bytes,
            self.max_database_bytes,
        )
        if (
            meta is None
            or meta[0] != expected_config[0]
            or meta[1] != expected_config[1]
            or not isinstance(meta[2], str)
            or _DIGEST_RE.fullmatch(meta[2]) is None
            or meta[2] == "0" * 64
            or not isinstance(meta[3], int)
            or isinstance(meta[3], bool)
            or not 0 <= int(meta[3]) <= _MAX_MUTATION_SEQUENCE
            or not isinstance(meta[4], str)
            or _DIGEST_RE.fullmatch(meta[4]) is None
            or meta[4] == "0" * 64
            or meta[5] not in {"normal", "manual_only"}
            or meta[13] != expected_config[2]
            or not self._compatible_response_limit(
                meta[14], allow_previous_default=allow_previous_default
            )
            or tuple(meta[15:]) != expected_config[4:]
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in meta[10:14]
            )
            or any(int(value) < 0 for value in meta[10:13])
        ):
            raise sqlite3.DatabaseError("durable media capacity metadata is invalid")
        if meta[5] == "normal":
            if any(value is not None for value in meta[6:10]):
                raise sqlite3.DatabaseError(
                    "durable media normal authority receipt is invalid"
                )
        else:
            if (
                not isinstance(meta[6], str)
                or _DIGEST_RE.fullmatch(meta[6]) is None
                or meta[6] == "0" * 64
                or not isinstance(meta[7], int)
                or isinstance(meta[7], bool)
                or int(meta[7]) < 1
                or not isinstance(meta[8], int)
                or isinstance(meta[8], bool)
                or int(meta[8]) < 0
                or not isinstance(meta[9], str)
                or _DIGEST_RE.fullmatch(meta[9]) is None
                or meta[9] == "0" * 64
                or int(meta[3]) != int(meta[8]) + 1
            ):
                raise sqlite3.DatabaseError(
                    "durable media manual authority receipt is invalid"
                )
        actual_usage = connection.execute(
            "SELECT COUNT(*),"
            "COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
            "COALESCE(SUM(reserved_response_bytes),0) "
            "FROM durable_media_requests"
        ).fetchone()
        if (
            actual_usage != tuple(meta[10:13])
            or int(meta[10]) > self.max_records
            or int(meta[11]) + int(meta[12]) > self.max_total_response_bytes
        ):
            raise sqlite3.DatabaseError("durable media capacity counters are corrupt")
        if self._schema_profile == _CHANNEL_MEDIA_SCHEMA_PROFILE:
            admission_usage = connection.execute(
                "SELECT COUNT(*) FROM durable_channel_media_admissions"
            ).fetchone()
            if (
                admission_usage is None
                or not isinstance(admission_usage[0], int)
                or isinstance(admission_usage[0], bool)
                or not 0 <= int(admission_usage[0]) <= self.max_records
            ):
                raise sqlite3.DatabaseError(
                    "durable channel media admission capacity is corrupt"
                )
            orphan_provider_admissions = connection.execute(
                "SELECT COUNT(*) FROM durable_channel_media_admissions a "
                "LEFT JOIN durable_media_requests r ON "
                "r.principal_hash=a.principal_hash AND r.operation=a.operation "
                "AND r.key_hash=a.key_hash WHERE a.state='provider_phase' AND "
                "(r.turn_id IS NULL OR r.turn_id<>a.turn_id "
                "OR r.request_sha256<>a.request_sha256 "
                "OR r.status<>'processing' OR r.provider_phase<>1 "
                "OR r.attempt_count<>a.attempt_count)"
            ).fetchone()
            inconsistent_live_admissions = connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests r "
                "LEFT JOIN durable_channel_media_admissions a ON "
                "a.principal_hash=r.principal_hash AND a.operation=r.operation "
                "AND a.key_hash=r.key_hash WHERE "
                "(r.provider_phase=0 AND a.turn_id IS NOT NULL) OR "
                "(r.provider_phase=1 AND (a.turn_id IS NULL "
                "OR a.turn_id<>r.turn_id OR a.request_sha256<>r.request_sha256 "
                "OR a.attempt_count<>r.attempt_count OR "
                "(r.status='processing' AND a.state<>'provider_phase') OR "
                "(r.status='succeeded' AND a.state<>'succeeded') OR "
                "(r.status='recovery_required' AND a.state<>'recovery_required')))"
            ).fetchone()
            if (
                orphan_provider_admissions != (0,)
                or inconsistent_live_admissions != (0,)
            ):
                raise sqlite3.DatabaseError(
                    "durable channel media admission authority is inconsistent"
                )
        asset_capacity = connection.execute(
            "SELECT max_capacity_bytes,reserved_total_bytes "
            "FROM durable_media_asset_capacity WHERE singleton=1"
        ).fetchone()
        asset_usage = connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes),0) "
            "FROM durable_media_asset_authority"
        ).fetchone()
        if (
            asset_capacity is None
            or asset_capacity[0] != self.max_asset_reservation_bytes
            or not isinstance(asset_capacity[1], int)
            or isinstance(asset_capacity[1], bool)
            or not 0 <= int(asset_capacity[1]) <= self.max_asset_reservation_bytes
            or asset_usage != (int(asset_capacity[1]),)
        ):
            raise sqlite3.DatabaseError(
                "durable paid-media asset capacity counters are corrupt"
            )
        mismatched_asset_authority = connection.execute(
            "SELECT COUNT(*) FROM durable_media_asset_authority a "
            "LEFT JOIN durable_media_requests r ON r.turn_id=a.turn_id "
            "WHERE r.turn_id IS NULL OR r.principal_hash<>a.principal_hash "
            "OR r.operation<>a.operation "
            "OR (a.state='reserved' AND r.status NOT IN "
            "('processing','recovery_required','succeeded')) "
            "OR (a.state='reserved' AND r.status='succeeded' "
            "AND r.operation<>'videos.create') "
            "OR (a.state IN ('committed','acked_pending_cleanup','acked') "
            "AND r.status<>'succeeded')"
        ).fetchone()
        if mismatched_asset_authority != (0,):
            raise sqlite3.DatabaseError(
                "durable paid-media asset authority is inconsistent"
            )
        authoritative_video_rows = connection.execute(
            "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
            "r.turn_id,a.state,a.token_set_digest FROM durable_media_requests r "
            "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
            "WHERE r.operation='videos.create' AND r.status='succeeded'"
        ).fetchall()
        for raw, encoded_bytes, turn_id, state, token_digest in authoritative_video_rows:
            _create_response, metadata = self._decode_video_envelope(
                raw,
                encoded_bytes,
                expected_turn_id=str(turn_id),
            )
            terminal = metadata.get("terminal_response")
            if state == "reserved":
                if token_digest is not None or (
                    terminal is not None
                    and (
                        not isinstance(terminal, dict)
                        or not _is_video_terminal_failure(terminal)
                    )
                ):
                    raise sqlite3.DatabaseError(
                        "nonterminal video asset authority is inconsistent"
                    )
                continue
            if not isinstance(terminal, dict):
                raise sqlite3.DatabaseError(
                    "terminal video asset authority is missing"
                )
            try:
                parsed_terminal = parse_asset_result(terminal)
            except PaidMediaAssetProtocolError as exc:
                raise sqlite3.DatabaseError(
                    "terminal video asset authority is corrupt"
                ) from exc
            if (
                parsed_terminal.kind != "video"
                or parsed_terminal.turn_id != turn_id
                or canonical_token_set_digest(
                    [asset.token for asset in parsed_terminal.assets]
                )
                != token_digest
            ):
                raise sqlite3.DatabaseError(
                    "terminal video asset authority does not match its result"
                )
        self._validate_anchor_against_database(connection)

    @staticmethod
    def _anchor_bytes(
        database_identity: str,
        mutation_sequence: int,
        authority_state_digest: str,
    ) -> bytes:
        if (
            _DIGEST_RE.fullmatch(database_identity) is None
            or database_identity == "0" * 64
            or _DIGEST_RE.fullmatch(authority_state_digest) is None
            or authority_state_digest == "0" * 64
            or not isinstance(mutation_sequence, int)
            or isinstance(mutation_sequence, bool)
            or not 0 <= mutation_sequence <= _MAX_MUTATION_SEQUENCE
        ):
            raise sqlite3.DatabaseError("durable media rollback anchor state is invalid")
        return json.dumps(
            {
                "database_identity": database_identity,
                "format": _ANCHOR_FORMAT,
                # Fixed-width text keeps every generation byte-for-byte the
                # same length.  An interrupted in-place write is either the
                # old value, the new value, or invalid; all three are safe
                # because only an exact database/anchor pair is accepted.
                "mutation_sequence": f"{mutation_sequence:016x}",
                "authority_state_digest": authority_state_digest,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _read_anchor(self) -> tuple[str, int, str]:
        try:
            self._assert_database_path()
            with self.anchor_path.open("rb") as stream:
                raw = stream.read(_ANCHOR_MAX_BYTES + 1)
            self._assert_database_path()
            if not raw or len(raw) > _ANCHOR_MAX_BYTES:
                raise ValueError("rollback anchor size is invalid")
            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict) or set(decoded) != {
                "authority_state_digest",
                "database_identity",
                "format",
                "mutation_sequence",
            }:
                raise ValueError("rollback anchor fields are invalid")
            identity = decoded.get("database_identity")
            state_digest = decoded.get("authority_state_digest")
            encoded_sequence = decoded.get("mutation_sequence")
            if decoded.get("format") != _ANCHOR_FORMAT:
                raise ValueError("rollback anchor format is invalid")
            if not isinstance(identity, str):
                raise ValueError("rollback anchor identity is invalid")
            if not isinstance(state_digest, str):
                raise ValueError("rollback anchor state digest is invalid")
            if (
                not isinstance(encoded_sequence, str)
                or re.fullmatch(r"[0-9a-f]{16}", encoded_sequence) is None
            ):
                raise ValueError("rollback anchor sequence is invalid")
            sequence = int(encoded_sequence, 16)
            canonical = self._anchor_bytes(identity, sequence, state_digest)
            if raw != canonical:
                raise ValueError("rollback anchor encoding is invalid")
            return identity, int(sequence), state_digest
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise OSError("durable media rollback anchor is unavailable") from exc

    def _write_anchor(
        self,
        database_identity: str,
        mutation_sequence: int,
        authority_state_digest: str,
        *,
        create_only: bool = False,
        allow_resize: bool = False,
    ) -> None:
        encoded = self._anchor_bytes(
            database_identity,
            mutation_sequence,
            authority_state_digest,
        )
        self._assert_database_path()
        flags = os.O_RDWR | os.O_CREAT
        flags |= os.O_EXCL if create_only else 0
        flags |= int(getattr(os, "O_BINARY", 0))
        if not create_only:
            if not self.anchor_path.exists():
                raise OSError("durable media rollback anchor is missing")
        descriptor: int | None = None
        try:
            descriptor = os.open(self.anchor_path, flags, 0o600)
            existing_size = int(os.fstat(descriptor).st_size)
            if not create_only and not allow_resize and existing_size != len(encoded):
                raise OSError("durable media rollback anchor size changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("durable media rollback anchor write was incomplete")
                view = view[written:]
            os.ftruncate(descriptor, len(encoded))
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            self._assert_database_path()
            if self._read_anchor() != (
                database_identity,
                mutation_sequence,
                authority_state_digest,
            ):
                raise OSError("durable media rollback anchor verification failed")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _database_anchor_state(
        connection: sqlite3.Connection,
    ) -> tuple[str, int, str]:
        row = connection.execute(
            "SELECT database_identity,mutation_sequence,authority_state_digest "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or not isinstance(row[0], str)
            or _DIGEST_RE.fullmatch(row[0]) is None
            or row[0] == "0" * 64
            or not isinstance(row[1], int)
            or isinstance(row[1], bool)
            or not 0 <= int(row[1]) <= _MAX_MUTATION_SEQUENCE
            or not isinstance(row[2], str)
            or _DIGEST_RE.fullmatch(row[2]) is None
            or row[2] == "0" * 64
        ):
            raise sqlite3.DatabaseError("durable media rollback metadata is invalid")
        return row[0], int(row[1]), row[2]

    def _validate_anchor_against_database(
        self, connection: sqlite3.Connection
    ) -> tuple[str, int, str]:
        database_state = self._database_anchor_state(connection)
        try:
            anchor_state = self._read_anchor()
        except OSError as exc:
            raise sqlite3.DatabaseError(
                "durable media rollback anchor cannot be verified"
            ) from exc
        if anchor_state != database_state:
            raise sqlite3.DatabaseError(
                "durable media database rollback or replacement detected"
            )
        return database_state

    def _pending_anchor_successor(
        self, connection: sqlite3.Connection
    ) -> tuple[tuple[str, int, str], tuple[str, int, str]] | None:
        """Identify only the anchor-first window of one legitimate next commit."""

        database_state = self._database_anchor_state(connection)
        try:
            anchor_state = self._read_anchor()
        except OSError:
            return None
        identity, sequence, state_digest = database_state
        if sequence >= _MAX_MUTATION_SEQUENCE:
            return None
        expected = (
            identity,
            sequence + 1,
            _next_authority_state_digest(
                state_digest,
                identity,
                sequence + 1,
            ),
        )
        if anchor_state != expected:
            return None
        return database_state, anchor_state

    @staticmethod
    def _root_state_from_connection(
        connection: sqlite3.Connection,
    ) -> DurableMediaRootState:
        row = connection.execute(
            "SELECT database_identity,mutation_sequence,authority_state_digest,"
            "authority_mode,authority_installation_id,authority_epoch,"
            "authority_recovery_floor,authority_recovery_state_digest "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("durable media authority state is missing")
        return DurableMediaRootState(
            database_identity=str(row[0]),
            mutation_sequence=int(row[1]),
            state_digest=str(row[2]),
            authority_mode=str(row[3]),  # type: ignore[arg-type]
            installation_id=None if row[4] is None else str(row[4]),
            epoch=None if row[5] is None else int(row[5]),
            recovery_floor=None if row[6] is None else int(row[6]),
            recovery_state_digest=None if row[7] is None else str(row[7]),
        )

    def inspect_root_state(self) -> DurableMediaRootState:
        """Read the exact local proof without enabling any mutation."""

        try:
            with self._read_transaction() as connection:
                return self._root_state_from_connection(connection)
        except sqlite3.OperationalError as exc:
            raise DurableMediaRequestUnavailable(
                "cannot inspect durable media authority state"
            ) from exc
        except (OSError, sqlite3.DatabaseError) as exc:
            raise DurableMediaAuthorityCorruption(
                "durable media authority state is structurally invalid"
            ) from exc

    @staticmethod
    def _is_reparse_or_symlink(info: os.stat_result) -> bool:
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & reparse
        )

    def _assert_database_path(self) -> None:
        for component in reversed((self.path, *self.path.parents)):
            try:
                info = os.lstat(component)
            except FileNotFoundError:
                continue
            if self._is_reparse_or_symlink(info):
                raise OSError("durable media request path contains a reparse point")
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            Path(f"{self.path}-journal"),
            self.anchor_path,
        ):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if self._is_reparse_or_symlink(info):
                raise OSError("durable media request files must not be reparse points")
            if not stat.S_ISREG(info.st_mode):
                raise OSError("durable media request database files must be regular files")

    def _database_family_presence(self) -> dict[str, bool]:
        self._assert_database_path()
        presence: dict[str, bool] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.lstat(f"{self.path}{suffix}")
            except FileNotFoundError:
                presence[suffix] = False
            else:
                presence[suffix] = True
        return presence

    def _database_path_identity(self) -> tuple[int, int]:
        self._assert_database_path()
        info = os.lstat(self.path)
        if not stat.S_ISREG(info.st_mode) or self._is_reparse_or_symlink(info):
            raise OSError("durable media request database path is unsafe")
        return int(info.st_dev), int(info.st_ino)

    def _assert_database_family_bounds(self) -> None:
        limits = {
            "": self.max_database_bytes,
            "-wal": 2 * self.max_database_bytes,
            "-shm": _MAX_SHM_BYTES,
            "-journal": self.max_database_bytes,
        }
        for suffix, limit in limits.items():
            candidate = Path(f"{self.path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if (
                self._is_reparse_or_symlink(info)
                or not stat.S_ISREG(info.st_mode)
                or int(info.st_size) > limit
            ):
                raise sqlite3.DatabaseError(
                    "durable media database family exceeds its bounded profile"
                )

    def _connect(
        self,
        *,
        check_same_thread: bool = True,
        configure_page_budget: bool = True,
    ) -> sqlite3.Connection:
        self._assert_database_path()
        connection: sqlite3.Connection | None = None
        try:
            connect_target: str = str(self.path)
            connect_options: dict[str, object] = {}
            if self._construction_policy in {"create_bound", "open_bound"}:
                connect_target = f"{self.path.as_uri()}?mode=rw"
                connect_options["uri"] = True
            connection = sqlite3.connect(
                connect_target,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=check_same_thread,
                **connect_options,
            )
            self._assert_database_path()
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise sqlite3.DatabaseError(
                    "durable media foreign-key enforcement is unavailable"
                )
            # This pragma is connection-scoped.  Setting it only on the schema
            # initializer silently leaves claim/phase/success transactions at
            # the process default.
            connection.execute("PRAGMA synchronous=FULL")
            if configure_page_budget:
                self._configure_page_budget(connection)
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    @staticmethod
    def _database_versions(connection: sqlite3.Connection) -> tuple[int, int]:
        data_row = connection.execute("PRAGMA data_version").fetchone()
        schema_row = connection.execute("PRAGMA schema_version").fetchone()
        if data_row is None or schema_row is None:
            raise sqlite3.DatabaseError("cannot read durable media database versions")
        data_version = data_row[0]
        schema_version = schema_row[0]
        if (
            not isinstance(data_version, int)
            or isinstance(data_version, bool)
            or data_version < 0
            or not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version < 0
        ):
            raise sqlite3.DatabaseError("durable media database versions are invalid")
        return data_version, schema_version

    @contextmanager
    def _read_transaction(self):
        """Open one validated read snapshot without advancing local authority."""

        with self._transaction_lock:
            self._assert_database_path()
            connection = self._keeper
            if connection is None:
                raise sqlite3.DatabaseError("durable media request store is closed")
            if connection.in_transaction:
                raise sqlite3.DatabaseError(
                    "durable media request transaction state is invalid"
                )
            pending_observation: (
                tuple[tuple[str, int, str], tuple[str, int, str]] | None
            ) = None
            reconciliation_attempts = 0
            while True:
                connection.execute("BEGIN")
                try:
                    self._assert_database_path()
                    data_version, schema_version = self._database_versions(connection)
                    if (
                        data_version != self._trusted_data_version
                        or schema_version != self._trusted_schema_version
                    ):
                        self._configure_page_budget(connection)
                        self._validate_schema(connection)
                        self._trusted_data_version = data_version
                        self._trusted_schema_version = schema_version
                    try:
                        self._validate_anchor_against_database(connection)
                    except sqlite3.DatabaseError:
                        pending = self._pending_anchor_successor(connection)
                        if (
                            pending is None
                            or pending == pending_observation
                            or reconciliation_attempts >= 4
                        ):
                            raise
                        pending_observation = pending
                        reconciliation_attempts += 1
                        connection.rollback()
                        # BEGIN IMMEDIATE is a cross-connection/process barrier.
                        # It waits for an active anchor-first writer to commit.
                        # If no writer exists (for example after a crash), it is
                        # acquired immediately and the unchanged mismatch fails
                        # closed on the next snapshot.
                        connection.execute("BEGIN IMMEDIATE")
                        connection.rollback()
                        continue
                    try:
                        yield connection
                    finally:
                        if connection.in_transaction:
                            connection.rollback()
                    return
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise

    @contextmanager
    def _write_transaction(self):
        """Commit one logical mutation and then synchronously confirm its root CAS."""

        with self._transaction_lock:
            if self._pre_mutation_hook_active:
                raise DurableMediaRequestUnavailable(
                    "durable media mutation gate is already active"
                )
            if self._commit_hook_active:
                raise DurableMediaRequestUnavailable(
                    "durable media mutation is unavailable during root confirmation"
                )
            if self._root_commit_pending is not None:
                raise DurableMediaRootCommitPending(
                    "installation-root commit confirmation is pending"
                )
            self._assert_database_path()
            if self._pre_mutation_hook is not None:
                self._pre_mutation_hook_active = True
                try:
                    self._pre_mutation_hook()
                finally:
                    self._pre_mutation_hook_active = False
            connection = self._keeper
            if connection is None:
                raise sqlite3.DatabaseError("durable media request store is closed")
            if connection.in_transaction:
                raise sqlite3.DatabaseError(
                    "durable media request transaction state is invalid"
                )
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._assert_database_path()
                data_version, schema_version = self._database_versions(connection)
                if (
                    data_version != self._trusted_data_version
                    or schema_version != self._trusted_schema_version
                ):
                    self._configure_page_budget(connection)
                    self._validate_schema(connection)
                    self._trusted_data_version = data_version
                    self._trusted_schema_version = schema_version
                self._validate_anchor_against_database(connection)
                before = self._root_state_from_connection(connection)
                if before.authority_mode == "manual_only":
                    raise DurableMediaRequestUnavailable(
                        "durable media authority is restricted to manual recovery"
                    )
                changes_before = connection.total_changes
                yield connection
                logical_change = connection.total_changes != changes_before
                if not logical_change:
                    connection.commit()
                    (
                        self._trusted_data_version,
                        self._trusted_schema_version,
                    ) = self._database_versions(connection)
                    return
                database_identity, mutation_sequence, state_digest = (
                    self._validate_anchor_against_database(connection)
                )
                if (
                    database_identity != before.database_identity
                    or mutation_sequence != before.mutation_sequence
                    or state_digest != before.state_digest
                ):
                    raise sqlite3.DatabaseError(
                        "durable media authority changed during local mutation"
                    )
                if mutation_sequence >= _MAX_MUTATION_SEQUENCE:
                    raise sqlite3.DatabaseError(
                        "durable media rollback sequence is exhausted"
                    )
                next_sequence = mutation_sequence + 1
                next_state_digest = _next_authority_state_digest(
                    state_digest,
                    database_identity,
                    next_sequence,
                )
                # Persist the external floor before the SQLite commit.  A crash
                # between these writes leaves the anchor ahead and therefore
                # locks the store instead of accepting a silent rollback.
                self._write_anchor(
                    database_identity,
                    next_sequence,
                    next_state_digest,
                )
                cursor = connection.execute(
                    "UPDATE durable_media_requests_meta SET mutation_sequence=?,"
                    "authority_state_digest=? "
                    "WHERE singleton=1 AND database_identity=? "
                    "AND mutation_sequence=? AND authority_state_digest=?",
                    (
                        next_sequence,
                        next_state_digest,
                        database_identity,
                        mutation_sequence,
                        state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "durable media rollback sequence changed concurrently"
                    )
                after = self._root_state_from_connection(connection)
                connection.commit()
                (
                    self._trusted_data_version,
                    self._trusted_schema_version,
                ) = self._database_versions(connection)
                transition = DurableMediaRootTransition(before=before, after=after)
                if self._root_commit_hook is not None:
                    self._commit_hook_active = True
                    try:
                        self._root_commit_hook(transition)
                    except BaseException:
                        self._root_commit_pending = transition
                        raise DurableMediaRootCommitPending(
                            "installation-root commit confirmation is pending"
                        ) from None
                    finally:
                        self._commit_hook_active = False
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                if connection.in_transaction:
                    connection.rollback()

    def resume_after_root_reconcile(
        self,
        expected_current_proof: DurableMediaRootState,
    ) -> DurableMediaRootState:
        """Resume writes only after a caller proves root equals local current state."""

        if not isinstance(expected_current_proof, DurableMediaRootState):
            raise ValueError("expected current root proof is invalid")
        with self._transaction_lock:
            current = self.inspect_root_state()
            if current != expected_current_proof:
                raise DurableMediaRequestUnavailable(
                    "durable media root reconciliation proof does not match"
                )
            if (
                self._root_commit_pending is not None
                and self._root_commit_pending.after != expected_current_proof
            ):
                raise DurableMediaRequestUnavailable(
                    "durable media root reconciliation proof is stale"
                )
            self._root_commit_pending = None
            return current

    def _configure_page_budget(self, connection: sqlite3.Connection) -> None:
        page_size_row = connection.execute("PRAGMA page_size").fetchone()
        page_count_row = connection.execute("PRAGMA page_count").fetchone()
        if page_size_row is None or page_count_row is None:
            raise sqlite3.DatabaseError("cannot read durable media page budget")
        page_size = int(page_size_row[0])
        page_count = int(page_count_row[0])
        if page_size <= 0 or page_count < 0:
            raise sqlite3.DatabaseError("durable media page metadata is invalid")
        max_pages = self.max_database_bytes // page_size
        if max_pages < 1:
            raise sqlite3.DatabaseError("durable media page budget is too small")
        configured_row = connection.execute(
            f"PRAGMA max_page_count={max_pages}"
        ).fetchone()
        if (
            configured_row is None
            or int(configured_row[0]) != max_pages
            or page_count > max_pages
        ):
            raise sqlite3.DatabaseError(
                "existing durable media database exceeds its page budget"
            )

    @staticmethod
    def _validated_now(value: float | None) -> float:
        current = time.time() if value is None else float(value)
        if not math.isfinite(current) or current < 0:
            raise ValueError("now must be a finite nonnegative timestamp")
        return current

    def _meta_usage(self, connection: sqlite3.Connection) -> tuple[int, int, int]:
        row = connection.execute(
            "SELECT record_count,response_bytes,reserved_bytes,max_records,"
            "max_response_bytes,max_total_response_bytes,max_database_bytes "
            "FROM durable_media_requests_meta WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or any(not isinstance(value, int) or isinstance(value, bool) for value in row)
            or any(int(value) < 0 for value in row[:3])
            or tuple(row[3:])
            != (
                self.max_records,
                self.max_response_bytes,
                self.max_total_response_bytes,
                self.max_database_bytes,
            )
            or int(row[0]) > self.max_records
            or int(row[1]) + int(row[2]) > self.max_total_response_bytes
        ):
            raise sqlite3.DatabaseError("durable media usage metadata is invalid")
        return int(row[0]), int(row[1]), int(row[2])

    def _prune(self, connection: sqlite3.Connection, current: float) -> None:
        # Once a provider-capable claim's lease is gone, its outcome is
        # ambiguous.  Persist that terminal fact before any capacity cleanup;
        # it is retained for 30 days from the lease boundary.
        connection.execute(
            "UPDATE durable_media_requests SET status='recovery_required',"
            "fencing_token='',reserved_response_bytes=0,response_json=NULL,"
            "expires_at=lease_expires_at+?,updated_at=lease_expires_at,"
            "lease_expires_at=0 WHERE (principal_hash,operation,key_hash) IN ("
            "SELECT principal_hash,operation,key_hash FROM durable_media_requests "
            "WHERE status='processing' AND provider_phase=1 "
            "AND lease_expires_at<=? ORDER BY lease_expires_at LIMIT ?)",
            (self.retention_seconds, current, self.prune_batch),
        )
        connection.execute(
            "DELETE FROM durable_media_requests "
            "WHERE (principal_hash,operation,key_hash) IN ("
            "SELECT principal_hash,operation,key_hash FROM durable_media_requests "
            "WHERE (status<>'processing' AND expires_at<=? AND NOT EXISTS("
            "SELECT 1 FROM durable_media_asset_authority a "
            "WHERE a.turn_id=durable_media_requests.turn_id "
            "AND a.state IN ('reserved','committed','acked_pending_cleanup'))) OR "
            "(status='processing' AND provider_phase=0 "
            "AND lease_expires_at+?<=? AND NOT EXISTS("
            "SELECT 1 FROM durable_media_asset_authority a "
            "WHERE a.turn_id=durable_media_requests.turn_id)) "
            "ORDER BY expires_at LIMIT ?)",
            (current, self.retention_seconds, current, self.prune_batch),
        )

    def _decode_response(self, raw: Any, encoded_bytes: Any) -> dict[str, object]:
        if (
            not isinstance(raw, str)
            or not isinstance(encoded_bytes, int)
            or isinstance(encoded_bytes, bool)
            or encoded_bytes < 2
            or encoded_bytes > self.max_response_bytes
            or len(raw.encode("utf-8")) != encoded_bytes
        ):
            raise sqlite3.DatabaseError("durable media response size is invalid")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError, RecursionError) as exc:
            raise sqlite3.DatabaseError("durable media response is corrupt") from exc
        if not isinstance(value, dict):
            raise sqlite3.DatabaseError("durable media response is not an object")
        if set(value) == {"response", "video_task"}:
            response = value.get("response")
            metadata = value.get("video_task")
            if not isinstance(response, dict) or not isinstance(metadata, dict):
                raise sqlite3.DatabaseError("durable video task envelope is corrupt")
            self._validated_video_metadata(metadata)
            return response
        return value

    @staticmethod
    def _validated_video_metadata(value: dict[str, object]) -> dict[str, object]:
        base_fields = {
            "version",
            "task_alias",
            "requested_model",
            "provider_name",
            "provider_domain",
            "provider_credential_domain",
            "upstream_model",
            "upstream_task_id",
            "poll_attempt",
            "poll_fencing_token",
            "poll_lease_expires_at",
            "next_poll_at",
            "last_response",
            "terminal_response",
        }
        prepared_fields = {
            "prepared_token",
            "prepared_provider_response",
            "prepared_asset_response",
            "prepare_sha256",
        }
        version = value.get("version")
        if type(version) is not int or version not in {
            _LEGACY_VIDEO_ENVELOPE_VERSION,
            _VIDEO_ENVELOPE_VERSION,
        }:
            raise sqlite3.DatabaseError(
                "durable video task metadata version is corrupt"
            )
        expected = (
            base_fields
            if version == _LEGACY_VIDEO_ENVELOPE_VERSION
            else base_fields | prepared_fields
        )
        if set(value) != expected:
            raise sqlite3.DatabaseError("durable video task metadata fields are corrupt")
        string_fields = (
            "task_alias",
            "requested_model",
            "provider_name",
            "provider_domain",
            "provider_credential_domain",
            "upstream_model",
            "upstream_task_id",
        )
        if any(not isinstance(value.get(field), str) for field in string_fields):
            raise sqlite3.DatabaseError(
                "durable video task route types are corrupt"
            )
        try:
            _video_turn_id(value.get("task_alias"))
            _validated_video_route_text(value.get("requested_model"), "requested_model")
            _validated_video_route_text(value.get("provider_name"), "provider_name")
            _validated_digest(value.get("provider_domain"), "provider_domain")
            _validated_digest(
                value.get("provider_credential_domain"),
                "provider_credential_domain",
            )
            _validated_video_route_text(value.get("upstream_model"), "upstream_model")
            _validated_video_route_text(value.get("upstream_task_id"), "upstream_task_id")
        except ValueError as exc:
            raise sqlite3.DatabaseError("durable video task route is corrupt") from exc
        poll_attempt = value.get("poll_attempt")
        fencing_token = value.get("poll_fencing_token")
        lease_expires_at = value.get("poll_lease_expires_at")
        next_poll_at = value.get("next_poll_at")
        if (
            not isinstance(poll_attempt, int)
            or isinstance(poll_attempt, bool)
            or not 0 <= poll_attempt <= 1_000_000
            or not isinstance(fencing_token, str)
            or (fencing_token != "" and _DIGEST_RE.fullmatch(fencing_token) is None)
            or not isinstance(lease_expires_at, (int, float))
            or isinstance(lease_expires_at, bool)
            or not math.isfinite(float(lease_expires_at))
            or float(lease_expires_at) < 0
            or not isinstance(next_poll_at, (int, float))
            or isinstance(next_poll_at, bool)
            or not math.isfinite(float(next_poll_at))
            or float(next_poll_at) < 0
            or ((fencing_token == "") != (float(lease_expires_at) == 0))
        ):
            raise sqlite3.DatabaseError("durable video task poll state is corrupt")
        for field in ("last_response", "terminal_response"):
            response = value.get(field)
            if response is not None and not isinstance(response, dict):
                raise sqlite3.DatabaseError("durable video task cached response is corrupt")
        if value.get("terminal_response") is not None and fencing_token:
            raise sqlite3.DatabaseError("terminal video task retains an active poll fence")
        if version == _VIDEO_ENVELOPE_VERSION:
            prepared_token = value.get("prepared_token")
            prepared_provider = value.get("prepared_provider_response")
            prepared_asset = value.get("prepared_asset_response")
            prepare_sha256 = value.get("prepare_sha256")
            if prepared_token == "":
                if (
                    prepared_provider is not None
                    or prepared_asset is not None
                    or prepare_sha256 != ""
                ):
                    raise sqlite3.DatabaseError(
                        "empty prepared video state retains recovery material"
                    )
            else:
                if (
                    not isinstance(prepared_token, str)
                    or not isinstance(prepared_provider, dict)
                    or (
                        prepared_asset is not None
                        and not isinstance(prepared_asset, dict)
                    )
                    or not isinstance(prepare_sha256, str)
                    or _DIGEST_RE.fullmatch(prepare_sha256) is None
                    or value.get("terminal_response") is not None
                ):
                    raise sqlite3.DatabaseError(
                        "prepared video recovery material is corrupt"
                    )
                try:
                    _provider, _asset, expected_digest = _prepared_video_material(
                        task_alias=value.get("task_alias"),
                        token=prepared_token,
                        provider_response=prepared_provider,
                        asset_response=prepared_asset,
                    )
                except ValueError as exc:
                    raise sqlite3.DatabaseError(
                        "prepared video recovery material is corrupt"
                    ) from exc
                if prepare_sha256 != expected_digest:
                    raise sqlite3.DatabaseError(
                        "prepared video recovery digest is corrupt"
                    )
        return value

    @staticmethod
    def _video_metadata_v2(value: dict[str, object]) -> dict[str, object]:
        """Upgrade one validated legacy envelope without changing its meaning."""

        DurableMediaRequestStore._validated_video_metadata(value)
        if value.get("version") == _VIDEO_ENVELOPE_VERSION:
            return dict(value)
        upgraded = dict(value)
        upgraded.update(
            {
                "version": _VIDEO_ENVELOPE_VERSION,
                "prepared_token": "",
                "prepared_provider_response": None,
                "prepared_asset_response": None,
                "prepare_sha256": "",
            }
        )
        DurableMediaRequestStore._validated_video_metadata(upgraded)
        return upgraded

    def _decode_video_envelope(
        self,
        raw: Any,
        encoded_bytes: Any,
        *,
        expected_turn_id: str,
    ) -> tuple[dict[str, object], dict[str, object]]:
        response = self._decode_response(raw, encoded_bytes)
        try:
            value = json.loads(raw)
        except (TypeError, ValueError, RecursionError) as exc:
            raise sqlite3.DatabaseError("durable video task envelope is corrupt") from exc
        if not isinstance(value, dict) or set(value) != {"response", "video_task"}:
            raise sqlite3.DatabaseError("durable video task registry is missing")
        metadata = value.get("video_task")
        if not isinstance(metadata, dict):
            raise sqlite3.DatabaseError("durable video task metadata is corrupt")
        self._validated_video_metadata(metadata)
        if metadata.get("task_alias") != _video_task_alias(expected_turn_id):
            raise sqlite3.DatabaseError("durable video task alias is corrupt")
        return response, metadata

    def _encode_video_envelope(
        self,
        response: dict[str, object],
        metadata: dict[str, object],
    ) -> str:
        if not isinstance(response, dict):
            raise ValueError("video response must be an object")
        normalized_metadata = self._video_metadata_v2(metadata)
        try:
            encoded = json.dumps(
                {"response": response, "video_task": normalized_metadata},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("video task envelope must be bounded JSON") from exc
        if len(encoded.encode("utf-8")) > self.max_response_bytes:
            raise ValueError("video task envelope exceeds durable storage limit")
        return encoded

    def _decode_asset_authority_response(
        self,
        raw: Any,
        encoded_bytes: Any,
        *,
        turn_id: str,
        operation: str,
    ) -> dict[str, object]:
        if operation == "images.create":
            return self._decode_response(raw, encoded_bytes)
        _create_response, metadata = self._decode_video_envelope(
            raw,
            encoded_bytes,
            expected_turn_id=turn_id,
        )
        terminal = metadata.get("terminal_response")
        if not isinstance(terminal, dict):
            raise sqlite3.DatabaseError(
                "durable video asset terminal response is unavailable"
            )
        return dict(terminal)

    def _validate_stored_row(
        self,
        row: tuple[Any, ...],
        *,
        expected_turn_id: str,
    ) -> tuple[str, str, float, int, int, dict[str, object] | None]:
        (
            stored_request,
            status,
            fencing_token,
            lease_expires_at,
            attempts,
            provider_phase,
            response_json,
            response_bytes,
            reserved_response_bytes,
            expires_at,
            stored_turn_id,
        ) = row
        if (
            not isinstance(stored_request, str)
            or _DIGEST_RE.fullmatch(stored_request) is None
            or stored_turn_id != expected_turn_id
            or status not in {"processing", "succeeded", "recovery_required"}
            or not isinstance(fencing_token, str)
            or not isinstance(lease_expires_at, (int, float))
            or isinstance(lease_expires_at, bool)
            or not math.isfinite(float(lease_expires_at))
            or not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or int(attempts) < 1
            or not isinstance(provider_phase, int)
            or isinstance(provider_phase, bool)
            or int(provider_phase) not in {0, 1}
            or not isinstance(reserved_response_bytes, int)
            or isinstance(reserved_response_bytes, bool)
            or int(reserved_response_bytes) < 0
            or not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
            or not math.isfinite(float(expires_at))
            or float(expires_at) < 0
        ):
            raise sqlite3.DatabaseError("durable media request state is corrupt")

        normalized_status = str(status)
        normalized_lease = float(lease_expires_at)
        normalized_phase = int(provider_phase)
        decoded: dict[str, object] | None = None
        if normalized_status == "processing":
            valid_pair = (
                response_json is None
                and response_bytes is None
                and 64 <= int(reserved_response_bytes) <= self.max_response_bytes
                and _DIGEST_RE.fullmatch(fencing_token) is not None
                and normalized_lease > 0
            )
        elif normalized_status == "succeeded":
            valid_pair = (
                normalized_phase == 1
                and response_json is not None
                and int(reserved_response_bytes) == 0
                and fencing_token == ""
                and normalized_lease == 0
            )
            if valid_pair:
                decoded = self._decode_response(response_json, response_bytes)
        else:
            valid_pair = (
                normalized_phase == 1
                and response_json is None
                and response_bytes is None
                and int(reserved_response_bytes) == 0
                and fencing_token == ""
                and normalized_lease == 0
            )
        if not valid_pair:
            raise sqlite3.DatabaseError(
                "durable media request status payload pairing is corrupt"
            )
        return (
            stored_request,
            normalized_status,
            normalized_lease,
            int(attempts),
            normalized_phase,
            decoded,
        )

    def _claim_read_result(
        self,
        row: tuple[Any, ...],
        *,
        expected_turn_id: str,
        request_digest: str,
        operation: str,
        current: float,
    ) -> DurableMediaRequestClaim | None:
        (
            stored_request,
            status,
            lease_expires_at,
            attempts,
            provider_phase,
            response,
        ) = self._validate_stored_row(row, expected_turn_id=expected_turn_id)
        expires_at = float(row[9])
        if status != "processing" and expires_at <= current:
            return None
        if (
            status == "processing"
            and provider_phase == 0
            and lease_expires_at + self.retention_seconds <= current
        ):
            return None
        if stored_request != request_digest:
            return DurableMediaRequestClaim(
                state="conflict", turn_id=expected_turn_id
            )
        if status == "processing" and lease_expires_at > current:
            return DurableMediaRequestClaim(
                state="processing",
                turn_id=expected_turn_id,
                attempt=attempts,
                retry_after_seconds=max(
                    1, int(lease_expires_at - current + 0.999)
                ),
            )
        if status == "processing":
            return None
        if status == "succeeded":
            if operation == "videos.create":
                try:
                    stored_document = json.loads(str(row[6]))
                except (TypeError, ValueError, RecursionError) as exc:
                    raise sqlite3.DatabaseError(
                        "durable legacy video response is corrupt"
                    ) from exc
                if not (
                    isinstance(stored_document, dict)
                    and set(stored_document) == {"response", "video_task"}
                ):
                    response = {
                        "task_id": _video_task_alias(expected_turn_id),
                        "status": "legacy_recovery_required",
                    }
                else:
                    create_response, metadata = self._decode_video_envelope(
                        row[6], row[7], expected_turn_id=expected_turn_id
                    )
                    terminal_response = metadata.get("terminal_response")
                    response = (
                        dict(terminal_response)
                        if isinstance(terminal_response, dict)
                        else create_response
                    )
            return DurableMediaRequestClaim(
                state="succeeded",
                turn_id=expected_turn_id,
                attempt=attempts,
                response=response,
            )
        return DurableMediaRequestClaim(
            state="recovery_required",
            turn_id=expected_turn_id,
            attempt=attempts,
        )

    def _channel_admission_read_result(
        self,
        connection: sqlite3.Connection,
        *,
        principal_hash: str,
        operation: str,
        key_hash: str,
        expected_turn_id: str,
        request_digest: str,
        allow_provider_phase: bool = True,
    ) -> DurableMediaRequestClaim | None:
        if self._schema_profile != _CHANNEL_MEDIA_SCHEMA_PROFILE:
            return None
        row = connection.execute(
            "SELECT request_sha256,state,attempt_count,turn_id "
            "FROM durable_channel_media_admissions WHERE principal_hash=? "
            "AND operation=? AND key_hash=?",
            (principal_hash, operation, key_hash),
        ).fetchone()
        if row is None:
            return None
        stored_request, state, attempts, stored_turn_id = row
        if (
            not isinstance(stored_request, str)
            or _DIGEST_RE.fullmatch(stored_request) is None
            or stored_request == "0" * 64
            or state not in {"provider_phase", "succeeded", "recovery_required"}
            or not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or attempts < 1
            or stored_turn_id != expected_turn_id
        ):
            raise sqlite3.DatabaseError(
                "durable channel media admission is corrupt"
            )
        if stored_request != request_digest:
            return DurableMediaRequestClaim(
                state="conflict",
                turn_id=expected_turn_id,
            )
        if state == "provider_phase" and not allow_provider_phase:
            return None
        return DurableMediaRequestClaim(
            state=(
                "result_expired"
                if state == "succeeded"
                else "recovery_required"
            ),
            turn_id=expected_turn_id,
            attempt=int(attempts),
        )

    def claim(
        self,
        *,
        principal_hash: str,
        operation: str,
        idempotency_key: str,
        request_sha256: str,
        max_success_bytes: int | None = None,
        admission_hook: Callable[[], None] | None = None,
        now: float | None = None,
    ) -> DurableMediaRequestClaim:
        principal = _validated_digest(principal_hash, "principal_hash")
        request_digest = _validated_digest(request_sha256, "request_sha256")
        normalized_operation = _validated_operation(operation)
        key = validate_media_idempotency_key(idempotency_key)
        hashed_key = _key_hash(key)
        turn_id = _turn_id(principal, normalized_operation, hashed_key)
        current = self._validated_now(now)
        response_reservation = (
            self.max_response_bytes
            if max_success_bytes is None
            else max_success_bytes
        )
        if (
            isinstance(response_reservation, bool)
            or not isinstance(response_reservation, int)
            or not 64 <= response_reservation <= self.max_response_bytes
        ):
            raise ValueError("max_success_bytes is outside the durable response budget")
        if admission_hook is not None and not callable(admission_hook):
            raise ValueError("admission_hook must be callable")
        try:
            with self._read_transaction() as connection:
                existing = connection.execute(
                    "SELECT request_sha256,status,fencing_token,lease_expires_at,"
                    "attempt_count,provider_phase,response_json,"
                    "length(CAST(response_json AS BLOB)),reserved_response_bytes,"
                    "expires_at,turn_id FROM durable_media_requests "
                    "WHERE principal_hash=? AND operation=? AND key_hash=?",
                    (principal, normalized_operation, hashed_key),
                ).fetchone()
                if existing is not None:
                    local = self._claim_read_result(
                        existing,
                        expected_turn_id=turn_id,
                        request_digest=request_digest,
                        operation=normalized_operation,
                        current=current,
                    )
                    if local is not None:
                        return local
                admission = self._channel_admission_read_result(
                    connection,
                    principal_hash=principal,
                    operation=normalized_operation,
                    key_hash=hashed_key,
                    expected_turn_id=turn_id,
                    request_digest=request_digest,
                    allow_provider_phase=not (
                        existing is not None
                        and existing[1] == "processing"
                        and existing[5] == 1
                    ),
                )
                if admission is not None:
                    return admission
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot read durable media request"
            ) from exc
        token = secrets.token_hex(32)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT request_sha256,status,fencing_token,lease_expires_at,"
                    "attempt_count,provider_phase,response_json,"
                    "length(CAST(response_json AS BLOB)),reserved_response_bytes,"
                    "expires_at,turn_id "
                    "FROM durable_media_requests WHERE principal_hash=? "
                    "AND operation=? AND key_hash=?",
                    (principal, normalized_operation, hashed_key),
                ).fetchone()
                if row is not None:
                    local = self._claim_read_result(
                        row,
                        expected_turn_id=turn_id,
                        request_digest=request_digest,
                        operation=normalized_operation,
                        current=current,
                    )
                    if local is not None:
                        return local
                admission = self._channel_admission_read_result(
                    connection,
                    principal_hash=principal,
                    operation=normalized_operation,
                    key_hash=hashed_key,
                    expected_turn_id=turn_id,
                    request_digest=request_digest,
                    allow_provider_phase=not (
                        row is not None
                        and row[1] == "processing"
                        and row[5] == 1
                    ),
                )
                if admission is not None:
                    return admission
                # The first read transaction deliberately permits completed,
                # conflicting and in-flight local results while a peer
                # authority is read-only.  Only a path that can really mutate
                # this exact key crosses the peer admission fence, and it does
                # so before prune, expiry deletion, capacity accounting or
                # insertion can change SQLite.
                if admission_hook is not None:
                    admission_hook()
                self._prune(connection, current)
                # The bounded global prune may not reach this exact key when a
                # large expired backlog exists.  Expiry semantics for the key
                # being claimed must still be exact at the 30-day boundary.
                connection.execute(
                    "DELETE FROM durable_media_requests WHERE principal_hash=? "
                    "AND operation=? AND key_hash=? AND ((status<>'processing' "
                    "AND expires_at<=? AND NOT EXISTS(SELECT 1 FROM "
                    "durable_media_asset_authority a WHERE a.turn_id="
                    "durable_media_requests.turn_id AND a.state IN "
                    "('reserved','committed','acked_pending_cleanup'))) OR "
                    "(status='processing' "
                    "AND provider_phase=0 AND lease_expires_at+?<=? "
                    "AND NOT EXISTS(SELECT 1 FROM durable_media_asset_authority a "
                    "WHERE a.turn_id=durable_media_requests.turn_id)))",
                    (
                        principal,
                        normalized_operation,
                        hashed_key,
                        current,
                        self.retention_seconds,
                        current,
                    ),
                )
                row = connection.execute(
                    "SELECT request_sha256,status,fencing_token,lease_expires_at,"
                    "attempt_count,provider_phase,response_json,"
                    "length(CAST(response_json AS BLOB)),reserved_response_bytes,"
                    "expires_at,turn_id "
                    "FROM durable_media_requests WHERE principal_hash=? "
                    "AND operation=? AND key_hash=?",
                    (principal, normalized_operation, hashed_key),
                ).fetchone()
                if row is None:
                    count, response_bytes, reserved_bytes = self._meta_usage(connection)
                    if (
                        count >= self.max_records
                        or response_bytes
                        + reserved_bytes
                        + response_reservation
                        > self.max_total_response_bytes
                    ):
                        raise DurableMediaRequestUnavailable(
                            "durable media request capacity reached"
                        )
                    connection.execute(
                        "INSERT INTO durable_media_requests "
                        "(principal_hash,operation,key_hash,turn_id,request_sha256,status,"
                        "fencing_token,lease_expires_at,attempt_count,provider_phase,"
                        "response_json,reserved_response_bytes,created_at,updated_at,"
                        "expires_at) "
                        "VALUES(?,?,?,?,?,'processing',?,?,1,0,NULL,?,?,?,?)",
                        (
                            principal,
                            normalized_operation,
                            hashed_key,
                            turn_id,
                            request_digest,
                            token,
                            current + self.lease_seconds,
                            response_reservation,
                            current,
                            current,
                            current + self.retention_seconds,
                        ),
                    )
                    return DurableMediaRequestClaim(
                        state="claimed",
                        turn_id=turn_id,
                        fencing_token=token,
                        attempt=1,
                    )
                (
                    stored_request,
                    status,
                    lease_expires_at,
                    attempts,
                    provider_phase,
                    response,
                ) = self._validate_stored_row(row, expected_turn_id=turn_id)
                if stored_request != request_digest:
                    return DurableMediaRequestClaim(state="conflict", turn_id=turn_id)
                if status == "processing" and float(lease_expires_at) > current:
                    retry_after = max(1, int(float(lease_expires_at) - current + 0.999))
                    return DurableMediaRequestClaim(
                        state="processing",
                        turn_id=turn_id,
                        attempt=int(attempts),
                        retry_after_seconds=retry_after,
                    )
                if status == "processing" and int(provider_phase) == 0:
                    next_attempt = int(attempts) + 1
                    connection.execute(
                        "UPDATE durable_media_requests SET fencing_token=?,"
                        "lease_expires_at=?,attempt_count=?,updated_at=?,expires_at=?,"
                        "reserved_response_bytes=? "
                        "WHERE principal_hash=? AND operation=? AND key_hash=? "
                        "AND status='processing' AND provider_phase=0 "
                        "AND lease_expires_at<=?",
                        (
                            token,
                            current + self.lease_seconds,
                            next_attempt,
                            current,
                            current + self.retention_seconds,
                            response_reservation,
                            principal,
                            normalized_operation,
                            hashed_key,
                            current,
                        ),
                    )
                    if connection.execute("SELECT changes()").fetchone() != (1,):
                        raise sqlite3.DatabaseError(
                            "expired durable media claim changed concurrently"
                        )
                    return DurableMediaRequestClaim(
                        state="claimed",
                        turn_id=turn_id,
                        fencing_token=token,
                        attempt=next_attempt,
                    )
                if status == "processing" and int(provider_phase) == 1:
                    connection.execute(
                        "UPDATE durable_media_requests SET status='recovery_required',"
                        "fencing_token='',lease_expires_at=0,response_json=NULL,"
                        "reserved_response_bytes=0,updated_at=?,expires_at=? "
                        "WHERE principal_hash=? AND operation=? AND key_hash=? "
                        "AND status='processing' AND provider_phase=1 "
                        "AND lease_expires_at<=?",
                        (
                            current,
                            current + self.retention_seconds,
                            principal,
                            normalized_operation,
                            hashed_key,
                            current,
                        ),
                    )
                    if connection.execute("SELECT changes()").fetchone() != (1,):
                        raise sqlite3.DatabaseError(
                            "provider-phase recovery state changed concurrently"
                        )
                    return DurableMediaRequestClaim(
                        state="recovery_required",
                        turn_id=turn_id,
                        attempt=int(attempts),
                    )
                if status == "succeeded":
                    if normalized_operation == "videos.create":
                        try:
                            stored_document = json.loads(str(row[6]))
                        except (TypeError, ValueError, RecursionError) as exc:
                            raise sqlite3.DatabaseError(
                                "durable legacy video response is corrupt"
                            ) from exc
                        if not (
                            isinstance(stored_document, dict)
                            and set(stored_document) == {"response", "video_task"}
                        ):
                            # Pre-registry rows contain an upstream task id but
                            # no frozen route/credential evidence.  Never leak
                            # or auto-poll that id after upgrade; expose only a
                            # deterministic local alias and conservatively keep
                            # capacity occupied until retention/manual recovery.
                            response = {
                                "task_id": _video_task_alias(turn_id),
                                "status": "legacy_recovery_required",
                            }
                    return DurableMediaRequestClaim(
                        state="succeeded",
                        turn_id=turn_id,
                        attempt=int(attempts),
                        response=response,
                    )
                if status == "recovery_required":
                    return DurableMediaRequestClaim(
                        state="recovery_required",
                        turn_id=turn_id,
                        attempt=int(attempts),
                    )
                raise sqlite3.DatabaseError("unhandled durable media request state")
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot claim durable media request"
            ) from exc

    def reserve_asset_capacity(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        principal_hash: str,
        operation: str,
        installation_epoch: int,
        reserved_bytes: int = _ASSET_OPERATION_RESERVATION_BYTES,
    ) -> bool:
        """Persist the Root-anchored logical closure before provider admission."""

        turn = _validated_digest(turn_id, "turn_id")
        token = _validated_digest(fencing_token, "fencing_token")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("installation_epoch must be a positive integer")
        if reserved_bytes != _ASSET_OPERATION_RESERVATION_BYTES:
            raise ValueError("paid-media asset reservation closure is invalid")
        try:
            with self._write_transaction() as connection:
                request = connection.execute(
                    "SELECT principal_hash,operation,status,provider_phase,fencing_token "
                    "FROM durable_media_requests WHERE turn_id=?",
                    (turn,),
                ).fetchone()
                if request != (
                    principal,
                    normalized_operation,
                    "processing",
                    0,
                    token,
                ):
                    return False
                existing = connection.execute(
                    "SELECT principal_hash,operation,installation_epoch,state,"
                    "reserved_bytes,token_set_digest,archive_receipt_sha256,acked_at "
                    "FROM durable_media_asset_authority WHERE turn_id=?",
                    (turn,),
                ).fetchone()
                expected = (
                    principal,
                    normalized_operation,
                    installation_epoch,
                    "reserved",
                    reserved_bytes,
                    None,
                    None,
                    None,
                )
                if existing is not None:
                    return tuple(existing) == expected
                connection.execute(
                    "INSERT INTO durable_media_asset_authority "
                    "(turn_id,principal_hash,operation,installation_epoch,state,"
                    "reserved_bytes,token_set_digest,archive_receipt_sha256,acked_at) "
                    "VALUES(?,?,?,?,'reserved',?,NULL,NULL,NULL)",
                    (
                        turn,
                        principal,
                        normalized_operation,
                        installation_epoch,
                        reserved_bytes,
                    ),
                )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot reserve durable paid-media asset capacity"
            ) from exc

    def enter_provider_phase(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        max_success_bytes: int | None = None,
        now: float | None = None,
    ) -> bool:
        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        response_reservation = (
            self.max_response_bytes
            if max_success_bytes is None
            else max_success_bytes
        )
        if (
            isinstance(response_reservation, bool)
            or not isinstance(response_reservation, int)
            or not 64 <= response_reservation <= self.max_response_bytes
        ):
            raise ValueError("max_success_bytes is outside the durable response budget")
        try:
            with self._write_transaction() as connection:
                current = self._validated_now(now)
                row = connection.execute(
                    "SELECT principal_hash,operation,key_hash,request_sha256,"
                    "attempt_count,reserved_response_bytes "
                    "FROM durable_media_requests "
                    "WHERE turn_id=? AND status='processing' AND provider_phase=0 "
                    "AND fencing_token=? AND lease_expires_at>?",
                    (normalized_turn, normalized_token, current),
                ).fetchone()
                if row is None:
                    return False
                reserved = row[5]
                if (
                    not isinstance(reserved, int)
                    or isinstance(reserved, bool)
                    or not 64 <= int(reserved) <= self.max_response_bytes
                ):
                    raise sqlite3.DatabaseError(
                        "durable media response reservation is invalid"
                    )
                expansion = response_reservation - int(reserved)
                if expansion > 0:
                    _count, response_bytes, reserved_bytes = self._meta_usage(connection)
                    if (
                        response_bytes + reserved_bytes + expansion
                        > self.max_total_response_bytes
                    ):
                        raise sqlite3.DatabaseError(
                            "durable media response capacity cannot be expanded before provider"
                        )
                if self._schema_profile == _CHANNEL_MEDIA_SCHEMA_PROFILE:
                    admission_count = connection.execute(
                        "SELECT COUNT(*) FROM durable_channel_media_admissions"
                    ).fetchone()
                    if (
                        admission_count is None
                        or not isinstance(admission_count[0], int)
                        or isinstance(admission_count[0], bool)
                        or int(admission_count[0]) < 0
                    ):
                        raise sqlite3.DatabaseError(
                            "durable channel media admission count is invalid"
                        )
                    if int(admission_count[0]) >= self.max_records:
                        raise DurableMediaRequestUnavailable(
                            "durable channel media admission capacity reached"
                        )
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET provider_phase=1,updated_at=?,"
                    "reserved_response_bytes=? "
                    "WHERE turn_id=? AND status='processing' AND provider_phase=0 "
                    "AND fencing_token=? AND lease_expires_at>? "
                    "AND reserved_response_bytes=?",
                    (
                        current,
                        response_reservation,
                        normalized_turn,
                        normalized_token,
                        current,
                        int(reserved),
                    ),
                )
                if cursor.rowcount != 1:
                    return False
                if self._schema_profile == _CHANNEL_MEDIA_SCHEMA_PROFILE:
                    connection.execute(
                        "INSERT INTO durable_channel_media_admissions "
                        "(principal_hash,operation,key_hash,turn_id,request_sha256,"
                        "state,attempt_count,provider_entered_at,updated_at) "
                        "VALUES(?,?,?,?,?,'provider_phase',?,?,?)",
                        (
                            str(row[0]),
                            str(row[1]),
                            str(row[2]),
                            normalized_turn,
                            str(row[3]),
                            int(row[4]),
                            current,
                            current,
                        ),
                    )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot enter durable media provider phase"
            ) from exc

    def renew_claim(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        now: float | None = None,
    ) -> bool:
        """Extend one live request lease without changing provider phase.

        Policy time is sampled only after the SQLite write transaction owns
        its lock.  A worker waiting behind another writer therefore cannot use
        a stale pre-wait clock value to resurrect an already expired claim.
        """

        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        try:
            with self._write_transaction() as connection:
                current = self._validated_now(now)
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET lease_expires_at=?,"
                    "updated_at=?,expires_at=? WHERE turn_id=? "
                    "AND status='processing' AND fencing_token=? "
                    "AND lease_expires_at>?",
                    (
                        current + self.lease_seconds,
                        current,
                        current + self.retention_seconds,
                        normalized_turn,
                        normalized_token,
                        current,
                    ),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot renew durable media request lease"
            ) from exc

    def abandon_pre_provider(
        self,
        *,
        turn_id: str,
        fencing_token: str,
    ) -> bool:
        """Release a known-unused claim without ever touching provider phase."""

        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        try:
            with self._write_transaction() as connection:
                cursor = connection.execute(
                    "DELETE FROM durable_media_requests WHERE turn_id=? "
                    "AND status='processing' AND provider_phase=0 "
                    "AND fencing_token=?",
                    (normalized_turn, normalized_token),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot abandon pre-provider media request"
            ) from exc

    def abandon_fenced_before_invocation(
        self,
        *,
        turn_id: str,
        fencing_token: str,
    ) -> bool:
        """Delete a phase-1 claim only when the caller proves no invocation began.

        This deliberately is not a retry transition.  Its only caller drains
        the exact `enter_provider_phase` worker after cancellation, releases
        the private mirror first, and then permanently abandons this claim.
        """

        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        try:
            with self._write_transaction() as connection:
                cursor = connection.execute(
                    "DELETE FROM durable_media_requests WHERE turn_id=? "
                    "AND status='processing' AND provider_phase=1 "
                    "AND fencing_token=? AND response_json IS NULL",
                    (normalized_turn, normalized_token),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot abandon fenced media request before invocation"
            ) from exc

    def succeed(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        response: dict[str, object],
        now: float | None = None,
    ) -> bool:
        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        if not isinstance(response, dict):
            raise ValueError("successful response must be an object")
        asset_result = None
        if response.get("schema") == PAID_MEDIA_ASSET_RESULT_SCHEMA:
            asset_result = parse_asset_result(response)
            if asset_result.turn_id != normalized_turn:
                raise ValueError("paid-media asset success turn does not match claim")
            # The protocol owns the tighter one-MiB ceiling even when an older
            # ledger was provisioned with a larger compatibility budget.
            canonical_asset_result(asset_result)
        try:
            encoded = json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("successful response must be bounded JSON") from exc
        if len(encoded.encode("utf-8")) > self.max_response_bytes:
            raise ValueError("successful response exceeds durable storage limit")
        expected_operation = (
            None
            if asset_result is None
            else "images.create" if asset_result.kind == "image" else "videos.create"
        )
        asset_token_set_digest = (
            None
            if asset_result is None
            else canonical_token_set_digest(
                [asset.token for asset in asset_result.assets]
            )
        )
        try:
            with self._write_transaction() as connection:
                current = self._validated_now(now)
                expires_at = (
                    _ASSET_SUCCESS_UNACKED_EXPIRES_AT
                    if asset_result is not None
                    else current + self.retention_seconds
                )
                authority = connection.execute(
                    "SELECT a.principal_hash,a.operation,a.state,a.reserved_bytes,"
                    "r.operation FROM durable_media_asset_authority a "
                    "JOIN durable_media_requests r ON r.turn_id=a.turn_id "
                    "WHERE a.turn_id=? AND r.status='processing' "
                    "AND r.provider_phase=1 AND r.fencing_token=?",
                    (normalized_turn, normalized_token),
                ).fetchone()
                if authority is not None and asset_result is None:
                    raise sqlite3.DatabaseError(
                        "reserved paid-media asset turn cannot persist a legacy success"
                    )
                if expected_operation is not None and (
                    authority is None
                    or authority[1] != expected_operation
                    or authority[2:] != (
                        "reserved",
                        _ASSET_OPERATION_RESERVATION_BYTES,
                        expected_operation,
                    )
                ):
                    raise sqlite3.DatabaseError(
                        "paid-media asset success lacks durable reservation authority"
                    )
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET status='succeeded',"
                    "fencing_token='',lease_expires_at=0,response_json=?,"
                    "reserved_response_bytes=0,updated_at=?,expires_at=? WHERE turn_id=? "
                    "AND status='processing' AND provider_phase=1 "
                    "AND fencing_token=? AND lease_expires_at>?",
                    (
                        encoded,
                        current,
                        expires_at,
                        normalized_turn,
                        normalized_token,
                        current,
                    ),
                )
                if cursor.rowcount != 1:
                    return False
                if expected_operation is not None:
                    cursor = connection.execute(
                        "UPDATE durable_media_asset_authority SET state='committed',"
                        "token_set_digest=? WHERE turn_id=? AND state='reserved' "
                        "AND operation=? AND reserved_bytes=?",
                        (
                            asset_token_set_digest,
                            normalized_turn,
                            expected_operation,
                            _ASSET_OPERATION_RESERVATION_BYTES,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.DatabaseError(
                            "paid-media asset success authority changed concurrently"
                        )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable media response"
            ) from exc

    def read_success_document(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        operation: str,
    ) -> DurableMediaSuccessDocument | None:
        """Re-read one exact immutable success row; sidecars never authorize."""

        turn = _validated_digest(turn_id, "turn_id")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        try:
            with self._read_transaction() as connection:
                row = connection.execute(
                    "SELECT status,provider_phase,response_json,"
                    "length(CAST(response_json AS BLOB)),turn_id,principal_hash,operation "
                    "FROM durable_media_requests WHERE turn_id=? AND principal_hash=? "
                    "AND operation=?",
                    (turn, principal, normalized_operation),
                ).fetchone()
                if row is None:
                    return None
                if (
                    row[0] != "succeeded"
                    or row[1] != 1
                    or row[4:] != (turn, principal, normalized_operation)
                ):
                    return None
                response = self._decode_response(row[2], row[3])
                return DurableMediaSuccessDocument(
                    principal_hash=principal,
                    operation=normalized_operation,
                    turn_id=turn,
                    response=response,
                )
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot re-read durable media success authority"
            ) from exc

    def read_unacked_asset_success_document(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        operation: str,
    ) -> DurableMediaSuccessDocument | None:
        """Return only a v2 success whose Root-anchored ACK state is unacked."""

        turn = _validated_digest(turn_id, "turn_id")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        try:
            with self._read_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.token_set_digest,a.state FROM durable_media_requests r "
                    "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? AND r.operation=? "
                    "AND r.status='succeeded' AND r.provider_phase=1 "
                    "AND a.principal_hash=r.principal_hash AND a.operation=r.operation "
                    "AND a.state='committed'",
                    (turn, principal, normalized_operation),
                ).fetchone()
                if row is None:
                    return None
                response = self._decode_asset_authority_response(
                    row[0],
                    row[1],
                    turn_id=turn,
                    operation=normalized_operation,
                )
                parsed = parse_asset_result(response)
                expected_operation = (
                    "images.create" if parsed.kind == "image" else "videos.create"
                )
                expected_tokens = canonical_token_set_digest(
                    [asset.token for asset in parsed.assets]
                )
                if (
                    parsed.turn_id != turn
                    or expected_operation != normalized_operation
                    or row[2] != expected_tokens
                    or row[3] != "committed"
                ):
                    raise sqlite3.DatabaseError(
                        "durable paid-media unacked authority is corrupt"
                    )
                return DurableMediaSuccessDocument(
                    principal_hash=principal,
                    operation=normalized_operation,
                    turn_id=turn,
                    response=response,
                )
        except PaidMediaAssetProtocolError as exc:
            raise DurableMediaRequestUnavailable(
                "durable paid-media unacked authority is corrupt"
            ) from exc
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot read unacked paid-media success authority"
            ) from exc

    def read_asset_success_document(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        operation: str,
    ) -> DurableMediaSuccessDocument | None:
        """Read immutable asset authority in any committed ACK phase."""

        turn = _validated_digest(turn_id, "turn_id")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        try:
            with self._read_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.token_set_digest,a.state FROM durable_media_requests r "
                    "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? AND r.operation=? "
                    "AND r.status='succeeded' AND r.provider_phase=1 "
                    "AND a.principal_hash=r.principal_hash AND a.operation=r.operation "
                    "AND a.state IN ('committed','acked_pending_cleanup','acked')",
                    (turn, principal, normalized_operation),
                ).fetchone()
                if row is None:
                    return None
                response = self._decode_asset_authority_response(
                    row[0],
                    row[1],
                    turn_id=turn,
                    operation=normalized_operation,
                )
                parsed = parse_asset_result(response)
                expected_operation = (
                    "images.create" if parsed.kind == "image" else "videos.create"
                )
                expected_tokens = canonical_token_set_digest(
                    [asset.token for asset in parsed.assets]
                )
                if (
                    parsed.turn_id != turn
                    or expected_operation != normalized_operation
                    or row[2] != expected_tokens
                    or row[3]
                    not in {"committed", "acked_pending_cleanup", "acked"}
                ):
                    raise sqlite3.DatabaseError(
                        "durable paid-media asset authority is corrupt"
                    )
                return DurableMediaSuccessDocument(
                    principal_hash=principal,
                    operation=normalized_operation,
                    turn_id=turn,
                    response=response,
                )
        except PaidMediaAssetProtocolError as exc:
            raise DurableMediaRequestUnavailable(
                "durable paid-media asset authority is corrupt"
            ) from exc
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot read paid-media asset success authority"
            ) from exc

    def ack_asset_success(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        operation: str,
        installation_epoch: int,
        tokens: list[str] | tuple[str, ...],
        archive_receipt_sha256: str,
        now: float | None = None,
    ) -> DurableMediaAssetAckReceipt:
        """Root-anchored full-set ACK CAS; exact repeats are the only replay."""

        turn = _validated_digest(turn_id, "turn_id")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("installation_epoch must be a positive integer")
        archive_digest = _validated_digest(
            archive_receipt_sha256, "archive_receipt_sha256"
        )
        token_set_digest = canonical_token_set_digest(tokens)
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.installation_epoch,a.state,a.reserved_bytes,a.token_set_digest,"
                    "a.archive_receipt_sha256 FROM durable_media_requests r "
                    "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? AND r.operation=? "
                    "AND r.status='succeeded' AND r.provider_phase=1 "
                    "AND a.principal_hash=r.principal_hash AND a.operation=r.operation",
                    (turn, principal, normalized_operation),
                ).fetchone()
                if row is None:
                    raise DurableMediaAssetConflict(
                        "paid-media ACK success authority is unavailable"
                    )
                response = self._decode_asset_authority_response(
                    row[0],
                    row[1],
                    turn_id=turn,
                    operation=normalized_operation,
                )
                parsed = parse_asset_result(response)
                expected_operation = (
                    "images.create" if parsed.kind == "image" else "videos.create"
                )
                expected_token_digest = canonical_token_set_digest(
                    [asset.token for asset in parsed.assets]
                )
                if (
                    parsed.turn_id != turn
                    or expected_operation != normalized_operation
                    or row[5] != expected_token_digest
                ):
                    raise sqlite3.DatabaseError(
                        "paid-media ACK durable success authority is corrupt"
                    )
                if (
                    row[2] != installation_epoch
                    or token_set_digest != expected_token_digest
                ):
                    raise DurableMediaAssetConflict(
                        "paid-media ACK conflicts with durable success"
                    )
                if row[3] in {"acked_pending_cleanup", "acked"}:
                    expected_reserved = (
                        0
                        if row[3] == "acked"
                        else _ASSET_OPERATION_RESERVATION_BYTES
                    )
                    if row[4] != expected_reserved or row[6] != archive_digest:
                        raise DurableMediaAssetConflict(
                            "paid-media ACK conflicts with durable receipt"
                        )
                    return DurableMediaAssetAckReceipt(
                        turn_id=turn,
                        principal_hash=principal,
                        operation=normalized_operation,
                        installation_epoch=installation_epoch,
                        token_set_digest=token_set_digest,
                        archive_receipt_sha256=archive_digest,
                        replayed=True,
                        cleanup_complete=row[3] == "acked",
                    )
                if row[3] != "committed" or row[4] != _ASSET_OPERATION_RESERVATION_BYTES:
                    raise DurableMediaAssetConflict(
                        "paid-media ACK state is not committable"
                    )
                cursor = connection.execute(
                    "UPDATE durable_media_asset_authority "
                    "SET state='acked_pending_cleanup',"
                    "archive_receipt_sha256=?,acked_at=? "
                    "WHERE turn_id=? AND principal_hash=? AND operation=? "
                    "AND installation_epoch=? AND state='committed' "
                    "AND reserved_bytes=? AND token_set_digest=?",
                    (
                        archive_digest,
                        current,
                        turn,
                        principal,
                        normalized_operation,
                        installation_epoch,
                        _ASSET_OPERATION_RESERVATION_BYTES,
                        token_set_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DurableMediaAssetConflict(
                        "paid-media ACK changed concurrently"
                    )
                return DurableMediaAssetAckReceipt(
                    turn_id=turn,
                    principal_hash=principal,
                    operation=normalized_operation,
                    installation_epoch=installation_epoch,
                    token_set_digest=token_set_digest,
                    archive_receipt_sha256=archive_digest,
                    replayed=False,
                    cleanup_complete=False,
                )
        except PaidMediaAssetProtocolError as exc:
            raise DurableMediaRequestUnavailable(
                "durable paid-media ACK document is invalid"
            ) from exc
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable paid-media ACK authority"
            ) from exc

    def complete_asset_ack_cleanup(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        operation: str,
        installation_epoch: int,
        token_set_digest: str,
        archive_receipt_sha256: str,
        now: float | None = None,
    ) -> bool:
        """Release Root capacity only after lease drain and byte cleanup succeeded."""

        turn = _validated_digest(turn_id, "turn_id")
        principal = _validated_digest(principal_hash, "principal_hash")
        normalized_operation = _validated_operation(operation)
        token_digest = _validated_digest(token_set_digest, "token_set_digest")
        archive_digest = _validated_digest(
            archive_receipt_sha256, "archive_receipt_sha256"
        )
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("installation_epoch must be a positive integer")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT state,reserved_bytes,token_set_digest,"
                    "archive_receipt_sha256 FROM durable_media_asset_authority "
                    "WHERE turn_id=? AND principal_hash=? AND operation=? "
                    "AND installation_epoch=?",
                    (turn, principal, normalized_operation, installation_epoch),
                ).fetchone()
                if row == ("acked", 0, token_digest, archive_digest):
                    return True
                if row != (
                    "acked_pending_cleanup",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                    token_digest,
                    archive_digest,
                ):
                    return False
                cursor = connection.execute(
                    "UPDATE durable_media_asset_authority SET state='acked',"
                    "reserved_bytes=0 WHERE turn_id=? AND principal_hash=? "
                    "AND operation=? AND installation_epoch=? "
                    "AND state='acked_pending_cleanup' AND reserved_bytes=? "
                    "AND token_set_digest=? AND archive_receipt_sha256=?",
                    (
                        turn,
                        principal,
                        normalized_operation,
                        installation_epoch,
                        _ASSET_OPERATION_RESERVATION_BYTES,
                        token_digest,
                        archive_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    return False
                connection.execute(
                    "UPDATE durable_media_requests SET expires_at=?,updated_at=? "
                    "WHERE turn_id=? AND principal_hash=? AND operation=? "
                    "AND status='succeeded' AND provider_phase=1",
                    (
                        current + self.retention_seconds,
                        current,
                        turn,
                        principal,
                        normalized_operation,
                    ),
                )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot complete durable paid-media ACK cleanup"
            ) from exc

    def succeed_video(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        principal_hash: str,
        response: dict[str, object],
        requested_model: str,
        provider_name: str,
        provider_domain: str,
        provider_credential_domain: str,
        upstream_model: str,
        upstream_task_id: str,
        terminal: bool,
        terminal_asset_response: dict[str, object] | None = None,
        prepared_provider_response: dict[str, object] | None = None,
        now: float | None = None,
    ) -> tuple[bool, dict[str, object]]:
        """Persist the create receipt and its owner-bound frozen poll route atomically."""

        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        principal = _validated_digest(principal_hash, "principal_hash")
        requested = _validated_video_route_text(requested_model, "requested_model")
        provider = _validated_video_route_text(provider_name, "provider_name")
        domain = _validated_digest(provider_domain, "provider_domain")
        credential_domain = _validated_digest(
            provider_credential_domain, "provider_credential_domain"
        )
        upstream = _validated_video_route_text(upstream_model, "upstream_model")
        provider_task = _validated_video_route_text(upstream_task_id, "upstream_task_id")
        if not isinstance(response, dict) or not isinstance(terminal, bool):
            raise ValueError("successful video response is invalid")
        parsed_terminal_asset = None
        terminal_asset_document: dict[str, object] | None = None
        terminal_token_digest: str | None = None
        if terminal_asset_response is not None:
            parsed_terminal_asset = parse_asset_result(terminal_asset_response)
            if (
                not terminal
                or parsed_terminal_asset.kind != "video"
                or parsed_terminal_asset.turn_id != normalized_turn
            ):
                raise ValueError("terminal video asset result does not match create")
            terminal_asset_document = json.loads(
                canonical_asset_result(parsed_terminal_asset)
            )
            terminal_token_digest = canonical_token_set_digest(
                [asset.token for asset in parsed_terminal_asset.assets]
            )
        task_alias = _video_task_alias(normalized_turn)
        prepared_token = ""
        prepared_provider_document: dict[str, object] | None = None
        prepared_sha256 = ""
        if prepared_provider_response is not None:
            if terminal or terminal_asset_response is not None:
                raise ValueError(
                    "prepared video create receipt cannot already be terminal"
                )
            prepared_token = create_asset_token()
            (
                prepared_provider_document,
                _prepared_asset,
                prepared_sha256,
            ) = _prepared_video_material(
                task_alias=task_alias,
                token=prepared_token,
                provider_response=prepared_provider_response,
                asset_response=None,
            )
            if prepared_provider_document != response:
                raise ValueError(
                    "prepared video provider receipt does not match create response"
                )
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                authority = connection.execute(
                    "SELECT principal_hash,operation,state,reserved_bytes "
                    "FROM durable_media_asset_authority WHERE turn_id=?",
                    (normalized_turn,),
                ).fetchone()
                authoritative = authority is not None
                if authoritative and authority != (
                    principal,
                    "videos.create",
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                ):
                    raise sqlite3.DatabaseError(
                        "video create asset reservation authority is invalid"
                    )
                if not authoritative and terminal_asset_document is not None:
                    raise sqlite3.DatabaseError(
                        "terminal video asset result lacks reservation authority"
                    )
                if not authoritative and prepared_provider_document is not None:
                    raise sqlite3.DatabaseError(
                        "prepared video receipt lacks reservation authority"
                    )

                if authoritative:
                    public_response = {
                        "task_id": task_alias,
                        "status": "processing",
                    }
                    if terminal_asset_document is not None:
                        terminal_response = terminal_asset_document
                        expires_at = _ASSET_SUCCESS_UNACKED_EXPIRES_AT
                    elif terminal and _is_video_terminal_failure(response):
                        terminal_response = _safe_video_status_response(
                            response, task_alias
                        )
                        expires_at = _ASSET_SUCCESS_UNACKED_EXPIRES_AT
                    elif terminal:
                        raise sqlite3.DatabaseError(
                            "successful terminal video lacks private asset result"
                        )
                    else:
                        terminal_response = None
                        expires_at = current + self.retention_seconds
                    last_response = terminal_response
                else:
                    public_response = _aliased_video_response(response, task_alias)
                    terminal_response = (
                        dict(public_response) if terminal else None
                    )
                    last_response = terminal_response
                    expires_at = current + self.retention_seconds

                metadata: dict[str, object] = {
                    "version": _VIDEO_ENVELOPE_VERSION,
                    "task_alias": task_alias,
                    "requested_model": requested,
                    "provider_name": provider,
                    "provider_domain": domain,
                    "provider_credential_domain": credential_domain,
                    "upstream_model": upstream,
                    "upstream_task_id": provider_task,
                    "poll_attempt": 0,
                    "poll_fencing_token": "",
                    "poll_lease_expires_at": 0.0,
                    "next_poll_at": 0.0,
                    "last_response": last_response,
                    "terminal_response": terminal_response,
                    "prepared_token": prepared_token,
                    "prepared_provider_response": prepared_provider_document,
                    "prepared_asset_response": None,
                    "prepare_sha256": prepared_sha256,
                }
                encoded = self._encode_video_envelope(public_response, metadata)
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET status='succeeded',"
                    "fencing_token='',lease_expires_at=0,response_json=?,"
                    "reserved_response_bytes=0,updated_at=?,expires_at=? WHERE turn_id=? "
                    "AND principal_hash=? AND operation='videos.create' "
                    "AND status='processing' AND provider_phase=1 AND fencing_token=?",
                    (
                        encoded,
                        current,
                        expires_at,
                        normalized_turn,
                        principal,
                        normalized_token,
                    ),
                )
                if cursor.rowcount != 1:
                    return False, public_response
                if authoritative and terminal_asset_document is not None:
                    cursor = connection.execute(
                        "UPDATE durable_media_asset_authority SET state='committed',"
                        "token_set_digest=? WHERE turn_id=? AND state='reserved' "
                        "AND operation='videos.create' AND reserved_bytes=?",
                        (
                            terminal_token_digest,
                            normalized_turn,
                            _ASSET_OPERATION_RESERVATION_BYTES,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.DatabaseError(
                            "terminal video asset authority changed concurrently"
                        )
                return True, public_response
        except PaidMediaAssetProtocolError as exc:
            raise ValueError("terminal video asset result is invalid") from exc
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable video task registry"
            ) from exc

    def _video_poll_read_result(
        self,
        row: tuple[Any, ...] | None,
        *,
        task_alias: str,
        turn_id: str,
        principal: str,
        current: float,
    ) -> DurableVideoPollClaim | None:
        if (
            row is None
            or row[0] != principal
            or row[1] != "videos.create"
            or row[2] != "succeeded"
        ):
            return DurableVideoPollClaim(state="not_found", task_alias=task_alias)
        _response, metadata = self._decode_video_envelope(
            row[3], row[4], expected_turn_id=turn_id
        )
        terminal_response = metadata.get("terminal_response")
        if isinstance(terminal_response, dict):
            return DurableVideoPollClaim(
                state="terminal",
                task_alias=task_alias,
                response=dict(terminal_response),
            )
        lease_expires_at = float(metadata["poll_lease_expires_at"])
        next_poll_at = float(metadata["next_poll_at"])
        if lease_expires_at > current or next_poll_at > current:
            retry_at = max(lease_expires_at, next_poll_at)
            cached = metadata.get("last_response")
            response_value = (
                dict(cached)
                if isinstance(cached, dict)
                else {"status": "processing", "task_id": task_alias}
            )
            return DurableVideoPollClaim(
                state="deferred",
                task_alias=task_alias,
                retry_after_seconds=max(1, int(math.ceil(retry_at - current))),
                response=response_value,
            )
        return None

    def _prepared_video_operator_material(
        self,
        row: tuple[Any, ...] | None,
        *,
        task_alias: str,
        turn_id: str,
        principal: str,
        installation_epoch: int,
        current: float,
    ) -> tuple[
        dict[str, object],
        dict[str, object] | None,
        dict[str, object],
        DurablePreparedVideoRecoverySnapshot,
    ]:
        """Validate the exact prepared-only state shared by inspect and claim."""

        if (
            row is None
            or row[0] != "succeeded"
            or row[1] != 1
            or row[4:] != (
                principal,
                "videos.create",
                installation_epoch,
                "reserved",
                _ASSET_OPERATION_RESERVATION_BYTES,
            )
        ):
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            )
        _create_response, metadata = self._decode_video_envelope(
            row[2],
            row[3],
            expected_turn_id=turn_id,
        )
        metadata = self._video_metadata_v2(metadata)
        if (
            isinstance(metadata.get("terminal_response"), dict)
            or float(metadata["poll_lease_expires_at"]) > current
            or float(metadata["next_poll_at"]) > current
        ):
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            )
        prepared_token = str(metadata.get("prepared_token") or "")
        prepared_provider = metadata.get("prepared_provider_response")
        if not prepared_token or not isinstance(prepared_provider, dict):
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            )
        try:
            normalized_provider, normalized_asset, prepare_sha256 = (
                _prepared_video_material(
                    task_alias=task_alias,
                    token=prepared_token,
                    provider_response=prepared_provider,
                    asset_response=metadata.get("prepared_asset_response"),
                )
            )
        except ValueError as exc:
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            ) from exc
        if not hmac.compare_digest(
            str(metadata.get("prepare_sha256") or ""),
            prepare_sha256,
        ):
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            )
        snapshot = DurablePreparedVideoRecoverySnapshot(
            candidate_sha256=_prepared_video_operator_candidate_digest(
                task_alias=task_alias,
                principal_hash=principal,
                installation_epoch=installation_epoch,
                prepare_sha256=prepare_sha256,
            ),
            prepare_sha256=prepare_sha256,
        )
        return normalized_provider, normalized_asset, metadata, snapshot

    def inspect_prepared_video_recovery(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        installation_epoch: int,
        now: float | None = None,
    ) -> DurablePreparedVideoRecoverySnapshot:
        """Read one prepared candidate without taking a poll/provider lease."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("installation_epoch must be a positive integer")
        current = self._validated_now(now)
        try:
            with self._read_transaction() as connection:
                row = connection.execute(
                    "SELECT r.status,r.provider_phase,r.response_json,"
                    "length(CAST(r.response_json AS BLOB)),a.principal_hash,"
                    "a.operation,a.installation_epoch,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r "
                    "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create'",
                    (turn_id, principal),
                ).fetchone()
                return self._prepared_video_operator_material(
                    row,
                    task_alias=task_alias,
                    turn_id=turn_id,
                    principal=principal,
                    installation_epoch=installation_epoch,
                    current=current,
                )[3]
        except DurableMediaRequestUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            ) from exc

    def claim_prepared_video_recovery(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        installation_epoch: int,
        expected_candidate_sha256: str,
        now: float | None = None,
    ) -> DurablePreparedVideoRecoveryClaim:
        """Claim only a pre-existing prepared result; no provider state exists."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        expected = _validated_digest(
            expected_candidate_sha256,
            "expected_candidate_sha256",
        )
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("installation_epoch must be a positive integer")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.status,r.provider_phase,r.response_json,"
                    "length(CAST(r.response_json AS BLOB)),a.principal_hash,"
                    "a.operation,a.installation_epoch,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r "
                    "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create'",
                    (turn_id, principal),
                ).fetchone()
                prepared_provider, prepared_asset, metadata, snapshot = (
                    self._prepared_video_operator_material(
                        row,
                        task_alias=task_alias,
                        turn_id=turn_id,
                        principal=principal,
                        installation_epoch=installation_epoch,
                        current=current,
                    )
                )
                if not hmac.compare_digest(snapshot.candidate_sha256, expected):
                    raise DurableMediaRequestUnavailable(
                        "prepared video operator recovery changed after inspection"
                    )
                fencing_token = secrets.token_hex(32)
                updated_metadata = dict(metadata)
                updated_metadata.update(
                    {
                        "poll_attempt": int(metadata["poll_attempt"]) + 1,
                        "poll_fencing_token": fencing_token,
                        "poll_lease_expires_at": current
                        + _VIDEO_POLL_LEASE_SECONDS,
                        "next_poll_at": 0.0,
                    }
                )
                create_response, _old_metadata = self._decode_video_envelope(
                    row[2],
                    row[3],
                    expected_turn_id=turn_id,
                )
                encoded = self._encode_video_envelope(
                    create_response,
                    updated_metadata,
                )
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,"
                    "updated_at=?,expires_at=? WHERE turn_id=? "
                    "AND principal_hash=? AND operation='videos.create' "
                    "AND status='succeeded' AND provider_phase=1",
                    (
                        encoded,
                        current,
                        current + self.retention_seconds,
                        turn_id,
                        principal,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "prepared video operator recovery changed concurrently"
                    )
                return DurablePreparedVideoRecoveryClaim(
                    task_alias=task_alias,
                    fencing_token=fencing_token,
                    prepared_token=str(updated_metadata["prepared_token"]),
                    prepared_provider_response=dict(prepared_provider),
                    prepared_asset_response=(
                        dict(prepared_asset)
                        if isinstance(prepared_asset, dict)
                        else None
                    ),
                    prepare_sha256=snapshot.prepare_sha256,
                    candidate_sha256=snapshot.candidate_sha256,
                )
        except DurableMediaRequestUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "prepared video operator recovery is unavailable"
            ) from exc

    def begin_video_poll(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        now: float | None = None,
    ) -> DurableVideoPollClaim:
        """Authorize one poll and durably fence concurrent/provider-hammering reads."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        current = self._validated_now(now)
        try:
            with self._read_transaction() as connection:
                existing = connection.execute(
                    "SELECT principal_hash,operation,status,response_json,"
                    "length(CAST(response_json AS BLOB)) "
                    "FROM durable_media_requests WHERE turn_id=?",
                    (turn_id,),
                ).fetchone()
                local = self._video_poll_read_result(
                    existing,
                    task_alias=task_alias,
                    turn_id=turn_id,
                    principal=principal,
                    current=current,
                )
                if local is not None:
                    return local
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT principal_hash,operation,status,response_json,"
                    "length(CAST(response_json AS BLOB)) "
                    "FROM durable_media_requests WHERE turn_id=?",
                    (turn_id,),
                ).fetchone()
                local = self._video_poll_read_result(
                    row,
                    task_alias=task_alias,
                    turn_id=turn_id,
                    principal=principal,
                    current=current,
                )
                if local is not None:
                    return local
                self._prune(connection, current)
                row = connection.execute(
                    "SELECT principal_hash,operation,status,response_json,"
                    "length(CAST(response_json AS BLOB)) "
                    "FROM durable_media_requests WHERE turn_id=?",
                    (turn_id,),
                ).fetchone()
                local = self._video_poll_read_result(
                    row,
                    task_alias=task_alias,
                    turn_id=turn_id,
                    principal=principal,
                    current=current,
                )
                if local is not None:
                    return local
                response, metadata = self._decode_video_envelope(
                    row[3], row[4], expected_turn_id=turn_id
                )
                token = secrets.token_hex(32)
                attempt = int(metadata["poll_attempt"]) + 1
                updated_metadata = self._video_metadata_v2(metadata)
                updated_metadata.update(
                    {
                        "poll_attempt": attempt,
                        "poll_fencing_token": token,
                        "poll_lease_expires_at": current + _VIDEO_POLL_LEASE_SECONDS,
                        "next_poll_at": 0.0,
                    }
                )
                encoded = self._encode_video_envelope(response, updated_metadata)
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,updated_at=?,"
                    "expires_at=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        encoded,
                        current,
                        current + self.retention_seconds,
                        turn_id,
                        principal,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError("durable video poll ownership changed")
                prepared_token = str(
                    updated_metadata.get("prepared_token") or ""
                )
                return DurableVideoPollClaim(
                    state="prepared" if prepared_token else "claimed",
                    task_alias=task_alias,
                    requested_model=str(metadata["requested_model"]),
                    provider_name=str(metadata["provider_name"]),
                    provider_domain=str(metadata["provider_domain"]),
                    provider_credential_domain=str(
                        metadata["provider_credential_domain"]
                    ),
                    upstream_model=str(metadata["upstream_model"]),
                    upstream_task_id=str(metadata["upstream_task_id"]),
                    fencing_token=token,
                    attempt=attempt,
                    prepared_token=prepared_token,
                    prepared_provider_response=(
                        dict(updated_metadata["prepared_provider_response"])
                        if isinstance(
                            updated_metadata.get("prepared_provider_response"),
                            dict,
                        )
                        else None
                    ),
                    prepared_asset_response=(
                        dict(updated_metadata["prepared_asset_response"])
                        if isinstance(
                            updated_metadata.get("prepared_asset_response"),
                            dict,
                        )
                        else None
                    ),
                    prepare_sha256=str(
                        updated_metadata.get("prepare_sha256") or ""
                    ),
                )
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot authorize durable video poll"
            ) from exc

    def prepare_video_poll_asset(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        provider_response: dict[str, object],
        now: float | None = None,
    ) -> DurablePreparedVideoAsset:
        """Persist the raw capability before the private asset store can commit it."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        fence = _validated_digest(fencing_token, "fencing_token")
        current = self._validated_now(now)
        if not isinstance(provider_response, dict):
            raise ValueError("prepared video provider response is invalid")
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.principal_hash,a.operation,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r JOIN durable_media_asset_authority a "
                    "ON a.turn_id=r.turn_id WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError(
                        "prepared video poll request is unavailable"
                    )
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                metadata = self._video_metadata_v2(metadata)
                if metadata.get("poll_fencing_token") != fence:
                    raise sqlite3.DatabaseError(
                        "prepared video poll fence changed"
                    )
                if row[2:] != (
                    principal,
                    "videos.create",
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                ):
                    raise sqlite3.DatabaseError(
                        "prepared video asset authority is invalid"
                    )

                existing_token = str(metadata.get("prepared_token") or "")
                token = existing_token or create_asset_token()
                normalized_provider, normalized_asset, prepare_digest = (
                    _prepared_video_material(
                        task_alias=task_alias,
                        token=token,
                        provider_response=provider_response,
                        asset_response=metadata.get("prepared_asset_response"),
                    )
                )
                if existing_token:
                    if (
                        metadata.get("prepared_provider_response")
                        != normalized_provider
                        or metadata.get("prepared_asset_response")
                        != normalized_asset
                        or metadata.get("prepare_sha256") != prepare_digest
                    ):
                        raise sqlite3.DatabaseError(
                            "prepared video recovery material changed"
                        )
                else:
                    metadata.update(
                        {
                            "prepared_token": token,
                            "prepared_provider_response": normalized_provider,
                            "prepared_asset_response": None,
                            "prepare_sha256": prepare_digest,
                        }
                    )
                    encoded = self._encode_video_envelope(
                        create_response, metadata
                    )
                    cursor = connection.execute(
                        "UPDATE durable_media_requests SET response_json=?,"
                        "updated_at=?,expires_at=? WHERE turn_id=? "
                        "AND principal_hash=? AND operation='videos.create' "
                        "AND status='succeeded'",
                        (
                            encoded,
                            current,
                            current + self.retention_seconds,
                            turn_id,
                            principal,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.DatabaseError(
                            "prepared video request changed concurrently"
                        )
                return DurablePreparedVideoAsset(
                    task_alias=task_alias,
                    token=token,
                    provider_response=dict(normalized_provider),
                    asset_response=(
                        dict(normalized_asset)
                        if isinstance(normalized_asset, dict)
                        else None
                    ),
                    prepare_sha256=prepare_digest,
                )
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot prepare durable video asset recovery"
            ) from exc

    def attach_video_poll_asset(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        response: dict[str, object],
        now: float | None = None,
    ) -> DurablePreparedVideoAsset:
        """Attach the exact verified v2 descriptor without publishing it."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        fence = _validated_digest(fencing_token, "fencing_token")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.principal_hash,a.operation,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r JOIN durable_media_asset_authority a "
                    "ON a.turn_id=r.turn_id WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError(
                        "prepared video poll request is unavailable"
                    )
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                metadata = self._video_metadata_v2(metadata)
                if metadata.get("poll_fencing_token") != fence:
                    raise sqlite3.DatabaseError(
                        "prepared video poll fence changed"
                    )
                if row[2:] != (
                    principal,
                    "videos.create",
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                ):
                    raise sqlite3.DatabaseError(
                        "prepared video asset authority is invalid"
                    )
                prepared_token = str(metadata.get("prepared_token") or "")
                prepared_provider = metadata.get("prepared_provider_response")
                if not prepared_token or not isinstance(prepared_provider, dict):
                    raise sqlite3.DatabaseError(
                        "prepared video token is unavailable"
                    )
                normalized_provider, normalized_asset, prepare_digest = (
                    _prepared_video_material(
                        task_alias=task_alias,
                        token=prepared_token,
                        provider_response=prepared_provider,
                        asset_response=response,
                    )
                )
                if normalized_asset is None:
                    raise sqlite3.DatabaseError(
                        "prepared video asset result is unavailable"
                    )
                existing_asset = metadata.get("prepared_asset_response")
                if existing_asset is not None and (
                    existing_asset != normalized_asset
                    or metadata.get("prepare_sha256") != prepare_digest
                ):
                    raise sqlite3.DatabaseError(
                        "prepared video asset result changed"
                    )
                if existing_asset is None:
                    metadata.update(
                        {
                            "prepared_asset_response": normalized_asset,
                            "prepare_sha256": prepare_digest,
                        }
                    )
                    encoded = self._encode_video_envelope(
                        create_response, metadata
                    )
                    cursor = connection.execute(
                        "UPDATE durable_media_requests SET response_json=?,"
                        "updated_at=?,expires_at=? WHERE turn_id=? "
                        "AND principal_hash=? AND operation='videos.create' "
                        "AND status='succeeded'",
                        (
                            encoded,
                            current,
                            current + self.retention_seconds,
                            turn_id,
                            principal,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.DatabaseError(
                            "prepared video request changed concurrently"
                        )
                return DurablePreparedVideoAsset(
                    task_alias=task_alias,
                    token=prepared_token,
                    provider_response=dict(normalized_provider),
                    asset_response=dict(normalized_asset),
                    prepare_sha256=prepare_digest,
                )
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot attach durable prepared video asset"
            ) from exc

    def commit_prepared_video_poll_asset(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        prepare_sha256: str,
        now: float | None = None,
    ) -> tuple[bool, dict[str, object]]:
        """Publish one fully prepared asset and Root authority in one transaction."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        fence = _validated_digest(fencing_token, "fencing_token")
        prepare_digest = _validated_digest(
            prepare_sha256, "prepared video digest"
        )
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.principal_hash,a.operation,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r JOIN durable_media_asset_authority a "
                    "ON a.turn_id=r.turn_id WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    return False, {}
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                metadata = self._video_metadata_v2(metadata)
                if metadata.get("poll_fencing_token") != fence:
                    return False, {}
                if row[2:] != (
                    principal,
                    "videos.create",
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                ):
                    raise sqlite3.DatabaseError(
                        "prepared terminal video authority is invalid"
                    )
                prepared_token = str(metadata.get("prepared_token") or "")
                prepared_provider = metadata.get("prepared_provider_response")
                prepared_asset = metadata.get("prepared_asset_response")
                if (
                    not prepared_token
                    or not isinstance(prepared_provider, dict)
                    or not isinstance(prepared_asset, dict)
                    or metadata.get("prepare_sha256") != prepare_digest
                ):
                    raise sqlite3.DatabaseError(
                        "prepared terminal video material is incomplete"
                    )
                _provider, public_response, expected_digest = (
                    _prepared_video_material(
                        task_alias=task_alias,
                        token=prepared_token,
                        provider_response=prepared_provider,
                        asset_response=prepared_asset,
                    )
                )
                if (
                    public_response is None
                    or expected_digest != prepare_digest
                ):
                    raise sqlite3.DatabaseError(
                        "prepared terminal video digest changed"
                    )
                parsed = parse_asset_result(public_response)
                token_digest = canonical_token_set_digest(
                    [asset.token for asset in parsed.assets]
                )
                metadata.update(
                    {
                        "poll_fencing_token": "",
                        "poll_lease_expires_at": 0.0,
                        "last_response": public_response,
                        "terminal_response": public_response,
                        "next_poll_at": 0.0,
                        "prepared_token": "",
                        "prepared_provider_response": None,
                        "prepared_asset_response": None,
                        "prepare_sha256": "",
                    }
                )
                encoded = self._encode_video_envelope(
                    create_response, metadata
                )
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,updated_at=?,"
                    "expires_at=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        encoded,
                        current,
                        _ASSET_SUCCESS_UNACKED_EXPIRES_AT,
                        turn_id,
                        principal,
                    ),
                )
                if cursor.rowcount != 1:
                    return False, public_response
                cursor = connection.execute(
                    "UPDATE durable_media_asset_authority SET state='committed',"
                    "token_set_digest=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND state='reserved' "
                    "AND reserved_bytes=?",
                    (
                        token_digest,
                        turn_id,
                        principal,
                        _ASSET_OPERATION_RESERVATION_BYTES,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "prepared terminal video authority changed concurrently"
                    )
                return True, public_response
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot commit durable prepared video asset"
            ) from exc

    def finish_video_poll_asset(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        response: dict[str, object],
        now: float | None = None,
    ) -> tuple[bool, dict[str, object]]:
        """Atomically publish one verified v2 terminal result and its Root authority."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        token = _validated_digest(fencing_token, "fencing_token")
        try:
            parsed = parse_asset_result(response)
        except PaidMediaAssetProtocolError as exc:
            raise ValueError("terminal video asset result is invalid") from exc
        if parsed.kind != "video" or parsed.turn_id != turn_id:
            raise ValueError("terminal video asset result does not match poll")
        public_response = json.loads(canonical_asset_result(parsed))
        token_digest = canonical_token_set_digest(
            [asset.token for asset in parsed.assets]
        )
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.principal_hash,a.operation,a.state,a.reserved_bytes "
                    "FROM durable_media_requests r JOIN durable_media_asset_authority a "
                    "ON a.turn_id=r.turn_id WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    return False, public_response
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                if metadata.get("poll_fencing_token") != token:
                    return False, public_response
                if row[2:] != (
                    principal,
                    "videos.create",
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                ):
                    raise sqlite3.DatabaseError(
                        "terminal video poll asset authority is invalid"
                    )
                updated_metadata = dict(metadata)
                updated_metadata.update(
                    {
                        "poll_fencing_token": "",
                        "poll_lease_expires_at": 0.0,
                        "last_response": public_response,
                        "terminal_response": public_response,
                        "next_poll_at": 0.0,
                    }
                )
                encoded = self._encode_video_envelope(
                    create_response, updated_metadata
                )
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,updated_at=?,"
                    "expires_at=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        encoded,
                        current,
                        _ASSET_SUCCESS_UNACKED_EXPIRES_AT,
                        turn_id,
                        principal,
                    ),
                )
                if cursor.rowcount != 1:
                    return False, public_response
                cursor = connection.execute(
                    "UPDATE durable_media_asset_authority SET state='committed',"
                    "token_set_digest=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND state='reserved' "
                    "AND reserved_bytes=?",
                    (
                        token_digest,
                        turn_id,
                        principal,
                        _ASSET_OPERATION_RESERVATION_BYTES,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "terminal video poll authority changed concurrently"
                    )
                return True, public_response
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable terminal video asset result"
            ) from exc

    def finish_video_poll(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        response: dict[str, object],
        terminal: bool,
        now: float | None = None,
    ) -> tuple[bool, dict[str, object]]:
        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        token = _validated_digest(fencing_token, "fencing_token")
        if not isinstance(response, dict) or not isinstance(terminal, bool):
            raise ValueError("video poll response is invalid")
        try:
            response_bytes = json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("video poll response must be bounded JSON") from exc
        if len(response_bytes) > _MAX_VIDEO_POLL_RESPONSE_BYTES:
            raise ValueError("video poll response exceeds durable cache limit")
        legacy_public_response = _aliased_video_response(response, task_alias)
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.state,a.reserved_bytes FROM durable_media_requests r "
                    "LEFT JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    return False, legacy_public_response
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                if metadata.get("poll_fencing_token") != token:
                    return False, legacy_public_response
                authoritative = row[2] is not None
                if authoritative:
                    if row[2:] != (
                        "reserved",
                        _ASSET_OPERATION_RESERVATION_BYTES,
                    ):
                        raise sqlite3.DatabaseError(
                            "video poll asset reservation authority is invalid"
                        )
                    public_response = _safe_video_status_response(
                        response, task_alias
                    )
                    if terminal and not _is_video_terminal_failure(response):
                        raise ValueError(
                            "successful terminal video must use the asset commit slot"
                        )
                else:
                    public_response = legacy_public_response
                result_expires_at = (
                    _ASSET_SUCCESS_UNACKED_EXPIRES_AT
                    if authoritative and terminal
                    else current + self.retention_seconds
                )
                updated_metadata = dict(metadata)
                updated_metadata.update(
                    {
                        "poll_fencing_token": "",
                        "poll_lease_expires_at": 0.0,
                        "last_response": public_response,
                        "terminal_response": public_response if terminal else None,
                        "next_poll_at": (
                            0.0
                            if terminal
                            else current + _video_poll_backoff(int(metadata["poll_attempt"]))
                        ),
                    }
                )
                encoded = self._encode_video_envelope(create_response, updated_metadata)
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,updated_at=?,"
                    "expires_at=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        encoded,
                        current,
                        result_expires_at,
                        turn_id,
                        principal,
                    ),
                )
                return cursor.rowcount == 1, public_response
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable video poll result"
            ) from exc

    def complete_video_terminal_failure_cleanup(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        now: float | None = None,
    ) -> bool:
        """Release Root capacity after the local empty reservation was removed."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                    "a.state,a.reserved_bytes,a.token_set_digest "
                    "FROM durable_media_requests r LEFT JOIN "
                    "durable_media_asset_authority a ON a.turn_id=r.turn_id "
                    "WHERE r.turn_id=? AND r.principal_hash=? "
                    "AND r.operation='videos.create' AND r.status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    return False
                _create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                terminal = metadata.get("terminal_response")
                if (
                    not isinstance(terminal, dict)
                    or not _is_video_terminal_failure(terminal)
                    or metadata.get("poll_fencing_token") != ""
                ):
                    return False
                if row[2:] == (None, None, None):
                    return True
                if row[2:] != (
                    "reserved",
                    _ASSET_OPERATION_RESERVATION_BYTES,
                    None,
                ):
                    raise sqlite3.DatabaseError(
                        "failed video cleanup authority is invalid"
                    )
                cursor = connection.execute(
                    "DELETE FROM durable_media_asset_authority WHERE turn_id=? "
                    "AND principal_hash=? AND operation='videos.create' "
                    "AND state='reserved' AND reserved_bytes=? "
                    "AND token_set_digest IS NULL",
                    (
                        turn_id,
                        principal,
                        _ASSET_OPERATION_RESERVATION_BYTES,
                    ),
                )
                if cursor.rowcount != 1:
                    return False
                connection.execute(
                    "UPDATE durable_media_requests SET expires_at=?,updated_at=? "
                    "WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        current + self.retention_seconds,
                        current,
                        turn_id,
                        principal,
                    ),
                )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot complete terminal video failure cleanup"
            ) from exc

    def fail_video_poll(
        self,
        *,
        task_alias: str,
        principal_hash: str,
        fencing_token: str,
        now: float | None = None,
    ) -> bool:
        """Release a failed read fence while keeping the task and bounded retry delay."""

        turn_id = _video_turn_id(task_alias)
        principal = _validated_digest(principal_hash, "principal_hash")
        token = _validated_digest(fencing_token, "fencing_token")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                row = connection.execute(
                    "SELECT response_json,length(CAST(response_json AS BLOB)) "
                    "FROM durable_media_requests WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (turn_id, principal),
                ).fetchone()
                if row is None:
                    return False
                create_response, metadata = self._decode_video_envelope(
                    row[0], row[1], expected_turn_id=turn_id
                )
                if metadata.get("poll_fencing_token") != token:
                    return False
                updated_metadata = dict(metadata)
                updated_metadata.update(
                    {
                        "poll_fencing_token": "",
                        "poll_lease_expires_at": 0.0,
                        "next_poll_at": current
                        + _video_poll_backoff(int(metadata["poll_attempt"])),
                    }
                )
                encoded = self._encode_video_envelope(create_response, updated_metadata)
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET response_json=?,updated_at=?,"
                    "expires_at=? WHERE turn_id=? AND principal_hash=? "
                    "AND operation='videos.create' AND status='succeeded'",
                    (
                        encoded,
                        current,
                        current + self.retention_seconds,
                        turn_id,
                        principal,
                    ),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable video poll failure"
            ) from exc

    def list_active_video_leases(
        self,
        *,
        now: float | None = None,
    ) -> tuple[DurableVideoTaskLease, ...]:
        """Return every known nonterminal remote video for capacity recovery.

        The result contains only deterministic task aliases and irreversible
        paid-capability digests.  Any malformed registry row fails the entire
        read closed so a restart cannot silently under-count upstream work.
        """

        current = self._validated_now(now)
        try:
            with self._read_transaction() as connection:
                rows = connection.execute(
                    "SELECT turn_id,principal_hash,status,provider_phase,response_json,"
                    "length(CAST(response_json AS BLOB)) "
                    "FROM durable_media_requests WHERE operation='videos.create' "
                    "ORDER BY turn_id"
                ).fetchall()
                if len(rows) > self.max_records:
                    raise sqlite3.DatabaseError(
                        "durable video capacity registry exceeds its row limit"
                    )
                active: list[DurableVideoTaskLease] = []
                for (
                    turn_id,
                    principal_hash,
                    status,
                    provider_phase,
                    response_json,
                    response_bytes,
                ) in rows:
                    if (
                        not isinstance(turn_id, str)
                        or _DIGEST_RE.fullmatch(turn_id) is None
                        or not isinstance(principal_hash, str)
                        or _DIGEST_RE.fullmatch(principal_hash) is None
                    ):
                        raise sqlite3.DatabaseError(
                            "durable video capacity ownership is corrupt"
                        )
                    if (
                        not isinstance(status, str)
                        or status
                        not in {"processing", "succeeded", "recovery_required"}
                        or not isinstance(provider_phase, int)
                        or isinstance(provider_phase, bool)
                        or provider_phase not in {0, 1}
                    ):
                        raise sqlite3.DatabaseError(
                            "durable video capacity state is corrupt"
                        )
                    if status == "processing" and provider_phase == 0:
                        if response_json is not None or response_bytes is not None:
                            raise sqlite3.DatabaseError(
                                "durable pre-provider video state is corrupt"
                            )
                        continue
                    if status in {"recovery_required", "processing"}:
                        if (
                            response_json is not None
                            or response_bytes is not None
                            or provider_phase != 1
                        ):
                            raise sqlite3.DatabaseError(
                                "durable ambiguous video capacity state is corrupt"
                            )
                        active.append(
                            DurableVideoTaskLease(
                                task_alias=_video_task_alias(turn_id),
                                principal_hash=principal_hash,
                            )
                        )
                        continue
                    try:
                        _response, metadata = self._decode_video_envelope(
                            response_json,
                            response_bytes,
                            expected_turn_id=turn_id,
                        )
                    except sqlite3.DatabaseError:
                        # A structurally valid pre-registry success cannot be
                        # polled safely because route/credential identity was
                        # never frozen.  Count it, but never expose upstream ids.
                        self._decode_response(response_json, response_bytes)
                        active.append(
                            DurableVideoTaskLease(
                                task_alias=_video_task_alias(turn_id),
                                principal_hash=principal_hash,
                            )
                        )
                        continue
                    if metadata.get("terminal_response") is None:
                        active.append(
                            DurableVideoTaskLease(
                                task_alias=str(metadata["task_alias"]),
                                principal_hash=principal_hash,
                            )
                        )
                return tuple(active)
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot rebuild durable video capacity"
            ) from exc

    def mark_recovery_required(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        now: float | None = None,
    ) -> bool:
        """Make an ambiguous provider-phase outcome terminal for auto-submit."""

        normalized_turn = _validated_digest(turn_id, "turn_id")
        normalized_token = _validated_digest(fencing_token, "fencing_token")
        current = self._validated_now(now)
        try:
            with self._write_transaction() as connection:
                cursor = connection.execute(
                    "UPDATE durable_media_requests SET status='recovery_required',"
                    "fencing_token='',lease_expires_at=0,response_json=NULL,"
                    "reserved_response_bytes=0,updated_at=?,expires_at=? WHERE turn_id=? "
                    "AND status='processing' AND provider_phase=1 "
                    "AND fencing_token=?",
                    (
                        current,
                        current + self.retention_seconds,
                        normalized_turn,
                        normalized_token,
                    ),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable media recovery state"
            ) from exc

    def enter_authority_manual_only(
        self,
        *,
        installation_id: str,
        epoch: int,
        recovery_floor: int,
        recovery_state_digest: str,
    ) -> DurableMediaRootTransition:
        """Persist the one-step no-outbound receipt after a root recovery fence."""

        installation = _validated_nonzero_digest(
            installation_id, "installation_id"
        )
        recovery_digest = _validated_nonzero_digest(
            recovery_state_digest, "recovery_state_digest"
        )
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if (
            not isinstance(recovery_floor, int)
            or isinstance(recovery_floor, bool)
            or not 0 <= recovery_floor < _MAX_MUTATION_SEQUENCE
        ):
            raise ValueError("recovery_floor is invalid")
        try:
            with self._transaction_lock:
                if self._commit_hook_active:
                    raise DurableMediaRequestUnavailable(
                        "durable media recovery is unavailable during root confirmation"
                    )
                connection = self._keeper
                if connection is None:
                    raise sqlite3.DatabaseError(
                        "durable media request store is closed"
                    )
                if connection.in_transaction:
                    raise sqlite3.DatabaseError(
                        "durable media request transaction state is invalid"
                    )
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._validate_schema(connection)
                    identity, sequence, state_digest = (
                        self._validate_anchor_against_database(connection)
                    )
                    current = self._root_state_from_connection(connection)
                    expected_after_digest = _next_authority_state_digest(
                        recovery_digest,
                        identity,
                        recovery_floor + 1,
                    )
                    if current.authority_mode == "manual_only":
                        if (
                            current.installation_id != installation
                            or current.epoch != epoch
                            or current.recovery_floor != recovery_floor
                            or current.recovery_state_digest != recovery_digest
                            or current.mutation_sequence != recovery_floor + 1
                            or current.state_digest != expected_after_digest
                        ):
                            raise DurableMediaRequestUnavailable(
                                "durable media manual recovery receipt conflicts"
                            )
                        connection.commit()
                        before = DurableMediaRootState(
                            database_identity=identity,
                            mutation_sequence=recovery_floor,
                            state_digest=recovery_digest,
                            authority_mode="normal",
                        )
                        self._root_commit_pending = None
                        return DurableMediaRootTransition(
                            before=before,
                            after=current,
                        )
                    if (
                        sequence != recovery_floor
                        or state_digest != recovery_digest
                        or current.authority_mode != "normal"
                    ):
                        raise DurableMediaRequestUnavailable(
                            "durable media recovery fence does not match local state"
                        )
                    self._write_anchor(
                        identity,
                        recovery_floor + 1,
                        expected_after_digest,
                    )
                    cursor = connection.execute(
                        "UPDATE durable_media_requests_meta SET mutation_sequence=?,"
                        "authority_state_digest=?,authority_mode='manual_only',"
                        "authority_installation_id=?,authority_epoch=?,"
                        "authority_recovery_floor=?,"
                        "authority_recovery_state_digest=? "
                        "WHERE singleton=1 AND database_identity=? "
                        "AND mutation_sequence=? AND authority_state_digest=? "
                        "AND authority_mode='normal'",
                        (
                            recovery_floor + 1,
                            expected_after_digest,
                            installation,
                            epoch,
                            recovery_floor,
                            recovery_digest,
                            identity,
                            recovery_floor,
                            recovery_digest,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.DatabaseError(
                            "durable media recovery receipt changed concurrently"
                        )
                    after = self._root_state_from_connection(connection)
                    connection.commit()
                    (
                        self._trusted_data_version,
                        self._trusted_schema_version,
                    ) = self._database_versions(connection)
                    self._root_commit_pending = None
                    return DurableMediaRootTransition(before=current, after=after)
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                finally:
                    if connection.in_transaction:
                        connection.rollback()
        except (OSError, sqlite3.Error) as exc:
            raise DurableMediaRequestUnavailable(
                "cannot persist durable media manual recovery receipt"
            ) from exc

    def close(self) -> None:
        with self._transaction_lock:
            if self._keeper is not None:
                if self._keeper.in_transaction:
                    self._keeper.rollback()
                self._keeper.close()
                self._keeper = None
            self._trusted_data_version = None
            self._trusted_schema_version = None
