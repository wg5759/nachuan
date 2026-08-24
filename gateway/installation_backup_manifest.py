"""Closed, capture-only manifest for coordinated installation backups.

This module deliberately does not perform restore, re-anchor, service control or
credential export.  It records and verifies a stable, already-staged artifact
tree while keeping ``restoreReady`` permanently false.  A future restricted
maintenance coordinator must supply the missing proofs before a different
schema can authorize restoration.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import unicodedata
from typing import Iterable, Sequence

from gateway.installation_root import (
    InstallationRootSnapshot,
)
from gateway.paid_media_asset_protocol import (
    PaidMediaAssetProtocolError,
    canonical_token_set_digest,
    parse_asset_result,
)


MANIFEST_SCHEMA = "nachuan.installation-backup.v1"

# ``nachuan.installation-backup.v1`` is a closed historical wire contract.  Its
# SQLite identities and definitions must not follow the installed runtime's
# current Root or asset-store implementation.  In particular, v1 captured the
# two-component Installation Root v3 and the pre-Root-bound asset store v1.
_V1_ROOT_APPLICATION_ID = 0x4E434952  # "NCIR"
_V1_ROOT_SCHEMA_VERSION = 3
_V1_ROOT_COMPONENTS = ("desktop", "gateway")
_V1_ROOT_MAX_DATABASE_BYTES = 16 * 1024 * 1024
_V1_ROOT_MAX_REANCHOR_RECEIPTS = 65_536
_V1_ROOT_DDL = """
CREATE TABLE installation_root (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 3),
    installation_id TEXT NOT NULL CHECK (length(installation_id) = 64),
    owner_sid_digest TEXT NOT NULL CHECK (length(owner_sid_digest) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    root_revision INTEGER NOT NULL CHECK (root_revision >= 1),
    status TEXT NOT NULL CHECK (
        status IN ('provisioning','active','maintenance_locked','retired')
    ),
    lock_kind TEXT NOT NULL CHECK (
        lock_kind IN ('none','operator','integrity','reanchor','retired')
    ),
    lock_reason_digest TEXT CHECK (
        lock_reason_digest IS NULL OR length(lock_reason_digest) = 64
    ),
    reanchor_pending INTEGER NOT NULL CHECK (reanchor_pending IN (0,1)),
    reanchor_operation_digest TEXT CHECK (
        reanchor_operation_digest IS NULL OR length(reanchor_operation_digest) = 64
    ),
    reanchor_snapshot_digest TEXT CHECK (
        reanchor_snapshot_digest IS NULL OR length(reanchor_snapshot_digest) = 64
    ),
    reanchor_source_epoch INTEGER CHECK (
        reanchor_source_epoch IS NULL OR reanchor_source_epoch >= 1
    ),
    CHECK (
        (status = 'provisioning' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'active' AND lock_kind = 'none'
            AND lock_reason_digest IS NULL AND reanchor_pending = 0
            AND (
                (reanchor_operation_digest IS NULL
                    AND reanchor_snapshot_digest IS NULL
                    AND reanchor_source_epoch IS NULL)
                OR (reanchor_operation_digest IS NOT NULL
                    AND reanchor_snapshot_digest IS NOT NULL
                    AND reanchor_source_epoch IS NOT NULL
                    AND epoch = reanchor_source_epoch + 1)
            ))
        OR (status = 'maintenance_locked' AND lock_kind IN ('operator','integrity')
            AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
        OR (status = 'maintenance_locked' AND lock_kind = 'reanchor'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 1
            AND reanchor_operation_digest IS NOT NULL
            AND reanchor_snapshot_digest IS NOT NULL
            AND reanchor_source_epoch IS NOT NULL
            AND epoch = reanchor_source_epoch + 1)
        OR (status = 'retired' AND lock_kind = 'retired'
            AND lock_reason_digest IS NOT NULL AND reanchor_pending = 0
            AND reanchor_operation_digest IS NULL
            AND reanchor_snapshot_digest IS NULL
            AND reanchor_source_epoch IS NULL)
    )
)
"""
_V1_ROOT_COMPONENT_DDL = """
CREATE TABLE installation_components (
    component TEXT PRIMARY KEY CHECK (component IN ('desktop','gateway')),
    identity TEXT NOT NULL CHECK (length(identity) = 64),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    bound INTEGER NOT NULL CHECK (bound IN (0,1)),
    sequence_floor INTEGER NOT NULL CHECK (sequence_floor >= 0),
    state_digest TEXT CHECK (state_digest IS NULL OR length(state_digest) = 64),
    recovery_floor INTEGER CHECK (recovery_floor IS NULL OR recovery_floor >= 0),
    recovery_state_digest TEXT CHECK (
        recovery_state_digest IS NULL OR length(recovery_state_digest) = 64
    ),
    CHECK (
        (bound = 0 AND sequence_floor = 0 AND state_digest IS NULL
            AND recovery_floor IS NULL AND recovery_state_digest IS NULL)
        OR (bound = 1 AND state_digest IS NOT NULL AND (
            (recovery_floor IS NULL AND recovery_state_digest IS NULL)
            OR (recovery_floor = sequence_floor
                AND recovery_state_digest = state_digest)
        ))
    )
)
"""
_V1_ROOT_UPDATER_DDL = """
CREATE TABLE installation_updater (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    release_sequence INTEGER NOT NULL CHECK (release_sequence >= 0),
    keyring_sequence INTEGER NOT NULL CHECK (keyring_sequence >= 0),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
    state_digest TEXT NOT NULL CHECK (length(state_digest) = 64)
)
"""
_V1_ROOT_REANCHOR_RECEIPT_DDL = """
CREATE TABLE installation_reanchor_receipts (
    target_epoch INTEGER PRIMARY KEY CHECK (target_epoch >= 2),
    source_epoch INTEGER NOT NULL UNIQUE CHECK (source_epoch >= 1),
    operation_digest TEXT NOT NULL UNIQUE CHECK (length(operation_digest) = 64),
    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
    final_proof_digest TEXT NOT NULL CHECK (length(final_proof_digest) = 64),
    completed_root_revision INTEGER NOT NULL UNIQUE CHECK (
        completed_root_revision >= 1
    ),
    CHECK (target_epoch = source_epoch + 1)
) WITHOUT ROWID
"""
_V1_ROOT_REANCHOR_NO_UPDATE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_update
BEFORE UPDATE ON installation_reanchor_receipts
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""
_V1_ROOT_REANCHOR_NO_DELETE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_delete
BEFORE DELETE ON installation_reanchor_receipts
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""
_V1_ROOT_REANCHOR_NO_REPLACE_DDL = """
CREATE TRIGGER installation_reanchor_receipts_no_replace
BEFORE INSERT ON installation_reanchor_receipts
WHEN EXISTS (
    SELECT 1 FROM installation_reanchor_receipts
    WHERE target_epoch = NEW.target_epoch
        OR source_epoch = NEW.source_epoch
        OR operation_digest = NEW.operation_digest
        OR completed_root_revision = NEW.completed_root_revision
)
BEGIN
    SELECT RAISE(ABORT, 'installation reanchor receipts are append-only');
END
"""
_V1_ROOT_EXPECTED_DDL = {
    ("table", "installation_root"): _V1_ROOT_DDL,
    ("table", "installation_components"): _V1_ROOT_COMPONENT_DDL,
    ("table", "installation_updater"): _V1_ROOT_UPDATER_DDL,
    (
        "table",
        "installation_reanchor_receipts",
    ): _V1_ROOT_REANCHOR_RECEIPT_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_update",
    ): _V1_ROOT_REANCHOR_NO_UPDATE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_delete",
    ): _V1_ROOT_REANCHOR_NO_DELETE_DDL,
    (
        "trigger",
        "installation_reanchor_receipts_no_replace",
    ): _V1_ROOT_REANCHOR_NO_REPLACE_DDL,
}

_V1_GATEWAY_APPLICATION_ID = 0x4E434D52  # "NCMR"
_V1_GATEWAY_SCHEMA_VERSION = 4
_V1_GATEWAY_SCHEMA_FINGERPRINT = (
    "778b15d71388b12b6938ce0b5cd63c03a85a898eb0a7b7b9bef3c523004709bd"
)
_V1_GATEWAY_SCHEMA_DDL_SHA256 = (
    "adbfbca7e42a8560fa18944021b558acbd21b9f51050018bf0e61ec2b0306cc0"
)
_V1_GATEWAY_SCHEMA_OBJECTS = (
    ("index", "durable_media_expiry_idx"),
    ("index", "durable_media_turn_idx"),
    ("table", "durable_media_asset_authority"),
    ("table", "durable_media_asset_capacity"),
    ("table", "durable_media_requests"),
    ("table", "durable_media_requests_meta"),
    ("trigger", "durable_media_asset_capacity_insert"),
    ("trigger", "durable_media_asset_capacity_update"),
    ("trigger", "durable_media_asset_count_delete"),
    ("trigger", "durable_media_asset_count_insert"),
    ("trigger", "durable_media_asset_count_update"),
    ("trigger", "durable_media_capacity_insert"),
    ("trigger", "durable_media_capacity_update"),
    ("trigger", "durable_media_count_delete"),
    ("trigger", "durable_media_count_insert"),
    ("trigger", "durable_media_count_update"),
)
_V1_GATEWAY_REQUEST_COLUMNS = (
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
_V1_GATEWAY_META_COLUMNS = (
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
_V1_GATEWAY_REQUEST_DDL = """
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
        length(CAST(response_json AS BLOB)) <= 134217728
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
_V1_GATEWAY_META_DDL = """
CREATE TABLE durable_media_requests_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=4),
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
_V1_GATEWAY_ASSET_CAPACITY_DDL = """
CREATE TABLE durable_media_asset_capacity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    max_capacity_bytes INTEGER NOT NULL CHECK(
        max_capacity_bytes>=201326592
    ),
    reserved_total_bytes INTEGER NOT NULL CHECK(reserved_total_bytes>=0)
) WITHOUT ROWID
"""
_V1_GATEWAY_ASSET_AUTHORITY_DDL = """
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
        reserved_bytes IN (0,201326592)
    ),
    token_set_digest TEXT,
    archive_receipt_sha256 TEXT,
    acked_at REAL,
    CHECK(
        (state='reserved' AND reserved_bytes=201326592
            AND token_set_digest IS NULL AND archive_receipt_sha256 IS NULL
            AND acked_at IS NULL)
        OR
        (state='committed' AND reserved_bytes=201326592
            AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*'
            AND archive_receipt_sha256 IS NULL AND acked_at IS NULL)
        OR
        (state='acked_pending_cleanup'
            AND reserved_bytes=201326592
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
_V1_GATEWAY_EXPECTED_DDL = {
    ("table", "durable_media_requests"): _V1_GATEWAY_REQUEST_DDL,
    ("table", "durable_media_requests_meta"): _V1_GATEWAY_META_DDL,
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
    (
        "table",
        "durable_media_asset_capacity",
    ): _V1_GATEWAY_ASSET_CAPACITY_DDL,
    (
        "table",
        "durable_media_asset_authority",
    ): _V1_GATEWAY_ASSET_AUTHORITY_DDL,
    ("trigger", "durable_media_asset_capacity_insert"): """
CREATE TRIGGER durable_media_asset_capacity_insert
BEFORE INSERT ON durable_media_asset_authority
WHEN (SELECT reserved_total_bytes+NEW.reserved_bytes>max_capacity_bytes
    FROM durable_media_asset_capacity WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'durable paid-media asset capacity reached');
END
""",
    ("trigger", "durable_media_asset_capacity_update"): """
CREATE TRIGGER durable_media_asset_capacity_update
BEFORE UPDATE OF reserved_bytes ON durable_media_asset_authority
WHEN (SELECT reserved_total_bytes-OLD.reserved_bytes+NEW.reserved_bytes>
    max_capacity_bytes FROM durable_media_asset_capacity WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'durable paid-media asset capacity reached');
END
""",
    ("trigger", "durable_media_asset_count_insert"): """
CREATE TRIGGER durable_media_asset_count_insert
AFTER INSERT ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes+NEW.reserved_bytes
    WHERE singleton=1;
END
""",
    ("trigger", "durable_media_asset_count_delete"): """
CREATE TRIGGER durable_media_asset_count_delete
AFTER DELETE ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes-OLD.reserved_bytes
    WHERE singleton=1;
END
""",
    ("trigger", "durable_media_asset_count_update"): """
CREATE TRIGGER durable_media_asset_count_update
AFTER UPDATE OF reserved_bytes ON durable_media_asset_authority
BEGIN
    UPDATE durable_media_asset_capacity
    SET reserved_total_bytes=reserved_total_bytes-OLD.reserved_bytes+NEW.reserved_bytes
    WHERE singleton=1;
END
""",
}
_V1_GATEWAY_MAX_MUTATION_SEQUENCE = (1 << 63) - 1
_V1_GATEWAY_ANCHOR_FORMAT = 2
_V1_GATEWAY_ANCHOR_MAX_BYTES = 1024
_V1_GATEWAY_DEFAULT_MAX_RECORDS = 50_000
_V1_GATEWAY_DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024 * 1024
_V1_GATEWAY_DEFAULT_MAX_TOTAL_RESPONSE_BYTES = 512 * 1024 * 1024
_V1_GATEWAY_DEFAULT_MAX_DATABASE_BYTES = 1024 * 1024 * 1024
_V1_GATEWAY_DEFAULT_MAX_ASSET_RESERVATION_BYTES = 8 * 1024 * 1024 * 1024
_V1_GATEWAY_AUTHORITY_STATE_DOMAIN = (
    b"nachuan-durable-media-authority-state-v1\0"
)
_V1_GATEWAY_VIDEO_ALIAS_RE = re.compile(r"^nvt1_[0-9a-f]{64}$")
_V1_GATEWAY_VIDEO_TERMINAL_FAILURE_STATES = frozenset(
    {"failure", "failed", "error", "cancelled", "canceled"}
)

_V1_ASSET_APPLICATION_ID = 0x4E434153  # "NCAS"
_V1_ASSET_SCHEMA_VERSION = 1
_V1_ASSET_STORE_SCHEMA = "nachuan.paid-media-asset-store.v1"
_V1_ASSET_DEFAULT_STORE_CAPACITY_BYTES = 8 * 1024 * 1024 * 1024
_V1_ASSET_OPERATION_RESERVATION_BYTES = 201_326_592
_V1_ASSET_LEAF_RE = re.compile(r"^[0-9a-f]{64}\.asset$")
_V1_ASSET_META_DDL = """
CREATE TABLE asset_store_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema TEXT NOT NULL CHECK(schema='nachuan.paid-media-asset-store.v1'),
    installation_id TEXT NOT NULL CHECK(
        length(installation_id)=64 AND installation_id NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    max_capacity_bytes INTEGER NOT NULL CHECK(max_capacity_bytes>=201326592),
    reserved_total_bytes INTEGER NOT NULL CHECK(reserved_total_bytes>=0)
) WITHOUT ROWID
"""
_V1_ASSET_RESERVATION_DDL = """
CREATE TABLE asset_reservations (
    turn_id TEXT PRIMARY KEY CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=201326592),
    actual_bytes INTEGER NOT NULL DEFAULT 0 CHECK(actual_bytes>=0),
    state TEXT NOT NULL CHECK(state IN ('active','committed','acked')),
    token_set_digest TEXT,
    created_at REAL NOT NULL CHECK(created_at>=0),
    CHECK(
        (state='active' AND token_set_digest IS NULL) OR
        (state IN ('committed','acked') AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*')
    )
) WITHOUT ROWID
"""
_V1_ASSET_OBJECT_DDL = """
CREATE TABLE paid_media_assets (
    token_hash TEXT PRIMARY KEY CHECK(
        length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL REFERENCES asset_reservations(turn_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
    media_type TEXT NOT NULL CHECK(media_type IN (
        'image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'
    )),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 25165824),
    sha256 TEXT NOT NULL CHECK(
        length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    validation_receipt_sha256 TEXT NOT NULL CHECK(
        length(validation_receipt_sha256)=64 AND
        validation_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    object_leaf TEXT NOT NULL UNIQUE CHECK(length(object_leaf)=70),
    UNIQUE(turn_id, ordinal)
) WITHOUT ROWID
"""
_V1_ASSET_LEASE_DDL = """
CREATE TABLE asset_read_leases (
    token_hash TEXT NOT NULL REFERENCES paid_media_assets(token_hash) ON DELETE CASCADE,
    lease_id TEXT NOT NULL CHECK(
        length(lease_id)=64 AND lease_id NOT GLOB '*[^0-9a-f]*'
    ),
    expires_at REAL NOT NULL CHECK(expires_at>=0),
    PRIMARY KEY(token_hash, lease_id)
) WITHOUT ROWID
"""
_V1_ASSET_PENDING_COMMIT_DDL = """
CREATE TABLE asset_pending_commits (
    token_hash TEXT PRIMARY KEY CHECK(
        length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL REFERENCES asset_reservations(turn_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
    media_type TEXT NOT NULL CHECK(media_type IN (
        'image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'
    )),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 25165824),
    sha256 TEXT NOT NULL CHECK(
        length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    validation_receipt_sha256 TEXT NOT NULL CHECK(
        length(validation_receipt_sha256)=64 AND
        validation_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    staging_leaf TEXT NOT NULL CHECK(length(staging_leaf) BETWEEN 1 AND 128),
    object_leaf TEXT NOT NULL UNIQUE CHECK(length(object_leaf)=70),
    lease_expires_at REAL NOT NULL CHECK(lease_expires_at>=0),
    UNIQUE(turn_id, ordinal)
) WITHOUT ROWID
"""
_V1_ASSET_ACK_DDL = """
CREATE TABLE asset_ack_receipts (
    turn_id TEXT PRIMARY KEY CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    token_set_digest TEXT NOT NULL CHECK(
        length(token_set_digest)=64 AND token_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    archive_receipt_sha256 TEXT NOT NULL CHECK(
        length(archive_receipt_sha256)=64 AND
        archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    acked_at REAL NOT NULL CHECK(acked_at>=0)
) WITHOUT ROWID
"""
_V1_ASSET_EXPECTED_DDL = {
    ("table", "asset_store_meta"): _V1_ASSET_META_DDL,
    ("table", "asset_reservations"): _V1_ASSET_RESERVATION_DDL,
    ("table", "paid_media_assets"): _V1_ASSET_OBJECT_DDL,
    ("table", "asset_read_leases"): _V1_ASSET_LEASE_DDL,
    ("table", "asset_pending_commits"): _V1_ASSET_PENDING_COMMIT_DDL,
    ("table", "asset_ack_receipts"): _V1_ASSET_ACK_DDL,
}

MAX_MANIFEST_BYTES = 512 * 1024
MAX_ARTIFACTS = 1_024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024
MAX_SQLITE_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024 * 1024
_MAX_LOGICAL_PATH_BYTES = 1_024
_MAX_LOGICAL_PATH_DEPTH = 16
_MAX_LOGICAL_SEGMENT_BYTES = 255
_MAX_JSON_DEPTH = 32
_MAX_TREE_ENTRIES = MAX_ARTIFACTS * (_MAX_LOGICAL_PATH_DEPTH + 1)
_MAX_DIRECTORY_CHILDREN = 2_048
_MAX_SQLITE_PROGRESS_CALLBACKS = 1_000_000
_MAX_CANONICAL_STRING_BYTES = 1024 * 1024
# Keep all manifest integers exactly representable by both Python and
# JavaScript/TypeScript verifiers.  JSON itself does not carry an integer type.
_MAX_COUNTER = (1 << 53) - 1
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_RE = re.compile(r"^snapshot-[0-9a-f]{64}$")
_PORTABLE_SEGMENT_RE = re.compile(r"^[a-z0-9._-]+$")
_MANIFEST_DOMAIN = b"nachuan.installation-backup.v1\0"
_ARTIFACT_SET_DOMAIN = b"nachuan.installation-backup.artifact-set.v1\0"
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}

REQUIRED_MISSING_RESTORE_PROOFS = frozenset(
    {
        "asset_store_root_binding",
        "asset_store_reanchor_adapter",
        "canonical_final_proof_manifest",
        "desktop_reanchor_adapter",
        "gateway_reanchor_adapter",
        "restricted_maintenance_coordinator",
        "schema_v2_installer_migration",
    }
)

REQUIRED_MISSING_CAPTURE_PROOFS = frozenset(
    {
        "asset_store_root_binding",
        "capture_manifest_trusted_attestation",
        "desktop_capacity_active_slot",
        "desktop_inventory_adapter",
        "desktop_quiescence_stage_drain",
        "desktop_root_composite_binding",
        "desktop_safe_storage_semantic_validation",
        "desktop_vault_closed_index",
        "restricted_capture_coordinator",
        "windows_pinned_staging_acl",
    }
)

_ROLE_POLICY: dict[str, tuple[str, str]] = {
    "installation_root_evidence": ("sqlite", "evidence_only"),
    "gateway_ledger": ("sqlite", "restore_reanchor_required"),
    "gateway_rollback_anchor": ("file", "restore_reanchor_required"),
    "gateway_writer_owner_evidence": ("file", "evidence_only"),
    "asset_store_database": ("sqlite", "restore_reanchor_required"),
    "asset_store_object": ("file", "restore_reanchor_required"),
    "desktop_ledger": ("file", "restore_reanchor_required"),
    "desktop_ledger_anchor": ("file", "restore_reanchor_required"),
    "desktop_ledger_pair_intent": ("file", "restore_reanchor_required"),
    "desktop_vault_authority_head": ("file", "restore_reanchor_required"),
    "desktop_vault_authority_journal": ("file", "restore_reanchor_required"),
    "desktop_vault_entry": ("file", "restore_reanchor_required"),
    "desktop_capacity_anchor": ("file", "restore_reanchor_required"),
    "desktop_capacity_active_slot": ("file", "restore_reanchor_required"),
    "desktop_capacity_inactive_slot": ("file", "restore_reanchor_required"),
    "desktop_recovery_intent": ("file", "restore_reanchor_required"),
    "desktop_installation_authority": ("file", "restore_reanchor_required"),
    "desktop_installation_authority_anchor": (
        "file",
        "restore_reanchor_required",
    ),
    "desktop_installation_authority_pair_intent": (
        "file",
        "restore_reanchor_required",
    ),
    "desktop_legacy_seal": ("file", "restore_reanchor_required"),
}

_OPTIONAL_REPEATABLE_ROLES = frozenset(
    {
        "asset_store_object",
        "desktop_recovery_intent",
        "desktop_vault_entry",
    }
)
_OPTIONAL_SINGLETON_ROLES = frozenset({"desktop_capacity_inactive_slot"})
_REQUIRED_SINGLETON_ROLES = frozenset(
    {
        "installation_root_evidence",
        "gateway_ledger",
        "gateway_rollback_anchor",
        "gateway_writer_owner_evidence",
        "asset_store_database",
        "desktop_ledger",
        "desktop_ledger_anchor",
        "desktop_ledger_pair_intent",
        "desktop_vault_authority_head",
        "desktop_vault_authority_journal",
        "desktop_capacity_anchor",
        "desktop_capacity_active_slot",
        "desktop_installation_authority",
        "desktop_installation_authority_anchor",
        "desktop_installation_authority_pair_intent",
        "desktop_legacy_seal",
    }
)
_ROLE_CARDINALITY: dict[str, tuple[int, int]] = {
    role: (1, 1) for role in _REQUIRED_SINGLETON_ROLES
}
_ROLE_CARDINALITY.update(
    {role: (0, MAX_ARTIFACTS) for role in _OPTIONAL_REPEATABLE_ROLES}
)
_ROLE_CARDINALITY.update({role: (0, 1) for role in _OPTIONAL_SINGLETON_ROLES})

_FORBIDDEN_V1_ROLES = frozenset(
    {
        "configuration",
        "credential_blob",
        "desktop_capacity",
        "desktop_vault",
        "desktop_vault_authority",
        "undo_signing_key",
        "updater_state",
    }
)

_FIXED_ROLE_PATHS = {
    "desktop_ledger": "desktop/user-data/data/paid-media-ledger.json",
    "desktop_ledger_anchor": "desktop/user-data/data/paid-media-ledger.json.anchor",
    "desktop_ledger_pair_intent": (
        "desktop/user-data/data/paid-media-ledger.json.pair-intent"
    ),
    "desktop_vault_authority_head": (
        "desktop/user-data/data/paid-media-vault.authority.json"
    ),
    "desktop_vault_authority_journal": (
        "desktop/user-data/data/paid-media-vault.authority.journal"
    ),
    "desktop_capacity_anchor": (
        "desktop/user-data/data/paid-media-capacity.json.anchor"
    ),
    "desktop_installation_authority": (
        "desktop/user-data/data/paid-media-installation-authority.json"
    ),
    "desktop_installation_authority_anchor": (
        "desktop/user-data/data/paid-media-installation-authority.json.anchor"
    ),
    "desktop_installation_authority_pair_intent": (
        "desktop/user-data/data/paid-media-installation-authority.json.pair-intent"
    ),
    "desktop_legacy_seal": (
        "desktop/user-data/data/paid-media-legacy-seal.json"
    ),
}
_DESKTOP_VAULT_PREFIX = "desktop/user-data/data/paid-media-vault/"
_DESKTOP_RECOVERY_PREFIX = "desktop/user-data/data/paid-media-recovery-intents/"
_DESKTOP_CAPACITY_SLOT_PREFIX = (
    "desktop/user-data/data/paid-media-capacity.json.slot-"
)


class BackupManifestError(RuntimeError):
    """A capture manifest or its artifact tree is unsafe or inconsistent."""


@dataclass(frozen=True)
class ArtifactSpec:
    logical_path: str
    role: str
    kind: str
    restore_policy: str


def _canonical_value(
    value: object,
    *,
    label: str = "value",
    depth: int = 0,
) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise BackupManifestError(f"{label} exceeds the maximum JSON depth")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < -_MAX_COUNTER or value > _MAX_COUNTER:
            raise BackupManifestError(f"{label} integer is outside the canonical range")
        return
    if isinstance(value, float):
        raise BackupManifestError(f"{label} floats are forbidden")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise BackupManifestError(f"{label} string is not NFC-normalized")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise BackupManifestError(f"{label} string is not valid UTF-8") from exc
        if len(encoded) > _MAX_CANONICAL_STRING_BYTES:
            raise BackupManifestError(f"{label} string exceeds the byte limit")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _canonical_value(item, label=f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise BackupManifestError(f"{label} object keys must be strings")
            _canonical_value(key, label=f"{label} key", depth=depth + 1)
            _canonical_value(item, label=f"{label}.{key}", depth=depth + 1)
        return
    raise BackupManifestError(f"{label} contains an unsupported JSON value")


def canonical_json_bytes(value: object) -> bytes:
    """Return the one accepted UTF-8 JSON representation (without BOM/newline)."""

    _canonical_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BackupManifestError("manifest cannot be canonically encoded") from exc


def _digest(value: object, *, domain: bytes) -> str:
    return sha256(domain + canonical_json_bytes(value)).hexdigest()


def _require_digest(value: object, label: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise BackupManifestError(f"{label} must be a lowercase SHA-256")
    if not allow_zero and value == "0" * 64:
        raise BackupManifestError(f"{label} must not be zero")
    return value


def _require_counter(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackupManifestError(f"{label} must be an integer")
    if value < minimum or value > _MAX_COUNTER:
        raise BackupManifestError(f"{label} is outside the allowed range")
    return value


def _canonical_sql(value: object) -> str:
    return re.sub(r"\s+", "", str(value or "")).lower().rstrip(";")


def _v1_installation_principal(installation_id: str, epoch: int) -> str:
    normalized_id = _require_digest(installation_id, "installation id")
    normalized_epoch = _require_counter(epoch, "installation epoch", minimum=1)
    return sha256(
        b"nachuan.installation-principal.v1\0"
        + bytes.fromhex(normalized_id)
        + normalized_epoch.to_bytes(8, "big", signed=False)
    ).hexdigest()


def _v1_gateway_initial_authority_state_digest(database_identity: str) -> str:
    identity = _require_digest(database_identity, "gateway database identity")
    return sha256(
        _V1_GATEWAY_AUTHORITY_STATE_DOMAIN
        + b"initial\0"
        + str(_V1_GATEWAY_SCHEMA_VERSION).encode("ascii")
        + b"\0"
        + _V1_GATEWAY_SCHEMA_FINGERPRINT.encode("ascii")
        + b"\0"
        + identity.encode("ascii")
        + b"\x000000000000000000"
    ).hexdigest()


def _v1_gateway_anchor_bytes(
    database_identity: str,
    mutation_sequence: int,
    authority_state_digest: str,
) -> bytes:
    identity = _require_digest(database_identity, "gateway database identity")
    state_digest = _require_digest(
        authority_state_digest, "gateway authority state digest"
    )
    if (
        not isinstance(mutation_sequence, int)
        or isinstance(mutation_sequence, bool)
        or not 0 <= mutation_sequence <= _V1_GATEWAY_MAX_MUTATION_SEQUENCE
    ):
        raise BackupManifestError("gateway mutation sequence is invalid")
    return json.dumps(
        {
            "authority_state_digest": state_digest,
            "database_identity": identity,
            "format": _V1_GATEWAY_ANCHOR_FORMAT,
            "mutation_sequence": f"{mutation_sequence:016x}",
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _v1_gateway_schema_ddl_sha256(
    objects: dict[tuple[str, str], object],
) -> str:
    encoded = json.dumps(
        [
            [object_type, name, _canonical_sql(sql)]
            for (object_type, name), sql in sorted(objects.items())
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _v1_gateway_validate_video_metadata(value: object) -> dict[str, object]:
    expected_fields = {
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
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("version") != 1
    ):
        raise sqlite3.DatabaseError(
            "v1 gateway video metadata fields are invalid"
        )
    alias = value.get("task_alias")
    if not isinstance(alias, str) or _V1_GATEWAY_VIDEO_ALIAS_RE.fullmatch(alias) is None:
        raise sqlite3.DatabaseError("v1 gateway video task alias is invalid")
    for field in (
        "requested_model",
        "provider_name",
        "upstream_model",
        "upstream_task_id",
    ):
        text = value.get(field)
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text.strip()) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in text)
        ):
            raise sqlite3.DatabaseError(
                "v1 gateway video route metadata is invalid"
            )
    for field in ("provider_domain", "provider_credential_domain"):
        digest = value.get(field)
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise sqlite3.DatabaseError(
                "v1 gateway video provider domain is invalid"
            )
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
        raise sqlite3.DatabaseError(
            "v1 gateway video poll authority is invalid"
        )
    for field in ("last_response", "terminal_response"):
        response = value.get(field)
        if response is not None and not isinstance(response, dict):
            raise sqlite3.DatabaseError(
                "v1 gateway video cached response is invalid"
            )
    if value.get("terminal_response") is not None and fencing_token:
        raise sqlite3.DatabaseError(
            "v1 gateway terminal video retains a poll fence"
        )
    return value


def _v1_gateway_decode_video_metadata(
    raw: object,
    encoded_bytes: object,
    *,
    expected_turn_id: str,
    max_response_bytes: int,
) -> dict[str, object]:
    if (
        not isinstance(raw, str)
        or not isinstance(encoded_bytes, int)
        or isinstance(encoded_bytes, bool)
        or not 2 <= encoded_bytes <= max_response_bytes
        or len(raw.encode("utf-8")) != encoded_bytes
    ):
        raise sqlite3.DatabaseError(
            "v1 gateway video response size is invalid"
        )
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, RecursionError) as exc:
        raise sqlite3.DatabaseError(
            "v1 gateway video task envelope is invalid"
        ) from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"response", "video_task"}
        or not isinstance(value.get("response"), dict)
    ):
        raise sqlite3.DatabaseError(
            "v1 gateway video task registry is invalid"
        )
    metadata = _v1_gateway_validate_video_metadata(value.get("video_task"))
    if metadata["task_alias"] != f"nvt1_{_require_digest(expected_turn_id, 'turn id')}":
        raise sqlite3.DatabaseError("v1 gateway video task alias is corrupt")
    return metadata


def _v1_gateway_is_video_terminal_failure(response: dict[str, object]) -> bool:
    nested = response.get("data")
    nested_status = nested.get("status") if isinstance(nested, dict) else None
    status = str(response.get("status") or nested_status or "processing").strip().lower()
    if (
        not status
        or len(status) > 64
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", status) is None
    ):
        status = "processing"
    return status in _V1_GATEWAY_VIDEO_TERMINAL_FAILURE_STATES


def _require_exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise BackupManifestError(f"{label} has missing or unexpected fields")
    return value


def _logical_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BackupManifestError("artifact logical path is invalid")
    if unicodedata.normalize("NFC", value) != value:
        raise BackupManifestError("artifact logical path is not NFC-normalized")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeError as exc:
        raise BackupManifestError(
            "artifact logical path must use the portable ASCII subset"
        ) from exc
    if len(encoded) > _MAX_LOGICAL_PATH_BYTES:
        raise BackupManifestError("artifact logical path exceeds the byte limit")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
    ):
        raise BackupManifestError("artifact logical path is unsafe")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BackupManifestError("artifact logical path has an unsafe segment")
    if len(parts) > _MAX_LOGICAL_PATH_DEPTH:
        raise BackupManifestError("artifact logical path exceeds the depth limit")
    for part in parts:
        if (
            _PORTABLE_SEGMENT_RE.fullmatch(part) is None
            or len(part.encode("ascii")) > _MAX_LOGICAL_SEGMENT_BYTES
            or part.endswith((" ", "."))
            or ":" in part
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise BackupManifestError("artifact logical path has an unsafe segment")
    return value


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode)


def _assert_no_alternate_data_streams(path: Path) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = (
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", wintypes.WCHAR * 296),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),
        wintypes.DWORD,
    )
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),
    )
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = (wintypes.HANDLE,)
    find_close.restype = wintypes.BOOL

    data = WIN32_FIND_STREAM_DATA()
    handle = find_first(str(path), 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error == 38:  # ERROR_HANDLE_EOF: directories without named streams
            return
        raise BackupManifestError(
            f"cannot enumerate alternate data streams (WinError {error})"
        )
    try:
        while True:
            if data.cStreamName != "::$DATA":
                raise BackupManifestError(
                    f"artifact alternate data stream is forbidden: {path}"
                )
            if not find_next(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:  # ERROR_HANDLE_EOF
                    raise BackupManifestError(
                        f"cannot finish alternate data stream enumeration (WinError {error})"
                    )
                break
    finally:
        find_close(handle)


def _assert_regular_file(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise BackupManifestError(f"artifact file is unavailable: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
        raise BackupManifestError(f"artifact must be a regular non-reparse file: {path}")
    if int(info.st_nlink) != 1:
        raise BackupManifestError(f"artifact hardlinks are forbidden: {path}")
    if int(info.st_size) < 0 or int(info.st_size) > MAX_ARTIFACT_BYTES:
        raise BackupManifestError(f"artifact file exceeds the byte limit: {path}")
    _assert_no_alternate_data_streams(path)
    return info


def _fingerprint_file(
    path: Path,
    *,
    expected_size: int | None = None,
) -> tuple[int, str]:
    before = _assert_regular_file(path)
    if expected_size is not None and int(before.st_size) != expected_size:
        raise BackupManifestError(
            "artifact size changed after the declared-size preflight"
        )
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    descriptor: int | None = None
    digest = sha256()
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            _identity(opened) != _identity(before)
            or int(opened.st_size) != int(before.st_size)
            or _is_reparse_or_symlink(opened)
            or int(opened.st_nlink) != 1
        ):
            raise BackupManifestError("artifact identity changed while opening")
        if expected_size is None:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        else:
            remaining = expected_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise BackupManifestError(
                        "artifact ended before its declared byte length"
                    )
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise BackupManifestError(
                    "artifact exceeds its declared byte length"
                )
        opened_after = os.fstat(descriptor)
        if (
            _identity(opened_after) != _identity(opened)
            or int(opened_after.st_size) != int(opened.st_size)
            or int(opened_after.st_mtime_ns) != int(opened.st_mtime_ns)
            or int(opened_after.st_ctime_ns) != int(opened.st_ctime_ns)
        ):
            raise BackupManifestError("artifact changed while hashing")
    except OSError as exc:
        raise BackupManifestError(f"artifact cannot be read: {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    after = _assert_regular_file(path)
    if (
        _identity(after) != _identity(before)
        or int(after.st_size) != int(before.st_size)
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or int(after.st_ctime_ns) != int(before.st_ctime_ns)
    ):
        raise BackupManifestError("artifact changed after hashing")
    return int(before.st_size), digest.hexdigest()


def _sqlite_evidence(path: Path) -> dict[str, object]:
    uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=30)) as connection:
            application_id = connection.execute("PRAGMA application_id").fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
            page_count = connection.execute("PRAGMA page_count").fetchone()
            page_size = connection.execute("PRAGMA page_size").fetchone()
            if page_count is None or page_size is None:
                raise sqlite3.DatabaseError("SQLite page metadata is incomplete")
            pages = _require_counter(
                int(page_count[0]), "SQLite page count", minimum=1
            )
            size = _require_counter(
                int(page_size[0]), "SQLite page size", minimum=512
            )
            if pages * size > MAX_SQLITE_ARTIFACT_BYTES:
                raise sqlite3.DatabaseError("SQLite logical byte limit exceeded")
            progress_callbacks = 0

            def progress_guard() -> int:
                nonlocal progress_callbacks
                progress_callbacks += 1
                return int(progress_callbacks > _MAX_SQLITE_PROGRESS_CALLBACKS)

            connection.set_progress_handler(progress_guard, 1_000)
            rows = connection.execute("PRAGMA quick_check").fetchall()
            connection.set_progress_handler(None, 0)
    except (OSError, sqlite3.Error) as exc:
        raise BackupManifestError(f"SQLite artifact validation failed: {path}") from exc
    if rows != [("ok",)]:
        raise BackupManifestError(f"SQLite quick_check rejected artifact: {path}")
    if (
        application_id is None
        or user_version is None
        or journal_mode is None
        or page_count is None
        or page_size is None
    ):
        raise BackupManifestError(f"SQLite artifact metadata is incomplete: {path}")
    mode = str(journal_mode[0]).lower()
    if mode not in {"delete", "persist"}:
        raise BackupManifestError(f"SQLite artifact journal mode is unsafe: {path}")
    return {
        "applicationId": int(application_id[0]),
        "userVersion": int(user_version[0]),
        "journalMode": mode,
        "quickCheck": "ok",
    }


def _artifact_record(
    path: Path,
    spec: ArtifactSpec,
    *,
    expected_size: int | None = None,
) -> dict[str, object]:
    initial_info = _assert_regular_file(path)
    if expected_size is not None and int(initial_info.st_size) != expected_size:
        raise BackupManifestError(
            "artifact size changed after the declared-size preflight"
        )
    if spec.kind == "sqlite" and int(initial_info.st_size) > MAX_SQLITE_ARTIFACT_BYTES:
        raise BackupManifestError(f"SQLite artifact exceeds its byte limit: {path}")
    first_size, first_digest = _fingerprint_file(path, expected_size=expected_size)
    sqlite_evidence = _sqlite_evidence(path) if spec.kind == "sqlite" else None
    second_size, second_digest = _fingerprint_file(path, expected_size=expected_size)
    if (first_size, first_digest) != (second_size, second_digest):
        raise BackupManifestError("artifact changed during metadata validation")
    return {
        "logicalPath": spec.logical_path,
        "role": spec.role,
        "kind": spec.kind,
        "byteLength": first_size,
        "sha256": first_digest,
        "restorePolicy": spec.restore_policy,
        "sqlite": sqlite_evidence,
    }


def _validate_specs(specs: Sequence[ArtifactSpec]) -> tuple[ArtifactSpec, ...]:
    values = tuple(specs)
    if not values or len(values) > MAX_ARTIFACTS:
        raise BackupManifestError("artifact count is outside the allowed range")
    keys: set[str] = set()
    roles: dict[str, int] = {}
    normalized: list[ArtifactSpec] = []
    for raw in values:
        if not isinstance(raw, ArtifactSpec):
            raise BackupManifestError("artifact specifications must be ArtifactSpec values")
        logical_path = _logical_path(raw.logical_path)
        collision_key = logical_path.casefold()
        if collision_key in keys:
            raise BackupManifestError("artifact logical path collision")
        keys.add(collision_key)
        if raw.role in _FORBIDDEN_V1_ROLES:
            raise BackupManifestError(
                f"artifact role is forbidden in capture v1: {raw.role}"
            )
        expected = _ROLE_POLICY.get(raw.role)
        if expected is None:
            raise BackupManifestError("artifact role is not in the closed set")
        if (raw.kind, raw.restore_policy) != expected:
            raise BackupManifestError("artifact kind or restore policy conflicts with its role")
        roles[raw.role] = roles.get(raw.role, 0) + 1
        normalized.append(raw)
    if set(_ROLE_CARDINALITY) != set(_ROLE_POLICY):
        raise BackupManifestError("internal artifact role cardinality contract is incomplete")
    for role, (minimum, maximum) in _ROLE_CARDINALITY.items():
        count = roles.get(role, 0)
        if count < minimum or count > maximum:
            if minimum == maximum == 1:
                raise BackupManifestError(
                    f"required role must occur exactly once: {role}"
                )
            raise BackupManifestError(f"artifact role cardinality is invalid: {role}")
    result = tuple(sorted(normalized, key=lambda item: item.logical_path))
    path_set = {item.logical_path for item in result}
    expected_directories = _expected_directories(path_set)
    conflict = path_set.intersection(expected_directories)
    if conflict:
        raise BackupManifestError(
            "artifact path cannot be both a file and a parent directory"
        )
    child_counts: dict[str, int] = {}
    for logical_path in path_set | expected_directories:
        parent, _separator, _leaf = logical_path.rpartition("/")
        child_counts[parent] = child_counts.get(parent, 0) + 1
        if child_counts[parent] > _MAX_DIRECTORY_CHILDREN:
            raise BackupManifestError("artifact directory exceeds the child limit")

    by_role: dict[str, tuple[ArtifactSpec, ...]] = {
        role: tuple(item for item in result if item.role == role)
        for role in _ROLE_POLICY
    }
    for role, expected_path in _FIXED_ROLE_PATHS.items():
        if by_role[role][0].logical_path != expected_path:
            raise BackupManifestError(
                f"artifact role is not bound to its canonical path: {role}"
            )
    gateway_ledger = next(item for item in result if item.role == "gateway_ledger")
    gateway_anchor = next(
        item for item in result if item.role == "gateway_rollback_anchor"
    )
    if gateway_anchor.logical_path != f"{gateway_ledger.logical_path}.rollback-anchor":
        raise BackupManifestError(
            "gateway rollback anchor path is not bound to its ledger path"
        )
    active_capacity_path = by_role["desktop_capacity_active_slot"][0].logical_path
    allowed_slots = {
        f"{_DESKTOP_CAPACITY_SLOT_PREFIX}a",
        f"{_DESKTOP_CAPACITY_SLOT_PREFIX}b",
    }
    if active_capacity_path not in allowed_slots:
        raise BackupManifestError(
            "desktop capacity active slot is not bound to a canonical slot path"
        )
    inactive_capacity = by_role["desktop_capacity_inactive_slot"]
    if inactive_capacity:
        inactive_path = inactive_capacity[0].logical_path
        if inactive_path not in allowed_slots or inactive_path == active_capacity_path:
            raise BackupManifestError(
                "desktop capacity inactive slot is not the alternate canonical slot"
            )
    allowed_vault_directories = {
        "archives",
        "asset-validations",
        "assets",
        "claims",
        "cleanup-pending",
        "discoveries",
        "legacy-imports",
        "presentations",
        "video-tasks",
        "video-terminals",
    }
    for item in by_role["desktop_vault_entry"]:
        if not item.logical_path.startswith(_DESKTOP_VAULT_PREFIX):
            raise BackupManifestError(
                "desktop vault entry is outside the canonical vault path"
            )
        relative = item.logical_path[len(_DESKTOP_VAULT_PREFIX) :]
        parts = relative.split("/")
        if len(parts) < 2 or parts[0] not in allowed_vault_directories:
            raise BackupManifestError(
                "desktop vault entry is outside the allowed vault directories"
            )
    recovery_leaf = re.compile(r"^[0-9a-f]{64}\.prepared-intent\.json$")
    for item in by_role["desktop_recovery_intent"]:
        if not item.logical_path.startswith(_DESKTOP_RECOVERY_PREFIX):
            raise BackupManifestError(
                "desktop recovery intent is outside its canonical directory"
            )
        relative = item.logical_path[len(_DESKTOP_RECOVERY_PREFIX) :]
        if "/" in relative or recovery_leaf.fullmatch(relative) is None:
            raise BackupManifestError("desktop recovery intent leaf is invalid")
    return result


def _validate_credential_role_policy(
    specs: Sequence[ArtifactSpec],
    disposition: str,
) -> None:
    roles = {item.role for item in specs}
    forbidden = roles.intersection(_FORBIDDEN_V1_ROLES)
    if forbidden:
        raise BackupManifestError(
            "credential, configuration, updater and signing-key artifacts are "
            "forbidden in capture v1"
        )


def _expected_directories(paths: Iterable[str]) -> set[str]:
    directories: set[str] = set()
    for logical_path in paths:
        parts = logical_path.split("/")[:-1]
        for length in range(1, len(parts) + 1):
            directories.add("/".join(parts[:length]))
    return directories


def _normalize_artifact_root(value: str | os.PathLike[str]) -> Path:
    try:
        candidate = Path(os.fspath(value))
    except (TypeError, ValueError) as exc:
        raise BackupManifestError("artifact root path is invalid") from exc
    if not candidate.is_absolute():
        raise BackupManifestError("artifact root must be an absolute local path")
    absolute = Path(os.path.abspath(candidate))
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        raw = os.fspath(candidate)
        if raw.startswith("\\\\") or not absolute.drive:
            raise BackupManifestError("artifact root must be on a local Windows volume")
        get_drive_type = ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).GetDriveTypeW
        get_drive_type.argtypes = (wintypes.LPCWSTR,)
        get_drive_type.restype = wintypes.UINT
        if int(get_drive_type(absolute.anchor)) != 3:  # DRIVE_FIXED
            raise BackupManifestError("artifact root must be on a fixed local volume")
    return absolute


def _assert_no_reparse_parent_chain(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise BackupManifestError("artifact root parent chain is unavailable") from exc
        if _is_reparse_or_symlink(info):
            raise BackupManifestError(
                "artifact root parent chain contains a reparse point"
            )


def _tree_state(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        *_identity(info),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _scan_artifact_tree(
    root: Path,
    expected_paths: set[str],
    *,
    expected_sizes: dict[str, int] | None = None,
) -> tuple[
    tuple[int, int, int, int, int, int],
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
]:
    if not root.is_absolute():
        raise BackupManifestError("artifact root must be absolute before scanning")
    if expected_sizes is not None and set(expected_sizes) != expected_paths:
        raise BackupManifestError("declared artifact sizes do not match the path set")
    expected_directories = _expected_directories(expected_paths)
    if len(expected_paths) > MAX_ARTIFACTS:
        raise BackupManifestError("artifact count exceeds the scan limit")
    if len(expected_paths) + len(expected_directories) > _MAX_TREE_ENTRIES:
        raise BackupManifestError("artifact tree exceeds the entry limit")
    _assert_no_reparse_parent_chain(root)
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        raise BackupManifestError("artifact root is unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or _is_reparse_or_symlink(root_info):
        raise BackupManifestError("artifact root must be an ordinary directory")
    _assert_no_alternate_data_streams(root)

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    file_states: dict[str, tuple[int, int, int, int, int, int]] = {}
    directory_states: dict[str, tuple[int, int, int, int, int, int]] = {}
    total_file_bytes = 0
    total_entries = 0
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise BackupManifestError("artifact tree cannot be enumerated") from exc
        try:
            with entries:
                child_count = 0
                for entry in entries:
                    child_count += 1
                    total_entries += 1
                    if child_count > _MAX_DIRECTORY_CHILDREN:
                        raise BackupManifestError(
                            "artifact directory exceeds the child limit"
                        )
                    if total_entries > _MAX_TREE_ENTRIES:
                        raise BackupManifestError("artifact tree exceeds the entry limit")
                    logical_path = f"{prefix}/{entry.name}" if prefix else entry.name
                    _logical_path(logical_path)
                    if (
                        logical_path not in expected_paths
                        and logical_path not in expected_directories
                    ):
                        raise BackupManifestError(
                            "artifact tree contains an unexpected closed-set entry"
                        )
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise BackupManifestError(
                            "artifact tree entry is unavailable"
                        ) from exc
                    if _is_reparse_or_symlink(info):
                        raise BackupManifestError(
                            "artifact tree contains a symlink or reparse point"
                        )
                    path = Path(entry.path)
                    if stat.S_ISDIR(info.st_mode):
                        if logical_path not in expected_directories:
                            raise BackupManifestError(
                                "artifact file was replaced by a directory"
                            )
                        stable_info = os.lstat(path)
                        if not stat.S_ISDIR(
                            stable_info.st_mode
                        ) or _is_reparse_or_symlink(stable_info):
                            raise BackupManifestError(
                                "artifact directory identity changed during enumeration"
                            )
                        _assert_no_alternate_data_streams(path)
                        actual_directories.add(logical_path)
                        directory_states[logical_path] = _tree_state(stable_info)
                        pending.append((path, logical_path))
                    elif stat.S_ISREG(info.st_mode):
                        if logical_path not in expected_paths:
                            raise BackupManifestError(
                                "artifact directory was replaced by a file"
                            )
                        # On Windows, DirEntry.stat() reports st_nlink=0 even when
                        # os.lstat() exposes the real NTFS link count.
                        stable_info = _assert_regular_file(path)
                        actual_size = int(stable_info.st_size)
                        if (
                            expected_sizes is not None
                            and actual_size != expected_sizes[logical_path]
                        ):
                            raise BackupManifestError(
                                "artifact size does not match its declared byte length"
                            )
                        total_file_bytes += actual_size
                        if total_file_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                            raise BackupManifestError(
                                "artifact total byte limit exceeded"
                            )
                        actual_files.add(logical_path)
                        file_states[logical_path] = _tree_state(stable_info)
                    else:
                        raise BackupManifestError(
                            "artifact tree contains a special file"
                        )
        except BackupManifestError:
            raise
        except OSError as exc:
            raise BackupManifestError("artifact tree cannot be enumerated") from exc
    if actual_files != expected_paths:
        raise BackupManifestError("artifact tree does not match the closed set")
    if actual_directories != expected_directories:
        raise BackupManifestError("artifact directory tree does not match the closed set")
    return (
        _tree_state(root_info),
        tuple(sorted(directory_states.items())),
        tuple(sorted(file_states.items())),
    )


def _source_document(root: InstallationRootSnapshot) -> tuple[dict, dict]:
    if not isinstance(root, InstallationRootSnapshot):
        raise BackupManifestError("root snapshot type is invalid")
    if (
        root.status != "maintenance_locked"
        or root.lock_kind != "operator"
        or root.lock_reason_digest is None
        or root.reanchor_pending
        or root.reanchor_operation_digest is not None
        or root.reanchor_snapshot_digest is not None
        or root.reanchor_source_epoch is not None
    ):
        raise BackupManifestError("capture requires an operator maintenance lock")
    installation_id = _require_digest(root.installation_id, "installation id")
    owner_sid_digest = _require_digest(root.owner_sid_digest, "owner SID digest")
    lock_reason_digest = _require_digest(root.lock_reason_digest, "lock reason digest")
    epoch = _require_counter(root.epoch, "installation epoch", minimum=1)
    revision = _require_counter(root.root_revision, "root revision", minimum=1)
    if root.principal_digest != _v1_installation_principal(installation_id, epoch):
        raise BackupManifestError("installation principal does not match the root")
    components: dict[str, dict[str, object]] = {}
    if {item.component for item in root.components} != set(_V1_ROOT_COMPONENTS):
        raise BackupManifestError("root component set is invalid")
    for item in root.components:
        if (
            not item.bound
            or item.epoch != epoch
            or item.state_digest is None
            or item.recovery_floor is not None
            or item.recovery_state_digest is not None
        ):
            raise BackupManifestError("capture requires stable bound components")
        components[item.component] = {
            "identity": _require_digest(item.identity, f"{item.component} identity"),
            "epoch": epoch,
            "sequenceFloor": _require_counter(
                item.sequence_floor, f"{item.component} sequence floor"
            ),
            "stateDigest": _require_digest(
                item.state_digest, f"{item.component} state digest"
            ),
            "bound": True,
        }
    updater = root.updater
    source = {
        "installationId": installation_id,
        "epoch": epoch,
        "rootRevision": revision,
        "rootSchemaVersion": _V1_ROOT_SCHEMA_VERSION,
        "rootStatus": root.status,
        "rootLockKind": root.lock_kind,
        "rootLockReasonDigest": lock_reason_digest,
        "principalDigest": _require_digest(root.principal_digest, "principal digest"),
        "ownerSidDigest": owner_sid_digest,
        "updater": {
            "releaseSequence": _require_counter(
                updater.release_sequence, "updater release sequence"
            ),
            "keyringSequence": _require_counter(
                updater.keyring_sequence, "updater keyring sequence"
            ),
            "artifactDigest": _require_digest(
                updater.artifact_digest, "updater artifact digest", allow_zero=True
            ),
            "stateDigest": _require_digest(
                updater.state_digest, "updater state digest", allow_zero=True
            ),
        },
    }
    component_document = {
        "desktop": components["desktop"],
        "gateway": components["gateway"],
        "assetStore": {"proofStatus": "missing_root_binding"},
    }
    return source, component_document


def _validate_root_artifact_projection(
    path: Path,
    source: dict,
    components: dict,
) -> None:
    try:
        with closing(_immutable_connection(path)) as connection:
            connection.row_factory = sqlite3.Row
            page_count = connection.execute("PRAGMA page_count").fetchone()
            page_size = connection.execute("PRAGMA page_size").fetchone()
            if (
                page_count is None
                or page_size is None
                or int(page_count[0]) < 1
                or int(page_size[0]) < 512
                or int(page_count[0]) * int(page_size[0])
                > _V1_ROOT_MAX_DATABASE_BYTES
            ):
                raise sqlite3.DatabaseError(
                    "v1 installation-root page allocation exceeds its limit"
                )
            application_id = connection.execute(
                "PRAGMA application_id"
            ).fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if (
                application_id is None
                or user_version is None
                or int(application_id[0]) != _V1_ROOT_APPLICATION_ID
                or int(user_version[0]) != _V1_ROOT_SCHEMA_VERSION
            ):
                raise sqlite3.DatabaseError(
                    "v1 installation-root schema identity is invalid"
                )
            schema_rows = connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE type IN ('table','index','trigger','view') "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            actual_schema = {
                (str(row[0]), str(row[1])): row[2] for row in schema_rows
            }
            if set(actual_schema) != set(_V1_ROOT_EXPECTED_DDL):
                raise sqlite3.DatabaseError(
                    "v1 installation-root schema object set is invalid"
                )
            for identity, expected_ddl in _V1_ROOT_EXPECTED_DDL.items():
                if _canonical_sql(actual_schema[identity]) != _canonical_sql(
                    expected_ddl
                ):
                    raise sqlite3.DatabaseError(
                        "v1 installation-root schema definition is invalid"
                    )
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise sqlite3.DatabaseError(
                    "v1 installation-root database is corrupt"
                )

            root_rows = connection.execute(
                "SELECT * FROM installation_root"
            ).fetchall()
            component_rows = connection.execute(
                "SELECT * FROM installation_components ORDER BY component"
            ).fetchall()
            updater_rows = connection.execute(
                "SELECT * FROM installation_updater"
            ).fetchall()
            receipt_rows = connection.execute(
                "SELECT * FROM installation_reanchor_receipts ORDER BY target_epoch"
            ).fetchall()
            if (
                len(root_rows) != 1
                or len(component_rows) != len(_V1_ROOT_COMPONENTS)
                or len(updater_rows) != 1
                or len(receipt_rows) > _V1_ROOT_MAX_REANCHOR_RECEIPTS
            ):
                raise sqlite3.DatabaseError(
                    "v1 installation-root singleton rows are invalid"
                )

            root_row = root_rows[0]
            installation_id = _require_digest(
                root_row["installation_id"], "installation id"
            )
            owner_sid_digest = _require_digest(
                root_row["owner_sid_digest"], "owner SID digest"
            )
            epoch = _require_counter(
                root_row["epoch"], "installation epoch", minimum=1
            )
            root_revision = _require_counter(
                root_row["root_revision"], "root revision", minimum=1
            )
            lock_reason_digest = _require_digest(
                root_row["lock_reason_digest"], "root lock reason digest"
            )
            if (
                root_row["singleton"] != 1
                or root_row["schema_version"] != _V1_ROOT_SCHEMA_VERSION
                or owner_sid_digest != str(source["ownerSidDigest"])
                or root_row["status"] != "maintenance_locked"
                or root_row["lock_kind"] != "operator"
                or root_row["reanchor_pending"] != 0
                or root_row["reanchor_operation_digest"] is not None
                or root_row["reanchor_snapshot_digest"] is not None
                or root_row["reanchor_source_epoch"] is not None
            ):
                raise sqlite3.DatabaseError(
                    "v1 installation-root capture state is invalid"
                )

            expected_targets = list(range(2, epoch + 1))
            if [int(row["target_epoch"]) for row in receipt_rows] != expected_targets:
                raise sqlite3.DatabaseError(
                    "v1 installation-root receipt chain is incomplete"
                )
            seen_operations: set[str] = set()
            seen_snapshots: set[str] = set()
            seen_final_proofs: set[str] = set()
            previous_revision = 0
            for receipt in receipt_rows:
                target_epoch = _require_counter(
                    receipt["target_epoch"],
                    "reanchor receipt target epoch",
                    minimum=2,
                )
                source_epoch = _require_counter(
                    receipt["source_epoch"],
                    "reanchor receipt source epoch",
                    minimum=1,
                )
                operation_digest = _require_digest(
                    receipt["operation_digest"],
                    "reanchor receipt operation digest",
                )
                snapshot_digest = _require_digest(
                    receipt["snapshot_digest"],
                    "reanchor receipt snapshot digest",
                )
                final_proof_digest = _require_digest(
                    receipt["final_proof_digest"],
                    "reanchor receipt final proof digest",
                )
                completed_revision = _require_counter(
                    receipt["completed_root_revision"],
                    "reanchor receipt root revision",
                    minimum=1,
                )
                if (
                    target_epoch != source_epoch + 1
                    or completed_revision <= previous_revision
                    or completed_revision > root_revision
                    or operation_digest in seen_operations
                    or snapshot_digest in seen_snapshots
                    or final_proof_digest in seen_final_proofs
                ):
                    raise sqlite3.DatabaseError(
                        "v1 installation-root receipt chain is inconsistent"
                    )
                previous_revision = completed_revision
                seen_operations.add(operation_digest)
                seen_snapshots.add(snapshot_digest)
                seen_final_proofs.add(final_proof_digest)

            actual_component_document: dict[str, dict[str, object]] = {}
            if {str(row["component"]) for row in component_rows} != set(
                _V1_ROOT_COMPONENTS
            ):
                raise sqlite3.DatabaseError(
                    "v1 installation-root component set is invalid"
                )
            for component_row in component_rows:
                component = str(component_row["component"])
                if (
                    component_row["epoch"] != epoch
                    or component_row["bound"] != 1
                    or component_row["recovery_floor"] is not None
                    or component_row["recovery_state_digest"] is not None
                ):
                    raise sqlite3.DatabaseError(
                        "v1 installation-root component binding is unstable"
                    )
                actual_component_document[component] = {
                    "identity": _require_digest(
                        component_row["identity"], f"{component} identity"
                    ),
                    "epoch": epoch,
                    "sequenceFloor": _require_counter(
                        component_row["sequence_floor"],
                        f"{component} sequence floor",
                    ),
                    "stateDigest": _require_digest(
                        component_row["state_digest"],
                        f"{component} state digest",
                    ),
                    "bound": True,
                }
            updater_row = updater_rows[0]
            if updater_row["singleton"] != 1:
                raise sqlite3.DatabaseError(
                    "v1 installation-root updater singleton is invalid"
                )
            actual_source = {
                "installationId": installation_id,
                "epoch": epoch,
                "rootRevision": root_revision,
                "rootSchemaVersion": _V1_ROOT_SCHEMA_VERSION,
                "rootStatus": "maintenance_locked",
                "rootLockKind": "operator",
                "rootLockReasonDigest": lock_reason_digest,
                "principalDigest": _v1_installation_principal(
                    installation_id, epoch
                ),
                "ownerSidDigest": owner_sid_digest,
                "updater": {
                    "releaseSequence": _require_counter(
                        updater_row["release_sequence"],
                        "updater release sequence",
                    ),
                    "keyringSequence": _require_counter(
                        updater_row["keyring_sequence"],
                        "updater keyring sequence",
                    ),
                    "artifactDigest": _require_digest(
                        updater_row["artifact_digest"],
                        "updater artifact digest",
                        allow_zero=True,
                    ),
                    "stateDigest": _require_digest(
                        updater_row["state_digest"],
                        "updater state digest",
                        allow_zero=True,
                    ),
                },
            }
            actual_components = {
                "desktop": actual_component_document["desktop"],
                "gateway": actual_component_document["gateway"],
                "assetStore": {"proofStatus": "missing_root_binding"},
            }
    except Exception as exc:
        raise BackupManifestError(
            "installation-root evidence failed closed-schema validation"
        ) from exc
    if actual_source != source or actual_components != components:
        raise BackupManifestError(
            "installation-root evidence does not match the manifest root projection"
        )


def _immutable_connection(path: Path) -> sqlite3.Connection:
    uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA foreign_keys=ON")
    if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
        connection.close()
        raise BackupManifestError("SQLite foreign-key enforcement is unavailable")
    return connection


def _validate_gateway_artifact_projection(
    path: Path,
    source: dict,
    components: dict,
) -> None:
    """Validate the historical Gateway v4 authority without upstream drift."""

    try:
        with closing(_immutable_connection(path)) as connection:
            application_id = connection.execute(
                "PRAGMA application_id"
            ).fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if (
                application_id is None
                or user_version is None
                or int(application_id[0]) != _V1_GATEWAY_APPLICATION_ID
                or int(user_version[0]) != _V1_GATEWAY_SCHEMA_VERSION
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway schema identity is invalid"
                )
            request_columns = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_xinfo(durable_media_requests)"
                )
            )
            meta_columns = tuple(
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_xinfo(durable_media_requests_meta)"
                )
            )
            if (
                request_columns != _V1_GATEWAY_REQUEST_COLUMNS
                or meta_columns != _V1_GATEWAY_META_COLUMNS
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway schema columns are invalid"
                )
            schema_rows = connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE type IN ('table','index','trigger') "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            actual_schema = {
                (str(row[0]), str(row[1])): row[2] for row in schema_rows
            }
            if tuple(sorted(actual_schema)) != _V1_GATEWAY_SCHEMA_OBJECTS:
                raise sqlite3.DatabaseError(
                    "v1 gateway schema object set is invalid"
                )
            if (
                _v1_gateway_schema_ddl_sha256(actual_schema)
                != _V1_GATEWAY_SCHEMA_DDL_SHA256
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway schema definition is invalid"
                )
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise sqlite3.DatabaseError("v1 gateway database is corrupt")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise sqlite3.DatabaseError(
                    "v1 gateway foreign-key graph is invalid"
                )

            meta = connection.execute(
                "SELECT schema_version,schema_fingerprint,database_identity,"
                "mutation_sequence,authority_state_digest,authority_mode,"
                "authority_installation_id,authority_epoch,authority_recovery_floor,"
                "authority_recovery_state_digest,record_count,response_bytes,"
                "reserved_bytes,max_records,max_response_bytes,"
                "max_total_response_bytes,max_database_bytes "
                "FROM durable_media_requests_meta WHERE singleton=1"
            ).fetchone()
            if (
                meta is None
                or meta[0] != _V1_GATEWAY_SCHEMA_VERSION
                or meta[1] != _V1_GATEWAY_SCHEMA_FINGERPRINT
                or not isinstance(meta[2], str)
                or _DIGEST_RE.fullmatch(meta[2]) is None
                or meta[2] == "0" * 64
                or not isinstance(meta[3], int)
                or isinstance(meta[3], bool)
                or not 0 <= int(meta[3]) <= _V1_GATEWAY_MAX_MUTATION_SEQUENCE
                or not isinstance(meta[4], str)
                or _DIGEST_RE.fullmatch(meta[4]) is None
                or meta[4] == "0" * 64
                or meta[5] not in {"normal", "manual_only"}
                or any(
                    not isinstance(value, int) or isinstance(value, bool)
                    for value in meta[10:17]
                )
                or any(int(value) < 0 for value in meta[10:13])
                or not 1 <= int(meta[13]) <= 1_000_000
                or not 64 <= int(meta[14]) <= 128 * 1024 * 1024
                or not 256 * 1024
                <= int(meta[16])
                <= _V1_GATEWAY_DEFAULT_MAX_DATABASE_BYTES
                or not 64 <= int(meta[15]) <= int(meta[16]) // 2
                or int(meta[14]) > int(meta[15])
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway capacity metadata is invalid"
                )
            if meta[5] == "normal":
                if any(value is not None for value in meta[6:10]):
                    raise sqlite3.DatabaseError(
                        "v1 gateway normal authority receipt is invalid"
                    )
            elif (
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
                    "v1 gateway manual authority receipt is invalid"
                )
            actual_usage = connection.execute(
                "SELECT COUNT(*),"
                "COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
                "COALESCE(SUM(reserved_response_bytes),0) "
                "FROM durable_media_requests"
            ).fetchone()
            if (
                actual_usage != tuple(meta[10:13])
                or int(meta[10]) > int(meta[13])
                or int(meta[11]) + int(meta[12]) > int(meta[15])
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway capacity counters are corrupt"
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
                or not isinstance(asset_capacity[0], int)
                or isinstance(asset_capacity[0], bool)
                or not _V1_ASSET_OPERATION_RESERVATION_BYTES
                <= int(asset_capacity[0])
                <= 1024 * 1024 * 1024 * 1024
                or not isinstance(asset_capacity[1], int)
                or isinstance(asset_capacity[1], bool)
                or not 0 <= int(asset_capacity[1]) <= int(asset_capacity[0])
                or asset_usage != (int(asset_capacity[1]),)
            ):
                raise sqlite3.DatabaseError(
                    "v1 gateway asset capacity counters are corrupt"
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
                    "v1 gateway asset authority is inconsistent"
                )
            authoritative_video_rows = connection.execute(
                "SELECT r.response_json,length(CAST(r.response_json AS BLOB)),"
                "r.turn_id,a.state,a.token_set_digest FROM durable_media_requests r "
                "JOIN durable_media_asset_authority a ON a.turn_id=r.turn_id "
                "WHERE r.operation='videos.create' AND r.status='succeeded'"
            ).fetchall()
            for (
                raw_response,
                encoded_bytes,
                turn_id,
                asset_state,
                token_digest,
            ) in authoritative_video_rows:
                metadata = _v1_gateway_decode_video_metadata(
                    raw_response,
                    encoded_bytes,
                    expected_turn_id=str(turn_id),
                    max_response_bytes=int(meta[14]),
                )
                terminal = metadata.get("terminal_response")
                if asset_state == "reserved":
                    if token_digest is not None or (
                        terminal is not None
                        and (
                            not isinstance(terminal, dict)
                            or not _v1_gateway_is_video_terminal_failure(terminal)
                        )
                    ):
                        raise sqlite3.DatabaseError(
                            "v1 gateway nonterminal video authority is invalid"
                        )
                    continue
                if not isinstance(terminal, dict):
                    raise sqlite3.DatabaseError(
                        "v1 gateway terminal video authority is missing"
                    )
                try:
                    parsed_terminal = parse_asset_result(terminal)
                except PaidMediaAssetProtocolError as exc:
                    raise sqlite3.DatabaseError(
                        "v1 gateway terminal video authority is corrupt"
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
                        "v1 gateway terminal video authority does not match its result"
                    )

            authority = (str(meta[2]), int(meta[3]), str(meta[4]))
            anchor_path = Path(f"{path.absolute()}.rollback-anchor")
            with anchor_path.open("rb") as stream:
                raw_anchor = stream.read(_V1_GATEWAY_ANCHOR_MAX_BYTES + 1)
            if not raw_anchor or len(raw_anchor) > _V1_GATEWAY_ANCHOR_MAX_BYTES:
                raise OSError("v1 gateway rollback anchor size is invalid")
            decoded_anchor = json.loads(raw_anchor.decode("utf-8"))
            if not isinstance(decoded_anchor, dict) or set(decoded_anchor) != {
                "authority_state_digest",
                "database_identity",
                "format",
                "mutation_sequence",
            }:
                raise ValueError("v1 gateway rollback anchor fields are invalid")
            encoded_sequence = decoded_anchor.get("mutation_sequence")
            if (
                decoded_anchor.get("format") != _V1_GATEWAY_ANCHOR_FORMAT
                or not isinstance(encoded_sequence, str)
                or re.fullmatch(r"[0-9a-f]{16}", encoded_sequence) is None
            ):
                raise ValueError("v1 gateway rollback anchor format is invalid")
            anchor_authority = (
                decoded_anchor.get("database_identity"),
                int(encoded_sequence, 16),
                decoded_anchor.get("authority_state_digest"),
            )
            if (
                raw_anchor != _v1_gateway_anchor_bytes(*anchor_authority)
                or anchor_authority != authority
            ):
                raise OSError(
                    "v1 gateway rollback anchor does not match the database"
                )
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise BackupManifestError(
            "gateway ledger failed closed-schema or rollback-anchor validation"
        ) from exc
    expected = components["gateway"]
    if authority != (
        expected["identity"],
        expected["sequenceFloor"],
        expected["stateDigest"],
    ):
        raise BackupManifestError(
            "gateway ledger does not match the installation-root projection"
        )
    if expected["epoch"] != source["epoch"] or expected["bound"] is not True:
        raise BackupManifestError("gateway root binding is not stable")


def _validate_asset_store_projection(
    path: Path,
    source: dict,
    records: Sequence[dict],
    database_logical_path: str,
) -> None:
    """Validate the exact asset schema while retaining its explicit Root gap."""

    try:
        with closing(_immutable_connection(path)) as connection:
            application_id = connection.execute(
                "PRAGMA application_id"
            ).fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if (
                application_id is None
                or user_version is None
                or int(application_id[0]) != _V1_ASSET_APPLICATION_ID
                or int(user_version[0]) != _V1_ASSET_SCHEMA_VERSION
            ):
                raise sqlite3.DatabaseError(
                    "v1 asset-store schema identity is invalid"
                )
            schema_rows = connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE type IN ('table','index','trigger') "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            actual_schema = {
                (str(row[0]), str(row[1])): row[2] for row in schema_rows
            }
            if set(actual_schema) != set(_V1_ASSET_EXPECTED_DDL):
                raise sqlite3.DatabaseError(
                    "v1 asset-store schema object set is invalid"
                )
            for identity, expected_ddl in _V1_ASSET_EXPECTED_DDL.items():
                if _canonical_sql(actual_schema[identity]) != _canonical_sql(
                    expected_ddl
                ):
                    raise sqlite3.DatabaseError(
                        "v1 asset-store schema definition is invalid"
                    )
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise sqlite3.DatabaseError("v1 asset-store database is corrupt")
            meta = connection.execute(
                "SELECT schema,installation_id,epoch,max_capacity_bytes,"
                "reserved_total_bytes "
                "FROM asset_store_meta WHERE singleton=1"
            ).fetchone()
            if (
                meta is None
                or tuple(meta[:3])
                != (
                    _V1_ASSET_STORE_SCHEMA,
                    str(source["installationId"]),
                    int(source["epoch"]),
                )
                or not isinstance(meta[3], int)
                or isinstance(meta[3], bool)
                or int(meta[3]) < _V1_ASSET_OPERATION_RESERVATION_BYTES
                or not isinstance(meta[4], int)
                or isinstance(meta[4], bool)
                or not 0 <= int(meta[4]) <= int(meta[3])
            ):
                raise sqlite3.DatabaseError("v1 asset-store metadata is invalid")
            usage = connection.execute(
                "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
            ).fetchone()
            if usage is None or int(usage[0]) != int(meta[4]):
                raise sqlite3.DatabaseError(
                    "v1 asset-store reservation counter is corrupt"
                )
            pending_mismatch = connection.execute(
                "SELECT COUNT(*) FROM asset_pending_commits p "
                "LEFT JOIN asset_reservations r ON r.turn_id=p.turn_id "
                "WHERE r.turn_id IS NULL OR r.state<>'active'"
            ).fetchone()
            if pending_mismatch != (0,):
                raise sqlite3.DatabaseError(
                    "v1 asset-store pending commit is inconsistent"
                )
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise sqlite3.DatabaseError(
                    "asset-store foreign-key check rejected the database"
                )
            actual_byte_mismatches = int(
                connection.execute(
                    "SELECT COUNT(*) FROM asset_reservations r WHERE "
                    "r.actual_bytes<>(SELECT COALESCE(SUM(a.byte_length),0) "
                    "FROM paid_media_assets a WHERE a.turn_id=r.turn_id)"
                ).fetchone()[0]
            )
            pending_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM asset_pending_commits"
                ).fetchone()[0]
            )
            lease_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM asset_read_leases"
                ).fetchone()[0]
            )
            asset_rows = connection.execute(
                "SELECT object_leaf,byte_length,sha256 FROM paid_media_assets "
                "ORDER BY object_leaf"
            ).fetchall()
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise BackupManifestError(
            "asset-store database failed closed-schema validation"
        ) from exc
    if pending_count != 0 or lease_count != 0 or actual_byte_mismatches != 0:
        raise BackupManifestError(
            "asset-store capture requires closed byte counters and no pending work"
        )
    object_prefix = database_logical_path.rsplit("/", 1)[0] + "/objects/"
    expected_objects: dict[str, tuple[int, str]] = {}
    for leaf, byte_length, object_digest in asset_rows:
        if (
            not isinstance(leaf, str)
            or _V1_ASSET_LEAF_RE.fullmatch(leaf) is None
        ):
            raise BackupManifestError("asset-store object leaf is invalid")
        logical_path = object_prefix + leaf
        if logical_path in expected_objects:
            raise BackupManifestError("asset-store object path is duplicated")
        expected_objects[logical_path] = (
            _require_counter(byte_length, "asset-store object byte length", minimum=1),
            _require_digest(object_digest, "asset-store object SHA-256"),
        )
    actual_objects = {
        str(item["logicalPath"]): (
            int(item["byteLength"]),
            str(item["sha256"]),
        )
        for item in records
        if item["role"] == "asset_store_object"
    }
    if actual_objects != expected_objects:
        raise BackupManifestError(
            "asset-store object artifacts do not match the database closed set"
        )
    asset_scope = database_logical_path.rsplit("/", 1)[0] + "/"
    scoped_paths = {
        str(item["logicalPath"])
        for item in records
        if str(item["logicalPath"]).startswith(asset_scope)
    }
    if scoped_paths != {database_logical_path, *expected_objects}:
        raise BackupManifestError(
            "asset-store artifact directory contains an out-of-contract role"
        )


def _validate_artifact_records(value: object) -> list[dict]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARTIFACTS:
        raise BackupManifestError("manifest artifact count is invalid")
    specs: list[ArtifactSpec] = []
    records: list[dict] = []
    total_bytes = 0
    previous_path: str | None = None
    for raw in value:
        record = _require_exact_keys(
            raw,
            {
                "logicalPath",
                "role",
                "kind",
                "byteLength",
                "sha256",
                "restorePolicy",
                "sqlite",
            },
            "artifact record",
        )
        path = _logical_path(record["logicalPath"])
        if previous_path is not None and path <= previous_path:
            raise BackupManifestError("artifact records are not canonically sorted")
        previous_path = path
        role = record["role"]
        kind = record["kind"]
        policy = record["restorePolicy"]
        if not all(isinstance(item, str) for item in (role, kind, policy)):
            raise BackupManifestError("artifact role, kind and policy must be strings")
        specs.append(ArtifactSpec(path, role, kind, policy))
        byte_length = _require_counter(
            record["byteLength"], "artifact byte length"
        )
        if byte_length > MAX_ARTIFACT_BYTES:
            raise BackupManifestError("artifact file exceeds the byte limit")
        total_bytes += byte_length
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise BackupManifestError("artifact total byte limit exceeded")
        _require_digest(record["sha256"], "artifact SHA-256")
        if kind == "sqlite":
            if byte_length > MAX_SQLITE_ARTIFACT_BYTES:
                raise BackupManifestError("SQLite artifact exceeds its byte limit")
            sqlite_value = _require_exact_keys(
                record["sqlite"],
                {"applicationId", "userVersion", "journalMode", "quickCheck"},
                "SQLite artifact evidence",
            )
            _require_counter(
                sqlite_value["applicationId"], "SQLite application id"
            )
            _require_counter(sqlite_value["userVersion"], "SQLite user version")
            if sqlite_value["journalMode"] not in {"delete", "persist"}:
                raise BackupManifestError("SQLite journal mode is invalid")
            if sqlite_value["quickCheck"] != "ok":
                raise BackupManifestError("SQLite quick_check evidence is invalid")
        elif record["sqlite"] is not None:
            raise BackupManifestError("non-SQLite artifact contains SQLite evidence")
        records.append(record)
    _validate_specs(specs)
    root_record = next(
        item for item in records if item["role"] == "installation_root_evidence"
    )
    if root_record["sqlite"] != {
        "applicationId": _V1_ROOT_APPLICATION_ID,
        "userVersion": _V1_ROOT_SCHEMA_VERSION,
        "journalMode": "delete",
        "quickCheck": "ok",
    }:
        raise BackupManifestError("installation-root SQLite evidence is invalid")
    expected_sqlite_identities = {
        "gateway_ledger": (
            _V1_GATEWAY_APPLICATION_ID,
            _V1_GATEWAY_SCHEMA_VERSION,
        ),
        "asset_store_database": (
            _V1_ASSET_APPLICATION_ID,
            _V1_ASSET_SCHEMA_VERSION,
        ),
    }
    for role, (application_id, user_version) in expected_sqlite_identities.items():
        record = next(item for item in records if item["role"] == role)
        sqlite_value = record["sqlite"]
        if (
            sqlite_value["applicationId"] != application_id
            or sqlite_value["userVersion"] != user_version
        ):
            raise BackupManifestError(f"{role} SQLite role identity is invalid")
    return records


def _validate_source(value: object) -> dict:
    source = _require_exact_keys(
        value,
        {
            "installationId",
            "epoch",
            "rootRevision",
            "rootSchemaVersion",
            "rootStatus",
            "rootLockKind",
            "rootLockReasonDigest",
            "principalDigest",
            "ownerSidDigest",
            "updater",
        },
        "manifest source",
    )
    installation_id = _require_digest(source["installationId"], "installation id")
    epoch = _require_counter(source["epoch"], "installation epoch", minimum=1)
    _require_counter(source["rootRevision"], "root revision", minimum=1)
    if source["rootSchemaVersion"] != _V1_ROOT_SCHEMA_VERSION:
        raise BackupManifestError("root schema version is unsupported")
    if source["rootStatus"] != "maintenance_locked" or source["rootLockKind"] != "operator":
        raise BackupManifestError("manifest source is not operator maintenance locked")
    _require_digest(source["rootLockReasonDigest"], "root lock reason digest")
    _require_digest(source["ownerSidDigest"], "owner SID digest")
    if source["principalDigest"] != _v1_installation_principal(
        installation_id, epoch
    ):
        raise BackupManifestError("manifest principal does not match installation epoch")
    updater = _require_exact_keys(
        source["updater"],
        {"releaseSequence", "keyringSequence", "artifactDigest", "stateDigest"},
        "updater projection",
    )
    _require_counter(updater["releaseSequence"], "updater release sequence")
    _require_counter(updater["keyringSequence"], "updater keyring sequence")
    _require_digest(updater["artifactDigest"], "updater artifact digest", allow_zero=True)
    _require_digest(updater["stateDigest"], "updater state digest", allow_zero=True)
    return source


def _validate_components(value: object, source: dict) -> dict:
    components = _require_exact_keys(
        value, {"desktop", "gateway", "assetStore"}, "component projection"
    )
    epoch = int(source["epoch"])
    for name in ("desktop", "gateway"):
        component = _require_exact_keys(
            components[name],
            {"identity", "epoch", "sequenceFloor", "stateDigest", "bound"},
            f"{name} component projection",
        )
        _require_digest(component["identity"], f"{name} identity")
        _require_digest(component["stateDigest"], f"{name} state digest")
        _require_counter(component["sequenceFloor"], f"{name} sequence floor")
        if component["epoch"] != epoch or component["bound"] is not True:
            raise BackupManifestError(f"{name} component is not bound to the source epoch")
    if components["assetStore"] != {"proofStatus": "missing_root_binding"}:
        raise BackupManifestError("asset-store proof status is not the required explicit gap")
    return components


def _validate_manifest(value: object, *, verify_digest: bool = True) -> dict:
    manifest = _require_exact_keys(
        value,
        {
            "schema",
            "snapshotId",
            "createdAtUnixMs",
            "capability",
            "captureReady",
            "captureProofStatus",
            "missingCaptureProofs",
            "restoreReady",
            "source",
            "components",
            "quiescence",
            "credentials",
            "artifacts",
            "artifactSetDigest",
            "missingRestoreProofs",
            "manifestSha256",
        },
        "capture manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise BackupManifestError("manifest schema is unsupported")
    if not isinstance(manifest["snapshotId"], str) or _SNAPSHOT_RE.fullmatch(
        manifest["snapshotId"]
    ) is None:
        raise BackupManifestError("snapshot id is invalid")
    _require_counter(manifest["createdAtUnixMs"], "creation timestamp")
    if (
        manifest["capability"] != "capture_only"
        or manifest["captureReady"] is not False
        or manifest["captureProofStatus"] != "partial"
        or manifest["restoreReady"] is not False
    ):
        raise BackupManifestError("v1 manifest must remain capture-only")
    if manifest["missingCaptureProofs"] != sorted(
        REQUIRED_MISSING_CAPTURE_PROOFS
    ):
        raise BackupManifestError("missing capture proofs are not the closed v1 set")
    source = _validate_source(manifest["source"])
    _validate_components(manifest["components"], source)
    quiescence = _require_exact_keys(
        manifest["quiescence"],
        {"status", "writersStoppedClaimed", "evidenceDigest"},
        "quiescence proof",
    )
    if (
        quiescence["status"] != "external_evidence_bound"
        or quiescence["writersStoppedClaimed"] is not True
    ):
        raise BackupManifestError("external quiescence evidence commitment is required")
    _require_digest(quiescence["evidenceDigest"], "quiescence evidence digest")
    credentials = _require_exact_keys(
        manifest["credentials"],
        {"disposition", "receiptDigest"},
        "credential disposition",
    )
    if credentials["disposition"] not in {"excluded", "reconfigure_required"}:
        raise BackupManifestError("credential disposition is not implemented")
    _require_digest(credentials["receiptDigest"], "credential disposition receipt")
    records = _validate_artifact_records(manifest["artifacts"])
    _validate_credential_role_policy(
        tuple(
            ArtifactSpec(
                str(item["logicalPath"]),
                str(item["role"]),
                str(item["kind"]),
                str(item["restorePolicy"]),
            )
            for item in records
        ),
        str(credentials["disposition"]),
    )
    expected_set_digest = _digest(records, domain=_ARTIFACT_SET_DOMAIN)
    if manifest["artifactSetDigest"] != expected_set_digest:
        raise BackupManifestError("artifact set digest does not match")
    if manifest["missingRestoreProofs"] != sorted(REQUIRED_MISSING_RESTORE_PROOFS):
        raise BackupManifestError("missing restore proofs are not the closed v1 set")
    _require_digest(manifest["manifestSha256"], "manifest SHA-256")
    if verify_digest:
        unsigned = dict(manifest)
        del unsigned["manifestSha256"]
        expected_manifest_digest = _digest(unsigned, domain=_MANIFEST_DOMAIN)
        if manifest["manifestSha256"] != expected_manifest_digest:
            raise BackupManifestError("manifest SHA-256 does not match")
    return manifest


def build_capture_manifest(
    *,
    snapshot_id: str,
    created_at_unix_ms: int,
    root_snapshot: InstallationRootSnapshot,
    artifact_root: str | os.PathLike[str],
    artifact_specs: Sequence[ArtifactSpec],
    quiescence_digest: str,
    credential_disposition: str,
    credential_receipt_digest: str,
) -> bytes:
    """Build canonical bytes for an already-staged, closed artifact tree."""

    if not isinstance(snapshot_id, str) or _SNAPSHOT_RE.fullmatch(snapshot_id) is None:
        raise BackupManifestError("snapshot id is invalid")
    created_at = _require_counter(created_at_unix_ms, "creation timestamp")
    quiescence = _require_digest(quiescence_digest, "quiescence evidence digest")
    if credential_disposition not in {"excluded", "reconfigure_required"}:
        raise BackupManifestError("credential disposition is not implemented")
    credential_receipt = _require_digest(
        credential_receipt_digest, "credential disposition receipt"
    )
    source, components = _source_document(root_snapshot)
    specs = _validate_specs(artifact_specs)
    _validate_credential_role_policy(specs, credential_disposition)
    root = _normalize_artifact_root(artifact_root)
    expected_paths = {item.logical_path for item in specs}
    tree_before = _scan_artifact_tree(root, expected_paths)
    records = [
        _artifact_record(root.joinpath(*item.logical_path.split("/")), item)
        for item in specs
    ]
    root_spec = next(
        item for item in specs if item.role == "installation_root_evidence"
    )
    _validate_root_artifact_projection(
        root.joinpath(*root_spec.logical_path.split("/")),
        source,
        components,
    )
    gateway_spec = next(item for item in specs if item.role == "gateway_ledger")
    _validate_gateway_artifact_projection(
        root.joinpath(*gateway_spec.logical_path.split("/")),
        source,
        components,
    )
    asset_spec = next(item for item in specs if item.role == "asset_store_database")
    _validate_asset_store_projection(
        root.joinpath(*asset_spec.logical_path.split("/")),
        source,
        records,
        asset_spec.logical_path,
    )
    if _scan_artifact_tree(root, expected_paths) != tree_before:
        raise BackupManifestError("artifact tree changed during capture")
    total_bytes = sum(int(item["byteLength"]) for item in records)
    if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
        raise BackupManifestError("artifact total byte limit exceeded")
    artifact_set_digest = _digest(records, domain=_ARTIFACT_SET_DOMAIN)
    unsigned = {
        "schema": MANIFEST_SCHEMA,
        "snapshotId": snapshot_id,
        "createdAtUnixMs": created_at,
        "capability": "capture_only",
        "captureReady": False,
        "captureProofStatus": "partial",
        "missingCaptureProofs": sorted(REQUIRED_MISSING_CAPTURE_PROOFS),
        "restoreReady": False,
        "source": source,
        "components": components,
        "quiescence": {
            "status": "external_evidence_bound",
            "writersStoppedClaimed": True,
            "evidenceDigest": quiescence,
        },
        "credentials": {
            "disposition": credential_disposition,
            "receiptDigest": credential_receipt,
        },
        "artifacts": records,
        "artifactSetDigest": artifact_set_digest,
        "missingRestoreProofs": sorted(REQUIRED_MISSING_RESTORE_PROOFS),
    }
    manifest = dict(unsigned)
    manifest["manifestSha256"] = _digest(unsigned, domain=_MANIFEST_DOMAIN)
    _validate_manifest(manifest)
    encoded = canonical_json_bytes(manifest)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise BackupManifestError("manifest exceeds the byte limit")
    return encoded


def _no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BackupManifestError(f"duplicate JSON key in manifest: {key}")
        value[key] = item
    return value


def _reject_excessive_raw_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise BackupManifestError("manifest JSON exceeds the depth limit")
        elif character in "]}":
            depth -= 1


def _parse_canonical_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        raise ValueError("JSON integer token exceeds the canonical length")
    parsed = int(value, 10)
    if parsed < -_MAX_COUNTER or parsed > _MAX_COUNTER:
        raise ValueError("JSON integer is outside the canonical range")
    return parsed


def _reject_json_number(_value: str) -> float:
    raise ValueError("JSON floats and non-finite numbers are forbidden")


def load_capture_manifest(raw: bytes) -> dict:
    """Parse and validate exact canonical manifest bytes."""

    if not isinstance(raw, bytes):
        raise BackupManifestError("manifest input must be bytes")
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise BackupManifestError("manifest exceeds the byte limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise BackupManifestError("manifest UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
        _reject_excessive_raw_json_depth(text)
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_int=_parse_canonical_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except BackupManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise BackupManifestError("manifest JSON is invalid") from exc
    manifest = _validate_manifest(value)
    if canonical_json_bytes(manifest) != raw:
        raise BackupManifestError("manifest bytes are not canonical JSON")
    return manifest


def verify_capture_manifest(
    raw: bytes,
    artifact_root: str | os.PathLike[str],
) -> dict:
    """Rehash and re-inspect the exact closed artifact tree bound by ``raw``."""

    manifest = load_capture_manifest(raw)
    records = manifest["artifacts"]
    specs = tuple(
        ArtifactSpec(
            item["logicalPath"],
            item["role"],
            item["kind"],
            item["restorePolicy"],
        )
        for item in records
    )
    root = _normalize_artifact_root(artifact_root)
    expected_paths = {item.logical_path for item in specs}
    expected_sizes = {
        str(item["logicalPath"]): int(item["byteLength"])
        for item in records
    }
    tree_before = _scan_artifact_tree(
        root,
        expected_paths,
        expected_sizes=expected_sizes,
    )
    for expected, spec in zip(records, specs, strict=True):
        actual = _artifact_record(
            root.joinpath(*spec.logical_path.split("/")),
            spec,
            expected_size=int(expected["byteLength"]),
        )
        if actual != expected:
            if actual["byteLength"] != expected["byteLength"]:
                raise BackupManifestError("artifact size does not match manifest")
            if actual["sha256"] != expected["sha256"]:
                raise BackupManifestError("artifact SHA-256 does not match manifest")
            raise BackupManifestError("artifact SQLite metadata does not match manifest")
    root_spec = next(
        item for item in specs if item.role == "installation_root_evidence"
    )
    _validate_root_artifact_projection(
        root.joinpath(*root_spec.logical_path.split("/")),
        manifest["source"],
        manifest["components"],
    )
    gateway_spec = next(item for item in specs if item.role == "gateway_ledger")
    _validate_gateway_artifact_projection(
        root.joinpath(*gateway_spec.logical_path.split("/")),
        manifest["source"],
        manifest["components"],
    )
    asset_spec = next(item for item in specs if item.role == "asset_store_database")
    _validate_asset_store_projection(
        root.joinpath(*asset_spec.logical_path.split("/")),
        manifest["source"],
        records,
        asset_spec.logical_path,
    )
    if (
        _scan_artifact_tree(
            root,
            expected_paths,
            expected_sizes=expected_sizes,
        )
        != tree_before
    ):
        raise BackupManifestError("artifact tree changed during verification")
    return manifest


__all__ = [
    "ArtifactSpec",
    "BackupManifestError",
    "MANIFEST_SCHEMA",
    "REQUIRED_MISSING_CAPTURE_PROOFS",
    "REQUIRED_MISSING_RESTORE_PROOFS",
    "build_capture_manifest",
    "canonical_json_bytes",
    "load_capture_manifest",
    "verify_capture_manifest",
]
