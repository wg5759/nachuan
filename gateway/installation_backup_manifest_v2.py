"""Frozen Root-v5 capture-manifest wire contract.

Version 2 validates an already-staged Installation Root v5 authority and the
three Root-bound SQLite authorities used by the Gateway.  It deliberately does
not stop writers, stage files, attest the manifest, restore data, or re-anchor
an installation.  Consequently both readiness flags are permanently false.

The portable path, file-identity, hardlink/reparse, bounded hashing, SQLite
quick-check and canonical-JSON substrate is reused from the frozen v1 module.
All v2 roles, schema identities, schema fingerprints and Root projections are
defined here and do not follow future runtime schema changes.
"""

from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Sequence

from gateway.installation_backup_manifest import (
    ArtifactSpec,
    BackupManifestError,
    _artifact_record as _bounded_artifact_record,
    _immutable_connection,
    _logical_path,
    _normalize_artifact_root,
    _require_counter,
    _require_digest,
    _require_exact_keys,
    _scan_artifact_tree,
    canonical_json_bytes,
)
from gateway.installation_root import InstallationRootSnapshot


MANIFEST_SCHEMA = "nachuan.installation-backup.v2"

MAX_MANIFEST_BYTES = 512 * 1024
MAX_ARTIFACTS = 1_024
MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_COUNTER = (1 << 53) - 1
_SNAPSHOT_RE = re.compile(r"^snapshot-[0-9a-f]{64}$")
_ASSET_LEAF_RE = re.compile(r"^[0-9a-f]{64}\.asset$")
_MANIFEST_DOMAIN = b"nachuan.installation-backup.v2\0"
_ARTIFACT_SET_DOMAIN = b"nachuan.installation-backup.artifact-set.v2\0"
_REANCHOR_CHAIN_DOMAIN = b"nachuan.installation-backup.reanchor-chain.v2\0"

_ROOT_APPLICATION_ID = 0x4E434952  # NCIR
_ROOT_SCHEMA_VERSION = 5
_ROOT_SCHEMA_FINGERPRINT = (
    "30f1c63e8dcc88eb465743d2fe7d5f34780ad76df5e4ef516f552180e9b1da78"
)
_ROOT_SCHEMA_OBJECTS = (
    ("table", "installation_components"),
    ("table", "installation_reanchor_receipts"),
    ("table", "installation_root"),
    ("table", "installation_schema_migrations"),
    ("table", "installation_updater"),
    ("trigger", "installation_reanchor_receipts_no_delete"),
    ("trigger", "installation_reanchor_receipts_no_replace"),
    ("trigger", "installation_reanchor_receipts_no_update"),
    ("trigger", "installation_schema_migrations_no_delete"),
    ("trigger", "installation_schema_migrations_no_replace"),
    ("trigger", "installation_schema_migrations_no_update"),
)

_GATEWAY_APPLICATION_ID = 0x4E434D52  # NCMR
_GATEWAY_SCHEMA_VERSION = 4
_GATEWAY_DECLARED_SCHEMA_FINGERPRINT = (
    "778b15d71388b12b6938ce0b5cd63c03a85a898eb0a7b7b9bef3c523004709bd"
)
_GATEWAY_SCHEMA_FINGERPRINT = (
    "5c0448ae0b3a7eeed0a57e74fc79c1155ab55badb430bd5e820a71ed9cd46419"
)
_GATEWAY_SCHEMA_OBJECTS = (
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

_CHANNEL_APPLICATION_ID = 0x4E43434D  # NCCM
_CHANNEL_SCHEMA_VERSION = 4
_CHANNEL_DECLARED_SCHEMA_FINGERPRINT = (
    "54d3bee1a719c4cd218ad8739e9c1f48b2ec655307c88bf8379eb911cd119c1a"
)
_CHANNEL_SCHEMA_FINGERPRINT = (
    "120a87ef37910848bf5bbdcc1bb9d39a23974b77377a87d5b18664fb8d0b78d7"
)
_CHANNEL_SCHEMA_OBJECTS = (
    ("index", "durable_media_expiry_idx"),
    ("index", "durable_media_turn_idx"),
    ("table", "durable_channel_media_admissions"),
    ("table", "durable_media_asset_authority"),
    ("table", "durable_media_asset_capacity"),
    ("table", "durable_media_requests"),
    ("table", "durable_media_requests_meta"),
    ("trigger", "durable_channel_media_admission_capacity"),
    ("trigger", "durable_channel_media_admission_terminal"),
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

_ASSET_APPLICATION_ID = 0x4E434153  # NCAS
_ASSET_SCHEMA_VERSION = 2
_ASSET_SCHEMA_NAME = "nachuan.paid-media-asset-store.v2"
_ASSET_SCHEMA_FINGERPRINT = (
    "31e34433f5a1830d0705b7b4967e164aeb0a4c2c88d3722966271d52f281c4bd"
)
_ASSET_SCHEMA_OBJECTS = (
    ("table", "asset_ack_receipts"),
    ("table", "asset_pending_commits"),
    ("table", "asset_read_leases"),
    ("table", "asset_reservations"),
    ("table", "asset_store_meta"),
    ("table", "paid_media_assets"),
)
_ASSET_AUTHORITY_PROJECTION_DOMAIN = (
    b"nachuan-paid-media-asset-projection-v2\x00"
)
_ASSET_AUTHORITY_STATE_DOMAIN = b"nachuan-paid-media-asset-authority-v2\x00"
_ASSET_AUTHORITY_PROJECTION_SPEC = (
    (
        "asset_store_meta",
        (
            "schema",
            "installation_id",
            "epoch",
            "database_identity",
            "authority_mode",
            "recovery_floor",
            "recovery_state_digest",
            "max_capacity_bytes",
            "reserved_total_bytes",
        ),
        "singleton",
    ),
    (
        "asset_reservations",
        (
            "turn_id",
            "principal_hash",
            "epoch",
            "operation",
            "reserved_bytes",
            "actual_bytes",
            "state",
            "token_set_digest",
            "created_at",
        ),
        "turn_id",
    ),
    (
        "paid_media_assets",
        (
            "token_hash",
            "turn_id",
            "ordinal",
            "media_type",
            "byte_length",
            "sha256",
            "validation_receipt_sha256",
            "object_leaf",
        ),
        "token_hash",
    ),
    (
        "asset_pending_commits",
        (
            "token_hash",
            "turn_id",
            "ordinal",
            "media_type",
            "byte_length",
            "sha256",
            "validation_receipt_sha256",
            "staging_leaf",
            "object_leaf",
            "lease_expires_at",
        ),
        "token_hash",
    ),
    (
        "asset_ack_receipts",
        (
            "turn_id",
            "principal_hash",
            "epoch",
            "operation",
            "token_set_digest",
            "archive_receipt_sha256",
            "acked_at",
        ),
        "turn_id",
    ),
)

_COMPONENTS = ("channel_media", "desktop", "gateway", "gateway_assets")

REQUIRED_MISSING_CAPTURE_PROOFS = frozenset(
    {
        "atomic_cross_component_writer_fence",
        "capture_manifest_trusted_attestation",
        "desktop_inventory_adapter",
        "desktop_quiescence_and_safe_storage_proof",
        "restricted_capture_coordinator",
        "schema_migration_capture_coordinator",
        "windows_pinned_staging_acl",
    }
)
REQUIRED_MISSING_RESTORE_PROOFS = frozenset(
    {
        "asset_store_reanchor_adapter",
        "canonical_final_proof_attestation",
        "channel_media_reanchor_adapter",
        "desktop_restore_and_reanchor_adapter",
        "gateway_reanchor_adapter",
        "installation_root_reanchor_coordinator",
        "restricted_restore_coordinator",
        "schema_v3_installer_migration",
    }
)

_ROLE_POLICY: dict[str, tuple[str, str]] = {
    "installation_root": ("sqlite", "evidence_only"),
    "gateway_ledger": ("sqlite", "restore_reanchor_required"),
    "gateway_rollback_anchor": ("file", "restore_reanchor_required"),
    "asset_store_database": ("sqlite", "restore_reanchor_required"),
    "asset_store_rollback_anchor": ("file", "restore_reanchor_required"),
    "asset_store_object": ("file", "restore_reanchor_required"),
    "channel_media_ledger": ("sqlite", "restore_reanchor_required"),
    "channel_media_rollback_anchor": ("file", "restore_reanchor_required"),
}
_REQUIRED_SINGLETON_ROLES = frozenset(_ROLE_POLICY) - {"asset_store_object"}
_MAX_ASSET_OBJECTS = MAX_ARTIFACTS - len(_REQUIRED_SINGLETON_ROLES)
_FIXED_ROLE_PATHS = {
    "installation_root": "authority/installation-root.db",
    "gateway_ledger": "gateway/durable-media.db",
    "gateway_rollback_anchor": "gateway/durable-media.db.rollback-anchor",
    "asset_store_database": "gateway-assets/asset-store.db",
    "asset_store_rollback_anchor": (
        "gateway-assets/asset-store.db.rollback-anchor"
    ),
    "channel_media_ledger": (
        "channel-media/channel-media-requests.db"
    ),
    "channel_media_rollback_anchor": (
        "channel-media/channel-media-requests.db.rollback-anchor"
    ),
}
_ASSET_OBJECT_PREFIX = "gateway-assets/objects/"
_ROLE_MAX_BYTES = {
    "installation_root": 16 * 1024 * 1024,
    "gateway_ledger": 1024 * 1024 * 1024,
    "gateway_rollback_anchor": 1024,
    "asset_store_database": 64 * 1024 * 1024,
    "asset_store_rollback_anchor": 1024,
    "asset_store_object": 24 * 1024 * 1024,
    "channel_media_ledger": 1024 * 1024 * 1024,
    "channel_media_rollback_anchor": 1024,
}
_SQLITE_CONTRACT = {
    "installation_root": (
        _ROOT_APPLICATION_ID,
        _ROOT_SCHEMA_VERSION,
        _ROOT_SCHEMA_FINGERPRINT,
    ),
    "gateway_ledger": (
        _GATEWAY_APPLICATION_ID,
        _GATEWAY_SCHEMA_VERSION,
        _GATEWAY_SCHEMA_FINGERPRINT,
    ),
    "asset_store_database": (
        _ASSET_APPLICATION_ID,
        _ASSET_SCHEMA_VERSION,
        _ASSET_SCHEMA_FINGERPRINT,
    ),
    "channel_media_ledger": (
        _CHANNEL_APPLICATION_ID,
        _CHANNEL_SCHEMA_VERSION,
        _CHANNEL_SCHEMA_FINGERPRINT,
    ),
}


def _digest(value: object, *, domain: bytes) -> str:
    return sha256(domain + canonical_json_bytes(value)).hexdigest()


def _schema_migration_operation_digest(
    installation_id: object,
    snapshot_digest: object,
) -> str:
    """Frozen replay identity used by the Root v4-to-v5 receipt."""

    installation = _require_digest(
        installation_id, "schema migration installation id"
    )
    snapshot = _require_digest(snapshot_digest, "schema migration snapshot digest")
    digest = sha256(b"nachuan.installation-root.schema-migration/v1\x00")
    for value in ("4", "5", installation, snapshot):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _schema_objects(connection: sqlite3.Connection) -> dict[tuple[str, str], object]:
    rows = connection.execute(
        "SELECT type,name,sql FROM sqlite_master "
        "WHERE type IN ('table','index','trigger') "
        "AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {(str(row[0]), str(row[1])): row[2] for row in rows}


def _canonical_sql_v2(value: object) -> str:
    """Return the exact sqlite_master SQL text frozen by the v2 wire."""

    if not isinstance(value, str) or not value:
        raise BackupManifestError("SQLite schema SQL text is invalid")
    return value


def _schema_fingerprint(objects: dict[tuple[str, str], object]) -> str:
    payload = [
        [object_type, name, _canonical_sql_v2(sql)]
        for (object_type, name), sql in sorted(objects.items())
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _asset_authority_projection_digest(connection: sqlite3.Connection) -> str:
    digest = sha256(_ASSET_AUTHORITY_PROJECTION_DOMAIN)
    for table, columns, order_by in _ASSET_AUTHORITY_PROJECTION_SPEC:
        heading = json.dumps(
            [table, *columns],
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        digest.update(len(heading).to_bytes(4, "big"))
        digest.update(heading)
        query = f"SELECT {','.join(columns)} FROM {table} ORDER BY {order_by}"
        for row in connection.execute(query):
            encoded = json.dumps(
                list(row),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("ascii")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(b"\x00")
    return digest.hexdigest()


def _asset_authority_state_digest(
    *,
    database_identity: str,
    installation_id: str,
    epoch: int,
    mutation_sequence: int,
    projection_digest: str,
) -> str:
    return sha256(
        _ASSET_AUTHORITY_STATE_DOMAIN
        + bytes(database_identity, "ascii")
        + b"\x00"
        + bytes(installation_id, "ascii")
        + b"\x00"
        + f"{epoch:016x}".encode("ascii")
        + b"\x00"
        + f"{mutation_sequence:016x}".encode("ascii")
        + b"\x00"
        + bytes(projection_digest, "ascii")
    ).hexdigest()


def _inspect_sqlite_schema(path: Path) -> tuple[int, int, str]:
    try:
        with closing(_immutable_connection(path)) as connection:
            application_id = connection.execute("PRAGMA application_id").fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            objects = _schema_objects(connection)
    except (OSError, sqlite3.Error) as exc:
        raise BackupManifestError("SQLite closed-schema inspection failed") from exc
    if application_id is None or user_version is None:
        raise BackupManifestError("SQLite identity is incomplete")
    return int(application_id[0]), int(user_version[0]), _schema_fingerprint(objects)


def _validate_specs(specs: Sequence[ArtifactSpec]) -> tuple[ArtifactSpec, ...]:
    values = tuple(specs)
    if not values or len(values) > MAX_ARTIFACTS:
        raise BackupManifestError("artifact count is outside the v2 limit")
    paths: set[str] = set()
    roles: dict[str, int] = {}
    normalized: list[ArtifactSpec] = []
    for value in values:
        if not isinstance(value, ArtifactSpec):
            raise BackupManifestError("artifact specifications must be ArtifactSpec values")
        logical_path = _logical_path(value.logical_path)
        collision = logical_path.casefold()
        if collision in paths:
            raise BackupManifestError("artifact logical path collision")
        paths.add(collision)
        expected = _ROLE_POLICY.get(value.role)
        if expected is None or (value.kind, value.restore_policy) != expected:
            raise BackupManifestError("artifact role, kind or policy is outside v2")
        roles[value.role] = roles.get(value.role, 0) + 1
        normalized.append(
            ArtifactSpec(logical_path, value.role, value.kind, value.restore_policy)
        )
    for role in _REQUIRED_SINGLETON_ROLES:
        if roles.get(role) != 1:
            raise BackupManifestError(f"required v2 role must occur once: {role}")
    if set(roles) - set(_ROLE_POLICY):
        raise BackupManifestError("artifact role is outside the closed v2 set")
    for role, path in _FIXED_ROLE_PATHS.items():
        actual = next(item.logical_path for item in normalized if item.role == role)
        if actual != path:
            raise BackupManifestError(f"artifact role is not at its v2 path: {role}")
    for item in normalized:
        if item.role == "asset_store_object":
            if not item.logical_path.startswith(_ASSET_OBJECT_PREFIX):
                raise BackupManifestError("asset object is outside its v2 directory")
            leaf = item.logical_path[len(_ASSET_OBJECT_PREFIX) :]
            if "/" in leaf or _ASSET_LEAF_RE.fullmatch(leaf) is None:
                raise BackupManifestError("asset object leaf is invalid")
    return tuple(sorted(normalized, key=lambda item: item.logical_path))


def _preflight_artifact_sizes(
    tree_state: tuple,
    specs: Sequence[ArtifactSpec],
) -> dict[str, int]:
    try:
        file_states = dict(tree_state[2])
    except (IndexError, TypeError, ValueError) as exc:
        raise BackupManifestError("artifact size preflight state is invalid") from exc
    expected_paths = {item.logical_path for item in specs}
    if set(file_states) != expected_paths:
        raise BackupManifestError("artifact size preflight path set is invalid")
    sizes: dict[str, int] = {}
    total = 0
    for spec in specs:
        state = file_states[spec.logical_path]
        if not isinstance(state, tuple) or len(state) < 4:
            raise BackupManifestError("artifact size preflight state is invalid")
        size = _require_counter(state[3], "artifact byte length")
        if size > _ROLE_MAX_BYTES[spec.role]:
            raise BackupManifestError(
                f"artifact exceeds the v2 role limit: {spec.role}"
            )
        total += size
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise BackupManifestError("artifact total byte limit exceeded")
        sizes[spec.logical_path] = size
    return sizes


def _artifact_record(root: Path, spec: ArtifactSpec, *, expected_size: int | None = None) -> dict:
    record = _bounded_artifact_record(
        root.joinpath(*spec.logical_path.split("/")),
        spec,
        expected_size=expected_size,
    )
    limit = _ROLE_MAX_BYTES[spec.role]
    if int(record["byteLength"]) > limit:
        raise BackupManifestError(f"artifact exceeds the v2 role limit: {spec.role}")
    if spec.kind == "sqlite":
        application_id, user_version, fingerprint = _inspect_sqlite_schema(
            root.joinpath(*spec.logical_path.split("/"))
        )
        evidence = dict(record["sqlite"])
        evidence["schemaFingerprint"] = fingerprint
        record["sqlite"] = evidence
        if (application_id, user_version, fingerprint) != _SQLITE_CONTRACT[spec.role]:
            raise BackupManifestError(f"{spec.role} SQLite contract is unsupported")
    return record


def _snapshot_projection(root: InstallationRootSnapshot) -> tuple[dict, dict]:
    if not isinstance(root, InstallationRootSnapshot):
        raise BackupManifestError("root snapshot is invalid")
    if (
        root.status != "maintenance_locked"
        or root.lock_kind != "operator"
        or root.lock_reason_digest is None
        or root.reanchor_pending
        or root.reanchor_operation_digest is not None
        or root.reanchor_snapshot_digest is not None
        or root.reanchor_source_epoch is not None
    ):
        raise BackupManifestError("v2 capture requires operator maintenance lock")
    source = {
        "installationId": _require_digest(root.installation_id, "installation id"),
        "ownerSidDigest": _require_digest(root.owner_sid_digest, "owner SID digest"),
        "epoch": _require_counter(root.epoch, "installation epoch", minimum=1),
        "rootRevision": _require_counter(root.root_revision, "root revision", minimum=1),
        "rootSchemaVersion": _ROOT_SCHEMA_VERSION,
        "rootSchemaFingerprint": _ROOT_SCHEMA_FINGERPRINT,
        "rootStatus": "maintenance_locked",
        "rootLockKind": "operator",
        "rootLockReasonDigest": _require_digest(
            root.lock_reason_digest, "root lock reason digest"
        ),
        "principalDigest": _require_digest(root.principal_digest, "root principal"),
        "updater": {
            "releaseSequence": _require_counter(
                root.updater.release_sequence, "updater release sequence"
            ),
            "keyringSequence": _require_counter(
                root.updater.keyring_sequence, "updater keyring sequence"
            ),
            "artifactDigest": _require_digest(
                root.updater.artifact_digest, "updater artifact digest", allow_zero=True
            ),
            "stateDigest": _require_digest(
                root.updater.state_digest, "updater state digest", allow_zero=True
            ),
        },
    }
    components: dict[str, dict] = {}
    identities: set[str] = {root.installation_id}
    if tuple(sorted(item.component for item in root.components)) != _COMPONENTS:
        raise BackupManifestError("root component set is not Root v5")
    for name in _COMPONENTS:
        value = root.component(name)  # type: ignore[arg-type]
        identity = _require_digest(value.identity, f"{name} identity")
        if identity in identities:
            raise BackupManifestError("root component identities are not distinct")
        identities.add(identity)
        if (
            not value.bound
            or value.epoch != root.epoch
            or value.state_digest is None
            or value.recovery_floor is not None
            or value.recovery_state_digest is not None
        ):
            raise BackupManifestError(f"{name} is not a stable bound component")
        components[name] = {
            "identity": identity,
            "epoch": root.epoch,
            "bound": True,
            "sequenceFloor": _require_counter(
                value.sequence_floor, f"{name} sequence floor"
            ),
            "stateDigest": _require_digest(
                value.state_digest, f"{name} state digest"
            ),
            "recoveryFloor": None,
            "recoveryStateDigest": None,
            "artifactProofStatus": (
                "missing_desktop_inventory_adapter"
                if name == "desktop"
                else "root_bound_staged_artifact"
            ),
        }
    return source, components


def _root_projection(path: Path) -> tuple[dict, dict]:
    try:
        with closing(_immutable_connection(path)) as connection:
            connection.row_factory = sqlite3.Row
            objects = _schema_objects(connection)
            if (
                tuple(sorted(objects)) != _ROOT_SCHEMA_OBJECTS
                or _schema_fingerprint(objects) != _ROOT_SCHEMA_FINGERPRINT
            ):
                raise sqlite3.DatabaseError("Root v5 schema is not frozen v2")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise sqlite3.DatabaseError("Root foreign-key check failed")
            root_rows = connection.execute("SELECT * FROM installation_root").fetchall()
            component_rows = connection.execute(
                "SELECT * FROM installation_components ORDER BY component"
            ).fetchall()
            updater_rows = connection.execute("SELECT * FROM installation_updater").fetchall()
            reanchors = connection.execute(
                "SELECT * FROM installation_reanchor_receipts ORDER BY target_epoch"
            ).fetchall()
            migrations = connection.execute(
                "SELECT * FROM installation_schema_migrations ORDER BY target_version"
            ).fetchall()
    except (OSError, sqlite3.Error) as exc:
        raise BackupManifestError("installation Root v5 projection is invalid") from exc
    if len(root_rows) != 1 or len(component_rows) != 4 or len(updater_rows) != 1:
        raise BackupManifestError("installation Root v5 singleton state is invalid")
    if len(migrations) > 1 or len(reanchors) > 65_536:
        raise BackupManifestError("installation Root receipt capacity is invalid")
    root = root_rows[0]
    if (
        root["singleton"] != 1
        or root["schema_version"] != 5
        or root["status"] != "maintenance_locked"
        or root["lock_kind"] != "operator"
        or root["reanchor_pending"] != 0
        or root["reanchor_operation_digest"] is not None
        or root["reanchor_snapshot_digest"] is not None
        or root["reanchor_source_epoch"] is not None
    ):
        raise BackupManifestError("installation Root is not capture locked")
    installation_id = _require_digest(root["installation_id"], "installation id")
    epoch = _require_counter(root["epoch"], "installation epoch", minimum=1)
    root_revision = _require_counter(root["root_revision"], "root revision", minimum=1)
    updater = updater_rows[0]
    source = {
        "installationId": installation_id,
        "ownerSidDigest": _require_digest(root["owner_sid_digest"], "owner SID digest"),
        "epoch": epoch,
        "rootRevision": root_revision,
        "rootSchemaVersion": 5,
        "rootSchemaFingerprint": _ROOT_SCHEMA_FINGERPRINT,
        "rootStatus": "maintenance_locked",
        "rootLockKind": "operator",
        "rootLockReasonDigest": _require_digest(
            root["lock_reason_digest"], "root lock reason digest"
        ),
        "principalDigest": sha256(
            b"nachuan.installation-principal.v1\0"
            + bytes.fromhex(installation_id)
            + epoch.to_bytes(8, "big")
        ).hexdigest(),
        "updater": {
            "releaseSequence": _require_counter(
                updater["release_sequence"], "updater release sequence"
            ),
            "keyringSequence": _require_counter(
                updater["keyring_sequence"], "updater keyring sequence"
            ),
            "artifactDigest": _require_digest(
                updater["artifact_digest"], "updater artifact digest", allow_zero=True
            ),
            "stateDigest": _require_digest(
                updater["state_digest"], "updater state digest", allow_zero=True
            ),
        },
    }
    components: dict[str, dict] = {}
    identities = {installation_id}
    if tuple(str(row["component"]) for row in component_rows) != _COMPONENTS:
        raise BackupManifestError("installation Root component set is invalid")
    for row in component_rows:
        name = str(row["component"])
        identity = _require_digest(row["identity"], f"{name} identity")
        if identity in identities:
            raise BackupManifestError("installation Root identities collide")
        identities.add(identity)
        if (
            row["bound"] != 1
            or row["epoch"] != epoch
            or row["state_digest"] is None
            or row["recovery_floor"] is not None
            or row["recovery_state_digest"] is not None
        ):
            raise BackupManifestError(f"installation Root {name} proof is unstable")
        components[name] = {
            "identity": identity,
            "epoch": epoch,
            "bound": True,
            "sequenceFloor": _require_counter(
                row["sequence_floor"], f"{name} sequence floor"
            ),
            "stateDigest": _require_digest(row["state_digest"], f"{name} state digest"),
            "recoveryFloor": None,
            "recoveryStateDigest": None,
            "artifactProofStatus": (
                "missing_desktop_inventory_adapter"
                if name == "desktop"
                else "root_bound_staged_artifact"
            ),
        }
    reanchor_documents: list[dict] = []
    previous_revision = 0
    seen_operations: set[str] = set()
    seen_snapshots: set[str] = set()
    seen_final_proofs: set[str] = set()
    for expected_target, row in enumerate(reanchors, start=2):
        target = _require_counter(row["target_epoch"], "reanchor target", minimum=2)
        source_epoch = _require_counter(row["source_epoch"], "reanchor source", minimum=1)
        completed = _require_counter(
            row["completed_root_revision"], "reanchor root revision", minimum=1
        )
        document = {
            "targetEpoch": target,
            "sourceEpoch": source_epoch,
            "operationDigest": _require_digest(row["operation_digest"], "reanchor operation"),
            "snapshotDigest": _require_digest(row["snapshot_digest"], "reanchor snapshot"),
            "finalProofDigest": _require_digest(row["final_proof_digest"], "reanchor proof"),
            "completedRootRevision": completed,
        }
        if (
            target != expected_target
            or source_epoch != target - 1
            or completed <= previous_revision
            or completed >= root_revision
            or document["operationDigest"] in seen_operations
            or document["snapshotDigest"] in seen_snapshots
            or document["finalProofDigest"] in seen_final_proofs
        ):
            raise BackupManifestError("installation Root reanchor chain is invalid")
        previous_revision = completed
        seen_operations.add(str(document["operationDigest"]))
        seen_snapshots.add(str(document["snapshotDigest"]))
        seen_final_proofs.add(str(document["finalProofDigest"]))
        reanchor_documents.append(document)
    if len(reanchor_documents) != epoch - 1:
        raise BackupManifestError("installation Root reanchor chain is incomplete")
    source["reanchorReceiptCount"] = len(reanchor_documents)
    source["reanchorChainDigest"] = _digest(
        reanchor_documents, domain=_REANCHOR_CHAIN_DOMAIN
    )
    migration_documents: list[dict] = []
    for row in migrations:
        document = {
            "sourceVersion": _require_counter(
                row["source_version"], "schema migration source", minimum=1
            ),
            "targetVersion": _require_counter(
                row["target_version"], "schema migration target", minimum=1
            ),
            "installationId": _require_digest(
                row["installation_id"], "schema migration installation"
            ),
            "operationDigest": _require_digest(
                row["operation_digest"], "schema migration operation"
            ),
            "snapshotDigest": _require_digest(
                row["snapshot_digest"], "schema migration snapshot"
            ),
            "completedRootRevision": _require_counter(
                row["completed_root_revision"],
                "schema migration root revision",
                minimum=2,
            ),
        }
        if (
            document["sourceVersion"] != 4
            or document["targetVersion"] != 5
            or document["installationId"] != installation_id
            or document["operationDigest"]
            != _schema_migration_operation_digest(
                installation_id,
                document["snapshotDigest"],
            )
            or int(document["completedRootRevision"]) >= root_revision
        ):
            raise BackupManifestError("installation Root migration receipt is invalid")
        migration_documents.append(document)
    source["schemaMigrations"] = migration_documents
    return source, components


def _read_durable_anchor(path: Path) -> tuple[str, int, str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BackupManifestError("durable rollback anchor is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "authority_state_digest",
        "database_identity",
        "format",
        "mutation_sequence",
    }:
        raise BackupManifestError("durable rollback anchor fields are invalid")
    sequence = value.get("mutation_sequence")
    if (
        value.get("format") != 2
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9a-f]{16}", sequence) is None
    ):
        raise BackupManifestError("durable rollback anchor encoding is invalid")
    identity = _require_digest(value.get("database_identity"), "anchor identity")
    state_digest = _require_digest(value.get("authority_state_digest"), "anchor state")
    canonical = json.dumps(
        {
            "authority_state_digest": state_digest,
            "database_identity": identity,
            "format": 2,
            "mutation_sequence": sequence,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if raw != canonical:
        raise BackupManifestError("durable rollback anchor is not canonical")
    return identity, int(sequence, 16), state_digest


def _validate_durable_projection(
    database_path: Path,
    anchor_path: Path,
    *,
    component: dict,
    channel: bool,
) -> None:
    expected_objects = _CHANNEL_SCHEMA_OBJECTS if channel else _GATEWAY_SCHEMA_OBJECTS
    expected_fingerprint = (
        _CHANNEL_SCHEMA_FINGERPRINT if channel else _GATEWAY_SCHEMA_FINGERPRINT
    )
    expected_declared = (
        _CHANNEL_DECLARED_SCHEMA_FINGERPRINT
        if channel
        else _GATEWAY_DECLARED_SCHEMA_FINGERPRINT
    )
    try:
        with closing(_immutable_connection(database_path)) as connection:
            connection.row_factory = sqlite3.Row
            objects = _schema_objects(connection)
            if (
                tuple(sorted(objects)) != expected_objects
                or _schema_fingerprint(objects) != expected_fingerprint
            ):
                raise sqlite3.DatabaseError("durable schema is outside v2")
            meta_rows = connection.execute(
                "SELECT * FROM durable_media_requests_meta"
            ).fetchall()
            if len(meta_rows) != 1:
                raise sqlite3.DatabaseError("durable metadata singleton is invalid")
            meta = meta_rows[0]
            if (
                meta["singleton"] != 1
                or meta["schema_version"] != 4
                or meta["schema_fingerprint"] != expected_declared
                or meta["authority_mode"] != "normal"
                or any(
                    meta[name] is not None
                    for name in (
                        "authority_installation_id",
                        "authority_epoch",
                        "authority_recovery_floor",
                        "authority_recovery_state_digest",
                    )
                )
            ):
                raise sqlite3.DatabaseError("durable authority metadata is unstable")
            identity = _require_digest(meta["database_identity"], "durable identity")
            sequence = _require_counter(meta["mutation_sequence"], "durable sequence")
            state_digest = _require_digest(
                meta["authority_state_digest"], "durable state digest"
            )
            usage = connection.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(CAST(response_json AS BLOB))),0),"
                "COALESCE(SUM(reserved_response_bytes),0) FROM durable_media_requests"
            ).fetchone()
            if tuple(usage) != (
                meta["record_count"],
                meta["response_bytes"],
                meta["reserved_bytes"],
            ):
                raise sqlite3.DatabaseError("durable request counters are corrupt")
            asset_usage = connection.execute(
                "SELECT COALESCE(SUM(reserved_bytes),0) "
                "FROM durable_media_asset_authority"
            ).fetchone()
            asset_capacity = connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity "
                "WHERE singleton=1"
            ).fetchone()
            if (
                asset_capacity is None
                or asset_usage is None
                or tuple(asset_usage) != tuple(asset_capacity)
            ):
                raise sqlite3.DatabaseError("durable asset counters are corrupt")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise sqlite3.DatabaseError("durable foreign-key check failed")
            if tuple(connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests WHERE status='processing'"
            ).fetchone()) != (0,):
                raise sqlite3.DatabaseError("durable capture contains active work")
            if channel:
                inconsistent = connection.execute(
                    "SELECT COUNT(*) FROM durable_media_requests r LEFT JOIN "
                    "durable_channel_media_admissions a ON "
                    "a.principal_hash=r.principal_hash AND a.operation=r.operation "
                    "AND a.key_hash=r.key_hash WHERE "
                    "(r.provider_phase=0 AND a.turn_id IS NOT NULL) OR "
                    "(r.provider_phase=1 AND (a.turn_id IS NULL OR "
                    "a.turn_id<>r.turn_id OR a.request_sha256<>r.request_sha256 OR "
                    "a.attempt_count<>r.attempt_count OR "
                    "(r.status='succeeded' AND a.state<>'succeeded') OR "
                    "(r.status='recovery_required' AND a.state<>'recovery_required')))"
                ).fetchone()
                if tuple(inconsistent) != (0,):
                    raise sqlite3.DatabaseError("channel admission proof is inconsistent")
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if isinstance(exc, BackupManifestError):
            raise
        raise BackupManifestError("durable authority projection is invalid") from exc
    anchor = _read_durable_anchor(anchor_path)
    expected_root = (
        component["identity"],
        component["sequenceFloor"],
        component["stateDigest"],
    )
    if (identity, sequence, state_digest) != anchor or anchor != expected_root:
        raise BackupManifestError("durable authority, anchor and Root proof differ")


def _read_asset_anchor(path: Path) -> tuple[str, str, int, int, str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BackupManifestError("asset rollback anchor is invalid") from exc
    expected_keys = {
        "authority_mode",
        "authority_state_digest",
        "database_identity",
        "epoch",
        "format",
        "installation_id",
        "mutation_sequence",
        "recovery_floor",
        "recovery_state_digest",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise BackupManifestError("asset rollback anchor fields are invalid")
    epoch = value.get("epoch")
    sequence = value.get("mutation_sequence")
    if (
        value.get("format") != 1
        or value.get("authority_mode") != "normal"
        or value.get("recovery_floor") != "-" * 16
        or value.get("recovery_state_digest") != "-" * 64
        or not isinstance(epoch, str)
        or re.fullmatch(r"[0-9a-f]{16}", epoch) is None
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9a-f]{16}", sequence) is None
    ):
        raise BackupManifestError("asset rollback anchor state is invalid")
    identity = _require_digest(value.get("database_identity"), "asset anchor identity")
    installation_id = _require_digest(
        value.get("installation_id"), "asset anchor installation"
    )
    state_digest = _require_digest(
        value.get("authority_state_digest"), "asset anchor state"
    )
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if raw != canonical:
        raise BackupManifestError("asset rollback anchor is not canonical")
    return identity, installation_id, int(epoch, 16), int(sequence, 16), state_digest


def _validate_asset_projection(
    database_path: Path,
    anchor_path: Path,
    *,
    source: dict,
    component: dict,
    records: Sequence[dict],
) -> None:
    try:
        with closing(_immutable_connection(database_path)) as connection:
            connection.row_factory = sqlite3.Row
            objects = _schema_objects(connection)
            if (
                tuple(sorted(objects)) != _ASSET_SCHEMA_OBJECTS
                or _schema_fingerprint(objects) != _ASSET_SCHEMA_FINGERPRINT
            ):
                raise sqlite3.DatabaseError("asset schema is outside v2")
            rows = connection.execute("SELECT * FROM asset_store_meta").fetchall()
            if len(rows) != 1:
                raise sqlite3.DatabaseError("asset metadata singleton is invalid")
            meta = rows[0]
            if (
                meta["singleton"] != 1
                or meta["schema"] != _ASSET_SCHEMA_NAME
                or meta["installation_id"] != source["installationId"]
                or meta["epoch"] != source["epoch"]
                or meta["authority_mode"] != "normal"
                or meta["recovery_floor"] is not None
                or meta["recovery_state_digest"] is not None
            ):
                raise sqlite3.DatabaseError("asset authority metadata is unstable")
            identity = _require_digest(meta["database_identity"], "asset identity")
            sequence = _require_counter(meta["mutation_sequence"], "asset sequence")
            state_digest = _require_digest(
                meta["authority_state_digest"], "asset state digest"
            )
            asset_count = connection.execute(
                "SELECT COUNT(*) FROM paid_media_assets"
            ).fetchone()
            if (
                asset_count is None
                or not isinstance(asset_count[0], int)
                or int(asset_count[0]) < 0
                or int(asset_count[0]) > _MAX_ASSET_OBJECTS
            ):
                raise BackupManifestError("asset row count exceeds the v2 limit")
            actual_byte_mismatches = connection.execute(
                "SELECT COUNT(*) FROM asset_reservations r WHERE "
                "r.actual_bytes<>(SELECT COALESCE(SUM(a.byte_length),0) "
                "FROM paid_media_assets a WHERE a.turn_id=r.turn_id)"
            ).fetchone()
            if tuple(actual_byte_mismatches or ()) != (0,):
                raise BackupManifestError(
                    "asset reservation byte accounting is inconsistent"
                )
            projection_digest = _asset_authority_projection_digest(connection)
            expected_state_digest = _asset_authority_state_digest(
                database_identity=identity,
                installation_id=source["installationId"],
                epoch=source["epoch"],
                mutation_sequence=sequence,
                projection_digest=projection_digest,
            )
            if state_digest != expected_state_digest:
                raise sqlite3.DatabaseError(
                    "asset authority projection digest is inconsistent"
                )
            usage = connection.execute(
                "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
            ).fetchone()
            if tuple(usage) != (meta["reserved_total_bytes"],):
                raise sqlite3.DatabaseError("asset reservation counter is corrupt")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise sqlite3.DatabaseError("asset foreign-key check failed")
            if tuple(connection.execute("SELECT COUNT(*) FROM asset_pending_commits").fetchone()) != (0,):
                raise sqlite3.DatabaseError("asset capture has pending commits")
            if tuple(connection.execute("SELECT COUNT(*) FROM asset_read_leases").fetchone()) != (0,):
                raise sqlite3.DatabaseError("asset capture has active read leases")
            asset_rows = connection.execute(
                "SELECT object_leaf,byte_length,sha256 FROM paid_media_assets "
                "ORDER BY object_leaf"
            ).fetchall()
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if isinstance(exc, BackupManifestError):
            raise
        raise BackupManifestError("asset authority projection is invalid") from exc
    anchor = _read_asset_anchor(anchor_path)
    expected = (
        component["identity"],
        source["installationId"],
        source["epoch"],
        component["sequenceFloor"],
        component["stateDigest"],
    )
    if (identity, source["installationId"], source["epoch"], sequence, state_digest) != anchor:
        raise BackupManifestError("asset database and rollback anchor differ")
    if anchor != expected:
        raise BackupManifestError("asset authority does not match Root proof")
    expected_objects: dict[str, tuple[int, str]] = {}
    for row in asset_rows:
        leaf = str(row["object_leaf"])
        if _ASSET_LEAF_RE.fullmatch(leaf) is None:
            raise BackupManifestError("asset database object leaf is invalid")
        expected_objects[_ASSET_OBJECT_PREFIX + leaf] = (
            _require_counter(row["byte_length"], "asset object length", minimum=1),
            _require_digest(row["sha256"], "asset object SHA-256"),
        )
    actual_objects = {
        str(record["logicalPath"]): (
            int(record["byteLength"]),
            str(record["sha256"]),
        )
        for record in records
        if record["role"] == "asset_store_object"
    }
    if actual_objects != expected_objects:
        raise BackupManifestError("asset object artifacts do not close over the database")


def _validate_projections(root: Path, source: dict, components: dict, records: Sequence[dict]) -> None:
    root_source, root_components = _root_projection(
        root / _FIXED_ROLE_PATHS["installation_root"]
    )
    if root_source != source or root_components != components:
        raise BackupManifestError("staged Root proof differs from the manifest")
    _validate_durable_projection(
        root / _FIXED_ROLE_PATHS["gateway_ledger"],
        root / _FIXED_ROLE_PATHS["gateway_rollback_anchor"],
        component=components["gateway"],
        channel=False,
    )
    _validate_asset_projection(
        root / _FIXED_ROLE_PATHS["asset_store_database"],
        root / _FIXED_ROLE_PATHS["asset_store_rollback_anchor"],
        source=source,
        component=components["gateway_assets"],
        records=records,
    )
    _validate_durable_projection(
        root / _FIXED_ROLE_PATHS["channel_media_ledger"],
        root / _FIXED_ROLE_PATHS["channel_media_rollback_anchor"],
        component=components["channel_media"],
        channel=True,
    )


def _validate_artifact_records(value: object) -> list[dict]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARTIFACTS:
        raise BackupManifestError("artifact records are outside v2 limits")
    records: list[dict] = []
    specs: list[ArtifactSpec] = []
    total = 0
    previous: str | None = None
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
            "v2 artifact record",
        )
        path = _logical_path(record["logicalPath"])
        if previous is not None and path <= previous:
            raise BackupManifestError("artifact records are not canonically sorted")
        previous = path
        if not all(
            isinstance(record[field], str)
            for field in ("role", "kind", "restorePolicy")
        ):
            raise BackupManifestError("artifact role fields must be strings")
        spec = ArtifactSpec(
            path,
            str(record["role"]),
            str(record["kind"]),
            str(record["restorePolicy"]),
        )
        specs.append(spec)
        byte_length = _require_counter(record["byteLength"], "artifact byte length")
        if byte_length > _ROLE_MAX_BYTES.get(spec.role, -1):
            raise BackupManifestError("artifact byte length exceeds its v2 role")
        total += byte_length
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise BackupManifestError("artifact total byte limit exceeded")
        _require_digest(record["sha256"], "artifact SHA-256")
        if spec.kind == "sqlite":
            sqlite_value = _require_exact_keys(
                record["sqlite"],
                {
                    "applicationId",
                    "userVersion",
                    "journalMode",
                    "quickCheck",
                    "schemaFingerprint",
                },
                "v2 SQLite evidence",
            )
            expected = _SQLITE_CONTRACT.get(spec.role)
            if expected is None or (
                sqlite_value["applicationId"],
                sqlite_value["userVersion"],
                sqlite_value["schemaFingerprint"],
            ) != expected:
                raise BackupManifestError("artifact SQLite contract is invalid")
            if sqlite_value["journalMode"] not in {"delete", "persist"}:
                raise BackupManifestError("artifact SQLite journal mode is unsafe")
            if sqlite_value["quickCheck"] != "ok":
                raise BackupManifestError("artifact SQLite quick-check is invalid")
        elif record["sqlite"] is not None:
            raise BackupManifestError("non-SQLite artifact has SQLite evidence")
        records.append(record)
    if _validate_specs(specs) != tuple(specs):
        raise BackupManifestError("artifact records are not in canonical role order")
    return records


def _validate_source(value: object) -> dict:
    source = _require_exact_keys(
        value,
        {
            "installationId",
            "ownerSidDigest",
            "epoch",
            "rootRevision",
            "rootSchemaVersion",
            "rootSchemaFingerprint",
            "rootStatus",
            "rootLockKind",
            "rootLockReasonDigest",
            "principalDigest",
            "updater",
            "reanchorReceiptCount",
            "reanchorChainDigest",
            "schemaMigrations",
        },
        "v2 source",
    )
    _require_digest(source["installationId"], "installation id")
    _require_digest(source["ownerSidDigest"], "owner SID digest")
    _require_counter(source["epoch"], "installation epoch", minimum=1)
    _require_counter(source["rootRevision"], "root revision", minimum=1)
    _require_digest(source["rootLockReasonDigest"], "root lock reason")
    _require_digest(source["principalDigest"], "root principal")
    _require_counter(source["reanchorReceiptCount"], "reanchor receipt count")
    _require_digest(source["reanchorChainDigest"], "reanchor chain digest")
    if (
        source["rootSchemaVersion"] != 5
        or source["rootSchemaFingerprint"] != _ROOT_SCHEMA_FINGERPRINT
        or source["rootStatus"] != "maintenance_locked"
        or source["rootLockKind"] != "operator"
    ):
        raise BackupManifestError("v2 source is not a Root-v5 capture lock")
    updater = _require_exact_keys(
        source["updater"],
        {"releaseSequence", "keyringSequence", "artifactDigest", "stateDigest"},
        "v2 updater",
    )
    _require_counter(updater["releaseSequence"], "updater release sequence")
    _require_counter(updater["keyringSequence"], "updater keyring sequence")
    _require_digest(updater["artifactDigest"], "updater artifact digest", allow_zero=True)
    _require_digest(updater["stateDigest"], "updater state digest", allow_zero=True)
    migrations = source["schemaMigrations"]
    if not isinstance(migrations, list) or len(migrations) > 1:
        raise BackupManifestError("schema migration receipts are invalid")
    for item in migrations:
        receipt = _require_exact_keys(
            item,
            {
                "sourceVersion",
                "targetVersion",
                "installationId",
                "operationDigest",
                "snapshotDigest",
                "completedRootRevision",
            },
            "schema migration receipt",
        )
        if (
            receipt["sourceVersion"] != 4
            or receipt["targetVersion"] != 5
            or receipt["installationId"] != source["installationId"]
        ):
            raise BackupManifestError("schema migration receipt is outside v2")
        _require_digest(receipt["operationDigest"], "schema migration operation")
        snapshot_digest = _require_digest(
            receipt["snapshotDigest"], "schema migration snapshot"
        )
        if receipt["operationDigest"] != _schema_migration_operation_digest(
            source["installationId"], snapshot_digest
        ):
            raise BackupManifestError("schema migration receipt operation is invalid")
        completed = _require_counter(
            receipt["completedRootRevision"], "schema migration revision", minimum=2
        )
        if completed >= source["rootRevision"]:
            raise BackupManifestError("schema migration receipt is from the future")
    return source


def _validate_components(value: object, source: dict) -> dict:
    components = _require_exact_keys(value, set(_COMPONENTS), "v2 components")
    identities = {source["installationId"]}
    for name in _COMPONENTS:
        item = _require_exact_keys(
            components[name],
            {
                "identity",
                "epoch",
                "bound",
                "sequenceFloor",
                "stateDigest",
                "recoveryFloor",
                "recoveryStateDigest",
                "artifactProofStatus",
            },
            f"{name} v2 component",
        )
        identity = _require_digest(item["identity"], f"{name} identity")
        if identity in identities:
            raise BackupManifestError("v2 component identities collide")
        identities.add(identity)
        _require_counter(item["sequenceFloor"], f"{name} sequence floor")
        _require_digest(item["stateDigest"], f"{name} state digest")
        expected_status = (
            "missing_desktop_inventory_adapter"
            if name == "desktop"
            else "root_bound_staged_artifact"
        )
        if (
            item["epoch"] != source["epoch"]
            or item["bound"] is not True
            or item["recoveryFloor"] is not None
            or item["recoveryStateDigest"] is not None
            or item["artifactProofStatus"] != expected_status
        ):
            raise BackupManifestError(f"{name} component proof is not stable")
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
        "v2 capture manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise BackupManifestError("manifest schema is not v2")
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
        raise BackupManifestError("v2 must remain capture-only and not ready")
    if manifest["missingCaptureProofs"] != sorted(REQUIRED_MISSING_CAPTURE_PROOFS):
        raise BackupManifestError("missing capture proofs are not the v2 set")
    if manifest["missingRestoreProofs"] != sorted(REQUIRED_MISSING_RESTORE_PROOFS):
        raise BackupManifestError("missing restore proofs are not the v2 set")
    source = _validate_source(manifest["source"])
    _validate_components(manifest["components"], source)
    quiescence = _require_exact_keys(
        manifest["quiescence"],
        {"status", "writersStoppedClaimed", "evidenceDigest"},
        "v2 quiescence",
    )
    if (
        quiescence["status"] != "external_evidence_bound"
        or quiescence["writersStoppedClaimed"] is not True
    ):
        raise BackupManifestError("external quiescence commitment is required")
    _require_digest(quiescence["evidenceDigest"], "quiescence evidence")
    credentials = _require_exact_keys(
        manifest["credentials"],
        {"disposition", "receiptDigest"},
        "v2 credential disposition",
    )
    if credentials["disposition"] not in {"excluded", "reconfigure_required"}:
        raise BackupManifestError("credential disposition is unsupported")
    _require_digest(credentials["receiptDigest"], "credential receipt")
    records = _validate_artifact_records(manifest["artifacts"])
    if manifest["artifactSetDigest"] != _digest(
        records, domain=_ARTIFACT_SET_DOMAIN
    ):
        raise BackupManifestError("artifact set digest does not match")
    _require_digest(manifest["manifestSha256"], "manifest SHA-256")
    if verify_digest:
        unsigned = dict(manifest)
        del unsigned["manifestSha256"]
        if manifest["manifestSha256"] != _digest(unsigned, domain=_MANIFEST_DOMAIN):
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
    """Build canonical v2 bytes for a closed, already-staged authority tree."""

    if not isinstance(snapshot_id, str) or _SNAPSHOT_RE.fullmatch(snapshot_id) is None:
        raise BackupManifestError("snapshot id is invalid")
    created_at = _require_counter(created_at_unix_ms, "creation timestamp")
    quiescence = _require_digest(quiescence_digest, "quiescence evidence")
    if credential_disposition not in {"excluded", "reconfigure_required"}:
        raise BackupManifestError("credential disposition is unsupported")
    credential_receipt = _require_digest(
        credential_receipt_digest, "credential disposition receipt"
    )
    snapshot_source, snapshot_components = _snapshot_projection(root_snapshot)
    specs = _validate_specs(artifact_specs)
    root = _normalize_artifact_root(artifact_root)
    expected_paths = {item.logical_path for item in specs}
    tree_before = _scan_artifact_tree(root, expected_paths)
    expected_sizes = _preflight_artifact_sizes(tree_before, specs)
    records = [
        _artifact_record(
            root,
            item,
            expected_size=expected_sizes[item.logical_path],
        )
        for item in specs
    ]
    source, components = _root_projection(root / _FIXED_ROLE_PATHS["installation_root"])
    comparable_source = {
        key: value
        for key, value in source.items()
        if key not in {"reanchorReceiptCount", "reanchorChainDigest", "schemaMigrations"}
    }
    if comparable_source != snapshot_source or components != snapshot_components:
        raise BackupManifestError("root snapshot differs from staged Root evidence")
    _validate_projections(root, source, components, records)
    if _scan_artifact_tree(
        root,
        expected_paths,
        expected_sizes=expected_sizes,
    ) != tree_before:
        raise BackupManifestError("artifact tree changed during v2 capture")
    if sum(int(item["byteLength"]) for item in records) > MAX_TOTAL_ARTIFACT_BYTES:
        raise BackupManifestError("artifact total byte limit exceeded")
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
        "artifactSetDigest": _digest(records, domain=_ARTIFACT_SET_DOMAIN),
        "missingRestoreProofs": sorted(REQUIRED_MISSING_RESTORE_PROOFS),
    }
    manifest = dict(unsigned)
    manifest["manifestSha256"] = _digest(unsigned, domain=_MANIFEST_DOMAIN)
    _validate_manifest(manifest)
    encoded = canonical_json_bytes(manifest)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise BackupManifestError("manifest exceeds the v2 byte limit")
    return encoded


def _no_duplicate_keys(pairs):  # noqa: ANN001, ANN201
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
                raise BackupManifestError("manifest JSON exceeds the v2 depth limit")
        elif character in "]}":
            depth -= 1


def _parse_canonical_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        raise ValueError("JSON integer token exceeds the v2 canonical length")
    parsed = int(value, 10)
    if parsed < -_MAX_COUNTER or parsed > _MAX_COUNTER:
        raise ValueError("JSON integer is outside the v2 canonical range")
    return parsed


def _reject_json_number(_value: str) -> float:
    raise ValueError("JSON floats and non-finite numbers are forbidden")


def load_capture_manifest(raw: bytes) -> dict:
    """Parse exact canonical v2 bytes and reject duplicate keys/numbers."""

    if not isinstance(raw, bytes):
        raise BackupManifestError("manifest input must be bytes")
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise BackupManifestError("manifest exceeds the v2 byte limit")
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
    """Rehash and re-inspect the exact v2 artifact tree."""

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
        str(item["logicalPath"]): int(item["byteLength"]) for item in records
    }
    tree_before = _scan_artifact_tree(
        root, expected_paths, expected_sizes=expected_sizes
    )
    for expected, spec in zip(records, specs, strict=True):
        actual = _artifact_record(
            root,
            spec,
            expected_size=int(expected["byteLength"]),
        )
        if actual != expected:
            if actual["byteLength"] != expected["byteLength"]:
                raise BackupManifestError("artifact size does not match v2")
            if actual["sha256"] != expected["sha256"]:
                raise BackupManifestError("artifact SHA-256 does not match v2")
            raise BackupManifestError("artifact metadata does not match v2")
    _validate_projections(
        root,
        manifest["source"],
        manifest["components"],
        records,
    )
    if _scan_artifact_tree(
        root, expected_paths, expected_sizes=expected_sizes
    ) != tree_before:
        raise BackupManifestError("artifact tree changed during v2 verification")
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
