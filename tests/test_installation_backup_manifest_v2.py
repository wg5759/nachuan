from __future__ import annotations

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import json
import os
import shutil
import sqlite3

import pytest

import gateway.installation_backup_manifest_v2 as manifest_v2
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import DurableMediaRequestStore
from gateway.installation_backup_manifest_v2 import (
    ArtifactSpec,
    BackupManifestError,
    MANIFEST_SCHEMA,
    build_capture_manifest,
    canonical_json_bytes,
    load_capture_manifest,
    verify_capture_manifest,
)
from gateway.installation_root import (
    InstallationRoot,
    InstallationRootDependencies,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
)


OWNER_SID = "S-1-5-21-1000-2000-3000-4000"


def digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


class IdentitySource:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, length: int) -> bytes:
        assert length == 32
        self.value += 1
        return self.value.to_bytes(32, "big")


def root_dependencies() -> InstallationRootDependencies:
    return InstallationRootDependencies(
        owner_sid=lambda: OWNER_SID,
        random_bytes=IdentitySource(),
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
    )


def asset_dependencies() -> PaidMediaAssetStoreDependencies:
    return PaidMediaAssetStoreDependencies(
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        disk_free=lambda _path: 32 * 1024 * 1024 * 1024,
    )


def sqlite_snapshot(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(source)) as source_db, closing(
        sqlite3.connect(destination)
    ) as target_db:
        source_db.backup(target_db)
        target_db.execute("PRAGMA journal_mode=DELETE")
        target_db.commit()


def staged_v2_authority(tmp_path: Path):  # noqa: ANN201
    live = tmp_path / "live"
    live.mkdir()
    root = InstallationRoot.provision(
        live / "installation-root.db",
        dependencies=root_dependencies(),
    )
    current = root.snapshot()

    gateway_component = current.component("gateway")
    gateway = DurableMediaRequestStore(
        live / "gateway.db",
        construction_policy="create_bound",
        expected_database_identity=gateway_component.identity,
    )
    gateway_state = gateway.inspect_root_state()
    current = root.bind_component(
        "gateway",
        installation_id=current.installation_id,
        epoch=current.epoch,
        identity=gateway_state.database_identity,
        sequence_floor=gateway_state.mutation_sequence,
        state_digest=gateway_state.state_digest,
        expected_root_revision=current.root_revision,
    ).snapshot

    asset_component = current.component("gateway_assets")
    assets = PaidMediaAssetStore.provision(
        live / "paid-media-assets",
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_database_identity=asset_component.identity,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=asset_dependencies(),
    )
    asset_state = assets.inspect_root_state()
    current = root.bind_component(
        "gateway_assets",
        installation_id=current.installation_id,
        epoch=current.epoch,
        identity=asset_state.database_identity,
        sequence_floor=asset_state.mutation_sequence,
        state_digest=asset_state.state_digest,
        expected_root_revision=current.root_revision,
    ).snapshot

    channel_component = current.component("channel_media")
    channel = DurableChannelMediaRequestStore(
        live / "channel-media.db",
        construction_policy="create_bound",
        expected_database_identity=channel_component.identity,
    )
    channel_state = channel.inspect_root_state()
    current = root.bind_component(
        "channel_media",
        installation_id=current.installation_id,
        epoch=current.epoch,
        identity=channel_state.database_identity,
        sequence_floor=channel_state.mutation_sequence,
        state_digest=channel_state.state_digest,
        expected_root_revision=current.root_revision,
    ).snapshot

    desktop_component = current.component("desktop")
    current = root.bind_component(
        "desktop",
        installation_id=current.installation_id,
        epoch=current.epoch,
        identity=desktop_component.identity,
        sequence_floor=0,
        state_digest=digest("desktop-authority-state"),
        expected_root_revision=current.root_revision,
    ).snapshot
    assert current.status == "active"
    current = root.enter_maintenance(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        reason_digest=digest("backup-v2-operator-maintenance"),
    ).snapshot
    gateway.close()
    assets.close()
    channel.close()

    stage = tmp_path / "stage"
    sqlite_snapshot(
        live / "installation-root.db",
        stage / "authority" / "installation-root.db",
    )
    sqlite_snapshot(live / "gateway.db", stage / "gateway" / "durable-media.db")
    shutil.copyfile(
        live / "gateway.db.rollback-anchor",
        stage / "gateway" / "durable-media.db.rollback-anchor",
    )
    sqlite_snapshot(
        live / "paid-media-assets" / "asset-store.db",
        stage / "gateway-assets" / "asset-store.db",
    )
    shutil.copyfile(
        live / "paid-media-assets" / "asset-store.db.rollback-anchor",
        stage / "gateway-assets" / "asset-store.db.rollback-anchor",
    )
    sqlite_snapshot(
        live / "channel-media.db",
        stage / "channel-media" / "channel-media-requests.db",
    )
    shutil.copyfile(
        live / "channel-media.db.rollback-anchor",
        stage / "channel-media" / "channel-media-requests.db.rollback-anchor",
    )
    return current, stage


def v2_specs() -> tuple[ArtifactSpec, ...]:
    return (
        ArtifactSpec(
            "authority/installation-root.db",
            "installation_root",
            "sqlite",
            "evidence_only",
        ),
        ArtifactSpec(
            "gateway/durable-media.db",
            "gateway_ledger",
            "sqlite",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "gateway/durable-media.db.rollback-anchor",
            "gateway_rollback_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "gateway-assets/asset-store.db",
            "asset_store_database",
            "sqlite",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "gateway-assets/asset-store.db.rollback-anchor",
            "asset_store_rollback_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "channel-media/channel-media-requests.db",
            "channel_media_ledger",
            "sqlite",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "channel-media/channel-media-requests.db.rollback-anchor",
            "channel_media_rollback_anchor",
            "file",
            "restore_reanchor_required",
        ),
    )


def build_v2(snapshot, stage: Path, *, specs=None) -> bytes:  # noqa: ANN001
    return build_capture_manifest(
        snapshot_id=f"snapshot-{digest('backup-v2-snapshot')}",
        created_at_unix_ms=1_800_000_000_000,
        root_snapshot=snapshot,
        artifact_root=stage,
        artifact_specs=v2_specs() if specs is None else specs,
        quiescence_digest=digest("external-quiescence-evidence"),
        credential_disposition="reconfigure_required",
        credential_receipt_digest=digest("credential-disposition-receipt"),
    )


def test_real_root_v5_staging_builds_and_reverifies_capture_only_v2(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)

    raw = build_v2(snapshot, stage)

    manifest = verify_capture_manifest(raw, stage)
    assert manifest["schema"] == MANIFEST_SCHEMA
    assert manifest["captureReady"] is False
    assert manifest["restoreReady"] is False
    assert manifest["source"]["rootSchemaVersion"] == 5
    assert manifest["source"]["schemaMigrations"] == []
    assert tuple(manifest["components"]) == (
        "channel_media",
        "desktop",
        "gateway",
        "gateway_assets",
    )


def test_swapped_rollback_anchor_cannot_be_rebound_by_manifest_hash(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    shutil.copyfile(
        stage / "channel-media" / "channel-media-requests.db.rollback-anchor",
        stage / "gateway" / "durable-media.db.rollback-anchor",
    )

    with pytest.raises(BackupManifestError, match="anchor|Root proof"):
        build_v2(snapshot, stage)


def test_extra_sqlite_schema_object_is_rejected_before_capture(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    with closing(sqlite3.connect(stage / "gateway" / "durable-media.db")) as db:
        db.execute("CREATE TABLE injected_backdoor(value TEXT)")
        db.commit()

    with pytest.raises(BackupManifestError, match="SQLite contract"):
        build_v2(snapshot, stage)


def test_semantically_different_sqlite_ddl_is_rejected_before_capture(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    database = stage / "gateway-assets" / "asset-store.db"
    with closing(sqlite3.connect(database)) as db:
        schema_version = int(db.execute("PRAGMA schema_version").fetchone()[0])
        db.execute("PRAGMA writable_schema=ON")
        changed = db.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='asset_store_meta'",
            ("'manual_only'", "'MANUAL_ONLY'"),
        )
        assert changed.rowcount == 1
        db.execute("PRAGMA writable_schema=OFF")
        db.execute(f"PRAGMA schema_version={schema_version + 1}")
        db.commit()

    with pytest.raises(BackupManifestError, match="SQLite contract"):
        build_v2(snapshot, stage)


def test_schema_fingerprint_preserves_sql_token_boundaries() -> None:
    spaced_tokens = {
        ("table", "example"): (
            "CREATE TABLE example(a INTEGER,aisnull INTEGER,CHECK(a IS NULL))"
        )
    }
    merged_identifier = {
        ("table", "example"): (
            "CREATE TABLE example(a INTEGER,aisnull INTEGER,CHECK(aisnull))"
        )
    }

    assert manifest_v2._schema_fingerprint(
        spaced_tokens
    ) != manifest_v2._schema_fingerprint(merged_identifier)


def test_asset_authority_projection_must_match_its_stored_state_digest(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    database = stage / "gateway-assets" / "asset-store.db"
    with closing(sqlite3.connect(database)) as db:
        db.execute(
            "UPDATE asset_store_meta SET max_capacity_bytes=max_capacity_bytes+1 "
            "WHERE singleton=1"
        )
        db.commit()

    with pytest.raises(BackupManifestError, match="projection"):
        build_v2(snapshot, stage)


def test_asset_reservation_actual_bytes_must_equal_its_asset_lengths(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    database = stage / "gateway-assets" / "asset-store.db"
    with closing(sqlite3.connect(database)) as db:
        db.execute(
            "INSERT INTO asset_reservations "
            "(turn_id,principal_hash,epoch,operation,reserved_bytes,actual_bytes,"
            "state,token_set_digest,created_at) VALUES(?,?,?,?,?,?,'active',NULL,0)",
            (
                digest("reservation-turn"),
                digest("reservation-principal"),
                snapshot.epoch,
                "images.create",
                OPERATION_RESERVATION_BYTES,
                1,
            ),
        )
        db.execute(
            "UPDATE asset_store_meta SET reserved_total_bytes=? WHERE singleton=1",
            (OPERATION_RESERVATION_BYTES,),
        )
        db.commit()

    with pytest.raises(BackupManifestError, match="byte accounting"):
        build_v2(snapshot, stage)


def test_asset_row_count_is_rejected_before_unbounded_projection_reads(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    database = stage / "gateway-assets" / "asset-store.db"
    asset_count = 1_018  # 1,024 total artifacts minus seven singleton roles.
    reservation_count = (asset_count + 3) // 4
    reservations = []
    assets = []
    for reservation_index in range(reservation_count):
        turn_id = digest(f"bounded-asset-turn-{reservation_index}")
        assets_for_turn = min(4, asset_count - reservation_index * 4)
        reservations.append(
            (
                turn_id,
                digest(f"bounded-asset-principal-{reservation_index}"),
                snapshot.epoch,
                "images.create",
                OPERATION_RESERVATION_BYTES,
                assets_for_turn,
                0,
            )
        )
        for ordinal in range(assets_for_turn):
            asset_index = reservation_index * 4 + ordinal
            assets.append(
                (
                    digest(f"bounded-asset-token-{asset_index}"),
                    turn_id,
                    ordinal,
                    "image/png",
                    1,
                    digest(f"bounded-asset-content-{asset_index}"),
                    digest(f"bounded-asset-validation-{asset_index}"),
                    f"{digest(f'bounded-asset-leaf-{asset_index}')}.asset",
                )
            )
    with closing(sqlite3.connect(database)) as db:
        db.executemany(
            "INSERT INTO asset_reservations "
            "(turn_id,principal_hash,epoch,operation,reserved_bytes,actual_bytes,"
            "state,token_set_digest,created_at) VALUES(?,?,?,?,?,?,'active',NULL,?)",
            reservations,
        )
        db.executemany(
            "INSERT INTO paid_media_assets "
            "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
            "validation_receipt_sha256,object_leaf) VALUES(?,?,?,?,?,?,?,?)",
            assets,
        )
        db.commit()

    with pytest.raises(BackupManifestError, match="asset row count"):
        build_v2(snapshot, stage)


def test_staged_root_component_proof_must_equal_supplied_snapshot(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    with closing(
        sqlite3.connect(stage / "authority" / "installation-root.db")
    ) as db:
        db.execute(
            "UPDATE installation_components SET state_digest=? WHERE component='desktop'",
            (digest("tampered-desktop-root-proof"),),
        )
        db.commit()

    with pytest.raises(BackupManifestError, match="snapshot differs"):
        build_v2(snapshot, stage)


def test_manifest_duplicate_keys_and_noncanonical_bytes_are_rejected(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    raw = build_v2(snapshot, stage)
    duplicate = b'{"schema":"nachuan.installation-backup.v2",' + raw[1:]
    with pytest.raises(BackupManifestError, match="duplicate JSON key"):
        load_capture_manifest(duplicate)
    with pytest.raises(BackupManifestError, match="canonical JSON"):
        load_capture_manifest(raw + b"\n")


def test_readiness_flags_cannot_be_promoted_by_self_rehashing(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    value = json.loads(build_v2(snapshot, stage))
    value["captureReady"] = True

    with pytest.raises(BackupManifestError, match="not ready"):
        load_capture_manifest(canonical_json_bytes(value))


def test_unsafe_logical_path_is_rejected_before_tree_access(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    specs = list(v2_specs())
    specs[0] = ArtifactSpec(
        "authority/../installation-root.db",
        specs[0].role,
        specs[0].kind,
        specs[0].restore_policy,
    )

    with pytest.raises(BackupManifestError, match="unsafe segment"):
        build_v2(snapshot, stage, specs=tuple(specs))


def test_hardlinked_artifact_is_rejected_even_when_bytes_match(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    linked = tmp_path / "outside-hardlink.db"
    try:
        os.link(stage / "gateway" / "durable-media.db", linked)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable on test volume: {exc}")

    with pytest.raises(BackupManifestError, match="hardlink"):
        build_v2(snapshot, stage)


def test_reparse_artifact_is_rejected_even_when_target_bytes_match(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    anchor = stage / "channel-media" / "channel-media-requests.db.rollback-anchor"
    outside = tmp_path / "outside-channel-anchor"
    shutil.copyfile(anchor, outside)
    anchor.unlink()
    try:
        os.symlink(outside, anchor)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable on test host: {exc}")

    with pytest.raises(BackupManifestError, match="reparse|ordinary"):
        build_v2(snapshot, stage)


def test_role_size_budget_rejects_oversized_anchor(tmp_path: Path) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    anchor = stage / "gateway" / "durable-media.db.rollback-anchor"
    anchor.write_bytes(b"x" * 1025)

    with pytest.raises(BackupManifestError, match="role limit"):
        build_v2(snapshot, stage)


def test_role_size_preflight_rejects_sparse_oversize_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    anchor = stage / "gateway" / "durable-media.db.rollback-anchor"
    with anchor.open("r+b") as handle:
        handle.truncate(1025)
    hashed_paths: list[Path] = []
    original = manifest_v2._bounded_artifact_record

    def recording_hash(path, spec, *, expected_size=None):  # noqa: ANN001, ANN202
        hashed_paths.append(path)
        return original(path, spec, expected_size=expected_size)

    monkeypatch.setattr(manifest_v2, "_bounded_artifact_record", recording_hash)

    with pytest.raises(BackupManifestError, match="role limit"):
        build_v2(snapshot, stage)
    assert hashed_paths == []


def test_schema_migration_receipt_requires_deterministic_operation_binding(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    with closing(
        sqlite3.connect(stage / "authority" / "installation-root.db")
    ) as db:
        db.execute(
            "INSERT INTO installation_schema_migrations "
            "(target_version,source_version,installation_id,operation_digest,"
            "snapshot_digest,completed_root_revision) VALUES(5,4,?,?,?,2)",
            (
                snapshot.installation_id,
                digest("forged-migration-operation"),
                digest("migration-source-snapshot"),
            ),
        )
        db.commit()

    with pytest.raises(BackupManifestError, match="migration receipt"):
        build_v2(snapshot, stage)


def test_valid_schema_migration_receipt_is_bound_into_manifest_source(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    source_digest = digest("v4-logical-source-snapshot")
    operation = sha256(b"nachuan.installation-root.schema-migration/v1\x00")
    for value in ("4", "5", snapshot.installation_id, source_digest):
        encoded = value.encode("ascii")
        operation.update(len(encoded).to_bytes(8, "big"))
        operation.update(encoded)
    operation_digest = operation.hexdigest()
    with closing(
        sqlite3.connect(stage / "authority" / "installation-root.db")
    ) as db:
        db.execute(
            "INSERT INTO installation_schema_migrations "
            "(target_version,source_version,installation_id,operation_digest,"
            "snapshot_digest,completed_root_revision) VALUES(5,4,?,?,?,2)",
            (
                snapshot.installation_id,
                operation_digest,
                source_digest,
            ),
        )
        db.commit()

    manifest = verify_capture_manifest(build_v2(snapshot, stage), stage)
    assert manifest["source"]["schemaMigrations"] == [
        {
            "sourceVersion": 4,
            "targetVersion": 5,
            "installationId": snapshot.installation_id,
            "operationDigest": operation_digest,
            "snapshotDigest": source_digest,
            "completedRootRevision": 2,
        }
    ]


def test_sqlite_application_identity_is_part_of_frozen_wire_contract(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    with closing(
        sqlite3.connect(stage / "channel-media" / "channel-media-requests.db")
    ) as db:
        db.execute("PRAGMA application_id=0")

    with pytest.raises(BackupManifestError, match="SQLite contract"):
        build_v2(snapshot, stage)


def test_declared_asset_object_must_exist_in_asset_database_projection(
    tmp_path: Path,
) -> None:
    snapshot, stage = staged_v2_authority(tmp_path)
    payload = b"not-authoritative-without-an-asset-row"
    leaf = f"{sha256(payload).hexdigest()}.asset"
    object_path = stage / "gateway-assets" / "objects" / leaf
    object_path.parent.mkdir()
    object_path.write_bytes(payload)
    specs = v2_specs() + (
        ArtifactSpec(
            f"gateway-assets/objects/{leaf}",
            "asset_store_object",
            "file",
            "restore_reanchor_required",
        ),
    )

    with pytest.raises(BackupManifestError, match="do not close"):
        build_v2(snapshot, stage, specs=specs)
