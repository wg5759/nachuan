from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest

from gateway import durable_media_requests as durable_module
from gateway import installation_backup_manifest as manifest_module
from gateway import installation_root as root_module
from gateway import paid_media_asset_store as asset_store_module
from gateway.installation_backup_manifest import (
    ArtifactSpec,
    BackupManifestError,
    build_capture_manifest,
    load_capture_manifest,
    verify_capture_manifest,
)
from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
)


def digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def v1_installation_principal(installation_id: str, epoch: int) -> str:
    return sha256(
        b"nachuan.installation-principal.v1\0"
        + bytes.fromhex(installation_id)
        + epoch.to_bytes(8, "big", signed=False)
    ).hexdigest()


def test_v1_contract_constants_do_not_follow_upstream_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert manifest_module._V1_ROOT_APPLICATION_ID == 0x4E434952
    assert manifest_module._V1_ROOT_SCHEMA_VERSION == 3
    assert manifest_module._V1_GATEWAY_APPLICATION_ID == 0x4E434D52
    assert manifest_module._V1_GATEWAY_SCHEMA_VERSION == 4
    assert (
        manifest_module._V1_GATEWAY_SCHEMA_DDL_SHA256
        == "adbfbca7e42a8560fa18944021b558acbd21b9f51050018bf0e61ec2b0306cc0"
    )
    assert len(manifest_module._V1_GATEWAY_EXPECTED_DDL) == 16
    assert (
        manifest_module._v1_gateway_schema_ddl_sha256(
            manifest_module._V1_GATEWAY_EXPECTED_DDL
        )
        == "adbfbca7e42a8560fa18944021b558acbd21b9f51050018bf0e61ec2b0306cc0"
    )
    assert manifest_module._V1_ASSET_APPLICATION_ID == 0x4E434153
    assert manifest_module._V1_ASSET_SCHEMA_VERSION == 1
    assert (
        manifest_module._V1_ASSET_STORE_SCHEMA
        == "nachuan.paid-media-asset-store.v1"
    )

    monkeypatch.setattr(root_module, "_SCHEMA_VERSION", 400)
    monkeypatch.setattr(root_module, "_EXPECTED_OBJECTS", {})
    monkeypatch.setattr(durable_module, "_SCHEMA_VERSION", 400)
    monkeypatch.setattr(durable_module, "_SCHEMA_AUXILIARY_DDL", {})
    monkeypatch.setattr(asset_store_module, "_SCHEMA_VERSION", 200)
    monkeypatch.setattr(asset_store_module, "_EXPECTED_DDL", {})

    assert manifest_module._V1_ROOT_SCHEMA_VERSION == 3
    assert manifest_module._V1_GATEWAY_SCHEMA_VERSION == 4
    assert manifest_module._V1_ASSET_SCHEMA_VERSION == 1
    assert len(manifest_module._V1_ROOT_EXPECTED_DDL) == 7
    assert len(manifest_module._V1_ASSET_EXPECTED_DDL) == 6


def locked_root_snapshot() -> InstallationRootSnapshot:
    installation_id = digest("backup-installation")
    epoch = 7
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest=digest("backup-owner"),
        epoch=epoch,
        root_revision=41,
        status="maintenance_locked",
        lock_kind="operator",
        lock_reason_digest=digest("backup-maintenance"),
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=v1_installation_principal(installation_id, epoch),
        components=(
            ComponentState(
                component="desktop",
                identity=digest("backup-desktop-identity"),
                epoch=epoch,
                bound=True,
                sequence_floor=17,
                state_digest=digest("backup-desktop-state"),
                recovery_floor=None,
                recovery_state_digest=None,
            ),
            ComponentState(
                component="gateway",
                identity=digest("backup-gateway-identity"),
                epoch=epoch,
                bound=True,
                sequence_floor=0,
                state_digest=manifest_module._v1_gateway_initial_authority_state_digest(
                    digest("backup-gateway-identity")
                ),
                recovery_floor=None,
                recovery_state_digest=None,
            ),
        ),
        updater=UpdaterState(
            release_sequence=9,
            keyring_sequence=4,
            artifact_digest=digest("backup-updater-artifact"),
            state_digest=digest("backup-updater-state"),
        ),
    )


def artifact_specs() -> tuple[ArtifactSpec, ...]:
    return (
        ArtifactSpec(
            "programdata/root/installation-root.db",
            "installation_root_evidence",
            "sqlite",
            "evidence_only",
        ),
        ArtifactSpec(
            "programdata/gateway/paid-media-requests.db",
            "gateway_ledger",
            "sqlite",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "programdata/gateway/paid-media-requests.db.rollback-anchor",
            "gateway_rollback_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "programdata/gateway/writer-owner.receipt",
            "gateway_writer_owner_evidence",
            "file",
            "evidence_only",
        ),
        ArtifactSpec(
            "programdata/assets/asset-store.db",
            "asset_store_database",
            "sqlite",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-ledger.json",
            "desktop_ledger",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-ledger.json.anchor",
            "desktop_ledger_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-ledger.json.pair-intent",
            "desktop_ledger_pair_intent",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-vault.authority.json",
            "desktop_vault_authority_head",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-vault.authority.journal",
            "desktop_vault_authority_journal",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-capacity.json.anchor",
            "desktop_capacity_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-capacity.json.slot-a",
            "desktop_capacity_active_slot",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-installation-authority.json",
            "desktop_installation_authority",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-installation-authority.json.anchor",
            "desktop_installation_authority_anchor",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-installation-authority.json.pair-intent",
            "desktop_installation_authority_pair_intent",
            "file",
            "restore_reanchor_required",
        ),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-legacy-seal.json",
            "desktop_legacy_seal",
            "file",
            "restore_reanchor_required",
        ),
    )


def create_artifact_tree(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    for index, spec in enumerate(artifact_specs()):
        path = root.joinpath(*spec.logical_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if spec.role == "gateway_ledger":
            snapshot = locked_root_snapshot()
            gateway = snapshot.component("gateway")
            with closing(sqlite3.connect(path)) as connection:
                for ddl in manifest_module._V1_GATEWAY_EXPECTED_DDL.values():
                    connection.execute(ddl)
                connection.execute(
                    "INSERT INTO durable_media_requests_meta VALUES"
                    "(1,?,?,?,?,?,'normal',NULL,NULL,NULL,NULL,0,0,0,?,?,?,?)",
                    (
                        manifest_module._V1_GATEWAY_SCHEMA_VERSION,
                        manifest_module._V1_GATEWAY_SCHEMA_FINGERPRINT,
                        gateway.identity,
                        0,
                        gateway.state_digest,
                        manifest_module._V1_GATEWAY_DEFAULT_MAX_RECORDS,
                        manifest_module._V1_GATEWAY_DEFAULT_MAX_RESPONSE_BYTES,
                        manifest_module._V1_GATEWAY_DEFAULT_MAX_TOTAL_RESPONSE_BYTES,
                        manifest_module._V1_GATEWAY_DEFAULT_MAX_DATABASE_BYTES,
                    ),
                )
                connection.execute(
                    "INSERT INTO durable_media_asset_capacity VALUES(1,?,0)",
                    (
                        manifest_module._V1_GATEWAY_DEFAULT_MAX_ASSET_RESERVATION_BYTES,
                    ),
                )
                connection.execute(
                    f"PRAGMA application_id={manifest_module._V1_GATEWAY_APPLICATION_ID}"
                )
                connection.execute(
                    f"PRAGMA user_version={manifest_module._V1_GATEWAY_SCHEMA_VERSION}"
                )
                connection.commit()
                assert (
                    connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
                    == "delete"
                )
            Path(f"{path}.rollback-anchor").write_bytes(
                manifest_module._v1_gateway_anchor_bytes(
                    gateway.identity,
                    gateway.sequence_floor,
                    gateway.state_digest,
                )
            )
            continue
        if spec.role == "gateway_rollback_anchor" and path.exists():
            continue
        if spec.kind == "sqlite":
            connection = sqlite3.connect(path)
            try:
                if spec.role == "installation_root_evidence":
                    snapshot = locked_root_snapshot()
                    for ddl in manifest_module._V1_ROOT_EXPECTED_DDL.values():
                        connection.execute(ddl)
                    connection.execute(
                        "INSERT INTO installation_root "
                        "(singleton,schema_version,installation_id,owner_sid_digest,epoch,"
                        "root_revision,status,lock_kind,lock_reason_digest,reanchor_pending,"
                        "reanchor_operation_digest,reanchor_snapshot_digest,reanchor_source_epoch) "
                        "VALUES(1,?,?,?,?,?,'maintenance_locked','operator',?,0,NULL,NULL,NULL)",
                        (
                            manifest_module._V1_ROOT_SCHEMA_VERSION,
                            snapshot.installation_id,
                            snapshot.owner_sid_digest,
                            snapshot.epoch,
                            snapshot.root_revision,
                            snapshot.lock_reason_digest,
                        ),
                    )
                    for component in snapshot.components:
                        connection.execute(
                            "INSERT INTO installation_components "
                            "(component,identity,epoch,bound,sequence_floor,state_digest,"
                            "recovery_floor,recovery_state_digest) VALUES(?,?,?,?,?,?,NULL,NULL)",
                            (
                                component.component,
                                component.identity,
                                component.epoch,
                                1,
                                component.sequence_floor,
                                component.state_digest,
                            ),
                        )
                    connection.execute(
                        "INSERT INTO installation_updater "
                        "(singleton,release_sequence,keyring_sequence,artifact_digest,state_digest) "
                        "VALUES(1,?,?,?,?)",
                        (
                            snapshot.updater.release_sequence,
                            snapshot.updater.keyring_sequence,
                            snapshot.updater.artifact_digest,
                            snapshot.updater.state_digest,
                        ),
                    )
                    for target_epoch in range(2, snapshot.epoch + 1):
                        connection.execute(
                            "INSERT INTO installation_reanchor_receipts "
                            "(target_epoch,source_epoch,operation_digest,snapshot_digest,"
                            "final_proof_digest,completed_root_revision) VALUES(?,?,?,?,?,?)",
                            (
                                target_epoch,
                                target_epoch - 1,
                                digest(f"root-operation:{target_epoch}"),
                                digest(f"root-snapshot:{target_epoch}"),
                                digest(f"root-proof:{target_epoch}"),
                                5 * target_epoch,
                            ),
                        )
                    connection.execute(
                        f"PRAGMA application_id={manifest_module._V1_ROOT_APPLICATION_ID}"
                    )
                    connection.execute(
                        f"PRAGMA user_version={manifest_module._V1_ROOT_SCHEMA_VERSION}"
                    )
                elif spec.role == "asset_store_database":
                    snapshot = locked_root_snapshot()
                    for ddl in manifest_module._V1_ASSET_EXPECTED_DDL.values():
                        connection.execute(ddl)
                    connection.execute(
                        "INSERT INTO asset_store_meta VALUES(1,?,?,?,?,0)",
                        (
                            manifest_module._V1_ASSET_STORE_SCHEMA,
                            snapshot.installation_id,
                            snapshot.epoch,
                            manifest_module._V1_ASSET_DEFAULT_STORE_CAPACITY_BYTES,
                        ),
                    )
                    connection.execute(
                        f"PRAGMA application_id={manifest_module._V1_ASSET_APPLICATION_ID}"
                    )
                    connection.execute(
                        f"PRAGMA user_version={manifest_module._V1_ASSET_SCHEMA_VERSION}"
                    )
                else:
                    connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
                    connection.execute(
                        "INSERT INTO evidence(value) VALUES(?)",
                        (f"artifact-{index}",),
                    )
                    connection.execute(f"PRAGMA application_id={1000 + index}")
                    connection.execute("PRAGMA user_version=1")
                connection.commit()
                assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
            finally:
                connection.close()
        else:
            path.write_bytes(f"artifact:{index}:{spec.role}\n".encode("utf-8"))
    return root


def add_committed_asset_row(root: Path) -> tuple[str, bytes]:
    payload = b"closed asset object bytes"
    object_sha256 = sha256(payload).hexdigest()
    object_leaf = f"{digest('backup-object-leaf')}.asset"
    database = root / "programdata" / "assets" / "asset-store.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO asset_reservations "
            "(turn_id,principal_hash,epoch,operation,reserved_bytes,actual_bytes,"
            "state,token_set_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                digest("backup-asset-turn"),
                digest("backup-asset-principal"),
                locked_root_snapshot().epoch,
                "images.create",
                manifest_module._V1_ASSET_OPERATION_RESERVATION_BYTES,
                len(payload),
                "committed",
                digest("backup-asset-token-set"),
                1.0,
            ),
        )
        connection.execute(
            "INSERT INTO paid_media_assets "
            "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
            "validation_receipt_sha256,object_leaf) VALUES(?,?,?,?,?,?,?,?)",
            (
                digest("backup-asset-token"),
                digest("backup-asset-turn"),
                0,
                "image/png",
                len(payload),
                object_sha256,
                digest("backup-asset-validation"),
                object_leaf,
            ),
        )
        connection.execute(
            "UPDATE asset_store_meta SET reserved_total_bytes=? WHERE singleton=1",
            (manifest_module._V1_ASSET_OPERATION_RESERVATION_BYTES,),
        )
        connection.commit()
    return object_leaf, payload


def build_manifest(tmp_path: Path, **overrides) -> tuple[bytes, Path]:
    root = create_artifact_tree(tmp_path)
    arguments = {
        "snapshot_id": f"snapshot-{digest('backup-snapshot')}",
        "created_at_unix_ms": 1_784_320_000_000,
        "root_snapshot": locked_root_snapshot(),
        "artifact_root": root,
        "artifact_specs": artifact_specs(),
        "quiescence_digest": digest("backup-quiescence"),
        "credential_disposition": "reconfigure_required",
        "credential_receipt_digest": digest("backup-credential-disposition"),
    }
    arguments.update(overrides)
    return build_capture_manifest(**arguments), root


def test_capture_manifest_is_canonical_deterministic_and_explicitly_not_restore_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, root = build_manifest(tmp_path / "first")
    monkeypatch.setattr(root_module, "_SCHEMA_VERSION", 400)
    monkeypatch.setattr(root_module, "_EXPECTED_OBJECTS", {})
    monkeypatch.setattr(durable_module, "_SCHEMA_VERSION", 400)
    monkeypatch.setattr(durable_module, "_SCHEMA_AUXILIARY_DDL", {})
    monkeypatch.setattr(asset_store_module, "_SCHEMA_VERSION", 200)
    monkeypatch.setattr(asset_store_module, "_EXPECTED_DDL", {})
    second, _ = build_manifest(
        tmp_path / "second",
        artifact_specs=tuple(reversed(artifact_specs())),
    )

    assert first == second
    assert not first.startswith(b"\xef\xbb\xbf")
    parsed = load_capture_manifest(first)
    assert parsed["schema"] == "nachuan.installation-backup.v1"
    assert parsed["capability"] == "capture_only"
    assert parsed["captureReady"] is False
    assert parsed["captureProofStatus"] == "partial"
    assert parsed["missingCaptureProofs"] == sorted(
        manifest_module.REQUIRED_MISSING_CAPTURE_PROOFS
    )
    assert parsed["restoreReady"] is False
    assert parsed["source"]["rootStatus"] == "maintenance_locked"
    assert parsed["source"]["rootLockKind"] == "operator"
    assert parsed["components"]["assetStore"] == {
        "proofStatus": "missing_root_binding"
    }
    assert parsed["quiescence"] == {
        "status": "external_evidence_bound",
        "writersStoppedClaimed": True,
        "evidenceDigest": digest("backup-quiescence"),
    }
    assert parsed["missingRestoreProofs"] == sorted(
        manifest_module.REQUIRED_MISSING_RESTORE_PROOFS
    )
    assert [item["logicalPath"] for item in parsed["artifacts"]] == sorted(
        item.logical_path for item in artifact_specs()
    )
    assert first == manifest_module.canonical_json_bytes(parsed)
    verify_capture_manifest(first, root)


@pytest.mark.parametrize(
    "logical_path",
    [
        "../escape.json",
        "/absolute.json",
        "C:/drive.json",
        "appdata\\backslash.json",
        "appdata//empty.json",
        "appdata/./dot.json",
        "appdata/trailing. ",
        "appdata/config.json:secret",
        "appdata/CON/file.json",
        "appdata/control\x01.json",
        "appdata/e\u0301.json",
        "appdata/desktop/bad?.json",
        "appdata/desktop/Upper.json",
        f"appdata/desktop/{'a' * 256}.json",
    ],
)
def test_manifest_rejects_unsafe_or_noncanonical_logical_paths(
    tmp_path: Path,
    logical_path: str,
) -> None:
    root = create_artifact_tree(tmp_path)
    specs = list(artifact_specs())
    specs[-1] = replace(specs[-1], logical_path=logical_path)

    with pytest.raises(BackupManifestError, match="path"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('unsafe-path')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_manifest_rejects_duplicate_path_before_reading_files(tmp_path: Path) -> None:
    root = create_artifact_tree(tmp_path)
    specs = list(artifact_specs())
    specs.append(
        ArtifactSpec(
            "desktop/user-data/data/paid-media-legacy-seal.json",
            "desktop_legacy_seal",
            "file",
            "restore_reanchor_required",
        )
    )

    with pytest.raises(BackupManifestError, match="collision"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('collision')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_verifier_rejects_missing_extra_and_modified_artifacts(tmp_path: Path) -> None:
    manifest, root = build_manifest(tmp_path)
    target = (
        root / "desktop" / "user-data" / "data" / "paid-media-legacy-seal.json"
    )
    original = target.read_bytes()

    target.write_bytes(original + b"tampered")
    with pytest.raises(BackupManifestError, match="size|SHA-256"):
        verify_capture_manifest(manifest, root)
    target.write_bytes(original)
    verify_capture_manifest(manifest, root)

    extra = root / "unlisted.txt"
    extra.write_bytes(b"extra")
    with pytest.raises(BackupManifestError, match=r"closed.?set"):
        verify_capture_manifest(manifest, root)
    extra.unlink()

    target.unlink()
    with pytest.raises(BackupManifestError, match="closed set"):
        verify_capture_manifest(manifest, root)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"restoreReady": True}),
        lambda value: value.update({"capability": "restore_ready"}),
        lambda value: value.update({"captureReady": True}),
        lambda value: value.update({"captureProofStatus": "complete"}),
        lambda value: value.update({"missingCaptureProofs": []}),
        lambda value: value.update({"unexpected": "field"}),
        lambda value: value.update({"createdAtUnixMs": 1.5}),
        lambda value: value.update({"manifestSha256": "A" * 64}),
        lambda value: value.update({"artifactSetDigest": digest("wrong-set")}),
    ],
)
def test_loader_rejects_noncanonical_or_forged_manifest_fields(
    tmp_path: Path,
    mutation,
) -> None:
    manifest, _root = build_manifest(tmp_path)
    value = json.loads(manifest)
    mutation(value)
    forged = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(BackupManifestError):
        load_capture_manifest(forged)


def test_loader_rejects_pretty_json_duplicate_keys_bom_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _root = build_manifest(tmp_path)
    value = json.loads(manifest)
    pretty = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    with pytest.raises(BackupManifestError, match="canonical"):
        load_capture_manifest(pretty)
    with pytest.raises(BackupManifestError, match="duplicate"):
        load_capture_manifest(b'{"schema":"a","schema":"b"}')
    with pytest.raises(BackupManifestError, match="BOM"):
        load_capture_manifest(b"\xef\xbb\xbf" + manifest)
    monkeypatch.setattr(manifest_module, "MAX_MANIFEST_BYTES", len(manifest) - 1)
    with pytest.raises(BackupManifestError, match="byte limit"):
        load_capture_manifest(manifest)


def test_builder_requires_operator_lock_bound_components_and_exact_principal(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    base = locked_root_snapshot()
    invalid_snapshots = (
        replace(base, status="active", lock_kind="none", lock_reason_digest=None),
        replace(base, lock_kind="integrity"),
        replace(base, reanchor_pending=True),
        replace(base, principal_digest=digest("wrong-principal")),
        replace(
            base,
            components=(replace(base.component("desktop"), bound=False), base.component("gateway")),
        ),
    )

    for invalid in invalid_snapshots:
        with pytest.raises(BackupManifestError):
            build_capture_manifest(
                snapshot_id=f"snapshot-{digest(str(invalid))}",
                created_at_unix_ms=1,
                root_snapshot=invalid,
                artifact_root=root,
                artifact_specs=artifact_specs(),
                quiescence_digest=digest("quiescence"),
                credential_disposition="excluded",
                credential_receipt_digest=digest("credentials"),
            )


def test_builder_rejects_root_evidence_from_a_different_projection(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    drifted = replace(locked_root_snapshot(), root_revision=42)

    with pytest.raises(BackupManifestError, match="root.*projection|projection.*root"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('root-projection-drift')}",
            created_at_unix_ms=1,
            root_snapshot=drifted,
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_builder_rejects_missing_required_role_wrong_policy_and_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_artifact_tree(tmp_path)
    specs = artifact_specs()
    common = {
        "snapshot_id": f"snapshot-{digest('invalid-artifacts')}",
        "created_at_unix_ms": 1,
        "root_snapshot": locked_root_snapshot(),
        "artifact_root": root,
        "quiescence_digest": digest("quiescence"),
        "credential_disposition": "excluded",
        "credential_receipt_digest": digest("credentials"),
    }
    with pytest.raises(BackupManifestError, match="required role"):
        build_capture_manifest(artifact_specs=specs[:-1], **common)
    wrong_policy = list(specs)
    wrong_policy[0] = replace(wrong_policy[0], restore_policy="restore_reanchor_required")
    with pytest.raises(BackupManifestError, match="policy"):
        build_capture_manifest(artifact_specs=wrong_policy, **common)
    monkeypatch.setattr(manifest_module, "MAX_TOTAL_ARTIFACT_BYTES", 1)
    artifact_read_started = False

    def must_not_hash(_path: Path, _spec: ArtifactSpec):
        nonlocal artifact_read_started
        artifact_read_started = True
        raise AssertionError("capacity gate ran after artifact hashing")

    monkeypatch.setattr(manifest_module, "_artifact_record", must_not_hash)
    with pytest.raises(BackupManifestError, match="total byte"):
        build_capture_manifest(artifact_specs=specs, **common)
    assert artifact_read_started is False


@pytest.mark.parametrize(
    "role",
    [
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
    ],
)
def test_builder_requires_each_desktop_authority_artifact(
    tmp_path: Path,
    role: str,
) -> None:
    root = create_artifact_tree(tmp_path)
    specs = tuple(item for item in artifact_specs() if item.role != role)

    with pytest.raises(BackupManifestError, match="required role|cardinality"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest(f'missing:{role}')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.parametrize(
    ("role", "wrong_path"),
    [
        ("desktop_ledger_anchor", "desktop/user-data/data/unbound-ledger.anchor"),
        (
            "desktop_installation_authority_pair_intent",
            "desktop/user-data/data/unbound-authority.pair-intent",
        ),
        (
            "desktop_vault_authority_journal",
            "desktop/user-data/data/unbound-vault.journal",
        ),
        (
            "desktop_capacity_active_slot",
            "desktop/user-data/data/paid-media-capacity.json.slot-c",
        ),
    ],
)
def test_desktop_authority_roles_are_bound_to_production_logical_paths(
    role: str,
    wrong_path: str,
) -> None:
    specs = list(artifact_specs())
    index = next(index for index, item in enumerate(specs) if item.role == role)
    specs[index] = replace(specs[index], logical_path=wrong_path)

    with pytest.raises(BackupManifestError, match="canonical|bound|slot"):
        manifest_module._validate_specs(specs)


def test_capacity_inactive_slot_is_optional_but_must_be_the_other_slot() -> None:
    valid = (
        *artifact_specs(),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-capacity.json.slot-b",
            "desktop_capacity_inactive_slot",
            "file",
            "restore_reanchor_required",
        ),
    )
    assert any(
        item.role == "desktop_capacity_inactive_slot"
        for item in manifest_module._validate_specs(valid)
    )

    invalid = list(valid)
    invalid[-1] = replace(
        invalid[-1],
        logical_path="desktop/user-data/data/paid-media-capacity.json.slot-c",
    )
    with pytest.raises(BackupManifestError, match="inactive slot|canonical slot"):
        manifest_module._validate_specs(invalid)


def test_artifact_path_cannot_also_be_a_parent_directory() -> None:
    specs = (
        *artifact_specs(),
        ArtifactSpec(
            "desktop/user-data/data/paid-media-legacy-seal.json/child",
            "desktop_vault_entry",
            "file",
            "restore_reanchor_required",
        ),
    )
    with pytest.raises(BackupManifestError, match="file.*parent|parent.*file"):
        manifest_module._validate_specs(specs)


def test_builder_rejects_unimplemented_credential_portability_claim(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    with pytest.raises(BackupManifestError, match="credential disposition"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('portable-claim')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="portable_wrapped",
            credential_receipt_digest=digest("credentials"),
        )


def test_builder_rejects_javascript_unsafe_integers_and_non_ascii_paths(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    common = {
        "snapshot_id": f"snapshot-{digest('portable-canonical')}",
        "root_snapshot": locked_root_snapshot(),
        "artifact_root": root,
        "artifact_specs": artifact_specs(),
        "quiescence_digest": digest("quiescence"),
        "credential_disposition": "excluded",
        "credential_receipt_digest": digest("credentials"),
    }
    with pytest.raises(BackupManifestError, match="integer|range"):
        build_capture_manifest(created_at_unix_ms=2**53, **common)

    unsafe_specs = list(artifact_specs())
    unsafe_specs[-1] = replace(
        unsafe_specs[-1],
        logical_path="appdata/desktop/更新状态.json",
    )
    with pytest.raises(BackupManifestError, match="ASCII|path"):
        build_capture_manifest(
            created_at_unix_ms=1,
            artifact_specs=unsafe_specs,
            **{key: value for key, value in common.items() if key != "artifact_specs"},
        )


def test_sqlite_byte_limit_precedes_quick_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_artifact_tree(tmp_path)
    monkeypatch.setattr(manifest_module, "MAX_SQLITE_ARTIFACT_BYTES", 1)
    quick_check_started = False

    def must_not_open_sqlite(_path: Path):
        nonlocal quick_check_started
        quick_check_started = True
        raise AssertionError("SQLite quick_check ran before its byte gate")

    monkeypatch.setattr(manifest_module, "_sqlite_evidence", must_not_open_sqlite)
    with pytest.raises(BackupManifestError, match="SQLite.*byte limit|byte limit.*SQLite"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('sqlite-byte-gate')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )
    assert quick_check_started is False


def test_sqlite_metadata_and_root_identity_are_reverified(tmp_path: Path) -> None:
    manifest, root = build_manifest(tmp_path)
    value = json.loads(manifest)
    root_record = next(
        item for item in value["artifacts"] if item["role"] == "installation_root_evidence"
    )
    assert root_record["sqlite"] == {
        "applicationId": 1313032530,
        "journalMode": "delete",
        "quickCheck": "ok",
        "userVersion": 3,
    }

    connection = sqlite3.connect(root / "programdata" / "root" / "installation-root.db")
    try:
        connection.execute("PRAGMA user_version=4")
    finally:
        connection.close()
    with pytest.raises(BackupManifestError, match="SQLite|SHA-256"):
        verify_capture_manifest(manifest, root)


@pytest.mark.parametrize(
    ("role", "application_id", "user_version"),
    [
        (
            "gateway_ledger",
            durable_module._APPLICATION_ID,
            durable_module._SCHEMA_VERSION,
        ),
        (
            "asset_store_database",
            manifest_module._V1_ASSET_APPLICATION_ID,
            manifest_module._V1_ASSET_SCHEMA_VERSION,
        ),
    ],
)
def test_builder_rejects_sqlite_role_schema_masquerade(
    tmp_path: Path,
    role: str,
    application_id: int,
    user_version: int,
) -> None:
    root = create_artifact_tree(tmp_path)
    spec = next(item for item in artifact_specs() if item.role == role)
    path = root.joinpath(*spec.logical_path.split("/"))
    path.unlink()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence(value) VALUES('masquerade')")
        connection.execute(f"PRAGMA application_id={application_id}")
        connection.execute(f"PRAGMA user_version={user_version}")
        connection.commit()

    with pytest.raises(BackupManifestError, match="schema|role"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest(f'masquerade:{role}')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.parametrize(
    ("role", "application_id", "user_version"),
    [
        ("installation_root_evidence", 0x4E434952, 4),
        ("asset_store_database", 0x4E434153, 2),
    ],
)
def test_builder_rejects_current_v4_v2_schema_as_historical_v1(
    tmp_path: Path,
    role: str,
    application_id: int,
    user_version: int,
) -> None:
    root = create_artifact_tree(tmp_path)
    spec = next(item for item in artifact_specs() if item.role == role)
    path = root.joinpath(*spec.logical_path.split("/"))
    path.unlink()
    expected_ddl = (
        root_module._EXPECTED_OBJECTS
        if role == "installation_root_evidence"
        else asset_store_module._EXPECTED_DDL
    )
    with closing(sqlite3.connect(path)) as connection:
        for ddl in expected_ddl.values():
            connection.execute(ddl)
        connection.execute(f"PRAGMA application_id={application_id}")
        connection.execute(f"PRAGMA user_version={user_version}")
        connection.commit()
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    with pytest.raises(BackupManifestError, match="schema|role"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest(f'current-schema:{role}')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_artifact_root_rejects_hardlinks_and_symlink_or_reparse_when_supported(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    target = (
        root / "desktop" / "user-data" / "data" / "paid-media-legacy-seal.json"
    )
    hardlink = root / "desktop" / "user-data" / "data" / "legacy-hardlink.json"
    os.link(target, hardlink)
    with pytest.raises(BackupManifestError, match=r"hardlink|closed.?set"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('hardlink')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_builder_rechecks_the_whole_tree_after_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_artifact_tree(tmp_path)
    original = manifest_module._artifact_record
    already_changed = False

    def mutate_earlier_file(path: Path, spec: ArtifactSpec):
        nonlocal already_changed
        record = original(path, spec)
        if spec.role == "installation_root_evidence" and not already_changed:
            already_changed = True
            target = (
                root
                / "desktop"
                / "user-data"
                / "data"
                / "paid-media-capacity.json.slot-a"
            )
            target.write_bytes(target.read_bytes() + b"changed-after-hash")
        return record

    monkeypatch.setattr(manifest_module, "_artifact_record", mutate_earlier_file)
    with pytest.raises(BackupManifestError, match="changed during capture"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('whole-tree-recheck')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate data stream contract")
def test_artifact_tree_rejects_alternate_data_streams(tmp_path: Path) -> None:
    root = create_artifact_tree(tmp_path)
    target = (
        root / "desktop" / "user-data" / "data" / "paid-media-legacy-seal.json"
    )
    Path(f"{target}:hidden").write_bytes(b"unlisted secret stream")

    with pytest.raises(BackupManifestError, match="alternate data stream"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('alternate-stream')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction contract")
def test_artifact_root_rejects_a_junction_in_its_parent_chain(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(linked_parent), str(real_parent)],
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable on this Windows host")
    create_artifact_tree(real_parent)
    root = linked_parent / "artifacts"

    with pytest.raises(BackupManifestError, match="parent.*reparse|reparse.*parent"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('parent-junction')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_verifier_rejects_declared_size_mismatch_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, root = build_manifest(tmp_path)
    target = (
        root / "desktop" / "user-data" / "data" / "paid-media-legacy-seal.json"
    )
    target.write_bytes(target.read_bytes() + b"expanded-after-capture")
    hash_started = False

    def must_not_hash(_path: Path):
        nonlocal hash_started
        hash_started = True
        raise AssertionError("verifier hashed before the declared-size gate")

    monkeypatch.setattr(manifest_module, "_fingerprint_file", must_not_hash)
    with pytest.raises(BackupManifestError, match="size|byte length"):
        verify_capture_manifest(manifest, root)
    assert hash_started is False


def test_tree_scan_rejects_first_unexpected_entry_without_materializing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_artifact_tree(tmp_path)

    class UnexpectedEntry:
        name = "unexpected.json"

    class OneThenExplode:
        yielded = 0

        def __enter__(self):
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def __iter__(self):
            return self

        def __next__(self):
            if self.yielded == 0:
                self.yielded += 1
                return UnexpectedEntry()
            raise AssertionError("scanner consumed entries after the first closed-set miss")

    iterator = OneThenExplode()
    monkeypatch.setattr(manifest_module.os, "scandir", lambda _path: iterator)
    with pytest.raises(BackupManifestError, match="closed set|unexpected"):
        manifest_module._scan_artifact_tree(
            root,
            {item.logical_path for item in artifact_specs()},
        )
    assert iterator.yielded == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows directory ADS contract")
@pytest.mark.parametrize("target_kind", ["root", "directory"])
def test_artifact_tree_rejects_root_and_directory_alternate_streams(
    tmp_path: Path,
    target_kind: str,
) -> None:
    root = create_artifact_tree(tmp_path)
    target = root if target_kind == "root" else root / "desktop" / "user-data"
    Path(f"{target}:hidden").write_bytes(b"unlisted directory stream")

    with pytest.raises(BackupManifestError, match="alternate data stream"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest(f'directory-ads:{target_kind}')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_gateway_rollback_anchor_role_must_bind_the_adjacent_authority_path(
    tmp_path: Path,
) -> None:
    root = create_artifact_tree(tmp_path)
    specs = list(artifact_specs())
    anchor_index = next(
        index for index, item in enumerate(specs) if item.role == "gateway_rollback_anchor"
    )
    real_anchor = specs[anchor_index]
    specs[anchor_index] = replace(real_anchor, role="asset_store_object")
    fake_path = "programdata/gateway/unrelated.rollback-anchor"
    specs.append(
        ArtifactSpec(
            fake_path,
            "gateway_rollback_anchor",
            "file",
            "restore_reanchor_required",
        )
    )
    root.joinpath(*fake_path.split("/")).write_bytes(b"unrelated anchor role")

    with pytest.raises(BackupManifestError, match="anchor.*path|path.*anchor"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('misbound-gateway-anchor-role')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.parametrize("disposition", ["excluded", "reconfigure_required"])
def test_capture_never_includes_a_credential_blob(
    tmp_path: Path,
    disposition: str,
) -> None:
    root = create_artifact_tree(tmp_path)
    credential_path = "appdata/desktop/credentials/provider.blob"
    credential = root.joinpath(*credential_path.split("/"))
    credential.parent.mkdir(parents=True, exist_ok=True)
    credential.write_bytes(b"protected credential placeholder")
    specs = (
        *artifact_specs(),
        ArtifactSpec(
            credential_path,
            "credential_blob",
            "file",
            "quarantine_reconfigure",
        ),
    )

    with pytest.raises(BackupManifestError, match="credential"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('excluded-credential-blob')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition=disposition,
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.parametrize("role", ["configuration", "updater_state", "undo_signing_key"])
def test_capture_v1_forbids_secret_bearing_or_local_floor_artifacts(
    tmp_path: Path,
    role: str,
) -> None:
    root = create_artifact_tree(tmp_path)
    forbidden_path = f"desktop/user-data/{role}.json"
    target = root.joinpath(*forbidden_path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"must not enter capture v1")
    specs = (
        *artifact_specs(),
        ArtifactSpec(
            forbidden_path,
            role,
            "file",
            (
                "quarantine_reconfigure"
                if role != "updater_state"
                else "restore_reanchor_required"
            ),
        ),
    )

    with pytest.raises(BackupManifestError, match="forbidden"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest(f'forbidden:{role}')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="reconfigure_required",
            credential_receipt_digest=digest("credentials"),
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"[" * 2_000 + b"0" + b"]" * 2_000,
        b'{"createdAtUnixMs":' + b"9" * 5_000 + b"}",
    ],
)
def test_loader_normalizes_excessive_depth_and_integer_parse_failures(raw: bytes) -> None:
    with pytest.raises(BackupManifestError):
        load_capture_manifest(raw)


def test_asset_database_cannot_omit_a_committed_object(tmp_path: Path) -> None:
    root = create_artifact_tree(tmp_path)
    add_committed_asset_row(root)

    with pytest.raises(BackupManifestError, match="asset.*object|object.*asset"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('missing-asset-object')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=artifact_specs(),
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_asset_object_role_cannot_contain_an_orphan_object(tmp_path: Path) -> None:
    root = create_artifact_tree(tmp_path)
    logical_path = f"programdata/assets/objects/{digest('orphan')}.asset"
    path = root.joinpath(*logical_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"orphan object")
    specs = (
        *artifact_specs(),
        ArtifactSpec(
            logical_path,
            "asset_store_object",
            "file",
            "restore_reanchor_required",
        ),
    )

    with pytest.raises(BackupManifestError, match="asset.*object|object.*asset"):
        build_capture_manifest(
            snapshot_id=f"snapshot-{digest('orphan-asset-object')}",
            created_at_unix_ms=1,
            root_snapshot=locked_root_snapshot(),
            artifact_root=root,
            artifact_specs=specs,
            quiescence_digest=digest("quiescence"),
            credential_disposition="excluded",
            credential_receipt_digest=digest("credentials"),
        )


def test_asset_database_and_object_artifact_close_exactly(tmp_path: Path) -> None:
    root = create_artifact_tree(tmp_path)
    object_leaf, payload = add_committed_asset_row(root)
    logical_path = f"programdata/assets/objects/{object_leaf}"
    path = root.joinpath(*logical_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    specs = (
        *artifact_specs(),
        ArtifactSpec(
            logical_path,
            "asset_store_object",
            "file",
            "restore_reanchor_required",
        ),
    )

    manifest = build_capture_manifest(
        snapshot_id=f"snapshot-{digest('closed-asset-object')}",
        created_at_unix_ms=1,
        root_snapshot=locked_root_snapshot(),
        artifact_root=root,
        artifact_specs=specs,
        quiescence_digest=digest("quiescence"),
        credential_disposition="excluded",
        credential_receipt_digest=digest("credentials"),
    )
    assert verify_capture_manifest(manifest, root)["restoreReady"] is False
