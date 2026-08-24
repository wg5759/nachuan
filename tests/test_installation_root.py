from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from unittest.mock import Mock

import pytest

from gateway import installation_root as installation_root_module
from gateway.installation_root import (
    DEFAULT_DEPENDENCIES,
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootLocked,
    InstallationRootUnavailable,
    owner_sid_digest,
)
from gateway.secure_store import trusted_windows_system_executable


OWNER_SID = "S-1-5-21-1000-2000-3000-4000"


def digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def inject_reserved_prefix_view(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) "
            "VALUES('view','sqlite_nachuan_unauthorized',"
            "'sqlite_nachuan_unauthorized',0,"
            "'CREATE VIEW sqlite_nachuan_unauthorized AS SELECT 1 AS injected_value')"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()
    finally:
        connection.close()


def tamper_schema_tbl_name(path: Path, *, object_name: str, tbl_name: str) -> None:
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone() == (
            "persist",
        )
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name=? WHERE name=?",
            (tbl_name, object_name),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()
    finally:
        connection.close()


class IdentitySource:
    def __init__(self) -> None:
        self.value = 0
        self.lock = threading.Lock()

    def __call__(self, length: int) -> bytes:
        assert length == 32
        with self.lock:
            self.value += 1
            return self.value.to_bytes(32, "big")


class OneShotFault:
    def __init__(self, target: str) -> None:
        self.target = target
        self.triggered = False

    def __call__(self, stage: str) -> None:
        if stage == self.target and not self.triggered:
            self.triggered = True
            raise RuntimeError(f"simulated crash at {stage}")


def dependencies(
    *,
    owner_sid: str = OWNER_SID,
    assert_acl=None,
    harden_acl=None,
    fault=None,
    random_source: IdentitySource | None = None,
    trusted_boundary=None,
) -> InstallationRootDependencies:
    source = random_source or IdentitySource()
    return InstallationRootDependencies(
        owner_sid=lambda: owner_sid,
        random_bytes=source,
        assert_acl=assert_acl or (lambda _path, _directory: None),
        harden_acl=harden_acl or (lambda _path, _directory: None),
        trusted_boundary=trusted_boundary or (lambda path: path.parent),
        fault_injector=fault or (lambda _stage: None),
    )


def provision_active(
    tmp_path: Path,
    *,
    deps: InstallationRootDependencies | None = None,
    name: str = "installation-root.db",
) -> tuple[InstallationRoot, object, dict[str, str]]:
    deps = deps or dependencies()
    root = InstallationRoot.provision(tmp_path / name, dependencies=deps)
    snapshot = root.snapshot()
    state_digests = {
        "desktop": digest(f"{name}:desktop:0"),
        "gateway": digest(f"{name}:gateway:0"),
        "gateway_assets": digest(f"{name}:gateway_assets:0"),
        "channel_media": digest(f"{name}:channel_media:0"),
    }
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = snapshot.component(component)
        result = root.bind_component(
            component,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=state.identity,
            state_digest=state_digests[component],
            expected_root_revision=snapshot.root_revision,
        )
        assert result.applied is True
        snapshot = result.snapshot
    assert snapshot.status == "active"
    return root, snapshot, state_digests


def prepare_reanchor(
    root: InstallationRoot,
    active,
    *,
    label: str,
    snapshot_digest: str | None = None,
):
    operation_digest = digest(f"{label}:operation")
    snapshot_digest = snapshot_digest or digest(f"{label}:snapshot")
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest(f"{label}:maintenance"),
    ).snapshot
    current = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation_digest,
        snapshot_digest=snapshot_digest,
    ).snapshot
    return current, operation_digest, snapshot_digest


def bind_pending_reanchor(
    root: InstallationRoot,
    pending,
    *,
    label: str,
):
    current = pending
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"{label}:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot
    return current


def downgrade_active_fixture_to_v4(path: Path) -> None:
    """Build one exact historical v4 root from a validated active v5 fixture."""

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == "persist"
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA recursive_triggers=ON")
        connection.execute("BEGIN IMMEDIATE")
        for trigger in (
            "installation_schema_migrations_no_replace",
            "installation_schema_migrations_no_update",
            "installation_schema_migrations_no_delete",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("DROP TABLE installation_schema_migrations")
        connection.execute(
            "ALTER TABLE installation_root RENAME TO installation_root_v5_fixture"
        )
        connection.execute(
            "ALTER TABLE installation_components "
            "RENAME TO installation_components_v5_fixture"
        )
        connection.execute(installation_root_module._V4_ROOT_DDL)
        connection.execute(installation_root_module._V4_COMPONENT_DDL)
        connection.execute(
            "INSERT INTO installation_root "
            "(singleton,schema_version,installation_id,owner_sid_digest,epoch,"
            "root_revision,status,lock_kind,lock_reason_digest,reanchor_pending,"
            "reanchor_operation_digest,reanchor_snapshot_digest,"
            "reanchor_source_epoch) "
            "SELECT singleton,4,installation_id,owner_sid_digest,epoch,"
            "root_revision,status,lock_kind,lock_reason_digest,reanchor_pending,"
            "reanchor_operation_digest,reanchor_snapshot_digest,"
            "reanchor_source_epoch FROM installation_root_v5_fixture"
        )
        connection.execute(
            "INSERT INTO installation_components "
            "(component,identity,epoch,bound,sequence_floor,state_digest,"
            "recovery_floor,recovery_state_digest) "
            "SELECT component,identity,epoch,bound,sequence_floor,state_digest,"
            "recovery_floor,recovery_state_digest "
            "FROM installation_components_v5_fixture "
            "WHERE component IN ('desktop','gateway','gateway_assets')"
        )
        connection.execute("DROP TABLE installation_components_v5_fixture")
        connection.execute("DROP TABLE installation_root_v5_fixture")
        connection.execute("PRAGMA user_version=4")
        connection.commit()
    finally:
        connection.close()
    Path(f"{path}-journal").touch(exist_ok=True)


def test_runtime_open_missing_never_creates(tmp_path: Path) -> None:
    path = tmp_path / "missing-installation-root.db"

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=dependencies())

    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_provision_has_closed_schema_fixed_pragmas_and_four_party_activation(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    path = tmp_path / "installation-root.db"
    root = InstallationRoot.provision(path, dependencies=deps)
    initial = root.snapshot()

    assert initial.status == "provisioning"
    assert initial.epoch == 1
    assert initial.root_revision == 1
    assert len(initial.installation_id) == 64
    assert initial.installation_id != "0" * 64
    assert initial.owner_sid_digest == owner_sid_digest(OWNER_SID)
    assert OWNER_SID not in path.read_bytes().decode("latin1", errors="ignore")
    assert {item.component for item in initial.components} == {
        "desktop",
        "gateway",
        "gateway_assets",
        "channel_media",
    }
    assert all(not item.bound and item.sequence_floor == 0 for item in initial.components)
    assert all(item.recovery_floor is None for item in initial.components)
    assert all(item.recovery_state_digest is None for item in initial.components)
    assert len({item.identity for item in initial.components}) == 4
    assert initial.reanchor_operation_digest is None
    assert initial.reanchor_snapshot_digest is None
    assert initial.reanchor_source_epoch is None
    assert initial.updater.state_digest == "0" * 64
    assert Path(f"{path}-journal").is_file()

    connection = root._connect()  # Narrow assertion of connection-scoped policy.
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "persist"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert connection.execute("PRAGMA recursive_triggers").fetchone()[0] == 1
        objects = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT type,name FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        assert objects == {
            ("table", "installation_root"),
            ("table", "installation_components"),
            ("table", "installation_updater"),
            ("table", "installation_reanchor_receipts"),
            ("trigger", "installation_reanchor_receipts_no_replace"),
            ("trigger", "installation_reanchor_receipts_no_update"),
            ("trigger", "installation_reanchor_receipts_no_delete"),
            ("table", "installation_schema_migrations"),
            ("trigger", "installation_schema_migrations_no_replace"),
            ("trigger", "installation_schema_migrations_no_update"),
            ("trigger", "installation_schema_migrations_no_delete"),
        }
        assert connection.execute("PRAGMA application_id").fetchone()[0] == (
            installation_root_module._APPLICATION_ID
        )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
    finally:
        connection.close()

    first = initial.component("desktop")
    after_desktop = root.bind_component(
        "desktop",
        installation_id=initial.installation_id,
        epoch=initial.epoch,
        identity=first.identity,
        state_digest=digest("desktop-initial"),
        expected_root_revision=initial.root_revision,
        sequence_floor=1,
    ).snapshot
    assert after_desktop.status == "provisioning"
    assert after_desktop.component("desktop").bound is True
    assert after_desktop.component("desktop").sequence_floor == 1

    second = after_desktop.component("gateway")
    after_gateway = root.bind_component(
        "gateway",
        installation_id=after_desktop.installation_id,
        epoch=after_desktop.epoch,
        identity=second.identity,
        state_digest=digest("gateway-initial"),
        expected_root_revision=after_desktop.root_revision,
    ).snapshot
    assert after_gateway.status == "provisioning"

    third = after_gateway.component("gateway_assets")
    after_assets = root.bind_component(
        "gateway_assets",
        installation_id=after_gateway.installation_id,
        epoch=after_gateway.epoch,
        identity=third.identity,
        state_digest=digest("gateway-assets-initial"),
        expected_root_revision=after_gateway.root_revision,
    ).snapshot
    assert after_assets.status == "provisioning"

    fourth = after_assets.component("channel_media")
    active = root.bind_component(
        "channel_media",
        installation_id=after_assets.installation_id,
        epoch=after_assets.epoch,
        identity=fourth.identity,
        state_digest=digest("channel-media-initial"),
        expected_root_revision=after_assets.root_revision,
    ).snapshot
    assert active.status == "active"
    assert root.principal() == active.principal_digest
    assert InstallationRoot.open(path, dependencies=deps).principal() == active.principal_digest

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.provision(path, dependencies=deps)


def test_final_provisioning_bind_is_idempotent_after_commit_response_loss(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    path = tmp_path / "bind-response-loss.db"
    root = InstallationRoot.provision(path, dependencies=deps)
    initial = root.snapshot()
    desktop = initial.component("desktop")
    after_desktop = root.bind_component(
        "desktop",
        installation_id=initial.installation_id,
        epoch=initial.epoch,
        identity=desktop.identity,
        state_digest=digest("bind-loss-desktop"),
        expected_root_revision=initial.root_revision,
    ).snapshot
    gateway = after_desktop.component("gateway")
    after_gateway = root.bind_component(
        "gateway",
        installation_id=after_desktop.installation_id,
        epoch=after_desktop.epoch,
        identity=gateway.identity,
        state_digest=digest("bind-loss-gateway"),
        expected_root_revision=after_desktop.root_revision,
    ).snapshot
    gateway_assets = after_gateway.component("gateway_assets")
    gateway_assets_digest = digest("bind-loss-gateway-assets")
    after_assets = root.bind_component(
        "gateway_assets",
        installation_id=after_gateway.installation_id,
        epoch=after_gateway.epoch,
        identity=gateway_assets.identity,
        state_digest=gateway_assets_digest,
        expected_root_revision=after_gateway.root_revision,
    ).snapshot
    channel_media = after_assets.component("channel_media")
    channel_media_digest = digest("bind-loss-channel-media")
    fault = OneShotFault("component_bind.after_commit")
    crashing = InstallationRoot(
        path, dependencies=replace(deps, fault_injector=fault)
    )

    with pytest.raises(InstallationRootUnavailable):
        crashing.bind_component(
            "channel_media",
            installation_id=after_assets.installation_id,
            epoch=after_assets.epoch,
            identity=channel_media.identity,
            state_digest=channel_media_digest,
            expected_root_revision=after_assets.root_revision,
            sequence_floor=7,
        )
    assert fault.triggered is True
    committed = InstallationRoot.open(path, dependencies=deps).snapshot()
    assert committed.status == "active"
    assert committed.component("channel_media").sequence_floor == 7

    retry = root.bind_component(
        "channel_media",
        installation_id=after_assets.installation_id,
        epoch=after_assets.epoch,
        identity=channel_media.identity,
        state_digest=channel_media_digest,
        expected_root_revision=after_assets.root_revision,
        sequence_floor=7,
    )
    assert retry.applied is False
    assert retry.snapshot == committed


def test_installer_migrates_exact_active_v4_into_resumable_v5_component_lock(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="legacy-v4-migration.db",
    )
    legacy_components = {
        item.component: item for item in active.components if item.component != "channel_media"
    }
    legacy_revision = active.root_revision
    downgrade_active_fixture_to_v4(root.path)

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(root.path, dependencies=deps)

    migrated = InstallationRoot.migrate_v4_to_v5(
        root.path,
        dependencies=deps,
    )
    pending = migrated.snapshot()
    connection = sqlite3.connect(root.path)
    try:
        receipt = connection.execute(
            "SELECT source_version,target_version,operation_digest,snapshot_digest,"
            "completed_root_revision FROM installation_schema_migrations"
        ).fetchone()
    finally:
        connection.close()
    assert receipt is not None
    operation = str(receipt[2])
    source_snapshot = str(receipt[3])
    assert operation == installation_root_module._schema_migration_operation_digest(
        pending.installation_id,
        source_snapshot,
    )
    assert Path(f"{root.path}-journal").is_file()

    assert pending.status == "maintenance_locked"
    assert pending.lock_kind == "component_addition"
    assert pending.lock_reason_digest == source_snapshot
    assert pending.root_revision == legacy_revision + 1
    assert pending.component("channel_media").bound is False
    assert {
        item.component for item in pending.components if item.bound
    } == {"desktop", "gateway", "gateway_assets"}
    for name, previous in legacy_components.items():
        current = pending.component(name)
        assert current.identity == previous.identity
        assert current.sequence_floor == previous.sequence_floor
        assert current.state_digest == previous.state_digest

    exact_retry = InstallationRoot.migrate_v4_to_v5(
        root.path,
        dependencies=deps,
    )
    assert exact_retry.snapshot() == pending
    with pytest.raises(InstallationRootLocked, match="receipt does not match"):
        InstallationRoot.migrate_v4_to_v5(
            root.path,
            operation_digest=digest("different-v4-v5-operation"),
            snapshot_digest=source_snapshot,
            dependencies=deps,
        )

    channel = pending.component("channel_media")
    active_v5 = migrated.bind_component(
        "channel_media",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=channel.identity,
        state_digest=digest("migrated-channel-media-initial"),
        expected_root_revision=pending.root_revision,
    ).snapshot
    assert active_v5.status == "active"
    assert active_v5.lock_kind == "none"
    assert active_v5.root_revision == pending.root_revision + 1
    assert InstallationRoot.open(root.path, dependencies=deps).snapshot() == active_v5

    assert receipt == (4, 5, operation, source_snapshot, pending.root_revision)


def test_historical_v4_schema_fingerprint_is_frozen() -> None:
    payload = "\n".join(
        f"{identity[0]}:{identity[1]}:"
        f"{installation_root_module._canonical_sql(definition)}"
        for identity, definition in sorted(
            installation_root_module._V4_EXPECTED_OBJECTS.items()
        )
    ).encode("utf-8")
    assert sha256(payload).hexdigest() == (
        "70d66e31b9a7d375a334cdd57450c33a583fd79651d4dabec36d1271b6cf1674"
    )


def test_runtime_open_rejects_schema_migration_receipt_with_wrong_operation_digest(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="forged-schema-migration-receipt.db",
    )
    downgrade_active_fixture_to_v4(root.path)
    migrated = InstallationRoot.migrate_v4_to_v5(root.path, dependencies=deps)
    pending = migrated.snapshot()
    channel = pending.component("channel_media")
    migrated.bind_component(
        "channel_media",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=channel.identity,
        state_digest=digest("forged-receipt-channel"),
        expected_root_revision=pending.root_revision,
    )

    connection = sqlite3.connect(root.path)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == (
            "persist"
        )
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA recursive_triggers=ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TRIGGER installation_schema_migrations_no_update")
        connection.execute(
            "UPDATE installation_schema_migrations SET operation_digest=? "
            "WHERE target_version=5",
            (digest("wrong-schema-migration-operation"),),
        )
        connection.execute(
            installation_root_module._SCHEMA_MIGRATION_NO_UPDATE_DDL
        )
        connection.commit()
    finally:
        connection.close()
    Path(f"{root.path}-journal").touch(exist_ok=True)

    with pytest.raises(InstallationRootUnavailable) as caught:
        InstallationRoot.open(root.path, dependencies=deps)
    assert "schema migration receipt is invalid" in str(caught.value.__cause__)


def test_v4_migration_rejects_unbound_external_snapshot_identity(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="legacy-v4-wrong-snapshot.db",
    )
    downgrade_active_fixture_to_v4(root.path)

    with pytest.raises(InstallationRootLocked, match="snapshot digest does not match"):
        InstallationRoot.migrate_v4_to_v5(
            root.path,
            snapshot_digest=digest("caller-invented-v4-snapshot"),
            dependencies=deps,
        )
    raw = sqlite3.connect(root.path)
    try:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 4
        assert raw.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE name='installation_schema_migrations'"
        ).fetchone()[0] == 0
    finally:
        raw.close()


@pytest.mark.parametrize(
    "stage",
    ("schema_migration.before_commit", "schema_migration.after_commit"),
)
def test_v4_to_v5_migration_crash_is_atomic_or_exactly_replayable(
    tmp_path: Path,
    stage: str,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name=f"legacy-v4-{stage.rsplit('.', 1)[-1]}.db",
    )
    downgrade_active_fixture_to_v4(root.path)
    fault = OneShotFault(stage)

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.migrate_v4_to_v5(
            root.path,
            dependencies=replace(deps, fault_injector=fault),
        )
    assert fault.triggered is True

    raw = sqlite3.connect(root.path)
    try:
        version_after_crash = raw.execute("PRAGMA user_version").fetchone()[0]
    finally:
        raw.close()
    assert version_after_crash == (4 if stage.endswith("before_commit") else 5)
    assert Path(f"{root.path}-journal").is_file()

    resumed = InstallationRoot.migrate_v4_to_v5(
        root.path,
        dependencies=deps,
    ).snapshot()
    assert resumed.lock_kind == "component_addition"
    assert resumed.component("channel_media").bound is False


def test_v4_migration_rejects_extra_schema_without_mutating_source(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="legacy-v4-extra-object.db",
    )
    downgrade_active_fixture_to_v4(root.path)
    connection = sqlite3.connect(root.path)
    try:
        connection.execute("CREATE TABLE rogue_schema(value TEXT)")
        connection.commit()
    finally:
        connection.close()

    before = root.path.read_bytes()
    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.migrate_v4_to_v5(
            root.path,
            dependencies=deps,
        )
    assert root.path.read_bytes() == before
    raw = sqlite3.connect(root.path)
    try:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 4
        assert raw.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='rogue_schema'"
        ).fetchone()[0] == 1
    finally:
        raw.close()


def test_concurrent_v4_installers_converge_on_one_exact_v5_receipt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="legacy-v4-concurrent-installers.db",
    )
    downgrade_active_fixture_to_v4(root.path)
    original = InstallationRoot._validate_v4_migration_source
    preflight_barrier = threading.Barrier(2)

    def gated_preflight(self, connection, *, expected_owner_digest):  # noqa: ANN001,ANN202
        result = original(
            self,
            connection,
            expected_owner_digest=expected_owner_digest,
        )
        if not connection.in_transaction:
            preflight_barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(
        InstallationRoot,
        "_validate_v4_migration_source",
        gated_preflight,
    )

    def migrate():  # noqa: ANN202
        return InstallationRoot.migrate_v4_to_v5(
            root.path,
            dependencies=deps,
        ).snapshot()

    with ThreadPoolExecutor(max_workers=2) as pool:
        snapshots = list(pool.map(lambda _index: migrate(), range(2)))

    assert snapshots[0] == snapshots[1]
    assert snapshots[0].lock_kind == "component_addition"
    connection = sqlite3.connect(root.path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM installation_schema_migrations"
        ).fetchone()[0] == 1
    finally:
        connection.close()


def test_reanchor_rejects_component_identity_equal_to_installation_identity(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="reanchor-installation-identity-collision.db",
    )
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("identity-collision-maintenance"),
    ).snapshot
    colliding = InstallationRoot(
        root.path,
        dependencies=replace(
            deps,
            random_bytes=lambda length: bytes.fromhex(active.installation_id),
        ),
    )

    with pytest.raises(InstallationRootUnavailable, match="random identity is invalid"):
        colliding.begin_reanchor(
            installation_id=locked.installation_id,
            epoch=locked.epoch,
            expected_root_revision=locked.root_revision,
            operation_digest=digest("identity-collision-operation"),
            snapshot_digest=digest("identity-collision-snapshot"),
        )
    assert root.snapshot() == locked


def test_operator_maintenance_resume_requires_the_complete_four_component_set(
    tmp_path: Path,
) -> None:
    root, active, _state_digests = provision_active(tmp_path)
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("four-component-maintenance"),
    ).snapshot

    resumed = root.resume_active(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
    ).snapshot

    assert resumed.status == "active"
    assert {item.component for item in resumed.components if item.bound} == {
        "desktop",
        "gateway",
        "gateway_assets",
        "channel_media",
    }


def test_bound_component_floor_is_part_of_the_idempotent_binding(tmp_path: Path) -> None:
    deps = dependencies()
    root = InstallationRoot.provision(
        tmp_path / "binding-floor-conflict.db", dependencies=deps
    )
    initial = root.snapshot()
    desktop = initial.component("desktop")
    state_digest = digest("binding-floor-state")
    bound = root.bind_component(
        "desktop",
        installation_id=initial.installation_id,
        epoch=initial.epoch,
        identity=desktop.identity,
        state_digest=state_digest,
        sequence_floor=5,
        expected_root_revision=initial.root_revision,
    ).snapshot
    assert bound.component("desktop").sequence_floor == 5

    with pytest.raises(InstallationRootLocked):
        root.bind_component(
            "desktop",
            installation_id=initial.installation_id,
            epoch=initial.epoch,
            identity=desktop.identity,
            state_digest=state_digest,
            sequence_floor=6,
            expected_root_revision=bound.root_revision,
        )
    assert root.snapshot().lock_kind == "integrity"


def test_zero_digest_cannot_be_used_as_a_component_or_operator_commitment(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "zero-bind.db", dependencies=dependencies()
    )
    initial = root.snapshot()
    with pytest.raises(InstallationRootUnavailable):
        root.bind_component(
            "desktop",
            installation_id=initial.installation_id,
            epoch=initial.epoch,
            identity=initial.component("desktop").identity,
            state_digest="0" * 64,
            expected_root_revision=initial.root_revision,
        )
    assert root.snapshot() == initial

    active_root, active, state_digests = provision_active(
        tmp_path, name="zero-active.db"
    )
    desktop = active.component("desktop")
    with pytest.raises(InstallationRootUnavailable):
        active_root.verify_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            sequence_floor=0,
            state_digest="0" * 64,
        )
    with pytest.raises(InstallationRootUnavailable):
        active_root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=0,
            expected_state_digest=state_digests["desktop"],
            next_floor=1,
            next_state_digest="0" * 64,
            expected_root_revision=active.root_revision,
        )
    with pytest.raises(InstallationRootUnavailable):
        active_root.enter_maintenance(
            installation_id=active.installation_id,
            epoch=active.epoch,
            expected_root_revision=active.root_revision,
            reason_digest="0" * 64,
        )
    with pytest.raises(InstallationRootUnavailable):
        active_root.retire(
            installation_id=active.installation_id,
            epoch=active.epoch,
            expected_root_revision=active.root_revision,
            reason_digest="0" * 64,
        )
    assert active_root.snapshot() == active
    locked = active_root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("valid-zero-test-maintenance"),
    ).snapshot
    for operation_digest, snapshot_digest in (
        ("0" * 64, digest("valid-snapshot")),
        (digest("valid-operation"), "0" * 64),
    ):
        with pytest.raises(InstallationRootUnavailable):
            active_root.begin_reanchor(
                installation_id=locked.installation_id,
                epoch=locked.epoch,
                expected_root_revision=locked.root_revision,
                operation_digest=operation_digest,
                snapshot_digest=snapshot_digest,
            )
        assert active_root.snapshot() == locked


@pytest.mark.parametrize("tamper", ["extra_object", "application_id", "user_version"])
def test_open_rejects_schema_identity_or_extra_objects(
    tmp_path: Path, tamper: str
) -> None:
    deps = dependencies()
    path = tmp_path / f"schema-{tamper}.db"
    InstallationRoot.provision(path, dependencies=deps)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == "persist"
        if tamper == "extra_object":
            connection.execute("CREATE TABLE attacker_extra(value TEXT)")
        elif tamper == "application_id":
            connection.execute("PRAGMA application_id=7")
        else:
            connection.execute("PRAGMA user_version=7")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=deps)


@pytest.mark.parametrize("generation", ("v5", "v4"))
def test_schema_generations_reject_reserved_prefix_object_without_mutation(
    tmp_path: Path, generation: str
) -> None:
    deps = dependencies()
    path = tmp_path / f"reserved-prefix-{generation}.db"
    if generation == "v5":
        InstallationRoot.provision(path, dependencies=deps)
        open_store = lambda: InstallationRoot.open(path, dependencies=deps)
    else:
        root, _active, _digests = provision_active(
            tmp_path, deps=deps, name=path.name
        )
        downgrade_active_fixture_to_v4(root.path)
        open_store = lambda: InstallationRoot.migrate_v4_to_v5(
            path, dependencies=deps
        )
    inject_reserved_prefix_view(path)
    before = path.read_bytes()

    with pytest.raises(InstallationRootUnavailable):
        open_store()
    assert path.read_bytes() == before


def test_open_rejects_internal_object_tbl_name_drift_without_mutation(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    path = tmp_path / "schema-internal-tbl-name.db"
    InstallationRoot.provision(path, dependencies=deps)
    with sqlite3.connect(path) as connection:
        internal_name, original_table = connection.execute(
            "SELECT name,tbl_name FROM sqlite_master "
            "WHERE name LIKE 'sqlite_autoindex_%' ORDER BY name LIMIT 1"
        ).fetchone()
    replacement = (
        "installation_components"
        if original_table != "installation_components"
        else "installation_root"
    )
    tamper_schema_tbl_name(
        path, object_name=str(internal_name), tbl_name=replacement
    )
    before = path.read_bytes()

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=deps)
    assert path.read_bytes() == before


def test_open_rejects_semantically_different_quoted_schema_literal(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    path = tmp_path / "schema-quoted-literal.db"
    InstallationRoot.provision(path, dependencies=deps)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == "persist"
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        changed = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='installation_root'",
            ("'retired'", "'RETIRED'"),
        )
        assert changed.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=deps)


def test_runtime_acl_is_assert_only_and_owner_sid_is_bound(tmp_path: Path) -> None:
    source = IdentitySource()
    good = dependencies(random_source=source)
    path = tmp_path / "acl-root.db"
    InstallationRoot.provision(path, dependencies=good)

    harden = Mock()

    def reject_acl(_path: Path, _directory: bool) -> None:
        raise PermissionError("synthetic broad ACL")

    bad_acl = dependencies(
        random_source=source,
        assert_acl=reject_acl,
        harden_acl=harden,
    )
    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=bad_acl)
    harden.assert_not_called()

    wrong_owner = dependencies(owner_sid="S-1-5-21-9999", random_source=source)
    with pytest.raises(InstallationRootLocked):
        InstallationRoot.open(path, dependencies=wrong_owner)


def test_explicit_provision_may_harden_parent_before_acl_assertion(tmp_path: Path) -> None:
    state = {"parent_hardened": False, "files_hardened": set()}
    path = tmp_path / "installer-acl-root.db"
    journal_path = Path(f"{path}-journal")

    def harden(candidate: Path, directory: bool) -> None:
        if directory:
            assert candidate == tmp_path
            state["parent_hardened"] = True
        else:
            assert candidate in {path, journal_path}
            state["files_hardened"].add(candidate)

    def assert_acl(candidate: Path, directory: bool) -> None:
        if directory and not state["parent_hardened"]:
            raise PermissionError("parent has not been installer-hardened")
        if not directory and candidate not in state["files_hardened"]:
            raise PermissionError("file has not been installer-hardened")

    deps = dependencies(assert_acl=assert_acl, harden_acl=harden)
    root = InstallationRoot.provision(path, dependencies=deps)

    assert state == {
        "parent_hardened": True,
        "files_hardened": {path, journal_path},
    }
    assert root.snapshot().status == "provisioning"


def test_acl_assertion_covers_every_directory_to_explicit_trusted_boundary(
    tmp_path: Path,
) -> None:
    boundary = tmp_path / "Nachuan"
    state_root = boundary / "StateRoot"
    state_root.mkdir(parents=True)
    path = state_root / "installation-root.db"
    asserted: list[tuple[Path, bool]] = []
    deps = dependencies(
        assert_acl=lambda candidate, directory: asserted.append(
            (Path(candidate), directory)
        ),
        trusted_boundary=lambda _path: boundary,
    )

    InstallationRoot.provision(path, dependencies=deps)

    asserted_directories = {candidate for candidate, directory in asserted if directory}
    assert asserted_directories == {boundary, state_root}
    outside = tmp_path / "outside" / "root.db"
    outside.parent.mkdir()
    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(outside, dependencies=deps)
    assert not outside.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Known Folder API")
def test_default_windows_boundary_ignores_programdata_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installation_root_module._windows_program_data.cache_clear()
    expected = installation_root_module._default_trusted_boundary(
        tmp_path / "unused.db"
    )
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "attacker-controlled"))
    installation_root_module._windows_program_data.cache_clear()
    actual = installation_root_module._default_trusted_boundary(
        tmp_path / "unused.db"
    )
    assert actual == expected
    assert actual.name == "Nachuan"
    assert actual.parent != tmp_path / "attacker-controlled"


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Known Folder API")
def test_default_installation_root_path_is_fixed_and_environment_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installation_root_module._windows_program_data.cache_clear()
    expected = installation_root_module.default_installation_root_path()
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "attacker-controlled"))
    installation_root_module._windows_program_data.cache_clear()

    actual = installation_root_module.default_installation_root_path()

    assert actual == expected
    assert actual.parts[-3:] == ("Nachuan", "StateRoot", "installation-root.db")
    assert actual.parent.parent != tmp_path / "attacker-controlled"


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
def test_default_windows_provision_rejects_preowned_boundary_until_hardened(
    tmp_path: Path,
) -> None:
    boundary = tmp_path / "Nachuan"
    state_root = boundary / "StateRoot"
    state_root.mkdir(parents=True)
    DEFAULT_DEPENDENCIES.harden_acl(boundary, True)
    icacls = trusted_windows_system_executable("icacls.exe")
    broadened = subprocess.run(
        [str(icacls), str(boundary), "/grant", "*S-1-5-32-545:(F)"],
        capture_output=True,
        check=False,
    )
    assert broadened.returncode == 0, broadened.stderr
    reowned = subprocess.run(
        [str(icacls), str(boundary), "/setowner", "*S-1-5-32-545", "/q"],
        capture_output=True,
        check=False,
    )
    assert reowned.returncode == 0, reowned.stderr
    deps = replace(
        DEFAULT_DEPENDENCIES,
        trusted_boundary=lambda _path: boundary,
    )
    path = state_root / "installation-root.db"

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.provision(path, dependencies=deps)
    assert not path.exists()

    # Only the explicit Nachuan boundary is repaired.  The shared temp root is
    # never touched, mirroring the production prohibition on changing C:\\ or
    # ProgramData itself.
    DEFAULT_DEPENDENCIES.harden_acl(boundary, True)
    root = InstallationRoot.provision(path, dependencies=deps)
    assert root.snapshot().status == "provisioning"


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
def test_default_windows_acl_persistent_journal_survives_mutation_and_crash(
    tmp_path: Path,
) -> None:
    boundary = tmp_path / "Nachuan"
    state_root = boundary / "StateRoot"
    state_root.mkdir(parents=True)
    DEFAULT_DEPENDENCIES.harden_acl(boundary, True)
    deps = replace(
        DEFAULT_DEPENDENCIES,
        trusted_boundary=lambda _path: boundary,
    )
    path = state_root / "installation-root.db"
    root = InstallationRoot.provision(path, dependencies=deps)
    snapshot = root.snapshot()
    state_digests = {
        "desktop": digest("windows-acl-desktop"),
        "gateway": digest("windows-acl-gateway"),
        "gateway_assets": digest("windows-acl-gateway-assets"),
        "channel_media": digest("windows-acl-channel-media"),
    }
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        component_state = snapshot.component(component)
        snapshot = root.bind_component(
            component,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=component_state.identity,
            state_digest=state_digests[component],
            expected_root_revision=snapshot.root_revision,
        ).snapshot

    started = time.perf_counter()
    for _index in range(5):
        root.snapshot()
    elapsed = time.perf_counter() - started
    # Five snapshots previously spawned roughly 200 whoami/icacls processes and
    # took more than five seconds on the reference host.  Keep a wide budget so
    # this protects the architecture without becoming a load-sensitive microbench.
    assert elapsed < 1.5

    journal = Path(f"{path}-journal")
    journal_identity = installation_root_module._identity(os.lstat(journal))
    deps.assert_acl(path, False)
    deps.assert_acl(journal, False)

    desktop = snapshot.component("desktop")
    crash_script = """
from dataclasses import replace
import os
from pathlib import Path
import sys
from gateway.installation_root import DEFAULT_DEPENDENCIES, InstallationRoot

path = Path(sys.argv[1])
boundary = Path(sys.argv[2])

def crash(stage: str) -> None:
    if stage == "component_advance.after_floor_update":
        os._exit(73)

deps = replace(
    DEFAULT_DEPENDENCIES,
    trusted_boundary=lambda _path: boundary,
    fault_injector=crash,
)
root = InstallationRoot(path, dependencies=deps)
root.advance_component(
    "desktop",
    installation_id=sys.argv[3],
    epoch=int(sys.argv[4]),
    identity=sys.argv[5],
    expected_floor=0,
    expected_state_digest=sys.argv[6],
    next_floor=1,
    next_state_digest=sys.argv[7],
    expected_root_revision=int(sys.argv[8]),
)
"""
    crashed = subprocess.run(
        [
            sys.executable,
            "-c",
            crash_script,
            str(path),
            str(boundary),
            snapshot.installation_id,
            str(snapshot.epoch),
            desktop.identity,
            state_digests["desktop"],
            digest("windows-acl-desktop-next"),
            str(snapshot.root_revision),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert crashed.returncode == 73, (crashed.stdout, crashed.stderr)

    reopened = InstallationRoot.open(path, dependencies=deps)
    after_crash = reopened.snapshot()
    assert after_crash.component("desktop").sequence_floor == 0
    assert installation_root_module._identity(os.lstat(journal)) == journal_identity
    deps.assert_acl(journal, False)
    advanced = reopened.advance_component(
        "desktop",
        installation_id=after_crash.installation_id,
        epoch=after_crash.epoch,
        identity=after_crash.component("desktop").identity,
        expected_floor=0,
        expected_state_digest=state_digests["desktop"],
        next_floor=1,
        next_state_digest=digest("windows-acl-desktop-next"),
        expected_root_revision=after_crash.root_revision,
    )
    assert advanced.snapshot.component("desktop").sequence_floor == 1
    assert installation_root_module._identity(os.lstat(journal)) == journal_identity
    deps.assert_acl(journal, False)


def test_open_rejects_reparse_file_without_following_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deps = dependencies()
    path = tmp_path / "reparse-root.db"
    InstallationRoot.provision(path, dependencies=deps)
    original_lstat = installation_root_module.os.lstat

    class ReparseInfo:
        def __init__(self, wrapped) -> None:
            self._wrapped = wrapped
            self.st_file_attributes = 0x400

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    def fake_lstat(candidate):
        info = original_lstat(candidate)
        if os.path.normcase(os.fspath(candidate)) == os.path.normcase(os.fspath(path)):
            return ReparseInfo(info)
        return info

    monkeypatch.setattr(installation_root_module.os, "lstat", fake_lstat)
    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(path, dependencies=deps)


def test_concurrent_component_cas_has_one_applier_and_one_idempotent_observer(
    tmp_path: Path,
) -> None:
    root, active, state_digests = provision_active(tmp_path)
    desktop = active.component("desktop")
    next_digest = digest("desktop:1")
    barrier = threading.Barrier(2)

    def advance() -> bool:
        barrier.wait(timeout=5)
        return root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=0,
            expected_state_digest=state_digests["desktop"],
            next_floor=1,
            next_state_digest=next_digest,
            expected_root_revision=active.root_revision,
        ).applied

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: advance(), range(2)))

    assert sorted(results) == [False, True]
    verified = root.verify_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        sequence_floor=1,
        state_digest=next_digest,
    )
    assert verified.applied is False
    assert verified.snapshot.component("desktop").sequence_floor == 1


def test_stale_component_cas_cannot_integrity_lock_a_newer_commit(
    tmp_path: Path,
) -> None:
    root, active, state_digests = provision_active(
        tmp_path, name="stale-component-cas.db"
    )
    desktop = active.component("desktop")
    committed = root.advance_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        expected_floor=0,
        expected_state_digest=state_digests["desktop"],
        next_floor=1,
        next_state_digest=digest("winning-component-state"),
        expected_root_revision=active.root_revision,
    ).snapshot

    with pytest.raises(InstallationRootUnavailable, match="CAS revision changed"):
        root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=0,
            expected_state_digest=state_digests["desktop"],
            next_floor=1,
            next_state_digest=digest("stale-losing-component-state"),
            expected_root_revision=active.root_revision,
        )
    assert root.snapshot() == committed
    assert root.snapshot().status == "active"


def test_component_floor_transitions_reject_state_digest_reuse(tmp_path: Path) -> None:
    root, active, state_digests = provision_active(
        tmp_path, name="component-digest-reuse.db"
    )
    desktop = active.component("desktop")

    with pytest.raises(InstallationRootUnavailable, match="change state digest"):
        root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=0,
            expected_state_digest=state_digests["desktop"],
            next_floor=1,
            next_state_digest=state_digests["desktop"],
            expected_root_revision=active.root_revision,
        )
    assert root.snapshot() == active

    recovered = root.verify_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        sequence_floor=1,
        state_digest=digest("component-digest-reuse:recovered"),
        previous_state_digest=state_digests["desktop"],
    )
    fenced = recovered.snapshot.component("desktop")
    with pytest.raises(InstallationRootUnavailable, match="change state digest"):
        root.acknowledge_component_recovery(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            recovery_floor=fenced.sequence_floor,
            recovery_state_digest=str(fenced.state_digest),
            next_floor=fenced.sequence_floor + 1,
            next_state_digest=str(fenced.state_digest),
            expected_root_revision=recovered.snapshot.root_revision,
        )
    assert root.snapshot() == recovered.snapshot


def test_floor_plus_one_recovers_only_with_previous_digest_proof(tmp_path: Path) -> None:
    fault = OneShotFault("component_advance.before_commit")
    deps = dependencies(fault=fault)
    root, active, state_digests = provision_active(tmp_path, deps=deps)
    desktop = active.component("desktop")
    next_digest = digest("local-committed-desktop:1")

    with pytest.raises(InstallationRootUnavailable):
        root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=0,
            expected_state_digest=state_digests["desktop"],
            next_floor=1,
            next_state_digest=next_digest,
            expected_root_revision=active.root_revision,
        )
    assert fault.triggered is True
    assert root.snapshot().component("desktop").sequence_floor == 0

    recovered = root.verify_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        sequence_floor=1,
        state_digest=next_digest,
        previous_state_digest=state_digests["desktop"],
    )
    assert recovered.applied is True
    assert recovered.recovered is True
    fenced = recovered.snapshot.component("desktop")
    assert fenced.sequence_floor == 1
    assert fenced.recovery_floor == 1
    assert fenced.recovery_state_digest == next_digest

    exact_retry = root.verify_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        sequence_floor=1,
        state_digest=next_digest,
        previous_state_digest=state_digests["desktop"],
    )
    assert exact_retry.applied is False
    assert exact_retry.recovered is True

    with pytest.raises(InstallationRootLocked, match="must be acknowledged"):
        root.advance_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            expected_floor=1,
            expected_state_digest=next_digest,
            next_floor=2,
            next_state_digest=digest("desktop:2"),
            expected_root_revision=exact_retry.snapshot.root_revision,
        )

    acknowledged = root.acknowledge_component_recovery(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        recovery_floor=1,
        recovery_state_digest=next_digest,
        next_floor=2,
        next_state_digest=digest("desktop:manual-only:2"),
        expected_root_revision=exact_retry.snapshot.root_revision,
    )
    assert acknowledged.applied is True
    assert acknowledged.snapshot.component("desktop").recovery_floor is None
    assert acknowledged.snapshot.component("desktop").sequence_floor == 2
    acknowledgement_retry = root.acknowledge_component_recovery(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        recovery_floor=1,
        recovery_state_digest=next_digest,
        next_floor=2,
        next_state_digest=digest("desktop:manual-only:2"),
        expected_root_revision=exact_retry.snapshot.root_revision,
    )
    assert acknowledgement_retry.applied is False
    assert acknowledgement_retry.snapshot == acknowledged.snapshot


def test_floor_recovery_survives_commit_response_loss(tmp_path: Path) -> None:
    fault = OneShotFault("component_verify.after_commit")
    deps = dependencies(fault=fault)
    root, active, state_digests = provision_active(
        tmp_path, deps=deps, name="verify-response-loss.db"
    )
    desktop = active.component("desktop")
    next_digest = digest("response-loss-local-state")

    with pytest.raises(InstallationRootUnavailable):
        root.verify_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            sequence_floor=1,
            state_digest=next_digest,
            previous_state_digest=state_digests["desktop"],
        )

    retry = root.verify_component(
        "desktop",
        installation_id=active.installation_id,
        epoch=active.epoch,
        identity=desktop.identity,
        sequence_floor=1,
        state_digest=next_digest,
        previous_state_digest=state_digests["desktop"],
    )
    assert retry.applied is False
    assert retry.recovered is True
    assert retry.snapshot.component("desktop").recovery_floor == 1


def test_unproven_floor_plus_one_and_coordinated_old_snapshot_lock_root(
    tmp_path: Path,
) -> None:
    root, active, state_digests = provision_active(tmp_path)
    snapshot = active
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        current = snapshot.component(component)
        result = root.advance_component(
            component,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=current.identity,
            expected_floor=0,
            expected_state_digest=state_digests[component],
            next_floor=1,
            next_state_digest=digest(f"{component}:new-snapshot"),
            expected_root_revision=snapshot.root_revision,
        )
        snapshot = result.snapshot

    # Both local datasets are now presented as one coordinated old snapshot.
    old_desktop = active.component("desktop")
    with pytest.raises(InstallationRootLocked):
        root.verify_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=old_desktop.identity,
            sequence_floor=0,
            state_digest=state_digests["desktop"],
        )

    locked = root.snapshot()
    assert locked.status == "maintenance_locked"
    assert locked.lock_kind == "integrity"
    with pytest.raises(InstallationRootLocked):
        root.principal()


@pytest.mark.parametrize("conflict", ["digest", "jump"])
def test_component_digest_and_jump_conflicts_lock_root(
    tmp_path: Path, conflict: str
) -> None:
    root, active, state_digests = provision_active(
        tmp_path, name=f"conflict-{conflict}.db"
    )
    desktop = active.component("desktop")
    installation_id = active.installation_id
    sequence_floor = 0
    state_digest = state_digests["desktop"]
    previous_state_digest = None
    if conflict == "digest":
        state_digest = digest("conflicting-same-floor-digest")
    else:
        sequence_floor = 2
        state_digest = digest("jumped-two-floors")
        previous_state_digest = state_digests["desktop"]

    with pytest.raises(InstallationRootLocked):
        root.verify_component(
            "desktop",
            installation_id=installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            sequence_floor=sequence_floor,
            state_digest=state_digest,
            previous_state_digest=previous_state_digest,
        )

    assert root.snapshot().lock_kind == "integrity"


@pytest.mark.parametrize(
    ("fault_stage", "lock_committed"),
    [
        ("component_verify.before_commit", False),
        ("component_verify.after_commit", True),
    ],
)
def test_integrity_lock_uses_common_commit_fence_and_fault_hooks(
    tmp_path: Path,
    fault_stage: str,
    lock_committed: bool,
) -> None:
    deps = dependencies()
    root, active, state_digests = provision_active(
        tmp_path,
        deps=deps,
        name=f"integrity-fence-{fault_stage.rsplit('.', 1)[-1]}.db",
    )
    desktop = active.component("desktop")
    fault = OneShotFault(fault_stage)
    crashing = InstallationRoot(
        root.path,
        dependencies=replace(deps, fault_injector=fault),
    )

    with pytest.raises(InstallationRootUnavailable):
        crashing.verify_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=desktop.identity,
            sequence_floor=desktop.sequence_floor,
            state_digest=digest(f"conflict:{fault_stage}"),
            previous_state_digest=state_digests["desktop"],
        )
    assert fault.triggered is True

    reopened = InstallationRoot.open(root.path, dependencies=deps)
    if lock_committed:
        assert reopened.snapshot().lock_kind == "integrity"
    else:
        assert reopened.snapshot().status == "active"
        with pytest.raises(InstallationRootLocked):
            reopened.verify_component(
                "desktop",
                installation_id=active.installation_id,
                epoch=active.epoch,
                identity=desktop.identity,
                sequence_floor=desktop.sequence_floor,
                state_digest=digest(f"conflict:{fault_stage}"),
                previous_state_digest=state_digests["desktop"],
            )
        assert reopened.snapshot().lock_kind == "integrity"


def test_stale_installation_or_epoch_requests_never_rewrite_current_root(
    tmp_path: Path,
) -> None:
    root, old_active, old_digests = provision_active(
        tmp_path, name="stale-generation.db"
    )
    locked = root.enter_maintenance(
        installation_id=old_active.installation_id,
        epoch=old_active.epoch,
        expected_root_revision=old_active.root_revision,
        reason_digest=digest("stale-generation-maintenance"),
    ).snapshot
    operation = digest("stale-generation-reanchor-operation")
    restore_snapshot = digest("stale-generation-restore-snapshot")
    pending = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=restore_snapshot,
    ).snapshot
    current = pending
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        component_state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=component_state.identity,
            state_digest=digest(f"stale-generation:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot
    current = root.complete_reanchor(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        operation_digest=operation,
        snapshot_digest=restore_snapshot,
        final_proof_digest=digest("stale-generation-final-proof"),
    ).snapshot
    assert current.status == "active"
    old_desktop = old_active.component("desktop")

    with pytest.raises(InstallationRootLocked, match="epoch does not match"):
        root.verify_component(
            "desktop",
            installation_id=old_active.installation_id,
            epoch=old_active.epoch,
            identity=old_desktop.identity,
            sequence_floor=0,
            state_digest=old_digests["desktop"],
        )
    assert root.snapshot() == current

    with pytest.raises(InstallationRootLocked, match="epoch does not match"):
        root.advance_component(
            "desktop",
            installation_id=old_active.installation_id,
            epoch=old_active.epoch,
            identity=old_desktop.identity,
            expected_floor=0,
            expected_state_digest=old_digests["desktop"],
            next_floor=1,
            next_state_digest=digest("stale-generation-next"),
            expected_root_revision=old_active.root_revision,
        )
    assert root.snapshot() == current

    with pytest.raises(InstallationRootLocked, match="identity does not match"):
        root.verify_component(
            "desktop",
            installation_id=digest("another-installation"),
            epoch=current.epoch,
            identity=current.component("desktop").identity,
            sequence_floor=0,
            state_digest=digest("stale-generation:desktop"),
        )
    assert root.snapshot() == current

    next_maintenance = root.enter_maintenance(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        reason_digest=digest("next-maintenance"),
    ).snapshot
    with pytest.raises(InstallationRootLocked, match="historically completed"):
        root.begin_reanchor(
            installation_id=old_active.installation_id,
            epoch=old_active.epoch,
            expected_root_revision=locked.root_revision,
            operation_digest=operation,
            snapshot_digest=restore_snapshot,
        )
    assert root.snapshot() == next_maintenance


def test_maintenance_reanchor_changes_epoch_identities_and_principal_then_retires(
    tmp_path: Path,
) -> None:
    root, active, _state_digests = provision_active(tmp_path)
    old_principal = root.principal()
    old_identities = {item.component: item.identity for item in active.components}

    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("authorized restore"),
    ).snapshot
    assert locked.status == "maintenance_locked"
    with pytest.raises(InstallationRootLocked):
        root.principal()

    reanchored = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=digest("restore-operation"),
        snapshot_digest=digest("restore-snapshot"),
    ).snapshot
    assert reanchored.epoch == active.epoch + 1
    assert reanchored.reanchor_pending is True
    assert reanchored.reanchor_operation_digest == digest("restore-operation")
    assert reanchored.reanchor_snapshot_digest == digest("restore-snapshot")
    assert reanchored.reanchor_source_epoch == active.epoch
    assert all(not item.bound for item in reanchored.components)
    assert all(old_identities[item.component] != item.identity for item in reanchored.components)

    current = reanchored
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"reanchor:{component}:0"),
            expected_root_revision=current.root_revision,
        ).snapshot
    current = root.complete_reanchor(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        operation_digest=digest("restore-operation"),
        snapshot_digest=digest("restore-snapshot"),
        final_proof_digest=digest("restore-final-proof"),
    ).snapshot
    assert current.status == "active"
    assert current.reanchor_operation_digest == digest("restore-operation")
    assert current.reanchor_snapshot_digest == digest("restore-snapshot")
    assert current.reanchor_source_epoch == active.epoch
    assert current.principal_digest != old_principal
    assert root.principal() == current.principal_digest

    completed_retry = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=digest("restore-operation"),
        snapshot_digest=digest("restore-snapshot"),
    )
    assert completed_retry.applied is False
    assert completed_retry.snapshot == current
    with pytest.raises(InstallationRootLocked, match="not pending"):
        root.begin_reanchor(
            installation_id=locked.installation_id,
            epoch=locked.epoch,
            expected_root_revision=current.root_revision,
            operation_digest=digest("different-completed-operation"),
            snapshot_digest=digest("restore-snapshot"),
        )
    assert root.snapshot() == current

    retired = root.retire(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        reason_digest=digest("full uninstall confirmation"),
    ).snapshot
    assert retired.status == "retired"
    with pytest.raises(InstallationRootLocked):
        root.principal()
    with pytest.raises(InstallationRootLocked):
        root.verify_component(
            "desktop",
            installation_id=active.installation_id,
            epoch=active.epoch,
            identity=old_identities["desktop"],
            sequence_floor=0,
            state_digest=digest("old"),
        )


def test_pending_reanchor_is_idempotent_and_cannot_nest_or_be_poisoned(
    tmp_path: Path,
) -> None:
    root, active, _ = provision_active(tmp_path, name="reanchor-idempotence.db")
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("maintenance-idempotence"),
    ).snapshot
    operation = digest("reanchor-operation-idempotence")
    snapshot_digest = digest("reanchor-snapshot-idempotence")
    pending = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    ).snapshot

    retry = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    )
    assert retry.applied is False
    assert retry.snapshot == pending

    for candidate_epoch, candidate_operation, candidate_snapshot in (
        (pending.epoch, operation, snapshot_digest),
        (locked.epoch, digest("different-operation"), snapshot_digest),
        (locked.epoch, operation, digest("different-snapshot")),
    ):
        with pytest.raises(InstallationRootLocked, match="already in progress"):
            root.begin_reanchor(
                installation_id=locked.installation_id,
                epoch=candidate_epoch,
                expected_root_revision=pending.root_revision,
                operation_digest=candidate_operation,
                snapshot_digest=candidate_snapshot,
            )
        assert root.snapshot() == pending

    desktop = pending.component("desktop")
    partially_bound = root.bind_component(
        "desktop",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=desktop.identity,
        state_digest=digest("reanchor-desktop-bound"),
        expected_root_revision=pending.root_revision,
    ).snapshot
    late_retry = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    )
    assert late_retry.applied is False
    assert late_retry.snapshot == partially_bound
    assert late_retry.snapshot.lock_kind == "reanchor"


def test_reanchor_component_bindings_remain_locked_until_final_proof(
    tmp_path: Path,
) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-final-proof.db",
    )
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("restore-maintenance"),
    ).snapshot
    current = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=digest("restore-operation"),
        snapshot_digest=digest("restore-snapshot"),
    ).snapshot
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"restored:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot

    assert all(item.bound for item in current.components)
    assert current.status == "maintenance_locked"
    assert current.lock_kind == "reanchor"
    assert current.reanchor_pending is True
    with pytest.raises(InstallationRootLocked):
        root.principal()


def test_complete_reanchor_requires_exact_durable_final_proof(tmp_path: Path) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="reanchor-completion-proof.db",
    )
    operation = digest("completion-operation")
    snapshot_digest = digest("completion-snapshot")
    final_proof = digest("completion-final-proof")
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("completion-maintenance"),
    ).snapshot
    current = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    ).snapshot
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"completion:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot

    completed = root.complete_reanchor(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=final_proof,
    )
    assert completed.applied is True
    assert completed.snapshot.status == "active"
    assert completed.snapshot.reanchor_pending is False
    assert root.principal() == completed.snapshot.principal_digest

    reopened = InstallationRoot.open(root.path, dependencies=deps)
    replay = reopened.complete_reanchor(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=final_proof,
    )
    assert replay.applied is False
    assert replay.snapshot == completed.snapshot
    with pytest.raises(InstallationRootLocked, match="proof"):
        reopened.complete_reanchor(
            installation_id=current.installation_id,
            epoch=current.epoch,
            expected_root_revision=completed.snapshot.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=digest("different-final-proof"),
        )
    assert reopened.snapshot() == completed.snapshot


def test_complete_reanchor_without_every_binding_is_noop(tmp_path: Path) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-incomplete-proof.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label="incomplete-proof",
    )
    desktop = pending.component("desktop")
    partially_bound = root.bind_component(
        "desktop",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=desktop.identity,
        state_digest=digest("incomplete-proof:desktop"),
        expected_root_revision=pending.root_revision,
    ).snapshot
    gateway = partially_bound.component("gateway")
    partially_bound = root.bind_component(
        "gateway",
        installation_id=partially_bound.installation_id,
        epoch=partially_bound.epoch,
        identity=gateway.identity,
        state_digest=digest("incomplete-proof:gateway"),
        expected_root_revision=partially_bound.root_revision,
    ).snapshot
    assert partially_bound.component("desktop").bound is True
    assert partially_bound.component("gateway").bound is True
    assert partially_bound.component("gateway_assets").bound is False

    with pytest.raises(InstallationRootLocked, match="every component"):
        root.complete_reanchor(
            installation_id=partially_bound.installation_id,
            epoch=partially_bound.epoch,
            expected_root_revision=partially_bound.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=digest("incomplete-proof:final"),
        )

    assert root.snapshot() == partially_bound
    connection = sqlite3.connect(root.path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM installation_reanchor_receipts"
        ).fetchone()[0] == 0
    finally:
        connection.close()


def test_reanchor_receipt_remains_idempotence_source_after_maintenance(
    tmp_path: Path,
) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-receipt-idempotence.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label="receipt-idempotence",
    )
    bound = bind_pending_reanchor(
        root,
        pending,
        label="receipt-idempotence",
    )
    proof = digest("receipt-idempotence:proof")
    completed = root.complete_reanchor(
        installation_id=bound.installation_id,
        epoch=bound.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=proof,
    ).snapshot
    locked = root.enter_maintenance(
        installation_id=completed.installation_id,
        epoch=completed.epoch,
        expected_root_revision=completed.root_revision,
        reason_digest=digest("receipt-idempotence:later-maintenance"),
    ).snapshot
    with pytest.raises(InstallationRootLocked, match="historically completed"):
        root.complete_reanchor(
            installation_id=locked.installation_id,
            epoch=locked.epoch,
            expected_root_revision=bound.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=proof,
        )
    assert root.snapshot() == locked
    resumed = root.resume_active(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
    ).snapshot
    assert resumed.reanchor_operation_digest is None

    replay = root.complete_reanchor(
        installation_id=resumed.installation_id,
        epoch=resumed.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=proof,
    )
    assert replay.applied is False
    assert replay.snapshot == resumed
    with pytest.raises(InstallationRootLocked, match="proof"):
        root.complete_reanchor(
            installation_id=resumed.installation_id,
            epoch=resumed.epoch,
            expected_root_revision=resumed.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=digest("receipt-idempotence:different-proof"),
        )
    assert root.snapshot() == resumed
    retired = root.retire(
        installation_id=resumed.installation_id,
        epoch=resumed.epoch,
        expected_root_revision=resumed.root_revision,
        reason_digest=digest("receipt-idempotence:retired"),
    ).snapshot
    with pytest.raises(InstallationRootLocked, match="historically completed"):
        root.complete_reanchor(
            installation_id=retired.installation_id,
            epoch=retired.epoch,
            expected_root_revision=retired.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=proof,
        )
    assert root.snapshot() == retired


@pytest.mark.parametrize("same_proof", [True, False])
def test_concurrent_reanchor_completion_commits_exactly_one_receipt(
    tmp_path: Path,
    same_proof: bool,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name=f"reanchor-concurrent-{same_proof}.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label=f"concurrent-{same_proof}",
    )
    bound = bind_pending_reanchor(
        root,
        pending,
        label=f"concurrent-{same_proof}",
    )
    first_proof = digest(f"concurrent-{same_proof}:proof:first")
    second_proof = (
        first_proof
        if same_proof
        else digest(f"concurrent-{same_proof}:proof:second")
    )
    start = threading.Barrier(2)

    def complete(proof: str):
        candidate = InstallationRoot(root.path, dependencies=deps)
        start.wait(timeout=10)
        try:
            result = candidate.complete_reanchor(
                installation_id=bound.installation_id,
                epoch=bound.epoch,
                expected_root_revision=bound.root_revision,
                operation_digest=operation,
                snapshot_digest=snapshot_digest,
                final_proof_digest=proof,
            )
            return "result", result.applied
        except InstallationRootLocked:
            return "locked", None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(complete, (first_proof, second_proof)))

    if same_proof:
        assert sorted(outcomes) == [("result", False), ("result", True)]
    else:
        assert sorted(outcomes) == [("locked", None), ("result", True)]
    connection = sqlite3.connect(root.path)
    try:
        receipts = connection.execute(
            "SELECT final_proof_digest FROM installation_reanchor_receipts"
        ).fetchall()
    finally:
        connection.close()
    assert len(receipts) == 1
    assert receipts[0][0] in {first_proof, second_proof}
    assert root.require_active().epoch == bound.epoch


def test_second_reanchor_allows_same_snapshot_but_rejects_reused_operation(
    tmp_path: Path,
) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-second-epoch.db",
    )
    shared_snapshot = digest("shared-backup-snapshot")
    pending, first_operation, _ = prepare_reanchor(
        root,
        active,
        label="first-restore",
        snapshot_digest=shared_snapshot,
    )
    bound = bind_pending_reanchor(root, pending, label="first-restore")
    completed = root.complete_reanchor(
        installation_id=bound.installation_id,
        epoch=bound.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=first_operation,
        snapshot_digest=shared_snapshot,
        final_proof_digest=digest("first-restore:proof"),
    ).snapshot
    locked = root.enter_maintenance(
        installation_id=completed.installation_id,
        epoch=completed.epoch,
        expected_root_revision=completed.root_revision,
        reason_digest=digest("second-restore:maintenance"),
    ).snapshot

    with pytest.raises(InstallationRootLocked, match="already completed"):
        root.begin_reanchor(
            installation_id=locked.installation_id,
            epoch=locked.epoch,
            expected_root_revision=locked.root_revision,
            operation_digest=first_operation,
            snapshot_digest=shared_snapshot,
        )
    assert root.snapshot() == locked

    resumed = root.resume_active(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
    ).snapshot
    historical_replay = root.begin_reanchor(
        installation_id=resumed.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        operation_digest=first_operation,
        snapshot_digest=shared_snapshot,
    )
    assert historical_replay.applied is False
    assert historical_replay.snapshot == resumed
    locked = root.enter_maintenance(
        installation_id=resumed.installation_id,
        epoch=resumed.epoch,
        expected_root_revision=resumed.root_revision,
        reason_digest=digest("second-restore:maintenance-again"),
    ).snapshot

    second = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=digest("second-restore:operation"),
        snapshot_digest=shared_snapshot,
    )
    assert second.applied is True
    assert second.snapshot.epoch == completed.epoch + 1
    assert second.snapshot.reanchor_snapshot_digest == shared_snapshot


def test_retire_cannot_destroy_a_pending_reanchor(tmp_path: Path) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-retire-guard.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label="retire-guard",
    )

    with pytest.raises(InstallationRootLocked, match="reanchor"):
        root.retire(
            installation_id=pending.installation_id,
            epoch=pending.epoch,
            expected_root_revision=pending.root_revision,
            reason_digest=digest("retire-guard:reason"),
        )
    assert root.snapshot() == pending

    bound = bind_pending_reanchor(root, pending, label="retire-guard")
    completed = root.complete_reanchor(
        installation_id=bound.installation_id,
        epoch=bound.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=digest("retire-guard:proof"),
    )
    assert completed.applied is True
    assert completed.snapshot.status == "active"


def test_reanchor_receipts_reject_update_delete_and_insert_or_replace(
    tmp_path: Path,
) -> None:
    root, active, _ = provision_active(
        tmp_path,
        name="reanchor-append-only.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label="append-only",
    )
    bound = bind_pending_reanchor(root, pending, label="append-only")
    proof = digest("append-only:proof")
    root.complete_reanchor(
        installation_id=bound.installation_id,
        epoch=bound.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=proof,
    )

    connection = sqlite3.connect(root.path)
    try:
        assert connection.execute("PRAGMA recursive_triggers").fetchone() == (0,)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE installation_reanchor_receipts SET final_proof_digest=? "
                "WHERE target_epoch=2",
                (digest("append-only:update"),),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM installation_reanchor_receipts WHERE target_epoch=2"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "INSERT OR REPLACE INTO installation_reanchor_receipts "
                "SELECT target_epoch,source_epoch,operation_digest,snapshot_digest,?,"
                "completed_root_revision FROM installation_reanchor_receipts "
                "WHERE target_epoch=2",
                (digest("append-only:replace"),),
            )
        connection.rollback()
        assert connection.execute(
            "SELECT final_proof_digest FROM installation_reanchor_receipts "
            "WHERE target_epoch=2"
        ).fetchone() == (proof,)
    finally:
        connection.close()


def test_missing_middle_reanchor_receipt_fails_closed_after_trigger_recreated(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, current, _ = provision_active(
        tmp_path,
        deps=deps,
        name="reanchor-missing-middle.db",
    )
    for restore_number in (1, 2):
        pending, operation, snapshot_digest = prepare_reanchor(
            root,
            current,
            label=f"chain-{restore_number}",
        )
        bound = bind_pending_reanchor(
            root,
            pending,
            label=f"chain-{restore_number}",
        )
        current = root.complete_reanchor(
            installation_id=bound.installation_id,
            epoch=bound.epoch,
            expected_root_revision=bound.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=digest(f"chain-{restore_number}:proof"),
        ).snapshot

    connection = sqlite3.connect(root.path)
    try:
        connection.execute("DROP TRIGGER installation_reanchor_receipts_no_delete")
        connection.execute(
            "DELETE FROM installation_reanchor_receipts WHERE target_epoch=2"
        )
        connection.execute(installation_root_module._REANCHOR_RECEIPT_NO_DELETE_DDL)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(root.path, dependencies=deps)


def test_corrupt_huge_epoch_fails_without_materializing_epoch_range(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="reanchor-huge-epoch.db",
    )
    connection = sqlite3.connect(root.path)
    try:
        connection.execute(
            "UPDATE installation_root SET epoch=? WHERE singleton=1",
            (installation_root_module._MAX_COUNTER,),
        )
        connection.execute(
            "UPDATE installation_components SET epoch=?",
            (installation_root_module._MAX_COUNTER,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(root.path, dependencies=deps)


def test_open_rejects_authority_files_over_the_policy_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deps = dependencies()
    root, _active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="root-byte-limit.db",
    )
    monkeypatch.setattr(
        installation_root_module,
        "_MAX_AUTHORITY_FILE_BYTES",
        root.path.stat().st_size - 1,
    )

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(root.path, dependencies=deps)


def test_open_rejects_receipt_history_over_the_policy_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name="root-receipt-limit.db",
    )
    pending, operation, snapshot_digest = prepare_reanchor(
        root,
        active,
        label="receipt-limit",
    )
    bound = bind_pending_reanchor(root, pending, label="receipt-limit")
    root.complete_reanchor(
        installation_id=bound.installation_id,
        epoch=bound.epoch,
        expected_root_revision=bound.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=digest("receipt-limit:proof"),
    )
    monkeypatch.setattr(
        installation_root_module,
        "_MAX_REANCHOR_RECEIPTS",
        0,
    )

    with pytest.raises(InstallationRootUnavailable):
        InstallationRoot.open(root.path, dependencies=deps)


@pytest.mark.parametrize(
    "crash_stage",
    [
        "reanchor_complete.after_receipt",
        "reanchor_complete.after_root_update",
        "reanchor_complete.before_commit",
        "reanchor_complete.after_commit",
    ],
)
def test_complete_reanchor_crash_is_locked_or_exactly_replayable(
    tmp_path: Path,
    crash_stage: str,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path,
        deps=deps,
        name=f"complete-{crash_stage.rsplit('.', 1)[-1]}.db",
    )
    operation = digest(f"operation:{crash_stage}")
    snapshot_digest = digest(f"snapshot:{crash_stage}")
    final_proof = digest(f"proof:{crash_stage}")
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest(f"maintenance:{crash_stage}"),
    ).snapshot
    current = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    ).snapshot
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"{crash_stage}:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot

    fault = OneShotFault(crash_stage)
    crashing = InstallationRoot(
        root.path,
        dependencies=replace(deps, fault_injector=fault),
    )
    with pytest.raises(InstallationRootUnavailable):
        crashing.complete_reanchor(
            installation_id=current.installation_id,
            epoch=current.epoch,
            expected_root_revision=current.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=final_proof,
        )
    assert fault.triggered is True

    reopened = InstallationRoot.open(root.path, dependencies=deps)
    after_crash = reopened.snapshot()
    if crash_stage == "reanchor_complete.after_commit":
        assert after_crash.status == "active"
        retry = reopened.complete_reanchor(
            installation_id=current.installation_id,
            epoch=current.epoch,
            expected_root_revision=current.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=final_proof,
        )
        assert retry.applied is False
    else:
        assert after_crash.status == "maintenance_locked"
        assert after_crash.reanchor_pending is True
        retry = reopened.complete_reanchor(
            installation_id=current.installation_id,
            epoch=current.epoch,
            expected_root_revision=current.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
            final_proof_digest=final_proof,
        )
        assert retry.applied is True
        assert retry.snapshot.status == "active"


def test_final_reanchor_bind_is_idempotent_after_commit_response_loss(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root, active, _ = provision_active(
        tmp_path, deps=deps, name="reanchor-bind-response-loss.db"
    )
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest("reanchor-bind-maintenance"),
    ).snapshot
    pending = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=digest("reanchor-bind-operation"),
        snapshot_digest=digest("reanchor-bind-snapshot"),
    ).snapshot
    desktop = pending.component("desktop")
    after_desktop = root.bind_component(
        "desktop",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=desktop.identity,
        state_digest=digest("reanchor-bind-desktop"),
        expected_root_revision=pending.root_revision,
    ).snapshot
    gateway = after_desktop.component("gateway")
    after_gateway = root.bind_component(
        "gateway",
        installation_id=after_desktop.installation_id,
        epoch=after_desktop.epoch,
        identity=gateway.identity,
        state_digest=digest("reanchor-bind-gateway"),
        expected_root_revision=after_desktop.root_revision,
    ).snapshot
    gateway_assets = after_gateway.component("gateway_assets")
    gateway_assets_digest = digest("reanchor-bind-gateway-assets")
    after_assets = root.bind_component(
        "gateway_assets",
        installation_id=after_gateway.installation_id,
        epoch=after_gateway.epoch,
        identity=gateway_assets.identity,
        state_digest=gateway_assets_digest,
        expected_root_revision=after_gateway.root_revision,
    ).snapshot
    channel_media = after_assets.component("channel_media")
    channel_media_digest = digest("reanchor-bind-channel-media")
    fault = OneShotFault("component_bind.after_commit")
    crashing = InstallationRoot(
        root.path, dependencies=replace(deps, fault_injector=fault)
    )

    with pytest.raises(InstallationRootUnavailable):
        crashing.bind_component(
            "channel_media",
            installation_id=after_assets.installation_id,
            epoch=after_assets.epoch,
            identity=channel_media.identity,
            state_digest=channel_media_digest,
            expected_root_revision=after_assets.root_revision,
        )
    assert fault.triggered is True
    committed = InstallationRoot.open(root.path, dependencies=deps).snapshot()
    assert committed.status == "maintenance_locked"
    assert committed.reanchor_pending is True
    assert committed.epoch == pending.epoch
    assert all(item.bound for item in committed.components)

    retry = root.bind_component(
        "channel_media",
        installation_id=after_assets.installation_id,
        epoch=after_assets.epoch,
        identity=channel_media.identity,
        state_digest=channel_media_digest,
        expected_root_revision=after_assets.root_revision,
    )
    assert retry.applied is False
    assert retry.snapshot == committed
    completed = root.complete_reanchor(
        installation_id=committed.installation_id,
        epoch=committed.epoch,
        expected_root_revision=committed.root_revision,
        operation_digest=digest("reanchor-bind-operation"),
        snapshot_digest=digest("reanchor-bind-snapshot"),
        final_proof_digest=digest("reanchor-bind-final-proof"),
    ).snapshot
    assert completed.status == "active"


def test_updater_floors_allow_strict_jumps_bind_state_and_reject_rollback(
    tmp_path: Path,
) -> None:
    root, active, _state_digests = provision_active(tmp_path)
    artifact_one = digest("release-artifact-1")
    state_one = digest("verified-updater-state-1")
    advanced = root.advance_updater(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_release_sequence=0,
        expected_keyring_sequence=0,
        expected_artifact_digest="0" * 64,
        expected_updater_state_digest="0" * 64,
        next_release_sequence=10,
        next_keyring_sequence=4,
        next_artifact_digest=artifact_one,
        next_updater_state_digest=state_one,
        expected_root_revision=active.root_revision,
    ).snapshot
    assert advanced.updater.release_sequence == 10
    assert advanced.updater.keyring_sequence == 4
    assert advanced.updater.state_digest == state_one

    artifact_two = digest("release-artifact-2")
    state_two = digest("verified-updater-state-2")
    recovered = root.verify_updater(
        installation_id=advanced.installation_id,
        epoch=advanced.epoch,
        release_sequence=12,
        keyring_sequence=9,
        artifact_digest=artifact_two,
        updater_state_digest=state_two,
        previous_release_sequence=10,
        previous_keyring_sequence=4,
        previous_artifact_digest=artifact_one,
        previous_updater_state_digest=state_one,
    )
    assert recovered.recovered is True
    assert recovered.snapshot.updater.release_sequence == 12
    assert recovered.snapshot.updater.keyring_sequence == 9

    keyring_only_state = digest("verified-keyring-only-state")
    keyring_only = root.advance_updater(
        installation_id=advanced.installation_id,
        epoch=advanced.epoch,
        expected_release_sequence=12,
        expected_keyring_sequence=9,
        expected_artifact_digest=artifact_two,
        expected_updater_state_digest=state_two,
        next_release_sequence=12,
        next_keyring_sequence=15,
        next_artifact_digest=artifact_two,
        next_updater_state_digest=keyring_only_state,
        expected_root_revision=recovered.snapshot.root_revision,
    ).snapshot
    assert keyring_only.updater.release_sequence == 12
    assert keyring_only.updater.keyring_sequence == 15
    assert keyring_only.updater.artifact_digest == artifact_two

    with pytest.raises(InstallationRootLocked):
        root.verify_updater(
            installation_id=advanced.installation_id,
            epoch=advanced.epoch,
            release_sequence=10,
            keyring_sequence=4,
            artifact_digest=artifact_one,
            updater_state_digest=state_one,
        )
    assert root.snapshot().lock_kind == "integrity"


def test_stale_updater_cas_cannot_lock_a_newer_release(tmp_path: Path) -> None:
    root, active, _ = provision_active(tmp_path, name="stale-updater-cas.db")
    artifact_ten = digest("artifact-ten")
    state_ten = digest("updater-state-ten")
    release_ten = root.advance_updater(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_release_sequence=0,
        expected_keyring_sequence=0,
        expected_artifact_digest="0" * 64,
        expected_updater_state_digest="0" * 64,
        next_release_sequence=10,
        next_keyring_sequence=2,
        next_artifact_digest=artifact_ten,
        next_updater_state_digest=state_ten,
        expected_root_revision=active.root_revision,
    ).snapshot
    release_twelve = root.advance_updater(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_release_sequence=10,
        expected_keyring_sequence=2,
        expected_artifact_digest=artifact_ten,
        expected_updater_state_digest=state_ten,
        next_release_sequence=12,
        next_keyring_sequence=4,
        next_artifact_digest=digest("artifact-twelve"),
        next_updater_state_digest=digest("updater-state-twelve"),
        expected_root_revision=release_ten.root_revision,
    ).snapshot

    with pytest.raises(InstallationRootUnavailable, match="CAS revision changed"):
        root.advance_updater(
            installation_id=active.installation_id,
            epoch=active.epoch,
            expected_release_sequence=10,
            expected_keyring_sequence=2,
            expected_artifact_digest=artifact_ten,
            expected_updater_state_digest=state_ten,
            next_release_sequence=11,
            next_keyring_sequence=3,
            next_artifact_digest=digest("stale-artifact-eleven"),
            next_updater_state_digest=digest("stale-updater-state-eleven"),
            expected_root_revision=release_ten.root_revision,
        )
    assert root.snapshot() == release_twelve
    assert root.snapshot().status == "active"


@pytest.mark.parametrize(
    "crash_stage",
    [
        "reanchor.after_root_update",
        "reanchor.after_desktop_reset",
        "reanchor.after_gateway_assets_reset",
        "reanchor.before_commit",
        "reanchor.after_commit",
    ],
)
def test_reanchor_crash_points_remain_locked_and_can_continue(
    tmp_path: Path, crash_stage: str
) -> None:
    fault = OneShotFault(crash_stage)
    deps = dependencies(fault=fault)
    root, active, _state_digests = provision_active(
        tmp_path, deps=deps, name=f"reanchor-{crash_stage.rsplit('.', 1)[-1]}.db"
    )
    locked = root.enter_maintenance(
        installation_id=active.installation_id,
        epoch=active.epoch,
        expected_root_revision=active.root_revision,
        reason_digest=digest(f"maintenance:{crash_stage}"),
    ).snapshot
    operation = digest(f"operation:{crash_stage}")
    snapshot_digest = digest(f"snapshot:{crash_stage}")

    with pytest.raises(InstallationRootUnavailable):
        root.begin_reanchor(
            installation_id=locked.installation_id,
            epoch=locked.epoch,
            expected_root_revision=locked.root_revision,
            operation_digest=operation,
            snapshot_digest=snapshot_digest,
        )
    assert fault.triggered is True

    after_crash = InstallationRoot.open(root.path, dependencies=deps).snapshot()
    assert after_crash.status == "maintenance_locked"
    retry = root.begin_reanchor(
        installation_id=locked.installation_id,
        epoch=locked.epoch,
        expected_root_revision=locked.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
    )
    after_crash = retry.snapshot
    assert after_crash.reanchor_pending is True
    assert after_crash.lock_kind == "reanchor"
    assert after_crash.reanchor_operation_digest == operation
    assert after_crash.reanchor_source_epoch == locked.epoch

    current = after_crash
    for component in ("desktop", "gateway", "gateway_assets", "channel_media"):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=digest(f"{crash_stage}:{component}"),
            expected_root_revision=current.root_revision,
        ).snapshot
    current = root.complete_reanchor(
        installation_id=current.installation_id,
        epoch=current.epoch,
        expected_root_revision=current.root_revision,
        operation_digest=operation,
        snapshot_digest=snapshot_digest,
        final_proof_digest=digest(f"final-proof:{crash_stage}"),
    ).snapshot
    assert current.status == "active"
    assert current.epoch == active.epoch + 1
