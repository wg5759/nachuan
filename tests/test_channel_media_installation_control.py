from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sqlite3
import threading

import pytest

from gateway import installation_root as installation_root_module
from gateway.channel_media_installation_control import (
    ChannelMediaInstallationControl,
    ChannelMediaInstallationControlUnavailable,
)
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import DurableMediaRequestUnavailable
from gateway.installation_root import InstallationRoot, InstallationRootDependencies


OWNER_SID = "S-1-5-21-1000-2000-3000-4000"


def digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


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
    def __init__(self, stage: str) -> None:
        self.stage = stage
        self.triggered = False

    def __call__(self, current: str) -> None:
        if current == self.stage and not self.triggered:
            self.triggered = True
            raise RuntimeError("simulated response loss")


def dependencies(*, fault=None) -> InstallationRootDependencies:
    return InstallationRootDependencies(
        owner_sid=lambda: OWNER_SID,
        random_bytes=IdentitySource(),
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
        fault_injector=fault or (lambda _stage: None),
    )


def activate_other_components(root: InstallationRoot) -> None:
    snapshot = root.snapshot()
    for name in ("desktop", "gateway", "gateway_assets"):
        component = snapshot.component(name)
        snapshot = root.bind_component(
            name,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=component.identity,
            sequence_floor=0,
            state_digest=digest(f"activate:{name}"),
            expected_root_revision=snapshot.root_revision,
        ).snapshot
    assert snapshot.status == "active"


def active_control(tmp_path: Path, *, deps=None, name: str = "authority"):
    root = InstallationRoot.provision(
        tmp_path / f"{name}-root.db", dependencies=deps or dependencies()
    )
    path = tmp_path / f"{name}-channel-media.db"
    control = ChannelMediaInstallationControl.provision(root, path)
    activate_other_components(root)
    assert control.reconcile_startup().mode == "ready"
    return root, control, path


def downgrade_active_fixture_to_v4(path: Path) -> None:
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
            "reanchor_operation_digest,reanchor_snapshot_digest,reanchor_source_epoch) "
            "SELECT singleton,4,installation_id,owner_sid_digest,epoch,root_revision,"
            "status,lock_kind,lock_reason_digest,reanchor_pending,"
            "reanchor_operation_digest,reanchor_snapshot_digest,reanchor_source_epoch "
            "FROM installation_root_v5_fixture"
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


def test_normal_open_never_creates_and_explicit_provision_binds_channel_component(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "root.db", dependencies=dependencies()
    )
    path = tmp_path / "channel-media.db"

    with pytest.raises(ChannelMediaInstallationControlUnavailable):
        ChannelMediaInstallationControl.open_bound(root, path)
    assert not path.exists()
    assert not Path(f"{path}.rollback-anchor").exists()

    control = ChannelMediaInstallationControl.provision(root, path)
    try:
        snapshot = root.snapshot()
        component = snapshot.component("channel_media")
        local = control.inspect_local_authority()
        assert component.bound is True
        assert component.identity == local.database_identity
        assert component.sequence_floor == local.mutation_sequence == 0
        assert component.state_digest == local.state_digest
        assert control.state.mode == "provisioned_not_active"
        assert control.state.provider_dispatch_ready is False
    finally:
        control.close()


def test_root_commit_response_loss_is_confirmed_without_duplicate_advance(
    tmp_path: Path,
) -> None:
    fault = OneShotFault("component_advance.after_commit")
    root, control, _path = active_control(
        tmp_path, deps=dependencies(fault=fault), name="cas-loss"
    )
    try:
        claim = control.store.claim(
            channel="feishu",
            operation="vision.describe",
            message_key=f"fsmsg-v1:{digest('cas-loss-message')}",
            principal_hash=digest("cas-loss-principal"),
            request_sha256=digest("cas-loss-request"),
            now=2.0,
        )
        assert claim.state == "claimed"
        assert fault.triggered is True
        local = control.inspect_local_authority()
        component = root.snapshot().component("channel_media")
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
        assert control.state.mode == "ready"
    finally:
        control.close()


def test_active_installer_verifier_accepts_exact_nonzero_proof_without_writes(
    tmp_path: Path,
) -> None:
    root, control, path = active_control(tmp_path, name="active-installer")
    try:
        claim = control.store.claim(
            channel="feishu",
            operation="vision.describe",
            message_key=f"fsmsg-v1:{digest('active-installer-message')}",
            principal_hash=digest("active-installer-principal"),
            request_sha256=digest("active-installer-request"),
            now=2.5,
        )
        assert claim.state == "claimed"
    finally:
        control.close()
    before = root.snapshot()
    assert before.component("channel_media").sequence_floor == 1

    verified = ChannelMediaInstallationControl.verify_bound_for_active_installer(
        root,
        path,
    )
    try:
        assert verified.state.mode == "provisioned_not_active"
        assert verified.state.reason_code == "active-installer-proof-verified"
        with pytest.raises(ChannelMediaInstallationControlUnavailable):
            _ = verified.store
        assert root.snapshot() == before
    finally:
        verified.close()


def test_active_installer_verifier_rejects_local_plus_one_without_recovery(
    tmp_path: Path,
) -> None:
    root, control, path = active_control(tmp_path, name="active-installer-gap")
    identity = root.snapshot().component("channel_media").identity
    control.close()

    raw = DurableChannelMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        claim = raw.claim(
            channel="weixin",
            operation="vision.describe",
            message_key=f"wxmsg-v1:{digest('active-installer-gap-message')}",
            principal_hash=digest("active-installer-gap-principal"),
            request_sha256=digest("active-installer-gap-request"),
            now=2.75,
        )
        assert claim.state == "claimed"
        local_before = raw.inspect_root_state()
    finally:
        raw.close()
    root_before = root.snapshot()
    assert local_before.mutation_sequence == 1
    assert root_before.component("channel_media").sequence_floor == 0

    with pytest.raises(ChannelMediaInstallationControlUnavailable):
        ChannelMediaInstallationControl.verify_bound_for_active_installer(root, path)

    assert root.snapshot() == root_before
    raw = DurableChannelMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        assert raw.inspect_root_state() == local_before
    finally:
        raw.close()


def test_component_addition_lock_allows_only_explicit_provision_to_create_and_bind(
    tmp_path: Path,
) -> None:
    deps = dependencies()
    root_path = tmp_path / "migrated-root.db"
    legacy = InstallationRoot.provision(root_path, dependencies=deps)
    snapshot = legacy.snapshot()
    for name in ("desktop", "gateway", "gateway_assets", "channel_media"):
        component = snapshot.component(name)
        snapshot = legacy.bind_component(
            name,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=component.identity,
            state_digest=digest(f"legacy:{name}"),
            expected_root_revision=snapshot.root_revision,
        ).snapshot
    assert snapshot.status == "active"
    downgrade_active_fixture_to_v4(root_path)

    migrated = InstallationRoot.migrate_v4_to_v5(root_path, dependencies=deps)
    locked = migrated.snapshot()
    assert locked.status == "maintenance_locked"
    assert locked.lock_kind == "component_addition"
    path = tmp_path / "migrated-channel-media.db"

    with pytest.raises(ChannelMediaInstallationControlUnavailable):
        ChannelMediaInstallationControl.open_bound(migrated, path)
    assert not path.exists()
    assert not Path(f"{path}.rollback-anchor").exists()

    control = ChannelMediaInstallationControl.provision(migrated, path)
    try:
        assert migrated.snapshot().status == "active"
        assert control.state.mode == "ready"
        assert control.state.provider_dispatch_ready is True
    finally:
        control.close()

    reopened = ChannelMediaInstallationControl.open_bound(migrated, path)
    try:
        assert reopened.state.mode == "ready"
    finally:
        reopened.close()


def test_local_root_plus_one_reconciles_to_permanent_manual_only(
    tmp_path: Path,
) -> None:
    root, control, path = active_control(tmp_path, name="local-plus-one")
    identity = root.snapshot().component("channel_media").identity
    control.close()

    local_only = DurableChannelMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        claim = local_only.claim(
            channel="weixin",
            operation="vision.describe",
            message_key=f"wxmsg-v1:{digest('local-plus-one-message')}",
            principal_hash=digest("local-plus-one-principal"),
            request_sha256=digest("local-plus-one-request"),
            now=3.0,
        )
        assert claim.state == "claimed"
        assert local_only.inspect_root_state().mutation_sequence == 1
    finally:
        local_only.close()

    recovered = ChannelMediaInstallationControl.open_bound(root, path)
    try:
        assert recovered.state.mode == "manual_only"
        assert recovered.state.provider_dispatch_ready is False
        local = recovered.inspect_local_authority()
        component = root.snapshot().component("channel_media")
        assert local.mutation_sequence == component.sequence_floor == 2
        assert local.state_digest == component.state_digest
        assert component.recovery_floor is None
        with pytest.raises(ChannelMediaInstallationControlUnavailable):
            recovered.assert_provider_dispatch_ready()
        with pytest.raises(DurableMediaRequestUnavailable):
            recovered.store.claim(
                channel="weixin",
                operation="vision.describe",
                message_key=f"wxmsg-v1:{digest('manual-only-message')}",
                principal_hash=digest("manual-only-principal"),
                request_sha256=digest("manual-only-request"),
                now=4.0,
            )
    finally:
        recovered.close()


def test_paired_database_and_anchor_rollback_is_fused_against_root_floor(
    tmp_path: Path,
) -> None:
    root, control, path = active_control(tmp_path, name="paired-rollback")
    control.close()
    anchor_path = Path(f"{path}.rollback-anchor")
    old_database = path.read_bytes()
    old_anchor = anchor_path.read_bytes()

    advanced = ChannelMediaInstallationControl.open_bound(root, path)
    try:
        claim = advanced.store.claim(
            channel="feishu",
            operation="vision.describe",
            message_key=f"fsmsg-v1:{digest('paired-rollback-message')}",
            principal_hash=digest("paired-rollback-principal"),
            request_sha256=digest("paired-rollback-request"),
            now=5.0,
        )
        assert claim.state == "claimed"
        assert root.snapshot().component("channel_media").sequence_floor == 1
    finally:
        advanced.close()

    path.write_bytes(old_database)
    anchor_path.write_bytes(old_anchor)
    rolled_back = ChannelMediaInstallationControl.open_bound(root, path)
    try:
        assert rolled_back.state.mode == "fused"
        assert rolled_back.state.reason_code == "authority-mismatch"
        with pytest.raises(ChannelMediaInstallationControlUnavailable):
            _ = rolled_back.store
        with pytest.raises(ChannelMediaInstallationControlUnavailable):
            rolled_back.assert_provider_dispatch_ready()
    finally:
        rolled_back.close()


def test_close_interruption_keeps_store_attached_and_retry_finishes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _root, control, _path = active_control(tmp_path, name="close-retry")
    raw_store = control._store
    assert raw_store is not None
    original_close = raw_store.close
    calls = 0

    def interrupted_close() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt("simulated close interruption")
        original_close()

    monkeypatch.setattr(raw_store, "close", interrupted_close)
    with pytest.raises(KeyboardInterrupt):
        control.close()
    assert control._store is raw_store
    with pytest.raises(ChannelMediaInstallationControlUnavailable):
        _ = control.store

    control.close()
    assert calls == 2
    assert control._store is None
    assert control.state.mode == "detached"


def test_bound_channel_authority_has_one_cross_process_writer_owner(
    tmp_path: Path,
) -> None:
    root, first, path = active_control(tmp_path, name="single-writer")
    with pytest.raises(ChannelMediaInstallationControlUnavailable):
        ChannelMediaInstallationControl.open_bound(root, path)

    first.close()
    second = ChannelMediaInstallationControl.open_bound(root, path)
    try:
        assert second.state.mode == "ready"
    finally:
        second.close()


def test_claim_advances_channel_component_and_dispatch_requires_fresh_exact_proof(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "root.db", dependencies=dependencies()
    )
    control = ChannelMediaInstallationControl.provision(
        root, tmp_path / "channel-media.db"
    )
    try:
        activate_other_components(root)
        assert control.reconcile_startup().mode == "ready"

        before = control.inspect_local_authority()
        claim = control.store.claim(
            channel="weixin",
            operation="vision.describe",
            message_key=f"wxmsg-v1:{digest('message')}",
            principal_hash=digest("principal"),
            request_sha256=digest("request"),
            now=1.0,
        )
        assert claim.state == "claimed"

        local = control.inspect_local_authority()
        component = root.snapshot().component("channel_media")
        assert local.mutation_sequence == before.mutation_sequence + 1
        assert component.sequence_floor == local.mutation_sequence
        assert component.state_digest == local.state_digest
        ready = control.assert_provider_dispatch_ready()
        assert ready.mode == "ready"
        assert ready.provider_dispatch_ready is True
    finally:
        control.close()
