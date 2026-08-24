from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import shutil

import pytest

from gateway import asset_installation_control as asset_control_module
from gateway.asset_installation_control import (
    AssetInstallationControl,
    AssetInstallationControlUnavailable,
)
from gateway.installation_root import (
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootUnavailable,
)
from gateway.paid_media_asset_store import (
    PaidMediaAssetRootCommitPending,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
    PaidMediaAssetStoreError,
)


OWNER_SID = "S-1-5-21-1000-2000-3000-4000"
PRINCIPAL = sha256(b"asset-controller-principal").hexdigest()
TURN = sha256(b"asset-controller-turn").hexdigest()


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


class _IdentitySource:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, length: int) -> bytes:
        assert length == 32
        self.value += 1
        return self.value.to_bytes(32, "big")


class _RootProxy:
    def __init__(self, root: InstallationRoot) -> None:
        self.root = root
        self.advance_calls = 0

    def snapshot(self):  # noqa: ANN201
        return self.root.snapshot()

    def bind_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        return self.root.bind_component(*args, **kwargs)

    def advance_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        self.advance_calls += 1
        return self.root.advance_component(*args, **kwargs)

    def verify_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        return self.root.verify_component(*args, **kwargs)

    def acknowledge_component_recovery(
        self, *args, **kwargs  # noqa: ANN002, ANN003
    ):  # noqa: ANN201
        return self.root.acknowledge_component_recovery(*args, **kwargs)


class _ComponentAdditionRoot(_RootProxy):
    def __init__(self, root: InstallationRoot, snapshot) -> None:
        super().__init__(root)
        self.pending_snapshot = snapshot
        self.mutation_calls = 0

    def snapshot(self):  # noqa: ANN201
        return self.pending_snapshot

    def _reject_mutation(self, *_args, **_kwargs):  # noqa: ANN201
        self.mutation_calls += 1
        raise AssertionError("component-addition verification must be assertion-only")

    bind_component = _reject_mutation
    verify_component = _reject_mutation
    acknowledge_component_recovery = _reject_mutation
    advance_component = _reject_mutation


class _BindResponseLossRoot(_RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.lost = False
        self.bind_calls = 0

    def bind_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        self.bind_calls += 1
        result = self.root.bind_component(*args, **kwargs)
        if args and args[0] == "gateway_assets" and not self.lost:
            self.lost = True
            raise InstallationRootUnavailable("simulated bind response loss")
        return result


class _BindRevisionRaceRoot(_RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.asset_bind_calls = 0

    def bind_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        if args and args[0] == "gateway_assets":
            self.asset_bind_calls += 1
            if self.asset_bind_calls == 1:
                current = self.root.snapshot()
                gateway = current.component("gateway")
                self.root.bind_component(
                    "gateway",
                    installation_id=current.installation_id,
                    epoch=current.epoch,
                    identity=gateway.identity,
                    sequence_floor=0,
                    state_digest=_digest("asset-controller:bind-race:gateway"),
                    expected_root_revision=current.root_revision,
                )
        return self.root.bind_component(*args, **kwargs)


class _AdvanceResponseLossRoot(_RootProxy):
    def advance_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        self.advance_calls += 1
        result = self.root.advance_component(*args, **kwargs)
        raise InstallationRootUnavailable("simulated advance response loss")


class _NeverAdvanceRoot(_RootProxy):
    def advance_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        self.advance_calls += 1
        raise InstallationRootUnavailable("simulated Root outage")


class _RecoveryResponseLossRoot(_RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.verify_calls = 0
        self.ack_calls = 0

    def verify_component(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        self.verify_calls += 1
        self.root.verify_component(*args, **kwargs)
        raise InstallationRootUnavailable("simulated verify response loss")

    def acknowledge_component_recovery(
        self, *args, **kwargs  # noqa: ANN002, ANN003
    ):  # noqa: ANN201
        self.ack_calls += 1
        self.root.acknowledge_component_recovery(*args, **kwargs)
        raise InstallationRootUnavailable("simulated acknowledgement response loss")


def _root_dependencies() -> InstallationRootDependencies:
    return InstallationRootDependencies(
        owner_sid=lambda: OWNER_SID,
        random_bytes=_IdentitySource(),
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
    )


def _asset_dependencies() -> PaidMediaAssetStoreDependencies:
    return PaidMediaAssetStoreDependencies(
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        disk_free=lambda _path: 32 * 1024 * 1024 * 1024,
    )


def _bind_public_components(root: InstallationRoot) -> None:
    current = root.snapshot()
    for name in ("gateway", "desktop", "channel_media"):
        component = current.component(name)
        current = root.bind_component(
            name,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=component.identity,
            sequence_floor=0,
            state_digest=_digest(f"asset-controller:{name}:0"),
            expected_root_revision=current.root_revision,
        ).snapshot


def _component_addition_snapshot(active):
    channel = replace(
        active.component("channel_media"),
        bound=False,
        sequence_floor=0,
        state_digest=None,
        recovery_floor=None,
        recovery_state_digest=None,
    )
    return replace(
        active,
        root_revision=active.root_revision + 1,
        status="maintenance_locked",
        lock_kind="component_addition",
        lock_reason_digest=_digest("v4-v5-source-snapshot"),
        components=tuple(
            channel if item.component == "channel_media" else item
            for item in active.components
        ),
    )


def _replace_snapshot_component(snapshot, name: str, **changes):
    changed = replace(snapshot.component(name), **changes)
    return replace(
        snapshot,
        components=tuple(
            changed if item.component == name else item
            for item in snapshot.components
        ),
    )


def test_normal_open_never_creates_or_binds_asset_authority(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    before = root.snapshot()

    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.open_bound(root, asset_path)

    after = root.snapshot()
    assert after == before
    assert after.component("gateway_assets").bound is False
    assert not asset_path.exists()


def test_provision_binds_only_gateway_assets_to_exact_store_identity(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    initial = root.snapshot()
    gateway_before = initial.component("gateway")
    desktop_before = initial.component("desktop")
    assets_before = initial.component("gateway_assets")

    control = AssetInstallationControl.provision(
        root,
        tmp_path / "paid-media-assets",
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = control.inspect_local_authority()
        after = root.snapshot()
        assets_after = after.component("gateway_assets")
        assert after.status == "provisioning"
        assert assets_after.bound is True
        assert assets_after.identity == assets_before.identity
        assert assets_after.sequence_floor == local.mutation_sequence == 0
        assert assets_after.state_digest == local.state_digest
        assert local.database_identity == assets_before.identity
        assert after.component("gateway") == gateway_before
        assert after.component("desktop") == desktop_before
        assert control.state.mode == "provisioned_not_active"
        with pytest.raises(AssetInstallationControlUnavailable):
            _ = control.store
    finally:
        control.close()


def test_authoritative_asset_mutation_advances_only_gateway_assets_root(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    control = AssetInstallationControl.provision(
        root,
        tmp_path / "paid-media-assets",
        store_dependencies=_asset_dependencies(),
    )
    try:
        before = root.snapshot()
        assert before.status == "active"
        assert control.state.mode == "ready"
        gateway_before = before.component("gateway")
        desktop_before = before.component("desktop")
        assets_before = before.component("gateway_assets")

        control.store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=before.epoch,
            operation="images.create",
        )

        local = control.inspect_local_authority()
        after = root.snapshot()
        assets_after = after.component("gateway_assets")
        assert local.mutation_sequence == assets_before.sequence_floor + 1
        assert assets_after.sequence_floor == local.mutation_sequence
        assert assets_after.state_digest == local.state_digest
        assert after.component("gateway") == gateway_before
        assert after.component("desktop") == desktop_before
        assert control.state.mode == "ready"
    finally:
        control.close()


def test_second_controller_cannot_acquire_asset_writer_ownership(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    asset_path = tmp_path / "paid-media-assets"
    first = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        with pytest.raises(AssetInstallationControlUnavailable):
            AssetInstallationControl.open_bound(
                root,
                asset_path,
                store_dependencies=_asset_dependencies(),
            )
    finally:
        first.close()

    reopened = AssetInstallationControl.open_bound(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        assert reopened.state.mode == "ready"
    finally:
        reopened.close()


def test_asset_bind_response_loss_is_confirmed_without_duplicate_bind(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    proxy = _BindResponseLossRoot(root)
    asset_path = tmp_path / "paid-media-assets"

    control = AssetInstallationControl.provision(
        proxy,  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        committed = root.snapshot()
        assert committed.component("gateway_assets").bound is True
        assert asset_path.is_dir()
        assert proxy.bind_calls == 1
        assert control.state.mode == "provisioned_not_active"
        assert control.inspect_local_authority().database_identity == committed.component(
            "gateway_assets"
        ).identity
    finally:
        control.close()


def test_asset_bind_retries_after_unrelated_root_revision_race(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    proxy = _BindRevisionRaceRoot(root)
    asset_path = tmp_path / "paid-media-assets"

    control = AssetInstallationControl.provision(
        proxy,  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        committed = root.snapshot()
        local = control.inspect_local_authority()
        assert proxy.asset_bind_calls == 2
        assert committed.component("gateway").bound is True
        assert committed.component("desktop").bound is False
        assert committed.component("gateway_assets").sequence_floor == 0
        assert committed.component("gateway_assets").state_digest == local.state_digest
        assert control.state.mode == "provisioned_not_active"
    finally:
        control.close()


def test_root_hook_confirms_response_loss_without_duplicate_advance(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    proxy = _AdvanceResponseLossRoot(root)
    control = AssetInstallationControl.provision(
        proxy,  # type: ignore[arg-type]
        tmp_path / "paid-media-assets",
        store_dependencies=_asset_dependencies(),
    )
    try:
        control.store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=root.snapshot().epoch,
            operation="images.create",
        )
        local = control.inspect_local_authority()
        component = root.snapshot().component("gateway_assets")
        assert proxy.advance_calls == 1
        assert component.sequence_floor == local.mutation_sequence
        assert component.state_digest == local.state_digest
        assert control.state.mode == "ready"
    finally:
        control.close()


def test_unconfirmed_root_commit_fuses_and_blocks_following_writes(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    proxy = _NeverAdvanceRoot(root)
    control = AssetInstallationControl.provision(
        proxy,  # type: ignore[arg-type]
        tmp_path / "paid-media-assets",
        store_dependencies=_asset_dependencies(),
    )
    try:
        root_before = root.snapshot().component("gateway_assets")
        with pytest.raises(PaidMediaAssetRootCommitPending):
            control.store.reserve(
                turn_id=TURN,
                principal_hash=PRINCIPAL,
                epoch=root.snapshot().epoch,
                operation="images.create",
            )
        local_after = control.inspect_local_authority()
        assert proxy.advance_calls == 4
        assert local_after.mutation_sequence == root_before.sequence_floor + 1
        assert root.snapshot().component("gateway_assets") == root_before
        assert control.state.mode == "fused"

        with pytest.raises(AssetInstallationControlUnavailable):
            _ = control.store
        assert control.inspect_local_authority() == local_after
    finally:
        control.close()


def test_restart_closes_root_plus_one_gap_into_persistent_manual_only(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    asset_path = tmp_path / "paid-media-assets"
    failed = AssetInstallationControl.provision(
        _NeverAdvanceRoot(root),  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    root_before = root.snapshot().component("gateway_assets")
    with pytest.raises(PaidMediaAssetRootCommitPending):
        failed.store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=root.snapshot().epoch,
            operation="images.create",
        )
    pending = failed.inspect_local_authority()
    assert pending.mutation_sequence == root_before.sequence_floor + 1
    failed.close()

    recovered = AssetInstallationControl.open_bound(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = recovered.inspect_local_authority()
        component = root.snapshot().component("gateway_assets")
        assert recovered.state.mode == "manual_only"
        assert local.authority_mode == "manual_only"
        assert local.mutation_sequence == pending.mutation_sequence + 1
        assert local.recovery_floor == pending.mutation_sequence
        assert local.recovery_state_digest == pending.state_digest
        assert component.sequence_floor == local.mutation_sequence
        assert component.state_digest == local.state_digest
        assert component.recovery_floor is None
        assert component.recovery_state_digest is None
        assert recovered.store.inspect_root_state() == local
        with pytest.raises(PaidMediaAssetStoreError, match="manual recovery"):
            recovered.store.reserve(
                turn_id=_digest("manual-only-next-turn"),
                principal_hash=PRINCIPAL,
                epoch=root.snapshot().epoch,
                operation="images.create",
            )
    finally:
        recovered.close()

    reopened = AssetInstallationControl.open_bound(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        assert reopened.state.mode == "manual_only"
        assert reopened.inspect_local_authority().mutation_sequence == (
            pending.mutation_sequence + 1
        )
    finally:
        reopened.close()


def test_recovery_confirms_lost_verify_and_ack_responses_by_exact_reread(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    asset_path = tmp_path / "paid-media-assets"
    failed = AssetInstallationControl.provision(
        _NeverAdvanceRoot(root),  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    with pytest.raises(PaidMediaAssetRootCommitPending):
        failed.store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=root.snapshot().epoch,
            operation="images.create",
        )
    failed.close()

    proxy = _RecoveryResponseLossRoot(root)
    recovered = AssetInstallationControl.open_bound(
        proxy,  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = recovered.inspect_local_authority()
        component = root.snapshot().component("gateway_assets")
        assert proxy.verify_calls == 1
        assert proxy.ack_calls == 1
        assert recovered.state.mode == "manual_only"
        assert local.authority_mode == "manual_only"
        assert component.sequence_floor == local.mutation_sequence
        assert component.state_digest == local.state_digest
        assert component.recovery_floor is None
    finally:
        recovered.close()


@pytest.mark.parametrize("crash_phase", ["root_fenced", "local_manual"])
def test_recovery_resumes_each_persisted_verify_to_ack_crash_window(
    tmp_path: Path,
    crash_phase: str,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    asset_path = tmp_path / "paid-media-assets"
    failed = AssetInstallationControl.provision(
        _NeverAdvanceRoot(root),  # type: ignore[arg-type]
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    root_before = root.snapshot().component("gateway_assets")
    with pytest.raises(PaidMediaAssetRootCommitPending):
        failed.store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=root.snapshot().epoch,
            operation="images.create",
        )
    pending = failed.inspect_local_authority()
    failed.close()

    root.verify_component(
        "gateway_assets",
        installation_id=pending.installation_id,
        epoch=pending.epoch,
        identity=pending.database_identity,
        sequence_floor=pending.mutation_sequence,
        state_digest=pending.state_digest,
        previous_state_digest=root_before.state_digest,
    )
    fenced = root.snapshot().component("gateway_assets")
    assert fenced.recovery_floor == pending.mutation_sequence
    if crash_phase == "local_manual":
        raw = PaidMediaAssetStore.open_bound(
            asset_path,
            installation_id=pending.installation_id,
            epoch=pending.epoch,
            expected_database_identity=pending.database_identity,
            dependencies=_asset_dependencies(),
        )
        try:
            raw.enter_authority_manual_only(
                installation_id=pending.installation_id,
                epoch=pending.epoch,
                recovery_floor=pending.mutation_sequence,
                recovery_state_digest=pending.state_digest,
            )
        finally:
            raw.close()

    recovered = AssetInstallationControl.open_bound(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = recovered.inspect_local_authority()
        component = root.snapshot().component("gateway_assets")
        assert recovered.state.mode == "manual_only"
        assert local.authority_mode == "manual_only"
        assert local.mutation_sequence == pending.mutation_sequence + 1
        assert component.sequence_floor == local.mutation_sequence
        assert component.state_digest == local.state_digest
        assert component.recovery_floor is None
        assert component.recovery_state_digest is None
    finally:
        recovered.close()


def test_bound_component_with_missing_store_is_never_recreated(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    _bind_public_components(root)
    asset_path = tmp_path / "paid-media-assets"
    control = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    control.close()
    before = root.snapshot()
    shutil.rmtree(asset_path)

    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.provision(
            root,
            asset_path,
            store_dependencies=_asset_dependencies(),
        )

    assert root.snapshot() == before
    assert not asset_path.exists()


def test_existing_store_with_wrong_preallocated_identity_is_not_adopted(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    snapshot = root.snapshot()
    asset_path = tmp_path / "paid-media-assets"
    foreign = PaidMediaAssetStore.provision(
        asset_path,
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        expected_database_identity="e" * 64,
        dependencies=_asset_dependencies(),
    )
    foreign.close()
    database = asset_path / "asset-store.db"
    anchor = Path(f"{database}.rollback-anchor")
    before_database = database.read_bytes()
    before_anchor = anchor.read_bytes()

    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.provision(
            root,
            asset_path,
            store_dependencies=_asset_dependencies(),
        )

    assert root.snapshot() == snapshot
    assert database.read_bytes() == before_database
    assert anchor.read_bytes() == before_anchor


def test_component_addition_verifier_proves_existing_assets_without_writes(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    original = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert original.reconcile_startup().mode == "ready"
    original.store.reserve(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
        epoch=root.snapshot().epoch,
        operation="images.create",
    )
    original.close()
    active = root.snapshot()
    pending = _component_addition_snapshot(active)
    authority = _ComponentAdditionRoot(root, pending)
    ownership_path = asset_control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        pending.installation_id,
        pending.component("gateway_assets").identity,
    )
    protected_paths = tuple(
        sorted(item for item in asset_path.rglob("*") if item.is_file())
    ) + (ownership_path,)
    before_bytes = {item: item.read_bytes() for item in protected_paths}

    verified = AssetInstallationControl.verify_bound_for_component_addition(
        authority,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = verified.inspect_local_authority()
        component = pending.component("gateway_assets")
        assert verified.state.mode == "provisioned_not_active"
        assert verified.state.reason_code == "component-addition-proof-verified"
        assert verified.state.mutation_ready is False
        assert local.installation_id == pending.installation_id
        assert local.epoch == pending.epoch
        assert local.database_identity == component.identity
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
        assert local.authority_mode == "normal"
        assert local.recovery_floor is None
        assert local.recovery_state_digest is None
        with pytest.raises(AssetInstallationControlUnavailable):
            _ = verified.store
        with pytest.raises(PaidMediaAssetStoreError):
            verified.assert_local_mutation_ready()
        assert authority.mutation_calls == 0
        assert root.snapshot() == active
    finally:
        verified.close()

    assert {item: item.read_bytes() for item in protected_paths} == before_bytes


def test_component_addition_asset_verifier_rejects_lock_and_proof_drift(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    original = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert original.reconcile_startup().mode == "ready"
    original.close()
    pending = _component_addition_snapshot(root.snapshot())
    component = pending.component("gateway_assets")
    candidates = (
        replace(
            pending,
            status="active",
            lock_kind="none",
            lock_reason_digest=None,
        ),
        replace(pending, lock_kind="integrity"),
        _replace_snapshot_component(pending, "gateway_assets", bound=False),
        _replace_snapshot_component(
            pending,
            "gateway_assets",
            epoch=component.epoch + 1,
        ),
        _replace_snapshot_component(
            pending,
            "gateway_assets",
            sequence_floor=component.sequence_floor + 1,
        ),
        _replace_snapshot_component(
            pending,
            "gateway_assets",
            state_digest=_digest("component-addition-asset-root-digest-drift"),
        ),
        _replace_snapshot_component(
            pending,
            "gateway_assets",
            recovery_floor=component.sequence_floor,
            recovery_state_digest=component.state_digest,
        ),
    )
    protected_paths = tuple(
        sorted(item for item in asset_path.rglob("*") if item.is_file())
    )
    before_bytes = {item: item.read_bytes() for item in protected_paths}

    for candidate in candidates:
        authority = _ComponentAdditionRoot(root, candidate)
        with pytest.raises(AssetInstallationControlUnavailable):
            AssetInstallationControl.verify_bound_for_component_addition(
                authority,
                asset_path,
                store_dependencies=_asset_dependencies(),
            )
        assert authority.mutation_calls == 0

    assert {item: item.read_bytes() for item in protected_paths} == before_bytes


def test_component_addition_asset_verifier_never_creates_or_repairs(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    original = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert original.reconcile_startup().mode == "ready"
    original.close()
    pending = _component_addition_snapshot(root.snapshot())
    authority = _ComponentAdditionRoot(root, pending)
    missing = tmp_path / "missing-assets"

    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.verify_bound_for_component_addition(
            authority,
            missing,
            store_dependencies=_asset_dependencies(),
        )
    assert not missing.exists()

    ownership = asset_control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        pending.installation_id,
        pending.component("gateway_assets").identity,
    )
    moved_ownership = ownership.with_name(f"{ownership.name}.held-by-test")
    ownership.rename(moved_ownership)
    try:
        with pytest.raises(AssetInstallationControlUnavailable):
            AssetInstallationControl.verify_bound_for_component_addition(
                authority,
                asset_path,
                store_dependencies=_asset_dependencies(),
            )
        assert not ownership.exists()
    finally:
        moved_ownership.rename(ownership)

    database = asset_path / "asset-store.db"
    anchor = Path(f"{database}.rollback-anchor")
    moved_anchor = anchor.with_name(f"{anchor.name}.held-by-test")
    anchor.rename(moved_anchor)
    try:
        with pytest.raises(AssetInstallationControlUnavailable):
            AssetInstallationControl.verify_bound_for_component_addition(
                authority,
                asset_path,
                store_dependencies=_asset_dependencies(),
            )
        assert not anchor.exists()
    finally:
        moved_anchor.rename(anchor)


def test_component_addition_does_not_relax_asset_runtime_or_provisioning(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    original = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert original.reconcile_startup().mode == "ready"
    original.close()
    authority = _ComponentAdditionRoot(
        root,
        _component_addition_snapshot(root.snapshot()),
    )

    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.provision(
            authority,
            asset_path,
            store_dependencies=_asset_dependencies(),
        )
    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.open_bound(
            authority,
            asset_path,
            store_dependencies=_asset_dependencies(),
        )
    assert authority.mutation_calls == 0


def test_active_installer_verifier_proves_nonzero_assets_without_writes(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    original = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert original.reconcile_startup().mode == "ready"
    original.store.reserve(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
        epoch=root.snapshot().epoch,
        operation="images.create",
    )
    original.close()
    active = root.snapshot()
    authority = _ComponentAdditionRoot(root, active)
    ownership_path = asset_control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        active.installation_id,
        active.component("gateway_assets").identity,
    )
    protected_paths = tuple(
        sorted(item for item in asset_path.rglob("*") if item.is_file())
    ) + (ownership_path,)
    before_bytes = {item: item.read_bytes() for item in protected_paths}

    verified = AssetInstallationControl.verify_bound_for_active_installer(
        authority,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    try:
        local = verified.inspect_local_authority()
        component = active.component("gateway_assets")
        assert verified.state.mode == "provisioned_not_active"
        assert verified.state.reason_code == "active-installer-proof-verified"
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
        with pytest.raises(AssetInstallationControlUnavailable):
            _ = verified.store
        with pytest.raises(PaidMediaAssetStoreError):
            verified.assert_local_mutation_ready()
        assert authority.mutation_calls == 0
    finally:
        verified.close()

    assert {item: item.read_bytes() for item in protected_paths} == before_bytes


def test_active_asset_installer_verifier_rejects_recovery_and_missing_state(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "installation-root.db",
        dependencies=_root_dependencies(),
    )
    asset_path = tmp_path / "paid-media-assets"
    control = AssetInstallationControl.provision(
        root,
        asset_path,
        store_dependencies=_asset_dependencies(),
    )
    _bind_public_components(root)
    assert control.reconcile_startup().mode == "ready"
    before = root.snapshot()
    control.store.reserve(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
        epoch=before.epoch,
        operation="images.create",
    )
    control.close()
    exact = root.snapshot()
    previous = before.component("gateway_assets")
    current = exact.component("gateway_assets")
    candidates = (
        _replace_snapshot_component(
            exact,
            "gateway_assets",
            sequence_floor=previous.sequence_floor,
            state_digest=previous.state_digest,
        ),
        _replace_snapshot_component(
            exact,
            "gateway_assets",
            recovery_floor=current.sequence_floor,
            recovery_state_digest=current.state_digest,
        ),
        _component_addition_snapshot(exact),
    )

    for candidate in candidates:
        authority = _ComponentAdditionRoot(root, candidate)
        with pytest.raises(AssetInstallationControlUnavailable):
            AssetInstallationControl.verify_bound_for_active_installer(
                authority,
                asset_path,
                store_dependencies=_asset_dependencies(),
            )
        assert authority.mutation_calls == 0

    missing = tmp_path / "active-installer-missing-assets"
    authority = _ComponentAdditionRoot(root, exact)
    with pytest.raises(AssetInstallationControlUnavailable):
        AssetInstallationControl.verify_bound_for_active_installer(
            authority,
            missing,
            store_dependencies=_asset_dependencies(),
        )
    assert not missing.exists()
    assert authority.mutation_calls == 0
