from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import inspect
import multiprocessing
import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from gateway import gateway_installation_control as control_module
from gateway.durable_media_requests import (
    DurableMediaRequestUnavailable,
    DurableMediaRequestStore,
    DurableMediaRootCommitPending,
)
from gateway.gateway_installation_control import (
    GatewayInstallationControl,
    GatewayInstallationControlUnavailable,
    stable_paid_principal,
)
from gateway.installation_root import (
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootUnavailable,
)
from gateway.secure_store import (
    SecureStorageError,
    assert_restricted_windows_acl,
    trusted_windows_system_executable,
)


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


def activate_desktop(root: InstallationRoot, label: str = "desktop:0"):
    snapshot = root.snapshot()
    desktop = snapshot.component("desktop")
    result = root.bind_component(
        "desktop",
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        identity=desktop.identity,
        sequence_floor=0,
        state_digest=digest(label),
        expected_root_revision=snapshot.root_revision,
    )
    after_desktop = result.snapshot
    assets = after_desktop.component("gateway_assets")
    result = root.bind_component(
        "gateway_assets",
        installation_id=after_desktop.installation_id,
        epoch=after_desktop.epoch,
        identity=assets.identity,
        sequence_floor=0,
        state_digest=digest(f"{label}:gateway-assets"),
        expected_root_revision=after_desktop.root_revision,
    )
    after_assets = result.snapshot
    channel = after_assets.component("channel_media")
    result = root.bind_component(
        "channel_media",
        installation_id=after_assets.installation_id,
        epoch=after_assets.epoch,
        identity=channel.identity,
        sequence_floor=0,
        state_digest=digest(f"{label}:channel-media"),
        expected_root_revision=after_assets.root_revision,
    )
    return result.snapshot, digest(label)


def active_control(tmp_path: Path, *, deps=None, name: str = "authority"):
    deps = deps or dependencies()
    root = InstallationRoot.provision(
        tmp_path / f"{name}-root.db", dependencies=deps
    )
    path = tmp_path / f"{name}-media.db"
    control = GatewayInstallationControl.provision(root, path)
    assert control.state.mode == "provisioned_not_active"
    active, desktop_digest = activate_desktop(root, f"{name}:desktop:0")
    assert active.status == "active"
    assert control.reconcile_startup().mode == "ready"
    return root, control, path, desktop_digest


class RootProxy:
    def __init__(self, root: InstallationRoot) -> None:
        self.root = root
        self.snapshot_calls = 0

    def snapshot(self):
        self.snapshot_calls += 1
        return self.root.snapshot()

    def bind_component(self, *args, **kwargs):
        return self.root.bind_component(*args, **kwargs)

    def verify_component(self, *args, **kwargs):
        return self.root.verify_component(*args, **kwargs)

    def acknowledge_component_recovery(self, *args, **kwargs):
        return self.root.acknowledge_component_recovery(*args, **kwargs)

    def advance_component(self, *args, **kwargs):
        return self.root.advance_component(*args, **kwargs)


class ComponentAdditionRoot(RootProxy):
    def __init__(self, root: InstallationRoot, snapshot) -> None:
        super().__init__(root)
        self.pending_snapshot = snapshot
        self.mutation_calls = 0

    def snapshot(self):
        self.snapshot_calls += 1
        return self.pending_snapshot

    def _reject_mutation(self, *_args, **_kwargs):
        self.mutation_calls += 1
        raise AssertionError("component-addition verification must be assertion-only")

    bind_component = _reject_mutation
    verify_component = _reject_mutation
    acknowledge_component_recovery = _reject_mutation
    advance_component = _reject_mutation


def component_addition_snapshot(active):
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
        lock_reason_digest=digest("v4-v5-source-snapshot"),
        components=tuple(
            channel if item.component == "channel_media" else item
            for item in active.components
        ),
    )


def replace_snapshot_component(snapshot, name: str, **changes):
    changed = replace(snapshot.component(name), **changes)
    return replace(
        snapshot,
        components=tuple(
            changed if item.component == name else item
            for item in snapshot.components
        ),
    )


class SwitchableRoot(RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.unavailable = False

    def snapshot(self):
        self.snapshot_calls += 1
        if self.unavailable:
            raise InstallationRootUnavailable("simulated unavailable root")
        return self.root.snapshot()


class NeverCommitRoot(RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.advance_calls = 0

    def advance_component(self, *args, **kwargs):
        self.advance_calls += 1
        raise InstallationRootUnavailable("simulated CAS response loss")


class RevisionRaceRoot(RootProxy):
    def __init__(self, root: InstallationRoot, desktop_digest: str) -> None:
        super().__init__(root)
        self.desktop_digest = desktop_digest
        self.advance_calls = 0
        self.raced = False

    def advance_component(self, component, **kwargs):
        self.advance_calls += 1
        if component == "gateway" and not self.raced:
            self.raced = True
            current = self.root.snapshot()
            desktop = current.component("desktop")
            self.root.advance_component(
                "desktop",
                installation_id=current.installation_id,
                epoch=current.epoch,
                identity=desktop.identity,
                expected_floor=0,
                expected_state_digest=self.desktop_digest,
                next_floor=1,
                next_state_digest=digest("desktop:revision-race:1"),
                expected_root_revision=current.root_revision,
            )
        return self.root.advance_component(component, **kwargs)


class InterruptingRoot(RootProxy):
    def advance_component(self, *args, **kwargs):
        raise KeyboardInterrupt("simulated non-Exception root failure")


class OutboundRaceRoot(RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.target_thread: int | None = None
        self.sample_waiting = threading.Event()
        self.release_sample = threading.Event()
        self._blocked = False

    def snapshot(self):
        self.snapshot_calls += 1
        if (
            not self._blocked
            and self.target_thread == threading.get_ident()
        ):
            self._blocked = True
            self.sample_waiting.set()
            assert self.release_sample.wait(5)
        return self.root.snapshot()


class RepeatedOutboundRaceRoot(RootProxy):
    """Advance exact local/root authority during every targeted proof sample."""

    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.target_thread: int | None = None
        self.advance = None
        self.enabled = True
        self.races = 0

    def snapshot(self):
        self.snapshot_calls += 1
        if (
            self.enabled
            and self.advance is not None
            and self.target_thread == threading.get_ident()
            and self.races < control_module._MAX_OUTBOUND_INSPECTIONS
        ):
            self.races += 1
            failure: list[BaseException] = []

            def mutate() -> None:
                try:
                    self.advance(self.races)
                except BaseException as exc:  # pragma: no cover - rethrown below
                    failure.append(exc)

            worker = threading.Thread(target=mutate)
            worker.start()
            worker.join(10)
            assert not worker.is_alive()
            if failure:
                raise failure[0]
        return self.root.snapshot()


class BlockingCommitRoot(RootProxy):
    def __init__(self, root: InstallationRoot) -> None:
        super().__init__(root)
        self.target_thread: int | None = None
        self.commit_waiting = threading.Event()
        self.release_commit = threading.Event()
        self._blocked = False

    def snapshot(self):
        self.snapshot_calls += 1
        if not self._blocked and self.target_thread == threading.get_ident():
            self._blocked = True
            self.commit_waiting.set()
            assert self.release_commit.wait(10)
        return self.root.snapshot()


def _crash_while_holding_ownership(lock_path: str, acquired) -> None:
    ownership = control_module._GatewayLedgerOwnership.acquire(  # type: ignore[attr-defined]
        Path(lock_path), create_if_missing=False
    )
    acquired.set()
    # Deliberately bypass close/finally: the kernel handle must still be
    # released when this process exits.
    os._exit(91)


def test_normal_open_never_creates_and_explicit_provision_waits_for_installation_activation(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "root.db", dependencies=dependencies()
    )
    path = tmp_path / "gateway.db"

    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.open_bound(root, path)
    assert not path.exists()
    assert not Path(f"{path}.rollback-anchor").exists()

    control = GatewayInstallationControl.provision(root, path)
    try:
        assert control.state.mode == "provisioned_not_active"
        assert control.state.outbound_ready is False
        assert control.state.reason_code == "awaiting-installation-activation"
        before = control.inspect_local_authority()
        with pytest.raises(GatewayInstallationControlUnavailable):
            _ = control.store
        with pytest.raises(GatewayInstallationControlUnavailable):
            control.assert_outbound_ready()
        assert control.state.mode == "provisioned_not_active"
        raw_store = control._store  # Deliberate integration-boundary assertion.
        assert raw_store is not None
        with pytest.raises(DurableMediaRequestUnavailable):
            raw_store.claim(
                principal_hash="a" * 64,
                operation="images.create",
                idempotency_key="desktop-waiting-gate-4111-8111-111111111111",
                request_sha256=digest("waiting-gate"),
                now=0.5,
            )
        assert control.inspect_local_authority() == before
        active, _desktop_digest = activate_desktop(root)
        assert active.status == "active"
        ready = control.reconcile_startup()
        assert ready.mode == "ready"
        assert ready.outbound_ready is True
        assert ready.paid_principal == stable_paid_principal(
            active.principal_digest
        )
    finally:
        control.close()

    reopened = GatewayInstallationControl.open_bound(root, path)
    try:
        assert reopened.state.mode == "ready"
        assert reopened.store.inspect_root_state().mutation_sequence == 0
    finally:
        reopened.close()


def test_provision_is_idempotent_but_rejects_a_partial_db_anchor_pair(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "idempotent-root.db", dependencies=dependencies()
    )
    path = tmp_path / "idempotent-media.db"
    first = GatewayInstallationControl.provision(root, path)
    first.close()
    retried = GatewayInstallationControl.provision(root, path)
    try:
        assert retried.state.mode == "provisioned_not_active"
    finally:
        retried.close()

    partial_root = InstallationRoot.provision(
        tmp_path / "partial-root.db", dependencies=dependencies()
    )
    partial = tmp_path / "partial-media.db"
    partial.write_bytes(b"operator-owned")
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(partial_root, partial)
    assert partial.read_bytes() == b"operator-owned"
    assert not Path(f"{partial}.rollback-anchor").exists()


@pytest.mark.parametrize("receipt_length", [0, 1, 9, 31])
def test_pristine_provision_repairs_only_a_short_ownership_receipt_prefix(
    tmp_path: Path, receipt_length: int
) -> None:
    root = InstallationRoot.provision(
        tmp_path / f"receipt-{receipt_length}-root.db",
        dependencies=dependencies(),
    )
    snapshot = root.snapshot()
    component = snapshot.component("gateway")
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, snapshot.installation_id, component.identity
    )
    partial = control_module._OWNERSHIP_MAGIC[:receipt_length]  # type: ignore[attr-defined]
    lock_path.write_bytes(partial)
    path = tmp_path / f"receipt-{receipt_length}-media.db"

    control = GatewayInstallationControl.provision(root, path)
    try:
        assert control.state.mode == "provisioned_not_active"
    finally:
        control.close()
    assert lock_path.read_bytes() == control_module._OWNERSHIP_MAGIC  # type: ignore[attr-defined]
    if os.name == "nt":
        assert_restricted_windows_acl(lock_path)


@pytest.mark.parametrize("receipt", [b"BAD", b"NACHUAN_GATEWAY_LEDGER_OWNER_V2\n"])
def test_pristine_provision_never_repairs_nonprefix_ownership_corruption(
    tmp_path: Path, receipt: bytes
) -> None:
    root = InstallationRoot.provision(
        tmp_path / f"corrupt-{len(receipt)}-root.db", dependencies=dependencies()
    )
    snapshot = root.snapshot()
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, snapshot.installation_id, snapshot.component("gateway").identity
    )
    lock_path.write_bytes(receipt)
    path = tmp_path / f"corrupt-{len(receipt)}-media.db"

    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(root, path)

    assert lock_path.read_bytes() == receipt
    assert not path.exists()
    assert not Path(f"{path}.rollback-anchor").exists()


def test_pristine_provision_recovers_after_receipt_write_baseexception(
    tmp_path: Path, monkeypatch
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "receipt-interrupt-root.db", dependencies=dependencies()
    )
    snapshot = root.snapshot()
    component = snapshot.component("gateway")
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, snapshot.installation_id, component.identity
    )
    path = tmp_path / "receipt-interrupt-media.db"
    ownership_type = control_module._GatewayLedgerOwnership  # type: ignore[attr-defined]
    original_write = ownership_type._write_receipt

    def interrupted_write(descriptor: int) -> None:
        os.write(descriptor, control_module._OWNERSHIP_MAGIC[:11])  # type: ignore[attr-defined]
        os.fsync(descriptor)
        raise KeyboardInterrupt("simulated crash after partial receipt write")

    monkeypatch.setattr(
        ownership_type, "_write_receipt", staticmethod(interrupted_write)
    )
    with pytest.raises(KeyboardInterrupt):
        GatewayInstallationControl.provision(root, path)
    assert lock_path.read_bytes() == control_module._OWNERSHIP_MAGIC[:11]  # type: ignore[attr-defined]
    assert not path.exists()
    assert not Path(f"{path}.rollback-anchor").exists()
    if os.name == "nt":
        assert_restricted_windows_acl(lock_path)

    monkeypatch.setattr(
        ownership_type, "_write_receipt", staticmethod(original_write)
    )
    recovered = GatewayInstallationControl.provision(root, path)
    recovered.close()
    assert lock_path.read_bytes() == control_module._OWNERSHIP_MAGIC  # type: ignore[attr-defined]


def test_nonpristine_state_never_repairs_an_incomplete_ownership_receipt(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "nonpristine-root.db", dependencies=dependencies()
    )
    snapshot = root.snapshot()
    component = snapshot.component("gateway")
    path = tmp_path / "nonpristine-media.db"
    orphan = DurableMediaRequestStore(
        path,
        construction_policy="create_bound",
        expected_database_identity=component.identity,
    )
    initial = orphan.inspect_root_state()
    orphan.close()
    root.bind_component(
        "gateway",
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        identity=component.identity,
        sequence_floor=initial.mutation_sequence,
        state_digest=initial.state_digest,
        expected_root_revision=snapshot.root_revision,
    )
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, snapshot.installation_id, component.identity
    )
    incomplete = control_module._OWNERSHIP_MAGIC[:7]  # type: ignore[attr-defined]
    lock_path.write_bytes(incomplete)

    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(root, path)
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.open_bound(root, path)

    assert lock_path.read_bytes() == incomplete
    verifier = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=component.identity,
    )
    try:
        assert verifier.inspect_root_state() == initial
    finally:
        verifier.close()


def test_bound_gateway_restart_while_other_components_are_unbound_remains_waiting(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "waiting-root.db", dependencies=dependencies()
    )
    path = tmp_path / "waiting-media.db"
    provisioned = GatewayInstallationControl.provision(root, path)
    assert root.snapshot().component("gateway").bound is True
    provisioned.close()

    restarted = GatewayInstallationControl.open_bound(root, path)
    try:
        assert restarted.state.mode == "provisioned_not_active"
        assert restarted.state.reason_code == "awaiting-installation-activation"
        assert restarted.state.outbound_ready is False
        active, _desktop_digest = activate_desktop(root, "waiting:desktop:0")
        assert active.status == "active"
        assert restarted.reconcile_startup().mode == "ready"
    finally:
        restarted.close()


def test_bound_or_active_root_never_recreates_a_missing_gateway_pair(
    tmp_path: Path,
) -> None:
    # A provisioning root whose gateway bind survived but whose pair is absent
    # is authority loss, not a create retry.
    waiting_root = InstallationRoot.provision(
        tmp_path / "bound-missing-root.db", dependencies=dependencies()
    )
    waiting = waiting_root.snapshot()
    gateway = waiting.component("gateway")
    waiting_root.bind_component(
        "gateway",
        installation_id=waiting.installation_id,
        epoch=waiting.epoch,
        identity=gateway.identity,
        sequence_floor=0,
        state_digest=digest("lost-bound-gateway"),
        expected_root_revision=waiting.root_revision,
    )
    waiting_path = tmp_path / "bound-missing-media.db"
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(waiting_root, waiting_path)
    assert not waiting_path.exists()
    assert not Path(f"{waiting_path}.rollback-anchor").exists()

    # The same rule is stricter once every component binding made the root
    # active: no runtime/installer retry may mint a new sequence-zero ledger.
    active_root = InstallationRoot.provision(
        tmp_path / "active-missing-root.db", dependencies=dependencies()
    )
    initial = active_root.snapshot()
    gateway = initial.component("gateway")
    after_gateway = active_root.bind_component(
        "gateway",
        installation_id=initial.installation_id,
        epoch=initial.epoch,
        identity=gateway.identity,
        sequence_floor=0,
        state_digest=digest("active-lost-gateway"),
        expected_root_revision=initial.root_revision,
    ).snapshot
    desktop = after_gateway.component("desktop")
    after_desktop = active_root.bind_component(
        "desktop",
        installation_id=after_gateway.installation_id,
        epoch=after_gateway.epoch,
        identity=desktop.identity,
        sequence_floor=0,
        state_digest=digest("active-lost-desktop"),
        expected_root_revision=after_gateway.root_revision,
    ).snapshot
    assets = after_desktop.component("gateway_assets")
    after_assets = active_root.bind_component(
        "gateway_assets",
        installation_id=after_desktop.installation_id,
        epoch=after_desktop.epoch,
        identity=assets.identity,
        sequence_floor=0,
        state_digest=digest("active-lost-assets"),
        expected_root_revision=after_desktop.root_revision,
    ).snapshot
    channel = after_assets.component("channel_media")
    active = active_root.bind_component(
        "channel_media",
        installation_id=after_assets.installation_id,
        epoch=after_assets.epoch,
        identity=channel.identity,
        sequence_floor=0,
        state_digest=digest("active-lost-channel-media"),
        expected_root_revision=after_assets.root_revision,
    ).snapshot
    assert active.status == "active"
    active_path = tmp_path / "active-missing-media.db"
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(active_root, active_path)
    assert not active_path.exists()
    assert not Path(f"{active_path}.rollback-anchor").exists()


def test_explicit_retry_opens_pair_created_before_gateway_bind(
    tmp_path: Path,
) -> None:
    root = InstallationRoot.provision(
        tmp_path / "prebind-crash-root.db", dependencies=dependencies()
    )
    snapshot = root.snapshot()
    identity = snapshot.component("gateway").identity
    path = tmp_path / "prebind-crash-media.db"
    orphan = DurableMediaRequestStore(
        path,
        construction_policy="create_bound",
        expected_database_identity=identity,
    )
    initial_local = orphan.inspect_root_state()
    orphan.close()
    assert snapshot.component("gateway").bound is False

    retried = GatewayInstallationControl.provision(root, path)
    try:
        assert retried.state.mode == "provisioned_not_active"
        assert retried.inspect_local_authority() == initial_local
        assert root.snapshot().component("gateway").bound is True
    finally:
        retried.close()


def test_gateway_bind_commit_response_loss_retries_by_strict_open_only(
    tmp_path: Path,
) -> None:
    fault = OneShotFault("component_bind.after_commit")
    root = InstallationRoot.provision(
        tmp_path / "bind-loss-root.db", dependencies=dependencies(fault=fault)
    )
    path = tmp_path / "bind-loss-media.db"
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(root, path)
    assert fault.triggered is True
    assert path.is_file()
    assert Path(f"{path}.rollback-anchor").is_file()
    committed = root.snapshot()
    assert committed.status == "provisioning"
    assert committed.component("gateway").bound is True

    retried = GatewayInstallationControl.provision(root, path)
    try:
        assert retried.state.mode == "provisioned_not_active"
        assert retried.inspect_local_authority().mutation_sequence == 0
        assert root.snapshot().component("gateway").bound is True
    finally:
        retried.close()


def test_stable_paid_principal_has_fixed_vector_and_no_paid_key_input() -> None:
    root_principal = "ab" * 32
    assert stable_paid_principal(root_principal) == (
        "0923a5d3d03b103c282078cb7d82ee7dd1f317bc9bf0ff6dcc176766fec5081b"
    )
    assert tuple(inspect.signature(stable_paid_principal).parameters) == (
        "root_principal_digest",
    )
    # Rotating an authentication capability cannot affect a function that only
    # accepts the Installation Root principal.
    paid_keys = ("old-paid-key", "new-paid-key")
    assert {stable_paid_principal(root_principal) for _key in paid_keys} == {
        "0923a5d3d03b103c282078cb7d82ee7dd1f317bc9bf0ff6dcc176766fec5081b"
    }
    with pytest.raises(ValueError):
        stable_paid_principal("0" * 64)


def test_root_plus_one_startup_enters_permanent_manual_only_and_ack_is_idempotent(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="recovery"
    )
    control.close()

    local_only = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=root.snapshot().component("gateway").identity,
    )
    try:
        claim = local_only.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key="desktop-recovery-1111-4111-8111-111111111111",
            request_sha256="2" * 64,
            now=1.0,
        )
        assert claim.state == "claimed"
        assert local_only.inspect_root_state().mutation_sequence == 1
    finally:
        local_only.close()

    recovered = GatewayInstallationControl.open_bound(root, path)
    try:
        state = recovered.state
        assert state.mode == "manual_only"
        assert state.mutation_sequence == 2
        component = root.snapshot().component("gateway")
        assert component.sequence_floor == 2
        assert component.state_digest == state.state_digest
        assert component.recovery_floor is None
        manual_before = recovered.inspect_local_authority()
        with pytest.raises(DurableMediaRequestUnavailable):
            recovered.store.claim(
                principal_hash="1" * 64,
                operation="images.create",
                idempotency_key="desktop-manual-gate-4111-8111-111111111111",
                request_sha256=digest("manual-gate"),
                now=1.5,
            )
        assert recovered.inspect_local_authority() == manual_before
        with pytest.raises(GatewayInstallationControlUnavailable):
            recovered.assert_outbound_ready()
        assert recovered.state.mode == "manual_only"
        assert recovered.state.reason_code == "manual-recovery-required"
    finally:
        recovered.close()

    reopened = GatewayInstallationControl.open_bound(root, path)
    try:
        revision = root.snapshot().root_revision
        assert reopened.state.mode == "manual_only"
        assert reopened.reconcile_startup().mode == "manual_only"
        assert root.snapshot().root_revision == revision
    finally:
        reopened.close()


def test_manual_recovery_ack_response_loss_converges_from_fresh_snapshot(
    tmp_path: Path,
) -> None:
    fault = OneShotFault("component_recovery_ack.after_commit")
    deps = dependencies(fault=fault)
    root, control, path, _desktop_digest = active_control(
        tmp_path, deps=deps, name="ack-loss"
    )
    control.close()
    identity = root.snapshot().component("gateway").identity
    local_only = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        local_only.claim(
            principal_hash="3" * 64,
            operation="images.create",
            idempotency_key="desktop-ack-loss-1111-4111-8111-111111111111",
            request_sha256="4" * 64,
            now=2.0,
        )
    finally:
        local_only.close()

    recovered = GatewayInstallationControl.open_bound(root, path)
    try:
        assert fault.triggered is True
        assert recovered.state.mode == "manual_only"
        assert recovered.state.mutation_sequence == 2
        assert root.snapshot().component("gateway").sequence_floor == 2
    finally:
        recovered.close()


def test_root_commit_hook_confirms_cas_response_loss_without_duplicate_advance(
    tmp_path: Path,
) -> None:
    fault = OneShotFault("component_advance.after_commit")
    deps = dependencies(fault=fault)
    root, control, path, _desktop_digest = active_control(
        tmp_path, deps=deps, name="cas-loss"
    )
    control.close()
    reopened = GatewayInstallationControl.open_bound(root, path)
    try:
        claim = reopened.store.claim(
            principal_hash="5" * 64,
            operation="images.create",
            idempotency_key="desktop-cas-loss-1111-4111-8111-111111111111",
            request_sha256="6" * 64,
            now=3.0,
        )
        assert claim.state == "claimed"
        assert fault.triggered is True
        assert reopened.state.mode == "ready"
        assert reopened.state.mutation_sequence == 1
        assert root.snapshot().component("gateway").sequence_floor == 1
    finally:
        reopened.close()


def test_root_commit_retries_with_fresh_revision_after_unrelated_root_race(
    tmp_path: Path,
) -> None:
    root, control, path, desktop_digest = active_control(
        tmp_path, name="revision-race"
    )
    control.close()
    racing = RevisionRaceRoot(root, desktop_digest)
    reopened = GatewayInstallationControl.open_bound(racing, path)
    try:
        claim = reopened.store.claim(
            principal_hash="7" * 64,
            operation="images.create",
            idempotency_key="desktop-revision-race-4111-8111-111111111111",
            request_sha256="8" * 64,
            now=4.0,
        )
        assert claim.state == "claimed"
        assert racing.raced is True
        assert racing.advance_calls == 2
        snapshot = root.snapshot()
        assert snapshot.component("desktop").sequence_floor == 1
        assert snapshot.component("gateway").sequence_floor == 1
        assert reopened.state.mode == "ready"
    finally:
        reopened.close()


def test_root_commit_is_bounded_to_four_cas_calls_and_fuses_on_unconfirmed_state(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="bounded-cas"
    )
    control.close()
    failing = NeverCommitRoot(root)
    reopened = GatewayInstallationControl.open_bound(failing, path)
    try:
        with pytest.raises(DurableMediaRootCommitPending):
            reopened.store.claim(
                principal_hash="9" * 64,
                operation="images.create",
                idempotency_key="desktop-bounded-cas-4111-8111-111111111111",
                request_sha256="a" * 64,
                now=5.0,
            )
        assert failing.advance_calls == 4
        assert reopened.state.mode == "fused"
        assert reopened.state.reason_code == "root-commit-unconfirmed"
        replay = reopened.store.claim(
            principal_hash="9" * 64,
            operation="images.create",
            idempotency_key="desktop-bounded-cas-4111-8111-111111111111",
            request_sha256="a" * 64,
            now=6.0,
        )
        assert replay.state == "processing"
    finally:
        reopened.close()


def test_root_commit_baseexception_is_translated_only_after_controller_fuses(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="baseexception"
    )
    control.close()
    interrupted = InterruptingRoot(root)
    reopened = GatewayInstallationControl.open_bound(interrupted, path)
    try:
        with pytest.raises(DurableMediaRootCommitPending):
            reopened.store.claim(
                principal_hash="d" * 64,
                operation="images.create",
                idempotency_key="desktop-baseexception-4111-8111-111111111111",
                request_sha256="e" * 64,
                now=7.0,
            )
        assert reopened.state.mode == "fused"
        assert reopened.state.outbound_ready is False
        assert reopened.inspect_local_authority().mutation_sequence == 1
        assert root.snapshot().component("gateway").sequence_floor == 0
    finally:
        reopened.close()


def test_unknown_floor_gap_and_wrong_database_identity_fail_closed(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="unknown-gap"
    )
    control.close()
    identity = root.snapshot().component("gateway").identity
    local_only = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=identity,
    )
    try:
        for index in range(2):
            local_only.claim(
                principal_hash="b" * 64,
                operation="images.create",
                idempotency_key=(
                    f"desktop-gap-{index + 1:04d}-4111-8111-111111111111"
                ),
                request_sha256=digest(f"gap:{index}"),
                now=10.0 + index,
            )
        assert local_only.inspect_root_state().mutation_sequence == 2
    finally:
        local_only.close()

    gapped = GatewayInstallationControl.open_bound(root, path)
    try:
        assert gapped.state.mode == "fused"
        assert gapped.state.reason_code == "authority-mismatch"
        assert root.snapshot().status == "active"
        assert root.snapshot().component("gateway").sequence_floor == 0
    finally:
        gapped.close()

    other_path = tmp_path / "wrong-identity.db"
    wrong = DurableMediaRequestStore(
        other_path,
        construction_policy="create_bound",
        expected_database_identity="f" * 64,
    )
    wrong.close()
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.open_bound(root, other_path)


def test_each_outbound_check_reads_fresh_root_and_one_failure_is_transient(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="fresh-outbound"
    )
    control.close()
    proxy = SwitchableRoot(root)
    reopened = GatewayInstallationControl.open_bound(proxy, path)
    try:
        baseline = proxy.snapshot_calls
        assert reopened.assert_outbound_ready().mode == "ready"
        assert reopened.assert_outbound_ready().mode == "ready"
        assert proxy.snapshot_calls == baseline + 2

        proxy.unavailable = True
        with pytest.raises(GatewayInstallationControlUnavailable):
            reopened.assert_outbound_ready()
        failed_calls = proxy.snapshot_calls
        assert reopened.state.mode == "ready"
        assert reopened.state.reason_code == "outbound-proof-fresh"
        proxy.unavailable = False
        assert reopened.assert_outbound_ready().mode == "ready"
        assert proxy.snapshot_calls == failed_calls + 1
    finally:
        reopened.close()


def test_reconcile_root_read_failure_is_transient_without_a_local_commit(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="transient-reconcile"
    )
    control.close()
    proxy = SwitchableRoot(root)
    reopened = GatewayInstallationControl.open_bound(proxy, path)
    try:
        before = reopened.state
        proxy.unavailable = True
        with pytest.raises(GatewayInstallationControlUnavailable):
            reopened.reconcile_startup()
        assert reopened.state == before
        assert reopened.state.mode == "ready"
        proxy.unavailable = False
        assert reopened.reconcile_startup().mode == "ready"
    finally:
        reopened.close()


def test_deterministic_local_authority_corruption_is_sticky(
    tmp_path: Path,
) -> None:
    _root, control, path, _desktop_digest = active_control(
        tmp_path, name="local-corruption"
    )
    anchor = Path(f"{path}.rollback-anchor")
    anchor.write_bytes(b"deterministically-corrupt")
    try:
        with pytest.raises(GatewayInstallationControlUnavailable):
            control.assert_outbound_ready()
        assert control.state.mode == "fused"
        assert control.state.reason_code == "local-authority-corruption"
    finally:
        control.close()


def test_typed_transient_local_read_failure_does_not_sticky_fuse(
    tmp_path: Path, monkeypatch
) -> None:
    _root, control, _path, _desktop_digest = active_control(
        tmp_path, name="local-transient"
    )
    raw_store = control._store
    assert raw_store is not None
    original_inspect = raw_store.inspect_root_state

    def unavailable():
        raise DurableMediaRequestUnavailable("simulated local read contention")

    try:
        monkeypatch.setattr(raw_store, "inspect_root_state", unavailable)
        with pytest.raises(GatewayInstallationControlUnavailable):
            control.assert_outbound_ready()
        assert control.state.mode == "ready"
        assert control.state.reason_code == "authority-exact"
        monkeypatch.setattr(raw_store, "inspect_root_state", original_inspect)
        assert control.assert_outbound_ready().mode == "ready"
    finally:
        control.close()


def test_outbound_check_retries_old_local_new_root_concurrent_sample(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="outbound-race"
    )
    control.close()
    proxy = OutboundRaceRoot(root)
    reopened = GatewayInstallationControl.open_bound(proxy, path)
    try:
        def prove():
            proxy.target_thread = threading.get_ident()
            return reopened.assert_outbound_ready()

        with ThreadPoolExecutor(max_workers=1) as pool:
            proof = pool.submit(prove)
            assert proxy.sample_waiting.wait(5)
            claim = reopened.store.claim(
                principal_hash="1" * 64,
                operation="images.create",
                idempotency_key="desktop-outbound-race-4111-8111-111111111111",
                request_sha256=digest("outbound-race"),
                now=60.0,
            )
            assert claim.state == "claimed"
            proxy.release_sample.set()
            assert proof.result(timeout=5).mode == "ready"
        local = reopened.inspect_local_authority()
        component = root.snapshot().component("gateway")
        assert reopened.state.mode == "ready"
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
    finally:
        proxy.release_sample.set()
        reopened.close()


def test_outbound_legal_resampling_exhaustion_is_transient_and_stays_exact(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="outbound-resample"
    )
    control.close()
    proxy = RepeatedOutboundRaceRoot(root)
    reopened = GatewayInstallationControl.open_bound(proxy, path)
    try:
        def advance(index: int) -> None:
            claim = reopened.store.claim(
                principal_hash="3" * 64,
                operation="images.create",
                idempotency_key=(
                    f"desktop-resample-{index:04d}-4111-8111-111111111111"
                ),
                request_sha256=digest(f"resample:{index}"),
                now=70.0 + index,
            )
            assert claim.state == "claimed"

        proxy.advance = advance
        proxy.target_thread = threading.get_ident()
        with pytest.raises(GatewayInstallationControlUnavailable):
            reopened.assert_outbound_ready()
        assert proxy.races == control_module._MAX_OUTBOUND_INSPECTIONS
        local = reopened.inspect_local_authority()
        component = root.snapshot().component("gateway")
        assert reopened.state.mode == "ready"
        assert reopened.state.reason_code == "authority-exact"
        assert local.mutation_sequence == component.sequence_floor == proxy.races
        assert local.state_digest == component.state_digest == reopened.state.state_digest

        proxy.enabled = False
        assert reopened.assert_outbound_ready().mode == "ready"
    finally:
        proxy.enabled = False
        reopened.close()


def test_native_ownership_rejects_second_instance_alias_and_releases_on_close(
    tmp_path: Path,
) -> None:
    root, first, path, _desktop_digest = active_control(
        tmp_path, name="single-writer"
    )
    alias = Path(str(path).upper()) if os.name == "nt" else path
    try:
        before = first.inspect_local_authority()
        with pytest.raises(GatewayInstallationControlUnavailable):
            GatewayInstallationControl.open_bound(root, alias)
        assert first.inspect_local_authority() == before
        assert first.state.mode == "ready"
        assert root.snapshot().component("gateway").sequence_floor == 0
    finally:
        first.close()

    reopened = GatewayInstallationControl.open_bound(root, alias)
    try:
        assert reopened.state.mode == "ready"
    finally:
        reopened.close()


@pytest.mark.skipif(os.name != "nt", reason="validates Windows ownership-leaf ACL")
def test_existing_ownership_leaf_acl_is_verified_without_silent_repair(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="owner-acl"
    )
    snapshot = root.snapshot()
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, snapshot.installation_id, snapshot.component("gateway").identity
    )
    control.close()
    broadened = subprocess.run(
        [
            str(trusted_windows_system_executable("icacls.exe")),
            str(lock_path),
            "/grant",
            "*S-1-5-32-545:(R)",
            "/q",
        ],
        capture_output=True,
        check=False,
    )
    assert broadened.returncode == 0, broadened.stderr
    with pytest.raises(SecureStorageError):
        assert_restricted_windows_acl(lock_path)

    try:
        unexpected = GatewayInstallationControl.open_bound(root, path)
    except GatewayInstallationControlUnavailable:
        pass
    else:
        unexpected.close()
        pytest.fail("a broadened existing ownership ACL was accepted")

    with pytest.raises(SecureStorageError):
        assert_restricted_windows_acl(lock_path)


def test_close_waits_for_an_approved_write_root_hook_before_unlocking(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="closing-fence"
    )
    control.close()
    proxy = BlockingCommitRoot(root)
    reopened = GatewayInstallationControl.open_bound(proxy, path)

    def claim():
        proxy.target_thread = threading.get_ident()
        return reopened.store.claim(
            principal_hash="2" * 64,
            operation="images.create",
            idempotency_key="desktop-closing-fence-4111-8111-111111111111",
            request_sha256=digest("closing-fence"),
            now=61.0,
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            mutation = pool.submit(claim)
            assert proxy.commit_waiting.wait(5)
            closing = pool.submit(reopened.close)
            deadline = time.monotonic() + 5
            while not reopened._closing and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            assert reopened._closing is True
            assert closing.done() is False
            with pytest.raises(GatewayInstallationControlUnavailable):
                GatewayInstallationControl.open_bound(root, path)
            assert reopened.state.mode == "ready"
            assert reopened.state.reason_code != "root-commit-unconfirmed"
            proxy.release_commit.set()
            assert mutation.result(timeout=5).state == "claimed"
            closing.result(timeout=5)
        component = root.snapshot().component("gateway")
        assert component.sequence_floor == 1
        assert reopened.state.mode == "detached"
        assert reopened.state.reason_code == "store-closed"
    finally:
        proxy.release_commit.set()
        reopened.close()

    after = GatewayInstallationControl.open_bound(root, path)
    after.close()


def test_close_baseexception_keeps_ownership_and_remains_nonsticky(
    tmp_path: Path, monkeypatch
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="closing-interrupt"
    )
    raw_store = control._store
    assert raw_store is not None
    original_close = raw_store.close

    def interrupted_close() -> None:
        raise KeyboardInterrupt("simulated close interruption")

    monkeypatch.setattr(raw_store, "close", interrupted_close)
    with pytest.raises(KeyboardInterrupt):
        control.close()

    assert control._closing is True
    assert control.state.mode == "ready"
    assert control.state.reason_code != "root-commit-unconfirmed"
    with pytest.raises(GatewayInstallationControlUnavailable):
        _ = control.store
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.open_bound(root, path)

    monkeypatch.setattr(raw_store, "close", original_close)
    control.close()
    reopened = GatewayInstallationControl.open_bound(root, path)
    reopened.close()


@pytest.mark.skipif(os.name != "nt", reason="validates Windows mandatory handle release")
def test_native_ownership_is_released_after_holder_process_crash(
    tmp_path: Path,
) -> None:
    root, control, _path, _desktop_digest = active_control(
        tmp_path, name="owner-crash"
    )
    identity = root.snapshot().component("gateway").identity
    lock_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root, root.snapshot().installation_id, identity
    )
    control.close()

    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    process = context.Process(
        target=_crash_while_holding_ownership,
        args=(str(lock_path), acquired),
    )
    process.start()
    assert acquired.wait(10)
    process.join(10)
    assert process.exitcode == 91

    ownership = control_module._GatewayLedgerOwnership.acquire(  # type: ignore[attr-defined]
        lock_path, create_if_missing=False
    )
    ownership.close()


def test_startup_root_unavailable_does_not_create_or_mutate_the_bound_pair(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="startup-unavailable"
    )
    identity = root.snapshot().component("gateway").identity
    before_db = path.read_bytes()
    before_anchor = Path(f"{path}.rollback-anchor").read_bytes()
    control.close()
    proxy = SwitchableRoot(root)
    proxy.unavailable = True
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.open_bound(proxy, path)
    assert path.read_bytes() == before_db
    assert Path(f"{path}.rollback-anchor").read_bytes() == before_anchor
    assert root.snapshot().component("gateway").identity == identity


def test_concurrent_local_mutations_serialize_root_transitions_safely(
    tmp_path: Path,
) -> None:
    root, control, _path, _desktop_digest = active_control(
        tmp_path, name="threaded-transitions"
    )
    try:
        def claim(index: int):
            return control.store.claim(
                principal_hash="c" * 64,
                operation="images.create",
                idempotency_key=(
                    f"desktop-thread-{index:04d}-4111-8111-111111111111"
                ),
                request_sha256=digest(f"thread:{index}"),
                now=100.0 + index,
            )

        # Each in-flight request deliberately reserves the full default response
        # budget, so four is the exact safe concurrency bound of this fixture.
        with ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(claim, range(4)))
        assert all(item.state == "claimed" for item in claims)
        local = control.store.inspect_root_state()
        component = root.snapshot().component("gateway")
        assert local.mutation_sequence == 4
        assert component.sequence_floor == 4
        assert component.state_digest == local.state_digest
        assert control.state.mode == "ready"
        assert control.assert_outbound_ready().mode == "ready"
    finally:
        control.close()


def test_fused_controller_has_no_global_side_effect_on_independent_authority(
    tmp_path: Path,
) -> None:
    first_root, first_control, first_path, _ = active_control(
        tmp_path, name="isolated-first"
    )
    second_root, second_control, second_path, _ = active_control(
        tmp_path, name="isolated-second"
    )
    first_control.close()
    second_control.close()
    first = GatewayInstallationControl.open_bound(first_root, first_path)
    second = GatewayInstallationControl.open_bound(second_root, second_path)
    try:
        snapshot = first_root.snapshot()
        component = snapshot.component("gateway")
        first_root.advance_component(
            "gateway",
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=component.identity,
            expected_floor=component.sequence_floor,
            expected_state_digest=component.state_digest,
            next_floor=component.sequence_floor + 1,
            next_state_digest=digest("isolated-first-root-drift"),
            expected_root_revision=snapshot.root_revision,
        )
        with pytest.raises(GatewayInstallationControlUnavailable):
            first.assert_outbound_ready()
        assert first.state.mode == "fused"
        assert first.state.reason_code == "outbound-authority-mismatch"
        assert second.state.mode == "ready"
        assert second.assert_outbound_ready().mode == "ready"
    finally:
        first.close()
        second.close()


def test_component_addition_verifier_proves_existing_gateway_without_writes(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="component-addition-gateway"
    )
    original.store.claim(
        principal_hash="d" * 64,
        operation="images.create",
        idempotency_key="component-addition-4111-8111-111111111111",
        request_sha256=digest("component-addition-existing-operation"),
        now=50.0,
    )
    original.close()
    active = root.snapshot()
    pending = component_addition_snapshot(active)
    authority = ComponentAdditionRoot(root, pending)
    ownership_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        pending.installation_id,
        pending.component("gateway").identity,
    )
    protected_paths = (path, Path(f"{path}.rollback-anchor"), ownership_path)
    before_bytes = {item: item.read_bytes() for item in protected_paths}

    verified = GatewayInstallationControl.verify_bound_for_component_addition(
        authority,
        path,
    )
    try:
        local = verified.inspect_local_authority()
        component = pending.component("gateway")
        assert verified.state.mode == "provisioned_not_active"
        assert verified.state.reason_code == "component-addition-proof-verified"
        assert verified.state.outbound_ready is False
        assert local.database_identity == component.identity
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
        assert local.authority_mode == "normal"
        assert local.recovery_floor is None
        assert local.recovery_state_digest is None
        with pytest.raises(GatewayInstallationControlUnavailable):
            _ = verified.store
        with pytest.raises(DurableMediaRequestUnavailable):
            verified.assert_local_mutation_ready()
        assert authority.mutation_calls == 0
        assert root.snapshot() == active
    finally:
        verified.close()

    assert {item: item.read_bytes() for item in protected_paths} == before_bytes


def test_component_addition_gateway_verifier_rejects_lock_and_proof_drift(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="component-addition-gateway-drift"
    )
    original.close()
    pending = component_addition_snapshot(root.snapshot())
    component = pending.component("gateway")
    candidates = (
        replace(
            pending,
            status="active",
            lock_kind="none",
            lock_reason_digest=None,
        ),
        replace(pending, lock_kind="operator"),
        replace_snapshot_component(pending, "gateway", bound=False),
        replace_snapshot_component(
            pending, "gateway", epoch=component.epoch + 1
        ),
        replace_snapshot_component(
            pending,
            "gateway",
            sequence_floor=component.sequence_floor + 1,
        ),
        replace_snapshot_component(
            pending,
            "gateway",
            state_digest=digest("component-addition-root-digest-drift"),
        ),
        replace_snapshot_component(
            pending,
            "gateway",
            recovery_floor=component.sequence_floor,
            recovery_state_digest=component.state_digest,
        ),
    )
    before_db = path.read_bytes()
    anchor = Path(f"{path}.rollback-anchor")
    before_anchor = anchor.read_bytes()

    for candidate in candidates:
        authority = ComponentAdditionRoot(root, candidate)
        with pytest.raises(GatewayInstallationControlUnavailable):
            GatewayInstallationControl.verify_bound_for_component_addition(
                authority,
                path,
            )
        assert authority.mutation_calls == 0

    assert path.read_bytes() == before_db
    assert anchor.read_bytes() == before_anchor


def test_component_addition_gateway_verifier_never_creates_or_repairs(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="component-addition-gateway-missing"
    )
    original.close()
    pending = component_addition_snapshot(root.snapshot())
    authority = ComponentAdditionRoot(root, pending)
    missing = tmp_path / "missing-gateway.db"

    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.verify_bound_for_component_addition(
            authority,
            missing,
        )
    assert not missing.exists()
    assert not Path(f"{missing}.rollback-anchor").exists()

    ownership = control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        pending.installation_id,
        pending.component("gateway").identity,
    )
    moved_ownership = ownership.with_name(f"{ownership.name}.held-by-test")
    ownership.rename(moved_ownership)
    try:
        with pytest.raises(GatewayInstallationControlUnavailable):
            GatewayInstallationControl.verify_bound_for_component_addition(
                authority,
                path,
            )
        assert not ownership.exists()
    finally:
        moved_ownership.rename(ownership)

    anchor = Path(f"{path}.rollback-anchor")
    moved_anchor = anchor.with_name(f"{anchor.name}.held-by-test")
    anchor.rename(moved_anchor)
    try:
        with pytest.raises(GatewayInstallationControlUnavailable):
            GatewayInstallationControl.verify_bound_for_component_addition(
                authority,
                path,
            )
        assert not anchor.exists()
    finally:
        moved_anchor.rename(anchor)


def test_component_addition_does_not_relax_gateway_runtime_or_provisioning(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="component-addition-gateway-normal-paths"
    )
    original.close()
    authority = ComponentAdditionRoot(
        root,
        component_addition_snapshot(root.snapshot()),
    )

    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.provision(authority, path)
    runtime = GatewayInstallationControl.open_bound(authority, path)
    try:
        assert runtime.state.mode == "fused"
        assert runtime.state.outbound_ready is False
    finally:
        runtime.close()
    assert authority.mutation_calls == 0


def test_active_installer_verifier_proves_nonzero_gateway_without_writes(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="active-installer-gateway"
    )
    original.store.claim(
        principal_hash="e" * 64,
        operation="images.create",
        idempotency_key="active-installer-4111-8111-111111111111",
        request_sha256=digest("active-installer-existing-operation"),
        now=70.0,
    )
    original.close()
    active = root.snapshot()
    authority = ComponentAdditionRoot(root, active)
    ownership_path = control_module._ownership_path(  # type: ignore[attr-defined]
        root,
        active.installation_id,
        active.component("gateway").identity,
    )
    protected_paths = (path, Path(f"{path}.rollback-anchor"), ownership_path)
    before_bytes = {item: item.read_bytes() for item in protected_paths}

    verified = GatewayInstallationControl.verify_bound_for_active_installer(
        authority,
        path,
    )
    try:
        local = verified.inspect_local_authority()
        component = active.component("gateway")
        assert verified.state.mode == "provisioned_not_active"
        assert verified.state.reason_code == "active-installer-proof-verified"
        assert local.mutation_sequence == component.sequence_floor == 1
        assert local.state_digest == component.state_digest
        with pytest.raises(GatewayInstallationControlUnavailable):
            _ = verified.store
        with pytest.raises(DurableMediaRequestUnavailable):
            verified.assert_local_mutation_ready()
        assert authority.mutation_calls == 0
    finally:
        verified.close()

    assert {item: item.read_bytes() for item in protected_paths} == before_bytes


def test_gateway_installer_verifiers_reject_exact_manual_only_local_authority(
    tmp_path: Path,
) -> None:
    root, original, path, _desktop_digest = active_control(
        tmp_path, name="installer-manual-only-gateway"
    )
    original.close()
    active = root.snapshot()
    raw = DurableMediaRequestStore(
        path,
        construction_policy="open_bound",
        expected_database_identity=active.component("gateway").identity,
    )
    try:
        normal = raw.inspect_root_state()
        manual = raw.enter_authority_manual_only(
            installation_id=active.installation_id,
            epoch=active.epoch,
            recovery_floor=normal.mutation_sequence,
            recovery_state_digest=normal.state_digest,
        ).after
    finally:
        raw.close()
    exact_active = replace_snapshot_component(
        active,
        "gateway",
        sequence_floor=manual.mutation_sequence,
        state_digest=manual.state_digest,
        recovery_floor=None,
        recovery_state_digest=None,
    )
    candidates = (
        (
            GatewayInstallationControl.verify_bound_for_active_installer,
            exact_active,
        ),
        (
            GatewayInstallationControl.verify_bound_for_component_addition,
            component_addition_snapshot(exact_active),
        ),
    )

    for verifier, snapshot in candidates:
        authority = ComponentAdditionRoot(root, snapshot)
        try:
            unexpected = verifier(authority, path)
        except GatewayInstallationControlUnavailable:
            pass
        else:
            unexpected.close()
            pytest.fail("installer verifier accepted manual-only local authority")
        assert authority.mutation_calls == 0


def test_active_gateway_installer_verifier_rejects_recovery_and_missing_state(
    tmp_path: Path,
) -> None:
    root, control, path, _desktop_digest = active_control(
        tmp_path, name="active-installer-gateway-reject"
    )
    before = root.snapshot()
    control.store.claim(
        principal_hash="f" * 64,
        operation="images.create",
        idempotency_key="active-installer-gap-4111-8111-111111111111",
        request_sha256=digest("active-installer-gap"),
        now=80.0,
    )
    control.close()
    exact = root.snapshot()
    previous = before.component("gateway")
    current = exact.component("gateway")
    candidates = (
        replace_snapshot_component(
            exact,
            "gateway",
            sequence_floor=previous.sequence_floor,
            state_digest=previous.state_digest,
        ),
        replace_snapshot_component(
            exact,
            "gateway",
            recovery_floor=current.sequence_floor,
            recovery_state_digest=current.state_digest,
        ),
        component_addition_snapshot(exact),
    )

    for candidate in candidates:
        authority = ComponentAdditionRoot(root, candidate)
        with pytest.raises(GatewayInstallationControlUnavailable):
            GatewayInstallationControl.verify_bound_for_active_installer(
                authority,
                path,
            )
        assert authority.mutation_calls == 0

    missing = tmp_path / "active-installer-missing-gateway.db"
    authority = ComponentAdditionRoot(root, exact)
    with pytest.raises(GatewayInstallationControlUnavailable):
        GatewayInstallationControl.verify_bound_for_active_installer(
            authority,
            missing,
        )
    assert not missing.exists()
    assert not Path(f"{missing}.rollback-anchor").exists()
    assert authority.mutation_calls == 0
