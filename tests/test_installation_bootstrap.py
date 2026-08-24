from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from gateway import installation_bootstrap as bootstrap
from gateway import installation_root as installation_root_module
from gateway.asset_installation_control import AssetInstallationControl
from gateway.durable_media_requests import DurableMediaRequestStore
from gateway.gateway_installation_control import GatewayInstallationControl
from gateway.installation_root import DEFAULT_DEPENDENCIES, InstallationRoot
from gateway.paid_media_asset_store import PaidMediaAssetStoreDependencies


def _layout(tmp_path: Path):  # noqa: ANN202
    program_data = tmp_path / "ProgramData"
    program_data.mkdir()
    boundary = program_data / "Nachuan"
    state_root = boundary / "StateRoot"
    root_path = state_root / "installation-root.db"
    ledger_path = state_root / "gateway-paid-media-requests.db"
    dependencies = replace(
        DEFAULT_DEPENDENCIES,
        trusted_boundary=lambda _path: boundary,
    )
    return boundary, state_root, root_path, ledger_path, dependencies


def _provision(tmp_path: Path):  # noqa: ANN202
    boundary, state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    result = bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        dependencies=dependencies,
    )
    return (
        result,
        boundary,
        state_root,
        root_path,
        ledger_path,
        dependencies,
    )


def _downgrade_active_fixture_to_v4(path: Path) -> None:
    """Convert one validated active Root into the exact historical v4 schema."""

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


def test_clean_install_creates_all_gateway_authorities_and_waits_for_desktop(
    tmp_path: Path,
) -> None:
    result, boundary, state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )

    snapshot = InstallationRoot.open(
        root_path, dependencies=dependencies
    ).snapshot()
    assert result.installation_id == snapshot.installation_id
    assert result.epoch == 1
    assert result.root_status == "provisioning"
    assert result.gateway_bound is True
    assert result.desktop_bound is False
    assert result.asset_store_bound is True
    assert result.channel_media_bound is True
    assert snapshot.component("gateway").bound is True
    assert snapshot.component("desktop").bound is False
    assert snapshot.component("gateway_assets").bound is True
    assert snapshot.component("channel_media").bound is True
    assert boundary.is_dir()
    assert state_root.is_dir()
    assert root_path.is_file()
    assert Path(f"{root_path}-journal").is_file()
    assert ledger_path.is_file()
    assert Path(f"{ledger_path}.rollback-anchor").is_file()
    channel_media_ledger = state_root / "channel-media-requests.db"
    assert channel_media_ledger.is_file()
    assert Path(f"{channel_media_ledger}.rollback-anchor").is_file()
    asset_store = state_root / "paid-media-assets"
    assert (asset_store / "asset-store.db").is_file()
    assert (asset_store / "staging").is_dir()
    assert (asset_store / "objects").is_dir()


def test_completed_installer_retry_is_identity_preserving(tmp_path: Path) -> None:
    first, _boundary, _state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    before_root = root_path.read_bytes()
    before_identity = InstallationRoot.open(
        root_path, dependencies=dependencies
    ).snapshot().component("gateway").identity
    before_asset_identity = InstallationRoot.open(
        root_path, dependencies=dependencies
    ).snapshot().component("gateway_assets").identity
    before_channel_identity = InstallationRoot.open(
        root_path, dependencies=dependencies
    ).snapshot().component("channel_media").identity

    second = bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        dependencies=dependencies,
    )

    after = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert second == first
    assert after.installation_id == first.installation_id
    assert after.component("gateway").identity == before_identity
    assert after.component("gateway_assets").identity == before_asset_identity
    assert after.component("gateway_assets").bound is True
    assert after.component("channel_media").identity == before_channel_identity
    assert after.component("channel_media").bound is True
    assert root_path.read_bytes() == before_root


def test_retry_after_root_commit_finishes_gateway_binding(tmp_path: Path) -> None:
    boundary, _state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    bootstrap._prepare_empty_authority_directories(
        root_path, ledger_path, dependencies
    )
    interrupted = InstallationRoot.provision(
        root_path, dependencies=dependencies
    ).snapshot()
    assert interrupted.status == "provisioning"
    assert interrupted.component("gateway").bound is False
    assert not ledger_path.exists()

    result = bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        dependencies=dependencies,
    )

    resumed = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert boundary.is_dir()
    assert result.installation_id == interrupted.installation_id
    assert resumed.component("gateway").identity == interrupted.component(
        "gateway"
    ).identity
    assert resumed.component("gateway").bound is True
    assert resumed.component("channel_media").bound is True
    assert resumed.component("desktop").bound is False


def test_v4_upgrade_verifies_old_authorities_then_adds_channel_without_rebind(
    tmp_path: Path,
) -> None:
    _boundary, state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    bootstrap._prepare_empty_authority_directories(
        root_path,
        ledger_path,
        dependencies,
    )
    legacy = InstallationRoot.provision(root_path, dependencies=dependencies)
    gateway = GatewayInstallationControl.provision(legacy, ledger_path)
    gateway.close()
    asset_path = state_root / "paid-media-assets"
    asset_dependencies = PaidMediaAssetStoreDependencies(
        assert_acl=dependencies.assert_acl,
        harden_acl=dependencies.harden_acl,
        disk_free=lambda path: int(shutil.disk_usage(path).free),
    )
    assets = AssetInstallationControl.provision(
        legacy,
        asset_path,
        store_dependencies=asset_dependencies,
    )
    assets.close()

    snapshot = legacy.snapshot()
    for name, state_digest in (
        ("desktop", "d" * 64),
        ("channel_media", "c" * 64),
    ):
        component = snapshot.component(name)
        snapshot = legacy.bind_component(
            name,
            installation_id=snapshot.installation_id,
            epoch=snapshot.epoch,
            identity=component.identity,
            sequence_floor=0,
            state_digest=state_digest,
            expected_root_revision=snapshot.root_revision,
        ).snapshot
    assert snapshot.status == "active"

    gateway = GatewayInstallationControl.open_bound(legacy, ledger_path)
    try:
        claim = gateway.store.claim(
            principal_hash="1" * 64,
            operation="images.create",
            idempotency_key="v4-upgrade-proof-1111-4111-8111-111111111111",
            request_sha256="2" * 64,
            now=1.0,
        )
        assert claim.state == "claimed"
        local_gateway_before = gateway.inspect_local_authority()
    finally:
        gateway.close()
    old_snapshot = legacy.snapshot()
    old_gateway = old_snapshot.component("gateway")
    old_assets = old_snapshot.component("gateway_assets")
    assert old_gateway.sequence_floor == local_gateway_before.mutation_sequence == 1
    assert old_gateway.state_digest == local_gateway_before.state_digest

    _downgrade_active_fixture_to_v4(root_path)
    channel_path = state_root / "channel-media-requests.db"
    assert not channel_path.exists()

    result = bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        dependencies=dependencies,
    )

    migrated = InstallationRoot.open(root_path, dependencies=dependencies)
    after = migrated.snapshot()
    assert result.root_status == "active"
    assert result.desktop_bound is True
    assert result.gateway_bound is True
    assert result.asset_store_bound is True
    assert result.channel_media_bound is True
    assert after.component("gateway").identity == old_gateway.identity
    assert after.component("gateway").sequence_floor == old_gateway.sequence_floor
    assert after.component("gateway").state_digest == old_gateway.state_digest
    assert after.component("gateway_assets").identity == old_assets.identity
    assert after.component("gateway_assets").state_digest == old_assets.state_digest
    assert channel_path.is_file()
    assert Path(f"{channel_path}.rollback-anchor").is_file()

    gateway = GatewayInstallationControl.open_bound(migrated, ledger_path)
    try:
        assert gateway.state.mode == "ready"
        assert gateway.inspect_local_authority() == local_gateway_before
    finally:
        gateway.close()


def test_active_update_accepts_exact_nonzero_gateway_floor_without_mutation(
    tmp_path: Path,
) -> None:
    first, _boundary, _state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    root = InstallationRoot.open(root_path, dependencies=dependencies)
    snapshot = root.snapshot()
    desktop = snapshot.component("desktop")
    snapshot = root.bind_component(
        "desktop",
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        identity=desktop.identity,
        sequence_floor=0,
        state_digest="e" * 64,
        expected_root_revision=snapshot.root_revision,
    ).snapshot
    assert snapshot.status == "active"

    gateway = GatewayInstallationControl.open_bound(root, ledger_path)
    try:
        claim = gateway.store.claim(
            principal_hash="3" * 64,
            operation="images.create",
            idempotency_key="active-update-proof-1111-4111-8111-111111111111",
            request_sha256="4" * 64,
            now=2.0,
        )
        assert claim.state == "claimed"
    finally:
        gateway.close()
    before = root.snapshot()
    assert before.component("gateway").sequence_floor == 1

    result = bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        dependencies=dependencies,
    )

    after = root.snapshot()
    assert result.installation_id == first.installation_id
    assert result.root_status == "active"
    assert after == before


def test_active_update_rejects_local_plus_one_without_running_recovery(
    tmp_path: Path,
) -> None:
    _first, _boundary, _state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    root = InstallationRoot.open(root_path, dependencies=dependencies)
    snapshot = root.snapshot()
    desktop = snapshot.component("desktop")
    snapshot = root.bind_component(
        "desktop",
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        identity=desktop.identity,
        sequence_floor=0,
        state_digest="f" * 64,
        expected_root_revision=snapshot.root_revision,
    ).snapshot
    assert snapshot.status == "active"
    gateway_identity = snapshot.component("gateway").identity

    raw = DurableMediaRequestStore(
        ledger_path,
        construction_policy="open_bound",
        expected_database_identity=gateway_identity,
    )
    try:
        claim = raw.claim(
            principal_hash="5" * 64,
            operation="images.create",
            idempotency_key="active-update-gap-1111-4111-8111-111111111111",
            request_sha256="6" * 64,
            now=3.0,
        )
        assert claim.state == "claimed"
        local_before = raw.inspect_root_state()
    finally:
        raw.close()
    root_before = root.snapshot()
    assert local_before.mutation_sequence == 1
    assert root_before.component("gateway").sequence_floor == 0

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    assert root.snapshot() == root_before
    raw = DurableMediaRequestStore(
        ledger_path,
        construction_policy="open_bound",
        expected_database_identity=gateway_identity,
    )
    try:
        assert raw.inspect_root_state() == local_before
    finally:
        raw.close()


def test_existing_corrupt_root_is_never_overwritten_or_repaired(tmp_path: Path) -> None:
    boundary, state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    boundary.mkdir()
    state_root.mkdir()
    dependencies.harden_acl(boundary, True)
    dependencies.harden_acl(state_root, True)
    root_path.write_bytes(b"corrupt-authority")
    journal = Path(f"{root_path}-journal")
    journal.write_bytes(b"")
    dependencies.harden_acl(root_path, False)
    dependencies.harden_acl(journal, False)
    before = root_path.read_bytes()

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    assert root_path.read_bytes() == before
    assert journal.exists()
    assert not ledger_path.exists()


def test_unexpected_fresh_state_is_rejected_without_creating_root(tmp_path: Path) -> None:
    boundary, state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    state_root.mkdir(parents=True)
    marker = state_root / "unknown-authority.bin"
    marker.write_bytes(b"do-not-touch")

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    assert marker.read_bytes() == b"do-not-touch"
    assert not root_path.exists()
    assert not ledger_path.exists()


def test_ledger_path_cannot_escape_the_fixed_state_root(tmp_path: Path) -> None:
    _boundary, _state_root, root_path, _ledger_path, dependencies = _layout(tmp_path)
    redirected = tmp_path / "attacker" / "gateway-paid-media-requests.db"

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=redirected,
            dependencies=dependencies,
        )

    assert not root_path.exists()
    assert not redirected.exists()


def test_channel_media_path_cannot_escape_the_fixed_state_root(
    tmp_path: Path,
) -> None:
    _boundary, _state_root, root_path, ledger_path, dependencies = _layout(tmp_path)
    redirected = tmp_path / "attacker" / "channel-media-requests.db"

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            channel_media_ledger_path=redirected,
            dependencies=dependencies,
        )

    assert not root_path.exists()
    assert not redirected.exists()


def test_bound_gateway_loss_is_not_reinterpreted_as_first_install(tmp_path: Path) -> None:
    first, _boundary, _state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    for candidate in (
        ledger_path,
        Path(f"{ledger_path}.rollback-anchor"),
        Path(f"{ledger_path}-wal"),
        Path(f"{ledger_path}-shm"),
        Path(f"{ledger_path}-journal"),
    ):
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    snapshot = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert snapshot.installation_id == first.installation_id
    assert snapshot.component("gateway").bound is True
    assert not ledger_path.exists()


def test_bound_asset_store_loss_is_not_recreated_or_rebound(tmp_path: Path) -> None:
    first, _boundary, state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    asset_path = state_root / "paid-media-assets"
    before = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert before.component("gateway_assets").bound is True
    shutil.rmtree(asset_path)

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    after = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert after == before
    assert after.installation_id == first.installation_id
    assert not asset_path.exists()


def test_bound_channel_media_loss_is_not_recreated_or_rebound(tmp_path: Path) -> None:
    first, _boundary, state_root, root_path, ledger_path, dependencies = _provision(
        tmp_path
    )
    channel_path = state_root / "channel-media-requests.db"
    before = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert before.component("channel_media").bound is True
    for candidate in (
        channel_path,
        Path(f"{channel_path}.rollback-anchor"),
        Path(f"{channel_path}-wal"),
        Path(f"{channel_path}-shm"),
        Path(f"{channel_path}-journal"),
    ):
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass

    with pytest.raises(bootstrap.InstallationBootstrapError):
        bootstrap._provision_authority_at_paths(
            root_path=root_path,
            ledger_path=ledger_path,
            dependencies=dependencies,
        )

    after = InstallationRoot.open(root_path, dependencies=dependencies).snapshot()
    assert after == before
    assert after.installation_id == first.installation_id
    assert not channel_path.exists()


def test_fixed_public_entry_rejects_non_windows_or_non_elevated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap.os, "name", "posix")
    with pytest.raises(bootstrap.InstallationBootstrapError, match="elevated Windows"):
        bootstrap.provision_fixed_authority(elevated_probe=lambda: True)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Known Folder API")
def test_fixed_gateway_path_ignores_inherited_programdata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway import installation_paths
    from gateway import installation_root

    installation_root._windows_program_data.cache_clear()
    expected = installation_paths.default_gateway_ledger_path()
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "redirect"))
    installation_root._windows_program_data.cache_clear()

    actual = installation_paths.default_gateway_ledger_path()
    assert actual == expected
    assert actual.parts[-3:] == (
        "Nachuan",
        "StateRoot",
        "gateway-paid-media-requests.db",
    )
