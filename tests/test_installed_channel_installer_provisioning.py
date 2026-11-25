from __future__ import annotations

import hashlib
import json
import inspect
import os
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)
from gateway.installed_channel_default_paths import (
    LOCAL_APP_DATA,
    PROGRAM_DATA,
    resolve_installed_channel_default_paths,
)
from gateway.installed_channel_embedded_trust import (
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_file_lock import InstalledChannelFileLock
from gateway.installed_channel_installer_provisioning import (
    InstalledChannelInstallerProvisioningError,
    provision_installed_channel_supervisor_authority,
)
from gateway.installed_channel_supervisor_bootstrap import (
    load_default_installed_supervisor_authority,
)
from gateway.installed_channel_supervisor_entrypoint import (
    run_coordinator_loop,
    run_default_installed_supervisor,
)
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelSupervisorStatusStore,
)


def _active_snapshot() -> InstallationRootSnapshot:
    installation_id = "9" * 64
    epoch = 6
    components = tuple(
        ComponentState(
            component=name,
            identity=f"{index + 20:064x}",
            epoch=epoch,
            bound=True,
            sequence_floor=0,
            state_digest=f"{index + 30:064x}",
            recovery_floor=None,
            recovery_state_digest=None,
        )
        for index, name in enumerate(
            ("desktop", "gateway", "gateway_assets", "channel_media")
        )
    )
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="8" * 64,
        epoch=epoch,
        root_revision=12,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=installation_principal(installation_id, epoch),
        components=components,
        updater=UpdaterState(
            release_sequence=7,
            keyring_sequence=3,
            artifact_digest="a" * 64,
            state_digest="b" * 64,
        ),
    )


class _HostSigner:
    algorithm = "ecdsa-p256-sha256"
    provider = "test-software-ksp"
    hardware_backed = False

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_spki_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = hashlib.sha256(self.public_key_spki_der).hexdigest()

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, ec.ECDSA(hashes.SHA256()))


class _HostSignerStore:
    def __init__(self) -> None:
        self.signer = _HostSigner()
        self.opened = False

    def open_or_create(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        allow_create: bool,
    ) -> _HostSigner:
        assert installation_snapshot.status == "active"
        if not self.opened and not allow_create:
            raise RuntimeError("host signer is unavailable")
        self.opened = True
        return self.signer


def _fixture(tmp_path: Path, snapshot: InstallationRootSnapshot):
    program_data = (tmp_path / "ProgramData").resolve()
    local_app_data = (tmp_path / "LocalAppData").resolve()
    (program_data / "Nachuan" / "StateRoot").mkdir(parents=True)
    (program_data / "Nachuan" / "InstallerTrust").mkdir(parents=True)
    (local_app_data / "Nachuan" / "data").mkdir(parents=True)
    installed_resources = (tmp_path / "installed" / "resources").resolve()
    (installed_resources / "engine").mkdir(parents=True)
    (installed_resources / "store-runtime-profile.v1.json").write_bytes(
        b'{"schema":"test-profile"}'
    )
    frozen_resources = (tmp_path / "_MEI-test").resolve()
    (frozen_resources / "config").mkdir(parents=True)
    engine = installed_resources / "engine" / "engine.exe"
    engine.write_bytes(b"test-only-engine")
    host_signer_store = _HostSignerStore()
    trust_path = (
        frozen_resources
        / "config"
        / "installed-channel-supervisor-trust.v1.json"
    )
    trust_path.write_bytes(
        Path("config/installed-channel-supervisor-trust.v1.json").read_bytes()
    )
    paths = resolve_installed_channel_default_paths(
        engine_executable=engine,
        frozen_resource_root=frozen_resources,
        known_folder_resolver=lambda name: {
            PROGRAM_DATA: program_data,
            LOCAL_APP_DATA: local_app_data,
        }[name],
    )

    class Root:
        def require_active(self) -> InstallationRootSnapshot:
            if snapshot.status != "active":
                raise RuntimeError("not active")
            return snapshot

    return paths, host_signer_store, Root, trust_path


def test_client_provisioning_api_has_no_global_release_private_key_parameter() -> None:
    parameters = inspect.signature(
        provision_installed_channel_supervisor_authority
    ).parameters

    assert "host_signer_store" in parameters
    assert "release_authority_store" not in parameters


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI installer authority")
def test_installer_provisions_one_stopped_authority_and_replay_is_byte_stable(
    tmp_path: Path,
) -> None:
    program_data = (tmp_path / "ProgramData").resolve()
    local_app_data = (tmp_path / "LocalAppData").resolve()
    (program_data / "Nachuan" / "StateRoot").mkdir(parents=True)
    (program_data / "Nachuan" / "InstallerTrust").mkdir(parents=True)
    (local_app_data / "Nachuan" / "data").mkdir(parents=True)
    installed_resources = (tmp_path / "installed" / "resources").resolve()
    (installed_resources / "engine").mkdir(parents=True)
    (installed_resources / "store-runtime-profile.v1.json").write_bytes(
        b'{"schema":"test-profile"}'
    )
    frozen_resources = (tmp_path / "_MEI-test").resolve()
    (frozen_resources / "config").mkdir(parents=True)
    engine = (installed_resources / "engine" / "engine.exe").resolve()
    engine.write_bytes(b"test-only-engine")
    host_signer_store = _HostSignerStore()
    trust_path = (
        frozen_resources
        / "config"
        / "installed-channel-supervisor-trust.v1.json"
    )
    trust_path.write_bytes(
        Path("config/installed-channel-supervisor-trust.v1.json").read_bytes()
    )
    paths = resolve_installed_channel_default_paths(
        engine_executable=engine,
        frozen_resource_root=frozen_resources,
        known_folder_resolver=lambda name: {
            PROGRAM_DATA: program_data,
            LOCAL_APP_DATA: local_app_data,
        }[name],
    )
    snapshot = _active_snapshot()

    class Root:
        def require_active(self) -> InstallationRootSnapshot:
            return snapshot

    checked: list[tuple[str, bool]] = []
    hardened: list[tuple[str, bool]] = []
    first = provision_installed_channel_supervisor_authority(
        paths=paths,
        host_signer_store=host_signer_store,
        expected_trust_sha256=hashlib.sha256(trust_path.read_bytes()).hexdigest(),
        engine_port=18888,
        feishu_app_id="cli_test_app",
        feishu_app_secret="test-only-secret",
        installation_root_open=lambda path: Root()
        if path == paths.installation_root
        else None,
        assert_installer_acl=lambda path, directory: checked.append(
            (path.name, directory)
        ),
        assert_user_acl=lambda _path, _directory: None,
        harden_installer_acl=lambda path, directory: hardened.append(
            (path.name, directory)
        ),
        provision_lock_factory=nullcontext,
    )
    before = {
        path.name: path.read_bytes()
        for path in (
            paths.config,
            paths.config.with_name(paths.config.name + ".verification-key"),
            paths.host_signer_enrollment,
            paths.installer_anchor,
            paths.control,
        )
    }
    second = provision_installed_channel_supervisor_authority(
        paths=paths,
        host_signer_store=host_signer_store,
        expected_trust_sha256=hashlib.sha256(trust_path.read_bytes()).hexdigest(),
        engine_port=18888,
        feishu_app_id="cli_test_app",
        feishu_app_secret="test-only-secret",
        installation_root_open=lambda _path: Root(),
        assert_installer_acl=lambda _path, _directory: None,
        assert_user_acl=lambda _path, _directory: None,
        harden_installer_acl=lambda _path, _directory: None,
        provision_lock_factory=nullcontext,
    )

    assert first.created is True
    assert second.created is False
    assert first.key_id == host_signer_store.signer.key_id
    assert first.config_generation == 1
    assert first.stop_requested is True
    assert "test-only-secret" not in repr(first)
    assert {
        path.name: path.read_bytes()
        for path in (
            paths.config,
                paths.config.with_name(paths.config.name + ".verification-key"),
                paths.host_signer_enrollment,
                paths.installer_anchor,
            paths.control,
        )
    } == before
    assert hardened == [
        ("InstallerTrust", True),
        ("installed-channel-supervisor.host-enrollment.json", False),
        ("InstallerTrust", True),
        ("installed-channel-supervisor.anchor.json", False),
    ]
    assert set(checked) == {
        ("InstallerTrust", True),
        ("installed-channel-supervisor.host-enrollment.json", False),
        ("installed-channel-supervisor.anchor.json", False),
    }

    trust = load_installed_channel_embedded_trust(paths.embedded_trust)
    anchor_document = json.loads(paths.installer_anchor.read_text("ascii"))
    assert anchor_document["schema"] == (
        "nachuan.installed-channel-supervisor-host-anchor.v2"
    )
    assert anchor_document["host_signer_key_id"] == first.key_id
    assert first.key_id != trust.signer_key_id
    assert not (tmp_path / "release-authority").exists()
    loaded = load_default_installed_supervisor_authority(
        paths=paths,
        trust=trust,
        installation_root_open=lambda _path: Root(),
        assert_installer_acl=lambda _path, _directory: None,
        assert_user_acl=lambda _path, _directory: None,
    )
    control = InstalledChannelSupervisorControlStore(paths.control).load(
        anchor=loaded.epoch_anchor
    )
    assert control.stop_requested is True

    paths.connections.write_text("{}", encoding="utf-8")
    paths.connections_verification_key.write_text("test-only", encoding="utf-8")
    manager_calls: list[str] = []

    def forbidden_manager():
        manager_calls.append("manager")
        raise AssertionError("Stop must prevent child process manager creation")

    owner_events: list[str] = []

    class OwnerLock:
        def __enter__(self):
            owner_events.append("entered")
            return self

        def __exit__(self, _exc_type, _exc, _tb):
            owner_events.append("exited")

    def locked_loop(coordinator):
        assert owner_events == ["entered"]
        return run_coordinator_loop(coordinator)

    result = run_default_installed_supervisor(
        paths=paths,
        expected_trust_sha256=hashlib.sha256(trust_path.read_bytes()).hexdigest(),
        installation_root_open=lambda _path: Root(),
        assert_installer_acl=lambda _path, _directory: None,
        assert_user_acl=lambda _path, _directory: None,
        process_manager_factory=forbidden_manager,
        health_adapter_factory=lambda _manager: (_ for _ in ()).throw(
            AssertionError("Stop must prevent health adapter creation")
        ),
        supervisor_receipt_factory=lambda: InstalledChannelProcessReceipt(
            pid=7000,
            started_utc_ticks=133_000_000_000_007_000,
            command_line_sha256="7" * 64,
        ),
        owner_lock_factory=OwnerLock,
        engine_boot_token_factory=lambda: "f" * 64,
        loop_runner=locked_loop,
    )
    status = InstalledChannelSupervisorStatusStore(paths.status).load(
        anchor=loaded.epoch_anchor
    )
    assert result == 0
    assert manager_calls == []
    assert owner_events == ["entered", "exited"]
    assert status.state == "stopped"
    assert status.stop_requested is True
    assert status.roles == {}

    owner_path = paths.data_directory / "installed-channel-supervisor.owner.lock"
    with InstalledChannelFileLock(
        owner_path,
        error_type=RuntimeError,
        busy_message="test owner busy",
    ):
        conflict = run_default_installed_supervisor(
            paths=paths,
            expected_trust_sha256=hashlib.sha256(
                trust_path.read_bytes()
            ).hexdigest(),
            installation_root_open=lambda _path: Root(),
            assert_installer_acl=lambda _path, _directory: None,
            assert_user_acl=lambda _path, _directory: None,
            process_manager_factory=forbidden_manager,
            health_adapter_factory=lambda _manager: (_ for _ in ()).throw(
                AssertionError("owner conflict must precede health adapter")
            ),
            supervisor_receipt_factory=lambda: InstalledChannelProcessReceipt(
                pid=7001,
                started_utc_ticks=133_000_000_000_007_001,
                command_line_sha256="8" * 64,
            ),
            engine_boot_token_factory=lambda: "e" * 64,
        )
    assert conflict == 69
    assert manager_calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI installer authority")
def test_provisioning_root_is_rejected_before_any_authority_file_is_created(
    tmp_path: Path,
) -> None:
    active = _active_snapshot()
    components = (
        replace(active.components[0], bound=False, state_digest=None),
        *active.components[1:],
    )
    provisioning = replace(active, status="provisioning", components=components)
    paths, host_signer_store, Root, trust_path = _fixture(tmp_path, provisioning)

    with pytest.raises(
        InstalledChannelInstallerProvisioningError,
        match="active installation authority is unavailable",
    ):
        provision_installed_channel_supervisor_authority(
            paths=paths,
            host_signer_store=host_signer_store,
            expected_trust_sha256=hashlib.sha256(
                trust_path.read_bytes()
            ).hexdigest(),
            engine_port=18888,
            feishu_app_id="cli_test_app",
            feishu_app_secret="test-only-secret",
            installation_root_open=lambda _path: Root(),
            assert_installer_acl=lambda _path, _directory: None,
            assert_user_acl=lambda _path, _directory: None,
            harden_installer_acl=lambda _path, _directory: None,
            provision_lock_factory=nullcontext,
        )

    assert not paths.config.exists()
    assert not paths.config.with_name(
        paths.config.name + ".verification-key"
    ).exists()
    assert not paths.installer_anchor.exists()
    assert not paths.control.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI installer authority")
def test_config_without_verification_key_is_rejected_without_repair(
    tmp_path: Path,
) -> None:
    paths, host_signer_store, Root, trust_path = _fixture(tmp_path, _active_snapshot())
    paths.config.write_bytes(b"torn-config-must-not-be-rewritten")
    before = paths.config.read_bytes()

    with pytest.raises(
        InstalledChannelInstallerProvisioningError,
        match="authority file set is incomplete",
    ):
        provision_installed_channel_supervisor_authority(
            paths=paths,
            host_signer_store=host_signer_store,
            expected_trust_sha256=hashlib.sha256(
                trust_path.read_bytes()
            ).hexdigest(),
            engine_port=18888,
            feishu_app_id="cli_test_app",
            feishu_app_secret="test-only-secret",
            installation_root_open=lambda _path: Root(),
            assert_installer_acl=lambda _path, _directory: None,
            assert_user_acl=lambda _path, _directory: None,
            harden_installer_acl=lambda _path, _directory: None,
            provision_lock_factory=nullcontext,
        )

    assert paths.config.read_bytes() == before
    assert not paths.config.with_name(
        paths.config.name + ".verification-key"
    ).exists()
    assert not paths.installer_anchor.exists()
    assert not paths.control.exists()
