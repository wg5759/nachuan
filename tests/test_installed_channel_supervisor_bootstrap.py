from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.installation_root import installation_principal
from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
)
from gateway.installed_channel_config import (
    InstalledChannelSupervisorConfig,
    InstalledChannelSupervisorConfigStore,
)
from gateway.installed_channel_host_anchor import (
    InstalledChannelHostAnchor,
    InstalledChannelHostAnchorStore,
)
from gateway.installed_channel_host_enrollment import (
    InstalledChannelHostSignerEnrollment,
    InstalledChannelHostSignerEnrollmentStore,
)
from gateway.installed_channel_default_paths import (
    LOCAL_APP_DATA,
    PROGRAM_DATA,
    resolve_installed_channel_default_paths,
)
from gateway.installed_channel_embedded_trust import (
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_supervisor import (
    InstalledChannelEpochAnchor,
    InstalledChildLaunch,
)
from gateway.installed_channel_supervisor_bootstrap import (
    InstalledChannelBootstrapError,
    assemble_installed_supervisor_coordinator,
    assemble_default_installed_supervisor_coordinator,
    load_default_installed_supervisor_authority,
    load_installer_bound_supervisor_authority,
)
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelSupervisorStatusStore,
)
from gateway.installed_channel_health_probe import InstalledRoleHealthProof


def _anchor() -> InstalledChannelEpochAnchor:
    installation_id = "e" * 64
    epoch = 3
    return InstalledChannelEpochAnchor(
        installation_id=installation_id,
        installation_epoch=epoch,
        installation_principal=installation_principal(installation_id, epoch),
        config_generation=5,
    )


def _receipt(pid: int) -> InstalledChannelProcessReceipt:
    return InstalledChannelProcessReceipt(
        pid=pid,
        started_utc_ticks=133_000_000_000_000_000 + pid,
        command_line_sha256=f"{pid:064x}",
    )


def _snapshot(anchor: InstalledChannelEpochAnchor) -> InstallationRootSnapshot:
    components = tuple(
        ComponentState(
            component=name,
            identity=f"{index + 20:064x}",
            epoch=anchor.installation_epoch,
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
        installation_id=anchor.installation_id,
        owner_sid_digest="f" * 64,
        epoch=anchor.installation_epoch,
        root_revision=9,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=anchor.installation_principal,
        components=components,
        updater=UpdaterState(
            release_sequence=4,
            keyring_sequence=2,
            artifact_digest="a" * 64,
            state_digest="b" * 64,
        ),
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI bootstrap stores")
def test_bootstrap_assembles_one_ready_coordinator_without_persistent_registration(
    tmp_path,
) -> None:
    anchor = _anchor()
    control_store = InstalledChannelSupervisorControlStore(
        (tmp_path / "installed-channel-supervisor-control.json").resolve()
    )
    control_store.initialize(anchor=anchor)
    status_store = InstalledChannelSupervisorStatusStore(
        (tmp_path / "installed-channel-supervisor-status.json").resolve()
    )
    executable = str(Path(sys.executable).resolve())
    launch = InstalledChildLaunch(
        command=executable,
        args=(),
        cwd=str(tmp_path.resolve()),
        environment={},
    )
    launches = {"engine": launch, "weixin": launch, "feishu": launch}
    managers: list[object] = []

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class Manager:
        def __init__(self) -> None:
            self.next_pid = 8000
            self.processes = {}
            self.closed = 0

        def spawn_suspended(self, role, _launch):
            self.next_pid += 1
            process = Process(self.next_pid)
            self.processes[role] = process
            return process

        def assign_to_job(self, _role, _process):
            return None

        def resume(self, _role, _process):
            return None

        def process_receipt(self, role, process):
            assert self.processes[role] is process
            return _receipt(process.pid)

        def terminate_job(self):
            self.closed += 1

    class Health:
        def __init__(self, manager) -> None:
            self.manager = manager

        def __call__(self, role, process):
            return InstalledRoleHealthProof(
                role=role,
                pid=process.pid,
                state="ready",
                attested=True,
                start_allowed=True,
                ready=True,
                restart_recommended=False,
            )

        def check_runtime(self, _runtime, state):
            return state

    def manager_factory():
        manager = Manager()
        managers.append(manager)
        return manager

    coordinator = assemble_installed_supervisor_coordinator(
        anchor=anchor,
        launches=launches,
        control_store=control_store,
        status_store=status_store,
        process_manager_factory=manager_factory,
        health_adapter_factory=Health,
        supervisor_receipt=_receipt(7999),
        monotonic_clock=lambda: 1.0,
    )

    transition = coordinator.step()

    assert transition.watchdog.action == "started"
    assert transition.status.ready is True
    assert transition.status.status_generation == 1
    assert transition.status.roles["engine"].pid == 8001
    assert len(managers) == 1
    coordinator.close()
    assert managers[0].closed == 1

    control_store.request_stop(anchor=anchor, expected_control_generation=1)
    stopped_coordinator = assemble_installed_supervisor_coordinator(
        anchor=anchor,
        launches=launches,
        control_store=control_store,
        status_store=status_store,
        process_manager_factory=manager_factory,
        health_adapter_factory=Health,
        supervisor_receipt=_receipt(7999),
        monotonic_clock=lambda: 2.0,
    )
    stopped = stopped_coordinator.step()
    assert stopped.watchdog.action == "stopped"
    assert stopped.status.state == "stopped"
    assert stopped.status.status_generation == 2
    assert len(managers) == 1
    stopped_coordinator.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI bootstrap stores")
def test_bootstrap_passes_external_stop_without_constructing_process_manager(
    tmp_path,
) -> None:
    anchor = _anchor()
    control_store = InstalledChannelSupervisorControlStore(
        (tmp_path / "installed-channel-supervisor-control.json").resolve()
    )
    control_store.initialize(anchor=anchor)
    status_store = InstalledChannelSupervisorStatusStore(
        (tmp_path / "installed-channel-supervisor-status.json").resolve()
    )
    executable = str(Path(sys.executable).resolve())
    launch = InstalledChildLaunch(
        command=executable,
        args=(),
        cwd=str(tmp_path.resolve()),
        environment={},
    )
    launches = {"engine": launch, "weixin": launch, "feishu": launch}
    stop_event = threading.Event()
    stop_event.set()

    coordinator = assemble_installed_supervisor_coordinator(
        anchor=anchor,
        launches=launches,
        control_store=control_store,
        status_store=status_store,
        process_manager_factory=lambda: (_ for _ in ()).throw(
            AssertionError("external Stop must prevent process manager creation")
        ),
        health_adapter_factory=lambda _manager: (_ for _ in ()).throw(
            AssertionError("external Stop must prevent health adapter creation")
        ),
        supervisor_receipt=_receipt(7999),
        monotonic_clock=lambda: 1.0,
        external_stop_event=stop_event,
    )

    stopped = coordinator.step()

    assert stopped.watchdog.action == "external_stopped"
    assert stopped.status.state == "stopped"
    assert stopped.status.stop_requested is False


def test_loader_requires_config_generation_to_match_installer_anchor(tmp_path) -> None:
    anchor = _anchor()
    snapshot = _snapshot(anchor)
    config = InstalledChannelSupervisorConfig(
        generation=anchor.config_generation,
        engine_port=18888,
        runtime_key="sk-local-" + "1" * 64,
        approval_key="sk-approval-" + "2" * 64,
        paid_media_key="sk-paid-media-" + "3" * 64,
        weixin_bridge_key="sk-bridge-v2-weixin-" + "4" * 64,
        feishu_bridge_key="sk-bridge-v2-feishu-" + "5" * 64,
        feishu_app_id="cli_test_app",
        feishu_app_secret="test-only-secret",
    )
    config_path = (tmp_path / "installed-channel-supervisor.json").resolve()
    key_path = config_path.with_name(config_path.name + ".verification-key")

    class ConfigStore:
        path = config_path
        verification_key_path = key_path

        def load(self):
            return config

    host_private = ec.generate_private_key(ec.SECP256R1())
    host_public = host_private.public_key()
    host_public_der = host_public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    enrollment = InstalledChannelHostSignerEnrollment(
        installation_id=snapshot.installation_id,
        installation_epoch=snapshot.epoch,
        release_sequence=snapshot.updater.release_sequence,
        keyring_sequence=snapshot.updater.keyring_sequence,
        embedded_trust_sha256="d" * 64,
        key_id=hashlib.sha256(host_public_der).hexdigest(),
        provider="test-software-ksp",
        hardware_backed=False,
        document_sha256="c" * 64,
        public_key_spki_der=host_public_der,
        _key=host_public,
    )
    installer_anchor = InstalledChannelHostAnchor(
        installation_id=anchor.installation_id,
        installation_epoch=anchor.installation_epoch,
        installation_principal=anchor.installation_principal,
        installer_release_sequence=snapshot.updater.release_sequence,
        installer_keyring_sequence=snapshot.updater.keyring_sequence,
        config_generation=config.generation,
        config_ciphertext_sha256="a" * 64,
        verification_key_ciphertext_sha256="b" * 64,
        host_signer_key_id=enrollment.key_id,
        host_enrollment_sha256=enrollment.document_sha256,
    )

    class AnchorStore:
        def load(self, **kwargs):
            assert kwargs["installation_snapshot"] is snapshot
            assert kwargs["config_path"] == config_path
            assert kwargs["verification_key_path"] == key_path
            assert kwargs["enrollment"] is enrollment
            return installer_anchor

    loaded_config, loaded_epoch_anchor = load_installer_bound_supervisor_authority(
        installation_snapshot=snapshot,
        config_store=ConfigStore(),
        installer_anchor_store=AnchorStore(),
        host_enrollment=enrollment,
    )

    assert loaded_config is config
    assert loaded_epoch_anchor == anchor

    installer_anchor = replace(
        installer_anchor, config_generation=config.generation - 1
    )
    with pytest.raises(
        InstalledChannelBootstrapError,
        match="configuration differs from installer anchor",
    ):
        load_installer_bound_supervisor_authority(
            installation_snapshot=snapshot,
            config_store=ConfigStore(),
            installer_anchor_store=AnchorStore(),
            host_enrollment=enrollment,
        )


def test_default_loader_rejects_disabled_trust_before_opening_root(tmp_path) -> None:
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
    frozen_resources = (tmp_path / "_MEI-disabled").resolve()
    (frozen_resources / "config").mkdir(parents=True)
    (frozen_resources / "config" / "installed-channel-supervisor-trust.v1.json").write_bytes(
        b'{"algorithm":"ed25519","enabled":false,'
        b'"minimum_installer_release_sequence":0,"minimum_keyring_sequence":0,'
        b'"public_key_spki_base64":"",'
        b'"schema":"nachuan.installed-channel-supervisor-embedded-trust.v1",'
        b'"signer_key_id":""}\n'
    )
    engine = (installed_resources / "engine" / "engine.exe").resolve()
    engine.write_bytes(b"test-only-engine")
    paths = resolve_installed_channel_default_paths(
        engine_executable=engine,
        frozen_resource_root=frozen_resources,
        known_folder_resolver=lambda name: {
            PROGRAM_DATA: program_data,
            LOCAL_APP_DATA: local_app_data,
        }[name],
    )
    trust = load_installed_channel_embedded_trust(paths.embedded_trust)
    root_calls: list[object] = []

    with pytest.raises(
        InstalledChannelBootstrapError,
        match="production trust root is disabled",
    ):
        load_default_installed_supervisor_authority(
            paths=paths,
            trust=trust,
            installation_root_open=lambda path: root_calls.append(path),
            assert_installer_acl=lambda _path, _directory: None,
            assert_user_acl=lambda _path, _directory: None,
        )
    assert root_calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI default loader")
def test_default_loader_binds_enabled_trust_anchor_and_dpapi_config(tmp_path) -> None:
    program_data = (tmp_path / "ProgramData").resolve()
    local_app_data = (tmp_path / "LocalAppData").resolve()
    state_root = program_data / "Nachuan" / "StateRoot"
    installer_trust_root = program_data / "Nachuan" / "InstallerTrust"
    data_root = local_app_data / "Nachuan" / "data"
    state_root.mkdir(parents=True)
    installer_trust_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    installed_resources = (tmp_path / "installed" / "resources").resolve()
    (installed_resources / "engine").mkdir(parents=True)
    (installed_resources / "store-runtime-profile.v1.json").write_bytes(
        b'{"schema":"test-profile"}'
    )
    frozen_resources = (tmp_path / "_MEI-enabled").resolve()
    (frozen_resources / "config").mkdir(parents=True)
    engine = (installed_resources / "engine" / "engine.exe").resolve()
    engine.write_bytes(b"test-only-engine")

    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer_key_id = hashlib.sha256(public_der).hexdigest()
    trust_document = {
        "algorithm": "ed25519",
        "enabled": True,
        "minimum_installer_release_sequence": 4,
        "minimum_keyring_sequence": 2,
        "public_key_spki_base64": base64.b64encode(public_der).decode("ascii"),
        "schema": "nachuan.installed-channel-supervisor-embedded-trust.v1",
        "signer_key_id": signer_key_id,
    }
    trust_path = (
        frozen_resources
        / "config"
        / "installed-channel-supervisor-trust.v1.json"
    )
    trust_path.write_bytes(
        json.dumps(trust_document, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )
    paths = resolve_installed_channel_default_paths(
        engine_executable=engine,
        frozen_resource_root=frozen_resources,
        known_folder_resolver=lambda name: {
            PROGRAM_DATA: program_data,
            LOCAL_APP_DATA: local_app_data,
        }[name],
    )
    config_store = InstalledChannelSupervisorConfigStore(paths.config)
    config = config_store.create(
        engine_port=18888,
        feishu_app_id="cli_test_app",
        feishu_app_secret="test-only-secret",
    )
    epoch_anchor = InstalledChannelEpochAnchor(
        installation_id="e" * 64,
        installation_epoch=3,
        installation_principal=installation_principal("e" * 64, 3),
        config_generation=config.generation,
    )
    snapshot = _snapshot(epoch_anchor)
    trust = load_installed_channel_embedded_trust(paths.embedded_trust)
    host_private = ec.generate_private_key(ec.SECP256R1())

    class HostSigner:
        algorithm = "ecdsa-p256-sha256"
        provider = "test-software-ksp"
        hardware_backed = False
        public_key_spki_der = host_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = hashlib.sha256(public_key_spki_der).hexdigest()

        @staticmethod
        def sign(payload: bytes) -> bytes:
            return host_private.sign(payload, ec.ECDSA(hashes.SHA256()))

    enrollment, _ = InstalledChannelHostSignerEnrollmentStore(
        paths.host_signer_enrollment,
        trusted_boundary=paths.installer_trust_root,
        assert_installer_acl=lambda _path, _directory: None,
    ).create_if_absent(
        installation_snapshot=snapshot,
        signer=HostSigner(),
        embedded_trust_sha256=trust.document_sha256,
        harden_installer_acl=lambda _path, _directory: None,
    )
    InstalledChannelHostAnchorStore(
        paths.installer_anchor,
        trusted_boundary=paths.installer_trust_root,
        user_config_boundary=paths.data_directory,
        assert_installer_acl=lambda _path, _directory: None,
        assert_user_acl=lambda _path, _directory: None,
    ).create_if_absent(
        installation_snapshot=snapshot,
        config_generation=config.generation,
        config_path=config_store.path,
        verification_key_path=config_store.verification_key_path,
        enrollment=enrollment,
        signer=HostSigner(),
        harden_installer_acl=lambda _path, _directory: None,
    )

    class Root:
        def require_active(self):
            return snapshot

    loaded = load_default_installed_supervisor_authority(
        paths=paths,
        trust=trust,
        installation_root_open=lambda path: Root()
        if path == paths.installation_root
        else None,
        assert_installer_acl=lambda _path, _directory: None,
        assert_user_acl=lambda _path, _directory: None,
    )

    assert loaded.config.generation == 1
    assert loaded.config.engine_port == 18888
    assert loaded.epoch_anchor == epoch_anchor
    assert loaded.installation_snapshot is snapshot

    paths.connections.write_text("{}", encoding="utf-8")
    paths.connections_verification_key.write_text("test-only", encoding="utf-8")
    InstalledChannelSupervisorControlStore(paths.control).initialize(
        anchor=epoch_anchor
    )
    managers: list[object] = []

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class Manager:
        def __init__(self) -> None:
            self.next_pid = 9000
            self.processes = {}
            self.closed = 0

        def spawn_suspended(self, role, _launch):
            self.next_pid += 1
            process = Process(self.next_pid)
            self.processes[role] = process
            return process

        def assign_to_job(self, _role, _process):
            return None

        def resume(self, _role, _process):
            return None

        def process_receipt(self, role, process):
            assert self.processes[role] is process
            return _receipt(process.pid)

        def terminate_job(self):
            self.closed += 1

    class Health:
        def __init__(self, _manager) -> None:
            return None

        def __call__(self, role, process):
            return InstalledRoleHealthProof(
                role=role,
                pid=process.pid,
                state="ready",
                attested=True,
                start_allowed=True,
                ready=True,
                restart_recommended=False,
            )

        def check_runtime(self, _runtime, state):
            return state

    def manager_factory():
        manager = Manager()
        managers.append(manager)
        return manager

    coordinator = assemble_default_installed_supervisor_coordinator(
        paths=paths,
        loaded_authority=loaded,
        engine_boot_token="ab" * 32,
        process_manager_factory=manager_factory,
        health_adapter_factory=Health,
        supervisor_receipt=_receipt(8999),
        monotonic_clock=lambda: 1.0,
    )
    transition = coordinator.step()
    assert transition.status.ready is True
    assert transition.status.roles["engine"].pid == 9001
    assert len(managers) == 1
    coordinator.close()
    assert managers[0].closed == 1
