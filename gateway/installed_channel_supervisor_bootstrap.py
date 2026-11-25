"""Pure assembly boundary for one installed Supervisor coordinator."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from gateway.installation_root import InstallationRoot, InstallationRootSnapshot
from gateway.installed_channel_config import (
    InstalledChannelSupervisorConfig,
    InstalledChannelSupervisorConfigStore,
)
from gateway.installed_channel_default_paths import InstalledChannelDefaultPaths
from gateway.installed_channel_embedded_trust import InstalledChannelEmbeddedTrust
from gateway.installed_channel_host_anchor import (
    InstalledChannelHostAnchor,
    InstalledChannelHostAnchorStore,
)
from gateway.installed_channel_host_enrollment import (
    InstalledChannelHostSignerEnrollment,
    InstalledChannelHostSignerEnrollmentStore,
)
from gateway.installed_channel_supervisor import (
    InstalledChannelEpochAnchor,
    InstalledChannelSupervisorRuntime,
    InstalledChildLaunch,
    build_installed_channel_launches_from_config,
)
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)
from gateway.installed_channel_supervisor_coordinator import (
    InstalledChannelSupervisorCoordinator,
)
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelSupervisorStatusStore,
)
from gateway.installed_channel_supervisor_watchdog import (
    InstalledChannelSupervisorWatchdog,
)


class InstalledChannelBootstrapError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelLoadedAuthority:
    installation_snapshot: InstallationRootSnapshot
    config: InstalledChannelSupervisorConfig
    epoch_anchor: InstalledChannelEpochAnchor
    config_store: InstalledChannelSupervisorConfigStore


class _InstalledRuntimeBundle:
    def __init__(self, *, runtime, health_adapter) -> None:
        self._runtime = runtime
        self._health_adapter = health_adapter

    def start(self, *, stop_event=None):
        return self._runtime.start(stop_event=stop_event)

    def close(self) -> None:
        self._runtime.close()

    def force_close(self) -> None:
        return self._runtime.force_close()

    def is_quiescent(self) -> bool:
        return self._runtime.is_quiescent()

    def process_receipts(self):
        return self._runtime.process_receipts()

    def check_health(self, state):
        return self._health_adapter.check_runtime(self, state)


def assemble_default_installed_supervisor_coordinator(
    *,
    paths: InstalledChannelDefaultPaths,
    loaded_authority: InstalledChannelLoadedAuthority,
    engine_boot_token: str,
    process_manager_factory: Callable[[], object],
    health_adapter_factory: Callable[[object], object],
    supervisor_receipt: InstalledChannelProcessReceipt,
    monotonic_clock: Callable[[], float] | None = None,
    external_stop_event=None,
    drain_controller_factory=None,
    source_environment=None,
) -> InstalledChannelSupervisorCoordinator:
    """Assemble the full fixed-path coordinator from one verified authority."""

    if (
        not isinstance(paths, InstalledChannelDefaultPaths)
        or not isinstance(loaded_authority, InstalledChannelLoadedAuthority)
        or not callable(process_manager_factory)
        or not callable(health_adapter_factory)
        or not isinstance(supervisor_receipt, InstalledChannelProcessReceipt)
        or (monotonic_clock is not None and not callable(monotonic_clock))
        or (
            drain_controller_factory is not None
            and not callable(drain_controller_factory)
        )
        or (
            external_stop_event is not None
            and not callable(getattr(external_stop_event, "is_set", None))
        )
        or loaded_authority.config_store.path != paths.config
    ):
        raise InstalledChannelBootstrapError(
            "default Supervisor coordinator input is invalid"
        )
    try:
        loaded_authority.epoch_anchor.validate(
            snapshot=loaded_authority.installation_snapshot,
            config=loaded_authority.config,
        )
        launches = build_installed_channel_launches_from_config(
            config=loaded_authority.config,
            installation_snapshot=loaded_authority.installation_snapshot,
            epoch_anchor=loaded_authority.epoch_anchor,
            engine_executable=paths.engine_executable,
            data_directory=paths.data_directory,
            connections_path=paths.connections,
            engine_boot_token=engine_boot_token,
            runtime_profile_manifest=paths.runtime_profile,
            runtime_profile_sha256=paths.runtime_profile_sha256,
            source_environment=(
                dict(os.environ)
                if source_environment is None
                else source_environment
            ),
        )
        control_store = InstalledChannelSupervisorControlStore(paths.control)
        status_store = InstalledChannelSupervisorStatusStore(paths.status)
    except Exception as exc:
        raise InstalledChannelBootstrapError(
            "default Supervisor coordinator could not be prepared"
        ) from exc
    return assemble_installed_supervisor_coordinator(
        anchor=loaded_authority.epoch_anchor,
        launches=launches,
        control_store=control_store,
        status_store=status_store,
        process_manager_factory=process_manager_factory,
        health_adapter_factory=health_adapter_factory,
        supervisor_receipt=supervisor_receipt,
        monotonic_clock=monotonic_clock,
        external_stop_event=external_stop_event,
        drain_controller_factory=drain_controller_factory,
    )


def load_default_installed_supervisor_authority(
    *,
    paths: InstalledChannelDefaultPaths,
    trust: InstalledChannelEmbeddedTrust,
    installation_root_open=InstallationRoot.open,
    assert_installer_acl,
    assert_user_acl,
) -> InstalledChannelLoadedAuthority:
    """Load fixed installed authorities only after embedded trust is enabled."""

    if (
        not isinstance(paths, InstalledChannelDefaultPaths)
        or not isinstance(trust, InstalledChannelEmbeddedTrust)
        or not callable(installation_root_open)
        or not callable(assert_installer_acl)
        or not callable(assert_user_acl)
    ):
        raise InstalledChannelBootstrapError(
            "default Supervisor loader input is invalid"
        )
    try:
        trust.require_verifier()
    except Exception as exc:
        raise InstalledChannelBootstrapError(
            "production trust root is disabled"
        ) from exc
    try:
        installation_root = installation_root_open(paths.installation_root)
        snapshot = installation_root.require_active()
        config_store = InstalledChannelSupervisorConfigStore(paths.config)
        enrollment_store = InstalledChannelHostSignerEnrollmentStore(
            paths.host_signer_enrollment,
            trusted_boundary=paths.installer_trust_root,
            assert_installer_acl=assert_installer_acl,
        )
        enrollment = enrollment_store.load(
            installation_snapshot=snapshot,
            embedded_trust_sha256=trust.document_sha256,
        )
        anchor_store = InstalledChannelHostAnchorStore(
            paths.installer_anchor,
            trusted_boundary=paths.installer_trust_root,
            user_config_boundary=paths.data_directory,
            assert_installer_acl=assert_installer_acl,
            assert_user_acl=assert_user_acl,
        )
        config, epoch_anchor = load_installer_bound_supervisor_authority(
            installation_snapshot=snapshot,
            config_store=config_store,
            installer_anchor_store=anchor_store,
            host_enrollment=enrollment,
        )
    except Exception as exc:
        raise InstalledChannelBootstrapError(
            "default Supervisor authority is unavailable"
        ) from exc
    return InstalledChannelLoadedAuthority(
        installation_snapshot=snapshot,
        config=config,
        epoch_anchor=epoch_anchor,
        config_store=config_store,
    )


def load_installer_bound_supervisor_authority(
    *,
    installation_snapshot: InstallationRootSnapshot,
    config_store,
    installer_anchor_store,
    host_enrollment: InstalledChannelHostSignerEnrollment | None = None,
) -> tuple[InstalledChannelSupervisorConfig, InstalledChannelEpochAnchor]:
    """Load one config only when its protected bytes match the installer anchor."""

    if (
        not isinstance(installation_snapshot, InstallationRootSnapshot)
        or installation_snapshot.status != "active"
        or installation_snapshot.lock_kind != "none"
        or installation_snapshot.reanchor_pending
        or not callable(getattr(config_store, "load", None))
        or not callable(getattr(installer_anchor_store, "load", None))
        or not isinstance(host_enrollment, InstalledChannelHostSignerEnrollment)
    ):
        raise InstalledChannelBootstrapError(
            "installer-bound Supervisor authority is invalid"
        )
    config_path = getattr(config_store, "path", None)
    verification_key_path = getattr(config_store, "verification_key_path", None)
    try:
        installer_anchor = installer_anchor_store.load(
            installation_snapshot=installation_snapshot,
            config_path=config_path,
            verification_key_path=verification_key_path,
            enrollment=host_enrollment,
        )
        config = config_store.load()
    except Exception as exc:
        raise InstalledChannelBootstrapError(
            "installer-bound Supervisor authority is unavailable"
        ) from exc
    if (
        not isinstance(installer_anchor, InstalledChannelHostAnchor)
        or not isinstance(config, InstalledChannelSupervisorConfig)
        or installer_anchor.installation_id != installation_snapshot.installation_id
        or installer_anchor.installation_epoch != installation_snapshot.epoch
        or installer_anchor.installation_principal
        != installation_snapshot.principal_digest
        or installer_anchor.installer_release_sequence
        != installation_snapshot.updater.release_sequence
        or installer_anchor.installer_keyring_sequence
        != installation_snapshot.updater.keyring_sequence
        or installer_anchor.config_generation != config.generation
    ):
        raise InstalledChannelBootstrapError(
            "configuration differs from installer anchor"
        )
    epoch_anchor = InstalledChannelEpochAnchor.from_snapshot(
        installation_snapshot,
        config_generation=config.generation,
    )
    return config, epoch_anchor


def assemble_installed_supervisor_coordinator(
    *,
    anchor: InstalledChannelEpochAnchor,
    launches: dict[str, InstalledChildLaunch],
    control_store: InstalledChannelSupervisorControlStore,
    status_store: InstalledChannelSupervisorStatusStore,
    process_manager_factory: Callable[[], object],
    health_adapter_factory: Callable[[object], object],
    supervisor_receipt: InstalledChannelProcessReceipt,
    monotonic_clock: Callable[[], float] | None = None,
    external_stop_event=None,
    drain_controller_factory=None,
) -> InstalledChannelSupervisorCoordinator:
    """Assemble already-validated authorities without registering or starting them."""

    if (
        not isinstance(anchor, InstalledChannelEpochAnchor)
        or not isinstance(control_store, InstalledChannelSupervisorControlStore)
        or not isinstance(status_store, InstalledChannelSupervisorStatusStore)
        or not isinstance(supervisor_receipt, InstalledChannelProcessReceipt)
        or not callable(process_manager_factory)
        or not callable(health_adapter_factory)
        or (monotonic_clock is not None and not callable(monotonic_clock))
        or (
            drain_controller_factory is not None
            and not callable(drain_controller_factory)
        )
        or (
            external_stop_event is not None
            and not callable(getattr(external_stop_event, "is_set", None))
        )
        or not isinstance(launches, dict)
        or tuple(launches) != ("engine", "weixin", "feishu")
        or any(not isinstance(value, InstalledChildLaunch) for value in launches.values())
    ):
        raise InstalledChannelBootstrapError("Supervisor bootstrap input is invalid")
    try:
        control_store.load(anchor=anchor)
    except Exception as exc:
        raise InstalledChannelBootstrapError(
            "Supervisor control authority is unavailable"
        ) from exc

    def runtime_factory():
        try:
            manager = process_manager_factory()
            health_adapter = health_adapter_factory(manager)
            if not callable(health_adapter) or not callable(
                getattr(health_adapter, "check_runtime", None)
            ):
                raise InstalledChannelBootstrapError("health adapter is invalid")
            runtime = InstalledChannelSupervisorRuntime(
                launches=launches,
                process_manager=manager,
                health_probe=health_adapter,
                drain_controller_factory=drain_controller_factory,
            )
            return _InstalledRuntimeBundle(
                runtime=runtime,
                health_adapter=health_adapter,
            )
        except InstalledChannelBootstrapError:
            raise
        except Exception as exc:
            raise InstalledChannelBootstrapError(
                "Supervisor runtime could not be assembled"
            ) from exc

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=runtime_factory,
        control_loader=lambda: control_store.load(anchor=anchor),
        health_check=lambda runtime, state: runtime.check_health(state),
        monotonic_clock=monotonic_clock,
        external_stop_event=external_stop_event,
    )
    return InstalledChannelSupervisorCoordinator(
        anchor=anchor,
        watchdog=watchdog,
        status_store=status_store,
        supervisor_receipt=supervisor_receipt,
    )


__all__ = [
    "InstalledChannelBootstrapError",
    "InstalledChannelLoadedAuthority",
    "assemble_installed_supervisor_coordinator",
    "assemble_default_installed_supervisor_coordinator",
    "load_default_installed_supervisor_authority",
    "load_installer_bound_supervisor_authority",
]
