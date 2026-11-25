"""Installer-only publication of one stopped Supervisor authority."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from gateway.installation_root import InstallationRoot, InstallationRootSnapshot
from gateway.installed_channel_config import (
    InstalledChannelSupervisorConfigStore,
)
from gateway.installed_channel_default_paths import InstalledChannelDefaultPaths
from gateway.installed_channel_embedded_trust import (
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_host_anchor import InstalledChannelHostAnchorStore
from gateway.installed_channel_host_enrollment import (
    InstalledChannelHostSignerEnrollmentStore,
)
from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.installed_channel_supervisor_bootstrap import (
    load_default_installed_supervisor_authority,
)
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)


class InstalledChannelInstallerProvisioningError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelInstallerProvisioningResult:
    created: bool
    key_id: str
    config_generation: int
    stop_requested: bool


def provision_installed_channel_supervisor_authority(
    *,
    paths: InstalledChannelDefaultPaths,
    host_signer_store,
    expected_trust_sha256: str,
    engine_port: int,
    feishu_app_id: str,
    feishu_app_secret: str,
    installation_root_open=InstallationRoot.open,
    assert_installer_acl: Callable[[Path, bool], None],
    assert_user_acl: Callable[[Path, bool], None],
    harden_installer_acl: Callable[[Path, bool], None],
    provision_lock_factory: Callable[[], object],
) -> InstalledChannelInstallerProvisioningResult:
    """Publish config, signed anchor and a fail-closed initial Stop latch.

    This function is intentionally not called by the runtime Supervisor.  A
    trusted installer must supply its own installer-ACL policy, kernel lock and
    per-installation non-exportable host signer.  The global release private
    key is deliberately absent from this client-side API.
    """

    if (
        not isinstance(paths, InstalledChannelDefaultPaths)
        or not callable(getattr(host_signer_store, "open_or_create", None))
        or not callable(installation_root_open)
        or not callable(assert_installer_acl)
        or not callable(assert_user_acl)
        or not callable(harden_installer_acl)
        or not callable(provision_lock_factory)
    ):
        raise InstalledChannelInstallerProvisioningError(
            "installer provisioning input is invalid"
        )
    try:
        root = installation_root_open(paths.installation_root)
        snapshot = root.require_active()
    except Exception as exc:
        raise InstalledChannelInstallerProvisioningError(
            "active installation authority is unavailable"
        ) from exc
    if (
        not isinstance(snapshot, InstallationRootSnapshot)
        or snapshot.status != "active"
        or snapshot.lock_kind != "none"
        or snapshot.reanchor_pending
    ):
        raise InstalledChannelInstallerProvisioningError(
            "active installation authority is unavailable"
        )
    try:
        trust = load_installed_channel_embedded_trust(
            paths.embedded_trust,
            expected_sha256=expected_trust_sha256,
        )
        trust.require_verifier()
    except Exception as exc:
        raise InstalledChannelInstallerProvisioningError(
            "embedded release trust policy is unavailable"
        ) from exc
    if (
        snapshot.updater.release_sequence
        < trust.minimum_installer_release_sequence
        or snapshot.updater.keyring_sequence < trust.minimum_keyring_sequence
    ):
        raise InstalledChannelInstallerProvisioningError(
            "installation release floor differs from embedded trust"
        )

    try:
        lock = provision_lock_factory()
        enter = getattr(lock, "__enter__", None)
        exit_lock = getattr(lock, "__exit__", None)
        if not callable(enter) or not callable(exit_lock):
            raise InstalledChannelInstallerProvisioningError(
                "installer provisioning lock is invalid"
            )
        with lock:
            config_store = InstalledChannelSupervisorConfigStore(paths.config)
            key_path = config_store.verification_key_path
            config_exists = paths.config.exists()
            key_exists = key_path.exists()
            enrollment_exists = paths.host_signer_enrollment.exists()
            anchor_exists = paths.installer_anchor.exists()
            control_exists = paths.control.exists()
            if config_exists and not key_exists:
                raise InstalledChannelInstallerProvisioningError(
                    "Supervisor authority file set is incomplete"
                )
            if anchor_exists and not (
                config_exists
                and key_exists
                and control_exists
                and enrollment_exists
            ):
                raise InstalledChannelInstallerProvisioningError(
                    "committed Supervisor authority is incomplete"
                )
            signer = host_signer_store.open_or_create(
                installation_snapshot=snapshot,
                allow_create=not enrollment_exists,
            )
            enrollment_store = InstalledChannelHostSignerEnrollmentStore(
                paths.host_signer_enrollment,
                trusted_boundary=paths.installer_trust_root,
                assert_installer_acl=assert_installer_acl,
            )
            enrollment, enrollment_created = enrollment_store.create_if_absent(
                installation_snapshot=snapshot,
                signer=signer,
                embedded_trust_sha256=trust.document_sha256,
                harden_installer_acl=harden_installer_acl,
            )
            config_created = not config_exists
            if config_created:
                config = config_store.create(
                    engine_port=engine_port,
                    feishu_app_id=feishu_app_id,
                    feishu_app_secret=feishu_app_secret,
                )
            else:
                config = config_store.load()
            if (
                config.engine_port != engine_port
                or config.feishu_app_id != feishu_app_id
                or not hmac.compare_digest(
                    config.feishu_app_secret, feishu_app_secret
                )
            ):
                raise InstalledChannelInstallerProvisioningError(
                    "existing Supervisor configuration differs from request"
                )
            epoch_anchor = InstalledChannelEpochAnchor.from_snapshot(
                snapshot,
                config_generation=config.generation,
            )
            control_store = InstalledChannelSupervisorControlStore(paths.control)
            control_created = not control_exists
            if control_created:
                control = control_store.initialize(
                    anchor=epoch_anchor,
                    stop_requested=True,
                )
            else:
                control = control_store.load(anchor=epoch_anchor)
                if not anchor_exists and not control.stop_requested:
                    raise InstalledChannelInstallerProvisioningError(
                        "uncommitted Supervisor authority is not stopped"
                    )
            anchor_store = InstalledChannelHostAnchorStore(
                paths.installer_anchor,
                trusted_boundary=paths.installer_trust_root,
                user_config_boundary=paths.data_directory,
                assert_installer_acl=assert_installer_acl,
                assert_user_acl=assert_user_acl,
            )
            refreshed_root = installation_root_open(paths.installation_root)
            refreshed_snapshot = refreshed_root.require_active()
            if refreshed_snapshot != snapshot:
                raise InstalledChannelInstallerProvisioningError(
                    "installation authority changed during provisioning"
                )
            _anchor, anchor_created = anchor_store.create_if_absent(
                installation_snapshot=snapshot,
                config_generation=config.generation,
                config_path=config_store.path,
                verification_key_path=config_store.verification_key_path,
                enrollment=enrollment,
                signer=signer,
                harden_installer_acl=harden_installer_acl,
            )
            loaded = load_default_installed_supervisor_authority(
                paths=paths,
                trust=trust,
                installation_root_open=installation_root_open,
                assert_installer_acl=assert_installer_acl,
                assert_user_acl=assert_user_acl,
            )
            control = control_store.load(anchor=loaded.epoch_anchor)
    except InstalledChannelInstallerProvisioningError:
        raise
    except Exception as exc:
        raise InstalledChannelInstallerProvisioningError(
            "Supervisor authority could not be provisioned"
        ) from exc
    return InstalledChannelInstallerProvisioningResult(
        created=(
            enrollment_created
            or config_created
            or anchor_created
            or control_created
        ),
        key_id=enrollment.key_id,
        config_generation=config.generation,
        stop_requested=control.stop_requested,
    )


__all__ = [
    "InstalledChannelInstallerProvisioningError",
    "InstalledChannelInstallerProvisioningResult",
    "provision_installed_channel_supervisor_authority",
]
