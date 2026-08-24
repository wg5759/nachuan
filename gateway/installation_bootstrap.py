"""Explicit, fail-closed installer bootstrap for Installation Epoch Root.

Normal Gateway/Desktop startup must never import a create-on-missing policy.
The frozen engine exposes this module only through one exact installer command
line.  A completed provisioning attempt is idempotently verified; an existing
partial, corrupt, retired, or mismatched authority is never deleted, repaired,
or replaced.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import os
from pathlib import Path
import shutil
import stat
from typing import Callable

from gateway.asset_installation_control import AssetInstallationControl
from gateway.channel_media_installation_control import (
    ChannelMediaInstallationControl,
)
from gateway.gateway_installation_control import GatewayInstallationControl
from gateway.installation_paths import (
    default_channel_media_ledger_path,
    default_gateway_ledger_path,
    default_paid_media_asset_store_path,
)
from gateway.installation_root import (
    DEFAULT_DEPENDENCIES,
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootSnapshot,
    default_installation_root_path,
)
from gateway.paid_media_asset_store import PaidMediaAssetStoreDependencies


class InstallationBootstrapError(RuntimeError):
    """The elevated installer could not prove a safe authority transition."""


@dataclass(frozen=True, slots=True)
class InstallationBootstrapResult:
    """Non-secret proof returned only to installer tests and process status."""

    installation_id: str
    epoch: int
    root_status: str
    gateway_bound: bool
    desktop_bound: bool
    asset_store_bound: bool
    channel_media_bound: bool


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


def _plain_directory_identity(path: Path) -> tuple[int, int, int]:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_or_symlink(info):
        raise OSError("installer authority path is not a plain directory")
    return int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode)


def _plain_file_exists(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
        raise OSError("installer authority leaf is not a plain file")
    return True


def _checked_children(path: Path) -> frozenset[str]:
    before = _plain_directory_identity(path)
    names: set[str] = set()
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.name in {".", ".."} or not entry.name:
                raise OSError("installer authority directory has an invalid entry")
            names.add(entry.name)
    if _plain_directory_identity(path) != before:
        raise OSError("installer authority directory changed during inspection")
    return frozenset(names)


def _mkdir_one(path: Path) -> bool:
    try:
        os.mkdir(path, 0o700)
        return True
    except FileExistsError:
        _plain_directory_identity(path)
        return False


def _plain_directory_exists(path: Path) -> bool:
    try:
        _plain_directory_identity(path)
    except FileNotFoundError:
        return False
    return True


def _harden_stable_directory(
    path: Path,
    dependencies: InstallationRootDependencies,
) -> None:
    before = _plain_directory_identity(path)
    dependencies.harden_acl(path, True)
    dependencies.assert_acl(path, True)
    if _plain_directory_identity(path) != before:
        raise OSError("installer authority directory changed during ACL hardening")


def _assert_fixed_layout(
    root_path: Path,
    ledger_path: Path,
    asset_store_path: Path,
    channel_media_ledger_path: Path,
    dependencies: InstallationRootDependencies,
) -> tuple[Path, Path]:
    boundary = Path(dependencies.trusted_boundary(root_path))
    state_root = root_path.parent
    if (
        not root_path.is_absolute()
        or not ledger_path.is_absolute()
        or ".." in root_path.parts
        or ".." in ledger_path.parts
        or root_path.name != "installation-root.db"
        or ledger_path.name != "gateway-paid-media-requests.db"
        or asset_store_path.name != "paid-media-assets"
        or channel_media_ledger_path.name != "channel-media-requests.db"
        or state_root.parent != boundary
        or ledger_path.parent != state_root
        or asset_store_path.parent != state_root
        or channel_media_ledger_path.parent != state_root
        or not asset_store_path.is_absolute()
        or ".." in asset_store_path.parts
        or not channel_media_ledger_path.is_absolute()
        or ".." in channel_media_ledger_path.parts
        or boundary.parent == boundary
    ):
        raise OSError("installer authority paths do not match the fixed layout")
    return boundary, state_root


def _prepare_empty_authority_directories(
    root_path: Path,
    ledger_path: Path,
    dependencies: InstallationRootDependencies,
) -> None:
    """Create only the two fixed directories needed by a genuinely fresh root."""

    boundary, state_root = _assert_fixed_layout(
        root_path,
        ledger_path,
        root_path.parent / "paid-media-assets",
        root_path.parent / "channel-media-requests.db",
        dependencies,
    )

    # Never create or rewrite the shared ProgramData (or /var/lib) ancestor.
    _plain_directory_identity(boundary.parent)
    boundary_created = _mkdir_one(boundary)
    if not boundary_created and _checked_children(boundary) - {state_root.name}:
        raise OSError("fresh installer boundary contains unexpected state")
    state_root_exists = _plain_directory_exists(state_root)
    if state_root_exists and _checked_children(state_root):
        # Inspect before ACL mutation.  An unknown pre-existing leaf is not an
        # interrupted empty install and must remain byte-for-byte untouched.
        raise OSError("fresh installer StateRoot is not empty")
    _harden_stable_directory(boundary, dependencies)

    if not state_root_exists:
        _mkdir_one(state_root)
    _harden_stable_directory(state_root, dependencies)
    if _checked_children(state_root):
        raise OSError("fresh installer StateRoot changed before provisioning")


def _result_from_snapshot(
    snapshot: InstallationRootSnapshot,
) -> InstallationBootstrapResult:
    gateway = snapshot.component("gateway")
    desktop = snapshot.component("desktop")
    assets = snapshot.component("gateway_assets")
    channel_media = snapshot.component("channel_media")
    if not gateway.bound or not assets.bound or not channel_media.bound:
        raise InstallationBootstrapError(
            "gateway authorities were not completely bound"
        )
    if snapshot.status == "provisioning":
        if desktop.bound:
            raise InstallationBootstrapError("provisioning root has an invalid bind set")
    elif snapshot.status == "active":
        if not desktop.bound:
            raise InstallationBootstrapError("active root is missing Desktop binding")
    else:
        raise InstallationBootstrapError("installer root is not usable after provisioning")
    return InstallationBootstrapResult(
        installation_id=snapshot.installation_id,
        epoch=snapshot.epoch,
        root_status=snapshot.status,
        gateway_bound=gateway.bound,
        desktop_bound=desktop.bound,
        asset_store_bound=assets.bound,
        channel_media_bound=channel_media.bound,
    )


def _provision_authority_at_paths(
    *,
    root_path: Path,
    ledger_path: Path,
    asset_store_path: Path | None = None,
    channel_media_ledger_path: Path | None = None,
    dependencies: InstallationRootDependencies,
) -> InstallationBootstrapResult:
    """Testable core; production callers use :func:`provision_fixed_authority`."""

    root_path = Path(os.path.abspath(os.fspath(root_path)))
    ledger_path = Path(os.path.abspath(os.fspath(ledger_path)))
    asset_store_path = Path(
        os.path.abspath(
            os.fspath(asset_store_path or (root_path.parent / "paid-media-assets"))
        )
    )
    channel_media_ledger_path = Path(
        os.path.abspath(
            os.fspath(
                channel_media_ledger_path
                or (root_path.parent / "channel-media-requests.db")
            )
        )
    )
    control: GatewayInstallationControl | None = None
    asset_control: AssetInstallationControl | None = None
    channel_media_control: ChannelMediaInstallationControl | None = None
    try:
        _assert_fixed_layout(
            root_path,
            ledger_path,
            asset_store_path,
            channel_media_ledger_path,
            dependencies,
        )
        if _plain_file_exists(root_path):
            # Existing authority is assertion-only.  Upgrades must never repair
            # ACLs, replace bytes, or reinterpret corruption as a first install.
            root = InstallationRoot.open_or_migrate_for_installer(
                root_path,
                dependencies=dependencies,
            )
        else:
            _prepare_empty_authority_directories(
                root_path,
                ledger_path,
                dependencies,
            )
            root = InstallationRoot.provision(root_path, dependencies=dependencies)

        asset_dependencies = PaidMediaAssetStoreDependencies(
            assert_acl=dependencies.assert_acl,
            harden_acl=dependencies.harden_acl,
            disk_free=lambda path: int(shutil.disk_usage(path).free),
        )
        snapshot = root.snapshot()
        component_addition = (
            snapshot.status == "maintenance_locked"
            and snapshot.lock_kind == "component_addition"
        )
        if component_addition:
            # v4 -> v5 preserves the three historical component proofs and
            # locks Root until the new channel authority is present.  The old
            # stores are assertion-only here: never create, repair, rebind, or
            # require their (legitimately non-zero) floors to look pristine.
            control = (
                GatewayInstallationControl.verify_bound_for_component_addition(
                    root,
                    ledger_path,
                )
            )
            asset_control = (
                AssetInstallationControl.verify_bound_for_component_addition(
                    root,
                    asset_store_path,
                    store_dependencies=asset_dependencies,
                )
            )
            channel_media_control = ChannelMediaInstallationControl.provision(
                root,
                channel_media_ledger_path,
            )
            # Channel bind activates Root. The retained writer locks keep both
            # local proofs stable, so the installer can re-read and compare the
            # final Root without invoking runtime recovery/resume machinery.
            final_snapshot = root.snapshot()
            for component_name, state in (
                ("gateway", control.state),
                ("gateway_assets", asset_control.state),
            ):
                component = final_snapshot.component(component_name)
                if (
                    final_snapshot.status != "active"
                    or not component.bound
                    or component.identity != state.database_identity
                    or component.epoch != state.epoch
                    or component.sequence_floor != state.mutation_sequence
                    or component.state_digest != state.state_digest
                    or component.recovery_floor is not None
                    or component.recovery_state_digest is not None
                ):
                    raise InstallationBootstrapError(
                        "migrated retained authority proof changed"
                    )
            if channel_media_control.state.mode != "ready":
                raise InstallationBootstrapError(
                    "migrated channel authority is not ready"
                )
        elif snapshot.status == "provisioning":
            control = GatewayInstallationControl.provision(root, ledger_path)
            asset_control = AssetInstallationControl.provision(
                root,
                asset_store_path,
                store_dependencies=asset_dependencies,
            )
            channel_media_control = ChannelMediaInstallationControl.provision(
                root,
                channel_media_ledger_path,
            )
        elif snapshot.status == "active":
            # An installer/update retry over an already active authority is
            # strictly open-only.  In particular, a valid non-zero ledger
            # floor must never be rejected as a non-pristine provision retry.
            control = GatewayInstallationControl.verify_bound_for_active_installer(
                root,
                ledger_path,
            )
            asset_control = (
                AssetInstallationControl.verify_bound_for_active_installer(
                    root,
                    asset_store_path,
                    store_dependencies=asset_dependencies,
                )
            )
            channel_media_control = (
                ChannelMediaInstallationControl.verify_bound_for_active_installer(
                    root,
                    channel_media_ledger_path,
                )
            )
            if (
                control.state.mode != "provisioned_not_active"
                or control.state.reason_code != "active-installer-proof-verified"
                or asset_control.state.mode != "provisioned_not_active"
                or asset_control.state.reason_code
                != "active-installer-proof-verified"
                or channel_media_control.state.mode != "provisioned_not_active"
                or channel_media_control.state.reason_code
                != "active-installer-proof-verified"
            ):
                raise InstallationBootstrapError(
                    "active installation authority proof is incomplete"
                )
        else:
            raise InstallationBootstrapError(
                "installation root is not accepting installer verification"
            )
        return _result_from_snapshot(root.snapshot())
    except InstallationBootstrapError:
        raise
    except Exception as exc:
        raise InstallationBootstrapError(
            "installation authority provisioning failed closed"
        ) from exc
    finally:
        close_error: BaseException | None = None
        if channel_media_control is not None:
            try:
                channel_media_control.close()
            except BaseException as exc:
                close_error = exc
        if asset_control is not None:
            try:
                asset_control.close()
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        if control is not None:
            try:
                control.close()
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None:
            raise InstallationBootstrapError(
                "installation authority close was not confirmed"
            ) from close_error


def windows_process_is_elevated() -> bool:
    """Use a fixed Win32 API rather than a shell command or inherited marker."""

    if os.name != "nt":
        return False
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.IsUserAnAdmin.argtypes = ()
    shell32.IsUserAnAdmin.restype = ctypes.c_bool
    return bool(shell32.IsUserAnAdmin())


def provision_fixed_authority(
    *,
    elevated_probe: Callable[[], bool] = windows_process_is_elevated,
) -> InstallationBootstrapResult:
    """Provision/verify the one production authority from an elevated installer."""

    if os.name != "nt" or not elevated_probe():
        raise InstallationBootstrapError(
            "installation authority provisioning requires an elevated Windows installer"
        )
    root_path = default_installation_root_path()
    ledger_path = default_gateway_ledger_path()
    asset_store_path = default_paid_media_asset_store_path()
    channel_media_ledger_path = default_channel_media_ledger_path()
    if ledger_path != root_path.parent / "gateway-paid-media-requests.db":
        raise InstallationBootstrapError("fixed gateway authority path is inconsistent")
    if asset_store_path != root_path.parent / "paid-media-assets":
        raise InstallationBootstrapError("fixed paid-media asset path is inconsistent")
    if channel_media_ledger_path != root_path.parent / "channel-media-requests.db":
        raise InstallationBootstrapError(
            "fixed channel-media authority path is inconsistent"
        )
    return _provision_authority_at_paths(
        root_path=root_path,
        ledger_path=ledger_path,
        asset_store_path=asset_store_path,
        channel_media_ledger_path=channel_media_ledger_path,
        dependencies=DEFAULT_DEPENDENCIES,
    )


__all__ = [
    "InstallationBootstrapError",
    "InstallationBootstrapResult",
    "provision_fixed_authority",
]
