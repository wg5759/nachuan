from __future__ import annotations

import os
import ctypes
from pathlib import Path

import pytest

from gateway.installed_channel_installer_trust_acl import (
    InstalledChannelInstallerTrustAclError,
    assert_installed_runtime_principal,
    assert_installer_trust_boundary_acl,
    assert_installer_trust_private_file_acl,
    assert_installer_trust_public_file_acl,
    harden_installer_trust_boundary_acl,
    harden_installer_trust_private_file_acl,
    harden_installer_trust_public_file_acl,
)
from gateway.secure_store import harden_restricted_windows_acl
from gateway.installed_nachuan_core_identity import nachuan_core_service_sid
from gateway.installed_channel_provision_lock import (
    InstalledChannelProvisionBusy,
    InstalledChannelProvisionLock,
)


@pytest.mark.skipif(
    os.name != "nt" or not bool(ctypes.windll.shell32.IsUserAnAdmin()),
    reason="elevated Windows runtime rejection",
)
def test_elevated_administrator_cannot_be_the_runtime_owner() -> None:
    with pytest.raises(
        InstalledChannelInstallerTrustAclError,
        match="must use the dedicated NachuanCore service token",
    ):
        assert_installed_runtime_principal()


@pytest.mark.skipif(os.name != "nt", reason="Windows InstallerTrust ACL")
def test_installer_trust_acl_is_admin_write_runtime_read_and_exact(
    tmp_path: Path,
) -> None:
    runtime_sid = nachuan_core_service_sid()
    parent = (tmp_path / "Nachuan").resolve()
    boundary = parent / "InstallerTrust"
    parent.mkdir()
    boundary.mkdir()
    enrollment = boundary / "installed-channel-supervisor.host-enrollment.json"
    anchor = boundary / "installed-channel-supervisor.anchor.json"
    provision_lock = boundary / "installed-channel-supervisor.provision.lock"
    for path in (enrollment, anchor, provision_lock):
        path.write_bytes(b"test-only")

    harden_installer_trust_boundary_acl(
        program_data_boundary=parent,
        installer_trust_boundary=boundary,
        runtime_sid=runtime_sid,
    )
    harden_installer_trust_public_file_acl(enrollment, runtime_sid=runtime_sid)
    harden_installer_trust_public_file_acl(anchor, runtime_sid=runtime_sid)
    harden_installer_trust_private_file_acl(provision_lock)

    assert_installer_trust_boundary_acl(
        program_data_boundary=parent,
        installer_trust_boundary=boundary,
        runtime_sid=runtime_sid,
    )
    assert_installer_trust_public_file_acl(enrollment, runtime_sid=runtime_sid)
    assert_installer_trust_public_file_acl(anchor, runtime_sid=runtime_sid)
    assert_installer_trust_private_file_acl(provision_lock)

    harden_restricted_windows_acl(anchor, directory=False)
    with pytest.raises(
        InstalledChannelInstallerTrustAclError,
        match="InstallerTrust ACL differs from policy",
    ):
        assert_installer_trust_public_file_acl(anchor, runtime_sid=runtime_sid)


@pytest.mark.skipif(os.name != "nt", reason="Windows InstallerTrust lock")
def test_provision_lock_is_kernel_exclusive_and_never_creates_its_boundary(
    tmp_path: Path,
) -> None:
    runtime_sid = nachuan_core_service_sid()
    parent = (tmp_path / "Nachuan").resolve()
    boundary = parent / "InstallerTrust"
    parent.mkdir()
    boundary.mkdir()
    harden_installer_trust_boundary_acl(
        program_data_boundary=parent,
        installer_trust_boundary=boundary,
        runtime_sid=runtime_sid,
    )
    path = boundary / "installed-channel-supervisor.provision.lock"

    def make_lock() -> InstalledChannelProvisionLock:
        return InstalledChannelProvisionLock(
            path,
            trusted_boundary=boundary,
            assert_boundary_acl=lambda: assert_installer_trust_boundary_acl(
                program_data_boundary=parent,
                installer_trust_boundary=boundary,
                runtime_sid=runtime_sid,
            ),
            harden_lock_acl=harden_installer_trust_private_file_acl,
            assert_lock_acl=assert_installer_trust_private_file_acl,
        )

    first = make_lock()
    second = make_lock()
    with first:
        with pytest.raises(InstalledChannelProvisionBusy):
            with second:
                raise AssertionError("second provisioner must not enter")
    with second:
        assert path.is_file()
        assert_installer_trust_private_file_acl(path)

    missing = tmp_path / "missing" / "installed-channel-supervisor.provision.lock"
    with pytest.raises(FileNotFoundError):
        with InstalledChannelProvisionLock(
            missing,
            trusted_boundary=missing.parent,
            assert_boundary_acl=lambda: None,
            harden_lock_acl=lambda _path: None,
            assert_lock_acl=lambda _path: None,
        ):
            raise AssertionError("missing boundary must fail before entry")
    assert not missing.parent.exists()
