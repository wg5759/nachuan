from __future__ import annotations

import os
from pathlib import Path

import pytest

from gateway.installed_nachuan_core_identity import nachuan_core_service_sid
from gateway.installed_service_state_acl import (
    InstalledServiceStateAclError,
    assert_service_state_boundary_acl,
    assert_service_state_file_acl,
    assert_service_state_handle_acl,
    harden_service_state_boundary_acl,
    harden_service_state_file_acl,
)
from gateway.secure_store import harden_restricted_windows_acl


@pytest.mark.skipif(os.name != "nt", reason="Windows service state ACL")
def test_service_state_acl_is_exact_and_handle_verified(tmp_path: Path) -> None:
    service_sid = nachuan_core_service_sid()
    parent = (tmp_path / "Nachuan").resolve()
    boundary = parent / "ServiceState"
    parent.mkdir()
    boundary.mkdir()
    vault = boundary / "installed-service-secrets.json"
    vault.write_bytes(b"test-only")

    harden_service_state_boundary_acl(
        program_data_boundary=parent,
        service_state_boundary=boundary,
        service_sid=service_sid,
    )
    harden_service_state_file_acl(
        vault, trusted_boundary=boundary, service_sid=service_sid
    )
    assert_service_state_boundary_acl(
        program_data_boundary=parent,
        service_state_boundary=boundary,
        service_sid=service_sid,
    )
    assert_service_state_file_acl(
        vault, trusted_boundary=boundary, service_sid=service_sid
    )
    with vault.open("rb") as stream:
        assert_service_state_handle_acl(
            stream.fileno(),
            directory=False,
            service_sid=service_sid,
        )

    harden_restricted_windows_acl(vault, directory=False)
    with pytest.raises(
        InstalledServiceStateAclError,
        match="ServiceState ACL differs from policy",
    ):
        assert_service_state_file_acl(
            vault, trusted_boundary=boundary, service_sid=service_sid
        )
    with pytest.raises(InstalledServiceStateAclError):
        assert_service_state_file_acl(
            vault,
            trusted_boundary=boundary,
            service_sid="S-1-5-32-545",
        )

    outside = (tmp_path / "outside.json").resolve()
    outside.write_bytes(b"outside")
    with pytest.raises(InstalledServiceStateAclError, match="target is invalid"):
        harden_service_state_file_acl(
            outside,
            trusted_boundary=boundary,
            service_sid=service_sid,
        )
