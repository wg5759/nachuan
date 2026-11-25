from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gateway.installed_service_machine_vault import (
    InstalledServiceMachineSecretStore,
    InstalledServiceMachineSecretStoreConflict,
)
from gateway.installed_nachuan_core_identity import nachuan_core_service_sid
from gateway.installed_service_state_acl import (
    assert_service_state_boundary_acl,
    assert_service_state_file_acl,
    assert_service_state_handle_acl,
    harden_service_state_boundary_acl,
    harden_service_state_file_acl,
)
from gateway.installation_root import installation_principal


def _store(
    path: Path,
    boundary: Path,
    *,
    installation_id: str = "a" * 64,
    installation_principal_value: str | None = None,
    harden=lambda _candidate, _directory: None,
    assert_path=lambda _candidate, _directory: None,
    assert_handle=lambda _descriptor, _directory: None,
) -> InstalledServiceMachineSecretStore:
    return InstalledServiceMachineSecretStore(
        path,
        trusted_boundary=boundary,
        installation_id=installation_id,
        installation_epoch=3,
        installation_principal=(
            installation_principal_value
            if installation_principal_value is not None
            else installation_principal(installation_id, 3)
        ),
        service_sid=nachuan_core_service_sid(),
        harden_state_acl=harden,
        assert_state_acl=assert_path,
        assert_state_handle_acl=assert_handle,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows machine DPAPI service vault")
def test_machine_vault_is_reopenable_secret_free_and_never_overwritten(
    tmp_path: Path,
) -> None:
    boundary = (tmp_path / "ProgramData" / "Nachuan" / "ServiceState").resolve()
    boundary.mkdir(parents=True)
    path = boundary / "installed-service-secrets.json"
    parent = boundary.parent
    service_sid = nachuan_core_service_sid()
    hardened = []
    checked = []

    def harden(candidate: Path, directory: bool) -> None:
        hardened.append((candidate.name, directory))
        if directory:
            harden_service_state_boundary_acl(
                program_data_boundary=parent,
                service_state_boundary=boundary,
                service_sid=service_sid,
            )
        else:
            harden_service_state_file_acl(
                candidate,
                trusted_boundary=boundary,
                service_sid=service_sid,
            )

    def assert_path(candidate: Path, directory: bool) -> None:
        checked.append((candidate.name, directory))
        if directory:
            assert_service_state_boundary_acl(
                program_data_boundary=parent,
                service_state_boundary=boundary,
                service_sid=service_sid,
            )
        else:
            assert_service_state_file_acl(
                candidate,
                trusted_boundary=boundary,
                service_sid=service_sid,
            )

    def assert_handle(descriptor: int, directory: bool) -> None:
        checked.append(("open-handle", directory))
        assert_service_state_handle_acl(
            descriptor,
            directory=directory,
            service_sid=service_sid,
        )

    store = _store(
        path,
        boundary,
        harden=harden,
        assert_path=assert_path,
        assert_handle=assert_handle,
    )

    created = store.initialize()
    before = path.read_bytes()
    reopened = _store(
        path,
        boundary,
        assert_path=assert_path,
        assert_handle=assert_handle,
    ).load()

    assert reopened == created
    assert created.generation == 1
    assert created.service_instance_id
    assert created.pipe_root_key.startswith("sk-service-pipe-")
    assert created.control_key.startswith("sk-service-control-")
    assert created.state_hmac_key.startswith("sk-service-state-")
    assert "sk-service-" not in before.decode("ascii")
    assert created.pipe_root_key not in repr(created)
    assert json.loads(before) == {
        "schema": "nachuan.service-machine-protected-json.v1",
        "protection": "windows-dpapi-local-machine",
        "ciphertext": json.loads(before)["ciphertext"],
    }
    with pytest.raises(InstalledServiceMachineSecretStoreConflict):
        store.initialize()
    assert path.read_bytes() == before
    assert set(hardened) == {
        ("ServiceState", True),
        ("installed-service-secrets.json", False),
    }
    assert set(checked) == {
        ("ServiceState", True),
        ("installed-service-secrets.json", False),
        ("open-handle", False),
    }
    safe = store.safe_status()
    assert safe == {
        "schema": "nachuan.installed-service-machine-vault-status.v1",
        "generation": 1,
        "service_instance_id": created.service_instance_id,
        "service_keys_configured": True,
    }
    assert all(
        name not in before.decode("ascii")
        for name in ("provider", "weixin", "feishu", "codex", "kimi")
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows machine DPAPI service vault")
def test_machine_vault_ciphertext_is_bound_to_installation_and_service(
    tmp_path: Path,
) -> None:
    first_boundary = (tmp_path / "first" / "ServiceState").resolve()
    second_boundary = (tmp_path / "second" / "ServiceState").resolve()
    first_boundary.mkdir(parents=True)
    second_boundary.mkdir(parents=True)
    first_path = first_boundary / "installed-service-secrets.json"
    second_path = second_boundary / "installed-service-secrets.json"
    _store(first_path, first_boundary).initialize()
    second_path.write_bytes(first_path.read_bytes())

    with pytest.raises(Exception, match="service machine vault is invalid"):
        _store(
            second_path,
            second_boundary,
            installation_id="c" * 64,
        ).load()


def test_machine_vault_rejects_a_principal_not_derived_from_its_root() -> None:
    boundary = Path(r"C:\ProgramData\Nachuan\ServiceState")
    path = boundary / "installed-service-secrets.json"
    with pytest.raises(Exception, match="installation principal"):
        _store(
            path,
            boundary,
            installation_id="a" * 64,
            installation_principal_value="b" * 64,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows machine DPAPI service vault")
def test_machine_vault_rejects_a_different_file_opened_after_path_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = (tmp_path / "ProgramData" / "Nachuan" / "ServiceState").resolve()
    boundary.mkdir(parents=True)
    path = boundary / "installed-service-secrets.json"
    store = _store(path, boundary)
    store.initialize()
    decoy = boundary / "decoy.json"
    decoy.write_bytes(path.read_bytes())
    real_open = Path.open

    def swapped_open(candidate: Path, *args, **kwargs):
        selected = decoy if candidate == path else candidate
        return real_open(selected, *args, **kwargs)

    monkeypatch.setattr(Path, "open", swapped_open)
    with pytest.raises(Exception, match="changed during verification"):
        store.load()
