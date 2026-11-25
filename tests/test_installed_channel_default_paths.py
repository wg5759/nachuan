from __future__ import annotations

import os

import pytest

from gateway.installed_channel_default_paths import (
    LOCAL_APP_DATA,
    PROGRAM_DATA,
    resolve_installed_channel_default_paths,
    windows_known_folder,
)


def test_default_paths_ignore_ambient_environment_and_bind_known_folders(
    tmp_path, monkeypatch
) -> None:
    program_data = (tmp_path / "known-program-data").resolve()
    local_app_data = (tmp_path / "known-local-app-data").resolve()
    state_root = program_data / "Nachuan" / "StateRoot"
    installer_trust_root = program_data / "Nachuan" / "InstallerTrust"
    data_root = local_app_data / "Nachuan" / "data"
    frozen_resource_root = (tmp_path / "frozen-resources").resolve()
    installed_resource_root = (tmp_path / "installed" / "resources").resolve()
    state_root.mkdir(parents=True)
    installer_trust_root.mkdir(parents=True)
    data_root.mkdir(parents=True)
    (frozen_resource_root / "config").mkdir(parents=True)
    (installed_resource_root / "engine").mkdir(parents=True)
    profile = installed_resource_root / "store-runtime-profile.v1.json"
    profile.write_text('{"schema":"test-profile"}', encoding="utf-8")
    embedded_trust = (
        frozen_resource_root
        / "config"
        / "installed-channel-supervisor-trust.v1.json"
    )
    embedded_trust.write_text('{"schema":"test-trust"}', encoding="utf-8")
    engine = (installed_resource_root / "engine" / "engine.exe").resolve()
    engine.write_bytes(b"test-only-engine")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "attacker-program-data"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "attacker-local-data"))
    calls: list[str] = []

    def known_folder(name: str):
        calls.append(name)
        return {PROGRAM_DATA: program_data, LOCAL_APP_DATA: local_app_data}[name]

    paths = resolve_installed_channel_default_paths(
        engine_executable=engine,
        frozen_resource_root=frozen_resource_root,
        known_folder_resolver=known_folder,
    )

    assert calls == [PROGRAM_DATA, LOCAL_APP_DATA]
    assert paths.installation_root == state_root / "installation-root.db"
    assert paths.installer_trust_root == installer_trust_root
    assert paths.installer_anchor == (
        installer_trust_root / "installed-channel-supervisor.anchor.json"
    )
    assert paths.host_signer_enrollment == (
        installer_trust_root
        / "installed-channel-supervisor.host-enrollment.json"
    )
    assert paths.data_directory == data_root
    assert paths.config == data_root / "installed-channel-supervisor.json"
    assert paths.control == data_root / "installed-channel-supervisor-control.json"
    assert paths.status == data_root / "installed-channel-supervisor-status.json"
    assert paths.connections == data_root / "connections.json"
    assert paths.runtime_profile == profile
    assert paths.embedded_trust == embedded_trust
    assert paths.engine_executable == engine
    assert paths.installed_resource_root == installed_resource_root
    assert paths.frozen_resource_root == frozen_resource_root


@pytest.mark.skipif(os.name != "nt", reason="Windows Known Folder contract")
def test_native_known_folder_resolver_returns_distinct_existing_directories() -> None:
    program_data = windows_known_folder(PROGRAM_DATA)
    local_app_data = windows_known_folder(LOCAL_APP_DATA)

    assert program_data.is_absolute() and program_data.is_dir()
    assert local_app_data.is_absolute() and local_app_data.is_dir()
    assert program_data != local_app_data
