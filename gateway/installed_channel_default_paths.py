"""Known-Folder-only path resolution for the installed channel Supervisor."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PROGRAM_DATA = "program_data"
LOCAL_APP_DATA = "local_app_data"
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledChannelDefaultPathsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelDefaultPaths:
    program_data_boundary: Path
    installation_state_root: Path
    installer_trust_root: Path
    installation_root: Path
    installer_anchor: Path
    host_signer_enrollment: Path
    local_app_data_boundary: Path
    data_directory: Path
    config: Path
    control: Path
    status: Path
    connections: Path
    connections_verification_key: Path
    engine_executable: Path
    installed_resource_root: Path
    frozen_resource_root: Path
    runtime_profile: Path
    runtime_profile_sha256: str
    embedded_trust: Path


def _plain(path: Path, *, directory: bool) -> Path:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise InstalledChannelDefaultPathsError(
            "installed Supervisor path is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    ):
        raise InstalledChannelDefaultPathsError(
            "installed Supervisor path is invalid"
        )
    return path


def windows_known_folder(name: str) -> Path:
    """Resolve one fixed Windows Known Folder without consulting environment."""

    if os.name != "nt" or name not in {PROGRAM_DATA, LOCAL_APP_DATA}:
        raise InstalledChannelDefaultPathsError("Windows Known Folder is invalid")
    import ctypes
    from ctypes import wintypes
    from uuid import UUID

    class GUID(ctypes.Structure):
        _fields_ = (
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        )

    values = {
        PROGRAM_DATA: "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97",
        LOCAL_APP_DATA: "f1b32785-6fba-4fcf-9d55-7b8e7f157091",
    }
    value = UUID(values[name])
    folder_id = GUID(
        value.time_low,
        value.time_mid,
        value.time_hi_version,
        (ctypes.c_ubyte * 8)(*value.bytes[8:]),
    )
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32.SHGetKnownFolderPath.argtypes = (
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    ole32.CoTaskMemFree.restype = None
    raw = ctypes.c_wchar_p()
    result = int(
        shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id),
            0,
            None,
            ctypes.byref(raw),
        )
    )
    try:
        if result != 0 or not raw.value:
            raise InstalledChannelDefaultPathsError(
                "Windows Known Folder is unavailable"
            )
        path = Path(raw.value)
        if not path.is_absolute() or ".." in path.parts:
            raise InstalledChannelDefaultPathsError(
                "Windows Known Folder is invalid"
            )
        return path
    finally:
        if raw:
            ole32.CoTaskMemFree(ctypes.cast(raw, ctypes.c_void_p))


def resolve_installed_channel_default_paths(
    *,
    engine_executable: str | Path,
    frozen_resource_root: str | Path,
    known_folder_resolver: Callable[[str], Path] = windows_known_folder,
) -> InstalledChannelDefaultPaths:
    if not callable(known_folder_resolver):
        raise InstalledChannelDefaultPathsError("Known Folder resolver is invalid")
    engine = Path(os.path.abspath(os.fspath(engine_executable)))
    frozen_resources = Path(os.path.abspath(os.fspath(frozen_resource_root)))
    installed_resources = engine.parent.parent
    if (
        not Path(engine_executable).is_absolute()
        or not Path(frozen_resource_root).is_absolute()
        or engine.name.casefold() != "engine.exe"
        or engine.parent.name.casefold() != "engine"
        or installed_resources.name.casefold() != "resources"
    ):
        raise InstalledChannelDefaultPathsError(
            "installed Supervisor executable path is invalid"
        )
    _plain(engine, directory=False)
    _plain(engine.parent, directory=True)
    _plain(installed_resources, directory=True)
    _plain(frozen_resources, directory=True)
    try:
        program_data = Path(
            os.path.abspath(os.fspath(known_folder_resolver(PROGRAM_DATA)))
        )
        local_app_data = Path(
            os.path.abspath(os.fspath(known_folder_resolver(LOCAL_APP_DATA)))
        )
    except InstalledChannelDefaultPathsError:
        raise
    except Exception as exc:
        raise InstalledChannelDefaultPathsError(
            "Known Folder resolver is unavailable"
        ) from exc
    if not program_data.is_absolute() or not local_app_data.is_absolute():
        raise InstalledChannelDefaultPathsError("Known Folder path is invalid")
    _plain(program_data, directory=True)
    _plain(local_app_data, directory=True)
    program_boundary = _plain(program_data / "Nachuan", directory=True)
    state_root = _plain(program_boundary / "StateRoot", directory=True)
    installer_trust_root = _plain(
        program_boundary / "InstallerTrust", directory=True
    )
    local_boundary = _plain(local_app_data / "Nachuan", directory=True)
    data = _plain(local_boundary / "data", directory=True)
    profile = _plain(
        installed_resources / "store-runtime-profile.v1.json",
        directory=False,
    )
    embedded_trust = _plain(
        frozen_resources
        / "config"
        / "installed-channel-supervisor-trust.v1.json",
        directory=False,
    )
    profile_bytes = profile.read_bytes()
    if not profile_bytes or len(profile_bytes) > 4 * 1024 * 1024:
        raise InstalledChannelDefaultPathsError("runtime profile is invalid")
    config = data / "installed-channel-supervisor.json"
    connections = data / "connections.json"
    return InstalledChannelDefaultPaths(
        program_data_boundary=program_boundary,
        installation_state_root=state_root,
        installer_trust_root=installer_trust_root,
        installation_root=state_root / "installation-root.db",
        installer_anchor=(
            installer_trust_root / "installed-channel-supervisor.anchor.json"
        ),
        host_signer_enrollment=(
            installer_trust_root
            / "installed-channel-supervisor.host-enrollment.json"
        ),
        local_app_data_boundary=local_boundary,
        data_directory=data,
        config=config,
        control=data / "installed-channel-supervisor-control.json",
        status=data / "installed-channel-supervisor-status.json",
        connections=connections,
        connections_verification_key=connections.with_name(
            connections.name + ".verification-key"
        ),
        engine_executable=engine,
        installed_resource_root=installed_resources,
        frozen_resource_root=frozen_resources,
        runtime_profile=profile,
        runtime_profile_sha256=hashlib.sha256(profile_bytes).hexdigest(),
        embedded_trust=embedded_trust,
    )


__all__ = [
    "LOCAL_APP_DATA",
    "PROGRAM_DATA",
    "InstalledChannelDefaultPaths",
    "InstalledChannelDefaultPathsError",
    "resolve_installed_channel_default_paths",
    "windows_known_folder",
]
