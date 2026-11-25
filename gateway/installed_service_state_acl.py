"""Exact ACL policy for NachuanCore service-writable ProgramData state."""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path
from ctypes import wintypes

from gateway import secure_store as _secure_store
from gateway.installed_nachuan_core_identity import (
    validate_nachuan_core_service_sid,
)


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_FULL_ACCESS = 0x001F01FF
_MODIFY_ACCESS = 0x001301BF
_READ_EXECUTE = 0x001200A9
_ALLOW = 0
_OI_CI = 3
_DACL_PROTECTED = 0x1000


class InstalledServiceStateAclError(PermissionError):
    pass


def _service_sid(value: object) -> str:
    try:
        return validate_nachuan_core_service_sid(value)
    except ValueError as exc:
        raise InstalledServiceStateAclError(
            "ServiceState service SID is invalid"
        ) from exc


def _boundaries(
    program_data_boundary: str | Path,
    service_state_boundary: str | Path,
) -> tuple[Path, Path]:
    parent = Path(os.path.abspath(os.fspath(program_data_boundary)))
    boundary = Path(os.path.abspath(os.fspath(service_state_boundary)))
    if (
        not Path(program_data_boundary).is_absolute()
        or not Path(service_state_boundary).is_absolute()
        or parent.name.casefold() != "nachuan"
        or boundary.parent != parent
        or boundary.name.casefold() != "servicestate"
    ):
        raise InstalledServiceStateAclError("ServiceState boundary is invalid")
    return parent, boundary


def _file_target(
    path: str | Path, trusted_boundary: str | Path
) -> tuple[Path, Path]:
    target = Path(os.path.abspath(os.fspath(path)))
    boundary = Path(os.path.abspath(os.fspath(trusted_boundary)))
    if (
        not Path(path).is_absolute()
        or not Path(trusted_boundary).is_absolute()
        or boundary.name.casefold() != "servicestate"
        or boundary.parent.name.casefold() != "nachuan"
        or target.parent != boundary
    ):
        raise InstalledServiceStateAclError("ServiceState file target is invalid")
    _plain(boundary, directory=True)
    return target, boundary


def _plain(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise InstalledServiceStateAclError(
            "ServiceState ACL target is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    ):
        raise InstalledServiceStateAclError(
            "ServiceState ACL target is invalid"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _set(path: Path, *, directory: bool, service_sid: str, parent: bool) -> None:
    before = _plain(path, directory=directory)
    advapi32, kernel32 = _secure_store._windows_security_api()  # type: ignore[attr-defined]
    rights = "GRGX" if parent else "0x1301bf"
    flags = "OICI" if directory else ""
    sddl = (
        "O:BAD:P"
        f"(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
        f"(A;{flags};{rights};;;{service_sid})"
    )
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise InstalledServiceStateAclError(
            "ServiceState ACL could not be constructed"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        information = (
            _secure_store._OWNER_SECURITY_INFORMATION  # type: ignore[attr-defined]
            | _secure_store._DACL_SECURITY_INFORMATION  # type: ignore[attr-defined]
            | _secure_store._PROTECTED_DACL_SECURITY_INFORMATION  # type: ignore[attr-defined]
        )
        if not advapi32.SetFileSecurityW(str(path), information, descriptor):
            raise InstalledServiceStateAclError(
                "ServiceState ACL could not be applied"
            ) from ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)
    if _plain(path, directory=directory) != before:
        raise InstalledServiceStateAclError(
            "ServiceState ACL target changed during hardening"
        )


def _expected(
    *, directory: bool, service_sid: str, parent: bool
) -> dict[str, tuple[int, int, int]]:
    flags = _OI_CI if directory else 0
    return {
        _SYSTEM_SID: (_ALLOW, flags, _FULL_ACCESS),
        _ADMINISTRATORS_SID: (_ALLOW, flags, _FULL_ACCESS),
        service_sid: (
            _ALLOW,
            flags,
            _READ_EXECUTE if parent else _MODIFY_ACCESS,
        ),
    }


def _compare(
    owner: str,
    control: int,
    entries,
    *,
    directory: bool,
    service_sid: str,
    parent: bool,
) -> None:
    actual = {
        str(trustee).upper(): (int(ace_type), int(flags), int(mask))
        for ace_type, flags, mask, trustee in entries
    }
    if (
        owner.upper() != _ADMINISTRATORS_SID
        or not int(control) & _DACL_PROTECTED
        or len(actual) != len(entries)
        or actual
        != _expected(
            directory=directory,
            service_sid=service_sid,
            parent=parent,
        )
    ):
        raise InstalledServiceStateAclError(
            "ServiceState ACL differs from policy"
        )


def _assert_path(
    path: Path,
    *,
    directory: bool,
    service_sid: str,
    parent: bool,
) -> None:
    before = _plain(path, directory=directory)
    try:
        owner, control, entries = _secure_store._read_windows_security_state(  # type: ignore[attr-defined]
            path
        )
    except Exception as exc:
        raise InstalledServiceStateAclError(
            "ServiceState ACL could not be read"
        ) from exc
    if _plain(path, directory=directory) != before:
        raise InstalledServiceStateAclError(
            "ServiceState ACL target changed during verification"
        )
    _compare(
        owner,
        control,
        entries,
        directory=directory,
        service_sid=service_sid,
        parent=parent,
    )


def harden_service_state_boundary_acl(
    *,
    program_data_boundary: str | Path,
    service_state_boundary: str | Path,
    service_sid: str,
) -> None:
    parent, boundary = _boundaries(
        program_data_boundary, service_state_boundary
    )
    sid = _service_sid(service_sid)
    _set(parent, directory=True, service_sid=sid, parent=True)
    _set(boundary, directory=True, service_sid=sid, parent=False)
    assert_service_state_boundary_acl(
        program_data_boundary=parent,
        service_state_boundary=boundary,
        service_sid=sid,
    )


def assert_service_state_boundary_acl(
    *,
    program_data_boundary: str | Path,
    service_state_boundary: str | Path,
    service_sid: str,
) -> None:
    parent, boundary = _boundaries(
        program_data_boundary, service_state_boundary
    )
    sid = _service_sid(service_sid)
    _assert_path(parent, directory=True, service_sid=sid, parent=True)
    _assert_path(boundary, directory=True, service_sid=sid, parent=False)


def harden_service_state_file_acl(
    path: str | Path,
    *,
    trusted_boundary: str | Path,
    service_sid: str,
) -> None:
    target, boundary = _file_target(path, trusted_boundary)
    sid = _service_sid(service_sid)
    _set(target, directory=False, service_sid=sid, parent=False)
    assert_service_state_file_acl(
        target,
        trusted_boundary=boundary,
        service_sid=sid,
    )


def assert_service_state_file_acl(
    path: str | Path,
    *,
    trusted_boundary: str | Path,
    service_sid: str,
) -> None:
    target, _boundary = _file_target(path, trusted_boundary)
    _assert_path(
        target,
        directory=False,
        service_sid=_service_sid(service_sid),
        parent=False,
    )


def assert_service_state_handle_acl(
    descriptor: int,
    *,
    directory: bool,
    service_sid: str,
) -> None:
    sid = _service_sid(service_sid)
    try:
        native, actual_directory = _secure_store._native_handle_from_descriptor(  # type: ignore[attr-defined]
            descriptor,
            directory=directory,
        )
        owner, control, entries = _secure_store._read_windows_handle_security_state(  # type: ignore[attr-defined]
            native
        )
    except Exception as exc:
        raise InstalledServiceStateAclError(
            "ServiceState handle ACL could not be read"
        ) from exc
    _compare(
        owner,
        control,
        entries,
        directory=actual_directory,
        service_sid=sid,
        parent=False,
    )


__all__ = [
    "InstalledServiceStateAclError",
    "assert_service_state_boundary_acl",
    "assert_service_state_file_acl",
    "assert_service_state_handle_acl",
    "harden_service_state_boundary_acl",
    "harden_service_state_file_acl",
]
