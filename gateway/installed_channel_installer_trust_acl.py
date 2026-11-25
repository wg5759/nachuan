"""Exact Windows ACL policy for installer-owned Supervisor trust files."""

from __future__ import annotations

import ctypes
import os
import re
import stat
from pathlib import Path
from ctypes import wintypes

from gateway import secure_store as _secure_store
from gateway.installed_nachuan_core_identity import (
    nachuan_core_service_sid,
    validate_nachuan_core_runtime_token,
    validate_nachuan_core_service_sid,
)


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_SID = re.compile(r"^S-1-(?:[0-9]+-){1,14}[0-9]+$", re.IGNORECASE)
_FULL_ACCESS = 0x001F01FF
_GENERIC_READ_MAPPED = 0x00120089
_GENERIC_READ_EXECUTE_MAPPED = 0x001200A9
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_ACCESS_ALLOWED_ACE_TYPE = 0x00
_SE_DACL_PROTECTED = 0x1000


class InstalledChannelInstallerTrustAclError(PermissionError):
    pass


def assert_installed_runtime_principal() -> str:
    """Return the service SID only for the exact NachuanCore service token."""

    if os.name != "nt":
        raise InstalledChannelInstallerTrustAclError(
            "installed runtime principal is only available on Windows"
        )
    token_user_sid = _secure_store._current_user_sid()  # type: ignore[attr-defined]
    service_sid = nachuan_core_service_sid()
    advapi32, kernel32 = _secure_store._windows_security_api()  # type: ignore[attr-defined]
    advapi32.ConvertStringSidToSidW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    )
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.CheckTokenMembership.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.CheckTokenMembership.restype = wintypes.BOOL
    kernel32.GetCurrentProcessId.argtypes = ()
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    kernel32.ProcessIdToSessionId.argtypes = (
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL

    def is_member(sid: str) -> bool:
        converted = wintypes.LPVOID()
        if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(converted)):
            raise InstalledChannelInstallerTrustAclError(
                "installed runtime principal could not be verified"
            ) from ctypes.WinError(ctypes.get_last_error())
        try:
            member = wintypes.BOOL()
            if not advapi32.CheckTokenMembership(
                None, converted, ctypes.byref(member)
            ):
                raise InstalledChannelInstallerTrustAclError(
                    "installed runtime token could not be verified"
                ) from ctypes.WinError(ctypes.get_last_error())
            return bool(member.value)
        finally:
            kernel32.LocalFree(converted)

    session_id = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(
        kernel32.GetCurrentProcessId(), ctypes.byref(session_id)
    ):
        raise InstalledChannelInstallerTrustAclError(
            "installed runtime session could not be verified"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        return validate_nachuan_core_runtime_token(
            token_user_sid=token_user_sid,
            service_sid_member=is_member(service_sid),
            administrator_member=is_member(_ADMINISTRATORS_SID),
            session_id=int(session_id.value),
        )
    except ValueError as exc:
        raise InstalledChannelInstallerTrustAclError(
            "installed runtime must use the dedicated NachuanCore service token"
        ) from exc


def _runtime_sid(value: object) -> str:
    sid = str(value or "").upper()
    if _SID.fullmatch(sid) is None:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust runtime SID is invalid"
        )
    try:
        return validate_nachuan_core_service_sid(sid)
    except ValueError as exc:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust runtime SID is invalid"
        ) from exc


def _plain(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL target is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    ):
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL target is invalid"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _set_sddl(path: Path, sddl: str, *, directory: bool) -> None:
    if os.name != "nt":
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL is only available on Windows"
        )
    before = _plain(path, directory=directory)
    advapi32, kernel32 = _secure_store._windows_security_api()  # type: ignore[attr-defined]
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    ):
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL policy could not be constructed"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        information = (
            _secure_store._OWNER_SECURITY_INFORMATION  # type: ignore[attr-defined]
            | _secure_store._DACL_SECURITY_INFORMATION  # type: ignore[attr-defined]
            | _secure_store._PROTECTED_DACL_SECURITY_INFORMATION  # type: ignore[attr-defined]
        )
        if not advapi32.SetFileSecurityW(str(path), information, descriptor):
            raise InstalledChannelInstallerTrustAclError(
                "InstallerTrust ACL could not be applied"
            ) from ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)
    if _plain(path, directory=directory) != before:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL target changed during hardening"
        )


def _expected_entries(
    *, runtime_sid: str | None, directory: bool
) -> dict[str, tuple[int, int, int]]:
    flags = (
        _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if directory else 0
    )
    expected = {
        _SYSTEM_SID: (_ACCESS_ALLOWED_ACE_TYPE, flags, _FULL_ACCESS),
        _ADMINISTRATORS_SID: (
            _ACCESS_ALLOWED_ACE_TYPE,
            flags,
            _FULL_ACCESS,
        ),
    }
    if runtime_sid is not None:
        expected[runtime_sid] = (
            _ACCESS_ALLOWED_ACE_TYPE,
            flags,
            (
                _GENERIC_READ_EXECUTE_MAPPED
                if directory
                else _GENERIC_READ_MAPPED
            ),
        )
    return expected


def _assert_exact(
    path: Path,
    *,
    directory: bool,
    runtime_sid: str | None,
) -> None:
    before = _plain(path, directory=directory)
    try:
        owner, control, entries = _secure_store._read_windows_security_state(  # type: ignore[attr-defined]
            path
        )
    except Exception as exc:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL could not be read"
        ) from exc
    if _plain(path, directory=directory) != before:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL target changed during verification"
        )
    expected = _expected_entries(runtime_sid=runtime_sid, directory=directory)
    actual = {
        trustee.upper(): (int(ace_type), int(flags), int(mask))
        for ace_type, flags, mask, trustee in entries
    }
    if (
        owner.upper() != _ADMINISTRATORS_SID
        or not int(control) & _SE_DACL_PROTECTED
        or len(actual) != len(entries)
        or actual != expected
    ):
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust ACL differs from policy"
        )


def harden_installer_trust_boundary_acl(
    *,
    program_data_boundary: str | Path,
    installer_trust_boundary: str | Path,
    runtime_sid: str,
) -> None:
    parent = Path(os.path.abspath(os.fspath(program_data_boundary)))
    boundary = Path(os.path.abspath(os.fspath(installer_trust_boundary)))
    sid = _runtime_sid(runtime_sid)
    if (
        not Path(program_data_boundary).is_absolute()
        or not Path(installer_trust_boundary).is_absolute()
        or boundary.parent != parent
        or parent.name.casefold() != "nachuan"
        or boundary.name.casefold() != "installertrust"
    ):
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust boundary is invalid"
        )
    sddl = (
        "O:BAD:P"
        "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        f"(A;OICI;GRGX;;;{sid})"
    )
    _set_sddl(parent, sddl, directory=True)
    _set_sddl(boundary, sddl, directory=True)
    assert_installer_trust_boundary_acl(
        program_data_boundary=parent,
        installer_trust_boundary=boundary,
        runtime_sid=sid,
    )


def assert_installer_trust_boundary_acl(
    *,
    program_data_boundary: str | Path,
    installer_trust_boundary: str | Path,
    runtime_sid: str,
) -> None:
    parent = Path(os.path.abspath(os.fspath(program_data_boundary)))
    boundary = Path(os.path.abspath(os.fspath(installer_trust_boundary)))
    sid = _runtime_sid(runtime_sid)
    if boundary.parent != parent:
        raise InstalledChannelInstallerTrustAclError(
            "InstallerTrust boundary is invalid"
        )
    _assert_exact(parent, directory=True, runtime_sid=sid)
    _assert_exact(boundary, directory=True, runtime_sid=sid)


def harden_installer_trust_public_file_acl(
    path: str | Path, *, runtime_sid: str
) -> None:
    target = Path(os.path.abspath(os.fspath(path)))
    sid = _runtime_sid(runtime_sid)
    _set_sddl(
        target,
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" f"(A;;GR;;;{sid})",
        directory=False,
    )
    assert_installer_trust_public_file_acl(target, runtime_sid=sid)


def assert_installer_trust_public_file_acl(
    path: str | Path, *, runtime_sid: str
) -> None:
    _assert_exact(
        Path(os.path.abspath(os.fspath(path))),
        directory=False,
        runtime_sid=_runtime_sid(runtime_sid),
    )


def harden_installer_trust_private_file_acl(path: str | Path) -> None:
    target = Path(os.path.abspath(os.fspath(path)))
    _set_sddl(
        target,
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        directory=False,
    )
    assert_installer_trust_private_file_acl(target)


def assert_installer_trust_private_file_acl(path: str | Path) -> None:
    _assert_exact(
        Path(os.path.abspath(os.fspath(path))),
        directory=False,
        runtime_sid=None,
    )


__all__ = [
    "InstalledChannelInstallerTrustAclError",
    "assert_installed_runtime_principal",
    "assert_installer_trust_boundary_acl",
    "assert_installer_trust_private_file_acl",
    "assert_installer_trust_public_file_acl",
    "harden_installer_trust_boundary_acl",
    "harden_installer_trust_private_file_acl",
    "harden_installer_trust_public_file_acl",
]
