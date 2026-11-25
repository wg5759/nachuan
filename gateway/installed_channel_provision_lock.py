"""Kernel-exclusive lock for installer-owned Supervisor provisioning."""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path
from typing import Callable
from ctypes import wintypes


_FILENAME = "installed-channel-supervisor.provision.lock"
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_ERROR_SHARING_VIOLATION = 32
_ERROR_LOCK_VIOLATION = 33
_ERROR_ALREADY_EXISTS = 183
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9


class InstalledChannelProvisionLockError(RuntimeError):
    pass


class InstalledChannelProvisionBusy(InstalledChannelProvisionLockError):
    pass


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    )


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL


def _ordinary_boundary(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise InstalledChannelProvisionLockError(
            "provision lock boundary is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise InstalledChannelProvisionLockError(
            "provision lock boundary is invalid"
        )


class InstalledChannelProvisionLock:
    def __init__(
        self,
        path: str | Path,
        *,
        trusted_boundary: str | Path,
        assert_boundary_acl: Callable[[], None],
        harden_lock_acl: Callable[[Path], None],
        assert_lock_acl: Callable[[Path], None],
    ) -> None:
        target = Path(os.path.abspath(os.fspath(path)))
        boundary = Path(os.path.abspath(os.fspath(trusted_boundary)))
        if (
            os.name != "nt"
            or not Path(path).is_absolute()
            or not Path(trusted_boundary).is_absolute()
            or target.parent != boundary
            or target.name.casefold() != _FILENAME
            or not callable(assert_boundary_acl)
            or not callable(harden_lock_acl)
            or not callable(assert_lock_acl)
        ):
            raise InstalledChannelProvisionLockError(
                "provision lock location is invalid"
            )
        self.path = target
        self.boundary = boundary
        self._assert_boundary_acl = assert_boundary_acl
        self._harden_lock_acl = harden_lock_acl
        self._assert_lock_acl = assert_lock_acl
        self._handle: int | None = None

    def __enter__(self):
        if self._handle is not None:
            raise InstalledChannelProvisionLockError(
                "provision lock is already held"
            )
        _ordinary_boundary(self.boundary)
        self._assert_boundary_acl()
        ctypes.set_last_error(0)
        raw = _kernel32.CreateFileW(
            str(self.path),
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _WRITE_DAC,
            0,
            None,
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL
            | _FILE_FLAG_WRITE_THROUGH
            | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        handle = int(raw or 0)
        error = ctypes.get_last_error()
        if not handle or handle == int(_INVALID_HANDLE or -1):
            if error in {_ERROR_SHARING_VIOLATION, _ERROR_LOCK_VIOLATION}:
                raise InstalledChannelProvisionBusy(
                    "Supervisor provisioning is already active"
                )
            raise InstalledChannelProvisionLockError(
                "provision lock could not be opened"
            ) from ctypes.WinError(error)
        try:
            info = _FileAttributeTagInfo()
            if not _kernel32.GetFileInformationByHandleEx(
                wintypes.HANDLE(handle),
                _FILE_ATTRIBUTE_TAG_INFO_CLASS,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                raise InstalledChannelProvisionLockError(
                    "provision lock identity is unavailable"
                ) from ctypes.WinError(ctypes.get_last_error())
            if int(info.FileAttributes) & (
                _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise InstalledChannelProvisionLockError(
                    "provision lock is not a plain file"
                )
            if error == _ERROR_ALREADY_EXISTS:
                self._assert_lock_acl(self.path)
            else:
                self._harden_lock_acl(self.path)
                self._assert_lock_acl(self.path)
            _ordinary_boundary(self.boundary)
            self._assert_boundary_acl()
        except Exception:
            _kernel32.CloseHandle(wintypes.HANDLE(handle))
            raise
        self._handle = handle
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            _kernel32.CloseHandle(wintypes.HANDLE(handle))


__all__ = [
    "InstalledChannelProvisionBusy",
    "InstalledChannelProvisionLock",
    "InstalledChannelProvisionLockError",
]
