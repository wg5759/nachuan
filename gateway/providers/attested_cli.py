"""Absolute-path and SHA-256 attestation for optional local CLI providers."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat as stat_module
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class AttestedCli:
    path: str
    sha256: str


class AttestedCliPinError(RuntimeError):
    """Stable failure while holding an executable identity through one run."""


def _path_has_redirect(path: Path) -> bool:
    try:
        for component in reversed((path, *path.parents)):
            info = os.lstat(component)
            attributes = int(getattr(info, "st_file_attributes", 0))
            if component.is_symlink() or (
                attributes
                & int(getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            ):
                return True
        return False
    except OSError:
        return True


def _regular_non_reparse_file(path: Path) -> bool:
    try:
        stat = path.stat()
        reparse = int(getattr(stat, "st_file_attributes", 0)) & 0x400
        if not path.is_file() or path.is_symlink() or reparse or _path_has_redirect(path):
            return False
        # Hashing a .cmd/.bat/.ps1 shim does not bind the interpreter or target
        # script it resolves to.  Windows providers therefore accept only the
        # actual PE executable; script chains need a future recursive manifest.
        if os.name == "nt":
            return path.suffix.lower() == ".exe"
        return bool(stat.st_mode & 0o111)
    except OSError:
        return False


def file_sha256(path: str | Path, *, max_bytes: int = 512 * 1024 * 1024) -> str:
    candidate = Path(path)
    size = candidate.stat().st_size
    if size <= 0 or size > max_bytes:
        raise OSError("CLI executable size is outside the attestation bound")
    digest = hashlib.sha256()
    total = 0
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            total += len(chunk)
            if total > max_bytes:
                raise OSError("CLI executable grew beyond the attestation bound")
            digest.update(chunk)
    if total <= 0:
        raise OSError("CLI executable is empty")
    return digest.hexdigest()


def matches_attestation(path: str, expected_sha256: str) -> bool:
    candidate = Path(str(path or ""))
    expected = str(expected_sha256 or "").strip().lower()
    if not candidate.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    if not _regular_non_reparse_file(candidate):
        return False
    try:
        return hmac.compare_digest(file_sha256(candidate), expected)
    except OSError:
        return False


def _close_windows_handle(handle: int | None) -> bool:
    if os.name != "nt" or handle is None:
        return True
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    return bool(kernel32.CloseHandle(ctypes.c_void_p(handle)))


def _open_windows_read_pin(path: Path, *, directory: bool) -> int | None:
    if os.name != "nt":
        return None
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    flags = (
        0x00200000 | 0x02000000  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
        if directory
        else 0x00200000 | 0x08000000  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
    )
    raw = kernel32.CreateFileW(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ only: deny write/delete/replace
        None,
        3,  # OPEN_EXISTING
        flags,
        None,
    )
    handle = int(raw or 0)
    invalid = ctypes.c_void_p(-1).value
    return None if not handle or handle == invalid else handle


def _windows_final_path(handle: int) -> str | None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    required = int(
        kernel32.GetFinalPathNameByHandleW(ctypes.c_void_p(handle), None, 0, 0)
    )
    if required <= 0 or required > 32_768:
        return None
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        kernel32.GetFinalPathNameByHandleW(
            ctypes.c_void_p(handle), buffer, len(buffer), 0
        )
    )
    if written <= 0 or written >= len(buffer):
        return None
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.abspath(value))


@contextmanager
def pin_attested_cli(
    path: str | Path,
    expected_sha256: str,
) -> Iterator[Path]:
    """Keep an attested Windows path non-replaceable until the child exits."""

    candidate = Path(path)
    directory_handle = _open_windows_read_pin(candidate.parent, directory=True)
    file_handle = _open_windows_read_pin(candidate, directory=False)
    if os.name == "nt" and (directory_handle is None or file_handle is None):
        _close_windows_handle(file_handle)
        _close_windows_handle(directory_handle)
        raise AttestedCliPinError("binary_pin_failed")
    try:
        if not matches_attestation(str(candidate), expected_sha256):
            raise AttestedCliPinError("binary_attestation_rejected")
        if file_handle is not None:
            final_path = _windows_final_path(file_handle)
            if final_path != os.path.normcase(os.path.abspath(str(candidate))):
                raise AttestedCliPinError("binary_pin_identity_rejected")
        if directory_handle is not None:
            final_directory = _windows_final_path(directory_handle)
            if final_directory != os.path.normcase(
                os.path.abspath(str(candidate.parent))
            ):
                raise AttestedCliPinError("binary_pin_identity_rejected")
        yield candidate
        if os.name != "nt" and not matches_attestation(
            str(candidate), expected_sha256
        ):
            raise AttestedCliPinError("binary_changed_during_execution")
    finally:
        file_closed = _close_windows_handle(file_handle)
        directory_closed = _close_windows_handle(directory_handle)
        if not file_closed or not directory_closed:
            raise AttestedCliPinError("binary_pin_release_failed")


def from_environment(path_variable: str, hash_variable: str) -> AttestedCli | None:
    raw_path = str(os.environ.get(path_variable) or "").strip()
    expected = str(os.environ.get(hash_variable) or "").strip().lower()
    if not matches_attestation(raw_path, expected):
        return None
    return AttestedCli(path=str(Path(raw_path).resolve(strict=True)), sha256=expected)


__all__ = [
    "AttestedCli",
    "AttestedCliPinError",
    "file_sha256",
    "from_environment",
    "matches_attestation",
    "pin_attested_cli",
]
