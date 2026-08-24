"""Clone-only evidence guard for a Weixin SQLite file family.

The boundary in this phase is deliberately narrow: inspect a stopped SQLite
family and clone a rollback candidate into an already-existing staging
directory.  It never opens SQLite, never writes or removes an original family
member, and never claims that a clone is recoverable.  Original recovery,
helper-process isolation, Windows ACL authority, LocalService integration, and
production bridge wiring remain explicit NO-GO items.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
import json
import math
import ntpath
import os
from pathlib import Path
import re
import stat
import time
from typing import BinaryIO, Callable, Iterator


ORIGINAL_RECOVERY_SUPPORTED = False

DEFAULT_DEADLINE_SECONDS = 60.0
MAX_MAIN_BYTES = 256 * 1024 * 1024
MAX_WAL_BYTES = 16 * 1024 * 1024
MAX_SHM_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_LOCK_BYTES = 64 * 1024
COPY_CHUNK_BYTES = 1024 * 1024


class WeixinStateFamilyGuardError(RuntimeError):
    """The family cannot be observed or cloned without weakening the guard."""


class MemberRole(StrEnum):
    MAIN = "main"
    JOURNAL = "journal"
    WAL = "wal"
    SHM = "shm"
    LOCK = "lock"


class FamilyKind(StrEnum):
    CLEAN = "clean"
    ROLLBACK_CANDIDATE = "rollback_candidate"
    WAL_CANDIDATE = "wal_candidate"


class CloneOutcome(StrEnum):
    ROLLBACK_CANDIDATE_CLONED = "rollback_candidate_cloned"


@dataclass(frozen=True, slots=True)
class MemberSnapshot:
    role: MemberRole
    present: bool
    size: int | None
    modified_ns: int | None
    changed_ns: int | None
    attributes: int | None
    nlink: int | None
    volume_serial: int | None
    file_index: int | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class FamilySnapshot:
    schema: int
    kind: FamilyKind
    parent_enumeration_sha256: str
    family_sha256: str
    members: tuple[MemberSnapshot, ...]


@dataclass(frozen=True, slots=True)
class ClonedMemberReceipt:
    role: MemberRole
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RollbackCloneReceipt:
    schema: int
    outcome: CloneOutcome
    original_recovery_supported: bool
    source_family_sha256: str
    source_parent_enumeration_sha256: str
    source_members: tuple[MemberSnapshot, ...]
    main: ClonedMemberReceipt
    journal: ClonedMemberReceipt


@dataclass(frozen=True, slots=True)
class FamilyGuardSeams:
    """Deterministic test hooks; production callers should leave all as None."""

    after_snapshot: Callable[[], None] | None = None
    after_main_copy: Callable[[], None] | None = None
    before_source_revalidation: Callable[[], None] | None = None
    volume_id: Callable[[str, int], int] | None = None


@dataclass(frozen=True, slots=True)
class _Identity:
    volume_serial: int
    file_index: int
    mode_type: int
    size: int
    modified_ns: int
    changed_ns: int
    attributes: int
    nlink: int


@dataclass(slots=True)
class _PinnedMember:
    role: MemberRole
    path: Path
    stream: BinaryIO
    identity: _Identity
    final_path: str
    digest: str = ""

    def close(self) -> None:
        self.stream.close()


@dataclass(slots=True)
class _PinnedDirectory:
    path: Path
    identity: _Identity
    final_path: str
    native_handle: int | None = None
    descriptor: int | None = None

    def close(self) -> None:
        if self.descriptor is not None:
            descriptor, self.descriptor = self.descriptor, None
            os.close(descriptor)
        if self.native_handle is not None:
            handle, self.native_handle = self.native_handle, None
            _close_windows_handle(handle)


@dataclass(slots=True)
class _OpenFamily:
    main_path: Path
    parent_enumeration_sha256: str
    snapshot: FamilySnapshot
    pinned: dict[MemberRole, _PinnedMember]
    parent_pin: _PinnedDirectory


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float]) -> None:
        try:
            duration = float(seconds)
            start = float(clock())
        except (TypeError, ValueError, OverflowError) as exc:
            raise WeixinStateFamilyGuardError("deadline must be finite and positive") from exc
        if not math.isfinite(duration) or duration <= 0 or not math.isfinite(start):
            raise WeixinStateFamilyGuardError("deadline must be finite and positive")
        self._clock = clock
        self.expires_at = start + duration
        if not math.isfinite(self.expires_at):
            raise WeixinStateFamilyGuardError("deadline must be finite and positive")

    def check(self) -> None:
        try:
            now = float(self._clock())
        except (TypeError, ValueError, OverflowError) as exc:
            raise WeixinStateFamilyGuardError("deadline clock is invalid") from exc
        if not math.isfinite(now) or now >= self.expires_at:
            raise WeixinStateFamilyGuardError("SQLite family operation deadline expired")


_MEMBER_SUFFIX = {
    MemberRole.MAIN: "",
    MemberRole.JOURNAL: "-journal",
    MemberRole.WAL: "-wal",
    MemberRole.SHM: "-shm",
    MemberRole.LOCK: ".bridge.lock",
}
_MEMBER_LIMIT = {
    MemberRole.MAIN: MAX_MAIN_BYTES,
    MemberRole.JOURNAL: MAX_JOURNAL_BYTES,
    MemberRole.WAL: MAX_WAL_BYTES,
    MemberRole.SHM: MAX_SHM_BYTES,
    MemberRole.LOCK: MAX_LOCK_BYTES,
}


def recover_original(*_args: object, **_kwargs: object) -> None:
    """Reject original-file recovery unconditionally."""

    raise WeixinStateFamilyGuardError("original recovery is not supported")


def _lexical_absolute_local_path(value: str | Path) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise WeixinStateFamilyGuardError(
            "path must be an absolute local fixed-volume path"
        )
    if raw.startswith(("\\\\", "//", "\\?\\", "\\.\\")):
        raise WeixinStateFamilyGuardError(
            "path must be an absolute local fixed-volume path"
        )
    if os.name == "nt":
        drive, tail = ntpath.splitdrive(raw)
        if (
            re.fullmatch(r"[A-Za-z]:", drive) is None
            or not tail.startswith(("\\", "/"))
        ):
            raise WeixinStateFamilyGuardError(
                "path must be an absolute local fixed-volume path"
            )
        if ":" in tail:
            raise WeixinStateFamilyGuardError(
                "alternate data stream syntax is forbidden"
            )
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetDriveTypeW.restype = ctypes.c_uint32
        if int(kernel32.GetDriveTypeW(f"{drive}\\")) != 3:  # DRIVE_FIXED
            raise WeixinStateFamilyGuardError(
                "path must be an absolute local fixed-volume path"
            )
    else:
        if not os.path.isabs(raw):
            raise WeixinStateFamilyGuardError(
                "path must be an absolute local fixed-volume path"
            )
        if ":" in raw:
            raise WeixinStateFamilyGuardError(
                "alternate data stream syntax is forbidden"
            )
    pieces = raw.replace("\\", "/").split("/")
    if any(piece in {".", ".."} for piece in pieces):
        raise WeixinStateFamilyGuardError(
            "path must be an absolute local fixed-volume path"
        )
    return Path(os.path.normpath(raw))


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse
    )


def _canonical_lexical(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _close_windows_handle(handle: int) -> None:
    if os.name != "nt":
        return
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(ctypes.c_void_p(handle))


def _windows_open_handle(
    path: Path,
    *,
    directory: bool,
    create_new: bool = False,
) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    desired_access = (
        0x00000080  # FILE_READ_ATTRIBUTES
        if directory
        else (0x80000000 | (0x40000000 if create_new else 0))
    )
    raw_handle = kernel32.CreateFileW(
        os.fspath(path),
        desired_access,
        0 if create_new else 0x00000001,  # target exclusive; source share-read only
        None,
        1 if create_new else 3,  # CREATE_NEW / OPEN_EXISTING
        (
            0x00200000 | 0x02000000  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
            if directory
            else (
                0x00200000
                | 0x08000000
                | (0x80000000 if create_new else 0)
            )  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN | optional WRITE_THROUGH
        ),
        None,
    )
    handle = int(raw_handle or 0)
    invalid = int(ctypes.c_void_p(-1).value)
    if not handle or handle == invalid:
        error = ctypes.get_last_error()
        if create_new and error in {80, 183}:  # FILE_EXISTS / ALREADY_EXISTS
            raise FileExistsError(error, "clone target already exists", os.fspath(path))
        raise OSError(error, f"CreateFileW failed for {path}")
    return handle


def _windows_filetime_ns(value: object) -> int:
    ticks = (int(getattr(value, "dwHighDateTime")) << 32) | int(
        getattr(value, "dwLowDateTime")
    )
    return (ticks - 116_444_736_000_000_000) * 100


def _windows_handle_identity(handle: int) -> _Identity:
    import ctypes
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = (
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        )

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FileTime),
            ("ftLastAccessTime", _FileTime),
            ("ftLastWriteTime", _FileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    info = _ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(
        wintypes.HANDLE(handle), ctypes.byref(info)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = int(info.dwFileAttributes)
    is_directory = bool(attributes & 0x10)
    return _Identity(
        volume_serial=int(info.dwVolumeSerialNumber),
        file_index=(int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        mode_type=stat.S_IFDIR if is_directory else stat.S_IFREG,
        size=(int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
        modified_ns=_windows_filetime_ns(info.ftLastWriteTime),
        changed_ns=_windows_filetime_ns(info.ftCreationTime),
        attributes=attributes,
        nlink=int(info.nNumberOfLinks),
    )


def _windows_final_path(handle: int) -> str:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    required = int(
        kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0)
    )
    if required <= 0 or required > 32_768:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        kernel32.GetFinalPathNameByHandleW(
            wintypes.HANDLE(handle), buffer, len(buffer), 0
        )
    )
    if written <= 0 or written >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.abspath(value))


def _windows_assert_no_named_streams(path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    class _FindStreamData(ctypes.Structure):
        _fields_ = (
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", wintypes.WCHAR * 296),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.FindFirstStreamW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(_FindStreamData),
        wintypes.DWORD,
    ]
    kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    kernel32.FindNextStreamW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FindStreamData),
    ]
    kernel32.FindNextStreamW.restype = wintypes.BOOL
    kernel32.FindClose.argtypes = [wintypes.HANDLE]
    kernel32.FindClose.restype = wintypes.BOOL
    data = _FindStreamData()
    raw = kernel32.FindFirstStreamW(os.fspath(path), 0, ctypes.byref(data), 0)
    handle = int(raw or 0)
    invalid = int(ctypes.c_void_p(-1).value)
    if not handle or handle == invalid:
        error = ctypes.get_last_error()
        if error == 38:  # ERROR_HANDLE_EOF: no streams (common for directories)
            return
        raise WeixinStateFamilyGuardError(
            "alternate data stream enumeration failed"
        )
    try:
        while True:
            if data.cStreamName != "::$DATA":
                raise WeixinStateFamilyGuardError(
                    "alternate data stream is forbidden"
                )
            if not kernel32.FindNextStreamW(
                wintypes.HANDLE(handle), ctypes.byref(data)
            ):
                error = ctypes.get_last_error()
                if error != 38:
                    raise WeixinStateFamilyGuardError(
                        "alternate data stream enumeration failed"
                    )
                break
    finally:
        kernel32.FindClose(wintypes.HANDLE(handle))


def _identity(info: os.stat_result) -> _Identity:
    volume_serial = int(info.st_dev)
    if os.name == "nt":
        volume_serial &= 0xFFFF_FFFF
    return _Identity(
        volume_serial=volume_serial,
        file_index=int(info.st_ino),
        mode_type=stat.S_IFMT(info.st_mode),
        size=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        changed_ns=int(info.st_ctime_ns),
        attributes=int(getattr(info, "st_file_attributes", 0)),
        nlink=int(info.st_nlink),
    )


def _stream_identity(stream: BinaryIO) -> _Identity:
    if os.name != "nt":
        return _identity(os.fstat(stream.fileno()))
    import msvcrt

    return _windows_handle_identity(int(msvcrt.get_osfhandle(stream.fileno())))


def _stream_final_path(stream: BinaryIO, fallback: Path) -> str:
    if os.name != "nt":
        return _canonical_lexical(fallback)
    import msvcrt

    return _windows_final_path(int(msvcrt.get_osfhandle(stream.fileno())))


def _directory_pin_identity(pin: _PinnedDirectory) -> _Identity:
    if pin.native_handle is not None:
        return _windows_handle_identity(pin.native_handle)
    if pin.descriptor is None:
        raise WeixinStateFamilyGuardError("directory pin is closed")
    return _identity(os.fstat(pin.descriptor))


def _directory_pin_final_path(pin: _PinnedDirectory) -> str:
    if pin.native_handle is not None:
        return _windows_final_path(pin.native_handle)
    return _canonical_lexical(pin.path)


def _open_directory_pin(path: Path, deadline: _Deadline) -> _PinnedDirectory:
    deadline.check()
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise WeixinStateFamilyGuardError("path parent directory is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or _is_reparse_or_symlink(before):
        raise WeixinStateFamilyGuardError(
            "path parent must be a non-reparse directory"
        )
    before_identity = _identity(before)
    if os.name == "nt":
        try:
            handle = _windows_open_handle(path, directory=True)
            opened_identity = _windows_handle_identity(handle)
            final_path = _windows_final_path(handle)
            _windows_assert_no_named_streams(path)
            deadline.check()
        except BaseException as exc:
            if "handle" in locals():
                _close_windows_handle(handle)
            if isinstance(exc, WeixinStateFamilyGuardError):
                raise
            raise WeixinStateFamilyGuardError(
                "path parent directory could not be pinned"
            ) from exc
        if (
            opened_identity.mode_type != stat.S_IFDIR
            or bool(opened_identity.attributes & 0x400)
            or not _same_object_identity(opened_identity, before_identity)
            or final_path != _canonical_lexical(path)
        ):
            _close_windows_handle(handle)
            raise WeixinStateFamilyGuardError(
                "path parent must be a non-reparse directory"
            )
        return _PinnedDirectory(
            path=path,
            identity=opened_identity,
            final_path=final_path,
            native_handle=handle,
        )
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
        opened_identity = _identity(os.fstat(descriptor))
        deadline.check()
    except BaseException as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise WeixinStateFamilyGuardError(
            "path parent directory could not be pinned"
        ) from exc
    if (
        opened_identity.mode_type != stat.S_IFDIR
        or not _same_object_identity(opened_identity, before_identity)
    ):
        os.close(descriptor)
        raise WeixinStateFamilyGuardError(
            "path parent must be a non-reparse directory"
        )
    return _PinnedDirectory(
        path=path,
        identity=opened_identity,
        final_path=_canonical_lexical(path),
        descriptor=descriptor,
    )


@contextmanager
def _pinned_directory_chain(
    path: Path,
    deadline: _Deadline,
) -> Iterator[_PinnedDirectory]:
    current = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    with ExitStack() as stack:
        last = _open_directory_pin(current, deadline)
        stack.callback(last.close)
        for part in parts:
            deadline.check()
            current = current / part
            last = _open_directory_pin(current, deadline)
            stack.callback(last.close)
        yield last


def _assert_directory_chain(path: Path, deadline: _Deadline) -> None:
    with _pinned_directory_chain(path, deadline):
        deadline.check()


def _enumerate_parent(parent: Path, deadline: _Deadline) -> tuple[str, frozenset[str]]:
    rows: list[tuple[object, ...]] = []
    names: set[str] = set()
    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                deadline.check()
                info = entry.stat(follow_symlinks=False)
                names.add(entry.name)
                rows.append(
                    (
                        entry.name,
                        stat.S_IFMT(info.st_mode),
                        int(info.st_size),
                        int(info.st_mtime_ns),
                        int(info.st_ctime_ns),
                        int(getattr(info, "st_file_attributes", 0)),
                        int(info.st_nlink),
                        int(info.st_dev),
                        int(info.st_ino),
                    )
                )
    except OSError as exc:
        raise WeixinStateFamilyGuardError("parent enumeration failed") from exc
    deadline.check()
    payload = json.dumps(
        sorted(rows, key=lambda row: str(row[0]).casefold()),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest(), frozenset(names)


def _validate_member_lstat(path: Path, role: MemberRole) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise WeixinStateFamilyGuardError(f"{role} family member is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or _is_reparse_or_symlink(info):
        raise WeixinStateFamilyGuardError(
            f"{role} must be a regular non-reparse file"
        )
    if int(info.st_nlink) != 1:
        raise WeixinStateFamilyGuardError(f"{role} hardlinks are forbidden")
    size = int(info.st_size)
    if size < 0 or size > _MEMBER_LIMIT[role]:
        raise WeixinStateFamilyGuardError(f"{role} exceeds its byte limit")
    return info


def _open_member(path: Path, role: MemberRole, deadline: _Deadline) -> _PinnedMember:
    deadline.check()
    before = _validate_member_lstat(path, role)
    before_identity = _identity(before)
    if os.name == "nt":
        import msvcrt

        handle: int | None = None
        descriptor: int | None = None
        try:
            handle = _windows_open_handle(path, directory=False)
            opened_identity = _windows_handle_identity(handle)
            final_path = _windows_final_path(handle)
            _windows_assert_no_named_streams(path)
            deadline.check()
            if (
                opened_identity.mode_type != stat.S_IFREG
                or bool(opened_identity.attributes & 0x400)
                or opened_identity.nlink != 1
                or opened_identity.size > _MEMBER_LIMIT[role]
                or not _same_member_path_identity(opened_identity, before_identity)
                or final_path != _canonical_lexical(path)
            ):
                raise WeixinStateFamilyGuardError(
                    f"{role} identity changed while opening"
                )
            descriptor = msvcrt.open_osfhandle(
                handle,
                os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
            )
            handle = None  # ownership transferred to the CRT descriptor
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = None
        except BaseException as exc:
            if descriptor is not None:
                os.close(descriptor)
            if handle is not None:
                _close_windows_handle(handle)
            if isinstance(exc, WeixinStateFamilyGuardError):
                raise
            raise WeixinStateFamilyGuardError(f"{role} could not be pinned") from exc
        return _PinnedMember(
            role=role,
            path=path,
            stream=stream,
            identity=opened_identity,
            final_path=final_path,
        )
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WeixinStateFamilyGuardError(f"{role} could not be pinned") from exc
    try:
        opened = os.fstat(descriptor)
        deadline.check()
        opened_identity = _identity(opened)
        if (
            (
                opened_identity.volume_serial,
                opened_identity.file_index,
                opened_identity.mode_type,
                opened_identity.size,
                opened_identity.modified_ns,
                opened_identity.attributes,
                opened_identity.nlink,
            )
            != (
                before_identity.volume_serial,
                before_identity.file_index,
                before_identity.mode_type,
                before_identity.size,
                before_identity.modified_ns,
                before_identity.attributes,
                before_identity.nlink,
            )
            or not stat.S_ISREG(opened.st_mode)
            or _is_reparse_or_symlink(opened)
            or int(opened.st_nlink) != 1
        ):
            raise WeixinStateFamilyGuardError(f"{role} identity changed while opening")
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    return _PinnedMember(
        role=role,
        path=path,
        stream=stream,
        identity=opened_identity,
        final_path=_canonical_lexical(path),
    )


def _hash_pinned(member: _PinnedMember, deadline: _Deadline) -> str:
    digest = sha256()
    member.stream.seek(0)
    read = 0
    while True:
        deadline.check()
        chunk = member.stream.read(COPY_CHUNK_BYTES)
        deadline.check()
        if not chunk:
            break
        read += len(chunk)
        if read > _MEMBER_LIMIT[member.role]:
            raise WeixinStateFamilyGuardError(f"{member.role} exceeds its byte limit")
        digest.update(chunk)
    after = _stream_identity(member.stream)
    if after != member.identity or read != member.identity.size:
        raise WeixinStateFamilyGuardError(f"{member.role} changed while hashing")
    if _stream_final_path(member.stream, member.path) != member.final_path:
        raise WeixinStateFamilyGuardError(f"{member.role} final path changed while hashing")
    member.digest = digest.hexdigest()
    return member.digest


def _member_receipt(
    role: MemberRole,
    pinned: _PinnedMember | None,
) -> MemberSnapshot:
    if pinned is None:
        return MemberSnapshot(
            role=role,
            present=False,
            size=None,
            modified_ns=None,
            changed_ns=None,
            attributes=None,
            nlink=None,
            volume_serial=None,
            file_index=None,
            sha256=None,
        )
    value = pinned.identity
    return MemberSnapshot(
        role=role,
        present=True,
        size=value.size,
        modified_ns=value.modified_ns,
        changed_ns=value.changed_ns,
        attributes=value.attributes,
        nlink=value.nlink,
        volume_serial=value.volume_serial,
        file_index=value.file_index,
        sha256=pinned.digest,
    )


def _classify(presence: dict[MemberRole, bool]) -> FamilyKind:
    if not presence[MemberRole.MAIN]:
        raise WeixinStateFamilyGuardError("invalid SQLite family: main is missing")
    journal = presence[MemberRole.JOURNAL]
    wal = presence[MemberRole.WAL]
    shm = presence[MemberRole.SHM]
    if journal and (wal or shm):
        raise WeixinStateFamilyGuardError("invalid SQLite family: mixed journal modes")
    if wal != shm:
        raise WeixinStateFamilyGuardError("invalid SQLite family: WAL/SHM must be paired")
    if journal:
        return FamilyKind.ROLLBACK_CANDIDATE
    if wal:
        return FamilyKind.WAL_CANDIDATE
    return FamilyKind.CLEAN


def _family_digest(
    kind: FamilyKind,
    parent_digest: str,
    members: tuple[MemberSnapshot, ...],
) -> str:
    payload = {
        "kind": str(kind),
        "parent_enumeration_sha256": parent_digest,
        "members": [
            {
                "role": str(member.role),
                "present": member.present,
                "size": member.size,
                "modified_ns": member.modified_ns,
                "changed_ns": member.changed_ns,
                "attributes": member.attributes,
                "nlink": member.nlink,
                "volume_serial": member.volume_serial,
                "file_index": member.file_index,
                "sha256": member.sha256,
            }
            for member in members
        ],
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


@contextmanager
def _open_family(
    main_path: Path,
    deadline: _Deadline,
) -> Iterator[_OpenFamily]:
    with ExitStack() as stack:
        parent_pin = stack.enter_context(
            _pinned_directory_chain(main_path.parent, deadline)
        )
        expected_names = {
            role: f"{main_path.name}{suffix}"
            for role, suffix in _MEMBER_SUFFIX.items()
        }
        parent_digest, names = _enumerate_parent(main_path.parent, deadline)
        allowed = frozenset(expected_names.values())
        folded_prefix = main_path.name.casefold()
        unknown = sorted(
            name
            for name in names
            if name.casefold().startswith(folded_prefix) and name not in allowed
        )
        if unknown:
            raise WeixinStateFamilyGuardError("unknown SQLite sibling or super-journal")
        presence = {role: name in names for role, name in expected_names.items()}
        kind = _classify(presence)
        pinned: dict[MemberRole, _PinnedMember] = {}
        for role in MemberRole:
            if not presence[role]:
                continue
            member = _open_member(main_path.parent / expected_names[role], role, deadline)
            stack.callback(member.close)
            _hash_pinned(member, deadline)
            pinned[role] = member
        after_digest, after_names = _enumerate_parent(main_path.parent, deadline)
        if after_digest != parent_digest or after_names != names:
            raise WeixinStateFamilyGuardError("parent enumeration changed during snapshot")
        members = tuple(_member_receipt(role, pinned.get(role)) for role in MemberRole)
        snapshot = FamilySnapshot(
            schema=1,
            kind=kind,
            parent_enumeration_sha256=parent_digest,
            family_sha256=_family_digest(kind, parent_digest, members),
            members=members,
        )
        yield _OpenFamily(
            main_path=main_path,
            parent_enumeration_sha256=parent_digest,
            snapshot=snapshot,
            pinned=pinned,
            parent_pin=parent_pin,
        )


def snapshot_family(
    main_path: str | Path,
    *,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> FamilySnapshot:
    """Hash and classify a family without opening SQLite or changing bytes."""

    deadline = _Deadline(deadline_seconds, clock)
    main = _lexical_absolute_local_path(main_path)
    with _open_family(main, deadline) as opened:
        deadline.check()
        result = opened.snapshot
    deadline.check()
    return result


def _target_must_not_exist(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WeixinStateFamilyGuardError("clone target cannot be inspected") from exc
    raise WeixinStateFamilyGuardError("clone target already exists")


def _create_target_stream(
    target: Path,
) -> tuple[BinaryIO, _Identity, str]:
    if os.name == "nt":
        import msvcrt

        handle: int | None = None
        descriptor: int | None = None
        try:
            handle = _windows_open_handle(
                target,
                directory=False,
                create_new=True,
            )
            identity = _windows_handle_identity(handle)
            final_path = _windows_final_path(handle)
            _windows_assert_no_named_streams(target)
            if (
                identity.mode_type != stat.S_IFREG
                or bool(identity.attributes & 0x400)
                or identity.nlink != 1
                or final_path != _canonical_lexical(target)
            ):
                raise WeixinStateFamilyGuardError("clone target identity is unsafe")
            descriptor = msvcrt.open_osfhandle(
                handle,
                os.O_RDWR | int(getattr(os, "O_BINARY", 0)),
            )
            handle = None
            stream = os.fdopen(descriptor, "w+b", closefd=True)
            descriptor = None
            return stream, identity, final_path
        except BaseException as exc:
            if descriptor is not None:
                os.close(descriptor)
            if handle is not None:
                _close_windows_handle(handle)
            if isinstance(exc, FileExistsError):
                raise WeixinStateFamilyGuardError("clone target already exists") from exc
            if isinstance(exc, WeixinStateFamilyGuardError):
                raise
            raise WeixinStateFamilyGuardError(
                "clone target could not be created exclusively"
            ) from exc
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_BINARY", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise WeixinStateFamilyGuardError("clone target already exists") from exc
    except OSError as exc:
        raise WeixinStateFamilyGuardError(
            "clone target could not be created exclusively"
        ) from exc
    try:
        identity = _identity(os.fstat(descriptor))
        stream = os.fdopen(descriptor, "w+b", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    return stream, identity, _canonical_lexical(target)


def _run_hook(hook: Callable[[], None] | None, label: str) -> None:
    if hook is None:
        return
    try:
        hook()
    except BaseException as exc:
        raise WeixinStateFamilyGuardError(f"{label} seam did not complete") from exc


def _same_pinned_identity(current: _Identity, expected: _Identity) -> bool:
    return current == expected


def _same_object_identity(current: _Identity, expected: _Identity) -> bool:
    return (
        current.volume_serial,
        current.file_index,
        current.mode_type,
        current.attributes,
        current.nlink,
    ) == (
        expected.volume_serial,
        expected.file_index,
        expected.mode_type,
        expected.attributes,
        expected.nlink,
    )


def _same_member_path_identity(current: _Identity, expected: _Identity) -> bool:
    # Windows can lazily materialize creation-time metadata between lstat and
    # the first handle query.  Object identity, size, mtime, attributes, link
    # count, and a second digest from the still-pinned handle remain strict.
    return _same_object_identity(current, expected) and (
        current.size,
        current.modified_ns,
    ) == (
        expected.size,
        expected.modified_ns,
    )


def _copy_pinned(
    source: _PinnedMember,
    target: Path,
    *,
    expected_volume: int,
    deadline: _Deadline,
) -> ClonedMemberReceipt:
    deadline.check()
    target_stream, opened_identity, final_path = _create_target_stream(target)
    deadline.check()
    if opened_identity.volume_serial != expected_volume:
        target_stream.close()
        raise WeixinStateFamilyGuardError("clone target identity is unsafe")

    copied_digest = sha256()
    copied_size = 0
    with target_stream:
        source.stream.seek(0)
        while True:
            deadline.check()
            chunk = source.stream.read(COPY_CHUNK_BYTES)
            deadline.check()
            if not chunk:
                break
            copied_size += len(chunk)
            if copied_size > _MEMBER_LIMIT[source.role]:
                raise WeixinStateFamilyGuardError(
                    f"{source.role} exceeds its byte limit while copying"
                )
            target_stream.write(chunk)
            copied_digest.update(chunk)
        target_stream.flush()
        os.fsync(target_stream.fileno())
        deadline.check()
        if not _same_pinned_identity(
            _stream_identity(source.stream),
            source.identity,
        ):
            raise WeixinStateFamilyGuardError(f"{source.role} changed while copying")
        copied_hex = copied_digest.hexdigest()
        if copied_size != source.identity.size or copied_hex != source.digest:
            raise WeixinStateFamilyGuardError(f"{source.role} changed after snapshot")
        target_stream.seek(0)
        verified = sha256()
        verified_size = 0
        while True:
            deadline.check()
            chunk = target_stream.read(COPY_CHUNK_BYTES)
            deadline.check()
            if not chunk:
                break
            verified.update(chunk)
            verified_size += len(chunk)
        final_target = _stream_identity(target_stream)
        if (
            final_target.volume_serial != expected_volume
            or final_target.file_index != opened_identity.file_index
            or final_target.mode_type != opened_identity.mode_type
            or final_target.nlink != 1
            or final_target.size != copied_size
            or verified_size != copied_size
            or verified.hexdigest() != copied_hex
            or _stream_final_path(target_stream, target) != final_path
        ):
            raise WeixinStateFamilyGuardError("clone digest or identity verification failed")
    deadline.check()
    return ClonedMemberReceipt(
        role=source.role,
        size=copied_size,
        sha256=copied_hex,
    )


def _revalidate_source(opened: _OpenFamily, deadline: _Deadline) -> None:
    deadline.check()
    if (
        not _same_object_identity(
            _directory_pin_identity(opened.parent_pin),
            opened.parent_pin.identity,
        )
        or _directory_pin_final_path(opened.parent_pin) != opened.parent_pin.final_path
    ):
        raise WeixinStateFamilyGuardError("source parent identity changed during clone")
    parent_digest, _ = _enumerate_parent(opened.main_path.parent, deadline)
    if parent_digest != opened.parent_enumeration_sha256:
        raise WeixinStateFamilyGuardError("parent enumeration changed during clone")
    for role, member in opened.pinned.items():
        deadline.check()
        current = _identity(_validate_member_lstat(member.path, role))
        if not _same_member_path_identity(current, member.identity):
            raise WeixinStateFamilyGuardError(f"{role} path identity changed during clone")
        expected_digest = member.digest
        if _hash_pinned(member, deadline) != expected_digest:
            raise WeixinStateFamilyGuardError(f"{role} content changed during clone")


def clone_rollback_candidate(
    main_path: str | Path,
    stage_directory: str | Path,
    *,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    seams: FamilyGuardSeams | None = None,
) -> RollbackCloneReceipt:
    """Clone main+journal into an existing stage; never touch the originals."""

    main = _lexical_absolute_local_path(main_path)
    stage = _lexical_absolute_local_path(stage_directory)
    deadline = _Deadline(deadline_seconds, clock)
    active_seams = seams or FamilyGuardSeams()
    receipt: RollbackCloneReceipt | None = None
    with _pinned_directory_chain(stage, deadline) as stage_pin:
        stage_identity = stage_pin.identity
        with _open_family(main, deadline) as opened:
            if opened.snapshot.kind is not FamilyKind.ROLLBACK_CANDIDATE:
                raise WeixinStateFamilyGuardError("only rollback candidates may be cloned")
            source_volume = opened.pinned[MemberRole.MAIN].identity.volume_serial
            stage_volume = stage_identity.volume_serial
            if source_volume != stage_volume:
                raise WeixinStateFamilyGuardError(
                    "source and stage must use the same fixed volume"
                )
            if active_seams.volume_id is not None:
                try:
                    source_volume = int(active_seams.volume_id("source", source_volume))
                    stage_volume = int(active_seams.volume_id("stage", stage_volume))
                except BaseException as exc:
                    raise WeixinStateFamilyGuardError("volume identity seam failed") from exc
            if source_volume != stage_volume:
                raise WeixinStateFamilyGuardError(
                    "source and stage must use the same fixed volume"
                )
            target_main = stage / main.name
            target_journal = stage / f"{main.name}-journal"
            deadline.check()
            _target_must_not_exist(target_main)
            deadline.check()
            _target_must_not_exist(target_journal)
            deadline.check()
            _run_hook(active_seams.after_snapshot, "after-snapshot")
            main_receipt = _copy_pinned(
                opened.pinned[MemberRole.MAIN],
                target_main,
                expected_volume=stage_identity.volume_serial,
                deadline=deadline,
            )
            _run_hook(active_seams.after_main_copy, "after-main-copy")
            journal_receipt = _copy_pinned(
                opened.pinned[MemberRole.JOURNAL],
                target_journal,
                expected_volume=stage_identity.volume_serial,
                deadline=deadline,
            )
            _run_hook(
                active_seams.before_source_revalidation,
                "before-source-revalidation",
            )
            _revalidate_source(opened, deadline)
            current_stage = _identity(os.lstat(stage))
            if (
                not _same_object_identity(current_stage, stage_identity)
                or not _same_object_identity(
                    _directory_pin_identity(stage_pin),
                    stage_identity,
                )
                or _directory_pin_final_path(stage_pin) != stage_pin.final_path
            ):
                raise WeixinStateFamilyGuardError(
                    "stage directory identity changed during clone"
                )
            deadline.check()
            receipt = RollbackCloneReceipt(
                schema=1,
                outcome=CloneOutcome.ROLLBACK_CANDIDATE_CLONED,
                original_recovery_supported=False,
                source_family_sha256=opened.snapshot.family_sha256,
                source_parent_enumeration_sha256=opened.parent_enumeration_sha256,
                source_members=opened.snapshot.members,
                main=main_receipt,
                journal=journal_receipt,
            )
        deadline.check()
    deadline.check()
    if receipt is None:
        raise WeixinStateFamilyGuardError("clone receipt was not produced")
    return receipt
