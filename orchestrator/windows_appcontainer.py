"""Windows AppContainer launcher for one signed isolated-plugin request."""

from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO

from orchestrator.isolated_plugin import (
    IsolatedPluginWorkerError,
    VerifiedIsolatedPluginBundle,
)

_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NO_WINDOW = 0x08000000
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_ERROR_ALREADY_EXISTS_HRESULT = 0x800700B7
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_MAX_WIRE_OVERHEAD = 4
_PROFILE_MONIKER = "Nachuan.IsolatedPlugin.Worker.V1"
_READY_FRAME = b'{"schema":"nachuan.isolated-plugin.ready.v1"}'
_MAX_CONTROL_FRAME_BYTES = 256
_PACKAGED_STARTUP_TIMEOUT_MS = 30_000
_RUNTIME_MARKER = ".nachuan-runtime-fingerprint"
_MAX_RUNTIME_FILES = 5_000
_MAX_RUNTIME_BYTES = 256 * 1024 * 1024
_RuntimeRecord = tuple[str, int, str, Path]
_TOKEN_QUERY = 0x0008
_TOKEN_IS_APP_CONTAINER = 29
_TOKEN_APP_CONTAINER_SID = 31


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _STARTUPINFOW),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", wintypes.LPVOID),
        ("Capabilities", wintypes.LPVOID),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class _TOKEN_APPCONTAINER_INFORMATION(ctypes.Structure):
    _fields_ = [("TokenAppContainer", wintypes.LPVOID)]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount",
        "WriteOperationCount",
        "OtherOperationCount",
        "ReadTransferCount",
        "WriteTransferCount",
        "OtherTransferCount",
    )]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_userenv = ctypes.WinDLL("userenv", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


def _configure_api() -> None:
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
    ]
    _kernel32.CreatePipe.restype = wintypes.BOOL
    _kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _kernel32.SetHandleInformation.restype = wintypes.BOOL
    _kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    _kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    _kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    _kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    _kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_STARTUPINFOW),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    _kernel32.CreateProcessW.restype = wintypes.BOOL
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _userenv.CreateAppContainerProfile.restype = ctypes.c_long
    _userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    _userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    _userenv.DeleteAppContainerProfile.restype = ctypes.c_long
    _advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.FreeSid.argtypes = [wintypes.LPVOID]
    _advapi32.FreeSid.restype = wintypes.LPVOID
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    _advapi32.EqualSid.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL


_configure_api()
_launch_lock = threading.Lock()
_acl_grants: set[tuple[str, str, str]] = set()
_current_process_singleton_job = 0


def _close(handle: int | None) -> None:
    if handle:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))


def _profile(moniker: str) -> tuple[int, str]:
    sid = wintypes.LPVOID()
    hr = int(
        _userenv.CreateAppContainerProfile(moniker, moniker, moniker, None, 0, ctypes.byref(sid))
    ) & 0xFFFFFFFF
    if hr == _ERROR_ALREADY_EXISTS_HRESULT:
        delete_hr = int(_userenv.DeleteAppContainerProfile(moniker)) & 0xFFFFFFFF
        if delete_hr != 0:
            raise IsolatedPluginWorkerError(
                "stale AppContainer profile cannot be cleared"
            )
        if sid.value:
            _advapi32.FreeSid(sid)
        sid = wintypes.LPVOID()
        hr = int(
            _userenv.CreateAppContainerProfile(
                moniker,
                moniker,
                moniker,
                None,
                0,
                ctypes.byref(sid),
            )
        ) & 0xFFFFFFFF
    if hr != 0 or not sid.value:
        raise IsolatedPluginWorkerError("AppContainer profile is unavailable")
    text = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        _advapi32.FreeSid(sid)
        raise IsolatedPluginWorkerError("AppContainer SID is unavailable")
    try:
        sid_text = str(text.value)
    finally:
        _kernel32.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
    return int(sid.value), sid_text


def _grant(path: Path, sid: str, rights: str, *, recursive: bool = True) -> None:
    canonical = str(path.resolve())
    key = (canonical.casefold(), sid, rights + (":tree" if recursive else ":self"))
    if key in _acl_grants:
        return
    icacls = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"
    grant = f"*{sid}:(OI)(CI)({rights})" if recursive else f"*{sid}:({rights})"
    argv = [str(icacls), canonical, "/grant", grant]
    if recursive:
        argv.extend(["/T", "/C"])
    argv.append("/Q")
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IsolatedPluginWorkerError("AppContainer filesystem grant failed") from exc
    if result.returncode != 0:
        raise IsolatedPluginWorkerError("AppContainer filesystem grant failed")
    _acl_grants.add(key)


def _source_runtime() -> tuple[Path, Path, tuple[_RuntimeRecord, ...], str]:
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    base = Path(sys.base_prefix).resolve()
    runtime_dll = base / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    if not executable.is_file() or not runtime_dll.is_file():
        raise IsolatedPluginWorkerError("isolated plugin Python runtime is unavailable")
    inventory, fingerprint = _runtime_inventory(
        base,
        executable.name,
        closed=False,
    )
    return base, executable, inventory, fingerprint


def _runtime_file_digest(path: Path) -> tuple[int, str]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise IsolatedPluginWorkerError("isolated plugin runtime file is unavailable") from exc
    reparse = int(getattr(info, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or reparse:
        raise IsolatedPluginWorkerError("isolated plugin runtime file is invalid")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise IsolatedPluginWorkerError("isolated plugin runtime file cannot be read") from exc
    return int(info.st_size), digest.hexdigest()


def _runtime_inventory(
    root: Path,
    executable_name: str,
    *,
    closed: bool,
) -> tuple[tuple[_RuntimeRecord, ...], str]:
    selected: list[Path] = []
    allowed_top = {executable_name, "python3.dll"}
    for item in root.iterdir():
        if item.is_file() and (
            item.name in allowed_top
            or item.name.startswith("python") and item.suffix.casefold() == ".dll"
            or item.name.startswith("vcruntime") and item.suffix.casefold() == ".dll"
        ):
            selected.append(item)
        elif item.name in {"DLLs", "Lib"} and item.is_dir():
            for path in item.rglob("*"):
                try:
                    info = os.lstat(path)
                except OSError as exc:
                    raise IsolatedPluginWorkerError(
                        "isolated plugin runtime entry is unavailable"
                    ) from exc
                reparse = int(getattr(info, "st_file_attributes", 0)) & int(
                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                )
                if stat.S_ISDIR(info.st_mode) and not reparse:
                    continue
                if "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
                    if closed:
                        raise IsolatedPluginWorkerError(
                            "isolated plugin runtime cache is not closed"
                        )
                    continue
                selected.append(path)
        elif closed and item.name != _RUNTIME_MARKER:
            raise IsolatedPluginWorkerError("isolated plugin runtime cache is not closed")
    records: list[tuple[str, int, str, Path]] = []
    total = 0
    for path in selected:
        relative = path.relative_to(root).as_posix()
        size, digest = _runtime_file_digest(path)
        total += size
        records.append((relative, size, digest, path))
    records.sort(key=lambda item: item[0])
    if (
        not records
        or len(records) > _MAX_RUNTIME_FILES
        or total > _MAX_RUNTIME_BYTES
        or executable_name not in {item[0] for item in records}
    ):
        raise IsolatedPluginWorkerError("isolated plugin runtime inventory is invalid")
    fingerprint = hashlib.sha256()
    for relative, size, digest, _path in records:
        fingerprint.update(relative.encode("utf-8"))
        fingerprint.update(b"\0")
        fingerprint.update(str(size).encode("ascii"))
        fingerprint.update(b"\0")
        fingerprint.update(bytes.fromhex(digest))
    return tuple(records), fingerprint.hexdigest()


def _materialize_runtime(cache_root: Path) -> Path:
    _source_root, source_executable, source_inventory, fingerprint = _source_runtime()
    cache_root.mkdir(parents=True, exist_ok=True)
    name = (
        f"cpython-{sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro}-{fingerprint[:16]}"
    )
    destination = cache_root.resolve() / name
    marker = destination / _RUNTIME_MARKER
    executable = destination / source_executable.name
    if marker.is_file() and marker.read_text(encoding="ascii") == fingerprint:
        cached_inventory, cached_fingerprint = _runtime_inventory(
            destination,
            source_executable.name,
            closed=True,
        )
        cached_projection = tuple(item[:3] for item in cached_inventory)
        source_projection = tuple(item[:3] for item in source_inventory)
        if cached_fingerprint == fingerprint and cached_projection == source_projection:
            return executable
        raise IsolatedPluginWorkerError("isolated plugin runtime cache is invalid")
    if destination.exists():
        raise IsolatedPluginWorkerError("isolated plugin runtime cache is invalid")
    stage = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=cache_root))
    try:
        for relative, _size, _digest, source in source_inventory:
            target = stage / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        stage_inventory, stage_fingerprint = _runtime_inventory(
            stage,
            source_executable.name,
            closed=True,
        )
        if (
            stage_fingerprint != fingerprint
            or tuple(item[:3] for item in stage_inventory)
            != tuple(item[:3] for item in source_inventory)
        ):
            raise IsolatedPluginWorkerError(
                "isolated plugin runtime changed during staging"
            )
        (stage / _RUNTIME_MARKER).write_text(fingerprint, encoding="ascii")
        try:
            os.replace(stage, destination)
        except OSError:
            if not (
                marker.is_file()
                and marker.read_text(encoding="ascii") == fingerprint
                and executable.is_file()
            ):
                raise
        return executable
    except (OSError, UnicodeError) as exc:
        raise IsolatedPluginWorkerError("isolated plugin runtime staging failed") from exc
    finally:
        if stage.exists() and stage.parent.resolve() == cache_root.resolve():
            shutil.rmtree(stage, ignore_errors=True)


def _grant_runtime(cache_root: Path, sid: str) -> Path:
    executable = _materialize_runtime(cache_root)
    _grant(executable.parent, sid, "RX")
    return executable


def _pipe() -> tuple[int, int]:
    read = wintypes.HANDLE()
    write = wintypes.HANDLE()
    attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True)
    if not _kernel32.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0):
        raise IsolatedPluginWorkerError("isolated plugin pipe creation failed")
    return int(read.value), int(write.value)


def _noinherit(handle: int) -> None:
    if not _kernel32.SetHandleInformation(wintypes.HANDLE(handle), _HANDLE_FLAG_INHERIT, 0):
        raise IsolatedPluginWorkerError("isolated plugin pipe fencing failed")


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < size:
        chunk = stream.read(size - total)
        if not chunk:
            raise IsolatedPluginWorkerError("isolated plugin frame is truncated")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _read_frame(stream: BinaryIO, maximum: int) -> bytes:
    size = struct.unpack(">I", _read_exact(stream, _MAX_WIRE_OVERHEAD))[0]
    if size < 2 or size > maximum:
        raise IsolatedPluginWorkerError("isolated plugin frame is invalid")
    return _read_exact(stream, size)


def _token_matches_appcontainer(token: int, expected_sid: int) -> bool:
    value = wintypes.DWORD()
    returned = wintypes.DWORD()
    if not _advapi32.GetTokenInformation(
        wintypes.HANDLE(token),
        _TOKEN_IS_APP_CONTAINER,
        ctypes.byref(value),
        ctypes.sizeof(value),
        ctypes.byref(returned),
    ) or value.value != 1:
        return False
    size = wintypes.DWORD()
    _advapi32.GetTokenInformation(
        wintypes.HANDLE(token),
        _TOKEN_APP_CONTAINER_SID,
        None,
        0,
        ctypes.byref(size),
    )
    if ctypes.get_last_error() != 122 or not size.value:
        return False
    buffer = ctypes.create_string_buffer(size.value)
    if not _advapi32.GetTokenInformation(
        wintypes.HANDLE(token),
        _TOKEN_APP_CONTAINER_SID,
        buffer,
        size.value,
        ctypes.byref(size),
    ):
        return False
    information = ctypes.cast(
        buffer,
        ctypes.POINTER(_TOKEN_APPCONTAINER_INFORMATION),
    ).contents
    return bool(
        information.TokenAppContainer
        and _advapi32.EqualSid(
            information.TokenAppContainer,
            wintypes.LPVOID(expected_sid),
        )
    )


def _attest_appcontainer(process: int, expected_sid: int) -> bool:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        wintypes.HANDLE(process),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        return _token_matches_appcontainer(int(token.value or 0), expected_sid)
    finally:
        _close(int(token.value or 0))


def current_process_is_nachuan_appcontainer() -> bool:
    expected_sid = wintypes.LPVOID()
    hr = int(
        _userenv.DeriveAppContainerSidFromAppContainerName(
            _PROFILE_MONIKER,
            ctypes.byref(expected_sid),
        )
    ) & 0xFFFFFFFF
    if hr != 0 or not expected_sid.value:
        return False
    try:
        process = int(_kernel32.GetCurrentProcess() or 0)
        return _attest_appcontainer(process, int(expected_sid.value))
    finally:
        _advapi32.FreeSid(expected_sid)


def _job(
    bundle: VerifiedIsolatedPluginBundle,
    *,
    active_process_limit: int,
    apply_resource_limits: bool,
) -> int:
    raw = _kernel32.CreateJobObjectW(None, None)
    job = int(raw or 0)
    if not job:
        raise IsolatedPluginWorkerError("isolated plugin Job Object is unavailable")
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.ActiveProcessLimit = active_process_limit
    info.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_ACTIVE_PROCESS | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    if apply_resource_limits:
        info.BasicLimitInformation.PerProcessUserTimeLimit = (
            bundle.manifest.limits.cpu_time_ms * 10_000
        )
        info.BasicLimitInformation.LimitFlags |= (
            _JOB_OBJECT_LIMIT_PROCESS_TIME | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        )
        info.ProcessMemoryLimit = bundle.manifest.limits.memory_bytes
    if not _kernel32.SetInformationJobObject(
        wintypes.HANDLE(job),
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        _close(job)
        raise IsolatedPluginWorkerError("isolated plugin Job limits failed")
    return job


def fence_current_process_singleton(
    *,
    cpu_time_ms: int,
    memory_bytes: int,
) -> bool:
    """Put the packaged worker child in a nested one-process Job."""

    global _current_process_singleton_job
    if _current_process_singleton_job:
        return True
    raw = _kernel32.CreateJobObjectW(None, None)
    job = int(raw or 0)
    if not job:
        return False
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if not 100 <= cpu_time_ms <= 5_000 or not (
        32 * 1024 * 1024 <= memory_bytes <= 256 * 1024 * 1024
    ):
        return False
    info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_time_ms * 10_000
    info.BasicLimitInformation.ActiveProcessLimit = 1
    info.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_PROCESS_TIME
        | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    info.ProcessMemoryLimit = memory_bytes
    if not _kernel32.SetInformationJobObject(
        wintypes.HANDLE(job),
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ) or not _kernel32.AssignProcessToJobObject(
        wintypes.HANDLE(job),
        _kernel32.GetCurrentProcess(),
    ):
        _close(job)
        return False
    _current_process_singleton_job = job
    return True


def _environment_block(root: Path) -> ctypes.Array[ctypes.c_wchar]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
    system_drive = os.environ.get("SystemDrive") or system_root.drive
    user_profile = Path(
        os.environ.get("USERPROFILE") or Path.home()
    ).resolve()
    local_app_data = Path(
        os.environ.get("LOCALAPPDATA") or user_profile / "AppData" / "Local"
    ).resolve()
    roaming_app_data = Path(
        os.environ.get("APPDATA") or user_profile / "AppData" / "Roaming"
    ).resolve()
    values = {
        "ALLUSERSPROFILE": os.environ.get("ALLUSERSPROFILE")
        or str(Path(system_drive + "\\") / "ProgramData"),
        "APPDATA": str(roaming_app_data),
        "ComSpec": str(system_root / "System32" / "cmd.exe"),
        "HOMEDRIVE": os.environ.get("HOMEDRIVE") or user_profile.drive,
        "HOMEPATH": os.environ.get("HOMEPATH")
        or str(user_profile).removeprefix(user_profile.drive),
        "LOCALAPPDATA": str(local_app_data),
        "NUMBER_OF_PROCESSORS": str(os.cpu_count() or 1),
        "OS": "Windows_NT",
        "Path": str(system_root / "System32"),
        "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE")
        or platform.machine()
        or "AMD64",
        "ProgramData": os.environ.get("ProgramData")
        or str(Path(system_drive + "\\") / "ProgramData"),
        "PUBLIC": os.environ.get("PUBLIC")
        or str(Path(system_drive + "\\") / "Users" / "Public"),
        "SystemDrive": system_drive,
        "SystemRoot": str(system_root),
        "TEMP": str(root),
        "TMP": str(root),
        "USERPROFILE": str(user_profile),
        "WINDIR": str(system_root),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    # Windows needs these location variables while materialising the
    # AppContainer token/profile.  They are paths and account names only; the
    # parent's PATH, tokens, provider keys and arbitrary environment do not
    # cross the broker boundary.
    for key in (
        "COMPUTERNAME",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "SESSIONNAME",
        "USERDOMAIN",
        "USERNAME",
    ):
        value = os.environ.get(key)
        if value and "\0" not in value:
            values[key] = value
    text = "\0".join(f"{key}={values[key]}" for key in sorted(values, key=str.casefold)) + "\0\0"
    return ctypes.create_unicode_buffer(text)


class WindowsAppContainerLauncher:
    """No-capability AppContainer plus single-process kill-on-close Job Object."""

    def __init__(
        self,
        worker_script: str | Path | None = None,
        runtime_cache_root: str | Path | None = None,
        packaged_worker_executable: str | Path | None = None,
    ) -> None:
        if os.name != "nt":
            raise IsolatedPluginWorkerError("Windows AppContainer is unavailable")
        self.worker_script = Path(worker_script or Path(__file__).parents[1] / "cli" / "isolated_plugin_worker_entrypoint.py")
        local_app_data = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()))
        self.runtime_cache_root = Path(
            runtime_cache_root
            or local_app_data / "Nachuan" / "community" / "runtime-cache"
        )
        self.packaged_worker_executable = (
            Path(packaged_worker_executable).resolve()
            if packaged_worker_executable is not None
            else None
        )
        self.last_attestation = False
        self.last_ready_monotonic = 0.0
        self.last_terminal_monotonic = 0.0

    def execute(self, bundle: VerifiedIsolatedPluginBundle, request_json: bytes) -> bytes:
        if not isinstance(request_json, bytes):
            raise IsolatedPluginWorkerError("isolated plugin request is invalid")
        self.last_attestation = False
        self.last_ready_monotonic = 0.0
        self.last_terminal_monotonic = 0.0
        with _launch_lock:
            return self._execute_locked(bundle, request_json)

    def _execute_locked(self, bundle: VerifiedIsolatedPluginBundle, request_json: bytes) -> bytes:
        moniker = _PROFILE_MONIKER
        sid = 0
        profile_created = False
        run_root = Path(tempfile.mkdtemp(prefix="nachuan-plugin-appcontainer-"))
        child_stdin = child_stdout = parent_stdin = parent_stdout = 0
        process_handle = thread_handle = job = 0
        attribute_buffer: ctypes.Array[ctypes.c_char] | None = None
        attribute_list: int = 0
        output_stream: BinaryIO | None = None
        try:
            sid, sid_text = _profile(moniker)
            profile_created = True
            worker = run_root / "worker.py"
            plugin = run_root / "plugin.py"
            scratch = run_root / "scratch"
            scratch.mkdir()
            plugin.write_bytes(bundle.entrypoint_bytes)
            packaged_mode = bool(getattr(sys, "frozen", False)) or (
                self.packaged_worker_executable is not None
            )
            if packaged_mode:
                runtime_executable = (
                    self.packaged_worker_executable or Path(sys.executable).resolve()
                )
                if not runtime_executable.is_file():
                    raise IsolatedPluginWorkerError(
                        "isolated plugin packaged runtime is unavailable"
                    )
                _grant(runtime_executable, sid_text, "RX", recursive=False)
            else:
                worker.write_bytes(self.worker_script.read_bytes())
                runtime_executable = _grant_runtime(self.runtime_cache_root, sid_text)
            _grant(run_root, sid_text, "RX")
            _grant(scratch, sid_text, "M")

            child_stdin, parent_stdin = _pipe()
            parent_stdout, child_stdout = _pipe()
            _noinherit(parent_stdin)
            _noinherit(parent_stdout)

            size = ctypes.c_size_t()
            _kernel32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            if ctypes.get_last_error() != 122 or not size.value:
                raise IsolatedPluginWorkerError("AppContainer attribute sizing failed")
            attribute_buffer = ctypes.create_string_buffer(size.value)
            attribute_list = ctypes.addressof(attribute_buffer)
            if not _kernel32.InitializeProcThreadAttributeList(
                wintypes.LPVOID(attribute_list), 2, 0, ctypes.byref(size)
            ):
                raise IsolatedPluginWorkerError("AppContainer attribute list failed")
            capabilities = _SECURITY_CAPABILITIES(wintypes.LPVOID(sid), None, 0, 0)
            if not _kernel32.UpdateProcThreadAttribute(
                wintypes.LPVOID(attribute_list),
                0,
                _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(capabilities),
                ctypes.sizeof(capabilities),
                None,
                None,
            ):
                raise IsolatedPluginWorkerError("AppContainer security attribute failed")
            handles = (wintypes.HANDLE * 2)(wintypes.HANDLE(child_stdin), wintypes.HANDLE(child_stdout))
            if not _kernel32.UpdateProcThreadAttribute(
                wintypes.LPVOID(attribute_list),
                0,
                _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                ctypes.byref(handles),
                ctypes.sizeof(handles),
                None,
                None,
            ):
                raise IsolatedPluginWorkerError("AppContainer handle list failed")
            startup = _STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput = wintypes.HANDLE(child_stdin)
            startup.StartupInfo.hStdOutput = wintypes.HANDLE(child_stdout)
            startup.StartupInfo.hStdError = wintypes.HANDLE(child_stdout)
            startup.lpAttributeList = wintypes.LPVOID(attribute_list)
            process = _PROCESS_INFORMATION()
            if packaged_mode:
                argv = [
                    str(runtime_executable),
                    "--nachuan-isolated-plugin-worker",
                    str(plugin),
                    str(bundle.manifest.limits.max_request_bytes),
                    str(bundle.manifest.limits.max_response_bytes),
                    str(bundle.manifest.limits.cpu_time_ms),
                    str(bundle.manifest.limits.memory_bytes),
                ]
            else:
                argv = [
                    str(runtime_executable),
                    "-I",
                    "-S",
                    "-B",
                    "-X",
                    "utf8",
                    str(worker),
                    str(plugin),
                    str(bundle.manifest.limits.max_request_bytes),
                    str(bundle.manifest.limits.max_response_bytes),
                ]
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            environment = _environment_block(scratch)
            if not _kernel32.CreateProcessW(
                str(runtime_executable),
                command,
                None,
                None,
                True,
                _EXTENDED_STARTUPINFO_PRESENT
                | _CREATE_NO_WINDOW
                | _CREATE_SUSPENDED
                | _CREATE_UNICODE_ENVIRONMENT,
                environment,
                str(run_root),
                ctypes.cast(ctypes.byref(startup), ctypes.POINTER(_STARTUPINFOW)),
                ctypes.byref(process),
            ):
                error = ctypes.get_last_error()
                raise IsolatedPluginWorkerError(
                    f"AppContainer process creation failed (winerror={error})"
                )
            process_handle = int(process.hProcess or 0)
            thread_handle = int(process.hThread or 0)
            if not _attest_appcontainer(process_handle, sid):
                raise IsolatedPluginWorkerError("AppContainer token attestation failed")
            self.last_attestation = True
            job = _job(
                bundle,
                active_process_limit=2 if packaged_mode else 1,
                apply_resource_limits=not packaged_mode,
            )
            if not _kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), process.hProcess):
                raise IsolatedPluginWorkerError("AppContainer Job assignment failed")
            if int(_kernel32.ResumeThread(process.hThread)) != 1:
                raise IsolatedPluginWorkerError("AppContainer thread resume failed")
            _close(child_stdin)
            child_stdin = 0
            _close(child_stdout)
            child_stdout = 0

            descriptor = msvcrt.open_osfhandle(
                parent_stdout,
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
            output_stream = os.fdopen(descriptor, "rb", closefd=True)
            parent_stdout = 0
            ready_holder: list[bytes | BaseException] = []

            def read_ready() -> None:
                try:
                    if output_stream is None:
                        raise IsolatedPluginWorkerError(
                            "isolated plugin output is unavailable"
                        )
                    ready_holder.append(
                        _read_frame(output_stream, _MAX_CONTROL_FRAME_BYTES)
                    )
                except BaseException as exc:  # noqa: BLE001
                    ready_holder.append(exc)

            ready_reader = threading.Thread(target=read_ready, daemon=True)
            ready_reader.start()
            startup_timeout = (
                _PACKAGED_STARTUP_TIMEOUT_MS if packaged_mode else 5_000
            ) / 1000
            ready_reader.join(timeout=startup_timeout)
            if ready_reader.is_alive():
                _kernel32.TerminateJobObject(wintypes.HANDLE(job), 124)
                _kernel32.WaitForSingleObject(process.hProcess, 5_000)
                raise IsolatedPluginWorkerError(
                    "isolated plugin worker startup timed out"
                )
            if (
                len(ready_holder) != 1
                or isinstance(ready_holder[0], BaseException)
                or ready_holder[0] != _READY_FRAME
            ):
                raise IsolatedPluginWorkerError(
                    "isolated plugin worker readiness failed"
                )
            self.last_ready_monotonic = time.monotonic()
            descriptor = msvcrt.open_osfhandle(
                parent_stdin,
                os.O_WRONLY | getattr(os, "O_BINARY", 0),
            )
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(struct.pack(">I", len(request_json)))
                stream.write(request_json)
                stream.flush()
            parent_stdin = 0
            response_holder: list[bytes | BaseException] = []

            def read_response() -> None:
                try:
                    if output_stream is None:
                        raise IsolatedPluginWorkerError(
                            "isolated plugin output is unavailable"
                        )
                    body = _read_frame(
                        output_stream,
                        bundle.manifest.limits.max_response_bytes,
                    )
                    if output_stream.read(1):
                        raise IsolatedPluginWorkerError(
                            "isolated plugin emitted trailing output"
                        )
                    response_holder.append(body)
                except BaseException as exc:  # noqa: BLE001
                    response_holder.append(exc)

            reader = threading.Thread(target=read_response, daemon=True)
            reader.start()
            wait = int(
                _kernel32.WaitForSingleObject(
                    process.hProcess, bundle.manifest.limits.timeout_ms
                )
            )
            if wait == _WAIT_TIMEOUT:
                _kernel32.TerminateJobObject(wintypes.HANDLE(job), 124)
                _kernel32.WaitForSingleObject(process.hProcess, 5_000)
                self.last_terminal_monotonic = time.monotonic()
                raise IsolatedPluginWorkerError("isolated plugin timed out")
            if wait != _WAIT_OBJECT_0:
                raise IsolatedPluginWorkerError("isolated plugin wait failed")
            self.last_terminal_monotonic = time.monotonic()
            reader.join(timeout=5)
            if reader.is_alive() or len(response_holder) != 1 or isinstance(response_holder[0], BaseException):
                raise IsolatedPluginWorkerError("isolated plugin output failed")
            output = response_holder[0]
            if not isinstance(output, bytes):
                raise IsolatedPluginWorkerError("isolated plugin output failed")
            exit_code = wintypes.DWORD()
            if not _kernel32.GetExitCodeProcess(process.hProcess, ctypes.byref(exit_code)):
                raise IsolatedPluginWorkerError("isolated plugin exit status failed")
            if exit_code.value != 0:
                raise IsolatedPluginWorkerError(
                    "isolated plugin worker rejected the request "
                    f"(exit_code={exit_code.value})"
                )
            return output
        finally:
            if process_handle and job:
                _kernel32.TerminateJobObject(wintypes.HANDLE(job), 125)
            _close(parent_stdin)
            _close(parent_stdout)
            _close(child_stdin)
            _close(child_stdout)
            _close(thread_handle)
            _close(process_handle)
            _close(job)
            if output_stream is not None:
                output_stream.close()
            if attribute_list:
                _kernel32.DeleteProcThreadAttributeList(wintypes.LPVOID(attribute_list))
            if sid:
                _advapi32.FreeSid(wintypes.LPVOID(sid))
            if profile_created:
                _userenv.DeleteAppContainerProfile(moniker)
            shutil.rmtree(run_root, ignore_errors=True)


__all__ = [
    "WindowsAppContainerLauncher",
    "current_process_is_nachuan_appcontainer",
    "fence_current_process_singleton",
]
