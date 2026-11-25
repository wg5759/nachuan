"""Race-free Windows child Job manager for the installed channel Supervisor."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from threading import RLock

from gateway.installed_channel_supervisor import InstalledChildLaunch
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


class WindowsInstalledProcessError(RuntimeError):
    pass


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _CREATE_SUSPENDED = 0x00000004
    _CREATE_NO_WINDOW = 0x08000000
    _CREATE_UNICODE_ENVIRONMENT = 0x00000400
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _WAIT_OBJECT_0 = 0x00000000
    _WAIT_TIMEOUT = 0x00000102
    _STILL_ACTIVE = 259
    _DUPLICATE_SAME_ACCESS = 0x00000002
    _FORCE_TIMEOUT_SECONDS = 8.0
    _FORCE_TIMEOUT_MS = 8_000

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
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

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

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _kernel32.DuplicateHandle.restype = wintypes.BOOL
    _kernel32.GetCommandLineW.argtypes = []
    _kernel32.GetCommandLineW.restype = wintypes.LPWSTR
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _regular_nonreparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return bool(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and not (int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE)
    )


def _directory_nonreparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return bool(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and not (int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE)
    )


def _environment_block(environment) -> object:
    if os.name != "nt":
        raise WindowsInstalledProcessError("Windows environment block is unavailable")
    normalized: dict[str, str] = {}
    folded: set[str] = set()
    for raw_name, raw_value in environment.items():
        name = str(raw_name)
        value = str(raw_value)
        key = name.casefold()
        if (
            _ENVIRONMENT_NAME.fullmatch(name) is None
            or key in folded
            or "\0" in value
        ):
            raise WindowsInstalledProcessError("child environment is invalid")
        folded.add(key)
        normalized[name] = value
    text = "".join(
        f"{name}={normalized[name]}\0"
        for name in sorted(normalized, key=str.casefold)
    ) + "\0"
    return ctypes.create_unicode_buffer(text)  # type: ignore[name-defined]


def _command_line_digest(command_line: str) -> str:
    return hashlib.sha256(command_line.encode("utf-16-le", errors="strict")).hexdigest()


def _process_started_utc_ticks(handle: object) -> int:
    if os.name != "nt":
        raise WindowsInstalledProcessError("Windows process identity is unavailable")
    raw = getattr(handle, "value", handle)
    native = wintypes.HANDLE(int(raw))  # type: ignore[name-defined]
    creation = _FILETIME()  # type: ignore[name-defined]
    exit_time = _FILETIME()  # type: ignore[name-defined]
    kernel = _FILETIME()  # type: ignore[name-defined]
    user = _FILETIME()  # type: ignore[name-defined]
    if not _kernel32.GetProcessTimes(  # type: ignore[name-defined]
        native,
        ctypes.byref(creation),  # type: ignore[name-defined]
        ctypes.byref(exit_time),  # type: ignore[name-defined]
        ctypes.byref(kernel),  # type: ignore[name-defined]
        ctypes.byref(user),  # type: ignore[name-defined]
    ):
        raise WindowsInstalledProcessError("child creation time is unavailable")
    ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    if ticks <= 0:
        raise WindowsInstalledProcessError("child creation time is invalid")
    return ticks


def current_windows_process_receipt() -> InstalledChannelProcessReceipt:
    """Return an identity receipt for the current Supervisor process."""

    if os.name != "nt":
        raise WindowsInstalledProcessError("Windows process identity is unavailable")
    command_line = str(_kernel32.GetCommandLineW() or "")  # type: ignore[name-defined]
    if not command_line:
        raise WindowsInstalledProcessError("current command line is unavailable")
    return InstalledChannelProcessReceipt(
        pid=os.getpid(),
        started_utc_ticks=_process_started_utc_ticks(
            _kernel32.GetCurrentProcess()  # type: ignore[name-defined]
        ),
        command_line_sha256=_command_line_digest(command_line),
    )


class WindowsInstalledChildProcess:
    __slots__ = (
        "pid",
        "role",
        "_process_handle",
        "_thread_handle",
        "_assigned",
        "_resumed",
        "_exit_code",
        "_started_utc_ticks",
        "_command_line_sha256",
        "_owner",
    )

    def __init__(
        self,
        *,
        owner,
        role,
        pid,
        process_handle,
        thread_handle,
        started_utc_ticks,
        command_line_sha256,
    ) -> None:
        self.pid = int(pid)
        self.role = str(role)
        self._process_handle = int(process_handle)
        self._thread_handle = int(thread_handle)
        self._assigned = False
        self._resumed = False
        self._exit_code: int | None = None
        self._started_utc_ticks = int(started_utc_ticks)
        self._command_line_sha256 = str(command_line_sha256)
        self._owner = owner

    def poll(self) -> int | None:
        if self._exit_code is not None:
            return self._exit_code
        if not self._process_handle or os.name != "nt":
            return self._exit_code
        code = wintypes.DWORD()  # type: ignore[name-defined]
        if not _kernel32.GetExitCodeProcess(  # type: ignore[name-defined]
            wintypes.HANDLE(self._process_handle),  # type: ignore[name-defined]
            ctypes.byref(code),  # type: ignore[name-defined]
        ):
            raise WindowsInstalledProcessError("child exit status is unavailable")
        if int(code.value) == _STILL_ACTIVE:  # type: ignore[name-defined]
            return None
        self._exit_code = int(code.value)
        return self._exit_code

    def _close_handles(self) -> None:
        if os.name != "nt":
            return
        if self._thread_handle:
            if not _kernel32.CloseHandle(  # type: ignore[name-defined]
                wintypes.HANDLE(self._thread_handle)  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child thread handle close failed")
            self._thread_handle = 0
        if self._process_handle:
            if not _kernel32.CloseHandle(  # type: ignore[name-defined]
                wintypes.HANDLE(self._process_handle)  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child process handle close failed")
            self._process_handle = 0


class WindowsInstalledProcessManager:
    """Own one child-only Job; the Supervisor process is never assigned to it."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise WindowsInstalledProcessError("Windows Job Object is unavailable")
        raw = _kernel32.CreateJobObjectW(None, None)  # type: ignore[name-defined]
        self._job = int(raw or 0)
        self._children: dict[int, WindowsInstalledChildProcess] = {}
        self._closed = False
        self._force_requested = False
        self._state_lock = RLock()
        if not self._job:
            raise WindowsInstalledProcessError("child Job creation failed")
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()  # type: ignore[name-defined]
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE  # type: ignore[name-defined]
        if not _kernel32.SetInformationJobObject(  # type: ignore[name-defined]
            wintypes.HANDLE(self._job),  # type: ignore[name-defined]
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,  # type: ignore[name-defined]
            ctypes.byref(info),  # type: ignore[name-defined]
            ctypes.sizeof(info),  # type: ignore[name-defined]
        ):
            _kernel32.CloseHandle(wintypes.HANDLE(self._job))  # type: ignore[name-defined]
            self._job = 0
            raise WindowsInstalledProcessError("child Job limits failed")

    def _require_child(self, role, process) -> WindowsInstalledChildProcess:
        if (
            self._closed
            or not isinstance(process, WindowsInstalledChildProcess)
            or process._owner is not self
            or process.role != role
            or self._children.get(process.pid) is not process
        ):
            raise WindowsInstalledProcessError("child process identity is invalid")
        return process

    def spawn_suspended(
        self, role: str, launch: InstalledChildLaunch
    ) -> WindowsInstalledChildProcess:
        with self._state_lock:
            return self._spawn_suspended_locked(role, launch)

    def _spawn_suspended_locked(
        self, role: str, launch: InstalledChildLaunch
    ) -> WindowsInstalledChildProcess:
        if self._closed or self._force_requested or role not in {"engine", "weixin", "feishu"}:
            raise WindowsInstalledProcessError("child role is invalid")
        if not isinstance(launch, InstalledChildLaunch):
            raise WindowsInstalledProcessError("child launch is invalid")
        executable = Path(launch.command)
        cwd = Path(launch.cwd)
        if (
            not executable.is_absolute()
            or not _regular_nonreparse(executable)
            or not cwd.is_absolute()
            or not _directory_nonreparse(cwd)
        ):
            raise WindowsInstalledProcessError("child launch path is invalid")
        argv = [str(executable), *launch.args]
        command_line = subprocess.list2cmdline(argv)
        command = ctypes.create_unicode_buffer(command_line)  # type: ignore[name-defined]
        environment = _environment_block(launch.environment)
        startup = _STARTUPINFOW()  # type: ignore[name-defined]
        startup.cb = ctypes.sizeof(startup)  # type: ignore[name-defined]
        info = _PROCESS_INFORMATION()  # type: ignore[name-defined]
        if not _kernel32.CreateProcessW(  # type: ignore[name-defined]
            str(executable),
            command,
            None,
            None,
            False,
            _CREATE_SUSPENDED  # type: ignore[name-defined]
            | _CREATE_NO_WINDOW  # type: ignore[name-defined]
            | _CREATE_UNICODE_ENVIRONMENT,  # type: ignore[name-defined]
            environment,
            str(cwd),
            ctypes.byref(startup),  # type: ignore[name-defined]
            ctypes.byref(info),  # type: ignore[name-defined]
        ):
            raise WindowsInstalledProcessError("child suspended creation failed")
        try:
            started_utc_ticks = _process_started_utc_ticks(info.hProcess)
        except Exception:
            _kernel32.TerminateProcess(info.hProcess, 125)  # type: ignore[name-defined]
            _kernel32.CloseHandle(info.hThread)  # type: ignore[name-defined]
            _kernel32.CloseHandle(info.hProcess)  # type: ignore[name-defined]
            raise
        child = WindowsInstalledChildProcess(
            owner=self,
            role=role,
            pid=int(info.dwProcessId),
            process_handle=int(info.hProcess or 0),
            thread_handle=int(info.hThread or 0),
            started_utc_ticks=started_utc_ticks,
            command_line_sha256=_command_line_digest(command_line),
        )
        self._children[child.pid] = child
        return child

    def process_receipt(
        self, role: str, process: object
    ) -> InstalledChannelProcessReceipt:
        with self._state_lock:
            child = self._require_child(role, process)
            return InstalledChannelProcessReceipt(
                pid=child.pid,
                started_utc_ticks=child._started_utc_ticks,
                command_line_sha256=child._command_line_sha256,
            )

    def assign_to_job(self, role: str, process) -> None:
        with self._state_lock:
            child = self._require_child(role, process)
            if self._force_requested or child._assigned or child._resumed:
                raise WindowsInstalledProcessError("child assignment state is invalid")
            if not _kernel32.AssignProcessToJobObject(  # type: ignore[name-defined]
                wintypes.HANDLE(self._job),  # type: ignore[name-defined]
                wintypes.HANDLE(child._process_handle),  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child Job assignment failed")
            child._assigned = True

    def resume(self, role: str, process) -> None:
        with self._state_lock:
            child = self._require_child(role, process)
            if (
                self._force_requested
                or not child._assigned
                or child._resumed
                or not child._thread_handle
            ):
                raise WindowsInstalledProcessError("child resume state is invalid")
            previous = int(
                _kernel32.ResumeThread(  # type: ignore[name-defined]
                    wintypes.HANDLE(child._thread_handle)  # type: ignore[name-defined]
                )
            )
            if previous != 1:
                raise WindowsInstalledProcessError("child thread resume failed")
            child._resumed = True
            if not _kernel32.CloseHandle(  # type: ignore[name-defined]
                wintypes.HANDLE(child._thread_handle)  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child thread handle close failed")
            child._thread_handle = 0

    def wait_for_exit(self, role: str, process, *, timeout_ms: int) -> bool:
        with self._state_lock:
            child = self._require_child(role, process)
            if (
                isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int)
                or not 0 <= timeout_ms <= 120_000
                or not child._process_handle
            ):
                raise WindowsInstalledProcessError("child wait input is invalid")
            duplicate = wintypes.HANDLE()  # type: ignore[name-defined]
            current = _kernel32.GetCurrentProcess()  # type: ignore[name-defined]
            if not _kernel32.DuplicateHandle(  # type: ignore[name-defined]
                current,
                wintypes.HANDLE(child._process_handle),  # type: ignore[name-defined]
                current,
                ctypes.byref(duplicate),  # type: ignore[name-defined]
                0,
                False,
                _DUPLICATE_SAME_ACCESS,  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child wait handle is unavailable")
            proof_handle = int(duplicate.value or 0)
        try:
            wait = int(
                _kernel32.WaitForSingleObject(  # type: ignore[name-defined]
                    wintypes.HANDLE(proof_handle),  # type: ignore[name-defined]
                    timeout_ms,
                )
            )
            if wait == _WAIT_TIMEOUT:  # type: ignore[name-defined]
                return False
            if wait != _WAIT_OBJECT_0:  # type: ignore[name-defined]
                raise WindowsInstalledProcessError("child wait failed")
            code = wintypes.DWORD()  # type: ignore[name-defined]
            if not _kernel32.GetExitCodeProcess(  # type: ignore[name-defined]
                wintypes.HANDLE(proof_handle),  # type: ignore[name-defined]
                ctypes.byref(code),  # type: ignore[name-defined]
            ):
                raise WindowsInstalledProcessError("child wait proof is unavailable")
            if int(code.value) == _STILL_ACTIVE:  # type: ignore[name-defined]
                raise WindowsInstalledProcessError("child wait proof is invalid")
            with self._state_lock:
                child._exit_code = int(code.value)
            return True
        finally:
            if proof_handle:
                if not _kernel32.CloseHandle(  # type: ignore[name-defined]
                    wintypes.HANDLE(proof_handle)  # type: ignore[name-defined]
                ):
                    raise WindowsInstalledProcessError(
                        "child wait proof handle close failed"
                    )

    def alive_roles(self) -> tuple[str, ...]:
        with self._state_lock:
            if self._closed:
                return ()
            alive = []
            for child in self._children.values():
                if child.poll() is None:
                    alive.append(child.role)
            return tuple(alive)

    def _active_job_processes(self) -> int:
        if not self._job:
            return 0
        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()  # type: ignore[name-defined]
        returned = wintypes.DWORD()  # type: ignore[name-defined]
        if not _kernel32.QueryInformationJobObject(  # type: ignore[name-defined]
            wintypes.HANDLE(self._job),  # type: ignore[name-defined]
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,  # type: ignore[name-defined]
            ctypes.byref(info),  # type: ignore[name-defined]
            ctypes.sizeof(info),  # type: ignore[name-defined]
            ctypes.byref(returned),  # type: ignore[name-defined]
        ):
            raise WindowsInstalledProcessError("child Job state is unavailable")
        if int(returned.value) not in {0, ctypes.sizeof(info)}:  # type: ignore[name-defined]
            raise WindowsInstalledProcessError("child Job state is invalid")
        return int(info.ActiveProcesses)

    def is_quiescent(self) -> bool:
        with self._state_lock:
            if self._closed:
                return not self._children and not self._job
            return not self.alive_roles() and self._active_job_processes() == 0

    def wait_for_quiescence(self, *, timeout_ms: int) -> bool:
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or not 0 <= timeout_ms <= 120_000
        ):
            raise WindowsInstalledProcessError("child Job wait input is invalid")
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            if self.is_quiescent():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def close_quiescent(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            if not self.is_quiescent():
                raise WindowsInstalledProcessError("child process tree is not quiescent")
            for child in tuple(self._children.values()):
                child._close_handles()
            self._children.clear()
            if self._job:
                if not _kernel32.CloseHandle(  # type: ignore[name-defined]
                    wintypes.HANDLE(self._job)  # type: ignore[name-defined]
                ):
                    raise WindowsInstalledProcessError("child Job handle close failed")
                self._job = 0
            self._closed = True

    def terminate_job(self) -> None:
        force_requested_at = time.monotonic()
        with self._state_lock:
            if self._closed:
                return
            if self._job and not self._force_requested:
                if not _kernel32.TerminateJobObject(  # type: ignore[name-defined]
                    wintypes.HANDLE(self._job), 125  # type: ignore[name-defined]
                ):
                    raise WindowsInstalledProcessError("child Job termination failed")
                self._force_requested = True
            for child in tuple(self._children.values()):
                if child._process_handle and not child._assigned and child.poll() is None:
                    if not _kernel32.TerminateProcess(  # type: ignore[name-defined]
                            wintypes.HANDLE(child._process_handle), 125  # type: ignore[name-defined]
                    ):
                        raise WindowsInstalledProcessError(
                            "unassigned child termination failed"
                        )
            deadline = force_requested_at + _FORCE_TIMEOUT_SECONDS  # type: ignore[name-defined]
            for child in tuple(self._children.values()):
                if child._process_handle:
                    remaining_ms = max(
                        0,
                        min(
                            _FORCE_TIMEOUT_MS,  # type: ignore[name-defined]
                            int((deadline - time.monotonic()) * 1000),
                        ),
                    )
                    wait = int(
                        _kernel32.WaitForSingleObject(  # type: ignore[name-defined]
                            wintypes.HANDLE(child._process_handle),  # type: ignore[name-defined]
                            remaining_ms,
                        )
                    )
                    if wait != _WAIT_OBJECT_0 or child.poll() is None:  # type: ignore[name-defined]
                        raise WindowsInstalledProcessError(
                            "child process tree did not quiesce"
                        )
            if self._active_job_processes() != 0:
                raise WindowsInstalledProcessError("child process tree did not quiesce")
            self.close_quiescent()

    close = terminate_job

    def force_close(self) -> None:
        self.terminate_job()

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.terminate_job()

    def __del__(self) -> None:
        try:
            self.terminate_job()
        except Exception:
            pass


__all__ = [
    "WindowsInstalledChildProcess",
    "WindowsInstalledProcessError",
    "WindowsInstalledProcessManager",
    "current_windows_process_receipt",
]
