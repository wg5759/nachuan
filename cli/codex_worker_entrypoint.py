"""Contained helper for the official Codex CLI subscription adapter.

Parent Gateway -> this fixed helper -> attested Codex CLI.  Both request hops
carry prompts only through anonymous stdin pipes.  On Windows the helper is
assigned to a kill-on-close Job Object while still CREATE_SUSPENDED, so every
Codex descendant is contained before any helper code can execute.
"""

from __future__ import annotations

import json
import math
import os
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

# ``python -I <absolute-script>`` intentionally omits the script directory.
# Re-add only the immutable package root containing this helper.
if __package__ in {None, ""}:
    package_root = str(Path(__file__).resolve().parents[1])
    if package_root not in sys.path:
        sys.path.insert(0, package_root)

from gateway.codex_subscription_worker import (  # noqa: E402
    CodexSubscriptionError,
    CodexWorkerRequest,
    CodexWorkerResult,
    codex_cli_argv,
    codex_worker_environment,
)
from gateway.providers.attested_cli import (  # noqa: E402
    AttestedCliPinError,
    pin_attested_cli,
)
from gateway.secure_store import harden_restricted_windows_acl  # noqa: E402


_REQUEST_SCHEMA = "nachuan.codex-worker-request.v1"
_RESPONSE_SCHEMA = "nachuan.codex-worker-response.v1"
_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "operation",
        "executable_path",
        "executable_sha256",
        "prompt",
        "timeout_seconds",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "schema",
        "returncode",
        "stdout",
        "stderr",
        "process_tree_exit_verified",
    }
)
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
_MAX_STDOUT_BYTES = 4 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_HELPER_RESPONSE_BYTES = 6 * 1024 * 1024
_PROCESS_CLEANUP_GRACE_SECONDS = 2.0
_PRIVATE_DIRECTORY_CLEANUP_SECONDS = 2.0


@dataclass(frozen=True)
class CodexCliProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    cleanup_verified: bool


class CodexCliProcessError(RuntimeError):
    def __init__(self, code: str, *, cleanup_verified: bool) -> None:
        self.code = code
        self.cleanup_verified = cleanup_verified
        super().__init__(code)


CodexCliProcessRunner = Callable[..., CodexCliProcessResult]


class _DuplicateJsonKey(ValueError):
    pass


def _path_identity(path: Path) -> tuple[int, int, int]:
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    ):
        raise OSError("private directory identity rejected")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
    )


@contextmanager
def _private_directory(
    *,
    prefix: str,
    environment: Mapping[str, str],
) -> Iterator[Path]:
    """Create one identity-bound directory and retry transient Windows cleanup."""

    temp_parent_raw = str(
        environment.get("TEMP") or environment.get("TMP") or ""
    ).strip()
    temp_parent = Path(temp_parent_raw) if temp_parent_raw else None
    if temp_parent is not None and (
        not temp_parent.is_absolute() or not temp_parent.is_dir()
    ):
        raise CodexSubscriptionError("private_workdir_rejected")
    raw = Path(
        tempfile.mkdtemp(
            prefix=prefix,
            dir=str(temp_parent) if temp_parent is not None else None,
        )
    )
    expected_parent = raw.parent.resolve(strict=True)
    identity = _path_identity(raw)
    try:
        workdir = raw.resolve(strict=True)
        if temp_parent is not None and expected_parent != temp_parent.resolve(strict=True):
            raise OSError("private directory escaped its parent")
        if os.name == "nt":
            harden_restricted_windows_acl(workdir, directory=True)
        if _path_identity(workdir) != identity:
            raise OSError("private directory identity changed during ACL hardening")
        yield workdir
    except CodexSubscriptionError:
        raise
    except OSError:
        raise CodexSubscriptionError("private_workdir_rejected") from None
    finally:
        deadline = time.monotonic() + _PRIVATE_DIRECTORY_CLEANUP_SECONDS
        cleanup_error: BaseException | None = None
        while raw.exists():
            try:
                resolved = raw.resolve(strict=True)
                if (
                    resolved != raw
                    or resolved.parent.resolve(strict=True) != expected_parent
                    or _path_identity(resolved) != identity
                ):
                    raise OSError("private directory identity changed")
                shutil.rmtree(resolved)
                cleanup_error = None
                break
            except (OSError, PermissionError) as exc:
                cleanup_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.05, remaining))
        if raw.exists() or cleanup_error is not None:
            raise CodexSubscriptionError(
                "private_workdir_cleanup_failed",
                process_exit_verified=False,
            ) from None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _decode_strict_document(payload: bytes, *, maximum: int) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise ValueError("document size rejected")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("document encoding rejected") from None
    if text.startswith("\ufeff") or "\x00" in text:
        raise ValueError("document encoding rejected")
    try:
        value = json.loads(text, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("document JSON rejected") from None
    if not isinstance(value, dict):
        raise ValueError("document must be an object")
    return value


def _encode_request(request: CodexWorkerRequest) -> bytes:
    if not isinstance(request, CodexWorkerRequest):
        raise CodexSubscriptionError("helper_request_rejected")
    request.prompt_bytes()
    document = {
        "schema": _REQUEST_SCHEMA,
        "operation": request.operation,
        "executable_path": request.executable_path,
        "executable_sha256": request.executable_sha256,
        "prompt": request.prompt,
        "timeout_seconds": request.timeout_seconds,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > _MAX_REQUEST_BYTES:
        raise CodexSubscriptionError("helper_request_rejected")
    return payload


def _decode_request(payload: bytes) -> CodexWorkerRequest:
    try:
        document = _decode_strict_document(payload, maximum=_MAX_REQUEST_BYTES)
        if set(document) != _REQUEST_FIELDS or document.get("schema") != _REQUEST_SCHEMA:
            raise ValueError("request fields rejected")
        operation = document.get("operation")
        path = document.get("executable_path")
        digest = document.get("executable_sha256")
        prompt = document.get("prompt")
        timeout = document.get("timeout_seconds")
        if (
            operation not in {"status", "invoke", "logout"}
            or not isinstance(path, str)
            or not Path(path).is_absolute()
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            or not isinstance(prompt, str)
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0.05 <= float(timeout) <= 600.0
        ):
            raise ValueError("request value rejected")
        request = CodexWorkerRequest(
            operation=operation,
            executable_path=path,
            executable_sha256=digest,
            prompt=prompt,
            timeout_seconds=float(timeout),
        )
        request.prompt_bytes()
        return request
    except (OSError, TypeError, ValueError, CodexSubscriptionError):
        raise CodexSubscriptionError("helper_request_rejected") from None


def _encode_response(result: CodexWorkerResult) -> bytes:
    document = {
        "schema": _RESPONSE_SCHEMA,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "process_tree_exit_verified": result.process_tree_exit_verified,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > _MAX_HELPER_RESPONSE_BYTES:
        raise CodexSubscriptionError("helper_protocol_rejected")
    return payload


def _decode_response(payload: bytes) -> CodexWorkerResult:
    try:
        document = _decode_strict_document(
            payload,
            maximum=_MAX_HELPER_RESPONSE_BYTES,
        )
        if (
            set(document) != _RESPONSE_FIELDS
            or document.get("schema") != _RESPONSE_SCHEMA
        ):
            raise ValueError("response fields rejected")
        returncode = document.get("returncode")
        stdout = document.get("stdout")
        stderr = document.get("stderr")
        cleanup = document.get("process_tree_exit_verified")
        if (
            isinstance(returncode, bool)
            or not isinstance(returncode, int)
            or not -2**31 <= returncode < 2**31
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or not isinstance(cleanup, bool)
            or len(stdout.encode("utf-8", errors="strict")) > _MAX_STDOUT_BYTES
            or len(stderr.encode("utf-8", errors="strict")) > _MAX_STDERR_BYTES
            or "\x00" in stdout
            or "\x00" in stderr
        ):
            raise ValueError("response value rejected")
        return CodexWorkerResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            process_tree_exit_verified=cleanup,
        )
    except (UnicodeEncodeError, TypeError, ValueError):
        raise CodexSubscriptionError("helper_protocol_rejected") from None


def _default_cli_process_runner(
    argv: tuple[str, ...],
    *,
    stdin: bytes,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> CodexCliProcessResult:
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            creationflags=(
                int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if os.name == "nt"
                else 0
            ),
        )
    except OSError:
        raise CodexCliProcessError(
            "process_start_failed",
            cleanup_verified=True,
        ) from None
    try:
        stdout, stderr = process.communicate(
            input=stdin,
            timeout=float(timeout_seconds),
        )
    except subprocess.TimeoutExpired:
        cleanup_verified = False
        try:
            process.kill()
            process.communicate(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            cleanup_verified = process.poll() is not None
        except BaseException:
            cleanup_verified = False
        raise CodexCliProcessError(
            "timeout",
            cleanup_verified=cleanup_verified,
        ) from None
    except BaseException:
        cleanup_verified = False
        try:
            process.kill()
            process.communicate(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            cleanup_verified = process.poll() is not None
        except BaseException:
            cleanup_verified = False
        raise CodexCliProcessError(
            "process_io_failed",
            cleanup_verified=cleanup_verified,
        ) from None
    return CodexCliProcessResult(
        returncode=int(process.returncode),
        stdout=stdout,
        stderr=stderr,
        cleanup_verified=process.poll() is not None,
    )


def execute_codex_cli_request(
    request: CodexWorkerRequest,
    *,
    process_runner: CodexCliProcessRunner = _default_cli_process_runner,
    source_environment: Mapping[str, str] | None = None,
) -> CodexWorkerResult:
    """Execute one already pipe-delivered request inside an empty directory."""

    if not isinstance(request, CodexWorkerRequest):
        raise CodexSubscriptionError("helper_request_rejected")
    environment = codex_worker_environment(source_environment)
    try:
        with pin_attested_cli(
            request.executable_path,
            request.executable_sha256,
        ) as executable:
            with _private_directory(
                prefix="nachuan-codex-turn-",
                environment=environment,
            ) as workdir:
                if not workdir.is_dir() or any(workdir.iterdir()):
                    raise CodexSubscriptionError("private_workdir_rejected")
                argv = codex_cli_argv(request, workdir)
                stdin = request.prompt_bytes()
                try:
                    process_result = process_runner(
                        argv,
                        stdin=stdin,
                        cwd=workdir,
                        environment=environment,
                        timeout_seconds=float(request.timeout_seconds),
                    )
                except CodexCliProcessError as exc:
                    return CodexWorkerResult(
                        returncode=124 if exc.code == "timeout" else 70,
                        stdout="",
                        stderr=(
                            "worker_timeout"
                            if exc.code == "timeout"
                            else "worker_process_error"
                        ),
                        process_tree_exit_verified=exc.cleanup_verified,
                    )
                if not isinstance(process_result, CodexCliProcessResult):
                    raise CodexSubscriptionError("cli_result_rejected")
                if (
                    not isinstance(process_result.stdout, bytes)
                    or not isinstance(process_result.stderr, bytes)
                    or len(process_result.stdout) > _MAX_STDOUT_BYTES
                    or len(process_result.stderr) > _MAX_STDERR_BYTES
                ):
                    raise CodexSubscriptionError("cli_output_rejected")
                try:
                    stdout = process_result.stdout.decode("utf-8", errors="strict")
                    stderr = process_result.stderr.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    raise CodexSubscriptionError("cli_output_rejected") from None
                if "\x00" in stdout or "\x00" in stderr:
                    raise CodexSubscriptionError("cli_output_rejected")
                return CodexWorkerResult(
                    returncode=int(process_result.returncode),
                    stdout=stdout,
                    stderr=stderr,
                    process_tree_exit_verified=bool(
                        process_result.cleanup_verified
                    ),
                )
    except AttestedCliPinError as exc:
        code = (
            "binary_attestation_rejected"
            if exc.args and exc.args[0] == "binary_attestation_rejected"
            else "binary_pin_rejected"
        )
        raise CodexSubscriptionError(code) from None
    except OSError:
        raise CodexSubscriptionError("private_workdir_rejected") from None


def _close_windows_handle(handle: int | None) -> bool:
    if os.name != "nt" or handle is None:
        return True
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    return bool(kernel32.CloseHandle(ctypes.c_void_p(handle)))


def _create_windows_kill_on_close_job() -> int:
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
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

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    raw_job = kernel32.CreateJobObjectW(None, None)
    job = int(raw_job or 0)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        wintypes.HANDLE(job),
        9,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        error = ctypes.get_last_error()
        _close_windows_handle(job)
        raise OSError(error, "SetInformationJobObject failed")
    return job


def _assign_and_resume_windows_process(job: int, pid: int) -> None:
    import ctypes
    from ctypes import wintypes

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(THREADENTRY32),
    ]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(THREADENTRY32),
    ]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD

    process_handle = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)
    if not process_handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
        if not kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job),
            process_handle,
        ):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    finally:
        _close_windows_handle(int(process_handle))

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    snapshot_value = int(snapshot or 0)
    if (
        not snapshot_value
        or snapshot_value == ctypes.c_void_p(-1).value
    ):
        raise OSError(ctypes.get_last_error(), "thread snapshot failed")
    thread_ids: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while ok:
            if int(entry.th32OwnerProcessID) == pid:
                thread_ids.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            ok = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
        if ctypes.get_last_error() != 18:
            raise OSError(ctypes.get_last_error(), "thread enumeration failed")
    finally:
        _close_windows_handle(int(snapshot))
    if len(thread_ids) != 1:
        raise OSError("suspended helper did not have exactly one thread")
    thread_handle = kernel32.OpenThread(0x0002, False, thread_ids[0])
    if not thread_handle:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_count = int(kernel32.ResumeThread(thread_handle))
        if previous_count != 1:
            raise OSError("unexpected helper suspend count")
    finally:
        _close_windows_handle(int(thread_handle))


def _windows_job_active_processes(job: int) -> int:
    import ctypes
    from ctypes import wintypes

    class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
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

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    returned = wintypes.DWORD()
    if not kernel32.QueryInformationJobObject(
        wintypes.HANDLE(job),
        1,
        ctypes.byref(info),
        ctypes.sizeof(info),
        ctypes.byref(returned),
    ):
        raise OSError(ctypes.get_last_error(), "QueryInformationJobObject failed")
    if int(returned.value) != ctypes.sizeof(info):
        raise OSError("unexpected Job Object accounting size")
    return int(info.ActiveProcesses)


def _terminate_windows_job(job: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    if not kernel32.TerminateJobObject(wintypes.HANDLE(job), 1):
        raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")


def _wait_windows_job_empty(job: int, deadline: float) -> bool:
    while True:
        if _windows_job_active_processes(job) == 0:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _posix_process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_posix_group_empty(group: int, deadline: float) -> bool:
    while _posix_process_group_exists(group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _kill_contained_process_tree(
    process: subprocess.Popen[bytes],
    *,
    windows_job: int | None,
    posix_group: int | None,
) -> bool:
    deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
    if windows_job is not None:
        termination_requested = False
        try:
            _terminate_windows_job(windows_job)
            termination_requested = True
        except OSError:
            pass
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException:
            pass
        try:
            return (
                termination_requested
                and _wait_windows_job_empty(windows_job, deadline)
                and process.poll() is not None
            )
        except OSError:
            return False
    if posix_group is None:
        return False
    try:
        os.killpg(posix_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not _wait_posix_group_empty(posix_group, deadline):
        try:
            os.killpg(posix_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if not _wait_posix_group_empty(posix_group, deadline):
            return False
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None


def _contained_helper_transport(
    command: tuple[str, ...],
    request_bytes: bytes,
    *,
    environment: dict[str, str],
    timeout_seconds: float,
) -> bytes:
    """Run the fixed helper with whole-tree containment and bounded output."""

    windows_job: int | None = None
    posix_group: int | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        with _private_directory(
            prefix="nachuan-codex-helper-",
            environment=environment,
        ) as workdir:
            if any(workdir.iterdir()):
                raise CodexSubscriptionError("helper_private_workdir_rejected")
            if os.name == "nt":
                windows_job = _create_windows_kill_on_close_job()
                process = subprocess.Popen(
                    command,
                    cwd=str(workdir),
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=False,
                    bufsize=0,
                    creationflags=(
                        int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        | 0x00000004  # CREATE_SUSPENDED
                    ),
                )
                _assign_and_resume_windows_process(windows_job, process.pid)
            else:
                process = subprocess.Popen(
                    command,
                    cwd=str(workdir),
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=False,
                    bufsize=0,
                    start_new_session=True,
                )
                posix_group = process.pid
            try:
                stdout, stderr = process.communicate(
                    input=request_bytes,
                    timeout=float(timeout_seconds) + 5.0,
                )
            except subprocess.TimeoutExpired:
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise CodexSubscriptionError(
                    "helper_timeout",
                    process_exit_verified=verified,
                ) from None
            if (
                process.returncode != 0
                or stderr
                or len(stdout) > _MAX_HELPER_RESPONSE_BYTES
                or len(stderr) > _MAX_STDERR_BYTES
            ):
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise CodexSubscriptionError(
                    "helper_transport_rejected",
                    process_exit_verified=verified,
                )
            deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
            if windows_job is not None:
                empty = _wait_windows_job_empty(windows_job, deadline)
            else:
                empty = bool(
                    posix_group is not None
                    and _wait_posix_group_empty(posix_group, deadline)
                )
            if not empty or process.poll() is None:
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise CodexSubscriptionError(
                    "helper_process_tree_rejected",
                    process_exit_verified=verified,
                )
            return stdout
    except CodexSubscriptionError:
        raise
    except BaseException:
        verified = True
        if process is not None:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
        raise CodexSubscriptionError(
            "helper_transport_failed",
            process_exit_verified=verified,
        ) from None
    finally:
        if windows_job is not None and not _close_windows_handle(windows_job):
            raise CodexSubscriptionError(
                "helper_process_tree_rejected",
                process_exit_verified=False,
            )


def run_codex_worker_request(
    request: CodexWorkerRequest,
    *,
    source_environment: Mapping[str, str] | None = None,
) -> CodexWorkerResult:
    """Send one request to the fixed helper; no prompt or CLI path enters argv."""

    request_bytes = _encode_request(request)
    helper = Path(__file__).resolve(strict=True)
    command = (
        str(Path(sys.executable).resolve(strict=True)),
        "-I",
        str(helper),
        "--child",
    )
    response = _contained_helper_transport(
        command,
        request_bytes,
        environment=codex_worker_environment(source_environment),
        timeout_seconds=float(request.timeout_seconds),
    )
    return _decode_response(response)


def _child_main() -> int:
    payload = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    try:
        request = _decode_request(payload)
        result = execute_codex_cli_request(request)
    except CodexSubscriptionError as exc:
        result = CodexWorkerResult(
            returncode=70,
            stdout="",
            stderr=exc.code,
            process_tree_exit_verified=exc.process_exit_verified,
        )
    try:
        sys.stdout.buffer.write(_encode_response(result))
        sys.stdout.buffer.flush()
    except BaseException:
        return 70
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--child"]:
        raise SystemExit(64)
    raise SystemExit(_child_main())


__all__ = [
    "CodexCliProcessError",
    "CodexCliProcessResult",
    "execute_codex_cli_request",
    "run_codex_worker_request",
]
