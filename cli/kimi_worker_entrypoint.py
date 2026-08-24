"""Fixed contained helper for the Kimi Code subscription connector.

Gateway -> this fixed Python helper -> attested ``kimi.exe acp``.  The first
hop carries the executable identity and prompt only in anonymous stdin.  The
second hop carries the prompt only in ACP JSON-RPC stdin.  Neither hop places a
user prompt in a process command line.
"""

from __future__ import annotations

import json
import math
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol

# ``python -I <absolute-script>`` intentionally omits the script directory.
# Add only the package root that contains this fixed helper.
if __package__ in {None, ""}:
    package_root = str(Path(__file__).resolve().parents[1])
    if package_root not in sys.path:
        sys.path.insert(0, package_root)

from gateway.kimi_acp_product_protocol import (  # noqa: E402
    KimiAcpProductError,
    KimiAcpProtocolRequest,
    run_kimi_acp_product_protocol,
)
from gateway.kimi_subscription_worker import (  # noqa: E402
    KimiSubscriptionError,
    KimiWorkerRequest,
    KimiWorkerResult,
    is_stable_kimi_failure_code,
    kimi_cli_argv,
    kimi_worker_environment,
)
from gateway.providers.attested_cli import (  # noqa: E402
    AttestedCliPinError,
    pin_attested_cli,
)
from gateway.secure_store import harden_restricted_windows_acl  # noqa: E402


_REQUEST_SCHEMA = "nachuan.kimi-worker-request.v1"
_RESPONSE_SCHEMA = "nachuan.kimi-worker-response.v2"
_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "operation",
        "executable_path",
        "executable_sha256",
        "bound_version",
        "prompt",
        "timeout_seconds",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "schema",
        "returncode",
        "text",
        "session_id",
        "stop_reason",
        "actual_served_model",
        "tool_activity_observed",
        "process_tree_exit_verified",
        "failure_code",
    }
)
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
_MAX_RESPONSE_BYTES = 6 * 1024 * 1024
_MAX_TEXT_BYTES = 4 * 1024 * 1024
_MAX_SESSION_BYTES = 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_ACP_MESSAGE_BYTES = 5 * 1024 * 1024
_PROCESS_CLEANUP_GRACE_SECONDS = 2.0
_PRIVATE_DIRECTORY_CLEANUP_SECONDS = 2.0
_CANCELLATION_FLUSH_GRACE_SECONDS = 0.05
_CANCELLATION_POLL_SECONDS = 0.05
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


@dataclass(frozen=True)
class KimiCliProcessResult:
    returncode: int
    text: str
    session_id: str
    stop_reason: str
    actual_served_model: str | None
    tool_activity_observed: bool
    stderr: bytes
    cleanup_verified: bool


class KimiCliProcessError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        cleanup_verified: bool,
        failure_code: str | None = None,
    ) -> None:
        self.code = code
        self.cleanup_verified = cleanup_verified
        candidate_failure_code = failure_code if failure_code is not None else code
        self.failure_code = (
            candidate_failure_code
            if is_stable_kimi_failure_code(candidate_failure_code)
            else None
        )
        super().__init__(code)


class KimiCliProcessRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        prompt_bytes: bytes,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
    ) -> KimiCliProcessResult: ...


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _decode_document(payload: bytes, *, maximum: int) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise ValueError("document size rejected")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("document encoding rejected") from None
    if text.startswith("\ufeff") or "\x00" in text:
        raise ValueError("document encoding rejected")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("document JSON rejected") from None
    if not isinstance(value, dict):
        raise ValueError("document must be an object")
    return value


def _bounded_timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.05 <= float(value) <= 600.0
    ):
        raise ValueError("timeout rejected")
    return float(value)


def _encode_request(request: KimiWorkerRequest) -> bytes:
    if not isinstance(request, KimiWorkerRequest):
        raise KimiSubscriptionError("helper_request_rejected")
    request.prompt_bytes()
    document = {
        "schema": _REQUEST_SCHEMA,
        "operation": request.operation,
        "executable_path": request.executable_path,
        "executable_sha256": request.executable_sha256,
        "bound_version": request.bound_version,
        "prompt": request.prompt,
        "timeout_seconds": request.timeout_seconds,
    }
    try:
        payload = json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise KimiSubscriptionError("helper_request_rejected") from None
    if len(payload) > _MAX_REQUEST_BYTES:
        raise KimiSubscriptionError("helper_request_rejected")
    return payload


def _decode_request(payload: bytes) -> KimiWorkerRequest:
    try:
        document = _decode_document(payload, maximum=_MAX_REQUEST_BYTES)
        if set(document) != _REQUEST_FIELDS or document.get("schema") != _REQUEST_SCHEMA:
            raise ValueError("request schema rejected")
        operation = document.get("operation")
        executable_path = document.get("executable_path")
        executable_sha256 = document.get("executable_sha256")
        bound_version = document.get("bound_version")
        prompt = document.get("prompt")
        if (
            operation != "invoke"
            or not isinstance(executable_path, str)
            or not Path(executable_path).is_absolute()
            or len(executable_path) > 32_768
            or not isinstance(executable_sha256, str)
            or not _SHA256.fullmatch(executable_sha256)
            or not isinstance(bound_version, str)
            or not _VERSION.fullmatch(bound_version)
            or not isinstance(prompt, str)
        ):
            raise ValueError("request value rejected")
        request = KimiWorkerRequest(
            operation="invoke",
            executable_path=executable_path,
            executable_sha256=executable_sha256,
            bound_version=bound_version,
            prompt=prompt,
            timeout_seconds=_bounded_timeout(document.get("timeout_seconds")),
        )
        request.prompt_bytes()
        return request
    except (KimiSubscriptionError, TypeError, ValueError):
        raise KimiSubscriptionError("helper_request_rejected") from None


def _validated_worker_result(result: object) -> KimiWorkerResult:
    if not isinstance(result, KimiWorkerResult):
        raise ValueError("worker result rejected")
    returncode = result.returncode
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or not -(1 << 31) <= returncode < (1 << 31)
        or not isinstance(result.text, str)
        or not isinstance(result.session_id, str)
        or not isinstance(result.stop_reason, str)
        or (
            result.actual_served_model is not None
            and not isinstance(result.actual_served_model, str)
        )
        or not isinstance(result.tool_activity_observed, bool)
        or not isinstance(result.process_tree_exit_verified, bool)
        or (
            result.failure_code is not None
            and not is_stable_kimi_failure_code(result.failure_code)
        )
        or (returncode == 0 and result.failure_code is not None)
    ):
        raise ValueError("worker result rejected")
    try:
        text_size = len(result.text.encode("utf-8", errors="strict"))
        session_size = len(result.session_id.encode("utf-8", errors="strict"))
        stop_size = len(result.stop_reason.encode("utf-8", errors="strict"))
        actual_size = (
            0
            if result.actual_served_model is None
            else len(result.actual_served_model.encode("utf-8", errors="strict"))
        )
    except UnicodeEncodeError:
        raise ValueError("worker result encoding rejected") from None
    if (
        text_size > _MAX_TEXT_BYTES
        or session_size > _MAX_SESSION_BYTES
        or stop_size > 256
        or actual_size > 256
        or any(
            "\x00" in value or value.startswith("\ufeff")
            for value in (
                result.text,
                result.session_id,
                result.stop_reason,
                result.actual_served_model or "",
            )
        )
    ):
        raise ValueError("worker result bound rejected")
    return result


def _encode_response(result: KimiWorkerResult) -> bytes:
    try:
        valid = _validated_worker_result(result)
        payload = json.dumps(
            {
                "schema": _RESPONSE_SCHEMA,
                "returncode": valid.returncode,
                "text": valid.text,
                "session_id": valid.session_id,
                "stop_reason": valid.stop_reason,
                "actual_served_model": valid.actual_served_model,
                "tool_activity_observed": valid.tool_activity_observed,
                "process_tree_exit_verified": valid.process_tree_exit_verified,
                "failure_code": valid.failure_code,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise KimiSubscriptionError("helper_protocol_rejected") from None
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise KimiSubscriptionError("helper_protocol_rejected")
    return payload


def _decode_response(payload: bytes) -> KimiWorkerResult:
    try:
        document = _decode_document(payload, maximum=_MAX_RESPONSE_BYTES)
        if (
            set(document) != _RESPONSE_FIELDS
            or document.get("schema") != _RESPONSE_SCHEMA
        ):
            raise ValueError("response schema rejected")
        result = KimiWorkerResult(
            returncode=document.get("returncode"),  # type: ignore[arg-type]
            text=document.get("text"),  # type: ignore[arg-type]
            session_id=document.get("session_id"),  # type: ignore[arg-type]
            stop_reason=document.get("stop_reason"),  # type: ignore[arg-type]
            actual_served_model=document.get("actual_served_model"),  # type: ignore[arg-type]
            tool_activity_observed=document.get("tool_activity_observed"),  # type: ignore[arg-type]
            process_tree_exit_verified=document.get(
                "process_tree_exit_verified"
            ),  # type: ignore[arg-type]
            failure_code=document.get("failure_code"),  # type: ignore[arg-type]
        )
        return _validated_worker_result(result)
    except (TypeError, ValueError):
        raise KimiSubscriptionError("helper_protocol_rejected") from None


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
    temp_parent_raw = str(
        environment.get("TEMP") or environment.get("TMP") or ""
    ).strip()
    temp_parent = Path(temp_parent_raw) if temp_parent_raw else None
    if temp_parent is not None and (
        not temp_parent.is_absolute() or not temp_parent.is_dir()
    ):
        raise KimiSubscriptionError("private_workdir_rejected")
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
            raise OSError("private directory identity changed")
        yield workdir
    except KimiSubscriptionError:
        raise
    except OSError:
        raise KimiSubscriptionError("private_workdir_rejected") from None
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
            raise KimiSubscriptionError(
                "private_workdir_cleanup_failed",
                process_exit_verified=False,
            ) from None


def _close_process_pipes(process: Any) -> bool:
    closed = True
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, stream_name, None)
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                closed = False
    return closed


def _close_windows_handle(handle: int | None) -> bool:
    if os.name != "nt" or handle is None:
        return True
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return bool(kernel32.CloseHandle(wintypes.HANDLE(handle)))


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
            ("PerProcessTimeLimit", ctypes.c_longlong),
            ("PerJobTimeLimit", ctypes.c_longlong),
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
    info.BasicLimitInformation.LimitFlags = 0x00002000
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
    """Assign one still-suspended process, then resume its unique thread."""

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
    if not snapshot_value or snapshot_value == ctypes.c_void_p(-1).value:
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
        raise OSError("suspended process did not have exactly one thread")

    thread_handle = kernel32.OpenThread(0x0002, False, thread_ids[0])
    if not thread_handle:
        raise OSError(ctypes.get_last_error(), "OpenThread failed")
    try:
        previous_count = int(kernel32.ResumeThread(thread_handle))
        if previous_count != 1:
            raise OSError("unexpected process suspend count")
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
        raise OSError(ctypes.get_last_error(), "Job accounting failed")
    if int(returned.value) != ctypes.sizeof(info):
        raise OSError("unexpected Job accounting size")
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
        try:
            if _windows_job_active_processes(job) == 0:
                return True
        except OSError:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _posix_process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_posix_group_empty(process_group: int, deadline: float) -> bool:
    while _posix_process_group_exists(process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _kill_contained_process_tree(
    process: Any,
    *,
    windows_job: int | None,
    posix_group: int | None,
) -> bool:
    deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
    verified = True
    if windows_job is not None:
        try:
            _terminate_windows_job(windows_job)
        except OSError:
            verified = False
        try:
            if process.poll() is None:
                process.kill()
        except BaseException:
            verified = False
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException:
            verified = False
        verified = _wait_windows_job_empty(windows_job, deadline) and verified
    else:
        group = posix_group
        if group is not None:
            try:
                os.killpg(group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                verified = False
            if not _wait_posix_group_empty(group, time.monotonic() + 0.2):
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    verified = False
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException:
            verified = False
        if group is not None:
            verified = _wait_posix_group_empty(group, deadline) and verified
    try:
        verified = process.poll() is not None and verified
    except BaseException:
        verified = False
    return _close_process_pipes(process) and verified


def _wait_contained_tree_empty(
    process: Any,
    *,
    windows_job: int | None,
    posix_group: int | None,
    deadline: float,
) -> bool:
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except (subprocess.TimeoutExpired, TimeoutError):
        return False
    except BaseException:
        return False
    if process.poll() is None:
        return False
    if windows_job is not None:
        return _wait_windows_job_empty(windows_job, deadline)
    return bool(
        posix_group is not None
        and _wait_posix_group_empty(posix_group, deadline)
    )


@dataclass(frozen=True)
class _PipeEvent:
    kind: str
    payload: bytes | None = None


class _AcpPipeChannel:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        deadline: float,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise KimiCliProcessError(
                "pipe_setup_failed",
                cleanup_verified=False,
            )
        self.process = process
        self.deadline = deadline
        self.events: queue.Queue[_PipeEvent] = queue.Queue()
        self.stderr_chunks: list[bytes] = []
        self.stderr_size = 0
        self.stderr_oversize = False
        self.timed_out = False
        self.input_closed = False
        self.stdout_thread = threading.Thread(
            target=self._read_stdout,
            name="nachuan-kimi-product-stdout",
            daemon=True,
        )
        self.stderr_thread = threading.Thread(
            target=self._read_stderr,
            name="nachuan-kimi-product-stderr",
            daemon=True,
        )
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                raw = self.process.stdout.readline(_MAX_ACP_MESSAGE_BYTES + 1)
                if not raw:
                    self.events.put(_PipeEvent("eof"))
                    return
                if (
                    len(raw) > _MAX_ACP_MESSAGE_BYTES
                    or not raw.endswith(b"\n")
                ):
                    self.events.put(_PipeEvent("oversize"))
                    return
                self.events.put(_PipeEvent("line", raw))
        except BaseException:
            self.events.put(_PipeEvent("failed"))

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        try:
            while True:
                chunk = self.process.stderr.read(65536)
                if not chunk:
                    return
                remaining = _MAX_STDERR_BYTES + 1 - self.stderr_size
                if remaining > 0:
                    kept = chunk[:remaining]
                    self.stderr_chunks.append(kept)
                    self.stderr_size += len(kept)
                if len(chunk) > remaining or self.stderr_size > _MAX_STDERR_BYTES:
                    self.stderr_oversize = True
        except BaseException:
            self.stderr_oversize = True

    def _next(self) -> _PipeEvent:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.timed_out = True
            raise TimeoutError("ACP deadline elapsed")
        try:
            event = self.events.get(timeout=remaining)
        except queue.Empty:
            self.timed_out = True
            raise TimeoutError("ACP deadline elapsed") from None
        if event.kind == "line":
            return event
        if event.kind == "eof":
            raise EOFError
        if event.kind == "oversize":
            raise ValueError("ACP line exceeded bound")
        raise OSError("ACP stdout failed")

    def write_line(self, payload: bytes) -> None:
        if self.input_closed or not isinstance(payload, bytes):
            raise OSError("ACP stdin unavailable")
        assert self.process.stdin is not None
        self.process.stdin.write(payload)
        self.process.stdin.flush()

    def read_line(self) -> bytes:
        event = self._next()
        assert event.payload is not None
        return event.payload

    def close_input(self) -> None:
        if self.input_closed:
            return
        self.input_closed = True
        assert self.process.stdin is not None
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass

    def read_trailing_line(self) -> bytes | None:
        try:
            event = self._next()
        except EOFError:
            return None
        assert event.payload is not None
        return event.payload

    def finish_readers(self, deadline: float) -> None:
        for thread in (self.stdout_thread, self.stderr_thread):
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def stderr(self) -> bytes:
        return b"".join(self.stderr_chunks)


def _spawn_contained_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> tuple[subprocess.Popen[bytes], int | None, int | None]:
    windows_job: int | None = None
    process: subprocess.Popen[bytes] | None = None
    if os.name == "nt":
        try:
            windows_job = _create_windows_kill_on_close_job()
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
                    | 0x00000004
                ),
            )
            _assign_and_resume_windows_process(windows_job, process.pid)
            return process, windows_job, None
        except BaseException:
            verified = process is None
            if process is not None and windows_job is not None:
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=None,
                )
            elif process is not None:
                try:
                    process.kill()
                    process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
                    verified = process.poll() is not None
                except BaseException:
                    verified = False
                verified = _close_process_pipes(process) and verified
            if windows_job is not None:
                verified = _close_windows_handle(windows_job) and verified
            raise KimiCliProcessError(
                "process_tree_setup_failed",
                cleanup_verified=verified,
            ) from None
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
            start_new_session=True,
        )
    except OSError:
        raise KimiCliProcessError(
            "process_tree_setup_failed",
            cleanup_verified=True,
        ) from None
    return process, None, process.pid


def _run_acp_cli_process(
    argv: tuple[str, ...],
    *,
    prompt_bytes: bytes,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    bound_version: str,
) -> KimiCliProcessResult:
    process: subprocess.Popen[bytes] | None = None
    windows_job: int | None = None
    posix_group: int | None = None
    channel: _AcpPipeChannel | None = None
    try:
        process, windows_job, posix_group = _spawn_contained_process(
            argv,
            cwd=cwd,
            environment=environment,
        )
        channel = _AcpPipeChannel(
            process,
            deadline=time.monotonic() + float(timeout_seconds),
        )
        try:
            prompt = prompt_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise KimiCliProcessError(
                "prompt_encoding_rejected",
                cleanup_verified=False,
            ) from None
        try:
            protocol_result = run_kimi_acp_product_protocol(
                KimiAcpProtocolRequest(
                    prompt=prompt,
                    cwd=str(cwd),
                    bound_version=bound_version,
                ),
                channel,
            )
        except KimiAcpProductError as exc:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            raise KimiCliProcessError(
                "timeout" if channel.timed_out else "protocol_rejected",
                cleanup_verified=verified,
                failure_code=(
                    "auth_required"
                    if exc.code == "auth_required"
                    else None
                    if channel.timed_out
                    else "protocol_rejected"
                ),
            ) from None
        deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
        if not _wait_contained_tree_empty(
            process,
            windows_job=windows_job,
            posix_group=posix_group,
            deadline=deadline,
        ):
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            raise KimiCliProcessError(
                "process_tree_rejected",
                cleanup_verified=verified,
            )
        channel.finish_readers(deadline)
        if channel.stderr_oversize:
            raise KimiCliProcessError(
                "output_rejected",
                cleanup_verified=True,
            )
        return KimiCliProcessResult(
            returncode=int(process.returncode),
            text=protocol_result.text,
            session_id=protocol_result.session_id,
            stop_reason=protocol_result.stop_reason,
            actual_served_model=protocol_result.actual_served_model,
            tool_activity_observed=False,
            stderr=channel.stderr(),
            cleanup_verified=True,
        )
    except KimiCliProcessError:
        raise
    except BaseException:
        verified = True
        if process is not None:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
        raise KimiCliProcessError(
            "cancelled",
            cleanup_verified=verified,
        ) from None
    finally:
        if process is not None:
            _close_process_pipes(process)
        if windows_job is not None and not _close_windows_handle(windows_job):
            raise KimiCliProcessError(
                "process_tree_rejected",
                cleanup_verified=False,
            )


def execute_kimi_cli_request(
    request: KimiWorkerRequest,
    *,
    process_runner: KimiCliProcessRunner | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> KimiWorkerResult:
    """Execute one stdin-delivered request against a freshly re-pinned CLI."""

    if not isinstance(request, KimiWorkerRequest):
        raise KimiSubscriptionError("helper_request_rejected")
    prompt_bytes = request.prompt_bytes()
    environment = kimi_worker_environment(source_environment or {})
    runner: KimiCliProcessRunner
    if process_runner is None:

        def default_runner(
            argv: tuple[str, ...],
            *,
            prompt_bytes: bytes,
            cwd: Path,
            environment: dict[str, str],
            timeout_seconds: float,
        ) -> KimiCliProcessResult:
            return _run_acp_cli_process(
                argv,
                prompt_bytes=prompt_bytes,
                cwd=cwd,
                environment=environment,
                timeout_seconds=timeout_seconds,
                bound_version=request.bound_version,
            )

        runner = default_runner
    else:
        runner = process_runner

    try:
        with pin_attested_cli(
            request.executable_path,
            request.executable_sha256,
        ) as executable:
            with _private_directory(
                prefix="nachuan-kimi-turn-",
                environment=environment,
            ) as workdir:
                if not workdir.is_dir() or any(workdir.iterdir()):
                    raise KimiSubscriptionError("private_workdir_rejected")
                argv = kimi_cli_argv(request)
                if argv != (str(executable), "acp"):
                    raise KimiSubscriptionError("operation_rejected")
                try:
                    process_result = runner(
                        argv,
                        prompt_bytes=prompt_bytes,
                        cwd=workdir,
                        environment=environment,
                        timeout_seconds=float(request.timeout_seconds),
                    )
                except KimiCliProcessError as exc:
                    if exc.code == "output_rejected":
                        raise KimiSubscriptionError(
                            "cli_output_rejected",
                            process_exit_verified=exc.cleanup_verified,
                        ) from None
                    return KimiWorkerResult(
                        returncode=124 if exc.code == "timeout" else 70,
                        text="",
                        session_id="",
                        stop_reason="",
                        actual_served_model=None,
                        tool_activity_observed=False,
                        process_tree_exit_verified=exc.cleanup_verified,
                        failure_code=exc.failure_code,
                    )
                if not isinstance(process_result, KimiCliProcessResult):
                    raise KimiSubscriptionError("cli_result_rejected")
                if (
                    not isinstance(process_result.stderr, bytes)
                    or len(process_result.stderr) > _MAX_STDERR_BYTES
                    or not isinstance(process_result.cleanup_verified, bool)
                ):
                    raise KimiSubscriptionError("cli_output_rejected")
                result = KimiWorkerResult(
                    returncode=process_result.returncode,
                    text=process_result.text,
                    session_id=process_result.session_id,
                    stop_reason=process_result.stop_reason,
                    actual_served_model=process_result.actual_served_model,
                    tool_activity_observed=process_result.tool_activity_observed,
                    process_tree_exit_verified=process_result.cleanup_verified,
                )
                try:
                    return _validated_worker_result(result)
                except ValueError:
                    raise KimiSubscriptionError("cli_output_rejected") from None
    except AttestedCliPinError as exc:
        code = str(exc)
        raise KimiSubscriptionError(
            "binary_attestation_rejected"
            if "attestation" in code
            else "binary_pin_rejected"
        ) from None


def _contained_helper_transport(
    command: tuple[str, ...],
    request_bytes: bytes,
    *,
    environment: dict[str, str],
    timeout_seconds: float,
    cancellation_event: threading.Event | None = None,
) -> bytes:
    """Run the fixed helper inside a whole-tree containment boundary."""

    windows_job: int | None = None
    posix_group: int | None = None
    process: Any = None
    if cancellation_event is not None and cancellation_event.is_set():
        raise KimiSubscriptionError("helper_cancelled")
    try:
        with _private_directory(
            prefix="nachuan-kimi-helper-",
            environment=environment,
        ) as workdir:
            if any(workdir.iterdir()):
                raise KimiSubscriptionError("helper_private_workdir_rejected")
            if os.name == "nt":
                try:
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
                            | 0x00000004
                        ),
                    )
                    _assign_and_resume_windows_process(windows_job, process.pid)
                except BaseException:
                    verified = process is None
                    if process is not None and windows_job is not None:
                        verified = _kill_contained_process_tree(
                            process,
                            windows_job=windows_job,
                            posix_group=None,
                        )
                    elif process is not None:
                        try:
                            process.kill()
                            process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
                            verified = process.poll() is not None
                        except BaseException:
                            verified = False
                        verified = _close_process_pipes(process) and verified
                    raise KimiSubscriptionError(
                        "helper_process_tree_setup_failed",
                        process_exit_verified=verified,
                    ) from None
            else:
                try:
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
                except OSError:
                    raise KimiSubscriptionError(
                        "helper_process_tree_setup_failed"
                    ) from None
            try:
                transport_deadline = (
                    time.monotonic() + float(timeout_seconds) + 5.0
                )
                pending_input: bytes | None = request_bytes
                while True:
                    if (
                        cancellation_event is not None
                        and cancellation_event.is_set()
                    ):
                        verified = _kill_contained_process_tree(
                            process,
                            windows_job=windows_job,
                            posix_group=posix_group,
                        )
                        raise KimiSubscriptionError(
                            "helper_cancelled",
                            process_exit_verified=verified,
                        )
                    remaining = transport_deadline - time.monotonic()
                    if remaining <= 0:
                        verified = _kill_contained_process_tree(
                            process,
                            windows_job=windows_job,
                            posix_group=posix_group,
                        )
                        raise KimiSubscriptionError(
                            "helper_timeout",
                            process_exit_verified=verified,
                        )
                    wait_slice = (
                        min(_CANCELLATION_POLL_SECONDS, remaining)
                        if cancellation_event is not None
                        else remaining
                    )
                    try:
                        stdout, stderr = process.communicate(
                            input=pending_input,
                            timeout=wait_slice,
                        )
                        break
                    except subprocess.TimeoutExpired:
                        pending_input = None
                        continue
            except KimiSubscriptionError:
                raise
            except (KeyboardInterrupt, GeneratorExit):
                # The containment boundary is already active.  Give descendants
                # that were scheduled before cancellation one bounded quantum
                # to finish closing an in-flight diagnostic write, then tear
                # down the complete job/process group before returning.
                if process.poll() is None:
                    time.sleep(_CANCELLATION_FLUSH_GRACE_SECONDS)
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise KimiSubscriptionError(
                    "helper_cancelled",
                    process_exit_verified=verified,
                ) from None
            except BaseException:
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise KimiSubscriptionError(
                    "helper_transport_failed",
                    process_exit_verified=verified,
                ) from None
            if (
                process.returncode != 0
                or stderr
                or len(stdout) > _MAX_RESPONSE_BYTES
                or len(stderr) > _MAX_STDERR_BYTES
            ):
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise KimiSubscriptionError(
                    "helper_transport_rejected",
                    process_exit_verified=verified,
                )
            deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
            if not _wait_contained_tree_empty(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
                deadline=deadline,
            ):
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
                raise KimiSubscriptionError(
                    "helper_process_tree_rejected",
                    process_exit_verified=verified,
                )
            _close_process_pipes(process)
            return stdout
    except KimiSubscriptionError:
        raise
    except BaseException:
        verified = True
        if process is not None:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
        raise KimiSubscriptionError(
            "helper_transport_failed",
            process_exit_verified=verified,
        ) from None
    finally:
        if windows_job is not None and not _close_windows_handle(windows_job):
            raise KimiSubscriptionError(
                "helper_process_tree_rejected",
                process_exit_verified=False,
            )


def run_kimi_worker_request(
    request: KimiWorkerRequest,
    *,
    source_environment: Mapping[str, str] | None = None,
    cancellation_event: threading.Event | None = None,
) -> KimiWorkerResult:
    """Send one request to the fixed helper without putting secrets in argv."""

    request_bytes = _encode_request(request)
    helper = Path(__file__).resolve(strict=True)
    command = (
        str(Path(sys.executable).resolve(strict=True)),
        "-I",
        str(helper),
        "--child",
    )
    environment = kimi_worker_environment(source_environment or {})
    response = _contained_helper_transport(
        command,
        request_bytes,
        environment=environment,
        timeout_seconds=float(request.timeout_seconds),
        cancellation_event=cancellation_event,
    )
    return _decode_response(response)


def _child_main() -> int:
    payload = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    try:
        request = _decode_request(payload)
        result = execute_kimi_cli_request(
            request,
            source_environment=os.environ,
        )
    except KimiSubscriptionError as exc:
        result = KimiWorkerResult(
            returncode=70,
            text="",
            session_id="",
            stop_reason="",
            actual_served_model=None,
            tool_activity_observed=False,
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
    "KimiCliProcessError",
    "KimiCliProcessResult",
    "execute_kimi_cli_request",
    "run_kimi_worker_request",
]
