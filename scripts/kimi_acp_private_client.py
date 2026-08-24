"""Candidate-only private stdin client for Kimi Code's ACP subprocess.

This module deliberately does not integrate with ``scripts/xreview.sh``.  It is
the first, fake-server-tested transport slice for replacing ``kimi -p PROMPT``
with ACP v1 NDJSON over private pipes.  A result from this module is never a
formal review vote and never claims that a real Kimi model served the turn.
"""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from gateway.providers.attested_cli import matches_attestation


ACP_PROTOCOL_VERSION = 1
KIMI_K3_MODEL = "kimi-code/k3"
_CLIENT_INFO = {
    "name": "nachuan-private-review-candidate",
    "title": "Nachuan Private Review Candidate",
    "version": "0.1",
}
_MAX_HARD_MESSAGE_BYTES = 8 * 1024 * 1024
_MAX_HARD_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_HARD_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_HARD_TERMINATION_CONFIRMATION_SECONDS = 1.0
_SESSION_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z")
_SAFE_IGNORED_UPDATES = {
    "agent_thought_chunk",
    "available_commands_update",
    "plan",
    "usage_update",
}
_TOOL_UPDATES = {"tool_call", "tool_call_update"}


class KimiAcpReviewError(RuntimeError):
    """A prompt-redacted, stable failure from the candidate ACP client."""

    def __init__(self, code: str, *, process_exit_verified: bool = False) -> None:
        self.code = code
        self.process_exit_verified = process_exit_verified
        super().__init__(code)


@dataclass(frozen=True)
class KimiAcpReviewConfig:
    executable: Path
    executable_sha256: str
    review_snapshot: Path
    environment: Mapping[str, str] | None = None
    timeout_seconds: float = 60.0
    cleanup_grace_seconds: float = 1.0
    max_message_bytes: int = 5 * 1024 * 1024
    max_prompt_bytes: int = _MAX_HARD_PROMPT_BYTES
    max_output_bytes: int = _MAX_HARD_OUTPUT_BYTES


@dataclass(frozen=True)
class KimiAcpReviewResult:
    session_id: str
    text: str
    stop_reason: str
    requested_model: str
    process_id: int
    cleanup_method: str
    process_exit_verified: bool = True
    formal_vote_eligible: bool = False
    real_kimi_verified: bool = False


@dataclass(frozen=True)
class _WireEvent:
    kind: str
    value: object | None = None


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _validate_config(config: KimiAcpReviewConfig, prompt: str) -> tuple[Path, Path, bytes]:
    if not isinstance(prompt, str):
        raise KimiAcpReviewError("PROMPT_NOT_TEXT", process_exit_verified=True)
    try:
        prompt_bytes = prompt.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise KimiAcpReviewError(
            "PROMPT_INVALID_UTF8", process_exit_verified=True
        ) from None
    if not prompt_bytes or len(prompt_bytes) > int(config.max_prompt_bytes):
        raise KimiAcpReviewError(
            "PROMPT_SIZE_REJECTED", process_exit_verified=True
        )
    if not (256 <= int(config.max_message_bytes) <= _MAX_HARD_MESSAGE_BYTES):
        raise KimiAcpReviewError(
            "MESSAGE_BOUND_INVALID", process_exit_verified=True
        )
    if not (1 <= int(config.max_prompt_bytes) <= _MAX_HARD_PROMPT_BYTES):
        raise KimiAcpReviewError(
            "PROMPT_BOUND_INVALID", process_exit_verified=True
        )
    if not (1 <= int(config.max_output_bytes) <= _MAX_HARD_OUTPUT_BYTES):
        raise KimiAcpReviewError(
            "OUTPUT_BOUND_INVALID", process_exit_verified=True
        )
    if not (0.05 <= float(config.timeout_seconds) <= 600.0):
        raise KimiAcpReviewError("TIMEOUT_INVALID", process_exit_verified=True)
    if not (0.05 <= float(config.cleanup_grace_seconds) <= 10.0):
        raise KimiAcpReviewError(
            "CLEANUP_GRACE_INVALID", process_exit_verified=True
        )

    try:
        executable = Path(config.executable).resolve(strict=True)
        snapshot = Path(config.review_snapshot).resolve(strict=True)
    except OSError:
        raise KimiAcpReviewError(
            "REVIEW_SNAPSHOT_INVALID", process_exit_verified=True
        ) from None
    if not snapshot.is_dir() or not snapshot.is_absolute():
        raise KimiAcpReviewError(
            "REVIEW_SNAPSHOT_INVALID", process_exit_verified=True
        )
    return executable, snapshot, prompt_bytes


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
        0x00000001,  # FILE_SHARE_READ only: deny write/delete/replace races
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
def _pin_attested_executable(path: Path, expected_sha256: str) -> Iterator[Path]:
    """Keep the Windows file identity non-replaceable from hash through exit."""

    directory_handle = _open_windows_read_pin(path.parent, directory=True)
    file_handle = _open_windows_read_pin(path, directory=False)
    if os.name == "nt" and (directory_handle is None or file_handle is None):
        _close_windows_handle(file_handle)
        _close_windows_handle(directory_handle)
        raise KimiAcpReviewError("KIMI_BINARY_PIN_FAILED")
    try:
        if not matches_attestation(str(path), expected_sha256):
            raise KimiAcpReviewError("KIMI_BINARY_ATTESTATION_FAILED")
        if file_handle is not None:
            final_path = _windows_final_path(file_handle)
            if final_path != os.path.normcase(os.path.abspath(str(path))):
                raise KimiAcpReviewError("KIMI_BINARY_PIN_IDENTITY_MISMATCH")
        if directory_handle is not None:
            final_directory = _windows_final_path(directory_handle)
            if final_directory != os.path.normcase(os.path.abspath(str(path.parent))):
                raise KimiAcpReviewError("KIMI_BINARY_PIN_IDENTITY_MISMATCH")
        yield path
    finally:
        file_closed = _close_windows_handle(file_handle)
        directory_closed = _close_windows_handle(directory_handle)
        if not file_closed or not directory_closed:
            raise KimiAcpReviewError("KIMI_BINARY_PIN_RELEASE_FAILED")


def _validated_environment(source: Mapping[str, str] | None) -> dict[str, str]:
    raw = os.environ if source is None else source
    result: dict[str, str] = {}
    if len(raw) > 4096:
        raise KimiAcpReviewError(
            "CHILD_ENVIRONMENT_REJECTED", process_exit_verified=True
        )
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise KimiAcpReviewError(
                "CHILD_ENVIRONMENT_REJECTED", process_exit_verified=True
            )
        if not key or "\x00" in key or "=" in key or "\x00" in value:
            raise KimiAcpReviewError(
                "CHILD_ENVIRONMENT_REJECTED", process_exit_verified=True
            )
        result[key] = value
    return result


def _stdout_reader(
    stream: Any,
    events: queue.Queue[_WireEvent],
    max_message_bytes: int,
) -> None:
    try:
        while True:
            raw = stream.readline(max_message_bytes + 1)
            if not raw:
                events.put(_WireEvent("stdout_eof"))
                return
            if len(raw) > max_message_bytes or not raw.endswith(b"\n"):
                events.put(_WireEvent("stdout_oversize"))
                return
            events.put(_WireEvent("stdout", raw))
    except Exception:
        events.put(_WireEvent("stdout_failed"))


def _stderr_reader(stream: Any, events: queue.Queue[_WireEvent]) -> None:
    total = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            total += len(chunk)
            if total > _MAX_STDERR_BYTES:
                events.put(_WireEvent("stderr_oversize"))
                return
    except Exception:
        events.put(_WireEvent("stderr_failed"))


class _AcpConnection:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        events: queue.Queue[_WireEvent],
        *,
        deadline: float,
        max_message_bytes: int,
        max_output_bytes: int,
    ) -> None:
        self._process = process
        self._events = events
        self._deadline = deadline
        self._max_message_bytes = max_message_bytes
        self._max_output_bytes = max_output_bytes
        self._seen_response_ids: set[int] = set()
        self._next_request_id = 0
        self._session_id: str | None = None
        self._prompt_chunks: list[str] = []
        self._prompt_size = 0
        self._message_id: str | None = None
        self._message_id_presence: bool | None = None

    def request(self, method: str, params: Mapping[str, object]) -> object:
        request_id = self._next_request_id
        self._next_request_id += 1
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": dict(params),
            }
        )
        while True:
            message = self._receive()
            if "method" in message:
                self._handle_agent_message(message, active_method=method)
                continue
            response_id = message.get("id")
            if (
                isinstance(response_id, bool)
                or not isinstance(response_id, int)
                or response_id != request_id
                or response_id in self._seen_response_ids
            ):
                raise KimiAcpReviewError("JSONRPC_RESPONSE_ID_REJECTED")
            self._seen_response_ids.add(response_id)
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error:
                raise KimiAcpReviewError("JSONRPC_RESPONSE_SHAPE_REJECTED")
            if has_error:
                raise KimiAcpReviewError("ACP_AGENT_RPC_ERROR")
            return message["result"]

    def bind_session(self, session_id: str) -> None:
        self._session_id = session_id

    def prompt_text(self) -> str:
        text = "".join(self._prompt_chunks)
        if not text:
            raise KimiAcpReviewError("ACP_EMPTY_AGENT_MESSAGE")
        return text

    def _send(self, message: Mapping[str, object]) -> None:
        try:
            payload = json.dumps(
                message,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8", errors="strict") + b"\n"
        except (TypeError, ValueError, UnicodeEncodeError):
            raise KimiAcpReviewError("JSONRPC_REQUEST_ENCODING_FAILED") from None
        if len(payload) > self._max_message_bytes:
            raise KimiAcpReviewError("JSONRPC_REQUEST_SIZE_REJECTED")
        stream = self._process.stdin
        if stream is None:
            raise KimiAcpReviewError("ACP_STDIN_UNAVAILABLE")
        try:
            stream.write(payload)
            stream.flush()
        except (BrokenPipeError, OSError):
            raise KimiAcpReviewError("ACP_STDIN_WRITE_FAILED") from None

    def _receive(self) -> dict[str, Any]:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise KimiAcpReviewError("ACP_TIMEOUT")
        try:
            event = self._events.get(timeout=remaining)
        except queue.Empty:
            raise KimiAcpReviewError("ACP_TIMEOUT") from None
        if event.kind != "stdout":
            codes = {
                "stdout_eof": "ACP_STDOUT_EOF",
                "stdout_oversize": "ACP_MESSAGE_SIZE_REJECTED",
                "stdout_failed": "ACP_STDOUT_READ_FAILED",
                "stderr_oversize": "ACP_STDERR_SIZE_REJECTED",
                "stderr_failed": "ACP_STDERR_READ_FAILED",
            }
            raise KimiAcpReviewError(codes.get(event.kind, "ACP_TRANSPORT_FAILED"))
        raw = event.value
        if not isinstance(raw, bytes):
            raise KimiAcpReviewError("ACP_TRANSPORT_FAILED")
        try:
            text = raw[:-1].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise KimiAcpReviewError("ACP_MESSAGE_INVALID_UTF8") from None
        if "\n" in text or "\r" in text.rstrip("\r"):
            raise KimiAcpReviewError("ACP_EMBEDDED_NEWLINE_REJECTED")
        if text.endswith("\r"):
            text = text[:-1]
        try:
            message = json.loads(text, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, _DuplicateJsonKey, ValueError):
            raise KimiAcpReviewError("ACP_INVALID_JSON") from None
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise KimiAcpReviewError("JSONRPC_ENVELOPE_REJECTED")
        return message

    def _handle_agent_message(
        self, message: Mapping[str, Any], *, active_method: str
    ) -> None:
        method = message.get("method")
        if not isinstance(method, str):
            raise KimiAcpReviewError("JSONRPC_METHOD_REJECTED")
        if "id" in message:
            self._reject_reverse_request(message)
        if method != "session/update" or active_method != "session/prompt":
            raise KimiAcpReviewError("ACP_UNEXPECTED_NOTIFICATION")
        params = message.get("params")
        if not isinstance(params, dict) or params.get("sessionId") != self._session_id:
            raise KimiAcpReviewError("ACP_SESSION_BINDING_REJECTED")
        update = params.get("update")
        if not isinstance(update, dict):
            raise KimiAcpReviewError("ACP_UPDATE_SHAPE_REJECTED")
        update_type = update.get("sessionUpdate")
        if update_type in _TOOL_UPDATES:
            raise KimiAcpReviewError("ACP_TOOL_ACTIVITY_REJECTED")
        if update_type in _SAFE_IGNORED_UPDATES:
            return
        if update_type == "config_option_update":
            _validate_selected_model(update.get("configOptions"), KIMI_K3_MODEL)
            return
        if update_type != "agent_message_chunk":
            raise KimiAcpReviewError("ACP_UPDATE_TYPE_REJECTED")
        content = update.get("content")
        if not isinstance(content, dict) or content.get("type") != "text":
            raise KimiAcpReviewError("ACP_AGENT_MESSAGE_SHAPE_REJECTED")
        chunk = content.get("text")
        if not isinstance(chunk, str):
            raise KimiAcpReviewError("ACP_AGENT_MESSAGE_SHAPE_REJECTED")
        try:
            chunk_size = len(chunk.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise KimiAcpReviewError("ACP_AGENT_MESSAGE_INVALID_UTF8") from None
        self._prompt_size += chunk_size
        if self._prompt_size > self._max_output_bytes:
            raise KimiAcpReviewError("ACP_AGENT_OUTPUT_SIZE_REJECTED")
        has_message_id = "messageId" in update
        message_id = update.get("messageId")
        if self._message_id_presence is None:
            self._message_id_presence = has_message_id
        elif self._message_id_presence != has_message_id:
            raise KimiAcpReviewError("ACP_MESSAGE_ID_REJECTED")
        if has_message_id:
            if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
                raise KimiAcpReviewError("ACP_MESSAGE_ID_REJECTED")
            if self._message_id is None:
                self._message_id = message_id
            elif self._message_id != message_id:
                raise KimiAcpReviewError("ACP_MULTIPLE_AGENT_MESSAGES_REJECTED")
        self._prompt_chunks.append(chunk)

    def _reject_reverse_request(self, message: Mapping[str, Any]) -> None:
        method = message.get("method")
        request_id = message.get("id")
        if method == "session/request_permission":
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "cancelled"}},
                }
            )
            raise KimiAcpReviewError("ACP_PERMISSION_REQUEST_REJECTED")
        if isinstance(method, str) and (
            method.startswith("fs/") or method.startswith("terminal/")
        ):
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": "Method not supported by this client",
                    },
                }
            )
            raise KimiAcpReviewError("ACP_REVERSE_METHOD_REJECTED")
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )
        raise KimiAcpReviewError("ACP_REVERSE_METHOD_REJECTED")


def _find_model_option(config_options: object) -> dict[str, Any]:
    if not isinstance(config_options, list) or not (1 <= len(config_options) <= 64):
        raise KimiAcpReviewError("ACP_MODEL_OPTIONS_REJECTED")
    candidates: list[dict[str, Any]] = []
    for option in config_options:
        if not isinstance(option, dict):
            raise KimiAcpReviewError("ACP_MODEL_OPTIONS_REJECTED")
        if option.get("id") == "model" or option.get("category") == "model":
            candidates.append(option)
    if len(candidates) != 1:
        raise KimiAcpReviewError("ACP_MODEL_SELECTOR_AMBIGUOUS")
    option = candidates[0]
    if (
        not isinstance(option.get("id"), str)
        or not option["id"]
        or len(option["id"]) > 128
        or option.get("type") != "select"
    ):
        raise KimiAcpReviewError("ACP_MODEL_SELECTOR_REJECTED")
    choices = option.get("options")
    if not isinstance(choices, list) or not (1 <= len(choices) <= 256):
        raise KimiAcpReviewError("ACP_MODEL_OPTIONS_REJECTED")
    values: list[str] = []
    for choice in choices:
        if not isinstance(choice, dict) or not isinstance(choice.get("value"), str):
            raise KimiAcpReviewError("ACP_MODEL_OPTIONS_REJECTED")
        values.append(choice["value"])
    if len(values) != len(set(values)) or values.count(KIMI_K3_MODEL) != 1:
        raise KimiAcpReviewError("ACP_KIMI_K3_OPTION_REJECTED")
    return option


def _validate_selected_model(config_options: object, expected: str) -> dict[str, Any]:
    option = _find_model_option(config_options)
    if option.get("currentValue") != expected:
        raise KimiAcpReviewError("ACP_MODEL_SELECTION_NOT_CONFIRMED")
    return option


class _ProcessTreeGuard:
    """Own the OS primitive that contains every descendant of one ACP turn."""

    def __init__(
        self,
        *,
        windows_job: int | None = None,
        posix_process_group: int | None = None,
    ) -> None:
        self.windows_job = windows_job
        self.posix_process_group = posix_process_group
        self._closed = False

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        if self.windows_job is not None:
            return _close_windows_handle(self.windows_job)
        return True


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
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    raw_job = kernel32.CreateJobObjectW(None, None)
    job = int(raw_job or 0)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info)
    ):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(wintypes.HANDLE(job))
        raise OSError(error, "SetInformationJobObject failed")
    return job


def _assign_and_resume_suspended_windows_process(job: int, pid: int) -> None:
    """Assign a CREATE_SUSPENDED process before any of its code can execute."""

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
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # AssignProcessToJobObject requires PROCESS_SET_QUOTA | PROCESS_TERMINATE.
    process = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)
    if not process:
        raise OSError(ctypes.get_last_error(), "OpenProcess for job assignment failed")
    try:
        if not kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), process):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    finally:
        kernel32.CloseHandle(process)

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # SNAPTHREAD
    invalid_handle = ctypes.c_void_p(-1).value
    snapshot_value = int(snapshot or 0)
    if not snapshot_value or snapshot_value == invalid_handle:
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
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise OSError(ctypes.get_last_error(), "thread snapshot enumeration failed")
    finally:
        kernel32.CloseHandle(snapshot)
    if len(thread_ids) != 1:
        raise OSError("suspended ACP process did not have exactly one primary thread")

    thread = kernel32.OpenThread(0x0002, False, thread_ids[0])  # SUSPEND_RESUME
    if not thread:
        raise OSError(ctypes.get_last_error(), "OpenThread for resume failed")
    try:
        previous_suspend_count = int(kernel32.ResumeThread(thread))
        if previous_suspend_count != 1:
            raise OSError(
                ctypes.get_last_error(),
                "ACP primary thread suspend count was not exactly one",
            )
    finally:
        kernel32.CloseHandle(thread)


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
        raise OSError("QueryInformationJobObject returned an unexpected size")
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


def _posix_process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_posix_process_group_empty(process_group: int, deadline: float) -> bool:
    while _posix_process_group_exists(process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _spawn_acp_process(
    executable: Path,
    snapshot: Path,
    environment: Mapping[str, str],
) -> tuple[subprocess.Popen[bytes], _ProcessTreeGuard]:
    windows_job: int | None = None
    process: subprocess.Popen[bytes] | None = None
    if os.name == "nt":
        try:
            windows_job = _create_windows_kill_on_close_job()
            process = subprocess.Popen(
                [str(executable), "acp"],
                cwd=str(snapshot),
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                | 0x00000004,  # CREATE_SUSPENDED
            )
            _assign_and_resume_suspended_windows_process(windows_job, process.pid)
            return process, _ProcessTreeGuard(windows_job=windows_job)
        except BaseException:
            verified = process is None
            if windows_job is not None:
                job_termination_requested = False
                pipes_closed = True
                try:
                    _terminate_windows_job(windows_job)
                    job_termination_requested = True
                except BaseException:
                    pass
                try:
                    if process is not None and process.poll() is None:
                        # Assignment itself may have failed.  In that case the
                        # child is still suspended outside the empty job, so a
                        # direct TerminateProcess is also mandatory.
                        process.kill()
                    if process is not None:
                        process.wait(timeout=1.0)
                    verified = _wait_windows_job_empty(
                        windows_job, time.monotonic() + 1.0
                    ) and (process is None or process.poll() is not None)
                    verified = verified and job_termination_requested
                except BaseException:
                    verified = False
                finally:
                    if process is not None:
                        for stream in (process.stdin, process.stdout, process.stderr):
                            if stream is not None:
                                try:
                                    stream.close()
                                except OSError:
                                    pipes_closed = False
                    job_closed = _close_windows_handle(windows_job)
                    verified = verified and pipes_closed and job_closed
                    # Do not retain a Popen (and its pipe wrappers) in this
                    # exception frame's traceback.
                    process = None
            raise KimiAcpReviewError(
                "ACP_PROCESS_TREE_SETUP_FAILED",
                process_exit_verified=verified,
            ) from None

    try:
        process = subprocess.Popen(
            [str(executable), "acp"],
            cwd=str(snapshot),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            start_new_session=True,
        )
    except OSError:
        raise KimiAcpReviewError(
            "ACP_PROCESS_TREE_SETUP_FAILED", process_exit_verified=True
        ) from None
    return process, _ProcessTreeGuard(posix_process_group=process.pid)


def _cleanup_process(
    process: subprocess.Popen[bytes], guard: _ProcessTreeGuard, grace: float
) -> tuple[str, bool]:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass

    if guard.windows_job is not None:
        try:
            try:
                process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
            if process.poll() is not None and _windows_job_active_processes(
                guard.windows_job
            ) == 0:
                return "stdin-eof", True
            _terminate_windows_job(guard.windows_job)
            # ``cleanup_grace_seconds`` controls the cooperative EOF wait.  Once
            # TerminateJobObject has been issued, allow a small independent
            # verification window: a saturated Windows host can publish the
            # empty-job state later than a deliberately short cooperative grace.
            deadline = time.monotonic() + max(
                grace, _HARD_TERMINATION_CONFIRMATION_SECONDS
            )
            empty = _wait_windows_job_empty(guard.windows_job, deadline)
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                empty = False
            verified = empty and process.poll() is not None
            if not verified:
                raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
            return "job-terminated", True
        finally:
            if not guard.close():
                raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")

    process_group = guard.posix_process_group
    if process_group is None:
        raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    if process.poll() is not None and not _posix_process_group_exists(process_group):
        return "stdin-eof", True
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace
    if not _wait_posix_process_group_empty(process_group, deadline):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        if not _wait_posix_process_group_empty(process_group, deadline):
            raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
    remaining = max(0.0, deadline - time.monotonic())
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
    if process.poll() is None:
        raise KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
    return "process-group-terminated", True


def run_private_kimi_acp_review(
    config: KimiAcpReviewConfig, prompt: str
) -> KimiAcpReviewResult:
    """Run one candidate-only ACP v1 prompt over stdin against an attested CLI.

    The only child argv is ``[attested_executable, "acp"]``.  The prompt is
    serialized only into the child's anonymous stdin pipe.  This function does
    not prove the actually served upstream model, so its result is permanently
    ineligible for formal xreview voting.
    """

    executable, snapshot, _prompt_bytes = _validate_config(config, prompt)
    environment = _validated_environment(config.environment)
    process: subprocess.Popen[bytes] | None = None
    process_tree: _ProcessTreeGuard | None = None
    threads: list[threading.Thread] = []
    caught: BaseException | None = None
    completed: tuple[str, str, str, int] | None = None
    cleanup_method = "not-started"
    process_tree_exit_verified = True
    executable_pin = _pin_attested_executable(
        executable, config.executable_sha256
    )
    pin_active = False

    try:
        executable = executable_pin.__enter__()
        pin_active = True
        process, process_tree = _spawn_acp_process(
            executable, snapshot, environment
        )
        if process.stdout is None or process.stderr is None or process.stdin is None:
            raise KimiAcpReviewError("ACP_PIPE_SETUP_FAILED")
        events: queue.Queue[_WireEvent] = queue.Queue(maxsize=256)
        threads = [
            threading.Thread(
                target=_stdout_reader,
                args=(process.stdout, events, int(config.max_message_bytes)),
                name="nachuan-kimi-acp-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=_stderr_reader,
                args=(process.stderr, events),
                name="nachuan-kimi-acp-stderr",
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        connection = _AcpConnection(
            process,
            events,
            deadline=time.monotonic() + float(config.timeout_seconds),
            max_message_bytes=int(config.max_message_bytes),
            max_output_bytes=int(config.max_output_bytes),
        )

        initialized = connection.request(
            "initialize",
            {
                "protocolVersion": ACP_PROTOCOL_VERSION,
                "clientCapabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        if not isinstance(initialized, dict) or initialized.get("protocolVersion") != 1:
            raise KimiAcpReviewError("ACP_PROTOCOL_VERSION_REJECTED")
        agent_info = initialized.get("agentInfo")
        if (
            not isinstance(agent_info, dict)
            or agent_info.get("name") != "Kimi Code CLI"
            or not isinstance(agent_info.get("version"), str)
            or not agent_info["version"]
            or len(agent_info["version"]) > 128
        ):
            raise KimiAcpReviewError("ACP_AGENT_IDENTITY_REJECTED")

        created = connection.request(
            "session/new", {"cwd": str(snapshot), "mcpServers": []}
        )
        if not isinstance(created, dict):
            raise KimiAcpReviewError("ACP_SESSION_RESPONSE_REJECTED")
        session_id = created.get("sessionId")
        if not isinstance(session_id, str) or not _SESSION_ID_PATTERN.fullmatch(session_id):
            raise KimiAcpReviewError("ACP_SESSION_ID_REJECTED")
        connection.bind_session(session_id)
        model_option = _find_model_option(created.get("configOptions"))

        configured = connection.request(
            "session/set_config_option",
            {
                "sessionId": session_id,
                "configId": model_option["id"],
                "value": KIMI_K3_MODEL,
            },
        )
        if not isinstance(configured, dict):
            raise KimiAcpReviewError("ACP_MODEL_RESPONSE_REJECTED")
        selected = _validate_selected_model(
            configured.get("configOptions"), KIMI_K3_MODEL
        )
        if selected.get("id") != model_option.get("id"):
            raise KimiAcpReviewError("ACP_MODEL_SELECTOR_CHANGED")

        prompt_result = connection.request(
            "session/prompt",
            {
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": prompt}],
            },
        )
        if not isinstance(prompt_result, dict):
            raise KimiAcpReviewError("ACP_PROMPT_RESPONSE_REJECTED")
        stop_reason = prompt_result.get("stopReason")
        if stop_reason != "end_turn":
            raise KimiAcpReviewError("ACP_STOP_REASON_REJECTED")
        completed = (session_id, connection.prompt_text(), stop_reason, process.pid)
    except BaseException as exc:  # cleanup must also run for cancellation/interrupts
        caught = exc
        if process is None:
            process_tree_exit_verified = (
                exc.process_exit_verified
                if isinstance(exc, KimiAcpReviewError)
                and exc.code == "ACP_PROCESS_TREE_SETUP_FAILED"
                else True
            )
    finally:
        if process is not None and process_tree is not None:
            try:
                cleanup_method, process_tree_exit_verified = _cleanup_process(
                    process,
                    process_tree,
                    float(config.cleanup_grace_seconds),
                )
            except BaseException:
                caught = KimiAcpReviewError("ACP_PROCESS_CLEANUP_FAILED")
                process_tree_exit_verified = False
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            for thread in threads:
                thread.join(timeout=float(config.cleanup_grace_seconds))
        if pin_active:
            try:
                executable_pin.__exit__(None, None, None)
            except BaseException:
                caught = KimiAcpReviewError("KIMI_BINARY_PIN_RELEASE_FAILED")

    if caught is not None:
        if isinstance(caught, KimiAcpReviewError):
            caught.process_exit_verified = process_tree_exit_verified
            raise caught from None
        raise KimiAcpReviewError(
            "ACP_CLIENT_INTERNAL_FAILURE",
            process_exit_verified=process_tree_exit_verified,
        ) from None
    if (
        completed is None
        or process is None
        or process.poll() is None
        or not process_tree_exit_verified
    ):
        raise KimiAcpReviewError(
            "ACP_PROCESS_CLEANUP_FAILED", process_exit_verified=False
        )
    session_id, text, stop_reason, process_id = completed
    return KimiAcpReviewResult(
        session_id=session_id,
        text=text,
        stop_reason=stop_reason,
        requested_model=KIMI_K3_MODEL,
        process_id=process_id,
        cleanup_method=cleanup_method,
    )


__all__ = [
    "ACP_PROTOCOL_VERSION",
    "KIMI_K3_MODEL",
    "KimiAcpReviewConfig",
    "KimiAcpReviewError",
    "KimiAcpReviewResult",
    "run_private_kimi_acp_review",
]
