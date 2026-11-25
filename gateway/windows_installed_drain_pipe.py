"""Bounded Windows named-pipe transport for authenticated drain frames.

The transport is deliberately byte-only.  ``InstalledDrainProtocol`` remains
the authentication and replay authority; this module proves that one expected
parent process is talking to one expected child process over a local-only,
single-instance pipe.  It does not discover Root/config/vault state, register a
service, or enable the production ``NachuanCore`` runtime.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from types import MappingProxyType
from typing import Mapping

from gateway.installed_channel_drain import (
    InstalledDrainBinding,
    InstalledDrainCommand,
    InstalledDrainOperation,
    InstalledDrainProtocol,
    InstalledDrainRoleReceipt,
    derive_installed_drain_role_key,
)
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


_ROLES = frozenset({"engine", "weixin", "feishu"})
_SID = re.compile(r"S-1-(?:[0-9]+-){1,14}[0-9]+", re.IGNORECASE)
_MAX_FRAME_BYTES = 16_384
_MAX_TIMEOUT_MS = 30_000
_BOOTSTRAP_MAGIC = b"NACHUAN-DRAIN-KEY-V1\x00"
_BOOTSTRAP_ACK_MAGIC = b"NACHUAN-DRAIN-ACK-V1\x00"
_BOOTSTRAP_ACK_DOMAIN = b"nachuan-drain-key-bootstrap-ack-v1\x00"
_RETIRED_IO_LOCK = threading.RLock()
_RETIRED_IO: dict[object, tuple[int, object, object]] = {}


class WindowsInstalledDrainPipeError(RuntimeError):
    pass


class WindowsInstalledDrainPipeTimeout(WindowsInstalledDrainPipeError):
    def __init__(self, message: str, *, retry_safe: bool) -> None:
        if type(retry_safe) is not bool:
            raise ValueError("pipe timeout retry safety is invalid")
        super().__init__(message)
        self.retry_safe = retry_safe


def _positive_pid(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WindowsInstalledDrainPipeError(f"{field} is invalid")
    return value


def _timeout(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_TIMEOUT_MS
    ):
        raise WindowsInstalledDrainPipeError("pipe timeout is invalid")
    return value


def _frame(value: object) -> bytes:
    if (
        not isinstance(value, bytes)
        or not value
        or len(value) > _MAX_FRAME_BYTES
    ):
        raise WindowsInstalledDrainPipeError("pipe frame size is invalid")
    return value


def _remaining_timeout_ms(deadline: float) -> int:
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise WindowsInstalledDrainPipeError("pipe deadline expired")
    return min(_MAX_TIMEOUT_MS, remaining)


def installed_drain_pipe_name(*, binding: InstalledDrainBinding, role: str) -> str:
    if not isinstance(binding, InstalledDrainBinding) or role not in _ROLES:
        raise WindowsInstalledDrainPipeError("pipe identity is invalid")
    name = (
        rf"\\.\pipe\NachuanCore.Drain.v1.{binding.installation_id}."
        f"{binding.installation_epoch}.{binding.config_generation}."
        f"{binding.service_boot_id}.{role}"
    )
    if len(name) > 240:
        raise WindowsInstalledDrainPipeError("pipe name is invalid")
    return name


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _PIPE_ACCESS_DUPLEX = 0x00000003
    _FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    _FILE_FLAG_OVERLAPPED = 0x40000000
    _PIPE_TYPE_MESSAGE = 0x00000004
    _PIPE_READMODE_MESSAGE = 0x00000002
    _PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _ERROR_MORE_DATA = 234
    _ERROR_INSUFFICIENT_BUFFER = 122
    _ERROR_PIPE_CONNECTED = 535
    _ERROR_IO_PENDING = 997
    _ERROR_OPERATION_ABORTED = 995
    _ERROR_IO_INCOMPLETE = 996
    _ERROR_PIPE_NOT_CONNECTED = 233
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258
    _SDDL_REVISION_1 = 1
    _DACL_SECURITY_INFORMATION = 0x00000004
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _kernel32.CreateNamedPipeW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
    )
    _kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    _kernel32.ConnectNamedPipe.argtypes = (wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED))
    _kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    _kernel32.DisconnectNamedPipe.argtypes = (wintypes.HANDLE,)
    _kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    _kernel32.WaitNamedPipeW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD)
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL
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
    _kernel32.SetNamedPipeHandleState.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    _kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL
    _kernel32.GetNamedPipeClientProcessId.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    )
    _kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    _kernel32.GetNamedPipeServerProcessId.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    )
    _kernel32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_OVERLAPPED),
    )
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_OVERLAPPED),
    )
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.CreateEventW.argtypes = (
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    )
    _kernel32.CreateEventW.restype = wintypes.HANDLE
    _kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.GetOverlappedResult.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    )
    _kernel32.GetOverlappedResult.restype = wintypes.BOOL
    _kernel32.CancelIoEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID)
    _kernel32.CancelIoEx.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.GetKernelObjectSecurity.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.GetKernelObjectSecurity.restype = wintypes.BOOL
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL


def _require_windows() -> None:
    if os.name != "nt":
        raise WindowsInstalledDrainPipeError("Windows named pipe is unavailable")


def _close_handle(handle: int, field: str) -> None:
    if handle and not _kernel32.CloseHandle(wintypes.HANDLE(handle)):  # type: ignore[name-defined]
        raise WindowsInstalledDrainPipeError(f"{field} close failed")


def _new_event() -> tuple[int, object]:
    _collect_retired_io()
    raw = _kernel32.CreateEventW(None, True, False, None)  # type: ignore[name-defined]
    handle = int(raw or 0)
    if not handle:
        raise WindowsInstalledDrainPipeError("pipe event creation failed")
    overlapped = _OVERLAPPED()  # type: ignore[name-defined]
    overlapped.hEvent = wintypes.HANDLE(handle)  # type: ignore[name-defined]
    return handle, overlapped


def _retire_pending_io(event_handle: int, overlapped, buffer) -> None:
    """Keep native buffers alive without extending the caller's I/O deadline.

    CancelIoEx only requests cancellation. An unfinished operation still owns
    its OVERLAPPED, buffer and event. A poisoned connection must never reuse
    them; nonblocking collection releases them only after the exact event
    signals. Incomplete or failed cleanup retains them until a later transport
    operation/close or process exit. Never start a thread on the timeout path:
    thread startup itself can block under host pressure.
    """
    overlapped._event_cleanup_deferred = True
    retirement = object()
    with _RETIRED_IO_LOCK:
        # Native handle numbers are reusable; keep a unique retirement identity.
        _RETIRED_IO[retirement] = (event_handle, overlapped, buffer)


def _collect_retired_io() -> None:
    with _RETIRED_IO_LOCK:
        for retirement, (event_handle, _overlapped, _buffer) in list(_RETIRED_IO.items()):
            try:
                ready = _kernel32.WaitForSingleObject(  # type: ignore[name-defined]
                    wintypes.HANDLE(event_handle), 0  # type: ignore[name-defined]
                )
                if ready != _WAIT_OBJECT_0:  # type: ignore[name-defined]
                    continue
                _close_handle(event_handle, "retired pipe event")
            except Exception:
                continue
            del _RETIRED_IO[retirement]


def _finish_io_event(event_handle: int, overlapped) -> None:
    if not getattr(overlapped, "_event_cleanup_deferred", False):
        _close_handle(event_handle, "pipe event")
    _collect_retired_io()


def _wait_pending(
    handle: int,
    event_handle: int,
    overlapped,
    *,
    timeout_ms: int,
    operation: str,
    buffer=None,
) -> int:
    wait = int(
        _kernel32.WaitForSingleObject(  # type: ignore[name-defined]
            wintypes.HANDLE(event_handle), timeout_ms  # type: ignore[name-defined]
        )
    )
    if wait != _WAIT_OBJECT_0:  # type: ignore[name-defined]
        _kernel32.CancelIoEx(  # type: ignore[name-defined]
            wintypes.HANDLE(handle), ctypes.byref(overlapped)  # type: ignore[name-defined]
        )
    transferred = wintypes.DWORD()  # type: ignore[name-defined]
    completed = _kernel32.GetOverlappedResult(  # type: ignore[name-defined]
        wintypes.HANDLE(handle),  # type: ignore[name-defined]
        ctypes.byref(overlapped),  # type: ignore[name-defined]
        ctypes.byref(transferred),  # type: ignore[name-defined]
        False,
    )
    if completed:
        # Cancellation can lose to completion: do not drop an already-read frame.
        return int(transferred.value)
    error = ctypes.get_last_error()  # type: ignore[name-defined]
    if error == _ERROR_IO_INCOMPLETE:  # type: ignore[name-defined]
        if wait == _WAIT_OBJECT_0:  # type: ignore[name-defined]
            _kernel32.CancelIoEx(  # type: ignore[name-defined]
                wintypes.HANDLE(handle), ctypes.byref(overlapped)  # type: ignore[name-defined]
            )
        _retire_pending_io(event_handle, overlapped, buffer)
        raise WindowsInstalledDrainPipeTimeout(
            f"pipe {operation} cancellation pending", retry_safe=False
        )
    if wait == _WAIT_TIMEOUT:  # type: ignore[name-defined]
        raise WindowsInstalledDrainPipeTimeout(
            f"pipe {operation} timed out",
            retry_safe=(
                operation == "read"
                and error == _ERROR_OPERATION_ABORTED  # type: ignore[name-defined]
                and transferred.value == 0
            ),
        )
    if wait != _WAIT_OBJECT_0:  # type: ignore[name-defined]
        raise WindowsInstalledDrainPipeError(f"pipe {operation} wait failed")
    if error == _ERROR_MORE_DATA:  # type: ignore[name-defined]
        raise WindowsInstalledDrainPipeError("pipe frame size is invalid")
    raise WindowsInstalledDrainPipeError(f"pipe {operation} failed")


class WindowsInstalledDrainPipeConnection:
    def __init__(self, *, handle: int, disconnect_on_close: bool) -> None:
        _require_windows()
        if not handle:
            raise WindowsInstalledDrainPipeError("pipe handle is invalid")
        self._handle = handle
        self._disconnect_on_close = disconnect_on_close
        self._lock = threading.RLock()
        self._bootstrap_complete = False
        self._poisoned = False

    @staticmethod
    def validate_frame(frame: bytes) -> bytes:
        return _frame(frame)

    def _require_handle(self) -> int:
        if not self._handle:
            raise WindowsInstalledDrainPipeError("pipe connection is closed")
        if self._poisoned:
            raise WindowsInstalledDrainPipeError("pipe connection is poisoned")
        return self._handle

    @property
    def bootstrap_complete(self) -> bool:
        with self._lock:
            return self._bootstrap_complete

    def bootstrap_parent(self, role_key: bytes, *, timeout_ms: int) -> None:
        if (
            not self._disconnect_on_close
            or not isinstance(role_key, bytes)
            or len(role_key) != 32
            or not any(role_key)
        ):
            raise WindowsInstalledDrainPipeError("pipe role-key bootstrap is invalid")
        with self._lock:
            self._require_handle()
            if self._bootstrap_complete:
                raise WindowsInstalledDrainPipeError("pipe role-key bootstrap was repeated")
            try:
                deadline = time.monotonic() + _timeout(timeout_ms) / 1000.0
                challenge = secrets.token_bytes(32)
                self.send(
                    _BOOTSTRAP_MAGIC + challenge + role_key,
                    timeout_ms=_remaining_timeout_ms(deadline),
                )
                acknowledgement = self.receive(
                    timeout_ms=_remaining_timeout_ms(deadline)
                )
                expected = hmac.new(
                    role_key,
                    _BOOTSTRAP_ACK_DOMAIN + challenge,
                    hashlib.sha256,
                ).digest()
                if (
                    len(acknowledgement) != len(_BOOTSTRAP_ACK_MAGIC) + len(expected)
                    or not acknowledgement.startswith(_BOOTSTRAP_ACK_MAGIC)
                    or not hmac.compare_digest(
                        acknowledgement[len(_BOOTSTRAP_ACK_MAGIC) :], expected
                    )
                ):
                    raise WindowsInstalledDrainPipeError(
                        "pipe role-key acknowledgement is invalid"
                    )
                self._bootstrap_complete = True
            except WindowsInstalledDrainPipeTimeout as exc:
                self._poisoned = True
                raise
            except Exception:
                self._poisoned = True
                raise
        return None

    def bootstrap_child(self, *, timeout_ms: int) -> bytes:
        if self._disconnect_on_close:
            raise WindowsInstalledDrainPipeError("pipe role-key bootstrap is invalid")
        with self._lock:
            self._require_handle()
            if self._bootstrap_complete:
                raise WindowsInstalledDrainPipeError("pipe role-key bootstrap was repeated")
            try:
                deadline = time.monotonic() + _timeout(timeout_ms) / 1000.0
                frame = self.receive(timeout_ms=_remaining_timeout_ms(deadline))
                expected_length = len(_BOOTSTRAP_MAGIC) + 64
                if len(frame) != expected_length or not frame.startswith(_BOOTSTRAP_MAGIC):
                    raise WindowsInstalledDrainPipeError("pipe role-key frame is invalid")
                challenge_start = len(_BOOTSTRAP_MAGIC)
                challenge = frame[challenge_start : challenge_start + 32]
                role_key = frame[challenge_start + 32 :]
                if len(role_key) != 32 or not any(role_key):
                    raise WindowsInstalledDrainPipeError("pipe role key is invalid")
                acknowledgement = hmac.new(
                    role_key,
                    _BOOTSTRAP_ACK_DOMAIN + challenge,
                    hashlib.sha256,
                ).digest()
                self.send(
                    _BOOTSTRAP_ACK_MAGIC + acknowledgement,
                    timeout_ms=_remaining_timeout_ms(deadline),
                )
                self._bootstrap_complete = True
                return role_key
            except WindowsInstalledDrainPipeTimeout as exc:
                self._poisoned = True
                raise
            except Exception:
                self._poisoned = True
                raise

    def send(self, frame: bytes, *, timeout_ms: int) -> None:
        payload = _frame(frame)
        timeout = _timeout(timeout_ms)
        with self._lock:
            handle = self._require_handle()
            event_handle, overlapped = _new_event()
            try:
                buffer = ctypes.create_string_buffer(payload)  # type: ignore[name-defined]
                transferred = wintypes.DWORD()  # type: ignore[name-defined]
                completed = _kernel32.WriteFile(  # type: ignore[name-defined]
                    wintypes.HANDLE(handle),  # type: ignore[name-defined]
                    buffer,
                    len(payload),
                    ctypes.byref(transferred),  # type: ignore[name-defined]
                    ctypes.byref(overlapped),  # type: ignore[name-defined]
                )
                if completed:
                    count = int(transferred.value)
                elif ctypes.get_last_error() == _ERROR_IO_PENDING:  # type: ignore[name-defined]
                    count = _wait_pending(
                        handle,
                        event_handle,
                        overlapped,
                        timeout_ms=timeout,
                        operation="write",
                        buffer=buffer,
                    )
                else:
                    raise WindowsInstalledDrainPipeError("pipe write failed")
                if count != len(payload):
                    raise WindowsInstalledDrainPipeError("pipe write was incomplete")
            except WindowsInstalledDrainPipeTimeout as exc:
                if not exc.retry_safe:
                    self._poisoned = True
                raise
            except Exception:
                self._poisoned = True
                raise
            finally:
                _finish_io_event(event_handle, overlapped)
        return None

    def receive(self, *, timeout_ms: int) -> bytes:
        timeout = _timeout(timeout_ms)
        with self._lock:
            handle = self._require_handle()
            event_handle, overlapped = _new_event()
            try:
                buffer = ctypes.create_string_buffer(_MAX_FRAME_BYTES)  # type: ignore[name-defined]
                transferred = wintypes.DWORD()  # type: ignore[name-defined]
                completed = _kernel32.ReadFile(  # type: ignore[name-defined]
                    wintypes.HANDLE(handle),  # type: ignore[name-defined]
                    buffer,
                    _MAX_FRAME_BYTES,
                    ctypes.byref(transferred),  # type: ignore[name-defined]
                    ctypes.byref(overlapped),  # type: ignore[name-defined]
                )
                if completed:
                    count = int(transferred.value)
                else:
                    error = ctypes.get_last_error()  # type: ignore[name-defined]
                    if error == _ERROR_MORE_DATA:  # type: ignore[name-defined]
                        raise WindowsInstalledDrainPipeError("pipe frame size is invalid")
                    if error != _ERROR_IO_PENDING:  # type: ignore[name-defined]
                        raise WindowsInstalledDrainPipeError("pipe read failed")
                    count = _wait_pending(
                        handle,
                        event_handle,
                        overlapped,
                        timeout_ms=timeout,
                        operation="read",
                        buffer=buffer,
                    )
                if not 1 <= count <= _MAX_FRAME_BYTES:
                    raise WindowsInstalledDrainPipeError("pipe frame size is invalid")
                return bytes(buffer.raw[:count])
            except WindowsInstalledDrainPipeTimeout as exc:
                if not exc.retry_safe:
                    self._poisoned = True
                raise
            except Exception:
                self._poisoned = True
                raise
            finally:
                _finish_io_event(event_handle, overlapped)

    def abort(self) -> None:
        with self._lock:
            self._poisoned = True
            self.close()
        return None

    def close(self) -> None:
        with self._lock:
            handle = self._handle
            if not handle:
                return None
            _kernel32.CancelIoEx(wintypes.HANDLE(handle), None)  # type: ignore[name-defined]
            if self._disconnect_on_close:
                if not _kernel32.DisconnectNamedPipe(  # type: ignore[name-defined]
                    wintypes.HANDLE(handle)  # type: ignore[name-defined]
                ):
                    error = ctypes.get_last_error()  # type: ignore[name-defined]
                    if error != _ERROR_PIPE_NOT_CONNECTED:  # type: ignore[name-defined]
                        raise WindowsInstalledDrainPipeError("pipe disconnect failed")
            _close_handle(handle, "pipe")
            self._handle = 0
            _collect_retired_io()
        return None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


class WindowsInstalledDrainPipeServer:
    def __init__(
        self,
        *,
        binding: InstalledDrainBinding,
        role: str,
        allowed_service_sid: str,
    ) -> None:
        _require_windows()
        if not isinstance(allowed_service_sid, str) or _SID.fullmatch(
            allowed_service_sid
        ) is None:
            raise WindowsInstalledDrainPipeError("pipe service SID is invalid")
        self.address = installed_drain_pipe_name(binding=binding, role=role)
        self._poisoned = False
        descriptor = wintypes.LPVOID()  # type: ignore[name-defined]
        descriptor_size = wintypes.DWORD()  # type: ignore[name-defined]
        sddl = (
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
            f"(A;;GRGW;;;{allowed_service_sid})"
        )
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(  # type: ignore[name-defined]
            sddl,
            _SDDL_REVISION_1,  # type: ignore[name-defined]
            ctypes.byref(descriptor),  # type: ignore[name-defined]
            ctypes.byref(descriptor_size),  # type: ignore[name-defined]
        ):
            raise WindowsInstalledDrainPipeError("pipe security descriptor failed")
        attributes = _SECURITY_ATTRIBUTES(  # type: ignore[name-defined]
            nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),  # type: ignore[name-defined]
            lpSecurityDescriptor=descriptor,
            bInheritHandle=False,
        )
        try:
            raw = _kernel32.CreateNamedPipeW(  # type: ignore[name-defined]
                self.address,
                _PIPE_ACCESS_DUPLEX  # type: ignore[name-defined]
                | _FILE_FLAG_FIRST_PIPE_INSTANCE  # type: ignore[name-defined]
                | _FILE_FLAG_OVERLAPPED,  # type: ignore[name-defined]
                _PIPE_TYPE_MESSAGE  # type: ignore[name-defined]
                | _PIPE_READMODE_MESSAGE  # type: ignore[name-defined]
                | _PIPE_REJECT_REMOTE_CLIENTS,  # type: ignore[name-defined]
                1,
                _MAX_FRAME_BYTES,
                _MAX_FRAME_BYTES,
                5_000,
                ctypes.byref(attributes),  # type: ignore[name-defined]
            )
        finally:
            _kernel32.LocalFree(descriptor)  # type: ignore[name-defined]
        handle = int(raw or 0)
        if not handle or handle == _INVALID_HANDLE_VALUE:  # type: ignore[name-defined]
            raise WindowsInstalledDrainPipeError("pipe server creation failed")
        self._handle = handle
        self._lock = threading.RLock()

    def security_sddl(self) -> str:
        with self._lock:
            if not self._handle:
                raise WindowsInstalledDrainPipeError("pipe server is closed")
            if self._poisoned:
                raise WindowsInstalledDrainPipeError("pipe server is poisoned")
            needed = wintypes.DWORD()  # type: ignore[name-defined]
            ctypes.set_last_error(0)  # type: ignore[name-defined]
            first = _advapi32.GetKernelObjectSecurity(  # type: ignore[name-defined]
                wintypes.HANDLE(self._handle),  # type: ignore[name-defined]
                _DACL_SECURITY_INFORMATION,  # type: ignore[name-defined]
                None,
                0,
                ctypes.byref(needed),  # type: ignore[name-defined]
            )
            if first or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:  # type: ignore[name-defined]
                raise WindowsInstalledDrainPipeError("pipe security query failed")
            if not 1 <= int(needed.value) <= 65_536:
                raise WindowsInstalledDrainPipeError("pipe security size is invalid")
            descriptor = ctypes.create_string_buffer(int(needed.value))  # type: ignore[name-defined]
            if not _advapi32.GetKernelObjectSecurity(  # type: ignore[name-defined]
                wintypes.HANDLE(self._handle),  # type: ignore[name-defined]
                _DACL_SECURITY_INFORMATION,  # type: ignore[name-defined]
                descriptor,
                needed,
                ctypes.byref(needed),  # type: ignore[name-defined]
            ):
                raise WindowsInstalledDrainPipeError("pipe security query failed")
            rendered = wintypes.LPWSTR()  # type: ignore[name-defined]
            rendered_length = wintypes.DWORD()  # type: ignore[name-defined]
            if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(  # type: ignore[name-defined]
                descriptor,
                _SDDL_REVISION_1,  # type: ignore[name-defined]
                _DACL_SECURITY_INFORMATION,  # type: ignore[name-defined]
                ctypes.byref(rendered),  # type: ignore[name-defined]
                ctypes.byref(rendered_length),  # type: ignore[name-defined]
            ):
                raise WindowsInstalledDrainPipeError("pipe security render failed")
            try:
                value = str(rendered.value or "")
            finally:
                _kernel32.LocalFree(rendered)  # type: ignore[name-defined]
            if not value or not value.startswith("D:P"):
                raise WindowsInstalledDrainPipeError("pipe security descriptor is invalid")
            return value

    def accept(
        self, *, expected_client_pid: int, timeout_ms: int
    ) -> WindowsInstalledDrainPipeConnection:
        expected = _positive_pid(expected_client_pid, "client process id")
        timeout = _timeout(timeout_ms)
        with self._lock:
            if not self._handle:
                raise WindowsInstalledDrainPipeError("pipe server is closed")
            if self._poisoned:
                raise WindowsInstalledDrainPipeError("pipe server is poisoned")
            handle = self._handle
            event_handle, overlapped = _new_event()
            try:
                connected = _kernel32.ConnectNamedPipe(  # type: ignore[name-defined]
                    wintypes.HANDLE(handle), ctypes.byref(overlapped)  # type: ignore[name-defined]
                )
                if not connected:
                    error = ctypes.get_last_error()  # type: ignore[name-defined]
                    if error == _ERROR_IO_PENDING:  # type: ignore[name-defined]
                        _wait_pending(
                            handle,
                            event_handle,
                            overlapped,
                            timeout_ms=timeout,
                            operation="connect",
                        )
                    elif error != _ERROR_PIPE_CONNECTED:  # type: ignore[name-defined]
                        raise WindowsInstalledDrainPipeError("pipe connect failed")
            except Exception:
                self._poisoned = True
                raise
            finally:
                _finish_io_event(event_handle, overlapped)
            client_pid = wintypes.ULONG()  # type: ignore[name-defined]
            if not _kernel32.GetNamedPipeClientProcessId(  # type: ignore[name-defined]
                wintypes.HANDLE(handle), ctypes.byref(client_pid)  # type: ignore[name-defined]
            ):
                raise WindowsInstalledDrainPipeError("pipe client process is unavailable")
            if int(client_pid.value) != expected:
                self.close()
                raise WindowsInstalledDrainPipeError("pipe client process mismatch")
            self._handle = 0
            return WindowsInstalledDrainPipeConnection(
                handle=handle,
                disconnect_on_close=True,
            )

    def close(self) -> None:
        with self._lock:
            handle = self._handle
            if not handle:
                return None
            _kernel32.CancelIoEx(wintypes.HANDLE(handle), None)  # type: ignore[name-defined]
            _kernel32.DisconnectNamedPipe(wintypes.HANDLE(handle))  # type: ignore[name-defined]
            _close_handle(handle, "pipe server")
            self._handle = 0
            _collect_retired_io()
        return None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


class WindowsInstalledDrainPipeClient:
    @staticmethod
    def validate_frame(frame: bytes) -> bytes:
        return _frame(frame)

    @classmethod
    def connect(
        cls,
        *,
        binding: InstalledDrainBinding,
        role: str,
        expected_server_pid: int,
        timeout_ms: int,
    ) -> WindowsInstalledDrainPipeConnection:
        _require_windows()
        expected = _positive_pid(expected_server_pid, "server process id")
        timeout = _timeout(timeout_ms)
        address = installed_drain_pipe_name(binding=binding, role=role)
        if not _kernel32.WaitNamedPipeW(address, timeout):  # type: ignore[name-defined]
            raise WindowsInstalledDrainPipeError("pipe server is unavailable")
        raw = _kernel32.CreateFileW(  # type: ignore[name-defined]
            address,
            _GENERIC_READ | _GENERIC_WRITE,  # type: ignore[name-defined]
            0,
            None,
            _OPEN_EXISTING,  # type: ignore[name-defined]
            _FILE_FLAG_OVERLAPPED,  # type: ignore[name-defined]
            None,
        )
        handle = int(raw or 0)
        if not handle or handle == _INVALID_HANDLE_VALUE:  # type: ignore[name-defined]
            raise WindowsInstalledDrainPipeError("pipe client connection failed")
        try:
            server_pid = wintypes.ULONG()  # type: ignore[name-defined]
            if not _kernel32.GetNamedPipeServerProcessId(  # type: ignore[name-defined]
                wintypes.HANDLE(handle), ctypes.byref(server_pid)  # type: ignore[name-defined]
            ):
                raise WindowsInstalledDrainPipeError(
                    "pipe server process is unavailable"
                )
            if int(server_pid.value) != expected:
                raise WindowsInstalledDrainPipeError("pipe server process mismatch")
            mode = wintypes.DWORD(_PIPE_READMODE_MESSAGE)  # type: ignore[name-defined]
            if not _kernel32.SetNamedPipeHandleState(  # type: ignore[name-defined]
                wintypes.HANDLE(handle),  # type: ignore[name-defined]
                ctypes.byref(mode),  # type: ignore[name-defined]
                None,
                None,
            ):
                raise WindowsInstalledDrainPipeError("pipe message mode failed")
            return WindowsInstalledDrainPipeConnection(
                handle=handle,
                disconnect_on_close=False,
            )
        except Exception:
            _close_handle(handle, "pipe client")
            raise


class WindowsInstalledDrainPipeParentEndpoint:
    """Parent-facing request/snapshot adapter for ``InstalledParentDrainCoordinator``."""

    def __init__(self, *, connection, protocol, timeout_ms: int) -> None:
        if (
            not callable(getattr(connection, "send", None))
            or not callable(getattr(connection, "receive", None))
            or getattr(connection, "bootstrap_complete", None) is not True
            or not isinstance(protocol, InstalledDrainProtocol)
        ):
            raise WindowsInstalledDrainPipeError("parent pipe endpoint is invalid")
        self._connection = connection
        self._protocol = protocol
        self._timeout_ms = _timeout(timeout_ms)
        self._operation: InstalledDrainOperation | None = None
        self._last_command: InstalledDrainCommand | None = None
        self._receipt_pending = False
        self._lock = threading.RLock()

    def request(self, command: InstalledDrainCommand) -> None:
        if not isinstance(command, InstalledDrainCommand):
            raise WindowsInstalledDrainPipeError("parent drain command is invalid")
        with self._lock:
            if self._operation is not None and self._operation != command.operation:
                raise WindowsInstalledDrainPipeError("parent drain operation conflict")
            self._operation = command.operation
            try:
                self._connection.send(
                    self._protocol.encode_command(command),
                    timeout_ms=self._timeout_ms,
                )
                self._last_command = command
                self._receipt_pending = True
            except WindowsInstalledDrainPipeTimeout as exc:
                if exc.retry_safe:
                    raise
                self._connection.abort()
                raise
            except Exception:
                self._connection.abort()
                raise
        return None

    def snapshot(self, operation: InstalledDrainOperation) -> InstalledDrainRoleReceipt:
        with self._lock:
            if self._operation is None or self._operation != operation:
                raise WindowsInstalledDrainPipeError("parent drain operation is not active")
            try:
                if not self._receipt_pending:
                    if self._last_command is None:
                        raise WindowsInstalledDrainPipeError(
                            "parent drain command is unavailable"
                        )
                    self._connection.send(
                        self._protocol.encode_command(self._last_command),
                        timeout_ms=self._timeout_ms,
                    )
                    self._receipt_pending = True
                receipt = self._protocol.decode_receipt(
                    self._connection.receive(timeout_ms=self._timeout_ms)
                )
                self._receipt_pending = False
            except Exception:
                self._connection.abort()
                raise
            if receipt.operation != operation:
                raise WindowsInstalledDrainPipeError("parent drain receipt operation mismatch")
            return receipt


class WindowsInstalledDrainPipeChildEndpoint:
    """Child-facing authenticated command/receipt adapter."""

    def __init__(self, *, connection, protocol, timeout_ms: int) -> None:
        if (
            not callable(getattr(connection, "send", None))
            or not callable(getattr(connection, "receive", None))
            or getattr(connection, "bootstrap_complete", None) is not True
            or not isinstance(protocol, InstalledDrainProtocol)
        ):
            raise WindowsInstalledDrainPipeError("child pipe endpoint is invalid")
        self._connection = connection
        self._protocol = protocol
        self._timeout_ms = _timeout(timeout_ms)
        self._operation: InstalledDrainOperation | None = None
        self._lock = threading.RLock()

    def receive_command(self) -> InstalledDrainCommand:
        with self._lock:
            try:
                command = self._protocol.decode_command(
                    self._connection.receive(timeout_ms=self._timeout_ms)
                )
            except WindowsInstalledDrainPipeTimeout as exc:
                if exc.retry_safe:
                    raise
                self._connection.abort()
                raise
            except Exception:
                self._connection.abort()
                raise
            if self._operation is not None and self._operation != command.operation:
                raise WindowsInstalledDrainPipeError("child drain operation conflict")
            self._operation = command.operation
            return command

    def send_receipt(self, receipt: InstalledDrainRoleReceipt) -> None:
        if not isinstance(receipt, InstalledDrainRoleReceipt):
            raise WindowsInstalledDrainPipeError("child drain receipt is invalid")
        with self._lock:
            if self._operation is None or receipt.operation != self._operation:
                raise WindowsInstalledDrainPipeError("child drain receipt operation mismatch")
            try:
                self._connection.send(
                    self._protocol.encode_receipt(receipt),
                    timeout_ms=self._timeout_ms,
                )
            except Exception:
                self._connection.abort()
                raise
        return None


class WindowsInstalledDrainPipeParentHub:
    """Own the exact three servers and keep the control root parent-only."""

    def __init__(
        self,
        *,
        binding: InstalledDrainBinding,
        control_key: bytes,
        allowed_service_sid: str,
    ) -> None:
        if (
            not isinstance(binding, InstalledDrainBinding)
            or not isinstance(control_key, bytes)
            or len(control_key) != 32
            or not any(control_key)
            or not isinstance(allowed_service_sid, str)
            or _SID.fullmatch(allowed_service_sid) is None
        ):
            raise WindowsInstalledDrainPipeError("parent pipe hub input is invalid")
        self._binding = binding
        self._control_key: bytes | None = control_key
        self._servers: dict[str, WindowsInstalledDrainPipeServer] = {}
        self._connections: dict[str, WindowsInstalledDrainPipeConnection] = {}
        self._endpoints: Mapping[str, WindowsInstalledDrainPipeParentEndpoint] | None = None
        self._closed = False
        self._closing = False
        self._lock = threading.RLock()
        try:
            for role in ("engine", "weixin", "feishu"):
                self._servers[role] = WindowsInstalledDrainPipeServer(
                    binding=binding,
                    role=role,
                    allowed_service_sid=allowed_service_sid,
                )
        except Exception:
            self.close()
            raise

    def attach(
        self,
        *,
        processes: Mapping[str, InstalledChannelProcessReceipt],
        timeout_ms: int,
    ) -> Mapping[str, WindowsInstalledDrainPipeParentEndpoint]:
        timeout = _timeout(timeout_ms)
        if (
            not isinstance(processes, Mapping)
            or set(processes) != {"engine", "weixin", "feishu"}
            or any(
                not isinstance(processes[role], InstalledChannelProcessReceipt)
                for role in ("engine", "weixin", "feishu")
            )
        ):
            raise WindowsInstalledDrainPipeError("parent pipe process map is invalid")
        with self._lock:
            if (
                self._closed
                or self._closing
                or self._endpoints is not None
                or self._control_key is None
            ):
                raise WindowsInstalledDrainPipeError("parent pipe hub state is invalid")
            endpoints: dict[str, WindowsInstalledDrainPipeParentEndpoint] = {}
            try:
                deadline = time.monotonic() + timeout / 1000.0
                for role in ("engine", "weixin", "feishu"):
                    process = processes[role]
                    connection = self._servers[role].accept(
                        expected_client_pid=process.pid,
                        timeout_ms=_remaining_timeout_ms(deadline),
                    )
                    self._connections[role] = connection
                    role_key = derive_installed_drain_role_key(
                        control_key=self._control_key,
                        binding=self._binding,
                        role=role,
                        process=process,
                    )
                    connection.bootstrap_parent(
                        role_key,
                        timeout_ms=_remaining_timeout_ms(deadline),
                    )
                    endpoints[role] = WindowsInstalledDrainPipeParentEndpoint(
                        connection=connection,
                        protocol=InstalledDrainProtocol(
                            role_key=role_key,
                            binding=self._binding,
                            role=role,
                            process=process,
                        ),
                        timeout_ms=min(250, _remaining_timeout_ms(deadline)),
                    )
            except Exception:
                try:
                    self.close()
                except Exception:
                    pass
                raise
            self._control_key = None
            self._endpoints = MappingProxyType(dict(endpoints))
            return self._endpoints

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return None
            self._closing = True
            failures = False
            for role, connection in tuple(self._connections.items()):
                try:
                    connection.close()
                except Exception:
                    failures = True
                else:
                    self._connections.pop(role, None)
            for role, server in tuple(self._servers.items()):
                try:
                    server.close()
                except Exception:
                    failures = True
                else:
                    self._servers.pop(role, None)
            if failures:
                raise WindowsInstalledDrainPipeError("parent pipe hub close failed")
            self._control_key = None
            self._closed = True
        return None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


__all__ = [
    "WindowsInstalledDrainPipeChildEndpoint",
    "WindowsInstalledDrainPipeClient",
    "WindowsInstalledDrainPipeConnection",
    "WindowsInstalledDrainPipeError",
    "WindowsInstalledDrainPipeParentEndpoint",
    "WindowsInstalledDrainPipeParentHub",
    "WindowsInstalledDrainPipeServer",
    "WindowsInstalledDrainPipeTimeout",
    "installed_drain_pipe_name",
]
