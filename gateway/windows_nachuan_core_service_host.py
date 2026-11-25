"""Minimal fail-closed Windows service host for the dedicated NachuanCore service."""

from __future__ import annotations

import ctypes
import math
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Callable, Protocol

from gateway.installed_nachuan_core_identity import (
    NACHUAN_CORE_SERVICE_NAME,
    validate_nachuan_core_service_sid,
)


_EXIT_UNAVAILABLE = 69
_EXIT_REFUSED = 77
_SERVICE_STOPPED = 1
_SERVICE_START_PENDING = 2
_SERVICE_STOP_PENDING = 3
_SERVICE_RUNNING = 4
_SERVICE_CONTROL_STOP = 1
_SERVICE_CONTROL_INTERROGATE = 4
_SERVICE_CONTROL_SHUTDOWN = 5
_SERVICE_CONTROL_PRESHUTDOWN = 15
_SERVICE_ACCEPT_STOP_SHUTDOWN_PRESHUTDOWN = 0x1 | 0x4 | 0x100
_ERROR_CALL_NOT_IMPLEMENTED = 120
_ERROR_SERVICE_SPECIFIC_ERROR = 1066
_SERVICE_SPECIFIC_HOST_FAILURE = 0x4E430001
_ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
_SERVICE_WIN32_OWN_PROCESS = 0x10

_WIN_CALLBACK = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
_SERVICE_MAIN_CALLBACK = _WIN_CALLBACK(
    None,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPWSTR),
)
_HANDLER_EX_CALLBACK = _WIN_CALLBACK(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
)


class _ServiceStatusNative(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class _ServiceTableEntryW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", _SERVICE_MAIN_CALLBACK),
    ]


class ServiceHostError(RuntimeError):
    pass


class ServiceControllerUnavailable(ServiceHostError):
    pass


@dataclass(frozen=True, slots=True)
class ServiceStatus:
    current_state: int
    controls_accepted: int
    win32_exit_code: int = 0
    service_specific_exit_code: int = 0
    check_point: int = 0
    wait_hint_ms: int = 0


class ScmPort(Protocol):
    def dispatch(self, service_name: str, service_main: Callable[[], None]) -> None: ...

    def register_handler(self, service_name: str, handler: Callable[[int], int]): ...

    def report_status(self, status_handle, status: ServiceStatus) -> None: ...

    def assert_runtime_identity(self) -> str: ...


class EmptyServiceRuntime:
    """Production-safe placeholder; it owns no authority or child process."""

    def __init__(self) -> None:
        self._closed = False

    def start(self, _stop_event) -> None:
        return None

    def run(self, stop_event, on_stopping) -> int:
        stop_event.wait()
        on_stopping()
        return 0

    def close(self) -> None:
        self._closed = True
        return None

    def force_close(self) -> None:
        self._closed = True
        return None

    def is_quiescent(self) -> bool:
        return self._closed


class ServiceRuntimeShutdownController:
    """Bound graceful close, then force once and require quiescence proof."""

    def __init__(
        self,
        *,
        graceful_timeout_seconds: float = 30.0,
        force_timeout_seconds: float = 10.0,
    ) -> None:
        graceful = float(graceful_timeout_seconds)
        force = float(force_timeout_seconds)
        if (
            not math.isfinite(graceful)
            or not 0 <= graceful <= 30
            or not math.isfinite(force)
            or not 0 < force <= 10
        ):
            raise ServiceHostError("service shutdown timing is invalid")
        self._graceful_timeout = graceful
        self._force_timeout = force

    def shutdown(self, runtime) -> None:
        if any(
            not callable(getattr(runtime, method, None))
            for method in ("close", "force_close", "is_quiescent")
        ):
            raise ServiceHostError("service runtime shutdown is invalid")
        started = Event()
        completed = Event()
        errors: list[BaseException] = []

        def graceful_close() -> None:
            started.set()
            try:
                if runtime.close() is not None:
                    raise ServiceHostError("service runtime close is invalid")
            except BaseException as exc:  # noqa: BLE001 - worker reports to owner
                errors.append(exc)
            finally:
                completed.set()

        worker = Thread(target=graceful_close, daemon=True)
        deadline = time.monotonic() + self._graceful_timeout + self._force_timeout

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        worker.start()
        graceful_started = started.wait(min(self._force_timeout, remaining()))
        completed_in_grace = graceful_started and completed.wait(
            min(self._graceful_timeout, remaining())
        )
        if completed_in_grace:
            worker.join(min(1.0, remaining()))
        needs_force = (
            not graceful_started
            or not completed_in_grace
            or worker.is_alive()
            or bool(errors)
        )
        if not needs_force:
            try:
                quiescent = runtime.is_quiescent()
            except Exception:
                needs_force = True
            else:
                needs_force = type(quiescent) is not bool or not quiescent
        force_error: BaseException | None = None
        if needs_force:
            force_completed = Event()
            force_errors: list[BaseException] = []

            def force_close() -> None:
                try:
                    force_result = runtime.force_close()
                    if force_result is not None:
                        raise ServiceHostError(
                            "service runtime force close is invalid"
                        )
                except BaseException as exc:  # noqa: BLE001 - owner handles it
                    force_errors.append(exc)
                finally:
                    force_completed.set()

            force_worker = Thread(target=force_close, daemon=True)
            force_worker.start()
            if not force_completed.wait(remaining()):
                raise ServiceHostError("service runtime force close timed out")
            force_worker.join(remaining())
            if force_worker.is_alive():
                raise ServiceHostError("service runtime force close timed out")
            if force_errors:
                force_error = force_errors[0]
            if not completed.wait(remaining()):
                raise ServiceHostError("service runtime did not stop after force")
            worker.join(remaining())
        if worker.is_alive():
            raise ServiceHostError("service runtime close failed")
        quiescent = runtime.is_quiescent()
        if type(quiescent) is not bool or not quiescent:
            raise ServiceHostError("service runtime is not quiescent")
        if force_error is not None:
            raise ServiceHostError("service runtime force close failed")


class NativeWindowsScmPort:
    """Small native SCM surface; it does not create or configure a service."""

    def __init__(
        self,
        *,
        advapi32=None,
        get_last_error: Callable[[], int] | None = None,
        identity_probe: Callable[[], str] | None = None,
    ) -> None:
        if advapi32 is None:
            if os.name != "nt":
                raise ServiceHostError("Windows SCM is unavailable")
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._advapi32 = advapi32
        self._get_last_error = get_last_error or ctypes.get_last_error
        self._identity_probe = identity_probe or self._probe_runtime_identity
        self._callbacks: list[object] = []
        self._callback_failed = False
        self._configure_api()

    def _configure_api(self) -> None:
        self._advapi32.StartServiceCtrlDispatcherW.argtypes = (
            ctypes.POINTER(_ServiceTableEntryW),
        )
        self._advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        self._advapi32.RegisterServiceCtrlHandlerExW.argtypes = (
            wintypes.LPCWSTR,
            _HANDLER_EX_CALLBACK,
            wintypes.LPVOID,
        )
        self._advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
        self._advapi32.SetServiceStatus.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_ServiceStatusNative),
        )
        self._advapi32.SetServiceStatus.restype = wintypes.BOOL

    def dispatch(self, service_name: str, service_main: Callable[[], None]) -> None:
        if service_name != NACHUAN_CORE_SERVICE_NAME or not callable(service_main):
            raise ServiceHostError("service dispatcher input is invalid")

        def callback(argument_count, arguments) -> None:
            try:
                if (
                    int(argument_count) != 1
                    or not bool(arguments)
                    or arguments[0] != NACHUAN_CORE_SERVICE_NAME
                ):
                    self._callback_failed = True
                    return
                service_main()
            except BaseException:  # noqa: BLE001 - never cross the native callback
                self._callback_failed = True

        native_callback = _SERVICE_MAIN_CALLBACK(callback)
        self._callbacks.append(native_callback)
        entries = (_ServiceTableEntryW * 2)()
        entries[0].lpServiceName = service_name
        entries[0].lpServiceProc = native_callback
        entries[1].lpServiceName = None
        entries[1].lpServiceProc = _SERVICE_MAIN_CALLBACK()
        if not self._advapi32.StartServiceCtrlDispatcherW(entries):
            error = int(self._get_last_error())
            if error == _ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                raise ServiceControllerUnavailable
            raise ServiceHostError("service dispatcher failed")
        if self._callback_failed:
            raise ServiceHostError("service callback failed")

    def register_handler(self, service_name: str, handler: Callable[[int], int]):
        if service_name != NACHUAN_CORE_SERVICE_NAME or not callable(handler):
            raise ServiceHostError("service handler input is invalid")

        def callback(control, _event_type, _event_data, _context) -> int:
            try:
                result = handler(int(control))
                if isinstance(result, bool) or not isinstance(result, int):
                    return _ERROR_CALL_NOT_IMPLEMENTED
                return int(result)
            except BaseException:  # noqa: BLE001 - never cross the native callback
                return _ERROR_CALL_NOT_IMPLEMENTED

        native_callback = _HANDLER_EX_CALLBACK(callback)
        self._callbacks.append(native_callback)
        handle = self._advapi32.RegisterServiceCtrlHandlerExW(
            service_name,
            native_callback,
            None,
        )
        if not handle:
            raise ServiceHostError("service handler registration failed")
        return handle

    def report_status(self, status_handle, status: ServiceStatus) -> None:
        if not isinstance(status, ServiceStatus) or not status_handle:
            raise ServiceHostError("service status input is invalid")
        native = _ServiceStatusNative(
            dwServiceType=_SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=status.current_state,
            dwControlsAccepted=status.controls_accepted,
            dwWin32ExitCode=status.win32_exit_code,
            dwServiceSpecificExitCode=status.service_specific_exit_code,
            dwCheckPoint=status.check_point,
            dwWaitHint=status.wait_hint_ms,
        )
        if not self._advapi32.SetServiceStatus(status_handle, ctypes.byref(native)):
            raise ServiceHostError("service status report failed")

    def assert_runtime_identity(self) -> str:
        return self._identity_probe()

    @staticmethod
    def _probe_runtime_identity() -> str:
        from gateway.installed_channel_installer_trust_acl import (
            assert_installed_runtime_principal,
        )

        return assert_installed_runtime_principal()


class NachuanCoreServiceHost:
    def __init__(
        self,
        scm: ScmPort,
        *,
        runtime_factory=None,
        shutdown_controller=None,
    ) -> None:
        selected_runtime_factory = runtime_factory or EmptyServiceRuntime
        selected_shutdown_controller = (
            shutdown_controller or ServiceRuntimeShutdownController()
        )
        if not callable(selected_runtime_factory):
            raise ServiceHostError("service runtime factory is invalid")
        if not callable(getattr(selected_shutdown_controller, "shutdown", None)):
            raise ServiceHostError("service shutdown controller is invalid")
        self._scm = scm
        self._runtime_factory = selected_runtime_factory
        self._shutdown_controller = selected_shutdown_controller
        self._runtime = None
        self._shutdown_attempted = False
        self._runtime_shutdown_complete = False
        self._runtime_finalized = False
        self._stop_event = Event()
        self._status_handle = None
        self._exit_code = 0
        self._stopped_reported = False
        self._stop_pending_reported = False
        self._running_reported = False
        self._entry_lock = Lock()
        self._service_main_entered = False

    def run(self) -> int:
        try:
            self._scm.dispatch(NACHUAN_CORE_SERVICE_NAME, self._service_main)
        except ServiceControllerUnavailable:
            return _EXIT_REFUSED
        except Exception:  # noqa: BLE001 - never expose native or identity details
            return _EXIT_UNAVAILABLE
        with self._entry_lock:
            entered = self._service_main_entered
        if not entered or not self._stopped_reported:
            return _EXIT_UNAVAILABLE
        return self._exit_code

    def _service_main(self) -> None:
        with self._entry_lock:
            if self._service_main_entered:
                self._exit_code = _EXIT_UNAVAILABLE
                return
            self._service_main_entered = True
        try:
            self._status_handle = self._scm.register_handler(
                NACHUAN_CORE_SERVICE_NAME,
                self._control_handler,
            )
            self._report(
                ServiceStatus(
                    current_state=_SERVICE_START_PENDING,
                    controls_accepted=0,
                    check_point=1,
                    wait_hint_ms=15000,
                )
            )
            if self._stop_event.is_set():
                self._report_stop_pending()
                self._report_stopped()
                return
            validate_nachuan_core_service_sid(self._scm.assert_runtime_identity())
            runtime = self._runtime_factory()
            if any(
                not callable(getattr(runtime, method, None))
                for method in (
                    "start",
                    "run",
                    "close",
                    "force_close",
                    "is_quiescent",
                )
            ):
                raise ServiceHostError("service runtime is invalid")
            self._runtime = runtime
            try:
                start_result = runtime.start(self._stop_event)
            except BaseException:  # noqa: BLE001 - classify SCM Stop before fail
                if self._stop_event.is_set():
                    self._report_stop_pending()
                    self._close_runtime_once()
                    self._report_stopped()
                    return
                raise
            if start_result is not None:
                raise ServiceHostError("service runtime start is invalid")
            if self._stop_event.is_set():
                self._report_stop_pending()
                self._close_runtime_once()
                self._report_stopped()
                return
            self._report(
                ServiceStatus(
                    current_state=_SERVICE_RUNNING,
                    controls_accepted=_SERVICE_ACCEPT_STOP_SHUTDOWN_PRESHUTDOWN,
                )
            )
            self._running_reported = True

            def runtime_stopping() -> None:
                if not self._stop_event.is_set():
                    raise ServiceHostError("service runtime stop has no SCM event")
                self._report_stop_pending()

            runtime_result = runtime.run(
                self._stop_event,
                runtime_stopping,
            )
            if (
                isinstance(runtime_result, bool)
                or not isinstance(runtime_result, int)
                or runtime_result != 0
            ):
                raise ServiceHostError("service runtime result is invalid")
            if not self._stop_event.is_set():
                raise ServiceHostError("service runtime stopped without SCM control")
            self._report_stop_pending()
            self._close_runtime_once()
            self._report_stopped()
        except BaseException:  # noqa: BLE001 - callback boundary must never leak
            self._exit_code = _EXIT_UNAVAILABLE
            if self._running_reported:
                try:
                    self._report_stop_pending()
                except Exception:  # noqa: BLE001 - failed status is not retried
                    pass
            try:
                self._close_runtime_once()
            except Exception:  # noqa: BLE001 - runtime close is never retried
                pass
            try:
                self._report_stopped(
                    win32_exit_code=_ERROR_SERVICE_SPECIFIC_ERROR,
                    service_specific_exit_code=_SERVICE_SPECIFIC_HOST_FAILURE,
                )
            except Exception:  # noqa: BLE001 - STOPPED must never be retried
                pass
        finally:
            if self._stopped_reported:
                try:
                    self._finalize_runtime_after_stopped()
                except Exception:  # noqa: BLE001 - owner remains locked until exit
                    self._exit_code = _EXIT_UNAVAILABLE

    def _control_handler(self, control: int) -> int:
        if control in {
            _SERVICE_CONTROL_STOP,
            _SERVICE_CONTROL_SHUTDOWN,
            _SERVICE_CONTROL_PRESHUTDOWN,
        }:
            self._stop_event.set()
            return 0
        if control == _SERVICE_CONTROL_INTERROGATE:
            return 0
        return _ERROR_CALL_NOT_IMPLEMENTED

    def _report(self, status: ServiceStatus) -> None:
        if self._status_handle is None:
            raise ServiceHostError("service status handle is unavailable")
        self._scm.report_status(self._status_handle, status)

    def _report_stopped(
        self,
        *,
        win32_exit_code: int = 0,
        service_specific_exit_code: int = 0,
    ) -> None:
        if self._stopped_reported:
            return
        self._stopped_reported = True
        self._report(
            ServiceStatus(
                current_state=_SERVICE_STOPPED,
                controls_accepted=0,
                win32_exit_code=win32_exit_code,
                service_specific_exit_code=service_specific_exit_code,
            )
        )

    def _report_stop_pending(self) -> None:
        if self._stop_pending_reported:
            return
        self._stop_pending_reported = True
        self._report(
            ServiceStatus(
                current_state=_SERVICE_STOP_PENDING,
                controls_accepted=0,
                check_point=1,
                wait_hint_ms=45000,
            )
        )

    def _close_runtime_once(self) -> None:
        runtime = self._runtime
        if runtime is None:
            return
        if self._shutdown_attempted:
            if self._runtime_shutdown_complete:
                return
            raise ServiceHostError("service runtime shutdown already failed")
        self._shutdown_attempted = True
        self._shutdown_controller.shutdown(runtime)
        self._runtime_shutdown_complete = True

    def _finalize_runtime_after_stopped(self) -> None:
        runtime = self._runtime
        if runtime is None or self._runtime_finalized:
            return
        if not self._runtime_shutdown_complete:
            raise ServiceHostError("service runtime stopped before shutdown completed")
        finalizer = getattr(runtime, "after_stopped", None)
        if finalizer is not None:
            if not callable(finalizer) or finalizer() is not None:
                raise ServiceHostError("service runtime stopped finalizer is invalid")
        self._runtime_finalized = True
        self._runtime = None


__all__ = [
    "NachuanCoreServiceHost",
    "NativeWindowsScmPort",
    "EmptyServiceRuntime",
    "ScmPort",
    "ServiceControllerUnavailable",
    "ServiceHostError",
    "ServiceRuntimeShutdownController",
    "ServiceStatus",
    "run",
]


def run() -> int:
    return NachuanCoreServiceHost(
        NativeWindowsScmPort(),
        runtime_factory=EmptyServiceRuntime,
    ).run()
