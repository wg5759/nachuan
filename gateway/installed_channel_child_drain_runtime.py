"""Process-local control thread for one authenticated installed drain endpoint.

The runtime owns no credentials and performs no business work.  It serially
receives already-authenticated drain commands, applies them to the exact shared
``InstalledChildDrainFence``, and publishes aggregate receipts.  Transport or
protocol failure is terminal for this process generation and never retried.
"""

from __future__ import annotations

import threading

from gateway.installed_channel_drain import InstalledChildDrainFence
from gateway.windows_installed_drain_pipe import WindowsInstalledDrainPipeTimeout


class InstalledChannelChildDrainRuntimeError(RuntimeError):
    pass


class InstalledChannelChildDrainRuntime:
    def __init__(self, *, endpoint, fence: InstalledChildDrainFence) -> None:
        if (
            not callable(getattr(endpoint, "receive_command", None))
            or not callable(getattr(endpoint, "send_receipt", None))
            or not isinstance(fence, InstalledChildDrainFence)
        ):
            raise InstalledChannelChildDrainRuntimeError(
                "child drain runtime input is invalid"
            )
        self._endpoint = endpoint
        self._fence = fence
        self._exit_event = threading.Event()
        self._done = threading.Event()
        self._thread: threading.Thread | None = None
        self._error_code = ""
        self._lock = threading.RLock()
        self._stop_control = threading.Event()
        self._authenticated_exit = False
        self._business_entered = False

    @property
    def exit_event(self) -> threading.Event:
        return self._exit_event

    @property
    def fence(self) -> InstalledChildDrainFence:
        return self._fence

    def start(self) -> None:
        with self._lock:
            if self._thread is not None or self._done.is_set():
                raise InstalledChannelChildDrainRuntimeError(
                    "child drain runtime cannot start"
                )
            thread = threading.Thread(
                target=self._run,
                name="nachuan-installed-drain-control",
                daemon=True,
            )
            self._thread = thread
            try:
                thread.start()
            except BaseException as exc:
                self._error_code = type(exc).__name__
                self._fence.fail_closed()
                self._exit_event.set()
                self._done.set()
                raise InstalledChannelChildDrainRuntimeError('child control start failed') from exc
        return None

    def _run(self) -> None:
        try:
            while not self._stop_control.is_set():
                try:
                    command = self._endpoint.receive_command()
                except WindowsInstalledDrainPipeTimeout as exc:
                    if exc.retry_safe:
                        continue
                    raise
                with self._lock:
                    if self._stop_control.is_set():
                        break
                    receipt = self._fence.apply_command(command)
                self._endpoint.send_receipt(receipt)
                if command.action == "exit":
                    with self._lock:
                        if self._stop_control.is_set():
                            break
                        self._authenticated_exit = True
                    self._exit_event.set()
                    return
        except BaseException as exc:  # noqa: BLE001 - terminal thread boundary
            with self._lock:
                self._error_code = type(exc).__name__
            self._fence.fail_closed()
            self._exit_event.set()
        finally:
            self._done.set()

    def wait(self, *, timeout: float) -> bool:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise InstalledChannelChildDrainRuntimeError(
                "child drain wait timeout is invalid"
            )
        value = float(timeout)
        if not 0 <= value <= 120:
            raise InstalledChannelChildDrainRuntimeError(
                "child drain wait timeout is invalid"
            )
        return self._done.wait(value)

    def raise_if_failed(self) -> None:
        with self._lock:
            failed = bool(self._error_code)
        if failed:
            raise InstalledChannelChildDrainRuntimeError(
                "child drain control failed"
            )
        if not self._done.is_set() or not self._exit_event.is_set() or not self._authenticated_exit:
            raise InstalledChannelChildDrainRuntimeError(
                "child drain control did not exit cleanly"
            )
        return None

    def request_local_stop(self) -> None:
        """Stop after the current bounded read; this is not an authenticated exit."""
        with self._lock:
            if not self._authenticated_exit:
                self._fence.fail_closed()
            self._stop_control.set()
            self._exit_event.set()

    def validate_business_exit(self) -> None:
        # The exit event is delivered just before the control thread's finally.
        if not self.wait(timeout=1.0):
            raise InstalledChannelChildDrainRuntimeError('child control exit unverified')
        self.raise_if_failed()

    def run_business(self, business, *, bind_fence, join_timeout: float = 5.0) -> int:
        """Compose already-authenticated control with one business main.

        This method does not create/authenticate a pipe or load installation
        authority. Its caller owns that connection. Never bind close_claims as
        the business exit event, and never infer parent exit from a local Event.
        """
        if (not callable(business) or not callable(bind_fence)
                or isinstance(join_timeout, bool) or not isinstance(join_timeout, (int, float))
                or not 0 < join_timeout <= 30):
            raise InstalledChannelChildDrainRuntimeError('child business input invalid')
        with self._lock:
            if self._business_entered or self._thread is not None or self._done.is_set():
                raise InstalledChannelChildDrainRuntimeError('child business already entered')
            self._business_entered = True
            bind_fence(self._fence)
            self.start()
        try:
            result = business(stop_event=self._exit_event)
        finally:
            self.request_local_stop()
            completed = self.wait(timeout=join_timeout)
        if not completed:
            raise InstalledChannelChildDrainRuntimeError('child control did not stop')
        self.raise_if_failed()
        if type(result) is not int or not 0 <= result <= 255:
            raise InstalledChannelChildDrainRuntimeError('child business result invalid')
        return result


__all__ = [
    "InstalledChannelChildDrainRuntime",
    "InstalledChannelChildDrainRuntimeError",
]
