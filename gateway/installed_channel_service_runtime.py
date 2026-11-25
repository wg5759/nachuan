"""Service-lifecycle adapter for an already-loaded installed Coordinator.

The production service does not enable this adapter yet.  Its factory seam is
for reviewed, already-loaded authority only; it accepts no path or credential.
"""

from __future__ import annotations

import sys

from gateway.installed_channel_supervisor_entrypoint import run_coordinator_loop


class InstalledChannelServiceRuntimeError(RuntimeError):
    pass


class InstalledChannelOwnerCoordinatorLease:
    """Keep one already-entered owner lock until STOPPED was attempted."""

    def __init__(self, *, coordinator, owner_lock) -> None:
        if any(
            not callable(getattr(coordinator, method, None))
            for method in ("step", "close", "force_close", "is_quiescent")
        ) or not callable(getattr(owner_lock, "__exit__", None)):
            raise InstalledChannelServiceRuntimeError(
                "owned coordinator lease is invalid"
            )
        self._coordinator = coordinator
        self._owner_lock = owner_lock
        self._released = False

    def step(self):
        return self._coordinator.step()

    def close(self) -> None:
        return self._coordinator.close()

    def force_close(self) -> None:
        return self._coordinator.force_close()

    def is_quiescent(self) -> bool:
        quiescent = self._coordinator.is_quiescent()
        if type(quiescent) is not bool:
            raise InstalledChannelServiceRuntimeError(
                "owned coordinator quiescence is invalid"
            )
        return quiescent

    def after_stopped(self) -> None:
        if self._released:
            return None
        if not self.is_quiescent():
            raise InstalledChannelServiceRuntimeError(
                "owner lock cannot be released before quiescence"
            )
        result = self._owner_lock.__exit__(None, None, None)
        if result is not None and type(result) is not bool:
            raise InstalledChannelServiceRuntimeError(
                "owner lock release result is invalid"
            )
        self._released = True
        return None


def build_owned_coordinator_factory(*, owner_lock_factory, coordinator_factory):
    """Acquire the owner before assembly and return a long-lived lease."""

    if not callable(owner_lock_factory) or not callable(coordinator_factory):
        raise InstalledChannelServiceRuntimeError(
            "owned coordinator factory is invalid"
        )

    def factory(stop_event):
        owner_lock = owner_lock_factory()
        enter = getattr(owner_lock, "__enter__", None)
        exit_lock = getattr(owner_lock, "__exit__", None)
        if not callable(enter) or not callable(exit_lock):
            raise InstalledChannelServiceRuntimeError("owner lock is invalid")
        enter()
        try:
            coordinator = coordinator_factory(stop_event)
            return InstalledChannelOwnerCoordinatorLease(
                coordinator=coordinator,
                owner_lock=owner_lock,
            )
        except BaseException:  # noqa: BLE001 - release before preserving failure
            exc_info = sys.exc_info()
            try:
                exit_lock(*exc_info)
            finally:
                del exc_info
            raise

    return factory


class InstalledChannelServiceRuntime:
    def __init__(self, *, coordinator_factory, loop_runner=run_coordinator_loop) -> None:
        if not callable(coordinator_factory) or not callable(loop_runner):
            raise InstalledChannelServiceRuntimeError(
                "service runtime callback is invalid"
            )
        self._coordinator_factory = coordinator_factory
        self._loop_runner = loop_runner
        self._coordinator = None
        self._stop_event = None
        self._initial_transition = None
        self._started = False
        self._ran = False
        self._closed = False
        self._force_attempted = False

    @staticmethod
    def _event_is_set(stop_event) -> bool:
        if (
            not callable(getattr(stop_event, "is_set", None))
            or not callable(getattr(stop_event, "wait", None))
        ):
            raise InstalledChannelServiceRuntimeError(
                "service runtime stop event is invalid"
            )
        stopped = stop_event.is_set()
        if type(stopped) is not bool:
            raise InstalledChannelServiceRuntimeError(
                "service runtime stop event is invalid"
            )
        return stopped

    def start(self, stop_event) -> None:
        if self._started or self._closed or self._event_is_set(stop_event):
            raise InstalledChannelServiceRuntimeError(
                "service runtime cannot start"
            )
        coordinator = self._coordinator_factory(stop_event)
        self._coordinator = coordinator
        self._stop_event = stop_event
        if self._event_is_set(stop_event):
            raise InstalledChannelServiceRuntimeError(
                "service runtime cannot start"
            )
        if any(
            not callable(getattr(coordinator, method, None))
            for method in ("step", "close", "force_close", "is_quiescent")
        ):
            raise InstalledChannelServiceRuntimeError(
                "service runtime coordinator is invalid"
            )
        try:
            transition = coordinator.step()
        except BaseException as exc:  # noqa: BLE001 - Host owns final shutdown
            raise InstalledChannelServiceRuntimeError(
                "service runtime initial step failed"
            ) from exc
        action = getattr(getattr(transition, "watchdog", None), "action", None)
        if action not in {
            "started",
            "healthy",
            "stopped",
            "external_stopped",
            "retry_scheduled",
            "backoff",
        }:
            raise InstalledChannelServiceRuntimeError(
                "service runtime initial transition is invalid"
            )
        self._initial_transition = transition
        self._started = True
        return None

    def run(self, stop_event, on_stopping) -> int:
        if (
            not self._started
            or self._ran
            or self._closed
            or stop_event is not self._stop_event
            or not callable(on_stopping)
        ):
            raise InstalledChannelServiceRuntimeError(
                "service runtime run state is invalid"
            )
        self._ran = True
        result = self._loop_runner(
            self._coordinator,
            stop_event=stop_event,
            on_stopping=on_stopping,
            initial_transition=self._initial_transition,
            close_on_exit=False,
        )
        if isinstance(result, bool) or not isinstance(result, int) or not 0 <= result <= 255:
            raise InstalledChannelServiceRuntimeError(
                "service runtime loop result is invalid"
            )
        return result

    def close(self) -> None:
        if self._closed:
            return None
        coordinator = self._coordinator
        if coordinator is None:
            raise InstalledChannelServiceRuntimeError(
                "service runtime coordinator is unavailable"
            )
        result = coordinator.close()
        if result is not None:
            raise InstalledChannelServiceRuntimeError(
                "service runtime close result is invalid"
            )
        self._closed = True
        return None

    def force_close(self) -> None:
        if self._force_attempted:
            return None
        coordinator = self._coordinator
        if coordinator is None:
            raise InstalledChannelServiceRuntimeError(
                "service runtime coordinator is unavailable"
            )
        self._force_attempted = True
        result = coordinator.force_close()
        if result is not None:
            raise InstalledChannelServiceRuntimeError(
                "service runtime force result is invalid"
            )
        return None

    def is_quiescent(self) -> bool:
        coordinator = self._coordinator
        if coordinator is None:
            return False
        quiescent = coordinator.is_quiescent()
        if type(quiescent) is not bool:
            raise InstalledChannelServiceRuntimeError(
                "service runtime quiescence result is invalid"
            )
        return quiescent

    def after_stopped(self) -> None:
        coordinator = self._coordinator
        if coordinator is None:
            return None
        finalizer = getattr(coordinator, "after_stopped", None)
        if finalizer is None:
            return None
        if not callable(finalizer) or finalizer() is not None:
            raise InstalledChannelServiceRuntimeError(
                "service runtime stopped finalizer is invalid"
            )
        return None


__all__ = [
    "InstalledChannelOwnerCoordinatorLease",
    "InstalledChannelServiceRuntime",
    "InstalledChannelServiceRuntimeError",
    "build_owned_coordinator_factory",
]
