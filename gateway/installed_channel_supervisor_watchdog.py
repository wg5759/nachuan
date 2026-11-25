"""Deterministic watchdog policy for an installed channel process tree."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from threading import RLock
from typing import Callable

from gateway.installed_channel_supervisor import InstalledChannelSupervisorState
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControl,
)


class InstalledChannelWatchdogError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelWatchdogStep:
    action: str
    state: InstalledChannelSupervisorState | None
    control: InstalledChannelSupervisorControl
    restart_attempt: int
    retry_delay_seconds: float | None


class InstalledChannelSupervisorWatchdog:
    """Advance one bounded watchdog transition per ``step`` call.

    Sleeping is deliberately kept outside this object.  The caller receives an
    exact backoff deadline and must call ``step`` again; the watchdog itself
    re-reads the persistent stop latch before every start or health decision.
    """

    def __init__(
        self,
        *,
        runtime_factory: Callable[[], object],
        control_loader: Callable[[], InstalledChannelSupervisorControl],
        health_check: Callable[[object, InstalledChannelSupervisorState], bool],
        monotonic_clock: Callable[[], float] | None = None,
        initial_backoff_seconds: float = 1.0,
        maximum_backoff_seconds: float = 60.0,
        stable_reset_seconds: float = 300.0,
        external_stop_event=None,
    ) -> None:
        if not callable(runtime_factory) or not callable(control_loader) or not callable(
            health_check
        ):
            raise InstalledChannelWatchdogError("watchdog callback is invalid")
        values = (
            float(initial_backoff_seconds),
            float(maximum_backoff_seconds),
            float(stable_reset_seconds),
        )
        if (
            any(not math.isfinite(value) or value <= 0 for value in values)
            or values[0] > values[1]
        ):
            raise InstalledChannelWatchdogError("watchdog timing is invalid")
        if external_stop_event is not None and not callable(
            getattr(external_stop_event, "is_set", None)
        ):
            raise InstalledChannelWatchdogError("external stop event is invalid")
        self._runtime_factory = runtime_factory
        self._control_loader = control_loader
        self._health_check = health_check
        self._clock = monotonic_clock or time.monotonic
        self._initial_backoff = values[0]
        self._maximum_backoff = values[1]
        self._stable_reset = values[2]
        self._external_stop_event = external_stop_event
        self._runtime: object | None = None
        self._closing_runtime: object | None = None
        self._runtime_lock = RLock()
        self._state: InstalledChannelSupervisorState | None = None
        self._restart_attempt = 0
        self._retry_not_before: float | None = None
        self._healthy_since: float | None = None
        self._last_clock: float | None = None
        self._closed = False

    def _external_stop_requested(self) -> bool:
        if self._external_stop_event is None:
            return False
        try:
            stopped = self._external_stop_event.is_set()
        except Exception as exc:
            raise InstalledChannelWatchdogError(
                "external stop event is unavailable"
            ) from exc
        if type(stopped) is not bool:
            raise InstalledChannelWatchdogError("external stop event is invalid")
        return stopped

    def _now(self) -> float:
        try:
            raw = self._clock()
        except Exception as exc:
            raise InstalledChannelWatchdogError("watchdog clock is unavailable") from exc
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise InstalledChannelWatchdogError("watchdog clock is invalid")
        now = float(raw)
        if not math.isfinite(now) or (
            self._last_clock is not None and now < self._last_clock
        ):
            raise InstalledChannelWatchdogError("watchdog clock is invalid")
        self._last_clock = now
        return now

    def _close_runtime(self) -> None:
        with self._runtime_lock:
            if self._closing_runtime is not None:
                runtime = self._closing_runtime
            else:
                runtime = self._runtime
                self._runtime = None
                self._closing_runtime = runtime
            self._state = None
            self._healthy_since = None
        if runtime is None:
            return
        try:
            runtime.close()
        except Exception as exc:
            raise InstalledChannelWatchdogError(
                "installed process tree could not be closed"
            ) from exc
        with self._runtime_lock:
            if self._closing_runtime is runtime:
                self._closing_runtime = None

    def _load_control(self) -> InstalledChannelSupervisorControl:
        try:
            control = self._control_loader()
        except Exception as exc:
            self._close_runtime()
            raise InstalledChannelWatchdogError(
                "persistent stop latch is unavailable"
            ) from exc
        if not isinstance(control, InstalledChannelSupervisorControl):
            self._close_runtime()
            raise InstalledChannelWatchdogError("persistent stop latch is invalid")
        return control

    def _retry(
        self, now: float, control: InstalledChannelSupervisorControl
    ) -> InstalledChannelWatchdogStep:
        self._restart_attempt += 1
        exponent = min(self._restart_attempt - 1, 62)
        delay = min(
            self._maximum_backoff,
            self._initial_backoff * (2**exponent),
        )
        self._retry_not_before = now + delay
        return InstalledChannelWatchdogStep(
            action="retry_scheduled",
            state=None,
            control=control,
            restart_attempt=self._restart_attempt,
            retry_delay_seconds=delay,
        )

    def _external_stop(
        self, control: InstalledChannelSupervisorControl
    ) -> InstalledChannelWatchdogStep:
        self._close_runtime()
        self._retry_not_before = None
        return InstalledChannelWatchdogStep(
            action="external_stopped",
            state=None,
            control=control,
            restart_attempt=self._restart_attempt,
            retry_delay_seconds=None,
        )

    def _evaluate_health(
        self, runtime: object, state: InstalledChannelSupervisorState
    ) -> InstalledChannelSupervisorState | None:
        result = self._health_check(runtime, state)
        if result is True:
            return state
        if (
            isinstance(result, InstalledChannelSupervisorState)
            and result.start_allowed
            and dict(result.pids) == dict(state.pids)
        ):
            return result
        return None

    def step(self) -> InstalledChannelWatchdogStep:
        if self._closed:
            raise InstalledChannelWatchdogError("watchdog is closed")
        now = self._now()
        control = self._load_control()
        if self._external_stop_requested():
            return self._external_stop(control)
        if control.stop_requested:
            self._close_runtime()
            self._retry_not_before = None
            return InstalledChannelWatchdogStep(
                action="stopped",
                state=None,
                control=control,
                restart_attempt=self._restart_attempt,
                retry_delay_seconds=None,
            )
        if self._retry_not_before is not None and now < self._retry_not_before:
            return InstalledChannelWatchdogStep(
                action="backoff",
                state=None,
                control=control,
                restart_attempt=self._restart_attempt,
                retry_delay_seconds=self._retry_not_before - now,
            )
        self._retry_not_before = None

        if self._runtime is None:
            runtime = None
            try:
                runtime = self._runtime_factory()
                if not callable(getattr(runtime, "start", None)) or not callable(
                    getattr(runtime, "close", None)
                ):
                    raise InstalledChannelWatchdogError("runtime factory is invalid")
                if self._external_stop_event is None:
                    state = runtime.start()
                else:
                    state = runtime.start(stop_event=self._external_stop_event)
                if self._external_stop_requested():
                    runtime.close()
                    return self._external_stop(control)
                if (
                    not isinstance(state, InstalledChannelSupervisorState)
                    or not state.start_allowed
                ):
                    raise InstalledChannelWatchdogError("runtime start proof is invalid")
                refreshed = self._evaluate_health(runtime, state)
                if self._external_stop_requested():
                    runtime.close()
                    runtime = None
                    return self._external_stop(control)
                if refreshed is None:
                    raise InstalledChannelWatchdogError("runtime health proof is unavailable")
                state = refreshed
            except Exception:
                if runtime is not None:
                    try:
                        runtime.close()
                    except Exception as exc:
                        raise InstalledChannelWatchdogError(
                            "failed runtime could not be closed"
                        ) from exc
                if self._external_stop_requested():
                    return self._external_stop(control)
                return self._retry(now, control)
            self._runtime = runtime
            self._state = state
            self._healthy_since = now
            return InstalledChannelWatchdogStep(
                action="started",
                state=state,
                control=control,
                restart_attempt=self._restart_attempt,
                retry_delay_seconds=None,
            )

        assert self._state is not None
        try:
            refreshed = self._evaluate_health(self._runtime, self._state)
        except Exception:
            refreshed = None
        if self._external_stop_requested():
            return self._external_stop(control)
        if refreshed is None:
            self._close_runtime()
            return self._retry(now, control)
        self._state = refreshed
        if (
            self._healthy_since is not None
            and now - self._healthy_since >= self._stable_reset
        ):
            self._restart_attempt = 0
        return InstalledChannelWatchdogStep(
            action="healthy",
            state=self._state,
            control=control,
            restart_attempt=self._restart_attempt,
            retry_delay_seconds=None,
        )

    def process_receipts(self):
        if self._closed or self._runtime is None or self._state is None:
            raise InstalledChannelWatchdogError("running process tree is unavailable")
        reader = getattr(self._runtime, "process_receipts", None)
        if not callable(reader):
            raise InstalledChannelWatchdogError("process receipts are unavailable")
        try:
            receipts = reader()
        except Exception as exc:
            raise InstalledChannelWatchdogError(
                "process receipts are unavailable"
            ) from exc
        if tuple(receipts) != ("engine", "weixin", "feishu"):
            raise InstalledChannelWatchdogError("process receipts are invalid")
        return receipts

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_runtime()

    def force_close(self) -> None:
        with self._runtime_lock:
            runtime = self._closing_runtime or self._runtime
        if runtime is None:
            return None
        force = getattr(runtime, "force_close", None)
        if not callable(force) or force() is not None:
            raise InstalledChannelWatchdogError("runtime force close failed")
        return None

    def is_quiescent(self) -> bool:
        with self._runtime_lock:
            runtime = self._closing_runtime or self._runtime
        if runtime is None:
            return True
        probe = getattr(runtime, "is_quiescent", None)
        if not callable(probe):
            raise InstalledChannelWatchdogError("runtime quiescence is unavailable")
        quiescent = probe()
        if type(quiescent) is not bool:
            raise InstalledChannelWatchdogError("runtime quiescence is invalid")
        return quiescent


__all__ = [
    "InstalledChannelSupervisorWatchdog",
    "InstalledChannelWatchdogError",
    "InstalledChannelWatchdogStep",
]
