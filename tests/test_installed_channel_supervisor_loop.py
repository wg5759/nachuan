from __future__ import annotations

import threading
from types import SimpleNamespace

from gateway.installed_channel_supervisor_entrypoint import run_coordinator_loop


def test_coordinator_loop_uses_watchdog_backoff_and_stops_without_another_step() -> None:
    transitions = iter(
        (
            SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="started", retry_delay_seconds=None
                )
            ),
            SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="retry_scheduled", retry_delay_seconds=3.5
                )
            ),
            SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="stopped", retry_delay_seconds=None
                )
            ),
        )
    )

    class Coordinator:
        def __init__(self) -> None:
            self.steps = 0
            self.closed = 0

        def step(self):
            self.steps += 1
            return next(transitions)

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()
    sleeps: list[float] = []

    result = run_coordinator_loop(
        coordinator,
        healthy_interval_seconds=2.0,
        sleeper=sleeps.append,
    )

    assert result == 0
    assert coordinator.steps == 3
    assert coordinator.closed == 1
    assert sleeps == [2.0, 3.5]


def test_external_stop_before_first_step_closes_once_without_sleep() -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.steps = 0
            self.closed = 0

        def step(self):
            self.steps += 1
            raise AssertionError("external Stop must prevent the first step")

        def close(self) -> None:
            self.closed += 1

    stop_event = threading.Event()
    stop_event.set()
    coordinator = Coordinator()
    sleeps: list[float] = []

    result = run_coordinator_loop(
        coordinator,
        stop_event=stop_event,
        sleeper=sleeps.append,
    )

    assert result == 0
    assert coordinator.steps == 0
    assert coordinator.closed == 1
    assert sleeps == []


def test_stop_set_during_started_step_prevents_wait_and_second_step() -> None:
    stop_event = threading.Event()

    class Coordinator:
        def __init__(self) -> None:
            self.steps = 0
            self.closed = 0

        def step(self):
            self.steps += 1
            if self.steps != 1:
                raise AssertionError("external Stop must prevent a second step")
            stop_event.set()
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="started",
                    retry_delay_seconds=None,
                )
            )

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()
    sleeps: list[float] = []

    result = run_coordinator_loop(
        coordinator,
        stop_event=stop_event,
        sleeper=sleeps.append,
    )

    assert result == 0
    assert coordinator.steps == 1
    assert coordinator.closed == 1
    assert sleeps == []


def test_external_stop_interrupts_healthy_wait() -> None:
    waits: list[float] = []

    class StopEvent:
        def is_set(self) -> bool:
            return False

        def wait(self, delay: float) -> bool:
            waits.append(delay)
            return True

    class Coordinator:
        def __init__(self) -> None:
            self.steps = 0
            self.closed = 0

        def step(self):
            self.steps += 1
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="healthy",
                    retry_delay_seconds=None,
                )
            )

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()

    result = run_coordinator_loop(
        coordinator,
        stop_event=StopEvent(),
        healthy_interval_seconds=2.5,
        sleeper=lambda _delay: (_ for _ in ()).throw(
            AssertionError("external Stop waits must be interruptible")
        ),
    )

    assert result == 0
    assert coordinator.steps == 1
    assert coordinator.closed == 1
    assert waits == [2.5]


def test_external_stop_interrupts_exact_watchdog_backoff() -> None:
    waits: list[float] = []

    class StopEvent:
        def is_set(self) -> bool:
            return False

        def wait(self, delay: float) -> bool:
            waits.append(delay)
            return True

    class Coordinator:
        def __init__(self) -> None:
            self.closed = 0

        def step(self):
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="retry_scheduled",
                    retry_delay_seconds=7.25,
                )
            )

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()
    assert run_coordinator_loop(coordinator, stop_event=StopEvent()) == 0
    assert coordinator.closed == 1
    assert waits == [7.25]


def test_external_stop_notifier_runs_once_before_coordinator_close() -> None:
    stop_event = threading.Event()
    stop_event.set()
    calls: list[str] = []

    class Coordinator:
        def step(self):
            raise AssertionError("external Stop must prevent step")

        def close(self) -> None:
            calls.append("close")

    result = run_coordinator_loop(
        Coordinator(),
        stop_event=stop_event,
        on_stopping=lambda: calls.append("stopping"),
    )

    assert result == 0
    assert calls == ["stopping", "close"]


def test_close_failure_overrides_a_clean_external_stop() -> None:
    stop_event = threading.Event()
    stop_event.set()
    closes: list[str] = []

    class Coordinator:
        def step(self):
            raise AssertionError("external Stop must prevent step")

        def close(self) -> None:
            closes.append("close")
            raise RuntimeError("synthetic close failure")

    assert run_coordinator_loop(Coordinator(), stop_event=stop_event) == 70
    assert closes == ["close"]


def test_persistent_stop_stays_idle_until_resume_or_scm_stop() -> None:
    transitions = iter(
        (
            SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="stopped",
                    retry_delay_seconds=None,
                )
            ),
            SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="started",
                    retry_delay_seconds=None,
                )
            ),
        )
    )
    waits: list[float] = []
    stopping: list[str] = []

    class StopEvent:
        def is_set(self) -> bool:
            return False

        def wait(self, delay: float) -> bool:
            waits.append(delay)
            return len(waits) == 2

    class Coordinator:
        def __init__(self) -> None:
            self.steps = 0
            self.closed = 0

        def step(self):
            self.steps += 1
            return next(transitions)

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()
    result = run_coordinator_loop(
        coordinator,
        stop_event=StopEvent(),
        on_stopping=lambda: stopping.append("scm"),
        healthy_interval_seconds=2.0,
    )

    assert result == 0
    assert coordinator.steps == 2
    assert coordinator.closed == 1
    assert waits == [2.0, 2.0]
    assert stopping == ["scm"]


def test_system_exit_from_step_still_closes_the_coordinator() -> None:
    closes: list[str] = []

    class Coordinator:
        def step(self):
            raise SystemExit(9)

        def close(self) -> None:
            closes.append("close")

    assert run_coordinator_loop(Coordinator(), sleeper=lambda _delay: None) == 70
    assert closes == ["close"]


def test_system_exit_from_close_is_a_runtime_failure() -> None:
    class Coordinator:
        def step(self):
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="stopped",
                    retry_delay_seconds=None,
                )
            )

        def close(self) -> None:
            raise SystemExit(11)

    assert run_coordinator_loop(Coordinator(), sleeper=lambda _delay: None) == 70


def test_service_loop_leaves_coordinator_open_for_host_shutdown_owner() -> None:
    stop_event = threading.Event()
    stop_event.set()

    class Coordinator:
        def __init__(self) -> None:
            self.closed = 0

        def step(self):
            raise AssertionError("pre-set SCM Stop must prevent step")

        def close(self) -> None:
            self.closed += 1

    coordinator = Coordinator()
    result = run_coordinator_loop(
        coordinator,
        stop_event=stop_event,
        close_on_exit=False,
    )

    assert result == 0
    assert coordinator.closed == 0


def test_service_loop_consumes_start_transition_without_second_step() -> None:
    waits: list[float] = []
    stopping: list[str] = []
    initial = SimpleNamespace(
        watchdog=SimpleNamespace(
            action="started",
            retry_delay_seconds=None,
        )
    )

    class StopEvent:
        def is_set(self) -> bool:
            return False

        def wait(self, delay: float) -> bool:
            waits.append(delay)
            return True

    class Coordinator:
        def step(self):
            raise AssertionError("initial transition must prevent a second step")

        def close(self) -> None:
            raise AssertionError("Host owns service runtime shutdown")

    result = run_coordinator_loop(
        Coordinator(),
        stop_event=StopEvent(),
        on_stopping=lambda: stopping.append("scm"),
        initial_transition=initial,
        close_on_exit=False,
        healthy_interval_seconds=3.0,
    )

    assert result == 0
    assert waits == [3.0]
    assert stopping == ["scm"]
