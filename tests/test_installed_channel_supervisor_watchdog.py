from __future__ import annotations

import threading
from dataclasses import dataclass

import pytest

from gateway.installation_root import installation_principal
from gateway.installed_channel_supervisor import InstalledChannelSupervisorState
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControl,
)
from gateway.installed_channel_supervisor_watchdog import (
    InstalledChannelSupervisorWatchdog,
    InstalledChannelWatchdogError,
)


def _control(*, stop_requested: bool) -> InstalledChannelSupervisorControl:
    installation_id = "c" * 64
    epoch = 2
    return InstalledChannelSupervisorControl(
        control_generation=1,
        installation_id=installation_id,
        installation_epoch=epoch,
        installation_principal=installation_principal(installation_id, epoch),
        config_generation=3,
        stop_requested=stop_requested,
    )


@dataclass
class _Runtime:
    pid: int
    healthy: bool = True
    started: int = 0
    closed: int = 0

    def start(self) -> InstalledChannelSupervisorState:
        self.started += 1
        return InstalledChannelSupervisorState(
            pids={"engine": self.pid, "weixin": self.pid + 1, "feishu": self.pid + 2},
            ready=True,
        )

    def close(self) -> None:
        self.closed += 1


def test_stop_latch_blocks_initial_start() -> None:
    created: list[_Runtime] = []
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: created.append(_Runtime(100)) or created[-1],
        control_loader=lambda: _control(stop_requested=True),
        health_check=lambda runtime, _state: runtime.healthy,
        monotonic_clock=lambda: 10.0,
    )

    step = watchdog.step()

    assert step.action == "stopped"
    assert step.retry_delay_seconds is None
    assert created == []


def test_external_stop_blocks_runtime_factory_without_writing_persistent_stop() -> None:
    stop_event = threading.Event()
    stop_event.set()
    created: list[_Runtime] = []
    controls: list[InstalledChannelSupervisorControl] = []

    def load_control() -> InstalledChannelSupervisorControl:
        control = _control(stop_requested=False)
        controls.append(control)
        return control

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: created.append(_Runtime(100)) or created[-1],
        control_loader=load_control,
        health_check=lambda runtime, _state: runtime.healthy,
        monotonic_clock=lambda: 10.0,
        external_stop_event=stop_event,
    )

    step = watchdog.step()

    assert step.action == "external_stopped"
    assert step.control.stop_requested is False
    assert len(controls) == 1
    assert created == []


def test_external_stop_during_runtime_start_never_schedules_retry() -> None:
    stop_event = threading.Event()

    class Runtime:
        def __init__(self) -> None:
            self.closed = 0
            self.seen_event = None

        def start(self, *, stop_event):
            self.seen_event = stop_event
            stop_event.set()
            raise RuntimeError("synthetic interrupted start")

        def close(self) -> None:
            self.closed += 1

    runtime = Runtime()
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: _control(stop_requested=False),
        health_check=lambda _runtime, _state: True,
        monotonic_clock=lambda: 10.0,
        external_stop_event=stop_event,
    )

    step = watchdog.step()

    assert step.action == "external_stopped"
    assert step.retry_delay_seconds is None
    assert runtime.seen_event is stop_event
    assert runtime.closed == 1


def test_external_stop_during_initial_health_never_publishes_started() -> None:
    stop_event = threading.Event()

    class Runtime(_Runtime):
        def start(self, *, stop_event):
            self.started += 1
            return InstalledChannelSupervisorState(
                pids={"engine": self.pid, "weixin": self.pid + 1, "feishu": self.pid + 2},
                ready=True,
            )

    runtime = Runtime(400)

    def health(_runtime, _state):
        stop_event.set()
        return True

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: _control(stop_requested=False),
        health_check=health,
        monotonic_clock=lambda: 10.0,
        external_stop_event=stop_event,
    )

    step = watchdog.step()

    assert step.action == "external_stopped"
    assert step.state is None
    assert runtime.closed == 1


def test_external_stop_during_running_health_never_publishes_healthy() -> None:
    stop_event = threading.Event()

    class Runtime(_Runtime):
        def start(self, *, stop_event):
            self.started += 1
            return InstalledChannelSupervisorState(
                pids={"engine": self.pid, "weixin": self.pid + 1, "feishu": self.pid + 2},
                ready=True,
            )

    runtime = Runtime(500)
    health_calls = 0

    def health(_runtime, _state):
        nonlocal health_calls
        health_calls += 1
        if health_calls == 2:
            stop_event.set()
        return True

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: _control(stop_requested=False),
        health_check=health,
        monotonic_clock=iter((10.0, 11.0)).__next__,
        external_stop_event=stop_event,
    )

    assert watchdog.step().action == "started"
    stopped = watchdog.step()

    assert stopped.action == "external_stopped"
    assert stopped.state is None
    assert runtime.closed == 1


def test_watchdog_keeps_runtime_visible_until_concurrent_force_quiesces() -> None:
    close_started = threading.Event()
    release_close = threading.Event()

    class Runtime:
        def __init__(self) -> None:
            self.forces = 0
            self.quiescent = False

        def start(self):
            return InstalledChannelSupervisorState(
                pids={"engine": 700, "weixin": 701, "feishu": 702},
                ready=True,
            )

        def close(self) -> None:
            close_started.set()
            assert release_close.wait(5)
            self.quiescent = True

        def force_close(self) -> None:
            self.forces += 1
            release_close.set()

        def is_quiescent(self) -> bool:
            return self.quiescent

    runtime = Runtime()
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: _control(stop_requested=False),
        health_check=lambda _runtime, _state: True,
        monotonic_clock=lambda: 10.0,
    )
    assert watchdog.step().action == "started"

    closer = threading.Thread(target=watchdog.close)
    closer.start()
    assert close_started.wait(5)
    assert watchdog.is_quiescent() is False
    assert watchdog.force_close() is None
    closer.join(5)

    assert not closer.is_alive()
    assert runtime.forces == 1
    assert watchdog.is_quiescent() is True


def test_unhealthy_tree_is_closed_and_backoff_prevents_immediate_restart() -> None:
    clock = [100.0]
    created: list[_Runtime] = []

    def factory() -> _Runtime:
        runtime = _Runtime(100 + len(created) * 10)
        created.append(runtime)
        return runtime

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=factory,
        control_loader=lambda: _control(stop_requested=False),
        health_check=lambda runtime, _state: runtime.healthy,
        monotonic_clock=lambda: clock[0],
        initial_backoff_seconds=2.0,
        maximum_backoff_seconds=8.0,
        stable_reset_seconds=30.0,
    )
    assert watchdog.step().action == "started"
    created[0].healthy = False

    failed = watchdog.step()
    assert failed.action == "retry_scheduled"
    assert failed.retry_delay_seconds == 2.0
    assert failed.restart_attempt == 1
    assert created[0].closed == 1

    assert watchdog.step().action == "backoff"
    assert len(created) == 1
    clock[0] += 2.0
    restarted = watchdog.step()
    assert restarted.action == "started"
    assert restarted.restart_attempt == 1
    assert len(created) == 2


def test_unavailable_stop_latch_closes_a_running_tree() -> None:
    controls: list[object] = [_control(stop_requested=False), RuntimeError("broken")]
    runtime = _Runtime(200)

    def load_control() -> InstalledChannelSupervisorControl:
        value = controls.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=load_control,
        health_check=lambda current, _state: current.healthy,
        monotonic_clock=iter((10.0, 11.0)).__next__,
    )
    assert watchdog.step().action == "started"

    with pytest.raises(
        InstalledChannelWatchdogError, match="persistent stop latch is unavailable"
    ):
        watchdog.step()
    assert runtime.closed == 1


def test_detailed_health_state_can_remain_started_without_being_ready() -> None:
    runtime = _Runtime(300)
    degraded = InstalledChannelSupervisorState(
        pids={"engine": 300, "weixin": 301, "feishu": 302},
        ready=False,
        start_allowed=True,
    )
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: _control(stop_requested=False),
        health_check=lambda _runtime, _state: degraded,
        monotonic_clock=lambda: 20.0,
    )

    step = watchdog.step()

    assert step.action == "started"
    assert step.state == degraded
    assert step.state.ready is False
    assert runtime.closed == 0
