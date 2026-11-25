from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from gateway.installed_channel_service_runtime import (
    InstalledChannelOwnerCoordinatorLease,
    InstalledChannelServiceRuntime,
    InstalledChannelServiceRuntimeError,
    build_owned_coordinator_factory,
)
from gateway.windows_nachuan_core_service_host import NachuanCoreServiceHost


def test_service_runtime_owns_coordinator_until_host_shutdown() -> None:
    calls: list[str] = []
    seen_events = []

    class Coordinator:
        def __init__(self) -> None:
            self.quiescent = False

        def step(self):
            calls.append("coordinator.step")
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="started",
                    retry_delay_seconds=None,
                )
            )

        def close(self) -> None:
            calls.append("coordinator.close")
            self.quiescent = True

        def force_close(self) -> None:
            calls.append("coordinator.force")
            self.quiescent = True

        def is_quiescent(self) -> bool:
            calls.append("coordinator.quiescent")
            return self.quiescent

    coordinator = Coordinator()

    def coordinator_factory(stop_event):
        calls.append("coordinator.factory")
        seen_events.append(stop_event)
        return coordinator

    runtime = InstalledChannelServiceRuntime(
        coordinator_factory=coordinator_factory,
    )
    stop_event = threading.Event()

    assert runtime.start(stop_event) is None
    stop_event.set()
    stopping: list[str] = []
    assert runtime.run(stop_event, lambda: stopping.append("scm")) == 0
    assert coordinator.quiescent is False
    assert runtime.close() is None
    assert runtime.is_quiescent() is True

    assert seen_events == [stop_event]
    assert stopping == ["scm"]
    assert calls == [
        "coordinator.factory",
        "coordinator.step",
        "coordinator.close",
        "coordinator.quiescent",
    ]


def test_host_drives_service_runtime_to_quiescence_before_stopped() -> None:
    statuses = []
    calls: list[str] = []

    class Coordinator:
        def __init__(self) -> None:
            self.quiescent = False

        def step(self):
            calls.append("step")
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action="started",
                    retry_delay_seconds=None,
                )
            )

        def close(self) -> None:
            calls.append("close")
            self.quiescent = True

        def force_close(self) -> None:
            calls.append("force")
            self.quiescent = True

        def is_quiescent(self) -> bool:
            calls.append("quiescent")
            return self.quiescent

    class Scm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    runtime_factory = lambda: InstalledChannelServiceRuntime(
        coordinator_factory=lambda _stop_event: Coordinator()
    )
    host = NachuanCoreServiceHost(Scm(), runtime_factory=runtime_factory)

    assert host.run() == 0
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert calls == ["step", "close", "quiescent", "quiescent"]
    assert "force" not in calls


def test_pre_set_stop_event_prevents_coordinator_factory() -> None:
    stop_event = threading.Event()
    stop_event.set()
    calls: list[str] = []
    runtime = InstalledChannelServiceRuntime(
        coordinator_factory=lambda _event: calls.append("factory")
    )

    with pytest.raises(
        InstalledChannelServiceRuntimeError,
        match="cannot start",
    ):
        runtime.start(stop_event)
    assert calls == []


def test_stop_set_by_factory_prevents_initial_step() -> None:
    stop_event = threading.Event()
    calls: list[str] = []

    class Coordinator:
        def step(self):
            calls.append("step")
            raise AssertionError("Stop after factory must prevent initial step")

        def close(self) -> None:
            calls.append("close")

        def force_close(self) -> None:
            calls.append("force")

        def is_quiescent(self) -> bool:
            return True

    def factory(_event):
        calls.append("factory")
        stop_event.set()
        return Coordinator()

    runtime = InstalledChannelServiceRuntime(coordinator_factory=factory)
    with pytest.raises(
        InstalledChannelServiceRuntimeError,
        match="cannot start",
    ):
        runtime.start(stop_event)
    assert calls == ["factory"]


@pytest.mark.parametrize("action", ("retry_scheduled", "backoff"))
def test_initial_retry_transition_remains_in_service_loop(action: str) -> None:
    calls: list[str] = []

    class StopEvent:
        def __init__(self) -> None:
            self.waits: list[float] = []

        def is_set(self) -> bool:
            return False

        def wait(self, delay: float) -> bool:
            self.waits.append(delay)
            return True

    class Coordinator:
        def __init__(self) -> None:
            self.quiescent = False

        def step(self):
            calls.append("step")
            return SimpleNamespace(
                watchdog=SimpleNamespace(
                    action=action,
                    retry_delay_seconds=4.5,
                )
            )

        def close(self) -> None:
            self.quiescent = True

        def force_close(self) -> None:
            self.quiescent = True

        def is_quiescent(self) -> bool:
            return self.quiescent

    runtime = InstalledChannelServiceRuntime(
        coordinator_factory=lambda _event: Coordinator()
    )
    stop_event = StopEvent()

    assert runtime.start(stop_event) is None
    stopping: list[str] = []
    assert runtime.run(stop_event, lambda: stopping.append("scm")) == 0
    assert stop_event.waits == [4.5]
    assert stopping == ["scm"]


def test_owner_lock_is_acquired_before_factory_and_released_only_after_stopped() -> None:
    calls: list[str] = []

    class OwnerLock:
        def __enter__(self):
            calls.append("owner.enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            calls.append("owner.exit")
            return False

    class Coordinator:
        def __init__(self) -> None:
            self.quiescent = False

        def step(self):
            calls.append("coordinator.step")
            return SimpleNamespace(watchdog=SimpleNamespace(action="started"))

        def close(self):
            calls.append("coordinator.close")
            self.quiescent = True

        def force_close(self):
            calls.append("coordinator.force")
            self.quiescent = True

        def is_quiescent(self):
            calls.append("coordinator.quiescent")
            return self.quiescent

    def coordinator_factory(stop_event):
        assert isinstance(stop_event, threading.Event)
        calls.append("coordinator.factory")
        assert calls == ["owner.enter", "coordinator.factory"]
        return Coordinator()

    factory = build_owned_coordinator_factory(
        owner_lock_factory=OwnerLock,
        coordinator_factory=coordinator_factory,
    )
    lease = factory(threading.Event())
    assert isinstance(lease, InstalledChannelOwnerCoordinatorLease)
    lease.step()
    lease.close()
    assert lease.is_quiescent() is True
    assert "owner.exit" not in calls

    assert lease.after_stopped() is None
    assert lease.after_stopped() is None
    assert calls[-1] == "owner.exit"
    assert calls.count("owner.exit") == 1


def test_host_reports_stopped_before_releasing_owned_coordinator() -> None:
    events: list[str] = []

    class Coordinator:
        def __init__(self) -> None:
            self.quiescent = False

        def step(self):
            return SimpleNamespace(watchdog=SimpleNamespace(action="started"))

        def close(self):
            self.quiescent = True

        def force_close(self):
            self.quiescent = True

        def is_quiescent(self):
            return self.quiescent

        def after_stopped(self):
            events.append("owner.released")

    class Scm:
        handler = None

        def dispatch(self, service_name, service_main):
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status"

        def report_status(self, status_handle, status):
            events.append(f"status:{status.current_state}")
            if status.current_state == 4:
                self.handler(1)

        def assert_runtime_identity(self):
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    host = NachuanCoreServiceHost(
        Scm(),
        runtime_factory=lambda: InstalledChannelServiceRuntime(
            coordinator_factory=lambda _event: Coordinator()
        ),
    )

    assert host.run() == 0
    assert events[-2:] == ["status:1", "owner.released"]


def test_owned_factory_failure_releases_lock_without_returning_partial_lease() -> None:
    calls: list[str] = []

    class OwnerLock:
        def __enter__(self):
            calls.append("enter")

        def __exit__(self, exc_type, exc, tb):
            calls.append(f"exit:{exc_type.__name__}")
            return False

    def fail(_event):
        calls.append("factory")
        raise RuntimeError("assembly failed")

    factory = build_owned_coordinator_factory(
        owner_lock_factory=OwnerLock,
        coordinator_factory=fail,
    )
    with pytest.raises(RuntimeError, match="assembly failed"):
        factory(threading.Event())
    assert calls == ["enter", "factory", "exit:RuntimeError"]


def test_owner_lock_cannot_release_before_force_proves_quiescence() -> None:
    calls: list[str] = []

    class OwnerLock:
        def __enter__(self):
            calls.append("enter")

        def __exit__(self, _exc_type, _exc, _tb):
            calls.append("exit")

    class Coordinator:
        quiescent = False

        def step(self):
            return SimpleNamespace(watchdog=SimpleNamespace(action="started"))

        def close(self):
            return None

        def force_close(self):
            self.quiescent = True

        def is_quiescent(self):
            return self.quiescent

    lease = build_owned_coordinator_factory(
        owner_lock_factory=OwnerLock,
        coordinator_factory=lambda _event: Coordinator(),
    )(threading.Event())
    lease.close()
    with pytest.raises(
        InstalledChannelServiceRuntimeError,
        match="before quiescence",
    ):
        lease.after_stopped()
    assert calls == ["enter"]

    lease.force_close()
    lease.after_stopped()
    assert calls == ["enter", "exit"]
