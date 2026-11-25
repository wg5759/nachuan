from __future__ import annotations

import ctypes
import threading
from pathlib import Path

import pytest

from gateway.windows_nachuan_core_service_host import (
    NativeWindowsScmPort,
    NachuanCoreServiceHost,
    ServiceControllerUnavailable,
    ServiceRuntimeShutdownController,
)
from gateway.installed_channel_supervisor_entrypoint import run_coordinator_loop


def test_dispatcher_outside_scm_fails_closed_without_starting_service_main() -> None:
    calls: list[str] = []

    class OutsideScm:
        def dispatch(self, service_name, service_main) -> None:
            calls.append(f"dispatch:{service_name}")
            raise ServiceControllerUnavailable

        def register_handler(self, service_name, handler):
            raise AssertionError("handler must not be registered outside SCM")

        def report_status(self, status_handle, status) -> None:
            raise AssertionError("status must not be reported outside SCM")

        def assert_runtime_identity(self) -> str:
            raise AssertionError("identity must not be read outside SCM")

    assert NachuanCoreServiceHost(OutsideScm()).run() == 77
    assert calls == ["dispatch:NachuanCore"]


def test_dispatcher_return_without_service_main_is_never_success() -> None:
    class EmptyDispatcher:
        def dispatch(self, service_name, service_main) -> None:
            assert service_name == "NachuanCore"

        def register_handler(self, service_name, handler):
            raise AssertionError("service main was not called")

        def report_status(self, status_handle, status) -> None:
            raise AssertionError("service main was not called")

        def assert_runtime_identity(self) -> str:
            raise AssertionError("service main was not called")

    assert NachuanCoreServiceHost(EmptyDispatcher()).run() == 69


def test_service_main_reports_the_exact_empty_host_lifecycle() -> None:
    calls: list[str] = []
    statuses = []

    class FakeScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            calls.append(f"dispatch:{service_name}")
            service_main()

        def register_handler(self, service_name, handler):
            calls.append(f"register:{service_name}")
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            assert status_handle == "status-handle"
            calls.append(f"status:{status.current_state}")
            statuses.append(status)
            if status.current_state == 4:
                assert self.handler is not None
                assert self.handler(1) == 0

        def assert_runtime_identity(self) -> str:
            calls.append("identity")
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(FakeScm()).run() == 0
    assert calls == [
        "dispatch:NachuanCore",
        "register:NachuanCore",
        "status:2",
        "identity",
        "status:4",
        "status:3",
        "status:1",
    ]
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert [status.controls_accepted for status in statuses] == [0, 261, 0, 0]
    assert [status.check_point for status in statuses] == [1, 0, 1, 0]
    assert [status.wait_hint_ms for status in statuses] == [15000, 0, 45000, 0]
    assert all(status.win32_exit_code == 0 for status in statuses)
    assert all(status.service_specific_exit_code == 0 for status in statuses)


def test_runtime_is_created_after_identity_and_uses_the_handler_stop_event() -> None:
    calls: list[str] = []
    statuses = []
    seen_events = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, stop_event) -> None:
            calls.append("runtime.start")
            seen_events.append(stop_event)

        def run(self, stop_event, on_stopping) -> int:
            calls.append("runtime.run")
            seen_events.append(stop_event)
            assert stop_event.is_set()
            on_stopping()
            return 0

        def close(self) -> None:
            calls.append("runtime.close")
            self.closed = True

        def force_close(self) -> None:
            raise AssertionError("responsive runtime must not be forced")

        def is_quiescent(self) -> bool:
            return self.closed

    class RuntimeScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            calls.append("dispatch")
            service_main()

        def register_handler(self, service_name, handler):
            calls.append("register")
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            calls.append(f"status:{status.current_state}")
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            calls.append("identity")
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    def runtime_factory() -> Runtime:
        calls.append("runtime.factory")
        return Runtime()

    host = NachuanCoreServiceHost(RuntimeScm(), runtime_factory=runtime_factory)
    assert host.run() == 0
    assert seen_events[0] is seen_events[1]
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert calls == [
        "dispatch",
        "register",
        "status:2",
        "identity",
        "runtime.factory",
        "runtime.start",
        "status:4",
        "runtime.run",
        "status:3",
        "runtime.close",
        "status:1",
    ]


def test_graceful_timeout_forces_runtime_and_waits_before_stopped() -> None:
    release_close = threading.Event()
    calls: list[str] = []
    statuses = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, _stop_event) -> None:
            return None

        def run(self, stop_event, on_stopping) -> int:
            assert stop_event.is_set()
            on_stopping()
            return 0

        def close(self) -> None:
            calls.append("runtime.close.start")
            assert release_close.wait(5)
            self.closed = True
            calls.append("runtime.close.done")

        def force_close(self) -> None:
            calls.append("runtime.force")
            release_close.set()

        def is_quiescent(self) -> bool:
            calls.append("runtime.quiescent")
            return self.closed

    class Scm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            calls.append(f"status:{status.current_state}")
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=0,
        force_timeout_seconds=1,
    )
    host = NachuanCoreServiceHost(
        Scm(),
        runtime_factory=Runtime,
        shutdown_controller=controller,
    )

    assert host.run() == 0
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert calls.index("status:3") < calls.index("runtime.close.start")
    assert calls.index("runtime.close.start") < calls.index("runtime.force")
    assert calls.index("runtime.force") < calls.index("runtime.close.done")
    assert calls.index("runtime.close.done") < calls.index("runtime.quiescent")
    assert calls.index("runtime.quiescent") < calls.index("status:1")
    assert calls.count("runtime.force") == 1


def test_close_exception_forces_once_and_requires_quiescence() -> None:
    calls: list[str] = []

    class Runtime:
        def __init__(self) -> None:
            self.forced = False

        def close(self) -> None:
            calls.append("close")
            raise RuntimeError("synthetic graceful failure")

        def force_close(self) -> None:
            calls.append("force")
            self.forced = True

        def is_quiescent(self) -> bool:
            calls.append("quiescent")
            return self.forced

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=0,
        force_timeout_seconds=1,
    )
    controller.shutdown(Runtime())

    assert calls == ["close", "force", "quiescent"]


def test_nonquiescent_graceful_close_forces_once() -> None:
    calls: list[str] = []

    class Runtime:
        def __init__(self) -> None:
            self.forced = False

        def close(self) -> None:
            calls.append("close")

        def force_close(self) -> None:
            calls.append("force")
            self.forced = True

        def is_quiescent(self) -> bool:
            calls.append("quiescent")
            return self.forced

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=1,
        force_timeout_seconds=1,
    )
    controller.shutdown(Runtime())

    assert calls == ["close", "quiescent", "force", "quiescent"]


def test_quiescence_probe_exception_forces_once() -> None:
    calls: list[str] = []

    class Runtime:
        def __init__(self) -> None:
            self.forced = False

        def close(self) -> None:
            calls.append("close")

        def force_close(self) -> None:
            calls.append("force")
            self.forced = True

        def is_quiescent(self) -> bool:
            calls.append("quiescent")
            if not self.forced:
                raise RuntimeError("synthetic quiescence probe failure")
            return True

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=1,
        force_timeout_seconds=1,
    )
    controller.shutdown(Runtime())

    assert calls == ["close", "quiescent", "force", "quiescent"]


def test_force_failure_waits_for_close_proof_before_error_stopped() -> None:
    release_close = threading.Event()
    calls: list[str] = []
    statuses = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, _stop_event) -> None:
            return None

        def run(self, stop_event, on_stopping) -> int:
            assert stop_event.is_set()
            on_stopping()
            return 0

        def close(self) -> None:
            calls.append("close.start")
            assert release_close.wait(5)
            self.closed = True
            calls.append("close.done")

        def force_close(self) -> None:
            calls.append("force")
            release_close.set()
            raise RuntimeError("synthetic force failure")

        def is_quiescent(self) -> bool:
            calls.append("quiescent")
            return self.closed

    class Scm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            calls.append(f"status:{status.current_state}")
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=0,
        force_timeout_seconds=1,
    )
    host = NachuanCoreServiceHost(
        Scm(),
        runtime_factory=Runtime,
        shutdown_controller=controller,
    )

    assert host.run() == 69
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert calls.index("force") < calls.index("close.done")
    assert calls.index("close.done") < calls.index("quiescent")
    assert calls.index("quiescent") < calls.index("status:1")
    assert statuses[-1].win32_exit_code == 1066


def test_blocked_force_close_is_bounded_by_force_timeout() -> None:
    release_force = threading.Event()
    force_started = threading.Event()
    shutdown_done = threading.Event()
    failures: list[BaseException] = []

    class Runtime:
        def close(self) -> None:
            raise RuntimeError("force is required")

        def force_close(self) -> None:
            force_started.set()
            assert release_force.wait(5)

        def is_quiescent(self) -> bool:
            return False

    controller = ServiceRuntimeShutdownController(
        graceful_timeout_seconds=0,
        force_timeout_seconds=0.05,
    )

    def shutdown() -> None:
        try:
            controller.shutdown(Runtime())
        except BaseException as exc:
            failures.append(exc)
        finally:
            shutdown_done.set()

    owner = threading.Thread(target=shutdown)
    owner.start()
    try:
        assert force_started.wait(1)
        assert shutdown_done.wait(0.25)
    finally:
        release_force.set()
        owner.join(1)

    assert not owner.is_alive()
    assert len(failures) == 1


def test_handler_stop_event_reaches_the_interruptible_coordinator_loop() -> None:
    calls: list[str] = []
    statuses = []

    class Coordinator:
        def step(self):
            calls.append("coordinator.step")
            raise AssertionError("pre-set SCM Stop must prevent coordinator step")

        def close(self) -> None:
            calls.append("coordinator.close")

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, stop_event) -> None:
            calls.append("runtime.start")

        def run(self, stop_event, on_stopping) -> int:
            calls.append("runtime.run")
            return run_coordinator_loop(
                Coordinator(),
                stop_event=stop_event,
                on_stopping=on_stopping,
                sleeper=lambda _delay: (_ for _ in ()).throw(
                    AssertionError("SCM Stop must not sleep")
                ),
            )

        def close(self) -> None:
            calls.append("runtime.close")
            self.closed = True

        def force_close(self) -> None:
            raise AssertionError("responsive coordinator loop must not be forced")

        def is_quiescent(self) -> bool:
            return self.closed

    class Scm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            calls.append(f"status:{status.current_state}")
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    host = NachuanCoreServiceHost(Scm(), runtime_factory=Runtime)
    assert host.run() == 0
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert "coordinator.step" not in calls
    assert calls.index("status:3") < calls.index("coordinator.close")
    assert calls.index("coordinator.close") < calls.index("runtime.close")
    assert calls.index("runtime.close") < calls.index("status:1")


def test_running_runtime_failure_reports_stop_pending_before_close() -> None:
    calls: list[str] = []
    statuses = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, _stop_event) -> None:
            return None

        def run(self, _stop_event, _on_stopping) -> int:
            calls.append("runtime.run")
            raise RuntimeError("synthetic runtime failure")

        def close(self) -> None:
            calls.append("runtime.close")
            self.closed = True

        def force_close(self) -> None:
            raise AssertionError("responsive failed runtime must not be forced")

        def is_quiescent(self) -> bool:
            return self.closed

    class Scm:
        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            calls.append(f"status:{status.current_state}")

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(Scm(), runtime_factory=Runtime).run() == 69
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert calls.index("status:3") < calls.index("runtime.close")
    stopped = statuses[-1]
    assert stopped.win32_exit_code == 1066
    assert stopped.service_specific_exit_code == 0x4E430001


def test_runtime_cannot_claim_clean_stop_without_the_scm_event() -> None:
    statuses = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, _stop_event) -> None:
            return None

        def run(self, _stop_event, _on_stopping) -> int:
            return 0

        def close(self) -> None:
            self.closed = True

        def force_close(self) -> None:
            self.closed = True

        def is_quiescent(self) -> bool:
            return self.closed

    class Scm:
        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(Scm(), runtime_factory=Runtime).run() == 69
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]
    assert statuses[-1].win32_exit_code == 1066


def test_stop_during_runtime_start_closes_cleanly_without_running() -> None:
    statuses = []
    calls: list[str] = []

    class Runtime:
        def __init__(self) -> None:
            self.closed = False

        def start(self, stop_event) -> None:
            calls.append("runtime.start")
            stop_event.set()
            raise RuntimeError("synthetic interrupted start")

        def run(self, _stop_event, _on_stopping) -> int:
            raise AssertionError("interrupted start must not run")

        def close(self) -> None:
            calls.append("runtime.close")
            self.closed = True

        def force_close(self) -> None:
            raise AssertionError("responsive interrupted start must not force")

        def is_quiescent(self) -> bool:
            return self.closed

    class Scm:
        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(Scm(), runtime_factory=Runtime).run() == 0
    assert [status.current_state for status in statuses] == [2, 3, 1]
    assert calls == ["runtime.start", "runtime.close"]


def test_invalid_service_identity_stops_once_with_a_fixed_service_error() -> None:
    statuses = []
    runtime_factory_calls: list[str] = []

    class WrongIdentityScm:
        def dispatch(self, service_name, service_main) -> None:
            assert service_name == "NachuanCore"
            service_main()

        def register_handler(self, service_name, handler):
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-19"

    def runtime_factory():
        runtime_factory_calls.append("factory")
        raise AssertionError("invalid identity must not construct runtime")

    assert NachuanCoreServiceHost(
        WrongIdentityScm(),
        runtime_factory=runtime_factory,
    ).run() == 69
    assert [status.current_state for status in statuses] == [2, 1]
    assert runtime_factory_calls == []
    stopped = statuses[-1]
    assert stopped.win32_exit_code == 1066
    assert stopped.service_specific_exit_code == 0x4E430001
    assert stopped.controls_accepted == 0
    assert stopped.check_point == 0
    assert stopped.wait_hint_ms == 0


def test_stop_during_start_pending_never_reports_running() -> None:
    statuses = []
    identity_calls: list[str] = []
    runtime_factory_calls: list[str] = []

    class EarlyStopScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            if status.current_state == 2:
                assert self.handler is not None
                assert self.handler(1) == 0

        def assert_runtime_identity(self) -> str:
            identity_calls.append("identity")
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    def runtime_factory():
        runtime_factory_calls.append("factory")
        raise AssertionError("early Stop must not construct a runtime")

    assert NachuanCoreServiceHost(
        EarlyStopScm(),
        runtime_factory=runtime_factory,
    ).run() == 0
    assert identity_calls == []
    assert runtime_factory_calls == []
    assert [status.current_state for status in statuses] == [2, 3, 1]


def test_duplicate_service_main_never_starts_a_second_lifecycle() -> None:
    statuses = []

    class DuplicateMainScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()
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

    assert NachuanCoreServiceHost(DuplicateMainScm()).run() == 69
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]


def test_concurrent_service_main_reentry_is_rejected_while_first_is_running() -> None:
    statuses = []
    running = threading.Event()

    class ConcurrentMainScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            first = threading.Thread(target=service_main)
            first.start()
            assert running.wait(5)
            service_main()
            assert self.handler is not None
            self.handler(1)
            first.join(5)
            assert not first.is_alive()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            statuses.append(status)
            if status.current_state == 4:
                running.set()

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(ConcurrentMainScm()).run() == 69
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]


def test_concurrent_stop_and_preshutdown_controls_coalesce_once() -> None:
    running = threading.Event()
    result: list[int] = []
    statuses = []
    status_lock = threading.Lock()

    class ConcurrentScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            with status_lock:
                statuses.append(status)
            if status.current_state == 4:
                running.set()

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    scm = ConcurrentScm()
    host = NachuanCoreServiceHost(scm)
    host_thread = threading.Thread(target=lambda: result.append(host.run()))
    host_thread.start()
    assert running.wait(5)
    assert scm.handler is not None
    barrier = threading.Barrier(9)
    handler_results: list[int] = []

    def send(control: int) -> None:
        barrier.wait()
        handler_results.append(scm.handler(control))

    workers = [
        threading.Thread(target=send, args=(1 if index % 2 == 0 else 15,))
        for index in range(8)
    ]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(5)
        assert not worker.is_alive()
    host_thread.join(5)

    assert not host_thread.is_alive()
    assert result == [0]
    assert handler_results == [0] * 8
    states = [status.current_state for status in statuses]
    assert states == [2, 4, 3, 1]
    assert states.count(3) == 1
    assert states.count(1) == 1


def test_control_handler_returns_before_stop_pending_reporting_finishes() -> None:
    running = threading.Event()
    stop_pending_entered = threading.Event()
    allow_stop_pending = threading.Event()
    result: list[int] = []

    class BlockingStatusScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            if status.current_state == 4:
                running.set()
            if status.current_state == 3:
                stop_pending_entered.set()
                assert allow_stop_pending.wait(5)

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    scm = BlockingStatusScm()
    host_thread = threading.Thread(
        target=lambda: result.append(NachuanCoreServiceHost(scm).run())
    )
    host_thread.start()
    assert running.wait(5)
    assert scm.handler is not None
    assert scm.handler(1) == 0
    assert stop_pending_entered.wait(5)
    assert host_thread.is_alive()
    allow_stop_pending.set()
    host_thread.join(5)

    assert not host_thread.is_alive()
    assert result == [0]


def test_stop_controls_after_stopped_are_noops() -> None:
    statuses = []

    class LateControlScm:
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

    scm = LateControlScm()
    assert NachuanCoreServiceHost(scm).run() == 0
    before = list(statuses)
    assert scm.handler is not None
    assert scm.handler(1) == 0
    assert scm.handler(15) == 0
    assert statuses == before
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]


def test_native_adapter_uses_a_null_terminated_table_and_real_callbacks() -> None:
    native_states: list[int] = []
    service_names: list[str | None] = []

    class NativeCall:
        def __init__(self, implementation) -> None:
            self.implementation = implementation
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.implementation(*args)

    class FakeAdvapi32:
        handler = None

        def __init__(self) -> None:
            self.StartServiceCtrlDispatcherW = NativeCall(self.start_dispatcher)
            self.RegisterServiceCtrlHandlerExW = NativeCall(self.register_handler)
            self.SetServiceStatus = NativeCall(self.set_status)

        def start_dispatcher(self, table) -> int:
            service_names.extend([table[0].lpServiceName, table[1].lpServiceName])
            assert bool(table[0].lpServiceProc)
            assert not bool(table[1].lpServiceProc)
            arguments = (ctypes.c_wchar_p * 1)("NachuanCore")
            table[0].lpServiceProc(1, arguments)
            return 1

        def register_handler(self, service_name, handler, context):
            assert service_name == "NachuanCore"
            assert context is None
            self.handler = handler
            return 123

        def set_status(self, status_handle, status_pointer) -> int:
            assert status_handle == 123
            status = status_pointer._obj
            native_states.append(status.dwCurrentState)
            if status.dwCurrentState == 4:
                assert self.handler is not None
                assert self.handler(1, 0, None, None) == 0
            return 1

    fake = FakeAdvapi32()
    port = NativeWindowsScmPort(
        advapi32=fake,
        get_last_error=lambda: 0,
        identity_probe=lambda: "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048",
    )

    assert NachuanCoreServiceHost(port).run() == 0
    assert service_names == ["NachuanCore", None]
    assert native_states == [2, 4, 3, 1]


def test_native_service_main_rejects_start_parameters_before_registration() -> None:
    calls: list[str] = []

    class NativeCall:
        def __init__(self, implementation) -> None:
            self.implementation = implementation
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.implementation(*args)

    class ExtraArgumentAdvapi32:
        def __init__(self) -> None:
            self.StartServiceCtrlDispatcherW = NativeCall(self.start_dispatcher)
            self.RegisterServiceCtrlHandlerExW = NativeCall(self.register_handler)
            self.SetServiceStatus = NativeCall(self.set_status)

        def start_dispatcher(self, table) -> int:
            calls.append("dispatcher")
            arguments = (ctypes.c_wchar_p * 2)("NachuanCore", "unexpected")
            table[0].lpServiceProc(2, arguments)
            return 1

        def register_handler(self, *args):
            calls.append("register")
            raise AssertionError("extra ServiceMain args must fail before registration")

        def set_status(self, *args) -> int:
            calls.append("status")
            return 1

    port = NativeWindowsScmPort(
        advapi32=ExtraArgumentAdvapi32(),
        get_last_error=lambda: 0,
        identity_probe=lambda: "unused",
    )
    assert NachuanCoreServiceHost(port).run() == 69
    assert calls == ["dispatcher"]


def test_native_console_launch_maps_error_1063_without_fallback() -> None:
    calls: list[str] = []

    class NativeCall:
        def __init__(self, implementation) -> None:
            self.implementation = implementation
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.implementation(*args)

    class OutsideScmAdvapi32:
        def __init__(self) -> None:
            self.StartServiceCtrlDispatcherW = NativeCall(self.start_dispatcher)
            self.RegisterServiceCtrlHandlerExW = NativeCall(self.unexpected)
            self.SetServiceStatus = NativeCall(self.unexpected)

        def start_dispatcher(self, table) -> int:
            calls.append("dispatcher")
            return 0

        def unexpected(self, *args):
            raise AssertionError("service body must not start after error 1063")

    port = NativeWindowsScmPort(
        advapi32=OutsideScmAdvapi32(),
        get_last_error=lambda: 1063,
        identity_probe=lambda: "unused",
    )
    assert NachuanCoreServiceHost(port).run() == 77
    assert calls == ["dispatcher"]


def test_interrogate_is_read_only_and_unknown_control_is_rejected() -> None:
    statuses = []
    control_results: list[int] = []

    class ControlScm:
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
                control_results.extend(
                    [self.handler(4), self.handler(999), self.handler(1)]
                )

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(ControlScm()).run() == 0
    assert control_results == [0, 120, 0]
    assert [status.current_state for status in statuses] == [2, 4, 3, 1]


def test_service_host_source_has_no_registration_or_authority_surface() -> None:
    source = (
        Path(__file__).parents[1]
        / "gateway"
        / "windows_nachuan_core_service_host.py"
    ).read_text("utf-8")

    for required in (
        "StartServiceCtrlDispatcherW",
        "RegisterServiceCtrlHandlerExW",
        "SetServiceStatus",
    ):
        assert required in source
    assert "runtime_factory=EmptyServiceRuntime" in source
    for forbidden in (
        "CreateServiceW",
        "OpenSCManagerW",
        "ChangeServiceConfigW",
        "ChangeServiceConfig2W",
        "DeleteService",
        "StartServiceW",
        "ControlService",
        "gateway.installation_root",
        "gateway.installed_service_machine_vault",
        "gateway.installed_service_state_acl",
        "installed_channel_service_runtime",
        "windows_installed_drain_pipe",
        "installed_channel_supervisor_control",
        "installed_channel_supervisor_status",
        "request_stop",
        "write_protected_json",
        "gateway.connections",
        "sqlite3",
        "subprocess",
        "requests",
        "os.environ",
    ):
        assert forbidden not in source


def test_stopped_status_failure_is_never_retried() -> None:
    attempted_states: list[int] = []

    class FailingStoppedScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            attempted_states.append(status.current_state)
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)
            if status.current_state == 1:
                raise RuntimeError("status handle already closed")

        def assert_runtime_identity(self) -> str:
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(FailingStoppedScm()).run() == 69
    assert attempted_states == [2, 4, 3, 1]
    assert attempted_states.count(1) == 1


def test_handler_registration_failure_reads_no_identity_and_starts_no_body() -> None:
    calls: list[str] = []

    class RegistrationFailureScm:
        def dispatch(self, service_name, service_main) -> None:
            calls.append("dispatch")
            service_main()

        def register_handler(self, service_name, handler):
            calls.append("register")
            raise RuntimeError("registration failed")

        def report_status(self, status_handle, status) -> None:
            calls.append("status")

        def assert_runtime_identity(self) -> str:
            calls.append("identity")
            return "unused"

    assert NachuanCoreServiceHost(RegistrationFailureScm()).run() == 69
    assert calls == ["dispatch", "register"]


@pytest.mark.parametrize(
    ("failure_state", "expected_states", "expected_identity_calls"),
    (
        (2, [2, 1], 0),
        (4, [2, 4, 1], 1),
        (3, [2, 4, 3, 1], 1),
    ),
)
def test_pending_or_running_status_failure_closes_once_without_waiting(
    failure_state: int,
    expected_states: list[int],
    expected_identity_calls: int,
) -> None:
    attempted_states: list[int] = []
    identity_calls: list[str] = []

    class StatusFailureScm:
        handler = None

        def dispatch(self, service_name, service_main) -> None:
            service_main()

        def register_handler(self, service_name, handler):
            self.handler = handler
            return "status-handle"

        def report_status(self, status_handle, status) -> None:
            attempted_states.append(status.current_state)
            if status.current_state == failure_state:
                raise RuntimeError("synthetic status failure")
            if status.current_state == 4:
                assert self.handler is not None
                self.handler(1)

        def assert_runtime_identity(self) -> str:
            identity_calls.append("identity")
            return "S-1-5-80-3592173032-2360559626-4162995744-2148626960-2939811048"

    assert NachuanCoreServiceHost(StatusFailureScm()).run() == 69
    assert attempted_states == expected_states
    assert len(identity_calls) == expected_identity_calls
    assert attempted_states.count(1) == 1
