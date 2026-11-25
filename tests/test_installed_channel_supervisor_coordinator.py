from __future__ import annotations

import os
import threading

import pytest

from gateway.installation_root import installation_principal
from gateway.installed_channel_supervisor import (
    InstalledChannelEpochAnchor,
    InstalledChannelSupervisorState,
)
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)
from gateway.installed_channel_supervisor_coordinator import (
    InstalledChannelCoordinatorError,
    InstalledChannelSupervisorCoordinator,
)
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelSupervisorStatusStore,
)
from gateway.installed_channel_supervisor_watchdog import (
    InstalledChannelSupervisorWatchdog,
)


def _anchor() -> InstalledChannelEpochAnchor:
    installation_id = "d" * 64
    epoch = 6
    return InstalledChannelEpochAnchor(
        installation_id=installation_id,
        installation_epoch=epoch,
        installation_principal=installation_principal(installation_id, epoch),
        config_generation=8,
    )


def _receipt(seed: int) -> InstalledChannelProcessReceipt:
    return InstalledChannelProcessReceipt(
        pid=2000 + seed,
        started_utc_ticks=133_000_000_000_000_000 + seed,
        command_line_sha256=f"{seed:064x}",
    )


class _Runtime:
    def __init__(self) -> None:
        self.closed = 0

    def start(self) -> InstalledChannelSupervisorState:
        return InstalledChannelSupervisorState(
            pids={"engine": 2002, "weixin": 2003, "feishu": 2004},
            ready=True,
        )

    def process_receipts(self):
        return {
            "engine": _receipt(2),
            "weixin": _receipt(3),
            "feishu": _receipt(4),
        }

    def close(self) -> None:
        self.closed += 1


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI coordinator stores")
def test_coordinator_publishes_ready_then_persistent_stop_without_restart(tmp_path) -> None:
    anchor = _anchor()
    control_store = InstalledChannelSupervisorControlStore(
        (tmp_path / "installed-channel-supervisor-control.json").resolve()
    )
    control_store.initialize(anchor=anchor)
    status_store = InstalledChannelSupervisorStatusStore(
        (tmp_path / "installed-channel-supervisor-status.json").resolve()
    )
    runtimes: list[_Runtime] = []

    def factory() -> _Runtime:
        runtimes.append(_Runtime())
        return runtimes[-1]

    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=factory,
        control_loader=lambda: control_store.load(anchor=anchor),
        health_check=lambda _runtime, _state: True,
        monotonic_clock=iter((10.0, 11.0)).__next__,
    )
    coordinator = InstalledChannelSupervisorCoordinator(
        anchor=anchor,
        watchdog=watchdog,
        status_store=status_store,
        supervisor_receipt=_receipt(1),
    )

    started = coordinator.step()
    assert started.watchdog.action == "started"
    assert started.status.ready is True
    assert started.status.status_generation == 1

    control_store.request_stop(anchor=anchor, expected_control_generation=1)
    stopped = coordinator.step()
    assert stopped.watchdog.action == "stopped"
    assert stopped.status.state == "stopped"
    assert stopped.status.stop_requested is True
    assert stopped.status.status_generation == 2
    assert runtimes[0].closed == 1
    assert len(runtimes) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI coordinator stores")
def test_external_stop_publishes_stopped_without_persistent_stop(tmp_path) -> None:
    anchor = _anchor()
    control_store = InstalledChannelSupervisorControlStore(
        (tmp_path / "installed-channel-supervisor-control.json").resolve()
    )
    control_store.initialize(anchor=anchor)
    status_store = InstalledChannelSupervisorStatusStore(
        (tmp_path / "installed-channel-supervisor-status.json").resolve()
    )
    stop_event = threading.Event()
    stop_event.set()
    runtimes: list[_Runtime] = []
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtimes.append(_Runtime()) or runtimes[-1],
        control_loader=lambda: control_store.load(anchor=anchor),
        health_check=lambda _runtime, _state: True,
        monotonic_clock=lambda: 10.0,
        external_stop_event=stop_event,
    )
    coordinator = InstalledChannelSupervisorCoordinator(
        anchor=anchor,
        watchdog=watchdog,
        status_store=status_store,
        supervisor_receipt=_receipt(1),
    )

    stopped = coordinator.step()

    assert stopped.watchdog.action == "external_stopped"
    assert stopped.status.state == "stopped"
    assert stopped.status.stop_requested is False
    assert runtimes == []
    assert coordinator.is_quiescent() is True
    assert coordinator.force_close() is None
    assert coordinator.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI coordinator stores")
def test_status_publish_failure_closes_the_running_tree(tmp_path) -> None:
    anchor = _anchor()
    control_store = InstalledChannelSupervisorControlStore(
        (tmp_path / "installed-channel-supervisor-control.json").resolve()
    )
    control_store.initialize(anchor=anchor)
    status_path = (tmp_path / "installed-channel-supervisor-status.json").resolve()
    status_store = InstalledChannelSupervisorStatusStore(status_path)
    runtime = _Runtime()
    watchdog = InstalledChannelSupervisorWatchdog(
        runtime_factory=lambda: runtime,
        control_loader=lambda: control_store.load(anchor=anchor),
        health_check=lambda _runtime, _state: True,
        monotonic_clock=iter((10.0, 11.0)).__next__,
    )
    coordinator = InstalledChannelSupervisorCoordinator(
        anchor=anchor,
        watchdog=watchdog,
        status_store=status_store,
        supervisor_receipt=_receipt(1),
    )
    coordinator.step()
    status_path.write_bytes(b"not-a-protected-document")

    with pytest.raises(
        InstalledChannelCoordinatorError,
        match="Supervisor status could not be published",
    ):
        coordinator.step()
    assert runtime.closed == 1
