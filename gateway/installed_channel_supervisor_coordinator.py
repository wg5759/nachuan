"""Bind watchdog transitions to durable, identity-bound status receipts."""

from __future__ import annotations

from dataclasses import dataclass

from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelStatusError,
    InstalledChannelSupervisorStatus,
    InstalledChannelSupervisorStatusStore,
)
from gateway.installed_channel_supervisor_watchdog import (
    InstalledChannelSupervisorWatchdog,
    InstalledChannelWatchdogStep,
)


class InstalledChannelCoordinatorError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelCoordinatorStep:
    watchdog: InstalledChannelWatchdogStep
    status: InstalledChannelSupervisorStatus


class InstalledChannelSupervisorCoordinator:
    """Publish every externally meaningful watchdog transition before returning."""

    def __init__(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        watchdog: InstalledChannelSupervisorWatchdog,
        status_store: InstalledChannelSupervisorStatusStore,
        supervisor_receipt: InstalledChannelProcessReceipt,
    ) -> None:
        if not isinstance(anchor, InstalledChannelEpochAnchor):
            raise InstalledChannelCoordinatorError("installation anchor is invalid")
        if not isinstance(watchdog, InstalledChannelSupervisorWatchdog):
            raise InstalledChannelCoordinatorError("watchdog is invalid")
        if not isinstance(status_store, InstalledChannelSupervisorStatusStore):
            raise InstalledChannelCoordinatorError("status store is invalid")
        if not isinstance(supervisor_receipt, InstalledChannelProcessReceipt):
            raise InstalledChannelCoordinatorError("Supervisor receipt is invalid")
        self._anchor = anchor
        self._watchdog = watchdog
        self._status_store = status_store
        self._supervisor_receipt = supervisor_receipt
        self._status_generation: int | None = None
        self._closed = False

    def _expected_status_generation(self) -> int:
        if self._status_generation is not None:
            return self._status_generation
        if not self._status_store.path.exists():
            self._status_generation = 0
            return 0
        try:
            current = self._status_store.load(anchor=self._anchor)
        except InstalledChannelStatusError as exc:
            raise InstalledChannelCoordinatorError(
                "existing Supervisor status is unavailable"
            ) from exc
        self._status_generation = current.status_generation
        return current.status_generation

    def step(self) -> InstalledChannelCoordinatorStep:
        if self._closed:
            raise InstalledChannelCoordinatorError("coordinator is closed")
        transition = self._watchdog.step()
        if transition.action in {"started", "healthy"}:
            state = "ready" if transition.state and transition.state.ready else "degraded"
            roles = self._watchdog.process_receipts()
        elif transition.action in {"stopped", "external_stopped"}:
            state = "stopped"
            roles = {}
        elif transition.action in {"retry_scheduled", "backoff"}:
            state = "failed"
            roles = {}
        else:
            self._watchdog.close()
            raise InstalledChannelCoordinatorError("watchdog transition is invalid")
        try:
            status = self._status_store.publish(
                anchor=self._anchor,
                control=transition.control,
                expected_status_generation=self._expected_status_generation(),
                supervisor=self._supervisor_receipt,
                roles=roles,
                state=state,
                restart_attempt=transition.restart_attempt,
            )
        except Exception as exc:
            self._watchdog.close()
            raise InstalledChannelCoordinatorError(
                "Supervisor status could not be published"
            ) from exc
        self._status_generation = status.status_generation
        return InstalledChannelCoordinatorStep(watchdog=transition, status=status)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._watchdog.close()

    def force_close(self) -> None:
        return self._watchdog.force_close()

    def is_quiescent(self) -> bool:
        return self._watchdog.is_quiescent()


__all__ = [
    "InstalledChannelCoordinatorError",
    "InstalledChannelCoordinatorStep",
    "InstalledChannelSupervisorCoordinator",
]
