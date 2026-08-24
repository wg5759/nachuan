"""Bounded service-neutral startup reconciliation for restricted capture.

The module discovers durable work only; it does not claim a production
Gateway, Windows service, ACL, boot-clock, or real capture adapter wiring.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from gateway.maintenance_ticket_store import MaintenanceClaimedOperationDiscoveryPage
from gateway.restricted_capture_contract import RestrictedCaptureRequest, require_digest
from gateway.restricted_capture_operation_store import (
    RestrictedCaptureOperationDiscoveryPage,
)


MAX_STARTUP_DISCOVERY_PER_SOURCE = 64
MAX_STARTUP_SCAN_OPERATION_DIGESTS = 384


class _ClaimedTicketDiscovery(Protocol):
    def discover_claimed_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> MaintenanceClaimedOperationDiscoveryPage: ...


class _OperationDiscovery(Protocol):
    def discover_recoverable_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> RestrictedCaptureOperationDiscoveryPage: ...


class _RecoveryCoordinator(Protocol):
    def recover_claimed(self, request: RestrictedCaptureRequest) -> object: ...

    def recover(self, operation_digest: str) -> object: ...


@dataclass(frozen=True, slots=True)
class RestrictedCaptureStartupReport:
    attempted_operation_digests: tuple[str, ...]
    completed_operation_digests: tuple[str, ...]
    failed_clean_operation_digests: tuple[str, ...]
    deferred_operation_digests: tuple[str, ...]
    failed_operation_digests: tuple[str, ...]
    ambiguous_operation_digests: tuple[str, ...]
    claimed_next_cursor: str | None
    operation_next_cursor: str | None
    claimed_done: bool
    operation_done: bool
    scan_complete: bool


class RestrictedCaptureStartupReconciler:
    """Run one bounded page from each independent durable authority."""

    def __init__(
        self,
        *,
        tickets: _ClaimedTicketDiscovery,
        operations: _OperationDiscovery,
        coordinator: _RecoveryCoordinator,
    ) -> None:
        self._tickets = tickets
        self._operations = operations
        self._coordinator = coordinator
        # One reconciler instance is one bounded startup scan.  Keeping the
        # set across keyset pages prevents independent ticket/operation
        # cursors from replaying the same operation at a later page boundary.
        # A later periodic scan must construct a fresh reconciler instance.
        self._seen_operation_digests: set[str] = set()
        self._scan_lock = Lock()
        self._claimed_cursor: str | None = None
        self._operation_cursor: str | None = None
        self._claimed_done = False
        self._operation_done = False

    def reconcile_page(
        self,
        *,
        limit_per_source: int = 32,
    ) -> RestrictedCaptureStartupReport:
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError(
                "restricted capture startup reconciliation is already running"
            )
        try:
            return self._reconcile_page(limit_per_source=limit_per_source)
        finally:
            self._scan_lock.release()

    def _reconcile_page(
        self,
        *,
        limit_per_source: int,
    ) -> RestrictedCaptureStartupReport:
        if (
            isinstance(limit_per_source, bool)
            or not isinstance(limit_per_source, int)
            or not 1 <= limit_per_source <= MAX_STARTUP_DISCOVERY_PER_SOURCE
        ):
            raise ValueError("restricted capture startup request is invalid")
        claimed_queried = not self._claimed_done
        operation_queried = not self._operation_done
        claimed_page = (
            self._tickets.discover_claimed_operations(
                after_operation_digest=self._claimed_cursor,
                limit=limit_per_source,
            )
            if claimed_queried
            else MaintenanceClaimedOperationDiscoveryPage((), (), None)
        )
        operation_page = (
            self._operations.discover_recoverable_operations(
                after_operation_digest=self._operation_cursor,
                limit=limit_per_source,
            )
            if operation_queried
            else RestrictedCaptureOperationDiscoveryPage((), None)
        )
        if (
            len(claimed_page.items)
            + len(claimed_page.ambiguous_operation_digests)
            > limit_per_source
            or len(operation_page.items) > limit_per_source
        ):
            raise RuntimeError("restricted capture startup discovery exceeded its bound")
        self._validate_claimed_page(
            claimed_page,
            current_cursor=self._claimed_cursor,
        )
        self._validate_operation_page(
            operation_page,
            current_cursor=self._operation_cursor,
        )

        attempted: list[str] = []
        completed: list[str] = []
        failed_clean: list[str] = []
        deferred: list[str] = []
        failed: list[str] = []
        ambiguous = list(claimed_page.ambiguous_operation_digests)
        for operation_digest in ambiguous:
            self._remember(operation_digest)

        for request in claimed_page.items:
            operation_digest = request.operation_digest
            if not self._remember(operation_digest):
                continue
            attempted.append(operation_digest)
            try:
                result = self._coordinator.recover_claimed(request)
            except Exception:
                failed.append(operation_digest)
                continue
            self._classify_result(
                result,
                operation_digest=operation_digest,
                completed=completed,
                failed_clean=failed_clean,
                deferred=deferred,
                failed=failed,
            )

        for operation in operation_page.items:
            request = operation.request
            operation_digest = request.operation_digest
            if not self._remember(operation_digest):
                continue
            attempted.append(operation_digest)
            try:
                result = self._coordinator.recover(operation_digest)
            except Exception:
                failed.append(operation_digest)
                continue
            self._classify_result(
                result,
                operation_digest=operation_digest,
                completed=completed,
                failed_clean=failed_clean,
                deferred=deferred,
                failed=failed,
            )

        if claimed_queried:
            self._claimed_cursor = claimed_page.next_cursor
            self._claimed_done = claimed_page.next_cursor is None
        if operation_queried:
            self._operation_cursor = operation_page.next_cursor
            self._operation_done = operation_page.next_cursor is None
        return RestrictedCaptureStartupReport(
            attempted_operation_digests=tuple(attempted),
            completed_operation_digests=tuple(completed),
            failed_clean_operation_digests=tuple(failed_clean),
            deferred_operation_digests=tuple(deferred),
            failed_operation_digests=tuple(failed),
            ambiguous_operation_digests=tuple(ambiguous),
            claimed_next_cursor=self._claimed_cursor,
            operation_next_cursor=self._operation_cursor,
            claimed_done=self._claimed_done,
            operation_done=self._operation_done,
            scan_complete=self._claimed_done and self._operation_done,
        )

    @staticmethod
    def _validated_digest(value: object, *, cursor: bool = False) -> str:
        try:
            return require_digest(
                value,
                "restricted capture startup discovery cursor"
                if cursor
                else "restricted capture startup operation",
            )
        except ValueError as exc:
            raise RuntimeError(
                "restricted capture startup discovery cursor is invalid"
                if cursor
                else "restricted capture startup discovery page is invalid"
            ) from exc

    @classmethod
    def _validate_claimed_page(
        cls,
        page: MaintenanceClaimedOperationDiscoveryPage,
        *,
        current_cursor: str | None,
    ) -> None:
        if not isinstance(page, MaintenanceClaimedOperationDiscoveryPage):
            raise RuntimeError("restricted capture startup discovery page is invalid")
        item_digests: list[str] = []
        for request in page.items:
            if not isinstance(request, RestrictedCaptureRequest):
                raise RuntimeError(
                    "restricted capture startup discovery page is invalid"
                )
            item_digests.append(
                cls._validated_digest(request.operation_digest)
            )
        ambiguous = [
            cls._validated_digest(operation_digest)
            for operation_digest in page.ambiguous_operation_digests
        ]
        if (
            item_digests != sorted(item_digests)
            or ambiguous != sorted(ambiguous)
            or len(set(item_digests + ambiguous)) != len(item_digests) + len(ambiguous)
        ):
            raise RuntimeError("restricted capture startup discovery page is invalid")
        cls._validate_page_cursor(
            item_digests + ambiguous,
            next_cursor=page.next_cursor,
            current_cursor=current_cursor,
        )

    @classmethod
    def _validate_operation_page(
        cls,
        page: RestrictedCaptureOperationDiscoveryPage,
        *,
        current_cursor: str | None,
    ) -> None:
        if not isinstance(page, RestrictedCaptureOperationDiscoveryPage):
            raise RuntimeError("restricted capture startup discovery page is invalid")
        digests: list[str] = []
        for operation in page.items:
            request = getattr(operation, "request", None)
            phase = getattr(operation, "phase", None)
            if not isinstance(request, RestrictedCaptureRequest) or phase not in {
                "claimed",
                "fencing",
                "quiescent",
                "root_locked",
                "staging",
                "staged_verified",
                "published",
                "resuming",
                "recovery_required",
            }:
                raise RuntimeError(
                    "restricted capture startup discovery page is invalid"
                )
            digests.append(cls._validated_digest(request.operation_digest))
        if digests != sorted(digests) or len(set(digests)) != len(digests):
            raise RuntimeError("restricted capture startup discovery page is invalid")
        cls._validate_page_cursor(
            digests,
            next_cursor=page.next_cursor,
            current_cursor=current_cursor,
        )

    @classmethod
    def _validate_page_cursor(
        cls,
        digests: list[str],
        *,
        next_cursor: str | None,
        current_cursor: str | None,
    ) -> None:
        if current_cursor is not None:
            current = cls._validated_digest(current_cursor, cursor=True)
            if any(operation_digest <= current for operation_digest in digests):
                raise RuntimeError(
                    "restricted capture startup discovery cursor is invalid"
                )
        else:
            current = None
        if next_cursor is None:
            return
        following = cls._validated_digest(next_cursor, cursor=True)
        if (
            not digests
            or following != max(digests)
            or (current is not None and following <= current)
        ):
            raise RuntimeError(
                "restricted capture startup discovery cursor is invalid"
            )

    def _remember(self, operation_digest: str) -> bool:
        try:
            operation_id = require_digest(
                operation_digest,
                "restricted capture startup operation",
            )
        except ValueError as exc:
            raise RuntimeError(
                "restricted capture startup discovery is invalid"
            ) from exc
        if operation_id in self._seen_operation_digests:
            return False
        if (
            len(self._seen_operation_digests)
            >= MAX_STARTUP_SCAN_OPERATION_DIGESTS
        ):
            raise RuntimeError(
                "restricted capture startup scan exceeded its bound"
            )
        self._seen_operation_digests.add(operation_id)
        return True

    @staticmethod
    def _classify_result(
        result: object,
        *,
        operation_digest: str,
        completed: list[str],
        failed_clean: list[str],
        deferred: list[str],
        failed: list[str],
    ) -> None:
        phase = getattr(result, "phase", None)
        if phase == "completed":
            completed.append(operation_digest)
        elif phase == "failed_clean":
            failed_clean.append(operation_digest)
        elif phase in {
            "claimed",
            "fencing",
            "quiescent",
            "root_locked",
            "staging",
            "staged_verified",
            "published",
            "resuming",
            "recovery_required",
        }:
            deferred.append(operation_digest)
        else:
            failed.append(operation_digest)
