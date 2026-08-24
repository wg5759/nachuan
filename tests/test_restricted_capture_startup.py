from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha256
from threading import Event

import pytest

from gateway.maintenance_ticket_store import MaintenanceClaimedOperationDiscoveryPage
from gateway.restricted_capture_contract import RestrictedCaptureRequest
from gateway.restricted_capture_operation_store import (
    RestrictedCaptureOperationDiscoveryPage,
)
from gateway.restricted_capture_startup import RestrictedCaptureStartupReconciler


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _request(label: str) -> RestrictedCaptureRequest:
    return RestrictedCaptureRequest(
        requester_sid_digest=_digest(f"sid:{label}"),
        installation_id=_digest("installation"),
        epoch=7,
        root_revision=19,
        operation_digest=_digest(f"operation:{label}"),
    )


@dataclass(frozen=True)
class _Operation:
    request: RestrictedCaptureRequest
    phase: str


class _Tickets:
    def __init__(self, page: MaintenanceClaimedOperationDiscoveryPage) -> None:
        self.page = page
        self.calls: list[tuple[str | None, int]] = []

    def discover_claimed_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> MaintenanceClaimedOperationDiscoveryPage:
        self.calls.append((after_operation_digest, limit))
        return self.page


class _Operations:
    def __init__(self, page: RestrictedCaptureOperationDiscoveryPage) -> None:
        self.page = page
        self.calls: list[tuple[str | None, int]] = []

    def discover_recoverable_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> RestrictedCaptureOperationDiscoveryPage:
        self.calls.append((after_operation_digest, limit))
        return self.page


class _PagedTickets(_Tickets):
    def __init__(
        self,
        pages: list[MaintenanceClaimedOperationDiscoveryPage],
    ) -> None:
        self.pages = pages
        self.calls = []

    def discover_claimed_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> MaintenanceClaimedOperationDiscoveryPage:
        self.calls.append((after_operation_digest, limit))
        return self.pages.pop(0)


class _PagedOperations(_Operations):
    def __init__(
        self,
        pages: list[RestrictedCaptureOperationDiscoveryPage],
    ) -> None:
        self.pages = pages
        self.calls = []

    def discover_recoverable_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int,
    ) -> RestrictedCaptureOperationDiscoveryPage:
        self.calls.append((after_operation_digest, limit))
        return self.pages.pop(0)


class _Coordinator:
    def __init__(self, outcomes: dict[str, str | Exception]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, str]] = []

    def recover_claimed(self, request: RestrictedCaptureRequest) -> _Operation:
        self.calls.append(("claimed", request.operation_digest))
        return self._outcome(request)

    def recover(self, operation_digest: str) -> _Operation:
        self.calls.append(("journal", operation_digest))
        return self._outcome(_request_from_digest(operation_digest))

    def _outcome(self, request: RestrictedCaptureRequest) -> _Operation:
        outcome = self.outcomes[request.operation_digest]
        if isinstance(outcome, Exception):
            raise outcome
        return _Operation(request=request, phase=outcome)


class _BlockingCoordinator(_Coordinator):
    def __init__(self, request: RestrictedCaptureRequest) -> None:
        super().__init__({request.operation_digest: "recovery_required"})
        self.entered = Event()
        self.release = Event()

    def recover_claimed(self, request: RestrictedCaptureRequest) -> _Operation:
        self.calls.append(("claimed", request.operation_digest))
        self.entered.set()
        if not self.release.wait(timeout=10):
            raise RuntimeError("test coordinator release timed out")
        return self._outcome(request)


_REQUESTS: dict[str, RestrictedCaptureRequest] = {}


def _request_from_digest(operation_digest: str) -> RestrictedCaptureRequest:
    return _REQUESTS[operation_digest]


def test_startup_reconcile_prioritizes_claimed_orphans_deduplicates_and_reports() -> None:
    claimed = _request("claimed")
    duplicate = _request("duplicate")
    journal_only = _request("journal-only")
    failed = _request("failed")
    ambiguous = _request("ambiguous")
    _REQUESTS.clear()
    _REQUESTS.update(
        {
            item.operation_digest: item
            for item in (claimed, duplicate, journal_only, failed, ambiguous)
        }
    )
    claimed_items = tuple(
        sorted((claimed, duplicate), key=lambda item: item.operation_digest)
    )
    claimed_page_digests = sorted(
        [item.operation_digest for item in claimed_items]
        + [ambiguous.operation_digest]
    )
    operation_items = tuple(
        _Operation(item, "recovery_required")
        for item in sorted(
            (duplicate, journal_only, failed),
            key=lambda item: item.operation_digest,
        )
    )
    tickets = _Tickets(
        MaintenanceClaimedOperationDiscoveryPage(
            items=claimed_items,
            ambiguous_operation_digests=(ambiguous.operation_digest,),
            next_cursor=claimed_page_digests[-1],
        )
    )
    operations = _Operations(
        RestrictedCaptureOperationDiscoveryPage(
            items=operation_items,
            next_cursor=operation_items[-1].request.operation_digest,
        )
    )
    coordinator = _Coordinator(
        {
            claimed.operation_digest: "completed",
            duplicate.operation_digest: "failed_clean",
            journal_only.operation_digest: "recovery_required",
            failed.operation_digest: RuntimeError("private adapter detail"),
        }
    )

    report = RestrictedCaptureStartupReconciler(
        tickets=tickets,
        operations=operations,
        coordinator=coordinator,
    ).reconcile_page(limit_per_source=8)

    assert coordinator.calls == [
        *(("claimed", item.operation_digest) for item in claimed_items),
        *(
            ("journal", item.request.operation_digest)
            for item in operation_items
            if item.request.operation_digest
            not in {candidate.operation_digest for candidate in claimed_items}
        ),
    ]
    assert report.completed_operation_digests == (claimed.operation_digest,)
    assert report.failed_clean_operation_digests == (duplicate.operation_digest,)
    assert report.deferred_operation_digests == (journal_only.operation_digest,)
    assert report.failed_operation_digests == (failed.operation_digest,)
    assert report.ambiguous_operation_digests == (ambiguous.operation_digest,)
    assert report.claimed_next_cursor == claimed_page_digests[-1]
    assert report.operation_next_cursor == operation_items[-1].request.operation_digest
    assert report.claimed_done is False
    assert report.operation_done is False
    assert report.scan_complete is False
    assert "private adapter detail" not in repr(report)


def test_startup_reconcile_owns_cursors_and_complete_scan_is_idempotent() -> None:
    tickets = _Tickets(
        MaintenanceClaimedOperationDiscoveryPage((), (), None)
    )
    operations = _Operations(RestrictedCaptureOperationDiscoveryPage((), None))
    reconciler = RestrictedCaptureStartupReconciler(
        tickets=tickets,
        operations=operations,
        coordinator=_Coordinator({}),
    )

    report = reconciler.reconcile_page(limit_per_source=17)

    assert tickets.calls == [(None, 17)]
    assert operations.calls == [(None, 17)]
    assert report.attempted_operation_digests == ()
    assert report.claimed_done is True
    assert report.operation_done is True
    assert report.scan_complete is True
    assert reconciler.reconcile_page(limit_per_source=17).scan_complete is True
    assert tickets.calls == [(None, 17)]
    assert operations.calls == [(None, 17)]

    with pytest.raises(ValueError, match="startup request is invalid"):
        reconciler.reconcile_page(limit_per_source=0)
    with pytest.raises(ValueError, match="startup request is invalid"):
        reconciler.reconcile_page(limit_per_source=65)


def test_startup_scan_deduplicates_the_same_operation_across_cursor_pages() -> None:
    first_operation, shared = sorted(
        (_request("cross-page-first"), _request("cross-page-shared")),
        key=lambda item: item.operation_digest,
    )
    _REQUESTS.clear()
    _REQUESTS.update(
        {
            first_operation.operation_digest: first_operation,
            shared.operation_digest: shared,
        }
    )
    tickets = _PagedTickets(
        [
            MaintenanceClaimedOperationDiscoveryPage(
                items=(shared,),
                ambiguous_operation_digests=(),
                next_cursor=shared.operation_digest,
            ),
            MaintenanceClaimedOperationDiscoveryPage((), (), None),
        ]
    )
    operations = _PagedOperations(
        [
            RestrictedCaptureOperationDiscoveryPage(
                (_Operation(first_operation, "recovery_required"),),
                first_operation.operation_digest,
            ),
            RestrictedCaptureOperationDiscoveryPage(
                (_Operation(shared, "recovery_required"),),
                None,
            ),
        ]
    )
    coordinator = _Coordinator(
        {
            first_operation.operation_digest: "recovery_required",
            shared.operation_digest: "recovery_required",
        }
    )
    reconciler = RestrictedCaptureStartupReconciler(
        tickets=tickets,
        operations=operations,
        coordinator=coordinator,
    )

    first = reconciler.reconcile_page(limit_per_source=8)
    second = reconciler.reconcile_page(limit_per_source=8)

    assert coordinator.calls == [
        ("claimed", shared.operation_digest),
        ("journal", first_operation.operation_digest),
    ]
    assert first.attempted_operation_digests == (
        shared.operation_digest,
        first_operation.operation_digest,
    )
    assert second.attempted_operation_digests == ()


def test_startup_scan_stops_each_source_after_its_own_final_page() -> None:
    ticket_requests = sorted(
        (_request("ticket-1"), _request("ticket-2")),
        key=lambda item: item.operation_digest,
    )
    operation_requests = sorted(
        (_request("operation-1"), _request("operation-2"), _request("operation-3")),
        key=lambda item: item.operation_digest,
    )
    _REQUESTS.clear()
    _REQUESTS.update(
        {item.operation_digest: item for item in ticket_requests + operation_requests}
    )
    tickets = _PagedTickets(
        [
            MaintenanceClaimedOperationDiscoveryPage(
                (ticket_requests[0],), (), ticket_requests[0].operation_digest
            ),
            MaintenanceClaimedOperationDiscoveryPage((ticket_requests[1],), (), None),
        ]
    )
    operations = _PagedOperations(
        [
            RestrictedCaptureOperationDiscoveryPage(
                (_Operation(operation_requests[0], "recovery_required"),),
                operation_requests[0].operation_digest,
            ),
            RestrictedCaptureOperationDiscoveryPage(
                (_Operation(operation_requests[1], "recovery_required"),),
                operation_requests[1].operation_digest,
            ),
            RestrictedCaptureOperationDiscoveryPage(
                (_Operation(operation_requests[2], "recovery_required"),),
                None,
            ),
        ]
    )
    coordinator = _Coordinator(
        {
            item.operation_digest: "recovery_required"
            for item in ticket_requests + operation_requests
        }
    )
    reconciler = RestrictedCaptureStartupReconciler(
        tickets=tickets,
        operations=operations,
        coordinator=coordinator,
    )

    reports = [reconciler.reconcile_page(limit_per_source=1) for _ in range(3)]
    calls_before_complete_retry = (list(tickets.calls), list(operations.calls))
    complete_retry = reconciler.reconcile_page(limit_per_source=1)

    assert tickets.calls == [(None, 1), (ticket_requests[0].operation_digest, 1)]
    assert operations.calls == [
        (None, 1),
        (operation_requests[0].operation_digest, 1),
        (operation_requests[1].operation_digest, 1),
    ]
    assert reports[0].claimed_done is False
    assert reports[1].claimed_done is True
    assert reports[1].operation_done is False
    assert reports[2].scan_complete is True
    assert complete_retry.scan_complete is True
    assert calls_before_complete_retry == (tickets.calls, operations.calls)


def test_startup_scan_rejects_non_monotonic_source_cursor_without_committing() -> None:
    request = _request("cursor-validation")
    _REQUESTS.clear()
    _REQUESTS[request.operation_digest] = request
    tickets = _PagedTickets(
        [
            MaintenanceClaimedOperationDiscoveryPage(
                (request,), (), "f" * 64
            ),
            MaintenanceClaimedOperationDiscoveryPage((request,), (), None),
        ]
    )
    operations = _PagedOperations(
        [
            RestrictedCaptureOperationDiscoveryPage((), None),
            RestrictedCaptureOperationDiscoveryPage((), None),
        ]
    )
    coordinator = _Coordinator({request.operation_digest: "recovery_required"})
    reconciler = RestrictedCaptureStartupReconciler(
        tickets=tickets,
        operations=operations,
        coordinator=coordinator,
    )

    with pytest.raises(RuntimeError, match="discovery cursor is invalid"):
        reconciler.reconcile_page(limit_per_source=8)
    report = reconciler.reconcile_page(limit_per_source=8)

    assert tickets.calls == [(None, 8), (None, 8)]
    assert operations.calls == [(None, 8), (None, 8)]
    assert coordinator.calls == [("claimed", request.operation_digest)]
    assert report.scan_complete is True


def test_startup_scan_rejects_concurrent_page_reconciliation() -> None:
    request = _request("concurrent")
    coordinator = _BlockingCoordinator(request)
    reconciler = RestrictedCaptureStartupReconciler(
        tickets=_Tickets(
            MaintenanceClaimedOperationDiscoveryPage((request,), (), None)
        ),
        operations=_Operations(RestrictedCaptureOperationDiscoveryPage((), None)),
        coordinator=coordinator,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(reconciler.reconcile_page, limit_per_source=8)
        assert coordinator.entered.wait(timeout=5)
        second = executor.submit(reconciler.reconcile_page, limit_per_source=8)
        try:
            with pytest.raises(RuntimeError, match="already running"):
                second.result(timeout=2)
        finally:
            coordinator.release.set()
        assert first.result(timeout=5).attempted_operation_digests == (
            request.operation_digest,
        )

    assert coordinator.calls == [("claimed", request.operation_digest)]
