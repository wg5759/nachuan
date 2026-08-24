"""Shared truthful contracts for advisory workflows."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, TypeVar

from gateway.route_attestation import seal_route_receipt


RESPONSE_VERSION = 2
ROUTE_RECEIPT_VERSION = 1
_T = TypeVar("_T")
_DEFAULT_CLEANUP_TIMEOUT_SECONDS = 3.0


def _consume_task_result(task: asyncio.Task[Any]) -> None:
    """Retrieve a detached task result so late failure is not logged as lost."""

    if not task.done():
        return
    try:
        task.result()
    except BaseException:
        pass


async def _cancel_and_drain(
    tasks: Sequence[asyncio.Task[Any]],
    *,
    timeout: float,
) -> None:
    """Cancel siblings and wait only for a bounded cleanup interval."""

    active = set(tasks)
    for task in active:
        task.cancel()
    if not active:
        return
    done, stubborn = await asyncio.wait(active, timeout=max(0.0, timeout))
    for task in done:
        _consume_task_result(task)
    for task in stubborn:
        task.cancel()
        task.add_done_callback(_consume_task_result)


async def gather_fail_fast(
    calls: Sequence[Awaitable[_T]],
    *,
    fatal: Callable[[_T], bool],
    cleanup_timeout: float = _DEFAULT_CLEANUP_TIMEOUT_SECONDS,
) -> tuple[list[_T | None], list[int]]:
    """Collect in input order and explicitly cancel+await siblings on fatal data.

    ``asyncio.gather`` does not guarantee that siblings are cancelled and
    drained when one result violates a workflow contract.  This helper keeps
    already completed safe results while making cancellation deterministic.
    """

    tasks = [asyncio.create_task(call) for call in calls]
    positions = {task: index for index, task in enumerate(tasks)}
    pending: set[asyncio.Task[_T]] = set(tasks)
    results: list[_T | None] = [None] * len(tasks)
    cancelled: list[int] = []
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            stop = False
            for task in done:
                index = positions[task]
                result = task.result()
                results[index] = result
                stop = stop or fatal(result)
            if stop and pending:
                cancelled = sorted(positions[task] for task in pending)
                await _cancel_and_drain(
                    list(pending),
                    timeout=cleanup_timeout,
                )
                pending.clear()
        return results, cancelled
    except BaseException:
        if pending:
            await _cancel_and_drain(
                list(pending),
                timeout=cleanup_timeout,
            )
        raise


def route_receipt(
    *,
    requested_model: str | None,
    actual_model: str | None,
    route: Any,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build immutable call-time evidence with a truthful legacy alias."""

    from orchestrator.identity import (
        independence_domain_from_route,
        verified_route_model_evidence,
    )

    model_evidence = verified_route_model_evidence(route, response)
    route_virtual = str(getattr(route, "virtual_model", "") or "").strip()
    actual = str(actual_model or "").strip()
    identity_error = model_evidence.error
    if route is None:
        identity_error = "missing_route_snapshot"
    elif not route_virtual:
        identity_error = "missing_route_virtual"
    elif route_virtual != actual:
        identity_error = "actual_route_mismatch"

    authored_output: str | None = None
    if isinstance(response, dict):
        content = (
            (response.get("choices") or [{}])[0]
            .get("message", {})
            .get("content")
        )
        if isinstance(content, str):
            authored_output = content
    return seal_route_receipt({
        "route_receipt_version": ROUTE_RECEIPT_VERSION,
        # Compatibility for older desktop/client code.  Historically this was
        # requested_model and silently lied after failover; it now means actual.
        "model": actual_model,
        "requested_model": requested_model,
        "actual_model": actual_model,
        "provider": getattr(getattr(route, "provider", None), "name", None),
        "upstream_model": getattr(route, "upstream_model", None),
        "reported_model": model_evidence.reported_model,
        "observed_model": None if identity_error else model_evidence.observed_model,
        "model_family": None if identity_error else model_evidence.model_family,
        "model_identity_error": identity_error,
        "independence_domain": independence_domain_from_route(route),
        "tier": getattr(route, "tier", None),
        "flagship": getattr(route, "flagship", None),
    }, authored_output=authored_output)


def unserved_route_receipt(
    *,
    requested_model: str | None,
    reason: str,
) -> dict[str, Any]:
    """Describe a hop that never produced an invocation route or response.

    ``model`` is the legacy *actual served* field and must therefore remain
    ``None``.  The requested alias is retained separately for diagnostics.
    """

    receipt = route_receipt(
        requested_model=requested_model,
        actual_model=None,
        route=None,
        response=None,
    )
    receipt["model_identity_error"] = str(reason or "not_called")
    return seal_route_receipt(receipt)
