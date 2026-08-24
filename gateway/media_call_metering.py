"""Provider-call accounting wrappers for image and video operations."""

from __future__ import annotations

import asyncio
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Iterator

from gateway.provider_call_ledger import (
    ProviderCallAttemptProtocol,
    ProviderCallContext,
    ProviderCallLedgerProtocol,
    ProviderRouteIdentity,
    current_provider_call_context,
    financial_usage_from_payload,
    finish_provider_attempt_durable,
    observed_model_from_payload,
    resolve_provider_call_ledger_durable,
    start_provider_attempt_durable,
)
from gateway.providers.base import ProviderError
from gateway.schemas import ImageGenerationRequest, VideoGenerationRequest


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PAID_CREATE_OPERATION = {
    "media.generate_image": "images.create",
    "media.generate_video": "videos.create",
}


class PaidMediaAuthorityRequired(ProviderError):
    """A paid provider create was attempted outside a durable paid operation."""

    def __init__(self) -> None:
        super().__init__(
            "paid media creation requires a durable paid-media operation authority",
            status_code=403,
        )


class PaidMediaDispatchPermitRequired(ProviderError):
    """A router generation was invoked outside the metered dispatch boundary."""

    def __init__(self) -> None:
        super().__init__(
            "paid media dispatch requires an accounted provider attempt",
            status_code=403,
        )


@dataclass(slots=True)
class PaidMediaAuthority:
    """Request-scoped, non-secret proof that paid admission already succeeded."""

    principal_hash: str
    operation: str
    consumed: bool = False


_CURRENT_PAID_MEDIA_AUTHORITIES: ContextVar[tuple[PaidMediaAuthority, ...]] = (
    ContextVar("nachuan_paid_media_authorities", default=())
)


@dataclass(slots=True)
class _PaidMediaDispatchPermit:
    provider_generation: object
    operation: str
    consumed: bool = False


_CURRENT_PAID_MEDIA_DISPATCH_PERMITS: ContextVar[
    tuple[_PaidMediaDispatchPermit, ...]
] = ContextVar("nachuan_paid_media_dispatch_permits", default=())


def _consume_paid_media_dispatch_permit(
    provider_generation: object, operation: str
) -> None:
    for permit in reversed(_CURRENT_PAID_MEDIA_DISPATCH_PERMITS.get()):
        if (
            permit.provider_generation is provider_generation
            and permit.operation == operation
            and not permit.consumed
        ):
            permit.consumed = True
            return
    raise PaidMediaDispatchPermitRequired()


@contextmanager
def _bind_paid_media_dispatch_permit(
    provider_generation: object, operation: str
) -> Iterator[_PaidMediaDispatchPermit]:
    permit = _PaidMediaDispatchPermit(
        provider_generation=provider_generation,
        operation=operation,
    )
    current = _CURRENT_PAID_MEDIA_DISPATCH_PERMITS.get()
    token = _CURRENT_PAID_MEDIA_DISPATCH_PERMITS.set((*current, permit))
    try:
        yield permit
    finally:
        _CURRENT_PAID_MEDIA_DISPATCH_PERMITS.reset(token)


@contextmanager
def bind_paid_media_authority(
    *, principal_hash: str, operation: str
) -> Iterator[PaidMediaAuthority]:
    """Bind one already-claimed durable operation around its provider create only."""

    normalized_principal = str(principal_hash or "")
    normalized_operation = str(operation or "")
    if _DIGEST_RE.fullmatch(normalized_principal) is None:
        raise ValueError("paid media principal must be a lowercase SHA-256 digest")
    if normalized_operation not in frozenset(_PAID_CREATE_OPERATION.values()):
        raise ValueError("unsupported durable paid media operation")
    authority = PaidMediaAuthority(
        principal_hash=normalized_principal,
        operation=normalized_operation,
    )
    current = _CURRENT_PAID_MEDIA_AUTHORITIES.get()
    token = _CURRENT_PAID_MEDIA_AUTHORITIES.set((*current, authority))
    try:
        yield authority
    finally:
        _CURRENT_PAID_MEDIA_AUTHORITIES.reset(token)


def _require_paid_media_authority(operation: str) -> PaidMediaAuthority | None:
    expected = _PAID_CREATE_OPERATION.get(operation)
    if expected is None:
        return None
    for authority in reversed(_CURRENT_PAID_MEDIA_AUTHORITIES.get()):
        if authority.operation == expected and not authority.consumed:
            # ContextVars are copied into child tasks, but the authority object
            # itself is shared.  Consume synchronously before any ledger await so
            # a provider-created task cannot reuse one durable operation to
            # submit a second paid create.
            authority.consumed = True
            return authority
    raise PaidMediaAuthorityRequired()


@dataclass(frozen=True, slots=True)
class MediaHTTPAttemptScope:
    """Frozen identity used by adapters that meter each raw HTTP attempt."""

    ledger: ProviderCallLedgerProtocol
    identity: ProviderRouteIdentity
    context: ProviderCallContext
    first_attempt: int


_CURRENT_HTTP_ATTEMPT_SCOPE: ContextVar[MediaHTTPAttemptScope | None] = ContextVar(
    "nachuan_media_http_attempt_scope",
    default=None,
)


@contextmanager
def _bind_media_http_attempt_scope(scope: MediaHTTPAttemptScope) -> Iterator[None]:
    token = _CURRENT_HTTP_ATTEMPT_SCOPE.set(scope)
    try:
        yield
    finally:
        _CURRENT_HTTP_ATTEMPT_SCOPE.reset(token)


async def begin_media_http_attempt(raw_attempt: int) -> ProviderCallAttemptProtocol | None:
    """Start one adapter-owned raw HTTP attempt, or return ``None`` outside a scope."""

    scope = _CURRENT_HTTP_ATTEMPT_SCOPE.get()
    if scope is None:
        return None
    return await start_provider_attempt_durable(
        scope.ledger,
        identity=scope.identity,
        context=scope.context,
        attempt=scope.first_attempt + max(1, int(raw_attempt)) - 1,
        stream=False,
    )


def _operation_context(
    operation: str,
    explicit: ProviderCallContext | None,
) -> ProviderCallContext:
    base = explicit or current_provider_call_context()
    role = operation if not base.role else f"{base.role}/{operation}"
    return replace(base, role=role)


async def _call_with_accounting(
    *,
    provider: Any,
    requested_model: str,
    actual_model: str,
    upstream_model: str,
    operation: str,
    attempt: int,
    invoke: Callable[[], Awaitable[dict[str, Any]]],
    provider_call_ledger: ProviderCallLedgerProtocol | None,
    call_context: ProviderCallContext | None,
) -> dict[str, Any]:
    """Commit ``started`` before invoking one frozen provider operation."""

    # This is the common create boundary used by direct HTTP routes, Agent,
    # channel and Studio paths.  Reject before resolving or mutating the
    # financial ledger so a route decorator cannot be bypassed by another
    # in-process caller.
    _require_paid_media_authority(operation)
    ledger = await resolve_provider_call_ledger_durable(provider_call_ledger)
    identity = ProviderRouteIdentity(
        requested_model=str(requested_model),
        actual_model=str(actual_model),
        provider=str(getattr(provider, "name", "") or ""),
        upstream_model=str(upstream_model),
    )
    context = _operation_context(operation, call_context)
    internally_metered = frozenset(
        getattr(provider, "media_http_attempt_accounting_operations", ()) or ()
    )
    dispatch_operations = frozenset(
        getattr(provider, "_accounted_media_dispatch_operations", ()) or ()
    )
    requires_dispatch_permit = operation in dispatch_operations
    if operation in internally_metered and not requires_dispatch_permit:
        scope = MediaHTTPAttemptScope(
            ledger=ledger,
            identity=identity,
            context=context,
            first_attempt=attempt,
        )
        with _bind_media_http_attempt_scope(scope):
            return await invoke()

    provider_attempt = await start_provider_attempt_durable(
        ledger,
        identity=identity,
        context=context,
        attempt=attempt,
        stream=False,
    )
    try:
        if requires_dispatch_permit:
            with _bind_paid_media_dispatch_permit(provider, operation):
                result = await invoke()
        else:
            result = await invoke()
    except asyncio.CancelledError as exc:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="cancelled",
            error_type=type(exc).__name__,
            error_message=f"{operation} cancelled",
        )
        raise
    except asyncio.TimeoutError as exc:
        submission_kind = {
            "media.generate_image": "image",
            "media.generate_video": "video",
        }.get(operation)
        await finish_provider_attempt_durable(
            provider_attempt,
            status="timeout",
            error_type=(
                f"{submission_kind}_submission_outcome_unknown"
                if submission_kind
                else type(exc).__name__
            ),
            error_message=(
                f"{operation} submission outcome unknown; automatic retry forbidden"
                if submission_kind
                else f"{operation} timed out"
            ),
        )
        raise
    except Exception as exc:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="provider_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        raise
    await finish_provider_attempt_durable(
        provider_attempt,
        status="success",
        observed_model=observed_model_from_payload(result),
        usage=financial_usage_from_payload(result),
    )
    return result


async def generate_image_with_accounting(
    provider: Any,
    request: ImageGenerationRequest,
    upstream_model: str,
    *,
    actual_model: str,
    attempt: int = 1,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
) -> dict[str, Any]:
    frozen_upstream = str(upstream_model)
    return await _call_with_accounting(
        provider=provider,
        requested_model=request.model,
        actual_model=actual_model,
        upstream_model=frozen_upstream,
        operation="media.generate_image",
        attempt=attempt,
        invoke=lambda: provider.generate_image(request, frozen_upstream),
        provider_call_ledger=provider_call_ledger,
        call_context=call_context,
    )


async def generate_image_asset_urls_with_accounting(
    provider: Any,
    request: ImageGenerationRequest,
    upstream_model: str,
    *,
    actual_model: str,
    attempt: int = 1,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
) -> dict[str, Any]:
    """Meter the explicit bounded URL-only paid-media v2 adapter path."""

    frozen_upstream = str(upstream_model)
    return await _call_with_accounting(
        provider=provider,
        requested_model=request.model,
        actual_model=actual_model,
        upstream_model=frozen_upstream,
        operation="media.generate_image",
        attempt=attempt,
        invoke=lambda: provider.generate_image_asset_urls(request, frozen_upstream),
        provider_call_ledger=provider_call_ledger,
        call_context=call_context,
    )


async def generate_video_with_accounting(
    provider: Any,
    request: VideoGenerationRequest,
    upstream_model: str,
    *,
    actual_model: str,
    attempt: int = 1,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
) -> dict[str, Any]:
    frozen_upstream = str(upstream_model)
    return await _call_with_accounting(
        provider=provider,
        requested_model=request.model,
        actual_model=actual_model,
        upstream_model=frozen_upstream,
        operation="media.generate_video",
        attempt=attempt,
        invoke=lambda: provider.generate_video(request, frozen_upstream),
        provider_call_ledger=provider_call_ledger,
        call_context=call_context,
    )


async def get_video_with_accounting(
    provider: Any,
    task_id: str,
    *,
    requested_model: str,
    actual_model: str,
    upstream_model: str,
    attempt: int = 1,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
) -> dict[str, Any]:
    frozen_task_id = str(task_id)
    return await _call_with_accounting(
        provider=provider,
        requested_model=requested_model,
        actual_model=actual_model,
        upstream_model=str(upstream_model),
        operation="media.get_video",
        attempt=attempt,
        invoke=lambda: provider.get_video(frozen_task_id),
        provider_call_ledger=provider_call_ledger,
        call_context=call_context,
    )
