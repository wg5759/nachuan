from __future__ import annotations

import secrets
from types import SimpleNamespace
from typing import Any

from gateway.model_identity import exact_verified_model_identity
from gateway.failover import ChatFallbackResult
from gateway.provider_call_ledger import ProviderCallContext, current_provider_call_context
from gateway.route_attestation import (
    bind_model_review_call,
    canonical_provider_request_sha256,
    capture_provider_call_provenance,
)
from orchestrator.review_gate import reviewed_output_sha256
from orchestrator.workflows.common import route_receipt


class TrustedTestProvider:
    """Explicit test-only provider adapter; production generic trust stays closed."""

    def __init__(self, name: str, domain: str) -> None:
        self.name = name
        self.independence_domain = domain

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return exact_verified_model_identity(upstream_model, observed_model)


def trusted_route(row: dict[str, Any]) -> Any:
    return SimpleNamespace(
        virtual_model=row["model"],
        provider=TrustedTestProvider(row["provider"], row["independence_domain"]),
        upstream_model=row["upstream_model"],
        model_family=row["model_family"],
        independence_domain=row["independence_domain"],
        tier=row["tier"],
        flagship=bool(row.get("flagship")),
    )


def receipt_for(router: Any, actual_model: str, requested_model: str | None = None):  # noqa: ANN201
    route = router.resolve(actual_model)
    assert route is not None
    return route_receipt(
        requested_model=requested_model or actual_model,
        actual_model=actual_model,
        route=route,
        response={"model": route.upstream_model},
    )


def with_author_receipt(
    router: Any,
    model: str,
    result: dict[str, Any],
    *,
    requested_model: str | None = None,
) -> dict[str, Any]:
    return {
        **result,
        "actual_model": model,
        "actual_models": [model],
        "author_receipts": [receipt_for(router, model, requested_model)],
    }


def capture_trusted_chat_provenance(
    *,
    request_payload: object,
    response: dict[str, Any],
    requested_model: str,
    actual_model: str,
    route: Any,
) -> dict[str, Any] | None:
    """Test-only provider-bound sidecar for fake chat adapters."""

    return capture_provider_call_provenance(
        request_payload=request_payload,
        response=response,
        requested_model=requested_model,
        actual_model=actual_model,
        provider=str(getattr(getattr(route, "provider", None), "name", "") or ""),
        upstream_model=str(getattr(route, "upstream_model", "") or ""),
        route=route,
        call_id=secrets.token_hex(16),
        attempt=1,
        call_context=current_provider_call_context(),
        ledger_terminal_committed=True,
    )


def trusted_review_provenance(
    *,
    requested_model: str,
    actual_model: str,
    route: Any,
    verdict: str,
    reviewed_output: Any,
    business_role: str = "test.review",
    ledger_terminal_committed: bool = True,
) -> dict[str, Any]:
    """Mint one fresh, provider-bound review envelope for unit tests."""

    response = {
        "model": str(getattr(route, "upstream_model", "") or ""),
        "choices": [{"message": {"content": verdict}}],
    }
    with bind_model_review_call(
        reviewed_output_sha256=reviewed_output_sha256(reviewed_output),
        business_role=business_role,
    ):
        provenance = capture_provider_call_provenance(
            request_payload={
                "model": actual_model,
                "messages": [{"role": "user", "content": reviewed_output}],
            },
            response=response,
            requested_model=requested_model,
            actual_model=actual_model,
            provider=str(
                getattr(getattr(route, "provider", None), "name", "") or ""
            ),
            upstream_model=str(getattr(route, "upstream_model", "") or ""),
            route=route,
            call_id=secrets.token_hex(16),
            attempt=1,
            call_context=ProviderCallContext(role=business_role),
            ledger_terminal_committed=ledger_terminal_committed,
        )
    assert provenance is not None
    return provenance


def trusted_review_request_sha256(
    *,
    actual_model: str,
    reviewed_output: Any,
) -> str:
    """Expected digest for the explicit test-only fake review request."""

    return canonical_provider_request_sha256({
        "model": actual_model,
        "messages": [{"role": "user", "content": reviewed_output}],
    })


def trusted_chat_result(
    *,
    request_payload: object,
    response: dict[str, Any],
    requested_model: str,
    actual_model: str,
    route: Any,
) -> ChatFallbackResult:
    return ChatFallbackResult(
        response,
        actual_model,
        route,
        capture_trusted_chat_provenance(
            request_payload=request_payload,
            response=response,
            requested_model=requested_model,
            actual_model=actual_model,
            route=route,
        ),
    )
