"""Commercial budget gate integration tests.

The synthetic quote amounts in this file are test policy fixtures, not live
provider prices.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from gateway.failover import chat_with_fallback, stream_with_fallback
from gateway.provider_call_ledger import (
    CommercialBudgetAuthorization,
    CommercialBudgetExceeded,
    ProviderCallLedger,
    ProviderCallLedgerUnavailable,
)
from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.schemas import ChatCompletionRequest


@pytest.fixture(autouse=True)
def _isolate_quota_state():
    """Commercial failures must not cool models used by unrelated tests."""
    from gateway import quota_state

    quota_state.clear()
    try:
        yield
    finally:
        quota_state.clear()


class _Provider:
    name = "synthetic-budget-provider"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        return {
            "model": "synthetic-physical-model",
            "choices": [{"message": {"content": "ok"}}],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
            },
        }


class _UnknownProvider(_Provider):
    async def chat(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        raise ProviderSubmissionOutcomeUnknown("synthetic submission outcome unknown")


class _ConnectErrorProvider(_Provider):
    async def chat(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        raise httpx.ConnectError(
            "synthetic pre-submission connection failure",
            request=httpx.Request("POST", "https://synthetic.invalid/v1/chat"),
        )


class _WrappedReadTimeoutProvider(_Provider):
    async def chat(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        try:
            raise httpx.ReadTimeout(
                "synthetic response-phase timeout",
                request=httpx.Request("POST", "https://synthetic.invalid/v1/chat"),
            )
        except httpx.ReadTimeout as exc:
            raise ProviderError("synthetic adapter wrapper") from exc


class _ReadTimeoutStreamProvider:
    name = "synthetic-stream-timeout-provider"

    def __init__(self) -> None:
        self.calls = 0

    def stream(self, _request, _upstream_model):  # noqa: ANN001, ANN201
        self.calls += 1

        async def chunks():
            raise httpx.ReadTimeout(
                "synthetic stream response-phase timeout",
                request=httpx.Request("POST", "https://synthetic.invalid/v1/chat"),
            )
            yield {}  # pragma: no cover - makes this an async generator

        return chunks()


class _SuccessfulStreamProvider:
    name = "synthetic-stream-success-provider"

    def __init__(self) -> None:
        self.calls = 0

    def stream(self, _request, _upstream_model):  # noqa: ANN001, ANN201
        self.calls += 1

        async def chunks():
            yield {
                "model": "synthetic-stream-model",
                "choices": [{"delta": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                },
            }

        return chunks()


class _Route:
    def __init__(self, provider: _Provider) -> None:
        self.provider = provider
        self.upstream_model = "synthetic-upstream"
        self.tier = "synthetic"


class _Router:
    def __init__(self, route: _Route) -> None:
        self.route = route

    def resolve(self, model: str):  # noqa: ANN201
        return self.route if model == "synthetic-model" else None


def _authorization(operation_id: str) -> CommercialBudgetAuthorization:
    return CommercialBudgetAuthorization(
        operation_id=operation_id,
        quote_id="synthetic-fixed-quote-v1",
        reserve_microusd=60_000,
        capture_microusd=60_000,
    )


async def test_required_commercial_gate_rejects_missing_authority_before_provider(
    tmp_path, monkeypatch
) -> None:
    provider = _Provider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-required.db",
        required=True,
        commercial_budget_required=True,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )

    with pytest.raises(ProviderCallLedgerUnavailable, match="authorization is required"):
        await chat_with_fallback(
            _Router(_Route(provider)),
            ChatCompletionRequest(
                model="synthetic-model",
                messages=[{"role": "user", "content": "hello"}],
            ),
            provider_call_ledger=ledger,
        )

    assert provider.calls == 0
    assert ledger.financial_summary(period="all")["total_calls"] == 0


async def test_concurrent_reservations_cannot_overspend_one_balance(
    tmp_path, monkeypatch
) -> None:
    class BlockingProvider(_Provider):
        def __init__(self) -> None:
            super().__init__()
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def chat(self, request, upstream_model):  # noqa: ANN001
            self.calls += 1
            self.started.set()
            await self.release.wait()
            return {
                "model": "synthetic-physical-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

    provider = BlockingProvider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-concurrent.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-concurrent",
        amount_microusd=100_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )
    router = _Router(_Route(provider))
    request = ChatCompletionRequest(
        model="synthetic-model",
        messages=[{"role": "user", "content": "hello"}],
    )
    first = asyncio.create_task(
        chat_with_fallback(
            router,
            request,
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-concurrent-operation-1"),
        )
    )
    try:
        await asyncio.wait_for(provider.started.wait(), timeout=5.0)
        with pytest.raises(CommercialBudgetExceeded):
            await chat_with_fallback(
                router,
                request,
                provider_call_ledger=ledger,
                commercial_budget=_authorization("synthetic-concurrent-operation-2"),
            )
        assert ledger.commercial_budget_snapshot()["active_hold_microusd"] == 60_000
    finally:
        provider.release.set()
        await asyncio.wait_for(first, timeout=5.0)

    snapshot = ledger.commercial_budget_snapshot()
    assert provider.calls == 1
    assert snapshot["captured_microusd"] == 60_000
    assert snapshot["available_microusd"] == 40_000
    assert snapshot["reservation_states"] == {"captured": 1}


async def test_budget_is_reserved_and_second_call_is_rejected_before_provider(
    tmp_path, monkeypatch
) -> None:
    provider = _Provider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-budget.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-1",
        amount_microusd=100_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )
    request = ChatCompletionRequest(
        model="synthetic-model",
        messages=[{"role": "user", "content": "hello"}],
    )

    await chat_with_fallback(
        _Router(_Route(provider)),
        request,
        provider_call_ledger=ledger,
        commercial_budget=_authorization("synthetic-operation-1"),
    )

    first = ledger.commercial_budget_snapshot()
    assert first["currency"] == "USD"
    assert first["funded_microusd"] == 100_000
    assert first["captured_microusd"] == 60_000
    assert first["active_hold_microusd"] == 0
    assert first["available_microusd"] == 40_000
    assert first["reservation_states"] == {"captured": 1}

    with pytest.raises(CommercialBudgetExceeded):
        await chat_with_fallback(
            _Router(_Route(provider)),
            request,
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-operation-2"),
        )

    assert provider.calls == 1
    assert ledger.financial_summary(period="all")["total_calls"] == 1
    assert ledger.commercial_budget_snapshot() == first


async def test_commercial_call_id_cannot_be_changed_by_requoting_same_operation(
    tmp_path, monkeypatch
) -> None:
    provider = _Provider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-idempotency.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-idempotency",
        amount_microusd=100_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )
    request = ChatCompletionRequest(
        model="synthetic-model",
        messages=[{"role": "user", "content": "hello"}],
    )
    router = _Router(_Route(provider))
    original = _authorization("stable-commercial-operation")

    await chat_with_fallback(
        router,
        request,
        provider_call_ledger=ledger,
        commercial_budget=original,
    )
    before = ledger.commercial_budget_snapshot()
    requoted = CommercialBudgetAuthorization(
        operation_id="stable-commercial-operation",
        quote_id="synthetic-different-quote-v2",
        reserve_microusd=30_000,
        capture_microusd=30_000,
    )

    with pytest.raises(ProviderCallLedgerUnavailable, match="different quote evidence"):
        await chat_with_fallback(
            router,
            request,
            provider_call_ledger=ledger,
            commercial_budget=requoted,
        )

    assert provider.calls == 1
    assert ledger.financial_summary(period="all")["total_calls"] == 1
    assert ledger.commercial_budget_snapshot() == before


async def test_submission_outcome_unknown_keeps_the_hold_for_review(
    tmp_path, monkeypatch
) -> None:
    provider = _UnknownProvider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-unknown.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-unknown",
        amount_microusd=100_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            _Router(_Route(provider)),
            ChatCompletionRequest(
                model="synthetic-model",
                messages=[{"role": "user", "content": "hello"}],
            ),
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-unknown-operation"),
        )

    snapshot = ledger.commercial_budget_snapshot()
    assert provider.calls == 1
    assert snapshot["captured_microusd"] == 0
    assert snapshot["released_microusd"] == 0
    assert snapshot["active_hold_microusd"] == 60_000
    assert snapshot["available_microusd"] == 40_000
    assert snapshot["reservation_states"] == {"review_required": 1}
    financial = ledger.financial_summary(period="all")
    assert financial["total_calls"] == 1
    assert financial["outcome_unknown_calls"] == 1


async def test_proven_pre_submission_failure_releases_the_hold(
    tmp_path, monkeypatch
) -> None:
    provider = _ConnectErrorProvider()
    ledger = ProviderCallLedger(
        tmp_path / "commercial-release.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-release",
        amount_microusd=100_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-model"],
    )

    with pytest.raises(ProviderError):
        await chat_with_fallback(
            _Router(_Route(provider)),
            ChatCompletionRequest(
                model="synthetic-model",
                messages=[{"role": "user", "content": "hello"}],
            ),
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-release-operation"),
        )

    snapshot = ledger.commercial_budget_snapshot()
    assert provider.calls == 1
    assert snapshot["captured_microusd"] == 0
    assert snapshot["released_microusd"] == 60_000
    assert snapshot["active_hold_microusd"] == 0
    assert snapshot["available_microusd"] == 100_000
    assert snapshot["reservation_states"] == {"released": 1}


async def test_response_phase_unknown_stops_commercial_fallback_before_second_provider(
    tmp_path, monkeypatch
) -> None:
    first_provider = _WrappedReadTimeoutProvider()
    second_provider = _Provider()
    routes = {
        "synthetic-primary": _Route(first_provider),
        "synthetic-secondary": _Route(second_provider),
    }

    class Router:
        def resolve(self, model: str):  # noqa: ANN201
            return routes.get(model)

    ledger = ProviderCallLedger(
        tmp_path / "commercial-response-unknown.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-response-unknown",
        amount_microusd=200_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-primary", "synthetic-secondary"],
    )

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            Router(),
            ChatCompletionRequest(
                model="synthetic-primary",
                messages=[{"role": "user", "content": "hello"}],
            ),
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-response-unknown-operation"),
        )

    assert first_provider.calls == 1
    assert second_provider.calls == 0
    snapshot = ledger.commercial_budget_snapshot()
    assert snapshot["captured_microusd"] == 0
    assert snapshot["active_hold_microusd"] == 60_000
    assert snapshot["available_microusd"] == 140_000
    assert snapshot["reservation_states"] == {"review_required": 1}
    financial = ledger.financial_summary(period="all")
    assert financial["total_calls"] == 1
    assert financial["outcome_unknown_calls"] == 1


async def test_stream_response_unknown_stops_before_second_provider_and_hold(
    tmp_path, monkeypatch
) -> None:
    first_provider = _ReadTimeoutStreamProvider()
    second_provider = _SuccessfulStreamProvider()
    routes = {
        "synthetic-primary": _Route(first_provider),
        "synthetic-secondary": _Route(second_provider),
    }

    class Router:
        def resolve(self, model: str):  # noqa: ANN201
            return routes.get(model)

    ledger = ProviderCallLedger(
        tmp_path / "commercial-stream-unknown.db",
        required=True,
        commercial_budget_required=True,
    )
    ledger.fund_commercial_budget(
        funding_id="synthetic-funding-stream-unknown",
        amount_microusd=200_000,
    )
    monkeypatch.setattr(
        "gateway.failover.fallback_chain",
        lambda *_args, **_kwargs: ["synthetic-primary", "synthetic-secondary"],
    )

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        async for _chunk in stream_with_fallback(
            Router(),
            ChatCompletionRequest(
                model="synthetic-primary",
                messages=[{"role": "user", "content": "hello"}],
            ),
            provider_call_ledger=ledger,
            commercial_budget=_authorization("synthetic-stream-unknown-operation"),
        ):
            pass

    assert first_provider.calls == 1
    assert second_provider.calls == 0
    snapshot = ledger.commercial_budget_snapshot()
    assert snapshot["captured_microusd"] == 0
    assert snapshot["active_hold_microusd"] == 60_000
    assert snapshot["available_microusd"] == 140_000
    assert snapshot["reservation_states"] == {"review_required": 1}
    financial = ledger.financial_summary(period="all")
    assert financial["total_calls"] == 1
    assert financial["outcome_unknown_calls"] == 1
