from __future__ import annotations

from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from gateway.connections import is_verified_connection, mark_connection_verified
from gateway.model_identity import exact_verified_model_identity, model_family_from_identifier
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.providers.volcano import VolcanoProvider
from gateway.router import Router
from gateway.route_attestation import (
    reset_agent_author_context,
    set_agent_author_context,
)
from orchestrator import modes, orchestrated_agent
from orchestrator.review_gate import ReviewGate, review_observation as _review_observation
from orchestrator.workflows.common import route_receipt
from tests.review_fixtures import (
    trusted_chat_result,
    trusted_review_provenance,
    trusted_review_request_sha256,
)


_UNBOUND_REVIEW_OUTPUT = object()


def review_observation(
    router,  # noqa: ANN001
    *,
    requested_model: str,
    served_model: str,
    verdict: str,
    reviewed_output: object = _UNBOUND_REVIEW_OUTPUT,
    **kwargs,  # noqa: ANN003
):  # noqa: ANN201
    route = kwargs.get("route") or router.resolve(served_model)
    response = kwargs.get("response")
    if not isinstance(response, dict):
        response = {
            "model": kwargs.get("observed_model")
            or getattr(route, "upstream_model", None)
        }
    response = dict(response)
    response.setdefault("choices", [{"message": {"content": verdict}}])
    kwargs["response"] = response
    kwargs["route"] = route
    if reviewed_output is not _UNBOUND_REVIEW_OUTPUT:
        kwargs["reviewed_output"] = reviewed_output
        if route is not None:
            kwargs["provider_provenance"] = trusted_review_provenance(
                requested_model=requested_model,
                actual_model=served_model,
                route=route,
                verdict=verdict,
                reviewed_output=reviewed_output,
            )
            kwargs["expected_provider_request_sha256"] = (
                trusted_review_request_sha256(
                    actual_model=served_model,
                    reviewed_output=reviewed_output,
                )
            )
    return _review_observation(
        router,
        requested_model=requested_model,
        served_model=served_model,
        verdict=verdict,
        **kwargs,
    )


def _domain(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


class _TrustedProvider:
    def __init__(self, name: str, domain: str) -> None:
        self.name = name
        self.independence_domain = domain

    def expected_model_family(self, upstream_model: str) -> str | None:
        return model_family_from_identifier(upstream_model)

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return exact_verified_model_identity(upstream_model, observed_model)


class _MutableRouter:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def routes_info(self):  # noqa: ANN201
        return [dict(row) for row in self.rows]

    def resolve(self, model: str):  # noqa: ANN201
        row = next((row for row in self.rows if row["model"] == model), None)
        if row is None:
            return None
        provider = row.get("provider_object") or _TrustedProvider(
            str(row["provider"]), str(row["independence_domain"])
        )
        return SimpleNamespace(
            virtual_model=row["model"],
            provider=provider,
            upstream_model=row["upstream_model"],
            model_family=row["model_family"],
            independence_domain=row["independence_domain"],
            tier=row["tier"],
            flagship=bool(row.get("flagship")),
        )


def _rows() -> list[dict[str, object]]:
    return [
        {
            "model": "author-a",
            "provider": "trusted-a",
            "upstream_model": "gpt-4o",
            "model_family": "openai",
            "independence_domain": _domain("a"),
            "tier": "premium",
            "rank": 1,
            "flagship": False,
        },
        {
            "model": "review-b",
            "provider": "trusted-b",
            "upstream_model": "claude-sonnet-4-6",
            "model_family": "anthropic",
            "independence_domain": _domain("b"),
            "tier": "premium",
            "rank": 2,
            "flagship": False,
        },
        {
            "model": "review-c",
            "provider": "trusted-c",
            "upstream_model": "gemini-2.5-pro",
            "model_family": "google-gemini",
            "independence_domain": _domain("c"),
            "tier": "premium",
            "rank": 3,
            "flagship": False,
        },
        {
            "model": "worker-d",
            "provider": "trusted-d",
            "upstream_model": "qwen-turbo",
            "model_family": "alibaba-qwen",
            "independence_domain": _domain("d"),
            "tier": "cheap",
            "rank": 1,
            "flagship": False,
        },
    ]


def _add_author(
    gate: ReviewGate,
    router: _MutableRouter,
    model: str,
    *,
    role: str = "initiator",
    initiator: bool = True,
) -> bool:
    route = router.resolve(model)
    return gate.add_author(
        model,
        role=role,
        initiator=initiator,
        requested_model=model,
        route=route,
        response={"model": route.upstream_model},
    )


@pytest.mark.asyncio
async def test_org_missing_author_response_models_poison_lineage_despite_two_passes(
    monkeypatch,
) -> None:
    router = _MutableRouter(_rows())

    async def fake_ask(_router, requested, _messages, **_kwargs):  # noqa: ANN001
        route = router.resolve(requested)
        if requested in {"review-b", "review-c"}:
            response = {
                "model": route.upstream_model,
                "choices": [{"message": {"content": "independent\nPASS"}}],
            }
            return trusted_chat_result(
                request_payload={"model": requested, "messages": _messages},
                response=response,
                requested_model=requested,
                actual_model=requested,
                route=route,
            )
        # Every content-author hop deliberately omits response.model.
        return (
            {"choices": [{"message": {"content": f"draft from {requested}"}}]},
            requested,
            route,
        )

    monkeypatch.setattr(modes, "_ask_observed", fake_ask)

    result = await modes.run_org(
        router,
        [{"role": "user", "content": "build and verify it"}],
    )

    assert result["_route"]["reviewed"] is False
    assert result["_route"]["reviewer_vote_weight"] == 0
    assert result["_route"]["lineage_complete"] is False
    assert result["_route"]["unknown_lineage"]


@pytest.mark.asyncio
async def test_org_rejected_summary_failover_preserves_returned_draft_receipt(
    monkeypatch,
) -> None:
    router = _MutableRouter(_rows())
    initiator_calls = 0

    async def fake_ask(_router, requested, _messages, **_kwargs):  # noqa: ANN001
        nonlocal initiator_calls
        served = requested
        if requested == "author-a":
            initiator_calls += 1
            if initiator_calls == 2:
                served = "review-c"
        route = router.resolve(served)
        content = "independent\nPASS" if requested == "review-b" else "content"
        response = {
            "model": route.upstream_model,
            "choices": [{"message": {"content": content}}],
        }
        return trusted_chat_result(
            request_payload={"model": requested, "messages": _messages},
            response=response,
            requested_model=requested,
            actual_model=served,
            route=route,
        )

    monkeypatch.setattr(modes, "_ask_observed", fake_ask)

    result = await modes.run_org(
        router,
        [{"role": "user", "content": "analyze"}],
    )

    final_route = result["_route"]
    assert final_route["model"] == "worker-d"
    assert final_route["requested_model"] == "worker-d"
    assert final_route["actual_model"] == "worker-d"
    assert final_route["upstream_model"] == "qwen-turbo"
    assert final_route["reported_model"] == "qwen-turbo"
    assert final_route["route_receipt_version"] == 1
    assert final_route["final_model"] == "worker-d"
    assert final_route["summary_model_requested"] == "author-a"
    assert final_route["summary_model"] == "review-c"
    assert final_route["post_summary_review_error"] == (
        "initiator_summary_actual_mismatch"
    )


@pytest.mark.asyncio
async def test_org_rejects_failover_model_as_initiator_summary(
    monkeypatch,
) -> None:
    """A fallback model may not impersonate the initiator's summary stage."""

    router = _MutableRouter(_rows())
    initiator_calls = 0

    async def fake_ask(_router, requested, _messages, **_kwargs):  # noqa: ANN001
        nonlocal initiator_calls
        served = requested
        if requested == "author-a":
            initiator_calls += 1
            if initiator_calls == 2:
                served = "review-c"
        route = router.resolve(served)
        if requested == "author-a" and initiator_calls == 1:
            content = "plan"
        elif requested == "author-a":
            content = "fallback model wrote the summary"
        elif requested == "worker-d":
            content = "worker draft"
        else:
            content = "independent\nPASS"
        response = {
            "model": route.upstream_model,
            "choices": [{"message": {"content": content}}],
        }
        return trusted_chat_result(
            request_payload={"model": requested, "messages": _messages},
            response=response,
            requested_model=requested,
            actual_model=served,
            route=route,
        )

    monkeypatch.setattr(modes, "_ask_observed", fake_ask)

    result = await modes.run_org(
        router,
        [{"role": "user", "content": "analyze"}],
    )

    route = result["_route"]
    assert modes._text(result) == "worker draft"
    assert route["summary_model_requested"] == "author-a"
    assert route["summary_model"] == "review-c"
    assert route["post_summary_review_error"] == (
        "initiator_summary_actual_mismatch"
    )
    assert route["reviewed"] is False
    assert route["reviewer_vote_weight"] == 0


@pytest.mark.asyncio
async def test_org_review_uses_invocation_route_snapshot_not_hot_reloaded_router(
    monkeypatch,
) -> None:
    router = _MutableRouter(_rows())
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")

    async def fake_ask(_router, requested, _messages, **_kwargs):  # noqa: ANN001
        reviewer = next(row for row in router.rows if row["model"] == requested)
        reviewer["independence_domain"] = _domain("a")
        invocation_route = router.resolve(requested)
        # A reload after invocation makes the mutable registry look independent.
        reviewer["independence_domain"] = _domain("b")
        response = {
            "model": invocation_route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        }
        return trusted_chat_result(
            request_payload={"model": requested, "messages": _messages},
            response=response,
            requested_model=requested,
            actual_model=requested,
            route=invocation_route,
        )

    monkeypatch.setattr(modes, "_ask_observed", fake_ask)

    _requested, decision, _verdict = await modes._org_review(
        router,
        gate,
        plan="spec",
        output="draft",
        label="output",
        role="test.org.review",
    )

    assert decision is not None
    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_domain_is_lineage_domain"


@pytest.mark.asyncio
async def test_agent_verify_uses_invocation_route_snapshot_not_hot_reload(
    monkeypatch,
) -> None:
    router = _MutableRouter(_rows())
    reviewer = next(row for row in router.rows if row["model"] == "review-b")
    reviewer["independence_domain"] = _domain("a")
    invocation_route = router.resolve("review-b")
    reviewer["independence_domain"] = _domain("b")

    async def fake_call(*_args, **_kwargs):  # noqa: ANN002, ANN003
        response = {
            "model": invocation_route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        }
        return "PASS", "review-b", invocation_route, response

    monkeypatch.setattr(orchestrated_agent, "_llm_observed_response", fake_call)
    observation = await orchestrated_agent._verify(
        router,
        "review-b",
        "task",
        "plan",
        {"reply": "done", "tool_log": []},
    )
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    decision = gate.evaluate(observation)

    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_domain_is_lineage_domain"


def test_generic_openai_compat_cannot_self_attest_vendor_identity() -> None:
    provider = object.__new__(OpenAICompatProvider)

    assert provider.expected_model_family("claude-sonnet-4-6") is None
    assert provider.verify_model_identity(
        "claude-sonnet-4-6", "claude-sonnet-4-6"
    ) is None
    assert provider.expected_model_family("gpt-5.5") is None


def test_official_openai_compat_endpoint_has_family_bounded_identity() -> None:
    provider = object.__new__(OpenAICompatProvider)
    provider.base_url = "https://api.openai.com/v1"

    assert provider.expected_model_family("gpt-4o") == "openai"
    assert provider.verify_model_identity("gpt-4o", "gpt-4o") == (
        "gpt-4o",
        "openai",
    )
    assert provider.expected_model_family("claude-sonnet-4-6") is None
    assert provider.verify_model_identity(
        "claude-sonnet-4-6", "claude-sonnet-4-6"
    ) is None


@pytest.mark.parametrize(
    ("base_url", "model", "family"),
    [
        ("https://open.bigmodel.cn/api/paas/v4", "glm-4.6", "zhipu"),
        ("https://api.moonshot.cn/v1", "kimi-k2", "moonshot"),
        ("https://api.moonshot.ai/v1", "moonshot-v1", "moonshot"),
        (
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "qwen-max",
            "alibaba-qwen",
        ),
        (
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            "qwen3.7-plus",
            "alibaba-qwen",
        ),
        (
            "https://dashscope-us.aliyuncs.com/compatible-mode/v1",
            "qwen3.7-plus",
            "alibaba-qwen",
        ),
        ("https://api.z.ai/api/paas/v4", "glm-5.1", "zhipu"),
        (
            "https://workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
            "qwen-plus",
            "alibaba-qwen",
        ),
        (
            "https://api.hunyuan.cloud.tencent.com/v1",
            "hunyuan-turbo",
            "tencent-hunyuan",
        ),
        ("https://qianfan.baidubce.com/v2", "ernie-4.5", "baidu-ernie"),
        ("https://api.minimaxi.com/v1", "minimax-m1", "minimax"),
        ("https://api.minimax.io/v1", "minimax-m1", "minimax"),
        ("https://api.x.ai/v1", "grok-2", "xai-grok"),
        ("https://api.mistral.ai/v1", "mistral-large", "mistral"),
        ("https://apihub.agnes-ai.com/v1", "agnes-2.0", "agnes"),
        ("https://api.perplexity.ai", "sonar", "perplexity-sonar"),
    ],
)
def test_documented_official_compat_endpoints_attest_only_their_family(
    base_url: str, model: str, family: str
) -> None:
    provider = object.__new__(OpenAICompatProvider)
    provider.base_url = base_url

    assert provider.expected_model_family(model) == family
    assert provider.verify_model_identity(model, model) == (model, family)
    assert provider.verify_model_identity(model, f"{model}-different") is None


@pytest.mark.parametrize(
    "base_url",
    [
        "https://openrouter.ai/api/v1",
        "https://api.siliconflow.cn/v1",
        "https://api.siliconflow.com/v1",
        "https://api.groq.com/openai/v1",
    ],
)
def test_model_aggregators_cannot_attest_underlying_vendor_family(base_url: str) -> None:
    provider = object.__new__(OpenAICompatProvider)
    provider.base_url = base_url

    assert provider.expected_model_family("gpt-4o") is None
    assert provider.verify_model_identity("gpt-4o", "gpt-4o") is None


def test_mixed_official_platform_cannot_attest_a_different_vendor_family() -> None:
    provider = object.__new__(OpenAICompatProvider)
    provider.base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"

    assert provider.expected_model_family("deepseek-v3") is None
    assert provider.verify_model_identity("deepseek-v3", "deepseek-v3") is None


def test_dedicated_volcano_adapter_can_verify_known_exact_model() -> None:
    provider = object.__new__(VolcanoProvider)
    provider.base_url = "https://ark.cn-beijing.volces.com/api/v3"

    assert provider.expected_model_family("deepseek-v3") == "deepseek"
    assert provider.verify_model_identity("deepseek-v3", "deepseek-v3") == (
        "deepseek-v3",
        "deepseek",
    )


def test_volcano_label_on_untrusted_endpoint_cannot_grant_identity() -> None:
    provider = object.__new__(VolcanoProvider)
    provider.base_url = "https://attacker.example/api/v3"

    assert provider.expected_model_family("deepseek-v3") is None
    assert provider.verify_model_identity("deepseek-v3", "deepseek-v3") is None


@pytest.mark.asyncio
async def test_typical_official_endpoints_expose_two_independent_strong_seats() -> None:
    verification_key = b"review-receipt-test-key-32bytes!"

    class _Store:
        def is_verified(self, provider, connection):  # noqa: ANN001, ANN201
            return is_verified_connection(
                provider, connection, verification_key=verification_key
            )

        def all(self):  # noqa: ANN201
            return {
                "openai": mark_connection_verified("openai", {
                    "type": "openai_compat",
                    "base_url": "https://api.openai.com/v1",
                    "api_key": "test-only",
                    "enabled_models": [
                        {
                            "id": "gpt-author",
                            "upstream_model": "gpt-4o",
                            "tier": "premium",
                            "rank": 1,
                        }
                    ],
                }, verification_key=verification_key, verified_at="2026-07-16T12:34:56Z"),
                "google": mark_connection_verified("google", {
                    "type": "openai_compat",
                    "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                    "api_key": "test-only",
                    "enabled_models": [
                        {
                            "id": "gemini-reviewer",
                            "upstream_model": "gemini-2.5-pro",
                            "tier": "premium",
                            "rank": 2,
                        }
                    ],
                }, verification_key=verification_key, verified_at="2026-07-16T12:34:56Z"),
            }

    router = Router(models_config={}, store=_Store())
    try:
        gate = ReviewGate(router)
        author_route = router.resolve("gpt-author")
        assert gate.add_author(
            "gpt-author",
            role="initiator",
            initiator=True,
            requested_model="gpt-author",
            route=author_route,
            response={"model": "gpt-4o"},
        )
        assert gate.select_reviewer() == "gemini-reviewer"
        capability = gate.review_capability()
        assert capability["strong_route_count"] == 2
        assert capability["independent_pair_available"] is True
        assert capability["reason"] is None
    finally:
        await router.aclose()


@pytest.mark.asyncio
async def test_default_empty_config_reports_review_unavailable() -> None:
    class _EmptyStore:
        def all(self):  # noqa: ANN201
            return {}

    router = Router(models_config={}, store=_EmptyStore())
    try:
        gate = ReviewGate(router)
        capability = gate.review_capability()
        assert capability["independent_pair_available"] is False
        assert capability["reason"] in {
            "no_strong_verified_routes",
            "no_independent_strong_route_pair",
        }
    finally:
        await router.aclose()


def test_malicious_generic_compat_reviewer_claiming_claude_gets_zero_vote() -> None:
    rows = _rows()[:1]
    generic = object.__new__(OpenAICompatProvider)
    generic.name = "attacker"
    generic.independence_domain = _domain("attacker")
    rows.append(
        {
            "model": "attacker-review",
            "provider": "attacker",
            "provider_object": generic,
            "upstream_model": "claude-sonnet-4-6",
            "model_family": "anthropic",
            "independence_domain": generic.independence_domain,
            "tier": "premium",
            "rank": 2,
            "flagship": False,
        }
    )
    router = _MutableRouter(rows)
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    decision = gate.evaluate(
        review_observation(
            router,
            requested_model="attacker-review",
            served_model="attacker-review",
            route=router.resolve("attacker-review"),
            observed_model="claude-sonnet-4-6",
            verdict="PASS",
        )
    )

    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_model_identity_unknown"


def test_user_premium_tier_cannot_promote_mini_model_to_strong_review() -> None:
    rows = [_rows()[1]]
    rows.append(
        {
            "model": "spoofed-premium",
            "provider": "trusted-a",
            "upstream_model": "gpt-4o-mini",
            "model_family": "openai",
            "independence_domain": _domain("a"),
            "tier": "premium",
            "rank": 1,
            "flagship": False,
        }
    )
    router = _MutableRouter(rows)
    gate = ReviewGate(router)
    assert _add_author(gate, router, "review-b")
    decision = gate.evaluate(
        review_observation(
            router,
            requested_model="spoofed-premium",
            served_model="spoofed-premium",
            route=router.resolve("spoofed-premium"),
            observed_model="gpt-4o-mini",
            verdict="PASS",
        )
    )

    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_strength_not_qualified"


def test_same_virtual_author_identity_drift_poison_lineage() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    drift_route = SimpleNamespace(
        virtual_model="author-a",
        provider=_TrustedProvider("trusted-b", _domain("b")),
        upstream_model="claude-sonnet-4-6",
        model_family="anthropic",
        independence_domain=_domain("b"),
        tier="premium",
        flagship=False,
    )

    assert gate.add_author(
        "author-a",
        role="summary",
        requested_model="author-a",
        route=drift_route,
        response={"model": "claude-sonnet-4-6"},
    ) is False
    assert gate.lineage_complete is False

    review = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=router.resolve("review-b"),
        response={"model": "claude-sonnet-4-6"},
        verdict="PASS",
    )
    decision = gate.evaluate(review)
    assert decision.vote_weight == 0
    assert decision.reason == "author_lineage_unknown"


def test_same_verified_identity_is_stable_across_response_casing() -> None:
    rows = _rows()[:2]
    rows[0]["upstream_model"] = "GPT-4O"
    router = _MutableRouter(rows)
    gate = ReviewGate(router)
    first_route = router.resolve("author-a")

    assert gate.add_author(
        "author-a",
        role="initiator",
        initiator=True,
        route=first_route,
        response={"model": "GPT-4O"},
    )

    rows[0]["upstream_model"] = "gpt-4o"
    second_route = router.resolve("author-a")
    assert gate.add_author(
        "author-a",
        role="summary",
        route=second_route,
        response={"model": "gpt-4o"},
    )
    assert gate.lineage_complete is True
    assert gate.route_metadata(None)["author_lineage"][0]["observed_model"] == "gpt-4o"


def test_author_lineage_exposes_sanitized_per_call_receipts() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    route = router.resolve("author-a")
    assert gate.add_author(
        "author-a",
        role="planner",
        initiator=True,
        requested_model="requested-planner-alias",
        route=route,
        response={"model": "gpt-4o"},
    )
    assert gate.add_author(
        "author-a",
        role="summary",
        requested_model="author-a",
        route=route,
        response={"model": "gpt-4o"},
    )

    lineage = gate.route_metadata(None)["author_lineage"][0]
    assert lineage["route_receipt_version"] == 1
    assert [call["role"] for call in lineage["call_receipts"]] == [
        "planner",
        "summary",
    ]
    first = lineage["call_receipts"][0]
    assert first["requested_model"] == "requested-planner-alias"
    assert first["actual_model"] == "author-a"
    assert first["reported_model"] == "gpt-4o"
    assert first["observed_model"] == "gpt-4o"
    assert first["route_receipt_version"] == 1
    assert not ({"api_key", "base_url", "url"} & set(first))


def test_absorbed_review_contributor_keeps_invocation_identity_after_reload() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    invocation_route = router.resolve("review-b")
    observation = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=invocation_route,
        response={"model": "claude-sonnet-4-6"},
        verdict="FAIL",
        reviewed_output="candidate",
    )
    reviewer_row = next(row for row in router.rows if row["model"] == "review-b")
    reviewer_row.update(
        upstream_model="gpt-4.1",
        model_family="openai",
        independence_domain=_domain("a"),
    )

    assert gate.add_contributor(observation, role="review_feedback") is True
    assert "anthropic" in gate.contributor_families
    assert _domain("b") in gate.contributor_domains


def test_route_receipt_is_versioned_and_legacy_model_is_actual_served() -> None:
    router = _MutableRouter(_rows())
    route = router.resolve("review-b")
    receipt = route_receipt(
        requested_model="requested-alias",
        actual_model="review-b",
        route=route,
        response={"model": "claude-sonnet-4-6"},
    )

    assert receipt["route_receipt_version"] == 1
    assert receipt["requested_model"] == "requested-alias"
    assert receipt["actual_model"] == "review-b"
    assert receipt["model"] == "review-b"


def test_author_receipt_rejects_route_actual_alias_mismatch() -> None:
    router = _MutableRouter(_rows())
    route = router.resolve("author-a")
    receipt = route_receipt(
        requested_model="author-a",
        actual_model="different-alias",
        route=route,
        response={"model": "gpt-4o"},
    )
    gate = ReviewGate(router)

    assert receipt["model_identity_error"] == "actual_route_mismatch"
    assert gate.add_author(
        "different-alias",
        role="planner",
        initiator=True,
        receipt=receipt,
    ) is False
    assert gate.lineage_complete is False


def test_author_receipt_rejects_route_without_virtual_model_binding() -> None:
    router = _MutableRouter(_rows()[:2])
    source = router.resolve("author-a")
    unbound_route = SimpleNamespace(
        provider=source.provider,
        upstream_model=source.upstream_model,
        model_family=source.model_family,
        independence_domain=source.independence_domain,
        tier=source.tier,
        flagship=source.flagship,
    )
    receipt = route_receipt(
        requested_model="author-a",
        actual_model="author-a",
        route=unbound_route,
        response={"model": source.upstream_model},
    )
    gate = ReviewGate(router)

    assert receipt["model_identity_error"] == "missing_route_virtual"
    assert gate.add_author(
        "author-a",
        role="initiator",
        initiator=True,
        receipt=receipt,
    ) is False
    assert gate.lineage_complete is False


def test_reviewer_without_virtual_model_binding_has_zero_vote() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    source = router.resolve("review-b")
    unbound_route = SimpleNamespace(
        provider=source.provider,
        upstream_model=source.upstream_model,
        model_family=source.model_family,
        independence_domain=source.independence_domain,
        tier=source.tier,
        flagship=source.flagship,
    )
    observation = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=unbound_route,
        response={"model": source.upstream_model},
        verdict="PASS",
    )
    decision = gate.evaluate(observation)

    assert observation.model_identity_error == "missing_route_virtual"
    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_model_identity_unknown"


@pytest.mark.asyncio
async def test_economy_route_records_actual_failover_and_call_receipt(monkeypatch) -> None:
    router = _MutableRouter(
        [
            {
                **_rows()[3],
                "model": "requested-cheap",
                "rank": 1,
            },
            {**_rows()[0], "model": "actual-fallback", "tier": "cheap", "rank": 2},
        ]
    )
    actual_route = router.resolve("actual-fallback")

    async def fake_ask(_router, requested, _messages, **_kwargs):  # noqa: ANN001
        return (
            {
                "model": actual_route.upstream_model,
                "choices": [{"message": {"content": "served"}}],
            },
            "actual-fallback",
            actual_route,
        )

    monkeypatch.setattr(modes, "_ask_observed", fake_ask)
    result = await modes.run_economy(router, [{"role": "user", "content": "hi"}])

    assert result["_route"]["model"] == "actual-fallback"
    assert result["_route"]["requested_model"] == "requested-cheap"
    assert result["_route"]["actual_model"] == "actual-fallback"
    assert result["_route"]["route_receipt_version"] == 1


def test_unsigned_author_receipt_cannot_create_review_lineage() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("author-a")
    signed = route_receipt(
        requested_model="author-a",
        actual_model="author-a",
        route=route,
        response={"model": "gpt-4o"},
    )
    forged = {
        key: value for key, value in signed.items() if not key.startswith("_nachuan_")
    }
    gate = ReviewGate(router)

    assert gate.add_author(
        "author-a",
        role="initiator",
        initiator=True,
        receipt=forged,
    ) is False
    assert gate.lineage_complete is False
    assert gate.route_metadata(None)["unknown_lineage"][-1]["reason"] == (
        "invalid_call_attestation"
    )


def test_signed_author_receipt_rejects_identity_field_mutation() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("author-a")
    receipt = route_receipt(
        requested_model="author-a",
        actual_model="author-a",
        route=route,
        response={"model": "gpt-4o"},
    )
    receipt["provider"] = "attacker-controlled"
    gate = ReviewGate(router)

    assert gate.add_author(
        "author-a",
        role="initiator",
        initiator=True,
        receipt=receipt,
    ) is False
    assert gate.lineage_complete is False


def test_review_vote_rejects_verdict_swapped_after_provider_call() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    original = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=router.resolve("review-b"),
        response={"model": "claude-sonnet-4-6"},
        verdict="FAIL",
        reviewed_output="candidate",
    )

    decision = gate.evaluate(
        replace(original, verdict="PASS", passed=True),
        reviewed_output="candidate",
    )

    assert decision.vote_weight == 0
    assert decision.reviewed is False
    assert decision.reason == "reviewer_call_attestation_invalid"


def test_review_vote_rejects_identity_swapped_after_attestation() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    original = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=router.resolve("review-b"),
        response={"model": "claude-sonnet-4-6"},
        verdict="PASS",
        reviewed_output="candidate",
    )

    decision = gate.evaluate(
        replace(original, model_family="google-gemini"),
        reviewed_output="candidate",
    )

    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_observation_receipt_mismatch"


def test_review_receipt_cannot_replay_across_agent_turn_contexts() -> None:
    router = _MutableRouter(_rows()[:2])
    first = set_agent_author_context("turn-a")
    try:
        stale = review_observation(
            router,
            requested_model="review-b",
            served_model="review-b",
            route=router.resolve("review-b"),
            response={"model": "claude-sonnet-4-6"},
            verdict="PASS",
            reviewed_output="candidate",
        )
    finally:
        reset_agent_author_context(first)

    second = set_agent_author_context("turn-b")
    try:
        gate = ReviewGate(router)
        assert _add_author(gate, router, "author-a")
        decision = gate.evaluate(stale, reviewed_output="candidate")
    finally:
        reset_agent_author_context(second)

    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_call_attestation_invalid"


def test_provider_pass_provenance_cannot_be_rebound_to_another_candidate() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("review-b")
    provenance = trusted_review_provenance(
        requested_model="review-b",
        actual_model="review-b",
        route=route,
        verdict="PASS",
        reviewed_output="candidate-a",
    )
    response = {
        "model": route.upstream_model,
        "choices": [{"message": {"content": "PASS"}}],
    }

    first = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=route,
        response=response,
        verdict="PASS",
        reviewed_output="candidate-a",
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output="candidate-a",
        ),
    )
    rebound = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=route,
        response=response,
        verdict="PASS",
        reviewed_output="candidate-b",
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output="candidate-b",
        ),
    )

    assert first.review_receipt is not None
    assert rebound.review_receipt is None


def test_provider_fail_output_cannot_be_relabelled_as_pass() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("review-b")
    provenance = trusted_review_provenance(
        requested_model="review-b",
        actual_model="review-b",
        route=route,
        verdict="FAIL",
        reviewed_output="candidate",
    )
    observation = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=route,
        response={
            "model": route.upstream_model,
            "choices": [{"message": {"content": "FAIL"}}],
        },
        verdict="PASS",
        reviewed_output="candidate",
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output="candidate",
        ),
    )
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")

    decision = gate.evaluate(observation, reviewed_output="candidate")

    assert observation.review_receipt is None
    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_call_attestation_invalid"


def test_same_review_receipt_cannot_vote_in_a_second_gate() -> None:
    router = _MutableRouter(_rows()[:2])
    observation = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=router.resolve("review-b"),
        verdict="PASS",
        reviewed_output="candidate",
    )
    first_gate = ReviewGate(router)
    assert _add_author(first_gate, router, "author-a")
    assert first_gate.evaluate(
        observation, reviewed_output="candidate"
    ).reviewed is True

    second_gate = ReviewGate(router)
    assert _add_author(second_gate, router, "author-a")
    replay = second_gate.evaluate(observation, reviewed_output="candidate")

    assert replay.vote_weight == 0
    assert replay.reason == "review_receipt_replayed"


def test_same_review_receipt_cannot_approve_a_second_output_in_one_gate() -> None:
    router = _MutableRouter(_rows()[:2])
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")
    observation = review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=router.resolve("review-b"),
        verdict="PASS",
        reviewed_output="candidate-a",
    )
    assert gate.evaluate(
        observation, reviewed_output="candidate-a"
    ).reviewed is True

    mismatch = gate.evaluate(observation, reviewed_output="candidate-b")

    assert mismatch.vote_weight == 0
    assert mismatch.reason == "reviewed_output_mismatch"


def test_one_author_call_receipt_cannot_claim_two_business_roles() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("author-a")
    receipt = route_receipt(
        requested_model="author-a",
        actual_model="author-a",
        route=route,
        response={"model": route.upstream_model},
    )
    gate = ReviewGate(router)
    assert gate.add_author(
        "author-a",
        role="planner",
        initiator=True,
        receipt=receipt,
    )

    assert gate.add_author(
        "author-a",
        role="summary",
        receipt=receipt,
    ) is False
    assert gate.route_metadata(None)["unknown_lineage"][-1]["reason"] == (
        "call_receipt_reused"
    )


def test_uncommitted_provider_ledger_can_never_grant_review_vote() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("review-b")
    candidate = "candidate"
    provenance = trusted_review_provenance(
        requested_model="review-b",
        actual_model="review-b",
        route=route,
        verdict="PASS",
        reviewed_output=candidate,
        ledger_terminal_committed=False,
    )
    observation = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=route,
        response={
            "model": route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        },
        verdict="PASS",
        reviewed_output=candidate,
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output=candidate,
        ),
    )
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")

    decision = gate.evaluate(observation, reviewed_output=candidate)

    assert observation.review_receipt is None
    assert observation.review_receipt_error == "provider_call_ledger_uncommitted"
    assert decision.vote_weight == 0
    assert decision.reviewed is False
    assert decision.reason == "provider_call_ledger_uncommitted"


def test_genuine_verdict_for_a_different_provider_request_has_zero_vote() -> None:
    router = _MutableRouter(_rows()[:2])
    route = router.resolve("review-b")
    candidate = "candidate"
    provenance = trusted_review_provenance(
        requested_model="review-b",
        actual_model="review-b",
        route=route,
        verdict="PASS",
        reviewed_output=candidate,
    )
    observation = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=route,
        response={
            "model": route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        },
        verdict="PASS",
        reviewed_output=candidate,
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output="different review request",
        ),
    )
    gate = ReviewGate(router)
    assert _add_author(gate, router, "author-a")

    decision = gate.evaluate(observation, reviewed_output=candidate)

    assert observation.review_receipt is None
    assert decision.vote_weight == 0
    assert decision.reason == "reviewer_output_attestation_invalid"


def test_provider_verdict_cannot_be_paired_with_mutated_route_identity() -> None:
    router = _MutableRouter(_rows()[:2])
    provider_route = router.resolve("review-b")
    candidate = "candidate"
    provenance = trusted_review_provenance(
        requested_model="review-b",
        actual_model="review-b",
        route=provider_route,
        verdict="PASS",
        reviewed_output=candidate,
    )
    mutated_route = router.resolve("review-b")
    mutated_route.tier = "cheap"
    mutated_route.flagship = True
    observation = _review_observation(
        router,
        requested_model="review-b",
        served_model="review-b",
        route=mutated_route,
        response={
            "model": mutated_route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        },
        verdict="PASS",
        reviewed_output=candidate,
        provider_provenance=provenance,
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model="review-b",
            reviewed_output=candidate,
        ),
    )

    assert observation.review_receipt is None
    assert observation.review_receipt_error == "provider_review_attestation_invalid"
