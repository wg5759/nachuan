"""Read-only orchestration capability reporting; no provider calls are made."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi.testclient import TestClient

from gateway.app import app, _orchestration_capabilities
from gateway.model_identity import review_strength_from_identifier


AUTH = {"Authorization": "Bearer test-key"}


def _domain(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _route(
    model: str,
    family: str,
    domain: str,
    *,
    provider: str | None = None,
    upstream: str | None = None,
    tier: str = "premium",
    candidate: bool | None = None,
) -> dict[str, Any]:
    upstream_model = upstream or model
    strength = review_strength_from_identifier(upstream_model)
    return {
        "model": model,
        "provider": provider or f"provider-{model}",
        "upstream_model": upstream_model,
        "model_family": family,
        "independence_domain": domain,
        "tier": tier,
        "modality": "chat",
        "review_strength": strength,
        "review_vote_candidate": strength == "strong" if candidate is None else candidate,
    }


class _RoutesOnlyRouter:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls = 0

    def routes_info(self) -> list[dict[str, Any]]:
        self.calls += 1
        return [dict(row) for row in self.rows]

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"capability endpoint must not use router.{name}")


def test_capabilities_require_auth_and_endpoint_only_reads_route_metadata() -> None:
    router = _RoutesOnlyRouter(
        [
            _route("llama-3.3", "meta-llama", _domain("initiator"), tier="cheap"),
            _route("gpt-5.5", "openai", _domain("openai")),
        ]
    )
    with TestClient(app) as client:
        original_router = app.state.router
        app.state.router = router
        try:
            assert client.get("/v1/orchestration/capabilities").status_code == 401
            response = client.get("/v1/orchestration/capabilities", headers=AUTH)
        finally:
            app.state.router = original_router

    assert response.status_code == 200
    assert response.json() == {
        "chat_model_count": 2,
        "review_candidate_count": 1,
        "independent_identity_count": 2,
        "single_review_ready": True,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "post_summary_final_review_requires_two_independent_reviewers",
    }
    assert router.calls == 1


def test_capabilities_need_initiator_plus_four_independent_reviewers() -> None:
    rows = [
        _route("llama-3.3", "meta-llama", _domain("initiator"), tier="cheap"),
        _route("gpt-5.5", "openai", _domain("openai")),
        _route("claude-opus-4-8", "anthropic", _domain("anthropic")),
        _route("gemini-2.5-pro", "google-gemini", _domain("google")),
        _route("deepseek-v3", "deepseek", _domain("deepseek")),
    ]

    assert _orchestration_capabilities(_RoutesOnlyRouter(rows)) == {
        "chat_model_count": 5,
        "review_candidate_count": 4,
        "independent_identity_count": 5,
        "single_review_ready": True,
        "post_summary_final_review_ready": True,
        "four_vendor_review_ready": True,
        "reason": None,
    }


def test_same_family_aliases_never_multiply_independent_review_capacity() -> None:
    rows = [
        _route(
            f"openai-alias-{index}",
            "openai",
            _domain(f"endpoint-{index}"),
            upstream="gpt-5.5",
        )
        for index in range(5)
    ]

    result = _orchestration_capabilities(_RoutesOnlyRouter(rows))

    assert result == {
        "chat_model_count": 5,
        "review_candidate_count": 5,
        "independent_identity_count": 1,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "single_review_requires_independent_initiator_and_reviewer",
    }


def test_candidate_claims_do_not_override_registry_identity_or_scheduler_tier() -> None:
    forged = _route(
        "forged",
        "openai",
        _domain("forged"),
        upstream="unknown-strong-model",
        candidate=True,
    )
    forged["review_strength"] = "strong"
    cheap = _route("gpt-5.5", "openai", _domain("cheap"), tier="cheap")

    forged_result = _orchestration_capabilities(_RoutesOnlyRouter([forged]))
    cheap_result = _orchestration_capabilities(_RoutesOnlyRouter([cheap]))

    assert forged_result == {
        "chat_model_count": 1,
        "review_candidate_count": 0,
        "independent_identity_count": 0,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "no_trusted_chat_identity",
    }
    assert cheap_result == {
        "chat_model_count": 1,
        "review_candidate_count": 0,
        "independent_identity_count": 1,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "no_schedulable_strong_review_candidates",
    }


def test_route_snapshot_failure_and_duplicate_model_fail_closed() -> None:
    class BrokenRouter:
        @staticmethod
        def routes_info() -> list[dict[str, Any]]:
            raise RuntimeError("synthetic route snapshot failure")

    unavailable = _orchestration_capabilities(BrokenRouter())  # type: ignore[arg-type]
    duplicate = _route("gpt-5.5", "openai", _domain("one"))
    duplicate_result = _orchestration_capabilities(
        _RoutesOnlyRouter([duplicate, {**duplicate, "independence_domain": _domain("two")}])
    )

    assert unavailable == {
        "chat_model_count": 0,
        "review_candidate_count": 0,
        "independent_identity_count": 0,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "routes_snapshot_unavailable",
    }
    assert duplicate_result == {
        "chat_model_count": 0,
        "review_candidate_count": 0,
        "independent_identity_count": 0,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": "no_chat_models",
    }
