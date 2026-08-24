"""Truthful user-visible contracts for advisory workflows.

These tests use in-memory providers only.  They exercise the public workflow
functions without making a real model or network call.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import ValidationError

from gateway import failover
from gateway.model_identity import model_family_from_identifier
from gateway.providers.base import ProviderError
from gateway.router import connection_independence_domain
from gateway.schemas import (
    MAX_WORKFLOW_OUTPUT_CHARS,
    DebateWorkflowRequest,
    PanelWorkflowRequest,
)
from orchestrator.workflows.debate import run_debate
from orchestrator.workflows.decompose import run_decompose
from orchestrator.identity import calls_collide
from orchestrator.workflows.common import gather_fail_fast
from orchestrator.workflows.panel_judge import run_panel
from orchestrator.workflows.pipeline import run_pipeline


_AUTO_DOMAIN = object()
_AUTO_RESPONSE_MODEL = object()


class _Provider:
    def __init__(
        self,
        name: str,
        *,
        answer: str = "ok",
        fail: bool = False,
        independence_domain: str | None | object = _AUTO_DOMAIN,
        response_model: str | None | object = _AUTO_RESPONSE_MODEL,
        model_family: str | None = None,
    ) -> None:
        self.name = name
        self.answer = answer
        self.fail = fail
        self.calls = 0
        if independence_domain is _AUTO_DOMAIN:
            digest = hashlib.sha256(f"test-provider:{name}".encode()).hexdigest()
            independence_domain = f"sha256:{digest}"
        self.independence_domain = independence_domain
        self.response_model = response_model
        self.model_family = model_family or f"test-family:{name}"

    def expected_model_family(self, _upstream_model: str) -> str | None:
        return self.model_family

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        if upstream_model.strip().casefold() != observed_model.strip().casefold():
            return None
        return observed_model.strip(), self.model_family

    async def chat(self, _req: Any, upstream_model: str) -> dict[str, Any]:
        self.calls += 1
        if self.fail:
            raise ProviderError(f"{self.name} unavailable")
        response = {"choices": [{"message": {"content": self.answer}}]}
        response_model = (
            upstream_model
            if self.response_model is _AUTO_RESPONSE_MODEL
            else self.response_model
        )
        if response_model is not None:
            response["model"] = response_model
        return response


class _SecondCallFailsProvider(_Provider):
    async def chat(self, _req: Any, upstream_model: str) -> dict[str, Any]:
        self.calls += 1
        if self.calls == 2:
            raise ProviderError(f"{self.name} second call failed")
        return {
            "model": upstream_model,
            "choices": [{"message": {"content": self.answer}}],
        }


class _UnknownFamilyProvider(_Provider):
    def expected_model_family(self, _upstream_model: str) -> None:
        return None

    def verify_model_identity(
        self, _upstream_model: str, _observed_model: str
    ) -> None:
        return None


class _DelayedProvider(_Provider):
    def __init__(self, name: str, *, answer: str, delay: float) -> None:
        super().__init__(name, answer=answer)
        self.delay = delay
        self.cancelled = False

    async def chat(self, _req: Any, upstream_model: str) -> dict[str, Any]:
        self.calls += 1
        try:
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return {
            "model": upstream_model,
            "choices": [{"message": {"content": self.answer}}],
        }


@dataclass
class _Route:
    virtual_model: str
    provider: _Provider
    upstream_model: str
    tier: str = "premium"
    rank: int = 1
    flagship: bool = False


class _Router:
    def __init__(self, routes: list[_Route]) -> None:
        self._routes = {route.virtual_model: route for route in routes}

    def resolve(self, model: str) -> _Route | None:
        return self._routes.get(model)

    def routes_info(self) -> list[dict[str, Any]]:
        return [
            {
                "model": route.virtual_model,
                "provider": route.provider.name,
                "tier": route.tier,
                "rank": route.rank,
                "flagship": route.flagship,
            }
            for route in self._routes.values()
        ]


def test_router_independence_domain_ignores_connection_alias_and_hides_target() -> None:
    first = connection_independence_domain(
        {"type": "openai_compat", "base_url": "https://api.openai.com/v1/"}
    )
    second = connection_independence_domain(
        {"type": "volcano", "base_url": "HTTPS://API.OPENAI.COM:443/v1"}
    )
    cli_a = connection_independence_domain({"type": "claude_code"})
    cli_b = connection_independence_domain({"type": "claude_code"})

    assert first == second
    assert cli_a == cli_b
    assert first and first.startswith("sha256:")
    assert "openai.com" not in first
    assert first != cli_a


def test_router_independence_domain_canonicalizes_host_not_url_path() -> None:
    loopback_spellings = {
        connection_independence_domain(
            {"type": "openai_compat", "base_url": "http://localhost:8123/v1"}
        ),
        connection_independence_domain(
            {
                "type": "openai_compat",
                "base_url": "http://127.42.0.1:8123/%76%31",
            }
        ),
        connection_independence_domain(
            {"type": "openai_compat", "base_url": "http://[::1]:8123/anything"}
        ),
    }
    default_port_spellings = {
        connection_independence_domain(
            {"type": "openai_compat", "base_url": "https://api.openai.com/v1"}
        ),
        connection_independence_domain(
            {"type": "volcano", "base_url": "https://api.openai.com:443/%76%31"}
        ),
    }

    assert len(loopback_spellings) == 1
    assert None not in loopback_spellings
    assert len(default_port_spellings) == 1
    assert connection_independence_domain(
        {"type": "openai_compat", "base_url": "http://localhost:8124/v1"}
    ) in loopback_spellings


@pytest.mark.parametrize("provider_type", ["claude_code", "codex"])
def test_cli_independence_domain_ignores_unsupported_base_url(
    provider_type: str,
) -> None:
    domains = {
        connection_independence_domain({"type": provider_type}),
        connection_independence_domain(
            {"type": provider_type, "base_url": "http://localhost:8001/v1"}
        ),
        connection_independence_domain(
            {"type": provider_type, "base_url": "http://127.0.0.1:9002/other"}
        ),
    }

    assert len(domains) == 1
    assert None not in domains


def test_same_verified_model_family_collides_across_independent_domains() -> None:
    first_domain = "sha256:" + hashlib.sha256(b"host-a").hexdigest()
    second_domain = "sha256:" + hashlib.sha256(b"host-b").hexdigest()
    assert calls_collide(
        {
            "actual_model": "gpt-route-a",
            "provider": "connection-a",
            "upstream_model": "gpt-4o",
            "observed_model": "gpt-4o",
            "model_family": "openai",
            "independence_domain": first_domain,
        },
        {
            "actual_model": "gpt-route-b",
            "provider": "connection-b",
            "upstream_model": "gpt-4o-mini",
            "observed_model": "gpt-4o-mini",
            "model_family": "openai",
            "independence_domain": second_domain,
        },
    )


def test_generic_family_registry_does_not_guess_cli_alias_or_echo() -> None:
    assert model_family_from_identifier("claude-sonnet-4-6") == "anthropic"
    assert model_family_from_identifier("sonnet") is None
    assert model_family_from_identifier("opus") is None
    assert model_family_from_identifier("haiku") is None
    assert model_family_from_identifier("echo") is None


def test_identity_error_marker_forces_collision_even_with_stale_fields() -> None:
    first_domain = "sha256:" + hashlib.sha256(b"stale-host-a").hexdigest()
    second_domain = "sha256:" + hashlib.sha256(b"stale-host-b").hexdigest()

    assert calls_collide(
        {
            "actual_model": "route-a",
            "provider": "connection-a",
            "upstream_model": "gpt-4o",
            "observed_model": "gpt-4o",
            "model_family": "openai",
            "model_identity_error": "observed_model_mismatch",
            "independence_domain": first_domain,
        },
        {
            "actual_model": "route-b",
            "provider": "connection-b",
            "upstream_model": "claude-sonnet-4-6",
            "observed_model": "claude-sonnet-4-6",
            "model_family": "anthropic",
            "model_identity_error": None,
            "independence_domain": second_domain,
        },
    )


async def test_gather_fail_fast_bounds_cleanup_of_cancellation_resistant_task() -> None:
    release = asyncio.Event()

    async def fatal_result() -> str:
        return "fatal"

    async def ignores_first_cancel() -> str:
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        return "late"

    started = time.monotonic()
    results, cancelled = await asyncio.wait_for(
        gather_fail_fast(
            [fatal_result(), ignores_first_cancel()],
            fatal=lambda value: value == "fatal",
            cleanup_timeout=0.02,
        ),
        timeout=0.2,
    )
    elapsed = time.monotonic() - started
    release.set()
    await asyncio.sleep(0)

    assert elapsed < 0.15
    assert results == ["fatal", None]
    assert cancelled == [1]


async def test_pipeline_stops_when_submission_outcome_is_unknown(monkeypatch) -> None:
    requested = _Route(
        "requested-alias",
        _Provider("provider-a", fail=True),
        "upstream-requested",
    )
    actual = _Route(
        "actual-served",
        _Provider("provider-b", answer="served answer"),
        "upstream-actual",
    )
    monkeypatch.setitem(failover.FALLBACKS, "requested-alias", ["actual-served"])

    result = await run_pipeline(
        _Router([requested, actual]),
        prompt="work",
        steps=[{"model": "requested-alias", "instruction": "draft"}],
    )

    trace = result["trace"][0]
    assert trace["step"] == 1
    assert trace["requested_model"] == "requested-alias"
    assert trace["actual_model"] is None
    assert trace["provider"] is None
    assert trace["upstream_model"] is None
    assert trace["instruction"] == "draft"
    assert trace["output"] is None
    assert trace["status"] == "failed"
    assert trace["error"].startswith("ProviderSubmissionOutcomeUnknown:")
    assert trace["model"] is None
    assert trace["route_receipt_version"] == 1
    assert trace["model_identity_error"] == "missing_route_snapshot"
    assert requested.provider.calls == 1
    assert actual.provider.calls == 0
    assert result["response_version"] == 2
    assert result["final"] is None
    assert result["partial_output"] is None
    assert result["outcome"] == "failed"
    assert result["stopped_reason"] == "step_failed"
    assert result["workflow_kind"] == "pipeline_collaboration"


async def test_pipeline_failure_is_terminal_not_input_to_later_steps() -> None:
    broken = _Provider("provider-a", fail=True)
    never = _Provider("provider-b", answer="must not run")
    router = _Router(
        [
            _Route("broken", broken, "broken-upstream"),
            _Route("later", never, "later-upstream"),
        ]
    )

    result = await run_pipeline(
        router,
        prompt="work",
        steps=[
            {"model": "broken", "instruction": "draft"},
            {"model": "later", "instruction": "polish"},
        ],
    )

    assert broken.calls == 1
    assert never.calls == 0
    assert result["outcome"] == "failed"
    assert result["final"] is None
    assert result["partial_output"] is None
    assert [row["status"] for row in result["trace"]] == ["failed", "skipped"]
    skipped = result["trace"][1]
    assert skipped["model"] is None
    assert skipped["requested_model"] == "later"
    assert skipped["actual_model"] is None
    assert skipped["route_receipt_version"] == 1
    assert skipped["reported_model"] is None
    assert skipped["model_identity_error"] == "not_called"
    assert result["stopped_reason"] == "step_failed"


async def test_pipeline_uses_one_wall_deadline_and_cancels_inflight_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Keep the policy deadline deterministic under a loaded Windows runner.
    # asyncio keeps its real clock; only _ask_observed's remaining-budget
    # calculation sees the simulated 100 ms consumed by the first stage.
    class _PolicyClock:
        ticks = iter((10.0, 10.1))

        @classmethod
        def monotonic(cls) -> float:
            return next(cls.ticks)

    from orchestrator import modes as modes_module

    monkeypatch.setattr(modes_module, "time", _PolicyClock)
    first = _DelayedProvider("provider-a", answer="draft", delay=0.0)
    blocked = _DelayedProvider("provider-b", answer="late", delay=1.0)
    deadline = 10.2
    started = time.monotonic()

    result = await asyncio.wait_for(
        run_pipeline(
            _Router(
                [
                    _Route("first", first, "first-upstream"),
                    _Route("blocked", blocked, "blocked-upstream"),
                ]
            ),
            prompt="work",
            steps=[
                {"model": "first", "instruction": "draft"},
                {"model": "blocked", "instruction": "polish"},
            ],
            wall_deadline=deadline,
        ),
        timeout=0.5,
    )

    assert time.monotonic() - started < 0.3
    assert blocked.cancelled is True
    assert result["outcome"] == "partial"
    assert result["partial_output"] == "draft"
    assert result["stopped_reason"] == "deadline_exceeded"


def test_independent_workflows_reject_obvious_duplicate_or_self_judge_routes() -> None:
    with pytest.raises(ValidationError, match="distinct"):
        PanelWorkflowRequest(prompt="x", panelists=["a", "a"], judge="judge")
    with pytest.raises(ValidationError, match="judge"):
        PanelWorkflowRequest(prompt="x", panelists=["a", "b"], judge="a")
    with pytest.raises(ValidationError, match="distinct"):
        DebateWorkflowRequest(prompt="x", debaters=["a", "a"], judge="judge")
    with pytest.raises(ValidationError, match="judge"):
        DebateWorkflowRequest(prompt="x", debaters=["a", "b"], judge="b")


async def test_panel_collapses_same_provider_aliases_and_marks_partial() -> None:
    shared = _Provider("shared-provider", answer="candidate")
    judge_provider = _Provider("independent-provider", answer="summary")
    router = _Router(
        [
            _Route("alias-a", shared, "model-a"),
            _Route("alias-b", shared, "model-b"),
            _Route("judge", judge_provider, "judge-upstream"),
        ]
    )

    result = await run_panel(
        router,
        prompt="question",
        panelists=["alias-a", "alias-b"],
        judge="judge",
    )

    assert [row["requested_model"] for row in result["panelists"]] == [
        "alias-a",
        "alias-b",
    ]
    assert [row["actual_model"] for row in result["panelists"]] == [
        "alias-a",
        "alias-b",
    ]
    assert [row["status"] for row in result["panelists"]] == ["ok", "duplicate"]
    assert result["panelists"][1]["duplicate_of"] == "alias-a"
    assert result["effective_panelists"] == 1
    assert result["judge_route"]["actual_model"] == "judge"
    assert result["judge_independent"] is True
    assert result["outcome"] == "partial"
    assert result["collaboration_type"] == "multi_source_synthesis"
    assert result["judge_vote_weight"] == 0
    assert result["final_reviewed"] is False
    assert result["machine_verified"] is False


async def test_panel_collapses_same_model_family_across_independent_domains() -> None:
    first_domain = "sha256:" + hashlib.sha256(b"endpoint-a").hexdigest()
    second_domain = "sha256:" + hashlib.sha256(b"endpoint-b").hexdigest()
    result = await run_panel(
        _Router(
            [
                _Route(
                    "gpt-a",
                    _Provider(
                        "connection-a",
                        independence_domain=first_domain,
                        model_family="openai",
                    ),
                    "gpt-4o",
                ),
                _Route(
                    "gpt-b",
                    _Provider(
                        "connection-b",
                        independence_domain=second_domain,
                        model_family="openai",
                    ),
                    "gpt-4o-mini",
                ),
                _Route("judge", _Provider("judge", answer="summary"), "judge-model"),
            ]
        ),
        prompt="question",
        panelists=["gpt-a", "gpt-b"],
        judge="judge",
    )

    assert [row["status"] for row in result["panelists"]] == ["ok", "duplicate"]
    assert result["effective_panelists"] == 1


async def test_panel_wrong_observed_model_is_unknown_and_gets_no_vote() -> None:
    result = await run_panel(
        _Router(
            [
                _Route(
                    "author",
                    _Provider(
                        "author-provider",
                        response_model="wrong-model",
                        model_family="openai",
                    ),
                    "gpt-4o",
                ),
                _Route("judge", _Provider("judge", answer="summary"), "judge-model"),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )

    assert result["panelists"][0]["status"] == "identity_unknown"
    assert result["panelists"][0]["reported_model"] == "wrong-model"
    assert result["panelists"][0]["observed_model"] is None
    assert result["panelists"][0]["model_identity_error"] == "observed_model_mismatch"
    assert result["effective_panelists"] == 0
    assert result["judge_vote_weight"] == 0


async def test_panel_exact_but_unregistered_model_family_gets_no_vote() -> None:
    result = await run_panel(
        _Router(
            [
                _Route(
                    "author",
                    _UnknownFamilyProvider("unknown-family"),
                    "vendor-private-model",
                ),
                _Route("judge", _Provider("judge", answer="summary"), "judge-model"),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )

    author = result["panelists"][0]
    assert author["reported_model"] == "vendor-private-model"
    assert author["observed_model"] is None
    assert author["model_family"] is None
    assert author["model_identity_error"] == "unknown_model_family"
    assert author["status"] == "identity_unknown"
    assert result["effective_panelists"] == 0


async def test_panel_judge_unknown_submission_never_replays_on_author(monkeypatch) -> None:
    author = _Route(
        "author",
        _Provider("author-provider", answer="author output"),
        "author-upstream",
    )
    judge_requested = _Route(
        "judge-requested",
        _Provider("judge-provider", fail=True),
        "judge-upstream",
    )
    monkeypatch.setitem(failover.FALLBACKS, "judge-requested", ["author"])

    result = await run_panel(
        _Router([author, judge_requested]),
        prompt="question",
        panelists=["author"],
        judge="judge-requested",
    )

    assert result["judge_route"]["requested_model"] == "judge-requested"
    assert result["judge_route"]["actual_model"] is None
    assert result["judge_route"]["provider"] is None
    assert result["judge_route"]["model_identity_error"] == "provider_error_before_route"
    assert judge_requested.provider.calls == 1
    assert author.provider.calls == 1
    assert result["judge_independent"] is False
    assert result["judge_vote_weight"] == 0
    assert result["source_answers_reviewed"] is False
    assert result["final_reviewed"] is False
    assert result["outcome"] == "partial"
    assert "judge_failed" in result["degraded_reasons"]


async def test_debate_stops_when_aliases_collapse_to_one_provider() -> None:
    shared = _Provider("shared-provider", answer="candidate")
    judge_provider = _Provider("independent-provider", answer="summary")
    router = _Router(
        [
            _Route("alias-a", shared, "model-a"),
            _Route("alias-b", shared, "model-b"),
            _Route("judge", judge_provider, "judge-upstream"),
        ]
    )

    result = await run_debate(
        router,
        prompt="question",
        debaters=["alias-a", "alias-b"],
        judge="judge",
        rounds=3,
    )

    assert shared.calls == 2  # one initial attempt per requested route; no fake later rounds
    assert result["rounds_attempted"] == 1
    assert result["rounds_with_quorum"] == 0
    assert result["rounds_completed"] == 0
    assert result["effective_debaters"] == 1
    assert [row["status"] for row in result["round_details"][0]] == [
        "ok",
        "duplicate",
    ]
    assert result["judge_independent"] is True
    assert result["outcome"] == "partial"
    assert "debater_identity_collision" in result["degraded_reasons"]
    assert result["collaboration_type"] == "multi_source_synthesis"
    assert result["judge_vote_weight"] == 0
    assert result["final_reviewed"] is False
    assert result["machine_verified"] is False


async def test_decompose_reports_routes_but_does_not_claim_independent_review() -> None:
    planner = _Route(
        "planner",
        _Provider("planner-provider", answer="first task\nsecond task"),
        "planner-upstream",
        tier="premium",
    )
    worker = _Route(
        "worker",
        _Provider("worker-provider", answer="worker result"),
        "worker-upstream",
        tier="cheap",
    )
    aggregator = _Route(
        "aggregator",
        _Provider("planner-provider", answer="aggregate"),
        "aggregate-upstream",
        tier="premium",
    )

    result = await run_decompose(
        _Router([planner, worker, aggregator]),
        task="large task",
        planner="planner",
        aggregator="aggregator",
    )

    assert {
        key: result["planner_route"][key]
        for key in (
            "requested_model",
            "actual_model",
            "provider",
            "upstream_model",
            "tier",
        )
    } == {
        "requested_model": "planner",
        "actual_model": "planner",
        "provider": "planner-provider",
        "upstream_model": "planner-upstream",
        "tier": "premium",
    }
    assert result["planner_route"]["model"] == "planner"
    assert result["planner_route"]["observed_model"] == "planner-upstream"
    assert {row["actual_model"] for row in result["subtasks"]} == {"worker"}
    assert result["aggregator_route"]["actual_model"] == "aggregator"
    assert result["workflow_kind"] == "pipeline_collaboration"
    assert result["aggregation_is_review"] is False
    assert result["machine_verified"] is False
    assert result["outcome"] == "completed_unverified"


async def test_decompose_subtask_failure_is_partial_even_with_aggregate() -> None:
    router = _Router(
        [
            _Route(
                "planner",
                _Provider("planner-provider", answer="first task\nsecond task"),
                "planner-upstream",
                tier="premium",
            ),
            _Route(
                "worker",
                _SecondCallFailsProvider("worker-provider", answer="worker result"),
                "worker-upstream",
                tier="cheap",
            ),
            _Route(
                "aggregator",
                _Provider("aggregator-provider", answer="partial aggregate"),
                "aggregate-upstream",
                tier="premium",
            ),
        ]
    )

    result = await run_decompose(
        router,
        task="large task",
        planner="planner",
        aggregator="aggregator",
    )

    assert [row["status"] for row in result["subtasks"]] == ["ok", "failed"]
    assert result["final"] == "partial aggregate"
    assert result["outcome"] == "partial"
    assert result["stopped_reason"] == "subtask_failures"


async def test_decompose_pre_route_worker_failure_has_unserved_receipt() -> None:
    router = _Router(
        [
            _Route(
                "planner",
                _Provider("planner-provider", answer="first task"),
                "planner-upstream",
                tier="premium",
            ),
            _Route(
                "worker",
                _Provider("worker-provider", fail=True),
                "worker-upstream",
                tier="cheap",
            ),
            _Route(
                "aggregator",
                _Provider("aggregator-provider", answer="unused"),
                "aggregate-upstream",
                tier="premium",
            ),
        ]
    )

    result = await run_decompose(
        router,
        task="large task",
        planner="planner",
        aggregator="aggregator",
    )

    failed = result["subtasks"][0]
    assert failed["model"] is None
    assert failed["requested_model"] == "worker"
    assert failed["actual_model"] is None
    assert failed["route_receipt_version"] == 1
    assert failed["model_identity_error"] == "provider_error_before_route"
    assert result["aggregator_route"]["model"] is None
    assert result["aggregator_route"]["model_identity_error"] == "not_called"


@pytest.mark.parametrize("shared_domain", ["same-http-endpoint", "same-cli-login"])
async def test_panel_collapses_renamed_connections_in_same_independence_domain(
    shared_domain: str,
) -> None:
    digest = hashlib.sha256(shared_domain.encode()).hexdigest()
    domain = f"sha256:{digest}"
    router = _Router(
        [
            _Route(
                "alias-a",
                _Provider("connection-a", answer="first", independence_domain=domain),
                "upstream-a",
            ),
            _Route(
                "alias-b",
                _Provider("connection-b", answer="second", independence_domain=domain),
                "upstream-b",
            ),
            _Route("judge", _Provider("independent", answer="summary"), "judge-model"),
        ]
    )

    result = await run_panel(
        router,
        prompt="question",
        panelists=["alias-a", "alias-b"],
        judge="judge",
    )

    assert [row["status"] for row in result["panelists"]] == ["ok", "duplicate"]
    assert result["effective_panelists"] == 1
    assert "panelist_identity_collision" in result["degraded_reasons"]


async def test_panel_collapses_equivalent_loopback_backend_spellings() -> None:
    urls = [
        "http://localhost:8123/v1",
        "http://127.42.0.1:8123/%76%31",
        "http://[::1]:8123/another-path",
    ]
    panelists = [
        _Route(
            f"alias-{index}",
            _Provider(
                f"connection-{index}",
                answer=f"answer-{index}",
                    independence_domain=connection_independence_domain(
                        {"type": "openai_compat", "base_url": url}
                    ),
                ),
            f"upstream-{index}",
        )
        for index, url in enumerate(urls, start=1)
    ]

    result = await run_panel(
        _Router(
            [
                *panelists,
                _Route("judge", _Provider("independent", answer="summary"), "judge-model"),
            ]
        ),
        prompt="question",
        panelists=[route.virtual_model for route in panelists],
        judge="judge",
    )

    assert [row["status"] for row in result["panelists"]] == [
        "ok",
        "duplicate",
        "duplicate",
    ]
    assert result["effective_panelists"] == 1


async def test_panel_unknown_identity_cannot_grant_judge_vote() -> None:
    author = _Provider("author", answer="candidate")
    unknown_judge = _Provider(
        "renamed-judge",
        answer="untrusted summary",
        independence_domain=None,
        response_model=None,
    )

    result = await run_panel(
        _Router(
            [
                _Route("author", author, "author-model"),
                _Route("judge", unknown_judge, "judge-model"),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )

    assert result["judge_vote_weight"] == 0
    assert result["judge_independent"] is False
    assert result["review_verdict"] is None
    assert result["summary"] == "untrusted summary"
    assert result["verdict"] is None  # legacy verdict must never carry a zero-vote summary
    assert "judge_identity_unknown" in result["degraded_reasons"]


async def test_panel_pre_route_failure_does_not_report_requested_as_served() -> None:
    result = await run_panel(
        _Router(
            [
                _Route("author", _Provider("author", fail=True), "author-model"),
                _Route("judge", _Provider("judge", answer="unused"), "judge-model"),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )

    failed = result["panelists"][0]
    assert failed["model"] is None
    assert failed["requested_model"] == "author"
    assert failed["actual_model"] is None
    assert failed["route_receipt_version"] == 1
    assert failed["model_identity_error"] == "provider_error_before_route"
    assert result["judge_route"]["model"] is None
    assert result["judge_route"]["model_identity_error"] == "not_called"


async def test_debate_pre_route_failure_does_not_report_requested_as_served() -> None:
    result = await run_debate(
        _Router(
            [
                _Route("a", _Provider("a", fail=True), "model-a"),
                _Route("b", _Provider("b", fail=True), "model-b"),
                _Route("judge", _Provider("judge", answer="unused"), "judge-model"),
            ]
        ),
        prompt="question",
        debaters=["a", "b"],
        judge="judge",
        rounds=1,
    )

    first = result["round_details"][0][0]
    assert first["model"] is None
    assert first["requested_model"] == "a"
    assert first["actual_model"] is None
    assert first["route_receipt_version"] == 1
    assert first["model_identity_error"] == "provider_error_before_route"
    assert result["judge_route"]["model_identity_error"] == "not_called"


async def test_weak_panel_and_debate_synthesizers_never_review_their_final_output() -> None:
    panel = await run_panel(
        _Router(
            [
                _Route("author", _Provider("author", answer="candidate"), "gpt-4o"),
                _Route(
                    "judge",
                    _Provider("judge", answer="summary"),
                    "gpt-4o-mini",
                ),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )
    debate = await run_debate(
        _Router(
            [
                _Route("a", _Provider("a", answer="first"), "claude-sonnet-4-6"),
                _Route("b", _Provider("b", answer="second"), "gemini-2.5-pro"),
                _Route(
                    "judge",
                    _Provider("judge", answer="summary"),
                    "gpt-4o-mini",
                ),
            ]
        ),
        prompt="question",
        debaters=["a", "b"],
        judge="judge",
        rounds=1,
    )

    for result in (panel, debate):
        assert result["summary"] == "summary"
        assert result["judge_strength"] == "weak"
        assert result["source_answers_reviewed"] is False
        assert result["final_reviewed"] is False
        assert result["judge_vote_weight"] == 0
        assert result["synthesizer_vote_weight"] == 0
        assert result["review_verdict"] is None
        assert result["verdict"] is None


async def test_panel_output_limit_preserves_safe_partial_and_cancels_sibling() -> None:
    safe = _DelayedProvider("safe", answer="safe partial", delay=0.005)
    oversized = _DelayedProvider(
        "oversized",
        answer="x" * (MAX_WORKFLOW_OUTPUT_CHARS + 1),
        delay=0.02,
    )
    slow = _DelayedProvider("slow", answer="must be cancelled", delay=1.0)

    result = await asyncio.wait_for(
        run_panel(
            _Router(
                [
                    _Route("safe", safe, "safe-model"),
                    _Route("oversized", oversized, "oversized-model"),
                    _Route("slow", slow, "slow-model"),
                    _Route("judge", _Provider("judge", answer="unused"), "judge-model"),
                ]
            ),
            prompt="question",
            panelists=["safe", "oversized", "slow"],
            judge="judge",
        ),
        timeout=0.3,
    )

    assert slow.cancelled is True
    assert result["outcome"] == "partial"
    assert result["stopped_reason"] == "panelist_output_limit"
    assert [row["answer"] for row in result["panelists"] if row["status"] == "ok"] == [
        "safe partial"
    ]
    assert result["summary"] is None
    assert result["review_verdict"] is None


async def test_panel_response_keeps_version_and_legacy_model_alias() -> None:
    result = await run_panel(
        _Router(
            [
                _Route("author", _Provider("author", answer="candidate"), "author-model"),
                _Route("judge", _Provider("judge", answer="summary"), "gpt-4o"),
            ]
        ),
        prompt="question",
        panelists=["author"],
        judge="judge",
    )

    assert result["response_version"] == 2
    assert result["panelists"][0]["model"] == "author"
    assert result["judge_route"]["model"] == "judge"
    assert result["summary"] == "summary"
    assert result["judge_route"]["route_receipt_version"] == 1
    assert result["source_answers_reviewed"] is True
    assert result["final_reviewed"] is False
    assert result["judge_vote_weight"] == 0
    assert result["review_verdict"] is None


async def test_debate_distinguishes_attempted_rounds_from_quorum_rounds() -> None:
    shared_domain = "sha256:" + hashlib.sha256(b"same endpoint").hexdigest()
    router = _Router(
        [
            _Route(
                "a",
                _Provider("connection-a", independence_domain=shared_domain),
                "model-a",
            ),
            _Route(
                "b",
                _Provider("connection-b", independence_domain=shared_domain),
                "model-b",
            ),
            _Route("judge", _Provider("judge", answer="summary"), "judge-model"),
        ]
    )

    result = await run_debate(
        router,
        prompt="question",
        debaters=["a", "b"],
        judge="judge",
        rounds=3,
    )

    assert result["rounds_attempted"] == 1
    assert result["rounds_with_quorum"] == 0
    assert result["rounds_completed"] == 0  # compatibility alias means completed quorum rounds


async def test_pipeline_output_limit_returns_partial_instead_of_escaping() -> None:
    router = _Router(
        [
            _Route("first", _Provider("first", answer="safe draft"), "first-model"),
            _Route(
                "oversized",
                _Provider(
                    "oversized",
                    answer="x" * (MAX_WORKFLOW_OUTPUT_CHARS + 1),
                ),
                "oversized-model",
            ),
        ]
    )

    result = await run_pipeline(
        router,
        prompt="question",
        steps=[
            {"model": "first", "instruction": "draft"},
            {"model": "oversized", "instruction": "polish"},
        ],
    )

    assert result["outcome"] == "partial"
    assert result["partial_output"] == "safe draft"
    assert result["stopped_reason"] == "output_limit"
    assert result["trace"][1]["error_type"] == "output_limit"


async def test_decompose_invalid_planner_shape_is_upstream_failure_not_client_error() -> None:
    too_many = "\n".join(f"task {index}" for index in range(20))
    router = _Router(
        [
            _Route("planner", _Provider("planner", answer=too_many), "planner-model"),
            _Route("aggregator", _Provider("aggregator"), "aggregator-model"),
        ]
    )

    result = await run_decompose(
        router,
        task="large task",
        planner="planner",
        aggregator="aggregator",
    )

    assert result["outcome"] == "failed"
    assert result["stopped_reason"] == "plan_invalid"
    assert result["error_type"] == "upstream_contract"


async def test_decompose_aggregator_output_limit_preserves_route_and_subtasks() -> None:
    router = _Router(
        [
            _Route(
                "planner",
                _Provider("planner", answer="first task\nsecond task"),
                "planner-model",
                tier="premium",
            ),
            _Route(
                "worker",
                _Provider("worker", answer="safe result"),
                "worker-model",
                tier="cheap",
            ),
            _Route(
                "aggregator",
                _Provider(
                    "aggregator",
                    answer="x" * (MAX_WORKFLOW_OUTPUT_CHARS + 1),
                ),
                "aggregator-model",
                tier="premium",
            ),
        ]
    )

    result = await run_decompose(
        router,
        task="large task",
        planner="planner",
        aggregator="aggregator",
    )

    assert result["outcome"] == "partial"
    assert result["stopped_reason"] == "aggregator_output_limit"
    assert len([row for row in result["subtasks"] if row["status"] == "ok"]) == 2
    assert result["aggregator_route"]["actual_model"] == "aggregator"
    assert result["aggregator_route"]["observed_model"] == "aggregator-model"
