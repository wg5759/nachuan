"""多模型辩论：实际异源辩手多轮互评，再由独立裁判汇总。

请求别名只是路由意图；所有协同与独立性判断都绑定实际服务模型和
provider。若别名或故障转移落到同一身份，工作流会诚实降级为 partial，
不会继续制造后续“辩论轮”。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from gateway.failover import DEFAULT_TOTAL_TIMEOUT_SEC
from gateway.model_identity import (
    REVIEW_STRENGTH_REGISTRY_VERSION,
    review_strength_from_identifier,
)
from gateway.schemas import (
    MAX_WORKFLOW_CONCURRENCY,
    DebateWorkflowRequest,
    WorkflowOutputLimitError,
    require_workflow_output,
)
from orchestrator.identity import call_identity_known, calls_collide
from orchestrator.modes import _ask_observed, _text
from orchestrator.workflows.common import (
    RESPONSE_VERSION,
    gather_fail_fast,
    route_receipt,
    unserved_route_receipt,
)


_WORKFLOW_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC


def _msgs(prompt: str) -> list[dict[str, Any]]:
    return [{"role": "user", "content": prompt}]


def _failed_call(
    model_id: str,
    error: str,
    *,
    error_type: str,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    call_receipt = receipt or unserved_route_receipt(
        requested_model=model_id,
        reason=f"{error_type}_before_route",
    )
    return {
        **call_receipt,
        "answer": None,
        "status": "failed",
        "error": error[:2048],
        "error_type": error_type,
        "duplicate_of": None,
    }


def _route_only(call: dict[str, Any]) -> dict[str, Any]:
    return {
        key: call.get(key)
        for key in (
            "model",
            "requested_model",
            "actual_model",
            "provider",
            "upstream_model",
            "reported_model",
            "observed_model",
            "model_family",
            "model_identity_error",
            "independence_domain",
            "tier",
            "route_receipt_version",
        )
    }


async def _say(
    router: Any,
    requested_model: str,
    prompt: str,
    *,
    wall_deadline: float,
    label: str = "debater",
) -> dict[str, Any]:
    response: dict[str, Any] | None = None
    actual_model: str | None = None
    route: Any = None
    try:
        response, actual_model, route = await _ask_observed(
            router,
            requested_model,
            _msgs(prompt),
            wall_deadline=wall_deadline,
            role=f"debate.{label}.{requested_model}"[:256],
        )
        answer = require_workflow_output(
            _text(response),
            label=f"{label} {requested_model}",
        )
    except asyncio.CancelledError:
        raise
    except WorkflowOutputLimitError as exc:
        return _failed_call(
            requested_model,
            f"WorkflowOutputLimitError: {exc}",
            error_type="output_limit",
            receipt=route_receipt(
                requested_model=requested_model,
                actual_model=actual_model,
                route=route,
                response=response,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - one failed debater may yield partial work
        return _failed_call(
            requested_model,
            f"{type(exc).__name__}: {str(exc)[:2048]}",
            error_type="provider_error",
        )
    return {
        **route_receipt(
            requested_model=requested_model,
            actual_model=actual_model,
            route=route,
            response=response,
        ),
        "answer": answer,
        "status": "ok",
        "error": None,
        "error_type": None,
        "duplicate_of": None,
    }


def _deduplicate_round(
    rows: list[dict[str, Any]], degraded_reasons: list[str]
) -> list[dict[str, Any]]:
    accepted: list[dict[str, Any]] = []
    for row in rows:
        if not row.get("answer"):
            degraded_reasons.append("debater_failed")
            continue
        if not call_identity_known(row):
            row["status"] = "identity_unknown"
            degraded_reasons.append("debater_identity_unknown")
            continue
        duplicate = next((prior for prior in accepted if calls_collide(row, prior)), None)
        if duplicate is not None:
            row["status"] = "duplicate"
            row["duplicate_of"] = duplicate["actual_model"]
            degraded_reasons.append("debater_identity_collision")
            continue
        accepted.append(row)
    return accepted


def _legacy_round(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Keep the old transcript shape while the UI adopts round_details."""
    return {
        str(row["requested_model"]): str(row.get("answer") or row.get("error") or "")
        for row in rows
    }


async def run_debate(
    router: Any,
    *,
    prompt: str,
    debaters: list[str],
    judge: str,
    rounds: int = 2,
    wall_deadline: float | None = None,
) -> dict[str, Any]:
    spec = DebateWorkflowRequest(
        prompt=prompt,
        debaters=debaters,
        judge=judge,
        rounds=rounds,
    )
    prompt, debaters, judge, rounds = (
        spec.prompt,
        spec.debaters,
        spec.judge,
        spec.rounds,
    )
    deadline = wall_deadline or (time.monotonic() + _WORKFLOW_TOTAL_TIMEOUT_SEC)
    semaphore = asyncio.Semaphore(MAX_WORKFLOW_CONCURRENCY)
    degraded_reasons: list[str] = []
    round_details: list[list[dict[str, Any]]] = []
    transcript: list[dict[str, str]] = []
    lineage: list[dict[str, Any]] = []

    async def say(model: str, text: str, label: str) -> dict[str, Any]:
        async with semaphore:
            return await _say(
                router,
                model,
                text,
                wall_deadline=deadline,
                label=label,
            )

    async def collect_round(
        models: list[str], texts: list[str]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        round_number = len(round_details) + 1
        gathered, cancelled = await gather_fail_fast(
            [
                say(model, text, f"round.{round_number}.seat.{index + 1}")
                for index, (model, text) in enumerate(
                    zip(models, texts, strict=True)
                )
            ],
            fatal=lambda row: row.get("error_type") == "output_limit",
        )
        rows = [
            row
            if row is not None
            else _failed_call(
                models[index],
                "CancelledError: sibling output exceeded the workflow limit",
                error_type="sibling_cancelled",
            )
            for index, row in enumerate(gathered)
        ]
        return rows, [models[index] for index in cancelled]

    rows, cancelled_debaters = await collect_round(
        list(debaters),
        [prompt] * len(debaters),
    )
    accepted = _deduplicate_round(rows, degraded_reasons)
    round_details.append(rows)
    transcript.append(_legacy_round(rows))
    lineage.extend(accepted)
    rounds_with_quorum = 1 if len(accepted) >= 2 else 0
    output_limited = any(row.get("error_type") == "output_limit" for row in rows)

    while not output_limited and len(round_details) < rounds and len(accepted) >= 2:
        next_models: list[str] = []
        next_prompts: list[str] = []
        for current in accepted:
            others = "\n\n".join(
                (
                    f"【实际来源 {other['actual_model']} / {other['provider']}】:\n"
                    f"{other['answer']}"
                )
                for other in accepted
                if other is not current
            )
            next_prompt = (
                f"问题：{prompt}\n\n其他实际异源 AI 的回答：\n{others}\n\n"
                "请指出分歧、吸收可取之处，给出改进后的回答："
            )
            next_models.append(str(current["requested_model"]))
            next_prompts.append(next_prompt)
        rows, cancelled = await collect_round(next_models, next_prompts)
        cancelled_debaters.extend(cancelled)
        accepted = _deduplicate_round(rows, degraded_reasons)
        round_details.append(rows)
        transcript.append(_legacy_round(rows))
        if len(accepted) >= 2:
            rounds_with_quorum += 1
        output_limited = any(row.get("error_type") == "output_limit" for row in rows)
        for row in accepted:
            if not any(calls_collide(row, prior) for prior in lineage):
                lineage.append(row)

    if output_limited:
        degraded_reasons.append("debater_output_limit")
    if len(accepted) < 2:
        degraded_reasons.append("insufficient_independent_debaters")
    if len(round_details) < rounds:
        degraded_reasons.append("debate_stopped_early")

    if output_limited:
        has_partial = any(
            row.get("answer") and row.get("status") == "ok"
            for detail in round_details
            for row in detail
        )
        return {
            "response_version": RESPONSE_VERSION,
            "rounds": rounds,
            "rounds_attempted": len(round_details),
            "rounds_with_quorum": rounds_with_quorum,
            "rounds_completed": rounds_with_quorum,
            "transcript": transcript,
            "round_details": round_details,
            "effective_debaters": len(accepted),
            "judge": judge,
            "summary": None,
            "review_verdict": None,
            "verdict": None,
            "judge_error": "辩手输出超过安全上限；已取消并回收仍在运行的兄弟调用",
            "judge_route": unserved_route_receipt(
                requested_model=judge,
                reason="not_called",
            ),
            "judge_independent": False,
            "judge_vote_weight": 0,
            "synthesizer_vote_weight": 0,
            "judge_strength": None,
            "review_strength_registry_version": REVIEW_STRENGTH_REGISTRY_VERSION,
            "source_answers_reviewed": False,
            "final_reviewed": False,
            "outcome": "partial" if has_partial else "failed",
            "stopped_reason": "debater_output_limit",
            "degraded_reasons": sorted(set(degraded_reasons)),
            "cancelled_debaters": sorted(set(cancelled_debaters)),
            "collaboration_type": "multi_source_synthesis",
            "machine_verified": False,
        }

    joined = "\n\n".join(
        (
            f"【实际来源 {row['actual_model']} / {row['provider']}】:\n"
            f"{row['answer']}"
        )
        for row in accepted
    )
    if not joined:
        return {
            "response_version": RESPONSE_VERSION,
            "rounds": rounds,
            "rounds_attempted": len(round_details),
            "rounds_with_quorum": rounds_with_quorum,
            "rounds_completed": rounds_with_quorum,
            "transcript": transcript,
            "round_details": round_details,
            "effective_debaters": 0,
            "judge": judge,
            "summary": None,
            "review_verdict": None,
            "verdict": None,
            "judge_error": "没有可供汇总的辩手结果",
            "judge_route": unserved_route_receipt(
                requested_model=judge,
                reason="not_called",
            ),
            "judge_independent": False,
            "judge_vote_weight": 0,
            "synthesizer_vote_weight": 0,
            "judge_strength": None,
            "review_strength_registry_version": REVIEW_STRENGTH_REGISTRY_VERSION,
            "source_answers_reviewed": False,
            "final_reviewed": False,
            "outcome": "failed",
            "stopped_reason": "all_debaters_failed",
            "degraded_reasons": sorted(set(degraded_reasons)),
            "collaboration_type": "multi_source_synthesis",
            "machine_verified": False,
        }

    verdict = await _say(
        router,
        judge,
        (
            f"问题：{prompt}\n\n经过 {len(round_details)} 轮后的实际来源观点：\n"
            f"{joined}\n\n你只负责综合给出最佳答案；不得把自己的总结冒充机器验证。"
        ),
        wall_deadline=deadline,
        label="judge",
    )
    judge_independent = bool(
        verdict.get("answer")
        and call_identity_known(verdict)
        and all(not calls_collide(verdict, contributor) for contributor in lineage)
    )
    judge_strength = review_strength_from_identifier(verdict.get("observed_model"))
    source_answers_reviewed = bool(
        judge_independent and judge_strength == "strong"
    )
    if verdict.get("answer") and not call_identity_known(verdict):
        degraded_reasons.append("judge_identity_unknown")
    elif verdict.get("answer") and not judge_independent:
        degraded_reasons.append("judge_not_independent")
    if not verdict.get("answer"):
        degraded_reasons.append("judge_failed")

    complete = bool(
        verdict.get("answer")
        and judge_independent
        and rounds_with_quorum == rounds
        and len(accepted) == len(debaters)
        and not degraded_reasons
    )
    summary = verdict.get("answer")
    return {
        "response_version": RESPONSE_VERSION,
        "rounds": rounds,
        "rounds_attempted": len(round_details),
        "rounds_with_quorum": rounds_with_quorum,
        "rounds_completed": rounds_with_quorum,
        "transcript": transcript,
        "round_details": round_details,
        "effective_debaters": len(accepted),
        "judge": judge,
        "summary": summary,
        "review_verdict": None,
        "verdict": None,
        "judge_error": verdict.get("error"),
        "judge_route": _route_only(verdict),
        "judge_independent": judge_independent,
        "judge_vote_weight": 0,
        "synthesizer_vote_weight": 0,
        "judge_strength": judge_strength,
        "review_strength_registry_version": REVIEW_STRENGTH_REGISTRY_VERSION,
        "source_answers_reviewed": source_answers_reviewed,
        "final_reviewed": False,
        "outcome": "completed_unverified" if complete else "partial",
        "stopped_reason": None if complete else "collaboration_degraded",
        "degraded_reasons": sorted(set(degraded_reasons)),
        "collaboration_type": "multi_source_synthesis",
        "machine_verified": False,
    }
