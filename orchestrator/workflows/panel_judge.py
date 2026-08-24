"""panel_judge（M4 协作编排）：多个模型独立作答 → 裁判模型对比、综合成一份答案。

所有 panelist 并行作答；单个失败不影响全局。用 echo 当 panelist/judge 即可离线测试。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from gateway.failover import (
    DEFAULT_TOTAL_TIMEOUT_SEC,
)
from gateway.model_identity import (
    REVIEW_STRENGTH_REGISTRY_VERSION,
    review_strength_from_identifier,
)
from gateway.schemas import (
    MAX_WORKFLOW_CONCURRENCY,
    PanelWorkflowRequest,
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

_ASK_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC


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
        "error": error[:2048],
        "error_type": error_type,
        "status": "failed",
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


async def _ask(
    router: Any,
    model_id: str,
    messages: list[dict[str, Any]],
    *,
    wall_deadline: float | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    deadline = wall_deadline
    if deadline is None:
        deadline = time.monotonic() + _ASK_TOTAL_TIMEOUT_SEC
    res: dict[str, Any] | None = None
    actual_model: str | None = None
    route: Any = None
    try:
        res, actual_model, route = await _ask_observed(
            router,
            model_id,
            messages,
            wall_deadline=deadline,
            role=role,
        )
        content = require_workflow_output(
            _text(res),
            label=f"panelist {model_id}",
        )
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        return _failed_call(
            model_id,
            f"TimeoutError: 模型 {model_id} 响应超时",
            error_type="timeout",
        )
    except WorkflowOutputLimitError as exc:
        return _failed_call(
            model_id,
            f"WorkflowOutputLimitError: {exc}",
            error_type="output_limit",
            receipt=route_receipt(
                requested_model=model_id,
                actual_model=actual_model,
                route=route,
                response=res,
            ),
        )
    except Exception as e:  # noqa: BLE001 — 单个 panelist 失败不应中断全局
        error = f"{type(e).__name__}: {e}"
        return _failed_call(model_id, error, error_type="provider_error")
    return {
        **route_receipt(
            requested_model=model_id,
            actual_model=actual_model,
            route=route,
            response=res,
        ),
        "answer": content,
        "error": None,
        "error_type": None,
        "status": "ok",
        "duplicate_of": None,
    }


def _judge_prompt(prompt: str, answers: list[dict[str, Any]]) -> str:
    parts = [
        f"原始问题：\n{prompt}\n",
        "下面是多个 AI 对该问题的独立回答。请你作为裁判：先简短点评各回答优劣，再综合出一份最佳答案。\n",
    ]
    for i, a in enumerate(answers, 1):
        identity = f"{a['actual_model']} / {a['provider']}"
        parts.append(f"【回答 {i} · 实际来源 {identity}】\n{a['answer']}\n")
    parts.append(
        "请用中文输出：① 各回答简评；② 综合后的最终答案。你只做汇总，"
        "不得把自己的输出冒充为机器验证结果。"
    )
    return "\n".join(parts)


async def run_panel(
    router: Any,
    *,
    prompt: str,
    panelists: list[str],
    judge: str,
    wall_deadline: float | None = None,
) -> dict[str, Any]:
    """并行让 panelists 作答，再让 judge 综合。返回各家答案 + 裁判结论。"""
    spec = PanelWorkflowRequest(prompt=prompt, panelists=panelists, judge=judge)
    prompt, panelists, judge = spec.prompt, spec.panelists, spec.judge
    messages = [{"role": "user", "content": prompt}]
    semaphore = asyncio.Semaphore(MAX_WORKFLOW_CONCURRENCY)
    deadline = wall_deadline or (time.monotonic() + _ASK_TOTAL_TIMEOUT_SEC)

    async def one(index: int, model: str) -> dict[str, Any]:
        async with semaphore:
            return await _ask(
                router,
                model,
                messages,
                wall_deadline=deadline,
                role=f"panel.seat.{index + 1}.{model}"[:256],
            )

    gathered, cancelled = await gather_fail_fast(
        [one(index, model) for index, model in enumerate(panelists)],
        fatal=lambda row: row.get("error_type") == "output_limit",
    )
    answers = [
        row
        if row is not None
        else _failed_call(
            panelists[index],
            "CancelledError: sibling output exceeded the workflow limit",
            error_type="sibling_cancelled",
        )
        for index, row in enumerate(gathered)
    ]
    valid: list[dict[str, Any]] = []
    degraded_reasons: list[str] = []
    for answer in answers:
        if not answer.get("answer"):
            degraded_reasons.append("panelist_failed")
            continue
        if not call_identity_known(answer):
            answer["status"] = "identity_unknown"
            degraded_reasons.append("panelist_identity_unknown")
            continue
        duplicate = next((row for row in valid if calls_collide(answer, row)), None)
        if duplicate is not None:
            answer["status"] = "duplicate"
            answer["duplicate_of"] = duplicate["actual_model"]
            degraded_reasons.append("panelist_identity_collision")
            continue
        valid.append(answer)
    output_limited = any(
        answer.get("error_type") == "output_limit" for answer in answers
    )
    if output_limited:
        return {
            "response_version": RESPONSE_VERSION,
            "panelists": answers,
            "judge": judge,
            "summary": None,
            "review_verdict": None,
            "verdict": None,
            "judge_error": "面板输出超过安全上限；已取消并回收仍在运行的兄弟调用",
            "error": "面板输出超过安全上限",
            "effective_panelists": len(valid),
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
            "outcome": "partial" if valid else "failed",
            "stopped_reason": "panelist_output_limit",
            "degraded_reasons": sorted(
                set(degraded_reasons + ["panelist_output_limit"])
            ),
            "cancelled_panelists": [panelists[index] for index in cancelled],
            "collaboration_type": "multi_source_synthesis",
            "machine_verified": False,
        }
    if not valid:
        return {
            "response_version": RESPONSE_VERSION,
            "panelists": answers,
            "judge": judge,
            "summary": None,
            "review_verdict": None,
            "verdict": None,
            "judge_error": None,
            "error": "所有面板模型都失败了",
            "effective_panelists": 0,
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
            "stopped_reason": "all_panelists_failed",
            "degraded_reasons": sorted(set(degraded_reasons)),
            "collaboration_type": "multi_source_synthesis",
            "machine_verified": False,
        }
    verdict = await _ask(
        router,
        judge,
        [{"role": "user", "content": _judge_prompt(prompt, valid)}],
        wall_deadline=deadline,
        role=f"panel.judge.{judge}"[:256],
    )
    judge_independent = bool(
        verdict.get("answer")
        and call_identity_known(verdict)
        and all(not calls_collide(verdict, answer) for answer in valid)
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
        and len(valid) == len(panelists)
    )
    summary = verdict.get("answer")
    return {
        "response_version": RESPONSE_VERSION,
        "panelists": answers,
        "judge": judge,
        "summary": summary,
        # The judge authored this synthesis, so it cannot review its own final
        # output.  Legacy vote-bearing fields stay empty until a later,
        # independent final reviewer exists.
        "review_verdict": None,
        "verdict": None,
        "judge_error": verdict.get("error"),
        "effective_panelists": len(valid),
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
