"""拆解流水线：规划 → 子任务执行 → 汇总。

这是阶段协作，不是独立互审。规划器、执行器或汇总器可以复用同一实际
模型，但每次调用都必须公开请求路由与实际服务路由，且任何阶段失败都
只能得到 partial/failed，不能用失败文本伪装成完整产出。
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from gateway.failover import DEFAULT_TOTAL_TIMEOUT_SEC
from gateway.schemas import (
    MAX_DECOMPOSE_SUBTASKS,
    MAX_WORKFLOW_CONCURRENCY,
    DecomposeWorkflowRequest,
    WorkflowOutputLimitError,
    require_workflow_output,
)
from orchestrator.classify import classify
from orchestrator.modes import _ask_observed, _text, pick_model
from orchestrator.workflows.common import (
    RESPONSE_VERSION,
    gather_fail_fast,
    route_receipt,
    unserved_route_receipt,
)


_WORKFLOW_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC


def _msgs(prompt: str) -> list[dict[str, Any]]:
    return [{"role": "user", "content": prompt}]


async def _call(
    router: Any,
    requested_model: str,
    prompt: str,
    *,
    wall_deadline: float,
    role: str,
) -> tuple[str, dict[str, Any]]:
    response, actual_model, route = await _ask_observed(
        router,
        requested_model,
        _msgs(prompt),
        wall_deadline=wall_deadline,
        role=role,
    )
    return _text(response), route_receipt(
        requested_model=requested_model,
        actual_model=actual_model,
        route=route,
        response=response,
    )


def _base_result() -> dict[str, Any]:
    return {
        "response_version": RESPONSE_VERSION,
        "workflow_kind": "pipeline_collaboration",
        "aggregation_is_review": False,
        "machine_verified": False,
    }


async def run_decompose(
    router: Any,
    *,
    task: str,
    planner: str,
    aggregator: str,
    wall_deadline: float | None = None,
) -> dict[str, Any]:
    spec = DecomposeWorkflowRequest(task=task, planner=planner, aggregator=aggregator)
    task, planner, aggregator = spec.task, spec.planner, spec.aggregator
    deadline = wall_deadline or (time.monotonic() + _WORKFLOW_TOTAL_TIMEOUT_SEC)
    try:
        plan, planner_route = await _call(
            router,
            planner,
            f"把下面任务拆成 3-6 个可独立完成的子任务，每行一个，只列子任务、不要解释：\n\n{task}",
            wall_deadline=deadline,
            role=f"decompose.planner.{planner}"[:256],
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - return an honest terminal outcome
        return {
            **_base_result(),
            "plan": None,
            "planner": planner,
            "planner_route": unserved_route_receipt(
                requested_model=planner,
                reason="planner_call_failed_before_route",
            ),
            "subtasks": [],
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": f"{type(exc).__name__}: {str(exc)[:2048]}",
            "error_type": "planner_call",
            "outcome": "failed",
            "stopped_reason": "planner_failed",
        }
    try:
        plan = require_workflow_output(plan, label="decomposition plan")
    except WorkflowOutputLimitError as exc:
        return {
            **_base_result(),
            "plan": None,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": [],
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": f"WorkflowOutputLimitError: {str(exc)[:2048]}",
            "error_type": "output_limit",
            "outcome": "failed",
            "stopped_reason": "planner_output_limit",
        }
    subtasks = [
        re.sub(r"^[-*\d.、\s）)]+", "", line).strip()
        for line in plan.splitlines()
    ]
    subtasks = [subtask for subtask in subtasks if subtask]
    plan_contract_error: str | None = None
    if len(subtasks) > MAX_DECOMPOSE_SUBTASKS:
        plan_contract_error = (
            f"decomposition plan has more than {MAX_DECOMPOSE_SUBTASKS} subtasks"
        )
    elif any(len(subtask) > 16_384 for subtask in subtasks):
        plan_contract_error = "decomposition subtask exceeds 16384 characters"
    if plan_contract_error is not None:
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": [],
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": plan_contract_error,
            "error_type": "upstream_contract",
            "outcome": "failed",
            "stopped_reason": "plan_invalid",
        }
    if not subtasks:
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": [],
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": "规划器没有生成可执行子任务",
            "error_type": "upstream_contract",
            "outcome": "partial",
            "stopped_reason": "plan_empty",
        }

    semaphore = asyncio.Semaphore(MAX_WORKFLOW_CONCURRENCY)

    async def do(index: int, subtask: str) -> dict[str, Any]:
        async with semaphore:
            classified = classify(subtask)
            tier = "premium" if classified["difficulty"] == "hard" else "cheap"
            requested_model = pick_model(router, tier)
            if not requested_model:
                return {
                    "subtask": subtask,
                    **unserved_route_receipt(
                        requested_model=None,
                        reason="route_unavailable",
                    ),
                    "requested_tier": tier,
                    "answer": None,
                    "status": "failed",
                    "error": f"没有可用的 {tier} 模型",
                    "error_type": "route_unavailable",
                }
            receipt: dict[str, Any] | None = None
            try:
                answer, receipt = await _call(
                    router,
                    requested_model,
                    subtask,
                    wall_deadline=deadline,
                    role=f"decompose.worker.{index + 1}.{requested_model}"[:256],
                )
                answer = require_workflow_output(
                    answer,
                    label=f"subtask {subtask[:80]}",
                )
            except asyncio.CancelledError:
                raise
            except WorkflowOutputLimitError as exc:
                failed_receipt = receipt or unserved_route_receipt(
                    requested_model=requested_model,
                    reason="output_limit_before_route",
                )
                return {
                    "subtask": subtask,
                    **failed_receipt,
                    "requested_tier": tier,
                    "answer": None,
                    "status": "failed",
                    "error": f"WorkflowOutputLimitError: {str(exc)[:2048]}",
                    "error_type": "output_limit",
                }
            except Exception as exc:  # noqa: BLE001 - sibling results remain useful
                return {
                    "subtask": subtask,
                    **unserved_route_receipt(
                        requested_model=requested_model,
                        reason="provider_error_before_route",
                    ),
                    "requested_tier": tier,
                    "answer": None,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {str(exc)[:2048]}",
                    "error_type": "provider_error",
                }
            return {
                "subtask": subtask,
                **receipt,
                # Preserve the requested difficulty tier separately from the actual route tier.
                "requested_tier": tier,
                "answer": answer,
                "status": "ok",
                "error": None,
                "error_type": None,
            }

    gathered, cancelled = await gather_fail_fast(
        [do(index, subtask) for index, subtask in enumerate(subtasks)],
        fatal=lambda row: row.get("error_type") == "output_limit",
    )
    results: list[dict[str, Any]] = []
    for index, row in enumerate(gathered):
        if row is not None:
            results.append(row)
            continue
        subtask = subtasks[index]
        requested_tier = (
            "premium" if classify(subtask)["difficulty"] == "hard" else "cheap"
        )
        results.append(
            {
                "subtask": subtask,
                **unserved_route_receipt(
                    requested_model=None,
                    reason="sibling_cancelled",
                ),
                "requested_tier": requested_tier,
                "answer": None,
                "status": "failed",
                "error": "CancelledError: sibling output exceeded the workflow limit",
                "error_type": "sibling_cancelled",
            }
        )
    successful = [result for result in results if result.get("status") == "ok"]
    if any(result.get("error_type") == "output_limit" for result in results):
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": results,
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": "子任务输出超过安全上限；已取消并回收仍在运行的兄弟调用",
            "error_type": "output_limit",
            "cancelled_subtasks": [subtasks[index] for index in cancelled],
            "outcome": "partial" if successful else "failed",
            "stopped_reason": "subtask_output_limit",
        }
    if not successful:
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": results,
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="not_called",
            ),
            "final": None,
            "error": "所有子任务都失败了",
            "error_type": "subtask_failures",
            "outcome": "partial",
            "stopped_reason": "all_subtasks_failed",
        }

    joined = "\n\n".join(
        (
            f"子任务：{result['subtask']}\n"
            f"结果（实际来源 {result['actual_model']} / {result['provider']}）："
            f"{result['answer']}"
        )
        for result in successful
    )
    failed_names = [str(result["subtask"]) for result in results if result.get("status") != "ok"]
    omissions = (
        f"\n\n以下子任务失败，汇总必须明确标注缺口：{failed_names}"
        if failed_names
        else ""
    )
    aggregator_route: dict[str, Any] | None = None
    try:
        final, aggregator_route = await _call(
            router,
            aggregator,
            (
                f"原任务：{task}\n\n各子任务结果：\n{joined}{omissions}\n\n"
                "请综合成一份完整、连贯的产出；这只是汇总，不是独立验证："
            ),
            wall_deadline=deadline,
            role=f"decompose.aggregator.{aggregator}"[:256],
        )
        final = require_workflow_output(final, label="decomposition aggregate")
    except asyncio.CancelledError:
        raise
    except WorkflowOutputLimitError as exc:
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": results,
            "aggregator": aggregator,
            "aggregator_route": aggregator_route,
            "final": None,
            "error": f"WorkflowOutputLimitError: {str(exc)[:2048]}",
            "error_type": "output_limit",
            "outcome": "partial",
            "stopped_reason": "aggregator_output_limit",
        }
    except Exception as exc:  # noqa: BLE001 - preserve completed subtask evidence
        return {
            **_base_result(),
            "plan": plan,
            "planner": planner,
            "planner_route": planner_route,
            "subtasks": results,
            "aggregator": aggregator,
            "aggregator_route": unserved_route_receipt(
                requested_model=aggregator,
                reason="aggregator_call_failed_before_route",
            ),
            "final": None,
            "error": f"{type(exc).__name__}: {str(exc)[:2048]}",
            "error_type": "aggregator_call",
            "outcome": "partial",
            "stopped_reason": "aggregator_failed",
        }
    complete = len(successful) == len(results)
    return {
        **_base_result(),
        "plan": plan,
        "planner": planner,
        "planner_route": planner_route,
        "subtasks": results,
        "aggregator": aggregator,
        "aggregator_route": aggregator_route,
        "final": final,
        "error": None if complete else "部分子任务失败；最终内容仅为缺口明确的部分汇总",
        "error_type": None if complete else "subtask_failures",
        "outcome": "completed_unverified" if complete else "partial",
        "stopped_reason": None if complete else "subtask_failures",
    }
