"""流水线：固定工序，每步指定模型（如 DeepSeek 起草 → Kimi 润色 → 火山校对）。"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from gateway.failover import DEFAULT_TOTAL_TIMEOUT_SEC
from gateway.schemas import (
    PipelineWorkflowRequest,
    WorkflowOutputLimitError,
    require_workflow_output,
)
from orchestrator.modes import _ask_observed, _text
from orchestrator.workflows.common import (
    RESPONSE_VERSION,
    route_receipt,
    unserved_route_receipt,
)


_WORKFLOW_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC


async def run_pipeline(
    router: Any,
    *,
    prompt: str,
    steps: list[dict[str, Any]],
    wall_deadline: float | None = None,
) -> dict[str, Any]:
    spec = PipelineWorkflowRequest(prompt=prompt, steps=steps)
    prompt = spec.prompt
    current = prompt
    last_success: str | None = None
    trace: list[dict[str, Any]] = []
    wall_deadline = wall_deadline or (time.monotonic() + _WORKFLOW_TOTAL_TIMEOUT_SEC)
    for i, step in enumerate(spec.steps):
        requested_model = step.model
        instr = step.instruction
        p = f"{instr}\n\n输入：\n{current}" if instr else current
        response: dict[str, Any] | None = None
        actual_model: str | None = None
        route: Any = None
        try:
            response, actual_model, route = await _ask_observed(
                router,
                requested_model,
                [{"role": "user", "content": p}],
                wall_deadline=wall_deadline,
                role=f"pipeline.step.{i + 1}",
            )
            out = require_workflow_output(
                _text(response),
                label=f"pipeline step {i + 1}",
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            error = f"{type(e).__name__}: {str(e)[:2048]}"
            stopped_reason = (
                "output_limit"
                if isinstance(e, WorkflowOutputLimitError)
                else "deadline_exceeded"
                if isinstance(e, asyncio.TimeoutError) or time.monotonic() >= wall_deadline
                else "step_failed"
            )
            error_type = (
                "output_limit"
                if isinstance(e, WorkflowOutputLimitError)
                else "timeout"
                if stopped_reason == "deadline_exceeded"
                else "provider_error"
            )
            trace.append(
                {
                    "step": i + 1,
                    **route_receipt(
                        requested_model=requested_model,
                        actual_model=actual_model,
                        route=route,
                        response=response,
                    ),
                    "instruction": instr,
                    "output": None,
                    "status": "failed",
                    "error": error,
                    "error_type": error_type,
                }
            )
            for skipped_index, skipped in enumerate(spec.steps[i + 1 :], start=i + 2):
                skipped_receipt = unserved_route_receipt(
                    requested_model=skipped.model,
                    reason="not_called",
                )
                trace.append(
                    {
                        "step": skipped_index,
                        **skipped_receipt,
                        "instruction": skipped.instruction,
                        "output": None,
                        "status": "skipped",
                        "error": "not run because a required earlier step failed",
                        "error_type": "dependency_failed",
                    }
                )
            return {
                "response_version": RESPONSE_VERSION,
                "final": None,
                "partial_output": last_success,
                "trace": trace,
                "outcome": "partial" if last_success is not None else "failed",
                "stopped_reason": stopped_reason,
                "workflow_kind": "pipeline_collaboration",
                "machine_verified": False,
            }
        trace.append(
            {
                "step": i + 1,
                **route_receipt(
                    requested_model=requested_model,
                    actual_model=actual_model,
                    route=route,
                    response=response,
                ),
                "instruction": instr,
                "output": out,
                "status": "ok" if route is not None else "failed",
                "error": None if route is not None else out,
                "error_type": None if route is not None else "route_unknown",
            }
        )
        current = out
        last_success = out
    return {
        "response_version": RESPONSE_VERSION,
        "final": current,
        "partial_output": None,
        "trace": trace,
        "outcome": "completed_unverified",
        "stopped_reason": None,
        "workflow_kind": "pipeline_collaboration",
        "machine_verified": False,
    }
