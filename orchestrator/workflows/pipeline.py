"""流水线：固定工序，每步指定模型（如 DeepSeek 起草 → Kimi 润色 → 火山校对）。"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from gateway.failover import DEFAULT_TOTAL_TIMEOUT_SEC
from gateway.schemas import (
    PipelineWorkflowRequest,
    WorkflowOutputLimitError,
    require_workflow_output,
)
from orchestrator.modes import _ask_observed, _text
from orchestrator.plugin_kernel import EventDefinition
from orchestrator.workflows.common import (
    RESPONSE_VERSION,
    route_receipt,
    unserved_route_receipt,
)

_WORKFLOW_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC
PIPELINE_TURN_EVENT = EventDefinition("fact/workflow/pipeline/turn", "durable")
PIPELINE_STEP_EVENT = EventDefinition("fact/workflow/pipeline/step", "durable")
PIPELINE_MODEL_EVENT = EventDefinition("fact/workflow/pipeline/model", "durable")
PIPELINE_RESULT_EVENT = EventDefinition("fact/workflow/pipeline/result", "durable")

PipelineEventSink = Callable[
    [EventDefinition, Mapping[str, object]], Awaitable[None]
]


def _text_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def run_pipeline(
    router: Any,
    *,
    prompt: str,
    steps: list[dict[str, Any]],
    wall_deadline: float | None = None,
    workflow_id: str | None = None,
    event_sink: PipelineEventSink | None = None,
) -> dict[str, Any]:
    spec = PipelineWorkflowRequest(prompt=prompt, steps=steps)
    prompt = spec.prompt
    current = prompt
    last_success: str | None = None
    trace: list[dict[str, Any]] = []
    wall_deadline = wall_deadline or (time.monotonic() + _WORKFLOW_TOTAL_TIMEOUT_SEC)
    workflow_id = workflow_id or secrets.token_hex(16)

    async def emit(
        definition: EventDefinition,
        phase: str,
        **payload: object,
    ) -> None:
        if event_sink is None:
            return
        await event_sink(
            definition,
            {"workflow_id": workflow_id, "phase": phase, **payload},
        )

    await emit(
        PIPELINE_TURN_EVENT,
        "started",
        prompt_sha256=_text_sha256(prompt),
        prompt_chars=len(prompt),
        step_count=len(spec.steps),
    )
    for i, step in enumerate(spec.steps):
        requested_model = step.model
        instr = step.instruction
        p = f"{instr}\n\n输入：\n{current}" if instr else current
        await emit(
            PIPELINE_STEP_EVENT,
            "started",
            step_index=i + 1,
            instruction_sha256=_text_sha256(instr),
            instruction_chars=len(instr),
        )
        await emit(
            PIPELINE_MODEL_EVENT,
            "started",
            step_index=i + 1,
            requested_model=requested_model,
        )
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
            await emit(
                PIPELINE_MODEL_EVENT,
                "failed",
                step_index=i + 1,
                requested_model=requested_model,
                actual_model=actual_model,
                error_type=error_type,
            )
            await emit(
                PIPELINE_STEP_EVENT,
                "failed",
                step_index=i + 1,
                error_type=error_type,
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
                await emit(
                    PIPELINE_STEP_EVENT,
                    "skipped",
                    step_index=skipped_index,
                    requested_model=skipped.model,
                    error_type="dependency_failed",
                )
            failed_result = {
                "response_version": RESPONSE_VERSION,
                "workflow_id": workflow_id,
                "final": None,
                "partial_output": last_success,
                "trace": trace,
                "outcome": "partial" if last_success is not None else "failed",
                "stopped_reason": stopped_reason,
                "workflow_kind": "pipeline_collaboration",
                "machine_verified": False,
            }
            partial = last_success
            await emit(
                PIPELINE_RESULT_EVENT,
                "failed",
                outcome=failed_result["outcome"],
                stopped_reason=stopped_reason,
                result_sha256=_text_sha256(partial),
                result_chars=0 if partial is None else len(partial),
            )
            await emit(
                PIPELINE_TURN_EVENT,
                "failed",
                outcome=failed_result["outcome"],
                stopped_reason=stopped_reason,
            )
            return failed_result
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
        completed_trace = trace[-1]
        await emit(
            PIPELINE_MODEL_EVENT,
            "completed",
            step_index=i + 1,
            requested_model=requested_model,
            actual_model=completed_trace.get("actual_model"),
            provider=completed_trace.get("provider"),
            upstream_model=completed_trace.get("upstream_model"),
            result_sha256=_text_sha256(out),
            result_chars=len(out),
        )
        await emit(
            PIPELINE_STEP_EVENT,
            "completed",
            step_index=i + 1,
            result_sha256=_text_sha256(out),
            result_chars=len(out),
        )
        current = out
        last_success = out
    completed_result = {
        "response_version": RESPONSE_VERSION,
        "workflow_id": workflow_id,
        "final": current,
        "partial_output": None,
        "trace": trace,
        "outcome": "completed_unverified",
        "stopped_reason": None,
        "workflow_kind": "pipeline_collaboration",
        "machine_verified": False,
    }
    await emit(
        PIPELINE_RESULT_EVENT,
        "completed",
        outcome=completed_result["outcome"],
        stopped_reason=None,
        result_sha256=_text_sha256(current),
        result_chars=len(current),
    )
    await emit(
        PIPELINE_TURN_EVENT,
        "completed",
        outcome=completed_result["outcome"],
        stopped_reason=None,
    )
    return completed_result
