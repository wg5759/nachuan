"""Built-in advisory workflow capability plugins."""

from __future__ import annotations

from typing import Any

from orchestrator.plugin_kernel import PluginKernel, PluginManifestV1, ServiceDefinition
from orchestrator.workflows.pipeline import (
    PIPELINE_MODEL_EVENT,
    PIPELINE_RESULT_EVENT,
    PIPELINE_STEP_EVENT,
    PIPELINE_TURN_EVENT,
    run_pipeline,
)

BUILTIN_PIPELINE_WORKFLOW_PLUGIN_ID = "com.nachuan.workflow.pipeline"
PIPELINE_WORKFLOW_SERVICE = "workflow.pipeline"

BUILTIN_PIPELINE_WORKFLOW_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_PIPELINE_WORKFLOW_PLUGIN_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "workflow",
        "capabilities": [
            "workflow.execute:pipeline",
            f"event.emit:{PIPELINE_TURN_EVENT.name}",
            f"event.emit:{PIPELINE_STEP_EVENT.name}",
            f"event.emit:{PIPELINE_MODEL_EVENT.name}",
            f"event.emit:{PIPELINE_RESULT_EVENT.name}",
        ],
        "artifact_sha256": "69a59287440ef365263f280f755c58106412419a2e1fdde6a85f6becd44708be",
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)


def mount_builtin_pipeline_workflow(kernel: PluginKernel) -> None:
    kernel.services.define(ServiceDefinition(PIPELINE_WORKFLOW_SERVICE, "1"))
    for definition in (
        PIPELINE_TURN_EVENT,
        PIPELINE_STEP_EVENT,
        PIPELINE_MODEL_EVENT,
        PIPELINE_RESULT_EVENT,
    ):
        kernel.events.define(definition)

    def apply(ctx) -> None:
        ctx.permit("workflow.execute:pipeline")

        async def execute(
            router: Any,
            *,
            prompt: str,
            steps: list[dict[str, Any]],
            wall_deadline: float | None = None,
        ) -> dict[str, Any]:
            async def persist(definition, payload) -> None:
                await ctx.emit(definition.name, payload)

            return await run_pipeline(
                router,
                prompt=prompt,
                steps=steps,
                wall_deadline=wall_deadline,
                event_sink=persist,
            )

        ctx.provide_service(PIPELINE_WORKFLOW_SERVICE, execute)

    kernel.mount(BUILTIN_PIPELINE_WORKFLOW_MANIFEST, apply)


__all__ = [
    "BUILTIN_PIPELINE_WORKFLOW_MANIFEST",
    "BUILTIN_PIPELINE_WORKFLOW_PLUGIN_ID",
    "PIPELINE_WORKFLOW_SERVICE",
    "mount_builtin_pipeline_workflow",
]
