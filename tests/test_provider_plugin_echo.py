from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gateway.enterprise_rag_plugins import (
    BUILTIN_ENTERPRISE_DLP_MANIFEST,
    BUILTIN_ENTERPRISE_RERANKER_MANIFEST,
    BUILTIN_ENTERPRISE_RUNTIME_MANIFEST,
    BUILTIN_ENTERPRISE_SPLITTER_MANIFEST,
)
from gateway.provider_plugins import (
    BUILTIN_ECHO_MANIFEST,
    BUILTIN_LIST_SKILLS_MANIFEST,
    BUILTIN_SKILL_BUNDLE_MANIFEST,
    build_builtin_provider_kernel,
)
from gateway.router import Router
from gateway.schemas import ChatCompletionRequest
from orchestrator.plugin_kernel import PluginInUseError
from orchestrator.ui_plugins import BUILTIN_ORCHESTRATION_UI_MANIFEST
from orchestrator.workflow_plugins import BUILTIN_PIPELINE_WORKFLOW_MANIFEST


def test_builtin_echo_manifest_is_bound_to_current_source():
    source = Path(__file__).parents[1] / "gateway" / "providers" / "echo.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == (
        BUILTIN_ECHO_MANIFEST.artifact_sha256
    )


@pytest.mark.asyncio
async def test_router_builds_echo_from_plugin_service_and_holds_lifecycle_lease():
    kernel = build_builtin_provider_kernel()
    router = Router(models_config={}, plugin_kernel=kernel)
    route = router.resolve("echo")
    assert route is not None
    assert route.provider.name == "echo"

    response = await route.provider.chat(
        ChatCompletionRequest(
            model="echo",
            messages=[{"role": "user", "content": "plugin-ready"}],
        ),
        route.upstream_model,
    )
    assert response["choices"][0]["message"]["content"] == (
        "[echo:echo] plugin-ready"
    )

    with pytest.raises(PluginInUseError):
        await kernel.unmount(BUILTIN_ECHO_MANIFEST.plugin_id)

    await router.aclose()
    await kernel.unmount(BUILTIN_ECHO_MANIFEST.plugin_id)
    assert BUILTIN_ECHO_MANIFEST.plugin_id not in kernel.active_plugin_ids()
    await kernel.aclose()
    assert kernel.active_plugin_ids() == ()


@pytest.mark.asyncio
async def test_default_router_owns_and_closes_its_builtin_plugin_kernel():
    router = Router(models_config={})
    owned_kernel = router.plugin_kernel
    assert owned_kernel.active_plugin_ids() == (
        BUILTIN_ECHO_MANIFEST.plugin_id,
        BUILTIN_PIPELINE_WORKFLOW_MANIFEST.plugin_id,
        BUILTIN_ORCHESTRATION_UI_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_SPLITTER_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_RERANKER_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_DLP_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_RUNTIME_MANIFEST.plugin_id,
        BUILTIN_SKILL_BUNDLE_MANIFEST.plugin_id,
        BUILTIN_LIST_SKILLS_MANIFEST.plugin_id,
    )

    await router.aclose()

    assert owned_kernel.active_plugin_ids() == ()


@pytest.mark.asyncio
async def test_router_reload_reuses_kernel_and_keeps_old_generation_leased_until_close():
    kernel = build_builtin_provider_kernel()
    router = Router(models_config={}, plugin_kernel=kernel)
    original = router.resolve("echo")
    assert original is not None

    await router.reload()

    replacement = router.resolve("echo")
    assert replacement is not None
    assert replacement.provider is not original.provider
    assert kernel.active_plugin_ids() == (
        BUILTIN_ECHO_MANIFEST.plugin_id,
        BUILTIN_PIPELINE_WORKFLOW_MANIFEST.plugin_id,
        BUILTIN_ORCHESTRATION_UI_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_SPLITTER_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_RERANKER_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_DLP_MANIFEST.plugin_id,
        BUILTIN_ENTERPRISE_RUNTIME_MANIFEST.plugin_id,
        BUILTIN_SKILL_BUNDLE_MANIFEST.plugin_id,
        BUILTIN_LIST_SKILLS_MANIFEST.plugin_id,
    )
    with pytest.raises(PluginInUseError):
        await kernel.unmount(BUILTIN_ECHO_MANIFEST.plugin_id)

    await router.aclose()
    await kernel.unmount(BUILTIN_ECHO_MANIFEST.plugin_id)
    await kernel.aclose()
    assert kernel.active_plugin_ids() == ()
