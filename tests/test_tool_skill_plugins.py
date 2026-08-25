from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.provider_plugins import (
    BUILTIN_ECHO_MANIFEST,
    BUILTIN_LIST_SKILLS_MANIFEST,
    BUILTIN_SKILL_BUNDLE_MANIFEST,
    build_builtin_provider_kernel,
)
from orchestrator import tool_agent
from orchestrator.plugin_kernel import (
    PluginInUseError,
    PluginKernel,
    PluginManifestV1,
    PluginMountError,
    PluginStateError,
    ToolContractError,
    ToolDefinition,
    ToolNotFound,
)


def _tool_manifest(*, capabilities: list[str]) -> PluginManifestV1:
    return PluginManifestV1.from_mapping(
        {
            "schema": "nachuan.plugin.v1",
            "id": "com.nachuan.test.read-tool",
            "version": "1.0.0",
            "api_version": "1",
            "kind": "tool",
            "capabilities": capabilities,
            "artifact_sha256": "b" * 64,
            "execution": "in_process",
            "trust": "builtin",
            "publisher": "nachuan-tests",
        }
    )


def _definition() -> ToolDefinition:
    return ToolDefinition(
        name="list_demo",
        description="List a fixed, read-only demo catalog.",
        parameters={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    )


@pytest.mark.asyncio
async def test_tool_registration_requires_exact_capability_and_revokes_on_unmount():
    kernel = PluginKernel()

    with pytest.raises(PluginMountError):
        kernel.mount(
            _tool_manifest(capabilities=["tool.execute:other"]),
            lambda ctx: ctx.register_tool(_definition(), lambda _args: "demo"),
        )
    assert kernel.tool_schemas() == ()

    manifest = _tool_manifest(capabilities=["tool.execute:list_demo"])
    kernel.mount(
        manifest,
        lambda ctx: ctx.register_tool(_definition(), lambda _args: "demo"),
    )
    assert [item["function"]["name"] for item in kernel.tool_schemas()] == [
        "list_demo"
    ]

    lease = kernel.borrow_tool("list_demo")
    assert await lease.invoke({}) == "demo"
    with pytest.raises(PluginInUseError):
        await kernel.unmount(manifest.plugin_id)

    lease.release()
    with pytest.raises(PluginStateError):
        await lease.invoke({})
    await kernel.unmount(manifest.plugin_id)
    assert kernel.tool_schemas() == ()
    with pytest.raises(ToolNotFound):
        kernel.borrow_tool("list_demo")


@pytest.mark.asyncio
async def test_tool_arguments_and_results_are_closed_contracts():
    kernel = PluginKernel()
    manifest = _tool_manifest(capabilities=["tool.execute:list_demo"])
    kernel.mount(
        manifest,
        lambda ctx: ctx.register_tool(_definition(), lambda _args: object()),
    )
    lease = kernel.borrow_tool("list_demo")
    try:
        with pytest.raises(ToolContractError, match="arguments"):
            await lease.invoke({"unexpected": True})
        with pytest.raises(ToolContractError, match="result"):
            await lease.invoke({})
    finally:
        lease.release()
    await kernel.unmount(manifest.plugin_id)


@pytest.mark.asyncio
async def test_builtin_skill_bundle_is_data_only_and_holds_dependency_lease():
    kernel = build_builtin_provider_kernel()
    assert kernel.active_plugin_ids() == (
        BUILTIN_ECHO_MANIFEST.plugin_id,
        BUILTIN_SKILL_BUNDLE_MANIFEST.plugin_id,
        BUILTIN_LIST_SKILLS_MANIFEST.plugin_id,
    )
    assert {"list_skills", "load_skill"} <= {
        item["function"]["name"] for item in kernel.tool_schemas()
    }

    lease = kernel.borrow_tool("list_skills")
    try:
        result = await lease.invoke({})
    finally:
        lease.release()
    assert "Content Creator" in result
    assert "用到某个时调用 load_skill" in result

    load_lease = kernel.borrow_tool("load_skill")
    try:
        loaded = await load_lease.invoke({"name": "Content Creator"})
    finally:
        load_lease.release()
    assert "name: Content Creator" in loaded

    with pytest.raises(PluginInUseError):
        await kernel.unmount(BUILTIN_SKILL_BUNDLE_MANIFEST.plugin_id)
    await kernel.unmount(BUILTIN_LIST_SKILLS_MANIFEST.plugin_id)
    await kernel.unmount(BUILTIN_SKILL_BUNDLE_MANIFEST.plugin_id)
    await kernel.unmount(BUILTIN_ECHO_MANIFEST.plugin_id)


def test_builtin_list_skills_manifest_binds_exact_tool_plugin_source():
    source = Path(__file__).parents[1] / "orchestrator" / "tool_plugins.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == (
        BUILTIN_LIST_SKILLS_MANIFEST.artifact_sha256
    )


@pytest.mark.asyncio
async def test_legacy_tool_agent_uses_plugin_and_revocation_removes_runtime_schema(
    monkeypatch, tmp_path
):
    kernel = build_builtin_provider_kernel()
    router = SimpleNamespace(plugin_kernel=kernel)

    def forbidden_legacy_path() -> str:
        raise AssertionError("legacy skills.manifest_text path was used")

    monkeypatch.setattr(tool_agent.skills, "manifest_text", forbidden_legacy_path)
    monkeypatch.setattr(tool_agent.skills, "load_skill", forbidden_legacy_path)
    result = await tool_agent.execute_tool(
        "list_skills", {}, workdir=str(tmp_path), router=router
    )
    assert "Content Creator" in result
    assert {"list_skills", "load_skill"} <= {
        item["function"]["name"] for item in tool_agent._runtime_tools(router)
    }

    loaded = await tool_agent.execute_tool(
        "load_skill",
        {"name": "Content Creator"},
        workdir=str(tmp_path),
        router=router,
    )
    assert "name: Content Creator" in loaded

    await kernel.unmount(BUILTIN_LIST_SKILLS_MANIFEST.plugin_id)
    assert {"list_skills", "load_skill"}.isdisjoint({
        item["function"]["name"] for item in tool_agent._runtime_tools(router)
    })
    revoked = await tool_agent.execute_tool(
        "list_skills", {}, workdir=str(tmp_path), router=router
    )
    assert "未知工具" in revoked
    await kernel.aclose()
