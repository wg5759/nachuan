"""Built-in provider, reviewed-Skill bundle, and read-only tool plugins.

PK-002 migrates the no-network Echo provider.  PK-003 adds the exact reviewed
Skill bundle as frozen data plus list/load tools behind revocable capabilities.
All other providers and tools remain on their legacy paths until separately
accepted.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from gateway.providers.base import ChatProvider
from gateway.providers.echo import EchoProvider
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    ServiceDefinition,
)
from orchestrator.skill_bundle import EXPECTED_MANIFEST_SHA256
from orchestrator.tool_plugins import (
    LIST_SKILLS_TOOL_DEFINITION,
    LOAD_SKILL_TOOL_DEFINITION,
    SkillBundleV1,
    build_reviewed_skill_bundle,
    render_skill_content,
    render_skill_manifest,
)

BUILTIN_ECHO_PLUGIN_ID = "com.nachuan.provider.echo"
ECHO_FACTORY_SERVICE = "provider.factory.echo"
BUILTIN_SKILL_BUNDLE_PLUGIN_ID = "com.nachuan.skill-bundle.reviewed"
BUILTIN_LIST_SKILLS_PLUGIN_ID = "com.nachuan.tool.list-skills"
SKILL_BUNDLE_SERVICE = "skill.bundle.reviewed"

BUILTIN_ECHO_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_ECHO_PLUGIN_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "provider",
        "capabilities": ["provider.factory.echo"],
        "artifact_sha256": "b01075be8817f6511740edd948d43816913fd5b6f5036ff15833671386a2eece",
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)

BUILTIN_SKILL_BUNDLE_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_SKILL_BUNDLE_PLUGIN_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "skill_bundle",
        "capabilities": ["skill.bundle.provide"],
        "artifact_sha256": EXPECTED_MANIFEST_SHA256,
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)

BUILTIN_LIST_SKILLS_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_LIST_SKILLS_PLUGIN_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "tool",
        "capabilities": [
            "skill.bundle.read",
            "tool.execute:list_skills",
            "tool.execute:load_skill",
        ],
        "artifact_sha256": "6c1906b0d2b092891dedce8d6bf04fd1c544d70b8a0839b9002ff800137fb1ac",
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)

ProviderFactory = Callable[[str, Mapping[str, Any]], ChatProvider | None]


def provider_factory_service(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().casefold()
    return f"provider.factory.{normalized}"


def build_builtin_provider_kernel() -> PluginKernel:
    kernel = PluginKernel()
    kernel.services.define(ServiceDefinition(ECHO_FACTORY_SERVICE, "1"))
    kernel.services.define(ServiceDefinition(SKILL_BUNDLE_SERVICE, "1"))

    def apply(ctx) -> None:
        def create_echo(name: str, _conn: Mapping[str, Any]) -> ChatProvider:
            return EchoProvider(name=name)

        ctx.provide_service(ECHO_FACTORY_SERVICE, create_echo)

    kernel.mount(BUILTIN_ECHO_MANIFEST, apply)

    skill_bundle = build_reviewed_skill_bundle()
    if skill_bundle is None:
        return kernel

    kernel.mount(
        BUILTIN_SKILL_BUNDLE_MANIFEST,
        lambda ctx: ctx.provide_service(SKILL_BUNDLE_SERVICE, skill_bundle),
    )

    def apply_list_skills(ctx) -> None:
        reviewed = ctx.borrow_service(SKILL_BUNDLE_SERVICE, "skill.bundle.read")
        if not isinstance(reviewed, SkillBundleV1):
            raise TypeError("reviewed skill bundle service is invalid")
        ctx.register_tool(
            LIST_SKILLS_TOOL_DEFINITION,
            lambda _arguments: render_skill_manifest(reviewed),
        )
        ctx.register_tool(
            LOAD_SKILL_TOOL_DEFINITION,
            lambda arguments: render_skill_content(
                reviewed, str(arguments.get("name") or "")
            ),
        )

    kernel.mount(BUILTIN_LIST_SKILLS_MANIFEST, apply_list_skills)
    return kernel


__all__ = [
    "BUILTIN_ECHO_MANIFEST",
    "BUILTIN_ECHO_PLUGIN_ID",
    "BUILTIN_LIST_SKILLS_MANIFEST",
    "BUILTIN_LIST_SKILLS_PLUGIN_ID",
    "BUILTIN_SKILL_BUNDLE_MANIFEST",
    "BUILTIN_SKILL_BUNDLE_PLUGIN_ID",
    "ECHO_FACTORY_SERVICE",
    "SKILL_BUNDLE_SERVICE",
    "ProviderFactory",
    "build_builtin_provider_kernel",
    "provider_factory_service",
]
