"""Built-in model-provider capability plugins.

Only the no-network Echo provider is migrated in PK-002.  Existing providers
remain on the legacy constructor path until each one receives its own manifest,
capability contract, and lifecycle acceptance.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from gateway.providers.base import ChatProvider
from gateway.providers.echo import EchoProvider
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    ServiceDefinition,
)


BUILTIN_ECHO_PLUGIN_ID = "com.nachuan.provider.echo"
ECHO_FACTORY_SERVICE = "provider.factory.echo"

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

ProviderFactory = Callable[[str, Mapping[str, Any]], ChatProvider | None]


def provider_factory_service(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().casefold()
    return f"provider.factory.{normalized}"


def build_builtin_provider_kernel() -> PluginKernel:
    kernel = PluginKernel()
    kernel.services.define(ServiceDefinition(ECHO_FACTORY_SERVICE, "1"))

    def apply(ctx) -> None:
        def create_echo(name: str, _conn: Mapping[str, Any]) -> ChatProvider:
            return EchoProvider(name=name)

        ctx.provide_service(ECHO_FACTORY_SERVICE, create_echo)

    kernel.mount(BUILTIN_ECHO_MANIFEST, apply)
    return kernel


__all__ = [
    "BUILTIN_ECHO_MANIFEST",
    "BUILTIN_ECHO_PLUGIN_ID",
    "ECHO_FACTORY_SERVICE",
    "ProviderFactory",
    "build_builtin_provider_kernel",
    "provider_factory_service",
]
