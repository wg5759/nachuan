"""Trusted adapter from SDK bridge plans to the isolated plugin proxy.

The host validates every plan and projection as data.  It never imports an
OpenClaw/Cordis module or mounts worker-returned tools, services, hooks, routes,
commands, MCP servers, or UI components.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from nachuan_sdk.bridges import (
    BridgeContractError,
    EcosystemBridgePlanV1,
    canonical_json,
)
from orchestrator.isolated_plugin import IsolatedPluginContractError
from orchestrator.isolated_plugin_proxy import (
    ISOLATED_PLUGIN_SERVICE,
    IsolatedPluginProxyService,
)
from orchestrator.plugin_kernel import PluginKernel, PluginManifestV1, ServiceDefinition

BUILTIN_ECOSYSTEM_BRIDGE_ID = "com.nachuan.ecosystem-bridge"
ECOSYSTEM_BRIDGE_SERVICE = "ecosystem.bridge.project"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIAGNOSTIC = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CONTRACT_DIGEST = hashlib.sha256(
    b"nachuan.ecosystem-bridge.v1\0ecosystem.bridge.project.v1"
).hexdigest()

BUILTIN_ECOSYSTEM_BRIDGE_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_ECOSYSTEM_BRIDGE_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "compatibility",
        "capabilities": ["isolated.plugin.execute"],
        "artifact_sha256": _CONTRACT_DIGEST,
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)


@dataclass(frozen=True, slots=True)
class EcosystemBridgeInvocationV1:
    plugin_id: str
    version: str
    artifact_sha256: str
    plan: EcosystemBridgePlanV1
    schema: str = "nachuan.ecosystem-bridge-invocation.v1"

    @classmethod
    def from_mapping(cls, value: object) -> "EcosystemBridgeInvocationV1":
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "plugin_id",
            "version",
            "artifact_sha256",
            "plan",
        }:
            raise BridgeContractError("ecosystem bridge invocation is not closed")
        if value.get("schema") != "nachuan.ecosystem-bridge-invocation.v1":
            raise BridgeContractError("ecosystem bridge invocation schema is unsupported")
        plugin_id = value.get("plugin_id")
        version = value.get("version")
        artifact = value.get("artifact_sha256")
        if (
            not isinstance(plugin_id, str)
            or not 3 <= len(plugin_id) <= 128
            or not isinstance(version, str)
            or not 1 <= len(version) <= 64
            or not isinstance(artifact, str)
            or _SHA256.fullmatch(artifact) is None
        ):
            raise BridgeContractError("ecosystem bridge worker identity is invalid")
        return cls(
            plugin_id=plugin_id,
            version=version,
            artifact_sha256=artifact,
            plan=EcosystemBridgePlanV1.from_mapping(value.get("plan")),
        )


class EcosystemBridgeRuntime:
    def __init__(self, proxy: IsolatedPluginProxyService) -> None:
        if not isinstance(proxy, IsolatedPluginProxyService):
            raise TypeError("isolated plugin proxy is invalid")
        self._proxy = proxy

    def project(self, value: Mapping[str, object]) -> dict[str, object]:
        invocation = EcosystemBridgeInvocationV1.from_mapping(value)
        plan = invocation.plan
        worker_input = {
            "schema": "nachuan.ecosystem-bridge-worker-input.v1",
            "operation": "project",
            "plan_sha256": plan.sha256,
            "plan": plan.as_mapping(),
        }
        if len(canonical_json(worker_input)) > 64 * 1024:
            raise BridgeContractError("ecosystem bridge worker input is too large")
        result = self._proxy.execute_validated(
            {
                "plugin_id": invocation.plugin_id,
                "version": invocation.version,
                "artifact_sha256": invocation.artifact_sha256,
                "input": worker_input,
            },
            lambda output: self._validate_result(output, plan),
        )
        if not isinstance(result, dict):
            raise IsolatedPluginContractError("ecosystem bridge result is invalid")
        return result

    @staticmethod
    def _validate_result(
        value: object,
        plan: EcosystemBridgePlanV1,
    ) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "plan_sha256",
            "accepted",
            "diagnostics",
            "projection",
        }:
            raise IsolatedPluginContractError("ecosystem bridge result is not closed")
        if value.get("schema") != "nachuan.ecosystem-bridge-worker-result.v1":
            raise IsolatedPluginContractError("ecosystem bridge result schema is unsupported")
        if value.get("plan_sha256") != plan.sha256:
            raise IsolatedPluginContractError("ecosystem bridge result plan digest drifted")
        accepted = value.get("accepted")
        diagnostics = value.get("diagnostics")
        projection = value.get("projection")
        if (
            not isinstance(accepted, bool)
            or not isinstance(diagnostics, list)
            or len(diagnostics) > 32
            or any(not isinstance(item, str) or _DIAGNOSTIC.fullmatch(item) is None for item in diagnostics)
            or len(set(diagnostics)) != len(diagnostics)
        ):
            raise IsolatedPluginContractError("ecosystem bridge result diagnostics are invalid")
        expected_ids = [item.component_id for item in plan.components]
        if not accepted:
            if projection is not None or not diagnostics:
                raise IsolatedPluginContractError("rejected ecosystem projection is invalid")
            return {
                "schema": "nachuan.ecosystem-bridge-result.v1",
                "plan_sha256": plan.sha256,
                "accepted": False,
                "diagnostics": list(diagnostics),
                "projection": None,
            }
        if not isinstance(projection, Mapping) or set(projection) != {
            "schema",
            "ecosystem",
            "component_ids",
        }:
            raise IsolatedPluginContractError("ecosystem bridge projection is not closed")
        if (
            projection.get("schema") != "nachuan.ecosystem-projection.v1"
            or projection.get("ecosystem") != plan.source.ecosystem
            or projection.get("component_ids") != expected_ids
        ):
            raise IsolatedPluginContractError("ecosystem bridge projection drifted")
        normalized = {
            "schema": "nachuan.ecosystem-bridge-result.v1",
            "plan_sha256": plan.sha256,
            "accepted": True,
            "diagnostics": list(diagnostics),
            "projection": {
                "schema": "nachuan.ecosystem-projection.v1",
                "ecosystem": plan.source.ecosystem,
                "component_ids": expected_ids,
            },
        }
        if len(canonical_json(normalized)) > 64 * 1024:
            raise IsolatedPluginContractError("ecosystem bridge result is too large")
        return normalized


def mount_ecosystem_bridge(kernel: PluginKernel) -> None:
    kernel.services.define(ServiceDefinition(ECOSYSTEM_BRIDGE_SERVICE, "1"))

    def apply(ctx) -> None:
        proxy = ctx.borrow_service(ISOLATED_PLUGIN_SERVICE, "isolated.plugin.execute")
        if not isinstance(proxy, IsolatedPluginProxyService):
            raise TypeError("isolated plugin proxy service is invalid")
        ctx.provide_service(ECOSYSTEM_BRIDGE_SERVICE, EcosystemBridgeRuntime(proxy))

    kernel.mount(BUILTIN_ECOSYSTEM_BRIDGE_MANIFEST, apply)


__all__ = [
    "BUILTIN_ECOSYSTEM_BRIDGE_ID",
    "BUILTIN_ECOSYSTEM_BRIDGE_MANIFEST",
    "ECOSYSTEM_BRIDGE_SERVICE",
    "EcosystemBridgeInvocationV1",
    "EcosystemBridgeRuntime",
    "mount_ecosystem_bridge",
]
