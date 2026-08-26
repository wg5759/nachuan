from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nachuan_sdk import (
    IsolatedTransformPluginSpecV1,
    UpstreamSourcePinV1,
    build_deepseek_harness_bridge_plan,
    build_openclaw_bridge_plan,
    build_signed_transform_bundle,
    default_isolated_limits,
)
from nachuan_sdk.bridges import BridgeContractError
from orchestrator.ecosystem_bridge import (
    BUILTIN_ECOSYSTEM_BRIDGE_ID,
    ECOSYSTEM_BRIDGE_SERVICE,
    mount_ecosystem_bridge,
)
from orchestrator.isolated_plugin import (
    IsolatedPluginBroker,
    IsolatedPluginContractError,
    IsolatedPluginQuarantined,
)
from orchestrator.isolated_plugin_proxy import (
    BUILTIN_ISOLATED_PLUGIN_PROXY_ID,
    mount_isolated_plugin_proxy,
)
from orchestrator.plugin_kernel import (
    PluginInUseError,
    PluginKernel,
    PluginMountError,
)
from gateway.app import _plugin_ecosystem_readiness
from gateway.provider_plugins import build_builtin_provider_kernel

DEEPSEEK_HEAD = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e"
OPENCLAW_HEAD = "6f0395ec79f9eefe51575486279f44e595aeee2b"


def _deepseek_pin() -> UpstreamSourcePinV1:
    return UpstreamSourcePinV1(
        ecosystem="deepseek_harness",
        repository="deepseek-ai/deepseek-harness",
        commit=DEEPSEEK_HEAD,
    )


def _openclaw_pin() -> UpstreamSourcePinV1:
    return UpstreamSourcePinV1(
        ecosystem="openclaw",
        repository="openclaw/openclaw",
        commit=OPENCLAW_HEAD,
    )


def test_deepseek_bridge_projects_pinned_cordis_composition_without_code() -> None:
    plan = build_deepseek_harness_bridge_plan(
        b"- name: './greeter.ts'\n  config:\n    locale: en\n- name: '@scope/consumer'\n",
        source=_deepseek_pin(),
    )

    assert plan.source.commit == DEEPSEEK_HEAD
    assert [item.component_id for item in plan.components] == [
        "./greeter.ts",
        "@scope/consumer",
    ]
    assert all(item.kind == "cordis_plugin" for item in plan.components)
    assert plan.execution == "isolated_worker_only"
    assert plan.host_import_allowed is False
    assert "cordis-host-module-apply" in plan.unsupported_features
    assert "locale" not in json.dumps(plan.as_mapping())


@pytest.mark.parametrize(
    "payload",
    [
        b"- &entry {name: './one.ts'}\n- *entry\n",
        b"- name: !!python/object:dangerous {}\n",
        b"- name: '../escape.ts'\n",
        b"- name: './same.ts'\n- name: './same.ts'\n",
        b"- name: './one.ts'\n  entrypoint: './one.ts'\n",
    ],
)
def test_deepseek_bridge_rejects_alias_tags_escape_duplicates_and_open_fields(payload) -> None:
    with pytest.raises(BridgeContractError):
        build_deepseek_harness_bridge_plan(payload, source=_deepseek_pin())


def test_openclaw_bridge_hashes_native_manifest_and_skill_without_mounting_content() -> None:
    manifest = json.dumps(
        {
            "id": "demo-plugin",
            "name": "Demo",
            "description": "data projection only",
            "version": "1.0.0",
            "requiresPlugins": ["memory-core"],
            "providers": ["demo"],
            "configSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "hooks": ["before-agent-start"],
        },
        indent=2,
    ).encode()
    skill = b"---\nname: demo\n---\n# Never mounted into the host prompt\n"

    plan = build_openclaw_bridge_plan(
        manifest,
        skills={"skills/demo/SKILL.md": skill},
        source=_openclaw_pin(),
    )

    assert [item.kind for item in plan.components] == [
        "openclaw_plugin",
        "openclaw_skill",
    ]
    assert plan.components[1].source_sha256 not in {"", plan.components[0].source_sha256}
    assert "openclaw-manifest-field:hooks" in plan.unsupported_features
    assert "openclaw-native-runtime" in plan.unsupported_features
    encoded = json.dumps(plan.as_mapping(), sort_keys=True)
    assert "Never mounted" not in encoded
    assert "before-agent-start" not in encoded


def test_openclaw_bridge_rejects_duplicate_fields_bad_skill_paths_and_floating_pins() -> None:
    duplicate = b'{"id":"one","id":"two","configSchema":{}}'
    with pytest.raises(BridgeContractError, match="JSON"):
        build_openclaw_bridge_plan(duplicate, skills={}, source=_openclaw_pin())
    with pytest.raises(BridgeContractError, match="skill"):
        build_openclaw_bridge_plan(
            b'{"id":"one","configSchema":{}}',
            skills={"skills/one/nested/SKILL.md": b"# bad"},
            source=_openclaw_pin(),
        )
    with pytest.raises(BridgeContractError, match="commit"):
        UpstreamSourcePinV1(
            ecosystem="openclaw",
            repository="openclaw/openclaw",
            commit="main",
        )


def _bundle(tmp_path):
    private = Ed25519PrivateKey.generate()
    root = tmp_path / "bridge-worker"
    receipt = build_signed_transform_bundle(
        root,
        spec=IsolatedTransformPluginSpecV1(
            plugin_id="com.example.bridge-worker",
            version="1.0.0",
            publisher_key_id="example.publisher",
            license="Apache-2.0",
            limits=default_isolated_limits(),
        ),
        plugin_source=b"def handle(value):\n    return value\n",
        private_key=private,
    )
    return root, private.public_key().public_bytes_raw(), receipt


class _ProjectionLauncher:
    def __init__(self, mutate=None) -> None:
        self.calls = 0
        self.mutate = mutate

    def execute(self, _bundle, request_json: bytes) -> bytes:
        self.calls += 1
        request = json.loads(request_json)
        plan = request["input"]["plan"]
        output = {
            "schema": "nachuan.ecosystem-bridge-worker-result.v1",
            "plan_sha256": request["input"]["plan_sha256"],
            "accepted": True,
            "diagnostics": [],
            "projection": {
                "schema": "nachuan.ecosystem-projection.v1",
                "ecosystem": plan["source"]["ecosystem"],
                "component_ids": [item["id"] for item in plan["components"]],
            },
        }
        if self.mutate is not None:
            self.mutate(output)
        return json.dumps(
            {
                "schema": "nachuan.isolated-plugin.result.v1",
                "ok": True,
                "output": output,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def _invocation(receipt, plan):
    return {
        "schema": "nachuan.ecosystem-bridge-invocation.v1",
        "plugin_id": receipt.plugin_id,
        "version": receipt.version,
        "artifact_sha256": receipt.artifact_sha256,
        "plan": plan.as_mapping(),
    }


@pytest.mark.asyncio
async def test_bridge_runtime_holds_proxy_dependency_and_returns_only_closed_projection(tmp_path) -> None:
    root, public, receipt = _bundle(tmp_path)
    launcher = _ProjectionLauncher()
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(launcher),
        bundle_roots=[root],
        trusted_publishers={"example.publisher": public},
    )
    mount_ecosystem_bridge(kernel)
    plan = build_openclaw_bridge_plan(
        b'{"id":"demo","configSchema":{"type":"object"}}',
        skills={},
        source=_openclaw_pin(),
    )

    lease = kernel.borrow_service(ECOSYSTEM_BRIDGE_SERVICE)
    try:
        result = lease.value.project(_invocation(receipt, plan))
        assert result == {
            "schema": "nachuan.ecosystem-bridge-result.v1",
            "plan_sha256": plan.sha256,
            "accepted": True,
            "diagnostics": [],
            "projection": {
                "schema": "nachuan.ecosystem-projection.v1",
                "ecosystem": "openclaw",
                "component_ids": ["demo"],
            },
        }
        with pytest.raises(PluginInUseError):
            await kernel.unmount(BUILTIN_ISOLATED_PLUGIN_PROXY_ID)
    finally:
        lease.release()
    await kernel.unmount(BUILTIN_ECOSYSTEM_BRIDGE_ID)
    await kernel.unmount(BUILTIN_ISOLATED_PLUGIN_PROXY_ID)
    assert launcher.calls == 1


def test_bridge_mount_fails_closed_without_isolated_proxy() -> None:
    kernel = PluginKernel()
    with pytest.raises(PluginMountError):
        mount_ecosystem_bridge(kernel)
    assert kernel.active_plugin_ids() == ()
    assert kernel.services.has_provider(ECOSYSTEM_BRIDGE_SERVICE) is False


def test_worker_cannot_inject_extra_projection_fields(tmp_path) -> None:
    root, public, receipt = _bundle(tmp_path)
    launcher = _ProjectionLauncher(lambda output: output["projection"].update({"code": "run()"}))
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(launcher),
        bundle_roots=[root],
        trusted_publishers={"example.publisher": public},
    )
    mount_ecosystem_bridge(kernel)
    plan = build_deepseek_harness_bridge_plan(
        b"- name: './hello.ts'\n",
        source=_deepseek_pin(),
    )
    lease = kernel.borrow_service(ECOSYSTEM_BRIDGE_SERVICE)
    try:
        with pytest.raises(IsolatedPluginContractError, match="projection"):
            lease.value.project(_invocation(receipt, plan))
        with pytest.raises(IsolatedPluginQuarantined):
            lease.value.project(_invocation(receipt, plan))
    finally:
        lease.release()
    assert launcher.calls == 1


def test_worker_identity_drift_is_rejected_before_launch(tmp_path) -> None:
    root, public, receipt = _bundle(tmp_path)
    launcher = _ProjectionLauncher()
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(launcher),
        bundle_roots=[root],
        trusted_publishers={"example.publisher": public},
    )
    mount_ecosystem_bridge(kernel)
    plan = build_openclaw_bridge_plan(
        b'{"id":"demo","configSchema":{}}',
        skills={},
        source=_openclaw_pin(),
    )
    bad = _invocation(receipt, plan)
    bad["version"] = "1.0.1"
    lease = kernel.borrow_service(ECOSYSTEM_BRIDGE_SERVICE)
    try:
        with pytest.raises(IsolatedPluginContractError, match="identity"):
            lease.value.project(bad)
    finally:
        lease.release()
    assert launcher.calls == 0


def test_default_health_reports_sdk_but_keeps_marketplace_and_runtime_closed() -> None:
    class Router:
        plugin_kernel = build_builtin_provider_kernel()

    snapshot = _plugin_ecosystem_readiness(Router())
    assert snapshot == {
        "schema": "nachuan.plugin-ecosystem-readiness.v1",
        "sdk_api_version": "1",
        "bridges": {
            "deepseek_harness": "projection_only",
            "openclaw": "projection_only",
        },
        "isolated_proxy_ready": False,
        "bridge_runtime_ready": False,
        "marketplace_enabled": False,
        "production_ready": False,
    }


def test_health_reports_runtime_only_after_proxy_and_bridge_mount(tmp_path) -> None:
    root, public, _receipt = _bundle(tmp_path)
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(_ProjectionLauncher()),
        bundle_roots=[root],
        trusted_publishers={"example.publisher": public},
    )
    mount_ecosystem_bridge(kernel)

    class Router:
        plugin_kernel = kernel

    snapshot = _plugin_ecosystem_readiness(Router())
    assert snapshot["isolated_proxy_ready"] is True
    assert snapshot["bridge_runtime_ready"] is True
    assert snapshot["marketplace_enabled"] is False
    assert snapshot["production_ready"] is False
