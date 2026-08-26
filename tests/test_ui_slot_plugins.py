from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from gateway.app import _public_fastapi_app
from gateway.provider_plugins import build_builtin_provider_kernel
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    PluginMountError,
    UiSlotContractError,
    UiSlotDefinition,
)
from orchestrator.ui_plugins import (
    BUILTIN_ORCHESTRATION_UI_MANIFEST,
    UI_SLOT_CATALOG_PATH,
    UI_SLOT_CATALOG_SHA256,
    load_builtin_ui_slots,
)


def _manifest(plugin_id: str, capabilities: list[str]) -> PluginManifestV1:
    return PluginManifestV1.from_mapping(
        {
            "schema": "nachuan.plugin.v1",
            "id": plugin_id,
            "version": "1.0.0",
            "api_version": "1",
            "kind": "ui",
            "capabilities": capabilities,
            "artifact_sha256": "c" * 64,
            "execution": "in_process",
            "trust": "builtin",
            "publisher": "nachuan-tests",
        }
    )


def _slot() -> UiSlotDefinition:
    return UiSlotDefinition(
        slot_id="workspace.orchestration",
        surface="workspace.menu",
        component="orchestrate",
        order=600,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"slot_id": "BAD SLOT"},
        {"surface": "window.unrestricted"},
        {"component": "remote-script"},
        {"order": True},
        {"order": 10_001},
    ],
)
def test_ui_slot_definition_is_a_closed_renderer_allowlist(overrides) -> None:
    values = {
        "slot_id": "workspace.orchestration",
        "surface": "workspace.menu",
        "component": "orchestrate",
        "order": 600,
        **overrides,
    }
    with pytest.raises(UiSlotContractError):
        UiSlotDefinition(**values)


def test_ui_slot_registration_requires_exact_capability_and_rolls_back() -> None:
    kernel = PluginKernel()
    with pytest.raises(PluginMountError):
        kernel.mount(
            _manifest("com.nachuan.test.ui-denied", ["ui.slot:workspace.other"]),
            lambda ctx: ctx.register_ui_slot(_slot()),
        )
    assert kernel.ui_slot_snapshot() == ()


@pytest.mark.asyncio
async def test_ui_slot_snapshot_is_declarative_and_revoked_on_unmount() -> None:
    kernel = PluginKernel()
    manifest = _manifest(
        "com.nachuan.test.ui-slot", ["ui.slot:workspace.orchestration"]
    )
    kernel.mount(manifest, lambda ctx: ctx.register_ui_slot(_slot()))
    assert kernel.ui_slot_snapshot() == (
        {
            "slot_id": "workspace.orchestration",
            "surface": "workspace.menu",
            "component": "orchestrate",
            "order": 600,
            "plugin_id": manifest.plugin_id,
            "plugin_version": manifest.version,
            "artifact_sha256": manifest.artifact_sha256,
        },
    )
    serialized = json.dumps(kernel.ui_slot_snapshot(), sort_keys=True)
    for forbidden in ("<script", "http://", "https://", "javascript:", "html"):
        assert forbidden not in serialized.casefold()

    await kernel.unmount(manifest.plugin_id)
    assert kernel.ui_slot_snapshot() == ()


def test_second_provider_cannot_shadow_existing_surface_component() -> None:
    kernel = PluginKernel()
    first = _manifest(
        "com.nachuan.test.ui-first", ["ui.slot:workspace.orchestration"]
    )
    second = _manifest(
        "com.nachuan.test.ui-second", ["ui.slot:workspace.orchestration-alt"]
    )
    kernel.mount(first, lambda ctx: ctx.register_ui_slot(_slot()))
    conflicting = UiSlotDefinition(
        slot_id="workspace.orchestration-alt",
        surface="workspace.menu",
        component="orchestrate",
        order=601,
    )
    with pytest.raises(PluginMountError):
        kernel.mount(second, lambda ctx: ctx.register_ui_slot(conflicting))
    assert [item["plugin_id"] for item in kernel.ui_slot_snapshot()] == [
        first.plugin_id
    ]


def test_builtin_ui_plugin_is_bound_to_exact_catalog_bytes() -> None:
    payload = UI_SLOT_CATALOG_PATH.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == UI_SLOT_CATALOG_SHA256
    assert BUILTIN_ORCHESTRATION_UI_MANIFEST.artifact_sha256 == (
        UI_SLOT_CATALOG_SHA256
    )
    assert load_builtin_ui_slots() == (_slot(),)


@pytest.mark.asyncio
async def test_builtin_kernel_mounts_and_closes_ui_slot_plugin() -> None:
    kernel = build_builtin_provider_kernel()
    assert BUILTIN_ORCHESTRATION_UI_MANIFEST.plugin_id in kernel.active_plugin_ids()
    assert kernel.ui_slot_snapshot()[0]["slot_id"] == "workspace.orchestration"
    await kernel.aclose()
    assert kernel.ui_slot_snapshot() == ()


def test_public_plugin_ui_snapshot_projects_only_closed_slot_metadata() -> None:
    with TestClient(_public_fastapi_app) as client:
        response = client.get(
            "/v1/plugin-ui/snapshot",
            headers={"Authorization": "Bearer test-key"},
        )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "schema": "nachuan.plugin-ui.snapshot.v1",
        "slots": [
            {
                "slot_id": "workspace.orchestration",
                "surface": "workspace.menu",
                "component": "orchestrate",
                "order": 600,
                "plugin_id": BUILTIN_ORCHESTRATION_UI_MANIFEST.plugin_id,
                "plugin_version": BUILTIN_ORCHESTRATION_UI_MANIFEST.version,
                "artifact_sha256": BUILTIN_ORCHESTRATION_UI_MANIFEST.artifact_sha256,
            }
        ],
    }
    assert "/internal/v1/desktop/session/plugin-ui-snapshot" not in (
        _public_fastapi_app.openapi()["paths"]
    )
