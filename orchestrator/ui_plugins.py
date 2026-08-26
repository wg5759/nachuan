"""Built-in declarative UI slots for the Host/Main/Renderer boundary."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from gateway.config import PROJECT_ROOT
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    UiSlotContractError,
    UiSlotDefinition,
)

BUILTIN_ORCHESTRATION_UI_PLUGIN_ID = "com.nachuan.ui.orchestration"
UI_SLOT_CATALOG_PATH = PROJECT_ROOT / "config" / "ui-slots.v1.json"
UI_SLOT_CATALOG_SHA256 = (
    "8d258c8a84f3b707c51128117f9b2532c1c0519ecde94e1677c9141f08cd0a1f"
)
_MAX_CATALOG_BYTES = 16 * 1024

BUILTIN_ORCHESTRATION_UI_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_ORCHESTRATION_UI_PLUGIN_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "ui",
        "capabilities": ["ui.slot:workspace.orchestration"],
        "artifact_sha256": UI_SLOT_CATALOG_SHA256,
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)


def _regular_non_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse = int(getattr(info, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not reparse
        and int(getattr(info, "st_nlink", 1)) == 1
    )


def _directory_non_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse = int(getattr(info, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not reparse


def load_builtin_ui_slots() -> tuple[UiSlotDefinition, ...]:
    path = Path(os.path.abspath(os.fspath(UI_SLOT_CATALOG_PATH)))
    project_root = Path(os.path.abspath(os.fspath(PROJECT_ROOT)))
    if (
        path.parent != project_root / "config"
        or not _directory_non_reparse(project_root)
        or not _directory_non_reparse(path.parent)
        or not _regular_non_reparse(path)
    ):
        raise UiSlotContractError("built-in UI slot catalog is unavailable")
    payload = path.read_bytes()
    if (
        not payload
        or len(payload) > _MAX_CATALOG_BYTES
        or hashlib.sha256(payload).hexdigest() != UI_SLOT_CATALOG_SHA256
    ):
        raise UiSlotContractError("built-in UI slot catalog digest does not match")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UiSlotContractError("built-in UI slot catalog is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "slots"}:
        raise UiSlotContractError("built-in UI slot catalog is not closed")
    slots = value.get("slots")
    if value.get("schema") != "nachuan.ui-slot-catalog.v1" or not isinstance(
        slots, list
    ):
        raise UiSlotContractError("built-in UI slot catalog is invalid")
    if not 1 <= len(slots) <= 64:
        raise UiSlotContractError("built-in UI slot catalog size is invalid")
    definitions: list[UiSlotDefinition] = []
    for raw in slots:
        if not isinstance(raw, dict) or set(raw) != {
            "slot_id",
            "surface",
            "component",
            "order",
        }:
            raise UiSlotContractError("built-in UI slot entry is not closed")
        slot_id = raw.get("slot_id")
        surface = raw.get("surface")
        component = raw.get("component")
        order = raw.get("order")
        if (
            not isinstance(slot_id, str)
            or not isinstance(surface, str)
            or not isinstance(component, str)
            or isinstance(order, bool)
            or not isinstance(order, int)
        ):
            raise UiSlotContractError("built-in UI slot entry is invalid")
        definitions.append(
            UiSlotDefinition(
                slot_id=slot_id,
                surface=surface,
                component=component,
                order=order,
            )
        )
    if len({item.slot_id for item in definitions}) != len(definitions):
        raise UiSlotContractError("built-in UI slot catalog has duplicates")
    return tuple(definitions)


def mount_builtin_ui_plugins(kernel: PluginKernel) -> None:
    definitions = load_builtin_ui_slots()

    def apply(ctx) -> None:
        for definition in definitions:
            ctx.register_ui_slot(definition)

    kernel.mount(BUILTIN_ORCHESTRATION_UI_MANIFEST, apply)


__all__ = [
    "BUILTIN_ORCHESTRATION_UI_MANIFEST",
    "BUILTIN_ORCHESTRATION_UI_PLUGIN_ID",
    "UI_SLOT_CATALOG_PATH",
    "UI_SLOT_CATALOG_SHA256",
    "load_builtin_ui_slots",
    "mount_builtin_ui_plugins",
]
