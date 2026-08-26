"""Data-only compatibility projections for pinned external plugin ecosystems.

These parsers never import upstream modules, launch MCP servers, register hooks,
or expose skill text to the host.  They produce content-addressed plans that a
separately signed Nachuan isolated worker may inspect.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import yaml
from yaml.events import AliasEvent, CollectionStartEvent, ScalarEvent

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_OPENCLAW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
_CORDIS_NAME = re.compile(r"^(?:\./)?[A-Za-z0-9@][A-Za-z0-9@._/-]{0,254}$")
_SKILL_PATH = re.compile(r"^skills/([a-z0-9][a-z0-9._-]{1,63})/SKILL\.md$")
_MAX_SOURCE_BYTES = 256 * 1024
_MAX_SKILL_BYTES = 128 * 1024
_MAX_COMPONENTS = 128
_OFFICIAL_REPOSITORIES = {
    "deepseek_harness": "deepseek-ai/deepseek-harness",
    "openclaw": "openclaw/openclaw",
}


class BridgeContractError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BridgeContractError("bridge value is not bounded JSON") from exc


def _parse_json(payload: bytes, label: str) -> object:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_SOURCE_BYTES:
        raise BridgeContractError(f"{label} size is invalid")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise BridgeContractError(f"{label} JSON is invalid") from exc
    canonical_json(value)
    return value


def _bounded_json(value: object, label: str, maximum: int = 64 * 1024) -> bytes:
    encoded = canonical_json(value)
    if len(encoded) > maximum:
        raise BridgeContractError(f"{label} is too large")
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > 16 or nodes > 8_192:
            raise BridgeContractError(f"{label} is too complex")
        if isinstance(current, Mapping):
            if any(not isinstance(key, str) for key in current):
                raise BridgeContractError(f"{label} has a non-string key")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif not isinstance(current, (str, int, float, bool, type(None))):
            raise BridgeContractError(f"{label} contains a non-JSON value")
    return encoded


@dataclass(frozen=True, slots=True)
class UpstreamSourcePinV1:
    ecosystem: Literal["deepseek_harness", "openclaw"]
    repository: str
    commit: str
    schema: str = "nachuan.upstream-source-pin.v1"

    def __post_init__(self) -> None:
        expected = _OFFICIAL_REPOSITORIES.get(str(self.ecosystem))
        if expected is None or self.repository != expected:
            raise BridgeContractError("upstream repository is not the official pinned source")
        if not isinstance(self.commit, str) or _COMMIT.fullmatch(self.commit) is None:
            raise BridgeContractError("upstream commit must be an exact lowercase SHA-1")

    @classmethod
    def from_mapping(cls, value: object) -> "UpstreamSourcePinV1":
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "ecosystem",
            "repository",
            "commit",
        }:
            raise BridgeContractError("upstream source pin is not closed")
        if value.get("schema") != "nachuan.upstream-source-pin.v1":
            raise BridgeContractError("upstream source pin schema is unsupported")
        return cls(
            ecosystem=value.get("ecosystem"),  # type: ignore[arg-type]
            repository=value.get("repository"),  # type: ignore[arg-type]
            commit=value.get("commit"),  # type: ignore[arg-type]
        )

    def as_mapping(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "ecosystem": self.ecosystem,
            "repository": self.repository,
            "commit": self.commit,
        }


@dataclass(frozen=True, slots=True)
class BridgeComponentV1:
    component_id: str
    kind: Literal["cordis_plugin", "openclaw_plugin", "openclaw_skill"]
    source_sha256: str
    metadata_sha256: str
    requires: tuple[str, ...] = ()
    schema: str = "nachuan.ecosystem-bridge-component.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.component_id, str)
            or not 1 <= len(self.component_id) <= 256
            or any(ord(char) < 32 for char in self.component_id)
        ):
            raise BridgeContractError("bridge component id is invalid")
        if self.kind not in {"cordis_plugin", "openclaw_plugin", "openclaw_skill"}:
            raise BridgeContractError("bridge component kind is invalid")
        if _SHA256.fullmatch(self.source_sha256) is None or _SHA256.fullmatch(
            self.metadata_sha256
        ) is None:
            raise BridgeContractError("bridge component digest is invalid")
        if (
            len(self.requires) > 64
            or len(set(self.requires)) != len(self.requires)
            or any(
                not isinstance(item, str)
                or not 1 <= len(item) <= 128
                or any(ord(char) < 32 for char in item)
                for item in self.requires
            )
        ):
            raise BridgeContractError("bridge component dependencies are invalid")

    @classmethod
    def from_mapping(cls, value: object) -> "BridgeComponentV1":
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "id",
            "kind",
            "source_sha256",
            "metadata_sha256",
            "requires",
        }:
            raise BridgeContractError("bridge component is not closed")
        if value.get("schema") != "nachuan.ecosystem-bridge-component.v1":
            raise BridgeContractError("bridge component schema is unsupported")
        requires = value.get("requires")
        if not isinstance(requires, list) or any(not isinstance(item, str) for item in requires):
            raise BridgeContractError("bridge component dependencies are invalid")
        return cls(
            component_id=value.get("id"),  # type: ignore[arg-type]
            kind=value.get("kind"),  # type: ignore[arg-type]
            source_sha256=value.get("source_sha256"),  # type: ignore[arg-type]
            metadata_sha256=value.get("metadata_sha256"),  # type: ignore[arg-type]
            requires=tuple(requires),
        )

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "id": self.component_id,
            "kind": self.kind,
            "source_sha256": self.source_sha256,
            "metadata_sha256": self.metadata_sha256,
            "requires": list(self.requires),
        }


@dataclass(frozen=True, slots=True)
class EcosystemBridgePlanV1:
    source: UpstreamSourcePinV1
    source_sha256: str
    components: tuple[BridgeComponentV1, ...]
    unsupported_features: tuple[str, ...]
    schema: str = "nachuan.ecosystem-bridge-plan.v1"
    execution: str = "isolated_worker_only"
    host_import_allowed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.source, UpstreamSourcePinV1):
            raise BridgeContractError("bridge source pin is invalid")
        if _SHA256.fullmatch(self.source_sha256) is None:
            raise BridgeContractError("bridge source digest is invalid")
        if (
            not 1 <= len(self.components) <= _MAX_COMPONENTS
            or any(not isinstance(item, BridgeComponentV1) for item in self.components)
            or len({item.component_id for item in self.components}) != len(self.components)
        ):
            raise BridgeContractError("bridge components are invalid")
        if (
            len(self.unsupported_features) > 128
            or tuple(sorted(set(self.unsupported_features))) != self.unsupported_features
            or any(
                not isinstance(item, str)
                or not 1 <= len(item) <= 128
                or any(ord(char) < 32 for char in item)
                for item in self.unsupported_features
            )
        ):
            raise BridgeContractError("bridge unsupported features are invalid")
        if self.execution != "isolated_worker_only" or self.host_import_allowed is not False:
            raise BridgeContractError("bridge execution boundary is invalid")

    @classmethod
    def from_mapping(cls, value: object) -> "EcosystemBridgePlanV1":
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "source",
            "source_sha256",
            "components",
            "unsupported_features",
            "execution",
            "host_import_allowed",
        }:
            raise BridgeContractError("bridge plan is not closed")
        if value.get("schema") != "nachuan.ecosystem-bridge-plan.v1":
            raise BridgeContractError("bridge plan schema is unsupported")
        raw_components = value.get("components")
        raw_unsupported = value.get("unsupported_features")
        if not isinstance(raw_components, list) or not isinstance(raw_unsupported, list):
            raise BridgeContractError("bridge plan collections are invalid")
        return cls(
            source=UpstreamSourcePinV1.from_mapping(value.get("source")),
            source_sha256=value.get("source_sha256"),  # type: ignore[arg-type]
            components=tuple(BridgeComponentV1.from_mapping(item) for item in raw_components),
            unsupported_features=tuple(raw_unsupported),  # type: ignore[arg-type]
            execution=value.get("execution"),  # type: ignore[arg-type]
            host_import_allowed=value.get("host_import_allowed"),  # type: ignore[arg-type]
        )

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source": self.source.as_mapping(),
            "source_sha256": self.source_sha256,
            "components": [item.as_mapping() for item in self.components],
            "unsupported_features": list(self.unsupported_features),
            "execution": self.execution,
            "host_import_allowed": self.host_import_allowed,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.as_mapping())).hexdigest()


def build_deepseek_harness_bridge_plan(
    composition_yaml: bytes,
    *,
    source: UpstreamSourcePinV1,
) -> EcosystemBridgePlanV1:
    if source.ecosystem != "deepseek_harness":
        raise BridgeContractError("DeepSeek bridge source pin is invalid")
    if not isinstance(composition_yaml, bytes) or not 1 <= len(composition_yaml) <= _MAX_SOURCE_BYTES:
        raise BridgeContractError("Cordis composition size is invalid")
    try:
        text = composition_yaml.decode("utf-8")
        events = tuple(yaml.parse(text, Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise BridgeContractError("Cordis composition YAML is invalid") from exc
    if len(events) > 16_384 or any(isinstance(event, AliasEvent) for event in events):
        raise BridgeContractError("Cordis aliases are not supported")
    for event in events:
        if isinstance(event, (ScalarEvent, CollectionStartEvent)) and event.tag:
            if not event.tag.startswith("tag:yaml.org,2002:"):
                raise BridgeContractError("Cordis custom YAML tags are not supported")
    try:
        value = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise BridgeContractError("Cordis composition YAML is invalid") from exc
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_COMPONENTS:
        raise BridgeContractError("Cordis composition must be a bounded plugin list")

    components: list[BridgeComponentV1] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, Mapping) or not set(entry).issubset({"name", "config"}):
            raise BridgeContractError("Cordis plugin entry is not closed")
        name = entry.get("name")
        if (
            not isinstance(name, str)
            or _CORDIS_NAME.fullmatch(name) is None
            or name.startswith("/")
            or ".." in name.split("/")
            or "://" in name
            or name in seen
        ):
            raise BridgeContractError("Cordis plugin name is invalid or duplicated")
        seen.add(name)
        config = entry.get("config", {})
        if not isinstance(config, Mapping):
            raise BridgeContractError("Cordis plugin config must be an object")
        config_bytes = _bounded_json(config, "Cordis plugin config")
        entry_bytes = canonical_json({"name": name, "config_sha256": hashlib.sha256(config_bytes).hexdigest()})
        components.append(
            BridgeComponentV1(
                component_id=name,
                kind="cordis_plugin",
                source_sha256=hashlib.sha256(entry_bytes).hexdigest(),
                metadata_sha256=hashlib.sha256(config_bytes).hexdigest(),
            )
        )
    return EcosystemBridgePlanV1(
        source=source,
        source_sha256=hashlib.sha256(composition_yaml).hexdigest(),
        components=tuple(components),
        unsupported_features=(
            "cordis-client-plugin",
            "cordis-dynamic-service-inject",
            "cordis-host-module-apply",
        ),
    )


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if (
        not isinstance(value, list)
        or len(value) > 64
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 128
            or any(ord(char) < 32 for char in item)
            for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise BridgeContractError(f"OpenClaw {label} is invalid")
    return tuple(value)


def build_openclaw_bridge_plan(
    manifest_json: bytes,
    *,
    skills: Mapping[str, bytes] | None,
    source: UpstreamSourcePinV1,
) -> EcosystemBridgePlanV1:
    if source.ecosystem != "openclaw":
        raise BridgeContractError("OpenClaw bridge source pin is invalid")
    value = _parse_json(manifest_json, "OpenClaw manifest")
    if not isinstance(value, Mapping):
        raise BridgeContractError("OpenClaw manifest must be an object")
    _bounded_json(value, "OpenClaw manifest", _MAX_SOURCE_BYTES)
    plugin_id = value.get("id")
    config_schema = value.get("configSchema")
    if not isinstance(plugin_id, str) or _OPENCLAW_ID.fullmatch(plugin_id) is None:
        raise BridgeContractError("OpenClaw plugin id is invalid")
    if not isinstance(config_schema, Mapping):
        raise BridgeContractError("OpenClaw configSchema is required")
    _bounded_json(config_schema, "OpenClaw configSchema")
    requires = _string_list(value.get("requiresPlugins"), "requiresPlugins")
    providers = _string_list(value.get("providers"), "providers")
    channels = _string_list(value.get("channels"), "channels")
    for field in ("name", "description", "version"):
        raw = value.get(field)
        if raw is not None and (
            not isinstance(raw, str)
            or not 1 <= len(raw) <= 1024
            or any(ord(char) < 32 and char not in "\t\n" for char in raw)
        ):
            raise BridgeContractError(f"OpenClaw {field} is invalid")

    safe_fields = {
        "id",
        "name",
        "description",
        "version",
        "requiresPlugins",
        "providers",
        "channels",
        "configSchema",
    }
    metadata = {
        "id": plugin_id,
        "name": value.get("name"),
        "description": value.get("description"),
        "version": value.get("version"),
        "requiresPlugins": list(requires),
        "providers": list(providers),
        "channels": list(channels),
        "configSchemaSha256": hashlib.sha256(canonical_json(config_schema)).hexdigest(),
    }
    metadata_bytes = _bounded_json(metadata, "OpenClaw safe metadata")
    components = [
        BridgeComponentV1(
            component_id=plugin_id,
            kind="openclaw_plugin",
            source_sha256=hashlib.sha256(manifest_json).hexdigest(),
            metadata_sha256=hashlib.sha256(metadata_bytes).hexdigest(),
            requires=requires,
        )
    ]
    skill_digests: list[dict[str, str]] = []
    for path, payload in sorted((skills or {}).items()):
        match = _SKILL_PATH.fullmatch(path)
        if match is None or not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_SKILL_BYTES:
            raise BridgeContractError("OpenClaw skill path or size is invalid")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BridgeContractError("OpenClaw skill must be UTF-8") from exc
        if "\x00" in text:
            raise BridgeContractError("OpenClaw skill contains NUL")
        digest = hashlib.sha256(payload).hexdigest()
        skill_id = match.group(1)
        skill_digests.append({"path": path, "sha256": digest})
        components.append(
            BridgeComponentV1(
                component_id=f"{plugin_id}/skill/{skill_id}",
                kind="openclaw_skill",
                source_sha256=digest,
                metadata_sha256=hashlib.sha256(
                    canonical_json({"path": path, "bytes": len(payload)})
                ).hexdigest(),
                requires=(plugin_id,),
            )
        )
    aggregate = canonical_json(
        {
            "manifest_sha256": hashlib.sha256(manifest_json).hexdigest(),
            "skills": skill_digests,
        }
    )
    unsupported = {
        "openclaw-native-runtime",
        "openclaw-skill-host-mount",
        *(f"openclaw-manifest-field:{field}" for field in set(value) - safe_fields),
    }
    return EcosystemBridgePlanV1(
        source=source,
        source_sha256=hashlib.sha256(aggregate).hexdigest(),
        components=tuple(components),
        unsupported_features=tuple(sorted(unsupported)),
    )


__all__ = [
    "BridgeComponentV1",
    "BridgeContractError",
    "EcosystemBridgePlanV1",
    "UpstreamSourcePinV1",
    "build_deepseek_harness_bridge_plan",
    "build_openclaw_bridge_plan",
    "canonical_json",
]
