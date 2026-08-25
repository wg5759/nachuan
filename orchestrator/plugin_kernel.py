"""Minimal trusted plugin kernel for Nachuan capability seams.

This module owns composition mechanics only.  It deliberately does not grant
filesystem, network, credential, channel, billing, or tenant authority.  Those
remain kernel choke points and are represented here only by revocable permits.
"""

from __future__ import annotations

import inspect
import json
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.:/-]{1,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SERVICE_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_EVENT_RE = re.compile(r"^(?:fact|runtime|policy)/[a-z0-9][a-z0-9._/-]{1,126}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_TOOL_ARGUMENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_TOOL_SCHEMA_BYTES = 64 * 1024
_MAX_TOOL_RESULT_CHARS = 2 * 1024 * 1024


class PluginKernelError(RuntimeError):
    pass


class PluginManifestError(PluginKernelError, ValueError):
    pass


class InProcessTrustError(PluginKernelError):
    pass


class PluginMountError(PluginKernelError):
    pass


class PluginDisposalError(PluginKernelError):
    pass


class PluginInUseError(PluginKernelError):
    pass


class PluginStateError(PluginKernelError):
    pass


class CapabilityDenied(PluginKernelError):
    pass


class ServiceConflict(PluginKernelError):
    pass


class ServiceNotFound(PluginKernelError):
    pass


class EventContractError(PluginKernelError):
    pass


class ToolContractError(PluginKernelError, ValueError):
    pass


class ToolConflict(PluginKernelError):
    pass


class ToolNotFound(PluginKernelError):
    pass


@dataclass(frozen=True, slots=True)
class PluginManifestV1:
    plugin_id: str
    version: str
    api_version: str
    kind: str
    capabilities: frozenset[str]
    artifact_sha256: str
    execution: Literal["in_process", "isolated_worker", "ephemeral"]
    trust: Literal["builtin", "verified_third_party", "untrusted"]
    publisher: str
    schema: str = "nachuan.plugin.v1"

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PluginManifestV1":
        if not isinstance(value, Mapping):
            raise PluginManifestError("manifest must be an object")
        allowed = {
            "schema",
            "id",
            "version",
            "api_version",
            "kind",
            "capabilities",
            "artifact_sha256",
            "execution",
            "trust",
            "publisher",
        }
        unknown = set(value) - allowed
        missing = allowed - set(value)
        if unknown:
            raise PluginManifestError("manifest has unknown fields")
        if missing:
            raise PluginManifestError("manifest is missing required fields")

        def required_string(name: str, *, limit: int = 128) -> str:
            item = value[name]
            if not isinstance(item, str) or not item or len(item) > limit:
                raise PluginManifestError(f"manifest {name} is invalid")
            return item

        schema = required_string("schema")
        if schema != "nachuan.plugin.v1":
            raise PluginManifestError("manifest schema is unsupported")
        plugin_id = required_string("id")
        if _IDENTIFIER_RE.fullmatch(plugin_id) is None:
            raise PluginManifestError("manifest id is invalid")
        version = required_string("version")
        if _VERSION_RE.fullmatch(version) is None:
            raise PluginManifestError("manifest version is invalid")
        api_version = required_string("api_version", limit=32)
        if not api_version.isascii() or not api_version.replace(".", "").isdigit():
            raise PluginManifestError("manifest api_version is invalid")
        kind = required_string("kind", limit=64)
        if _IDENTIFIER_RE.fullmatch(f"x.{kind}") is None:
            raise PluginManifestError("manifest kind is invalid")
        digest = required_string("artifact_sha256", limit=64).lower()
        if _SHA256_RE.fullmatch(digest) is None:
            raise PluginManifestError("manifest sha256 is invalid")
        publisher = required_string("publisher")

        raw_capabilities = value["capabilities"]
        if (
            not isinstance(raw_capabilities, (list, tuple))
            or len(raw_capabilities) > 128
        ):
            raise PluginManifestError("manifest capabilities are invalid")
        capabilities: list[str] = []
        for item in raw_capabilities:
            if not isinstance(item, str) or _CAPABILITY_RE.fullmatch(item) is None:
                raise PluginManifestError("manifest capability is invalid")
            capabilities.append(item)
        if len(set(capabilities)) != len(capabilities):
            raise PluginManifestError("manifest has duplicate capabilities")

        execution = required_string("execution")
        if execution not in {"in_process", "isolated_worker", "ephemeral"}:
            raise PluginManifestError("manifest execution is invalid")
        trust = required_string("trust")
        if trust not in {"builtin", "verified_third_party", "untrusted"}:
            raise PluginManifestError("manifest trust is invalid")
        return cls(
            plugin_id=plugin_id,
            version=version,
            api_version=api_version,
            kind=kind,
            capabilities=frozenset(capabilities),
            artifact_sha256=digest,
            execution=execution,  # type: ignore[arg-type]
            trust=trust,  # type: ignore[arg-type]
            publisher=publisher,
            schema=schema,
        )


@dataclass(frozen=True, slots=True)
class CapabilityPermit:
    plugin_id: str
    version: str
    generation: str
    capability: str


class CapabilityBroker:
    def __init__(self) -> None:
        self._active: dict[str, tuple[str, str, frozenset[str]]] = {}
        self._lock = threading.RLock()

    def activate(self, manifest: PluginManifestV1, generation: str) -> None:
        with self._lock:
            if manifest.plugin_id in self._active:
                raise PluginStateError("plugin capability generation is already active")
            self._active[manifest.plugin_id] = (
                manifest.version,
                generation,
                manifest.capabilities,
            )

    def revoke(self, plugin_id: str, generation: str) -> None:
        with self._lock:
            current = self._active.get(plugin_id)
            if current is not None and current[1] == generation:
                del self._active[plugin_id]

    def permit(self, plugin_id: str, generation: str, capability: str) -> CapabilityPermit:
        with self._lock:
            current = self._active.get(plugin_id)
            if (
                current is None
                or current[1] != generation
                or capability not in current[2]
            ):
                raise CapabilityDenied("plugin capability is not granted")
            return CapabilityPermit(plugin_id, current[0], generation, capability)

    def require(self, permit: CapabilityPermit, capability: str) -> None:
        if not isinstance(permit, CapabilityPermit) or permit.capability != capability:
            raise CapabilityDenied("capability permit does not match")
        with self._lock:
            current = self._active.get(permit.plugin_id)
            if (
                current is None
                or current[0] != permit.version
                or current[1] != permit.generation
                or capability not in current[2]
            ):
                raise CapabilityDenied("capability permit is stale")


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    name: str
    api_version: str

    def __post_init__(self) -> None:
        if _SERVICE_RE.fullmatch(self.name) is None:
            raise ValueError("service name is invalid")
        if not self.api_version or len(self.api_version) > 32:
            raise ValueError("service api version is invalid")


@dataclass(slots=True)
class _ServiceProvider:
    plugin_id: str
    generation: str
    value: object
    borrows: int = 0


class ServiceLease:
    def __init__(self, registry: "ServiceRegistry", name: str, provider: _ServiceProvider):
        self._registry = registry
        self._name = name
        self._provider = provider
        self._released = False

    @property
    def value(self) -> object:
        return self._provider.value

    @property
    def owner_plugin_id(self) -> str:
        return self._provider.plugin_id

    def release(self) -> None:
        if self._released:
            return
        self._registry._release(self._name, self._provider)
        self._released = True


class ServiceRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, ServiceDefinition] = {}
        self._providers: dict[str, _ServiceProvider] = {}
        self._lock = threading.RLock()

    def define(self, definition: ServiceDefinition) -> None:
        with self._lock:
            current = self._definitions.get(definition.name)
            if current is not None and current != definition:
                raise ServiceConflict("service definition conflicts")
            self._definitions[definition.name] = definition

    def provide(self, name: str, plugin_id: str, generation: str, value: object) -> Callable[[], None]:
        with self._lock:
            if name not in self._definitions:
                raise ServiceNotFound("service definition is missing")
            if name in self._providers:
                raise ServiceConflict("service already has a provider")
            record = _ServiceProvider(plugin_id, generation, value)
            self._providers[name] = record

        def dispose() -> None:
            with self._lock:
                current = self._providers.get(name)
                if current is not record:
                    return
                if record.borrows:
                    raise PluginInUseError("plugin service is still borrowed")
                del self._providers[name]

        return dispose

    def has_provider(self, name: str) -> bool:
        with self._lock:
            return name in self._providers

    def borrow(self, name: str) -> ServiceLease:
        with self._lock:
            record = self._providers.get(name)
            if record is None:
                raise ServiceNotFound("service provider is unavailable")
            record.borrows += 1
            return ServiceLease(self, name, record)

    def _release(self, name: str, record: _ServiceProvider) -> None:
        with self._lock:
            if record.borrows <= 0:
                raise PluginStateError("service lease is already released")
            record.borrows -= 1

    def assert_owner_not_borrowed(self, plugin_id: str, generation: str) -> None:
        with self._lock:
            if any(
                provider.plugin_id == plugin_id
                and provider.generation == generation
                and provider.borrows > 0
                for provider in self._providers.values()
            ):
                raise PluginInUseError("plugin service is still borrowed")


EventDomain = Literal["durable", "live", "capability"]


@dataclass(frozen=True, slots=True)
class EventDefinition:
    name: str
    domain: EventDomain

    def __post_init__(self) -> None:
        if _EVENT_RE.fullmatch(self.name) is None:
            raise ValueError("event name is invalid")
        if self.domain not in {"durable", "live", "capability"}:
            raise ValueError("event domain is invalid")


@dataclass(frozen=True, slots=True)
class _EventListener:
    token: str
    plugin_id: str
    generation: str
    callback: Callable[[object], object]


class EventRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, EventDefinition] = {}
        self._listeners: dict[str, list[_EventListener]] = {}
        self._lock = threading.RLock()

    def define(self, definition: EventDefinition) -> None:
        with self._lock:
            current = self._definitions.get(definition.name)
            if current is not None and current != definition:
                raise EventContractError("event definition conflicts")
            self._definitions[definition.name] = definition

    def listen(
        self,
        name: str,
        plugin_id: str,
        generation: str,
        callback: Callable[[object], object],
    ) -> Callable[[], None]:
        if not callable(callback):
            raise EventContractError("event listener is not callable")
        with self._lock:
            if name not in self._definitions:
                raise EventContractError("event definition is missing")
            record = _EventListener(secrets.token_hex(16), plugin_id, generation, callback)
            self._listeners.setdefault(name, []).append(record)

        def dispose() -> None:
            with self._lock:
                listeners = self._listeners.get(name, [])
                self._listeners[name] = [item for item in listeners if item is not record]

        return dispose

    async def emit(self, name: str, payload: object) -> int:
        with self._lock:
            if name not in self._definitions:
                raise EventContractError("event definition is missing")
            listeners = tuple(self._listeners.get(name, ()))
        for listener in listeners:
            result = listener.callback(payload)
            if inspect.isawaitable(result):
                await result
        return len(listeners)


@dataclass(frozen=True, slots=True, init=False)
class ToolDefinition:
    """Immutable, JSON-only OpenAI function schema for one plugin tool."""

    name: str
    description: str
    _parameters_json: str

    def __init__(
        self,
        *,
        name: str,
        description: str,
        parameters: Mapping[str, object],
    ) -> None:
        if not isinstance(name, str) or _TOOL_RE.fullmatch(name) is None:
            raise ToolContractError("tool name is invalid")
        if (
            not isinstance(description, str)
            or not description.strip()
            or len(description) > 1024
            or any(ord(char) < 32 and char not in "\t\n" for char in description)
        ):
            raise ToolContractError("tool description is invalid")
        if not isinstance(parameters, Mapping):
            raise ToolContractError("tool parameters must be an object")
        try:
            encoded = json.dumps(
                parameters,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            document = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ToolContractError("tool parameters are not JSON") from exc
        if len(encoded.encode("utf-8")) > _MAX_TOOL_SCHEMA_BYTES:
            raise ToolContractError("tool parameters schema is too large")
        if not isinstance(document, dict) or set(document) - {
            "type",
            "properties",
            "required",
            "additionalProperties",
        }:
            raise ToolContractError("tool parameters schema is not closed")
        if document.get("type") != "object":
            raise ToolContractError("tool parameters type must be object")
        properties = document.get("properties")
        if not isinstance(properties, dict) or len(properties) > 64:
            raise ToolContractError("tool properties are invalid")
        for argument, schema in properties.items():
            if (
                not isinstance(argument, str)
                or _TOOL_ARGUMENT_RE.fullmatch(argument) is None
                or not isinstance(schema, dict)
                or schema.get("type")
                not in {"string", "boolean", "integer", "number", "array", "object"}
            ):
                raise ToolContractError("tool property schema is invalid")
        required = document.get("required", [])
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(set(required)) != len(required)
            or not set(required).issubset(properties)
        ):
            raise ToolContractError("tool required arguments are invalid")
        if document.get("additionalProperties") is not False:
            raise ToolContractError("tool arguments must reject additional properties")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "description", description.strip())
        object.__setattr__(self, "_parameters_json", encoded)

    @property
    def parameters(self) -> dict[str, object]:
        return json.loads(self._parameters_json)

    def openai_schema(self) -> dict[str, object]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def validate_arguments(self, value: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise ToolContractError("tool arguments must be an object")
        document = self.parameters
        properties = document["properties"]
        required = set(document.get("required", []))
        keys = set(value)
        if keys - set(properties) or required - keys:
            raise ToolContractError("tool arguments do not match the closed schema")
        normalized: dict[str, object] = {}
        for name, raw in value.items():
            expected = properties[name]["type"]
            valid = {
                "string": isinstance(raw, str),
                "boolean": isinstance(raw, bool),
                "integer": isinstance(raw, int) and not isinstance(raw, bool),
                "number": isinstance(raw, (int, float)) and not isinstance(raw, bool),
                "array": isinstance(raw, list),
                "object": isinstance(raw, Mapping),
            }[expected]
            if not valid:
                raise ToolContractError("tool argument type is invalid")
            normalized[name] = raw
        try:
            encoded = json.dumps(
                normalized,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ToolContractError("tool arguments are not JSON") from exc
        if len(encoded.encode("utf-8")) > _MAX_TOOL_SCHEMA_BYTES:
            raise ToolContractError("tool arguments are too large")
        return json.loads(encoded)


@dataclass(slots=True)
class _ToolProvider:
    plugin_id: str
    generation: str
    definition: ToolDefinition
    permit: CapabilityPermit
    handler: Callable[[Mapping[str, object]], object]
    borrows: int = 0


class ToolLease:
    def __init__(
        self,
        registry: "ToolRegistry",
        provider: _ToolProvider,
    ) -> None:
        self._registry = registry
        self._provider = provider
        self._released = False

    @property
    def definition(self) -> ToolDefinition:
        return self._provider.definition

    @property
    def owner_plugin_id(self) -> str:
        return self._provider.plugin_id

    async def invoke(self, arguments: Mapping[str, object]) -> str:
        if self._released:
            raise PluginStateError("plugin tool lease is already released")
        return await self._registry._invoke(self._provider, arguments)

    def release(self) -> None:
        if self._released:
            return
        self._registry._release(self._provider)
        self._released = True


class ToolRegistry:
    def __init__(self, broker: CapabilityBroker) -> None:
        self._broker = broker
        self._providers: dict[str, _ToolProvider] = {}
        self._lock = threading.RLock()

    @staticmethod
    def capability_for(name: str) -> str:
        if _TOOL_RE.fullmatch(name) is None:
            raise ToolContractError("tool name is invalid")
        return f"tool.execute:{name}"

    def register(
        self,
        definition: ToolDefinition,
        *,
        plugin_id: str,
        generation: str,
        permit: CapabilityPermit,
        handler: Callable[[Mapping[str, object]], object],
    ) -> Callable[[], None]:
        if not isinstance(definition, ToolDefinition):
            raise ToolContractError("tool definition is invalid")
        if not callable(handler):
            raise ToolContractError("tool handler is not callable")
        capability = self.capability_for(definition.name)
        self._broker.require(permit, capability)
        if permit.plugin_id != plugin_id or permit.generation != generation:
            raise CapabilityDenied("tool permit owner does not match")
        with self._lock:
            if definition.name in self._providers:
                raise ToolConflict("tool already has a provider")
            record = _ToolProvider(
                plugin_id,
                generation,
                definition,
                permit,
                handler,
            )
            self._providers[definition.name] = record

        def dispose() -> None:
            with self._lock:
                current = self._providers.get(definition.name)
                if current is not record:
                    return
                if record.borrows:
                    raise PluginInUseError("plugin tool is still borrowed")
                del self._providers[definition.name]

        return dispose

    def has_provider(self, name: str) -> bool:
        with self._lock:
            return name in self._providers

    def schemas(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            definitions = tuple(
                provider.definition for provider in self._providers.values()
            )
        return tuple(definition.openai_schema() for definition in definitions)

    def borrow(self, name: str) -> ToolLease:
        with self._lock:
            provider = self._providers.get(name)
            if provider is None:
                raise ToolNotFound("tool provider is unavailable")
            provider.borrows += 1
            return ToolLease(self, provider)

    async def _invoke(
        self,
        provider: _ToolProvider,
        arguments: Mapping[str, object],
    ) -> str:
        with self._lock:
            current = self._providers.get(provider.definition.name)
            if current is not provider or provider.borrows <= 0:
                raise PluginStateError("plugin tool lease is stale")
        self._broker.require(
            provider.permit,
            self.capability_for(provider.definition.name),
        )
        normalized = provider.definition.validate_arguments(arguments)
        try:
            result = provider.handler(normalized)
            if inspect.isawaitable(result):
                result = await result
        except ToolContractError:
            raise
        except Exception as exc:
            raise ToolContractError("plugin tool execution failed") from exc
        if not isinstance(result, str) or len(result) > _MAX_TOOL_RESULT_CHARS:
            raise ToolContractError("plugin tool result is invalid")
        return result

    def _release(self, provider: _ToolProvider) -> None:
        with self._lock:
            if provider.borrows <= 0:
                raise PluginStateError("plugin tool lease is already released")
            provider.borrows -= 1

    def assert_owner_not_borrowed(self, plugin_id: str, generation: str) -> None:
        with self._lock:
            if any(
                provider.plugin_id == plugin_id
                and provider.generation == generation
                and provider.borrows > 0
                for provider in self._providers.values()
            ):
                raise PluginInUseError("plugin tool is still borrowed")


class _EffectCloseError(RuntimeError):
    def __init__(self, count: int) -> None:
        self.count = count
        super().__init__("plugin effect cleanup incomplete")


class EffectScope:
    def __init__(self) -> None:
        self._effects: list[Callable[[], object]] = []
        self._closed = False

    def add(self, disposer: Callable[[], object]) -> None:
        if self._closed:
            raise PluginStateError("plugin effect scope is closed")
        if not callable(disposer):
            raise TypeError("plugin disposer is not callable")
        self._effects.append(disposer)

    def close_sync(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures = 0
        for disposer in reversed(self._effects):
            try:
                result = disposer()
                if inspect.isawaitable(result):
                    close = getattr(result, "close", None)
                    if callable(close):
                        close()
                    failures += 1
            except BaseException:
                failures += 1
        self._effects.clear()
        if failures:
            raise _EffectCloseError(failures)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures = 0
        for disposer in reversed(self._effects):
            try:
                result = disposer()
                if inspect.isawaitable(result):
                    await result
            except BaseException:
                failures += 1
        self._effects.clear()
        if failures:
            raise _EffectCloseError(failures)


@dataclass(slots=True)
class _PluginRecord:
    manifest: PluginManifestV1
    generation: str
    scope: EffectScope


class PluginContext:
    def __init__(self, kernel: "PluginKernel", record: _PluginRecord) -> None:
        self._kernel = kernel
        self._record = record

    @property
    def manifest(self) -> PluginManifestV1:
        return self._record.manifest

    def effect(self, disposer: Callable[[], object]) -> None:
        self._record.scope.add(disposer)

    def provide_service(self, name: str, value: object) -> None:
        disposer = self._kernel.services.provide(
            name,
            self._record.manifest.plugin_id,
            self._record.generation,
            value,
        )
        self._record.scope.add(disposer)

    def borrow_service(self, name: str, capability: str) -> object:
        permit = self.permit(capability)
        self._kernel.require(permit, capability)
        lease = self._kernel.borrow_service(name)
        self._record.scope.add(lease.release)
        return lease.value

    def register_tool(
        self,
        definition: ToolDefinition,
        handler: Callable[[Mapping[str, object]], object],
    ) -> None:
        capability = self._kernel.tools.capability_for(definition.name)
        permit = self.permit(capability)
        disposer = self._kernel.tools.register(
            definition,
            plugin_id=self._record.manifest.plugin_id,
            generation=self._record.generation,
            permit=permit,
            handler=handler,
        )
        self._record.scope.add(disposer)

    def listen(self, event: str, callback: Callable[[object], object]) -> None:
        disposer = self._kernel.events.listen(
            event,
            self._record.manifest.plugin_id,
            self._record.generation,
            callback,
        )
        self._record.scope.add(disposer)

    def permit(self, capability: str) -> CapabilityPermit:
        return self._kernel.broker.permit(
            self._record.manifest.plugin_id,
            self._record.generation,
            capability,
        )


class PluginKernel:
    def __init__(self) -> None:
        self.services = ServiceRegistry()
        self.events = EventRegistry()
        self.broker = CapabilityBroker()
        self.tools = ToolRegistry(self.broker)
        self._active: dict[str, _PluginRecord] = {}
        self._mount_order: list[str] = []
        self._quarantined: set[str] = set()

    def mount(
        self,
        manifest: PluginManifestV1,
        apply: Callable[[PluginContext], object],
    ) -> str:
        if not isinstance(manifest, PluginManifestV1):
            raise TypeError("plugin manifest is invalid")
        if manifest.execution != "in_process" or manifest.trust != "builtin":
            raise InProcessTrustError("only builtin plugins may mount in process")
        if manifest.plugin_id in self._active or manifest.plugin_id in self._quarantined:
            raise PluginStateError("plugin is already active or quarantined")
        if not callable(apply):
            raise TypeError("plugin apply is not callable")
        record = _PluginRecord(manifest, secrets.token_hex(16), EffectScope())
        self._active[manifest.plugin_id] = record
        self._mount_order.append(manifest.plugin_id)
        self.broker.activate(manifest, record.generation)
        try:
            result = apply(PluginContext(self, record))
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise TypeError("async plugin apply is unsupported")
            if result is not None:
                if not callable(result):
                    raise TypeError("plugin apply result is not a disposer")
                record.scope.add(result)
        except BaseException as exc:
            self.broker.revoke(manifest.plugin_id, record.generation)
            self._active.pop(manifest.plugin_id, None)
            self._mount_order = [item for item in self._mount_order if item != manifest.plugin_id]
            try:
                record.scope.close_sync()
            except _EffectCloseError:
                self._quarantined.add(manifest.plugin_id)
            raise PluginMountError("plugin mount failed safely") from exc
        return record.generation

    async def unmount(self, plugin_id: str) -> None:
        record = self._active.get(plugin_id)
        if record is None:
            raise PluginStateError("plugin is not active")
        self.services.assert_owner_not_borrowed(plugin_id, record.generation)
        self.tools.assert_owner_not_borrowed(plugin_id, record.generation)
        self.broker.revoke(plugin_id, record.generation)
        self._active.pop(plugin_id, None)
        self._mount_order = [item for item in self._mount_order if item != plugin_id]
        try:
            await record.scope.close()
        except _EffectCloseError as exc:
            self._quarantined.add(plugin_id)
            raise PluginDisposalError("plugin cleanup incomplete; quarantined") from exc

    async def aclose(self) -> None:
        failures = 0
        for plugin_id in reversed(tuple(self._mount_order)):
            try:
                await self.unmount(plugin_id)
            except BaseException:
                failures += 1
        if failures:
            raise PluginDisposalError("plugin kernel cleanup incomplete")

    def borrow_service(self, name: str) -> ServiceLease:
        return self.services.borrow(name)

    def require(self, permit: CapabilityPermit, capability: str) -> None:
        self.broker.require(permit, capability)

    def borrow_tool(self, name: str) -> ToolLease:
        return self.tools.borrow(name)

    def tool_schemas(self) -> tuple[dict[str, object], ...]:
        return self.tools.schemas()

    def active_plugin_ids(self) -> tuple[str, ...]:
        return tuple(self._mount_order)

    def quarantined_plugin_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._quarantined))


__all__ = [
    "CapabilityDenied",
    "CapabilityPermit",
    "EventDefinition",
    "EventRegistry",
    "InProcessTrustError",
    "PluginContext",
    "PluginDisposalError",
    "PluginInUseError",
    "PluginKernel",
    "PluginKernelError",
    "PluginManifestError",
    "PluginManifestV1",
    "PluginMountError",
    "PluginStateError",
    "ServiceConflict",
    "ServiceDefinition",
    "ServiceLease",
    "ServiceNotFound",
    "ServiceRegistry",
    "ToolConflict",
    "ToolContractError",
    "ToolDefinition",
    "ToolLease",
    "ToolNotFound",
    "ToolRegistry",
]
