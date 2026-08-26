"""Built-in kernel proxy for preverified isolated third-party plugins."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from orchestrator.isolated_plugin import (
    IsolatedPluginBroker,
    IsolatedPluginContractError,
    SQLiteIsolatedPluginStateStore,
    VerifiedIsolatedPluginBundle,
    verify_isolated_plugin_bundle,
)
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    ServiceDefinition,
)

BUILTIN_ISOLATED_PLUGIN_PROXY_ID = "com.nachuan.isolated-plugin-proxy"
ISOLATED_PLUGIN_SERVICE = "isolated.plugin.execute"
_CONTRACT_DIGEST = hashlib.sha256(
    b"nachuan.isolated-plugin-proxy.v1\0isolated.plugin.execute.v1"
).hexdigest()

BUILTIN_ISOLATED_PLUGIN_PROXY_MANIFEST = PluginManifestV1.from_mapping(
    {
        "schema": "nachuan.plugin.v1",
        "id": BUILTIN_ISOLATED_PLUGIN_PROXY_ID,
        "version": "1.0.0",
        "api_version": "1",
        "kind": "isolation",
        "capabilities": [],
        "artifact_sha256": _CONTRACT_DIGEST,
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "杭州灵界科技有限公司",
    }
)


class IsolatedPluginProxyService:
    def __init__(
        self,
        broker: IsolatedPluginBroker,
        bundles: Sequence[VerifiedIsolatedPluginBundle],
    ) -> None:
        if not isinstance(broker, IsolatedPluginBroker):
            raise TypeError("isolated plugin broker is invalid")
        catalog: dict[str, VerifiedIsolatedPluginBundle] = {}
        for bundle in bundles:
            if not isinstance(bundle, VerifiedIsolatedPluginBundle):
                raise TypeError("isolated plugin bundle is not verified")
            if bundle.manifest.plugin_id in catalog:
                raise IsolatedPluginContractError("isolated plugin id is duplicated")
            catalog[bundle.manifest.plugin_id] = bundle
        self._broker = broker
        self._catalog = catalog

    def snapshot(self) -> tuple[dict[str, object], ...]:
        quarantined = set(self._broker.quarantined_identities())
        return tuple(
            {
                "schema": "nachuan.isolated-plugin.catalog-entry.v1",
                "id": bundle.manifest.plugin_id,
                "version": bundle.manifest.version,
                "artifact_sha256": bundle.manifest.artifact_sha256,
                "capabilities": sorted(bundle.manifest.capabilities),
                "quarantined": bundle.manifest.identity() in quarantined,
            }
            for bundle in sorted(
                self._catalog.values(),
                key=lambda item: item.manifest.plugin_id,
            )
        )

    def _resolve_request(
        self,
        request: Mapping[str, object],
    ) -> tuple[VerifiedIsolatedPluginBundle, dict[str, object]]:
        if not isinstance(request, Mapping) or set(request) != {
            "plugin_id",
            "version",
            "artifact_sha256",
            "input",
        }:
            raise IsolatedPluginContractError("isolated plugin proxy request is not closed")
        plugin_id = request.get("plugin_id")
        version = request.get("version")
        artifact = request.get("artifact_sha256")
        plugin_input = request.get("input")
        if (
            not isinstance(plugin_id, str)
            or not isinstance(version, str)
            or not isinstance(artifact, str)
            or not isinstance(plugin_input, Mapping)
        ):
            raise IsolatedPluginContractError("isolated plugin proxy request is invalid")
        bundle = self._catalog.get(plugin_id)
        if bundle is None:
            raise IsolatedPluginContractError("isolated plugin is unavailable")
        if (
            version != bundle.manifest.version
            or artifact != bundle.manifest.artifact_sha256
        ):
            raise IsolatedPluginContractError("isolated plugin identity does not match")
        return bundle, dict(plugin_input)

    def execute(self, request: Mapping[str, object]) -> object:
        bundle, plugin_input = self._resolve_request(request)
        return self._broker.execute(bundle, plugin_input)

    def execute_validated(
        self,
        request: Mapping[str, object],
        validator: Callable[[object], object],
    ) -> object:
        if not callable(validator):
            raise TypeError("isolated plugin result validator is invalid")
        bundle, plugin_input = self._resolve_request(request)
        return self._broker.execute(
            bundle,
            plugin_input,
            output_validator=validator,
        )


def mount_isolated_plugin_proxy(
    kernel: PluginKernel,
    broker: IsolatedPluginBroker,
    *,
    bundle_roots: Sequence[str | Path],
    trusted_publishers: Mapping[str, bytes],
    revoked: frozenset[tuple[str, str, str]] = frozenset(),
) -> None:
    bundles = tuple(
        verify_isolated_plugin_bundle(
            root,
            trusted_publishers=trusted_publishers,
            revoked=revoked,
        )
        for root in bundle_roots
    )
    service = IsolatedPluginProxyService(broker, bundles)
    kernel.services.define(ServiceDefinition(ISOLATED_PLUGIN_SERVICE, "1"))

    def apply(ctx) -> None:
        ctx.provide_service(ISOLATED_PLUGIN_SERVICE, service)

    kernel.mount(BUILTIN_ISOLATED_PLUGIN_PROXY_MANIFEST, apply)


def mount_windows_isolated_plugin_proxy(
    kernel: PluginKernel,
    *,
    data_root: str | Path,
    bundle_roots: Sequence[str | Path],
    trusted_publishers: Mapping[str, bytes],
    revoked: frozenset[tuple[str, str, str]] = frozenset(),
) -> IsolatedPluginBroker:
    """Compose the durable broker and the Windows kernel-enforced launcher."""

    from orchestrator.windows_appcontainer import WindowsAppContainerLauncher

    root = Path(data_root).resolve()
    broker = IsolatedPluginBroker(
        WindowsAppContainerLauncher(runtime_cache_root=root / "runtime-cache"),
        SQLiteIsolatedPluginStateStore(root / "state" / "quarantine.sqlite3"),
    )
    mount_isolated_plugin_proxy(
        kernel,
        broker,
        bundle_roots=bundle_roots,
        trusted_publishers=trusted_publishers,
        revoked=revoked,
    )
    return broker


__all__ = [
    "BUILTIN_ISOLATED_PLUGIN_PROXY_ID",
    "BUILTIN_ISOLATED_PLUGIN_PROXY_MANIFEST",
    "ISOLATED_PLUGIN_SERVICE",
    "IsolatedPluginProxyService",
    "mount_isolated_plugin_proxy",
    "mount_windows_isolated_plugin_proxy",
]
