from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from orchestrator.isolated_plugin import (
    IsolatedPluginBroker,
    IsolatedPluginContractError,
    isolated_plugin_signing_payload,
)
from orchestrator.isolated_plugin_proxy import (
    BUILTIN_ISOLATED_PLUGIN_PROXY_ID,
    ISOLATED_PLUGIN_SERVICE,
    mount_isolated_plugin_proxy,
)
from orchestrator.plugin_kernel import PluginInUseError, PluginKernel, ServiceNotFound


def _bundle(root: Path) -> tuple[bytes, dict[str, object]]:
    root.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    plugin = b"def handle(value):\n    return value\n"
    artifact = hashlib.sha256(plugin).hexdigest()
    sbom = json.dumps(
        {
            "schema": "nachuan.isolated-plugin-sbom.v1",
            "components": [
                {
                    "name": "com.example.kernel-proxy",
                    "version": "1.0.0",
                    "license": "Apache-2.0",
                    "sha256": artifact,
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest: dict[str, object] = {
        "schema": "nachuan.isolated-plugin.v1",
        "id": "com.example.kernel-proxy",
        "version": "1.0.0",
        "api_version": "1",
        "execution": "isolated_worker",
        "capabilities": ["transform.json"],
        "entrypoint": "plugin.py",
        "artifact_sha256": artifact,
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "publisher_key_id": "example.publisher",
        "limits": {
            "timeout_ms": 1_000,
            "cpu_time_ms": 500,
            "memory_bytes": 64 * 1024 * 1024,
            "max_request_bytes": 4_096,
            "max_response_bytes": 4_096,
        },
    }
    manifest["signature"] = private.sign(isolated_plugin_signing_payload(manifest)).hex()
    (root / "plugin.py").write_bytes(plugin)
    (root / "sbom.json").write_bytes(sbom)
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return public, manifest


class _EchoLauncher:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, _bundle, request_json: bytes) -> bytes:
        self.calls += 1
        request = json.loads(request_json)
        return json.dumps(
            {
                "schema": "nachuan.isolated-plugin.result.v1",
                "ok": True,
                "output": request["input"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@pytest.mark.asyncio
async def test_builtin_proxy_is_the_only_in_process_boundary_and_unloads_cleanly(tmp_path) -> None:
    public, manifest = _bundle(tmp_path / "plugin")
    launcher = _EchoLauncher()
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(launcher),
        bundle_roots=[tmp_path / "plugin"],
        trusted_publishers={"example.publisher": public},
    )

    assert kernel.active_plugin_ids() == (BUILTIN_ISOLATED_PLUGIN_PROXY_ID,)
    lease = kernel.borrow_service(ISOLATED_PLUGIN_SERVICE)
    service = lease.value
    assert service.execute(
        {
            "plugin_id": manifest["id"],
            "version": manifest["version"],
            "artifact_sha256": manifest["artifact_sha256"],
            "input": {"value": 7},
        }
    ) == {"value": 7}
    assert launcher.calls == 1
    assert service.snapshot() == (
        {
            "schema": "nachuan.isolated-plugin.catalog-entry.v1",
            "id": manifest["id"],
            "version": manifest["version"],
            "artifact_sha256": manifest["artifact_sha256"],
            "capabilities": ["transform.json"],
            "quarantined": False,
        },
    )

    with pytest.raises(PluginInUseError):
        await kernel.unmount(BUILTIN_ISOLATED_PLUGIN_PROXY_ID)
    lease.release()
    await kernel.unmount(BUILTIN_ISOLATED_PLUGIN_PROXY_ID)
    with pytest.raises(ServiceNotFound):
        kernel.borrow_service(ISOLATED_PLUGIN_SERVICE)


def test_proxy_rejects_identity_drift_before_worker_start(tmp_path) -> None:
    public, manifest = _bundle(tmp_path / "plugin")
    launcher = _EchoLauncher()
    kernel = PluginKernel()
    mount_isolated_plugin_proxy(
        kernel,
        IsolatedPluginBroker(launcher),
        bundle_roots=[tmp_path / "plugin"],
        trusted_publishers={"example.publisher": public},
    )
    lease = kernel.borrow_service(ISOLATED_PLUGIN_SERVICE)
    try:
        with pytest.raises(IsolatedPluginContractError, match="identity"):
            lease.value.execute(
                {
                    "plugin_id": manifest["id"],
                    "version": "1.0.1",
                    "artifact_sha256": manifest["artifact_sha256"],
                    "input": {},
                }
            )
    finally:
        lease.release()
    assert launcher.calls == 0
