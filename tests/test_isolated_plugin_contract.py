from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from orchestrator.isolated_plugin import (
    IsolatedPluginBroker,
    IsolatedPluginContractError,
    IsolatedPluginQuarantined,
    IsolatedPluginRevoked,
    IsolatedPluginSignatureError,
    IsolatedPluginWorkerError,
    SQLiteIsolatedPluginStateStore,
    isolated_plugin_signing_payload,
    verify_isolated_plugin_bundle,
)


def _write_bundle(root: Path, plugin: bytes = b"def handle(value):\n    return value\n"):
    root.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    plugin_digest = hashlib.sha256(plugin).hexdigest()
    sbom = json.dumps(
        {
            "schema": "nachuan.isolated-plugin-sbom.v1",
            "components": [
                {
                    "name": "com.example.demo",
                    "version": "1.0.0",
                    "license": "Apache-2.0",
                    "sha256": plugin_digest,
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest = {
        "schema": "nachuan.isolated-plugin.v1",
        "id": "com.example.demo",
        "version": "1.0.0",
        "api_version": "1",
        "execution": "isolated_worker",
        "capabilities": ["transform.json"],
        "entrypoint": "plugin.py",
        "artifact_sha256": plugin_digest,
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
    manifest["signature"] = private.sign(
        isolated_plugin_signing_payload(manifest)
    ).hex()
    (root / "plugin.py").write_bytes(plugin)
    (root / "sbom.json").write_bytes(sbom)
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return public, manifest


def test_signed_bundle_and_broker_accept_one_closed_json_result(tmp_path) -> None:
    public, _manifest = _write_bundle(tmp_path / "plugin")
    bundle = verify_isolated_plugin_bundle(
        tmp_path / "plugin", trusted_publishers={"example.publisher": public}
    )

    class Launcher:
        def execute(self, _bundle, request_json: bytes) -> bytes:
            request = json.loads(request_json)
            return json.dumps(
                {
                    "schema": "nachuan.isolated-plugin.result.v1",
                    "ok": True,
                    "output": {"echo": request},
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()

    broker = IsolatedPluginBroker(Launcher())
    assert broker.execute(bundle, {"value": 7}) == {
        "echo": {
            "schema": "nachuan.isolated-plugin.request.v1",
            "input": {"value": 7},
        }
    }
    assert broker.quarantined_identities() == ()


@pytest.mark.parametrize("target", ["plugin.py", "sbom.json", "manifest.json"])
def test_bundle_tampering_is_rejected_before_worker_start(tmp_path, target) -> None:
    root = tmp_path / "plugin"
    public, _manifest = _write_bundle(root)
    path = root / target
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises((IsolatedPluginContractError, IsolatedPluginSignatureError)):
        verify_isolated_plugin_bundle(
            root, trusted_publishers={"example.publisher": public}
        )


def test_unknown_publisher_revocation_and_extra_files_fail_closed(tmp_path) -> None:
    root = tmp_path / "plugin"
    public, manifest = _write_bundle(root)
    with pytest.raises(IsolatedPluginSignatureError, match="publisher"):
        verify_isolated_plugin_bundle(root, trusted_publishers={})
    identity = (manifest["id"], manifest["version"], manifest["artifact_sha256"])
    with pytest.raises(IsolatedPluginRevoked):
        verify_isolated_plugin_bundle(
            root,
            trusted_publishers={"example.publisher": public},
            revoked=frozenset({identity}),
        )
    (root / "extra.dll").write_bytes(b"malicious")
    with pytest.raises(IsolatedPluginContractError, match="file set"):
        verify_isolated_plugin_bundle(
            root, trusted_publishers={"example.publisher": public}
        )


def test_worker_protocol_failure_quarantines_exact_identity(tmp_path) -> None:
    root = tmp_path / "plugin"
    public, _manifest = _write_bundle(root)
    bundle = verify_isolated_plugin_bundle(
        root, trusted_publishers={"example.publisher": public}
    )

    class BrokenLauncher:
        def execute(self, _bundle, _request_json: bytes) -> bytes:
            return b'{"ok":true,"extra":"open"}'

    broker = IsolatedPluginBroker(BrokenLauncher())
    with pytest.raises(IsolatedPluginWorkerError):
        broker.execute(bundle, {"value": 1})
    assert broker.quarantined_identities() == (bundle.manifest.identity(),)
    with pytest.raises(IsolatedPluginQuarantined):
        broker.execute(bundle, {"value": 1})


def test_oversized_request_is_rejected_without_quarantining(tmp_path) -> None:
    root = tmp_path / "plugin"
    public, _manifest = _write_bundle(root)
    bundle = verify_isolated_plugin_bundle(
        root, trusted_publishers={"example.publisher": public}
    )

    class ForbiddenLauncher:
        def execute(self, _bundle, _request_json: bytes) -> bytes:
            raise AssertionError("worker must not start")

    broker = IsolatedPluginBroker(ForbiddenLauncher())
    with pytest.raises(IsolatedPluginContractError, match="request"):
        broker.execute(bundle, {"value": "x" * 5_000})
    assert broker.quarantined_identities() == ()


def test_quarantine_survives_broker_restart_and_is_exact_identity(tmp_path) -> None:
    root = tmp_path / "plugin"
    public, _manifest = _write_bundle(root)
    bundle = verify_isolated_plugin_bundle(
        root, trusted_publishers={"example.publisher": public}
    )
    state = SQLiteIsolatedPluginStateStore(tmp_path / "state" / "plugins.sqlite3")

    class BrokenLauncher:
        def execute(self, _bundle, _request_json: bytes) -> bytes:
            return b"not-json"

    first = IsolatedPluginBroker(BrokenLauncher(), state)
    with pytest.raises(IsolatedPluginWorkerError):
        first.execute(bundle, {"value": 1})

    class ForbiddenLauncher:
        def execute(self, _bundle, _request_json: bytes) -> bytes:
            raise AssertionError("persistently quarantined plugin must not start")

    restarted = IsolatedPluginBroker(
        ForbiddenLauncher(),
        SQLiteIsolatedPluginStateStore(state.path),
    )
    with pytest.raises(IsolatedPluginQuarantined):
        restarted.execute(bundle, {"value": 1})
    assert restarted.quarantined_identities() == (bundle.manifest.identity(),)
    assert state.is_quarantined(
        (bundle.manifest.plugin_id, "1.0.1", bundle.manifest.artifact_sha256)
    ) is False


def test_quarantine_store_rejects_schema_shadowing(tmp_path) -> None:
    path = tmp_path / "plugins.sqlite3"
    SQLiteIsolatedPluginStateStore(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE shadow (value TEXT)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IsolatedPluginContractError, match="authority"):
        SQLiteIsolatedPluginStateStore(path)
