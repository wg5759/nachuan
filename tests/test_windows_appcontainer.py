from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from orchestrator.isolated_plugin import (
    IsolatedPluginBroker,
    IsolatedPluginWorkerError,
    isolated_plugin_signing_payload,
    verify_isolated_plugin_bundle,
)
from orchestrator.windows_appcontainer import WindowsAppContainerLauncher

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows AppContainer only")


def _signed_bundle(
    root: Path,
    plugin: bytes,
    *,
    timeout_ms: int = 5_000,
    cpu_time_ms: int = 2_000,
):
    root.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    plugin_digest = hashlib.sha256(plugin).hexdigest()
    sbom = json.dumps(
        {
            "schema": "nachuan.isolated-plugin-sbom.v1",
            "components": [
                {
                    "name": "com.example.appcontainer-probe",
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
        "id": "com.example.appcontainer-probe",
        "version": "1.0.0",
        "api_version": "1",
        "execution": "isolated_worker",
        "capabilities": ["transform.json"],
        "entrypoint": "plugin.py",
        "artifact_sha256": plugin_digest,
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "publisher_key_id": "example.publisher",
        "limits": {
            "timeout_ms": timeout_ms,
            "cpu_time_ms": cpu_time_ms,
            "memory_bytes": 128 * 1024 * 1024,
            "max_request_bytes": 8_192,
            "max_response_bytes": 8_192,
        },
    }
    manifest["signature"] = private.sign(isolated_plugin_signing_payload(manifest)).hex()
    (root / "plugin.py").write_bytes(plugin)
    (root / "sbom.json").write_bytes(sbom)
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return verify_isolated_plugin_bundle(
        root,
        trusted_publishers={"example.publisher": public},
    )


def test_real_appcontainer_executes_one_signed_plugin(tmp_path) -> None:
    bundle = _signed_bundle(
        tmp_path / "bundle",
        b"def handle(value):\n    return {'echo': value['echo']}\n",
    )
    launcher = WindowsAppContainerLauncher(runtime_cache_root=tmp_path / "runtime-cache")
    broker = IsolatedPluginBroker(launcher)

    assert broker.execute(bundle, {"echo": "isolated"}) == {"echo": "isolated"}
    assert launcher.last_attestation is True


def test_real_appcontainer_denies_host_file_network_and_child_process(tmp_path) -> None:
    canary = tmp_path / "host-secret.txt"
    canary.write_text("host-only-secret", encoding="utf-8")
    outside_write = tmp_path / "must-not-exist.txt"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.25)
    accepted: list[bool] = []

    def accept_once() -> None:
        try:
            connection, _address = listener.accept()
        except OSError:
            accepted.append(False)
            return
        accepted.append(True)
        connection.close()

    thread = threading.Thread(target=accept_once)
    thread.start()
    plugin = b'''\
def _attempt(action):
    try:
        action()
    except BaseException:
        return False
    return True

def _importable(name):
    try:
        __import__(name)
    except BaseException:
        return False
    return True

def _network(port):
    import socket
    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()

def _child():
    import subprocess
    import sys
    subprocess.run([sys.executable, "-I", "-S", "-c", "pass"], timeout=1, check=False)

def handle(value):
    socket_imported = _importable("socket")
    subprocess_imported = _importable("subprocess")
    read_allowed = _attempt(lambda: open(value["read_path"], encoding="utf-8").read())
    write_allowed = _attempt(lambda: open(value["write_path"], "w", encoding="utf-8").write("bad"))
    network_allowed = _attempt(lambda: _network(value["port"]))
    child_allowed = _attempt(_child)
    return {
        "socket_imported": socket_imported,
        "subprocess_imported": subprocess_imported,
        "read_allowed": read_allowed,
        "write_allowed": write_allowed,
        "network_allowed": network_allowed,
        "child_allowed": child_allowed,
    }
'''
    bundle = _signed_bundle(tmp_path / "bundle", plugin)
    launcher = WindowsAppContainerLauncher(runtime_cache_root=tmp_path / "runtime-cache")
    broker = IsolatedPluginBroker(launcher)
    try:
        result = broker.execute(
            bundle,
            {
                "read_path": str(canary),
                "write_path": str(outside_write),
                "port": listener.getsockname()[1],
            },
        )
    finally:
        listener.close()
        thread.join(timeout=2)

    assert result == {
        "socket_imported": True,
        "subprocess_imported": True,
        "read_allowed": False,
        "write_allowed": False,
        "network_allowed": False,
        "child_allowed": False,
    }
    assert launcher.last_attestation is True
    assert not outside_write.exists()
    assert accepted == [False]


def test_real_appcontainer_timeout_kills_job_and_quarantines_identity(tmp_path) -> None:
    bundle = _signed_bundle(
        tmp_path / "bundle",
        b"def handle(value):\n    while True:\n        pass\n",
        timeout_ms=200,
        cpu_time_ms=5_000,
    )
    launcher = WindowsAppContainerLauncher(runtime_cache_root=tmp_path / "runtime-cache")
    broker = IsolatedPluginBroker(launcher)

    started = time.monotonic()
    with pytest.raises(IsolatedPluginWorkerError, match="timed out"):
        broker.execute(bundle, {})

    # First use may spend host-dependent time staging and ACLing the dedicated
    # runtime.  The plugin deadline starts only after the trusted ready frame.
    assert launcher.last_ready_monotonic >= started
    assert 0 < launcher.last_terminal_monotonic - launcher.last_ready_monotonic < 3
    assert launcher.last_attestation is True
    assert broker.quarantined_identities() == (bundle.manifest.identity(),)


@pytest.mark.skipif(
    not os.environ.get("NACHUAN_TEST_PACKAGED_ENGINE"),
    reason="packaged engine acceptance requires an explicit frozen artifact",
)
def test_packaged_engine_worker_self_fences_against_child_process(tmp_path) -> None:
    plugin = b'''\
def handle(value):
    try:
        import subprocess
        import sys
        subprocess.run([sys.executable, "--help"], timeout=1, check=False)
    except BaseException:
        child_allowed = False
    else:
        child_allowed = True
    return {"child_allowed": child_allowed, "value": value["value"]}
'''
    bundle = _signed_bundle(tmp_path / "bundle", plugin)
    launcher = WindowsAppContainerLauncher(
        runtime_cache_root=tmp_path / "runtime-cache",
        packaged_worker_executable=Path(
            os.environ["NACHUAN_TEST_PACKAGED_ENGINE"]
        ),
    )
    broker = IsolatedPluginBroker(launcher)

    assert broker.execute(bundle, {"value": "packaged"}) == {
        "child_allowed": False,
        "value": "packaged",
    }
    assert launcher.last_attestation is True
