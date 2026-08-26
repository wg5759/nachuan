from __future__ import annotations

import hashlib
import threading

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.kimi_subscription_login import KimiSubscriptionLoginError


AUTH = {"Authorization": "Bearer test-key"}


class _FakeSubscriptionConnectors:
    def list_public(self) -> list[dict[str, object]]:
        return [
            {
                "id": "codex",
                "label": "Codex",
                "state": "ready",
                "auth": "device_code",
                "transport": "stdio_jsonl",
                "version": "0.144.5",
                "capabilities": ["chat", "code"],
                "login_supported": True,
                "logout_supported": True,
                "token": "must-not-leak",
                "stdout": "raw cli output",
            },
            {
                "id": "kimi-code",
                "label": "Kimi Code",
                "state": "authenticated_unprobed",
                "auth": "device_code",
                "transport": "acp_stdio",
                "version": "0.27.0",
                "capabilities": ["chat", "code"],
                "login_supported": True,
                "logout_supported": False,
            },
        ]


def test_subscription_connector_discovery_returns_only_public_capabilities() -> None:
    app.state.subscription_connectors = _FakeSubscriptionConnectors()
    try:
        with TestClient(app) as client:
            response = client.get("/v1/subscription-connectors", headers=AUTH)
    finally:
        del app.state.subscription_connectors

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload == {
            "connectors": [
                {
                    "id": "codex",
                    "label": "Codex",
                    "state": "ready",
                    "auth": "device_code",
                    "transport": "stdio_jsonl",
                    "version": "0.144.5",
                    "capabilities": ["chat", "code"],
                    "login_supported": True,
                    "logout_supported": True,
                },
                {
                    "id": "kimi-code",
                    "label": "Kimi Code",
                    "state": "authenticated_unprobed",
                    "auth": "device_code",
                    "transport": "acp_stdio",
                    "version": "0.27.0",
                    "capabilities": ["chat", "code"],
                    "login_supported": True,
                    "logout_supported": False,
                },
            ]
        }
    serialized = response.text.lower()
    for forbidden in ("token", "cookie", "auth.json", "credential_path", "stdout", "stderr"):
        assert forbidden not in serialized


def test_default_registry_uses_only_explicit_attested_cli(
    tmp_path, monkeypatch
) -> None:
    codex = (tmp_path / "codex.exe").resolve()
    image = bytearray(128)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    codex.write_bytes(image)
    monkeypatch.setenv("CODEX_CLI_PATH", str(codex))
    monkeypatch.setenv(
        "CODEX_CLI_SHA256", hashlib.sha256(codex.read_bytes()).hexdigest()
    )
    monkeypatch.setenv("PATH", str(tmp_path / "ignored-path"))

    class FakeCodexWorker:
        def __init__(self, *, environment):
            assert environment["CODEX_CLI_PATH"] == str(codex)

        def probe_status(self) -> str:
            return "authenticated_unprobed"

    monkeypatch.setattr(
        "gateway.subscription_connectors.CodexSubscriptionWorker",
        FakeCodexWorker,
    )
    if hasattr(app.state, "subscription_connectors"):
        del app.state.subscription_connectors

    with TestClient(app) as client:
        response = client.get("/v1/subscription-connectors", headers=AUTH)

    assert response.status_code == 200
    connectors = {item["id"]: item for item in response.json()["connectors"]}
    assert connectors["codex"]["state"] == "authenticated_unprobed"
    assert connectors["kimi-code"]["state"] == "not_installed"
    assert str(codex).lower() not in response.text.lower()


def test_default_registry_probes_attested_kimi_login_state(
    tmp_path, monkeypatch
) -> None:
    kimi = (tmp_path / "kimi.exe").resolve()
    image = bytearray(128)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    kimi.write_bytes(image)
    digest = hashlib.sha256(kimi.read_bytes()).hexdigest()
    kimi_home = (tmp_path / "kimi-home").resolve()
    temp_root = (tmp_path / "kimi-temp").resolve()
    kimi_home.mkdir()
    temp_root.mkdir()
    monkeypatch.setenv("KIMI_CLI_PATH", str(kimi))
    monkeypatch.setenv("KIMI_CLI_SHA256", digest)
    monkeypatch.setenv("KIMI_CLI_VERSION", "0.27.0")
    monkeypatch.setenv("KIMI_CODE_HOME", str(kimi_home))
    monkeypatch.setenv("KIMI_CLI_TEMP_ROOT", str(temp_root))

    class FakeKimiLoginController:
        def __init__(self, *, protected_overlay):
            assert protected_overlay["KIMI_CLI_PATH"] == str(kimi)
            assert protected_overlay["KIMI_CLI_SHA256"] == digest
            assert protected_overlay["KIMI_CODE_HOME"] == str(kimi_home)

        def probe_status(self) -> str:
            return "authenticated_unprobed"

    monkeypatch.setattr(
        "gateway.subscription_connectors.KimiSubscriptionLoginController",
        FakeKimiLoginController,
        raising=False,
    )
    if hasattr(app.state, "subscription_connectors"):
        del app.state.subscription_connectors

    with TestClient(app) as client:
        response = client.get("/v1/subscription-connectors", headers=AUTH)

    assert response.status_code == 200
    connectors = {item["id"]: item for item in response.json()["connectors"]}
    assert connectors["kimi-code"]["state"] == "authenticated_unprobed"
    assert str(kimi).lower() not in response.text.lower()


def test_kimi_probe_failure_isolated_without_hiding_other_connectors(
    tmp_path, monkeypatch
) -> None:
    kimi = (tmp_path / "kimi.exe").resolve()
    image = bytearray(128)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    kimi.write_bytes(image)
    digest = hashlib.sha256(kimi.read_bytes()).hexdigest()
    kimi_home = (tmp_path / "kimi-home").resolve()
    temp_root = (tmp_path / "kimi-temp").resolve()
    kimi_home.mkdir()
    temp_root.mkdir()
    monkeypatch.setenv("KIMI_CLI_PATH", str(kimi))
    monkeypatch.setenv("KIMI_CLI_SHA256", digest)
    monkeypatch.setenv("KIMI_CLI_VERSION", "0.27.0")
    monkeypatch.setenv("KIMI_CODE_HOME", str(kimi_home))
    monkeypatch.setenv("KIMI_CLI_TEMP_ROOT", str(temp_root))

    class FailingKimiLoginController:
        def __init__(self, *, protected_overlay):
            assert protected_overlay["KIMI_CLI_PATH"] == str(kimi)

        def probe_status(self) -> str:
            raise KimiSubscriptionLoginError("auth_probe_failed")

    monkeypatch.setattr(
        "gateway.subscription_connectors.KimiSubscriptionLoginController",
        FailingKimiLoginController,
    )
    if hasattr(app.state, "subscription_connectors"):
        del app.state.subscription_connectors

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/v1/subscription-connectors", headers=AUTH)

    assert response.status_code == 200
    connectors = {item["id"]: item for item in response.json()["connectors"]}
    assert connectors["codex"]["state"] == "not_installed"
    assert connectors["kimi-code"]["state"] == "unavailable"


def test_attested_subscription_status_probes_do_not_block_each_other(
    monkeypatch,
) -> None:
    barrier = threading.Barrier(2)

    class FakeDiscovery:
        def __init__(self, *, environment):
            assert isinstance(environment, dict)

        def list_public(self) -> list[dict[str, object]]:
            return [
                {
                    "id": "codex",
                    "label": "Codex",
                    "state": "installed_unprobed",
                    "auth": "device_code",
                    "transport": "stdio_jsonl",
                    "version": "0.144.5",
                    "capabilities": ["chat", "code"],
                    "login_supported": True,
                    "logout_supported": True,
                },
                {
                    "id": "kimi-code",
                    "label": "Kimi Code",
                    "state": "installed_unprobed",
                    "auth": "device_code",
                    "transport": "acp_stdio",
                    "version": "0.27.0",
                    "capabilities": ["chat", "code"],
                    "login_supported": True,
                    "logout_supported": False,
                },
            ]

    class FakeCodexWorker:
        def __init__(self, *, environment):
            assert isinstance(environment, dict)

        def probe_status(self) -> str:
            barrier.wait(timeout=2)
            return "authenticated_unprobed"

    class FakeKimiLoginController:
        def __init__(self, *, protected_overlay):
            assert isinstance(protected_overlay, dict)

        def probe_status(self) -> str:
            barrier.wait(timeout=2)
            return "authenticated_unprobed"

    monkeypatch.setattr(
        "gateway.subscription_connectors.SubscriptionCliDiscovery",
        FakeDiscovery,
    )
    monkeypatch.setattr(
        "gateway.subscription_connectors.CodexSubscriptionWorker",
        FakeCodexWorker,
    )
    monkeypatch.setattr(
        "gateway.subscription_connectors.KimiSubscriptionLoginController",
        FakeKimiLoginController,
    )
    if hasattr(app.state, "subscription_connectors"):
        del app.state.subscription_connectors

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/v1/subscription-connectors", headers=AUTH)

    assert response.status_code == 200
    states = {
        item["id"]: item["state"] for item in response.json()["connectors"]
    }
    assert states == {
        "codex": "authenticated_unprobed",
        "kimi-code": "authenticated_unprobed",
    }


def test_subscription_connector_discovery_requires_runtime_authentication() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/subscription-connectors")

    assert response.status_code == 401
