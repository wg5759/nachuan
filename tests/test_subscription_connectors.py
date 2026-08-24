from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from gateway.app import app


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


def test_subscription_connector_discovery_requires_runtime_authentication() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/subscription-connectors")

    assert response.status_code == 401
