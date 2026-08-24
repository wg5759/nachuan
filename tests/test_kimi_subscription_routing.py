from __future__ import annotations

import copy
import hashlib
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.connections import normalize_connection_candidate
from gateway.kimi_subscription_worker import KimiInvocation
from gateway.router import Router, connection_independence_domain
from gateway.runtime_profile import resolve_runtime_profile


_PUBLIC_MODEL_ID = "kimi-code-subscription"


def _model() -> dict[str, object]:
    return {
        "id": _PUBLIC_MODEL_ID,
        "upstream_model": _PUBLIC_MODEL_ID,
        "tier": "premium",
        "description": "Kimi Code subscription (served model not asserted)",
        "modality": "chat",
        "rank": 0,
        "flagship": False,
        "tool_capable": False,
        "skills": ["code", "reasoning"],
    }


def _candidate() -> dict[str, object]:
    return {
        "type": "kimi_code",
        "api_key": "",
        "base_url": "",
        "enabled_models": [_model()],
    }


def _fake_pe() -> bytes:
    payload = bytearray(160)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[96:100] = b"kimi"
    return bytes(payload)


def _environment(tmp_path: Path) -> dict[str, str]:
    executable = (tmp_path / "kimi.exe").resolve()
    executable.write_bytes(_fake_pe())
    return {
        "KIMI_CLI_PATH": str(executable),
        "KIMI_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "KIMI_CLI_VERSION": "0.27.0",
    }


class _Worker:
    def invoke(
        self,
        prompt: str,
        *,
        cancellation_event: threading.Event,
    ) -> KimiInvocation:
        del prompt, cancellation_event
        return KimiInvocation(
            text="fake reply",
            session_id="session-0123456789abcdef",
            model_id=_PUBLIC_MODEL_ID,
            actual_served_model=None,
        )


class _VerifiedStore:
    def __init__(self, connection: dict[str, object]) -> None:
        self._connection = connection

    def all(self) -> dict[str, dict[str, object]]:
        return {"kimi-code": copy.deepcopy(self._connection)}

    def is_verified(self, provider: str, connection: dict[str, object]) -> bool:
        return provider == "kimi-code" and connection == self._connection


def test_kimi_code_login_is_a_separate_honest_connection_product(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")

    development = resolve_runtime_profile(
        frozen=False,
        environment={"NACHUAN_RUNTIME_PROFILE": "development"},
    )
    store = resolve_runtime_profile(
        frozen=True,
        environment={"NACHUAN_RUNTIME_PROFILE": "development"},
    )
    catalog = {
        item["name"]: item for item in Router.__new__(Router).catalog_view()
    }

    assert development.allows_connection_type("kimi_code") is True
    assert development.allows_provider_type("kimi_code") is True
    assert store.allows_connection_type("kimi_code") is False
    assert store.allows_provider_type("kimi_code") is False

    kimi = catalog["kimi-code"]
    moonshot = catalog["moonshot"]
    assert kimi["type"] == "kimi_code"
    assert kimi["auth"] == "login"
    assert kimi["default_base_url"] == ""
    assert kimi["connectable"] is True
    assert [model["id"] for model in kimi["models"]] == [_PUBLIC_MODEL_ID]
    assert [model["upstream_model"] for model in kimi["models"]] == [
        _PUBLIC_MODEL_ID
    ]
    assert kimi["models"][0]["tool_capable"] is False
    assert moonshot["type"] == "openai_compat"
    assert moonshot["auth"] == "api_key"
    assert moonshot["default_base_url"].startswith("https://api.moonshot.")
    assert "k3" not in repr(kimi).casefold()

    normalized = normalize_connection_candidate(
        "kimi-code",
        _candidate(),
        verify_public=False,
    )
    assert normalized["type"] == "kimi_code"
    assert normalized["api_key"] == ""
    assert "base_url" not in normalized
    assert normalized["enabled_models"] == [_model()]

    keyed = copy.deepcopy(_candidate())
    keyed["api_key"] = "must-not-be-treated-as-a-moonshot-key"
    with pytest.raises(ValueError, match="API Key"):
        normalize_connection_candidate(
            "kimi-code",
            keyed,
            verify_public=False,
        )

    targeted = copy.deepcopy(_candidate())
    targeted["base_url"] = "https://api.moonshot.cn/v1"
    with pytest.raises(ValueError, match="base URL"):
        normalize_connection_candidate(
            "kimi-code",
            targeted,
            verify_public=False,
        )

    claimed = copy.deepcopy(_candidate())
    claimed["enabled_models"][0]["upstream_model"] = "kimi-code/k3"
    with pytest.raises(ValueError, match="kimi-code-subscription"):
        normalize_connection_candidate(
            "kimi-code",
            claimed,
            verify_public=False,
        )


def test_verified_kimi_route_reaches_models_without_claiming_actual_k3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")
    connection = normalize_connection_candidate(
        "kimi-code",
        _candidate(),
        verify_public=False,
    )
    router = Router(
        models_config={"providers": {}, "models": {}},
        store=_VerifiedStore(connection),
        kimi_worker=_Worker(),
        kimi_environment=_environment(tmp_path),
    )

    route = router.resolve(_PUBLIC_MODEL_ID)
    assert route is not None
    assert route.virtual_model == _PUBLIC_MODEL_ID
    assert route.upstream_model == _PUBLIC_MODEL_ID
    assert route.exec_backend == ""
    assert route.tool_capable is False
    assert route.model_family is None
    assert route.independence_domain == connection_independence_domain(connection)
    assert route.independence_domain is not None
    assert route.independence_domain != connection_independence_domain(
        {
            "type": "openai_compat",
            "base_url": "https://api.moonshot.cn/v1",
        }
    )

    with TestClient(app) as client:
        original_router = client.app.state.router
        client.app.state.router = router
        try:
            response = client.get(
                "/v1/models",
                headers={"Authorization": "Bearer test-key"},
            )
        finally:
            client.app.state.router = original_router

    assert response.status_code == 200
    models = {
        model["id"]: model for model in response.json()["data"]
    }
    public = models[_PUBLIC_MODEL_ID]
    assert public["owned_by"] == "kimi-code"
    assert public["chat_usable"] is True
    assert public["tool_capable"] is False
    assert public["review_vote_candidate"] is False
    assert public["review_strength"] is None
    assert "actual_served_model" not in public
    assert "k3" not in repr(public).casefold()
