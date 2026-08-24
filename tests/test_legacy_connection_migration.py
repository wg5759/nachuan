from __future__ import annotations

import asyncio
import json
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway import admin, local_model
from gateway.auth import require_api_key, require_approval_admin_key
from gateway.connections import ConnectionStore
from gateway.legacy_connections import migrate_legacy_desktop_connections
from gateway.router import Router
from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json,
)


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI migration contract")


def _legacy_path(roaming):
    return roaming / "aggregator-desktop" / "data" / "connections.json"


def test_existing_new_connection_document_is_authoritative(tmp_path) -> None:
    roaming = tmp_path / "roaming"
    data_dir = tmp_path / "Nachuan"
    source = _legacy_path(roaming)
    source.parent.mkdir(parents=True)
    source.write_text("{this legacy source must not be opened", encoding="utf-8")
    destination = data_dir / "connections.json"
    write_protected_json(
        destination,
        {"new-runtime": {"api_key": "new-runtime-secret"}},
        purpose="nachuan/connections",
    )
    before = destination.read_bytes()

    assert not migrate_legacy_desktop_connections(
        data_dir,
        roaming_app_data=roaming,
    )

    assert destination.read_bytes() == before
    assert read_protected_json(
        destination,
        purpose="nachuan/connections",
    ) == {"new-runtime": {"api_key": "new-runtime-secret"}}


def test_malformed_legacy_source_fails_closed_without_creating_destination(
    tmp_path,
) -> None:
    roaming = tmp_path / "roaming"
    data_dir = tmp_path / "Nachuan"
    source = _legacy_path(roaming)
    source.parent.mkdir(parents=True)
    source.write_text('{"schema":"unknown-protected-format"}', encoding="utf-8")

    with pytest.raises(SecureStorageError, match="保护格式"):
        migrate_legacy_desktop_connections(
            data_dir,
            roaming_app_data=roaming,
        )

    assert not (data_dir / "connections.json").exists()


def test_reparse_legacy_source_is_rejected(tmp_path) -> None:
    roaming = tmp_path / "roaming"
    data_dir = tmp_path / "Nachuan"
    source = _legacy_path(roaming)
    source.parent.mkdir(parents=True)
    real_source = tmp_path / "outside-connections.json"
    real_source.write_text("{}", encoding="utf-8")
    try:
        source.symlink_to(real_source)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(SecureStorageError, match="reparse"):
        migrate_legacy_desktop_connections(
            data_dir,
            roaming_app_data=roaming,
        )

    assert not (data_dir / "connections.json").exists()


def test_imported_agnes_credential_can_be_reverified_without_resubmitting_key(
    tmp_path, monkeypatch
) -> None:
    legacy_key = "synthetic-imported-agnes-key"
    roaming = tmp_path / "roaming"
    data_dir = tmp_path / "Nachuan"
    source = roaming / "aggregator-desktop" / "data" / "connections.json"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps(
            {
                "agnes": {
                    "type": "openai_compat",
                    "api_key": legacy_key,
                    "base_url": "https://apihub.agnes-ai.com/v1",
                    "enabled_models": [
                        {
                            "id": "agnes-flash",
                            "upstream_model": "agnes-2.0-flash",
                            "modality": "chat",
                        },
                        {
                            "id": "agnes-image",
                            "upstream_model": "agnes-image-2.1-flash",
                            "modality": "image",
                        },
                        {
                            "id": "agnes-video",
                            "upstream_model": "agnes-video-v2.0",
                            "modality": "video",
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    assert migrate_legacy_desktop_connections(
        data_dir,
        roaming_app_data=roaming,
    )

    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    authorization_headers: list[str] = []

    class _Headers:
        @staticmethod
        def get_list(_name):
            return []

    class _ProviderResponse:
        status_code = 200
        headers = _Headers()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield json.dumps(
                {
                    "id": "connect-check",
                    "model": "agnes-2.0-flash",
                    "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                }
            ).encode("utf-8")

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        def stream(self, _method, _url, *, headers, json):
            del json
            authorization_headers.append(headers.get("Authorization", ""))
            return _ProviderResponse()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    store = ConnectionStore(data_dir / "connections.json")
    imported = store.masked()["agnes"]
    assert imported["state"] == "legacy_unverified"
    assert imported["credential_present"] is True
    assert imported["credential_reverification_available"] is True

    live_router = Router(models_config={}, store=store)
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = live_router
    with TestClient(test_app) as client:
        response = client.post(
            "/admin/connections/agnes",
            json={
                "type": "openai_compat",
                "api_key": "",
                "base_url": "https://apihub.agnes-ai.com/v1",
                "enabled_models": [
                    {
                        "id": "agnes-flash",
                        "upstream_model": "agnes-2.0-flash",
                        "modality": "chat",
                    },
                    {
                        "id": "agnes-image",
                        "upstream_model": "agnes-image-2.1-flash",
                        "modality": "image",
                    },
                    {
                        "id": "agnes-video",
                        "upstream_model": "agnes-video-v2.0",
                        "modality": "video",
                    },
                ],
                "preserve_existing_credential": True,
            },
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True, response.json()
    assert authorization_headers == [f"Bearer {legacy_key}"]
    assert store.masked()["agnes"]["state"] == "verified"
    assert live_router.resolve("agnes-flash") is not None
    assert live_router.resolve("agnes-image") is not None
    assert live_router.resolve("agnes-video") is not None
    asyncio.run(live_router.aclose())


def test_imported_credential_reverification_binding_rejects_target_drift(
    tmp_path,
) -> None:
    roaming = tmp_path / "roaming"
    data_dir = tmp_path / "Nachuan"
    source = _legacy_path(roaming)
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps(
            {
                "agnes": {
                    "type": "openai_compat",
                    "api_key": "synthetic-imported-agnes-key",
                    "base_url": "https://apihub.agnes-ai.com/v1",
                    "enabled_models": [
                        {
                            "id": "agnes-flash",
                            "upstream_model": "agnes-2.0-flash",
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    assert migrate_legacy_desktop_connections(
        data_dir,
        roaming_app_data=roaming,
    )
    store = ConnectionStore(data_dir / "connections.json")
    imported = store.get("agnes")
    assert imported is not None
    assert store.can_reverify_imported_credential("agnes", imported)

    imported["base_url"] = "https://api.openai.com/v1"
    store.set("agnes", imported)

    drifted = store.get("agnes")
    assert drifted is not None
    assert not store.can_reverify_imported_credential("agnes", drifted)
    assert "credential_reverification_available" not in store.masked()["agnes"]
