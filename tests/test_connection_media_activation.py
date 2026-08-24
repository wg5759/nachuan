from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.app import app


AUTH = {"Authorization": "Bearer test-key"}


def test_agnes_connection_activates_catalog_media_without_paid_probe(
    approval_auth_headers, monkeypatch
) -> None:
    upstream_calls: list[tuple[str, str]] = []

    class _Headers(dict):
        def get_list(self, name: str) -> list[str]:
            value = self.get(name)
            return [] if value is None else [str(value)]

    class _ProviderResponse:
        status_code = 200
        text = ""
        headers = _Headers({"content-length": "128"})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        @staticmethod
        def json() -> dict:
            return {
                "id": "connection-check",
                "model": "agnes-2.0-flash",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            }

        async def aiter_bytes(self):
            yield json.dumps(self.json()).encode("utf-8")

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        def stream(self, method, url, *, headers, json):
            del headers
            upstream_calls.append((url, json["model"]))
            return _ProviderResponse()

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )

    with TestClient(app) as client:
        response = client.post(
            "/admin/connections/agnes",
            headers=approval_auth_headers,
            json={
                "type": "openai_compat",
                "api_key": "user-owned-agnes-key",
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
            },
        )

        assert response.status_code == 200
        assert response.json()["ok"] is True, response.json()
        assert response.json()["models"] == [
            "agnes-flash",
            "agnes-image",
            "agnes-video",
        ]
        assert response.json()["unprobed_models"] == [
            "agnes-image",
            "agnes-video",
        ]
        assert response.json()["rejected_models"] == []

        roster = {
            item["id"]: item
            for item in client.get("/v1/models", headers=AUTH).json()["data"]
        }
        assert roster["agnes-flash"]["modality"] == "chat"
        assert roster["agnes-image"]["modality"] == "image"
        assert roster["agnes-video"]["modality"] == "video"

        assert (
            client.delete(
                "/admin/connections/agnes", headers=approval_auth_headers
            ).status_code
            == 200
        )

    assert upstream_calls == [
        (
            "https://apihub.agnes-ai.com/v1/chat/completions",
            "agnes-2.0-flash",
        )
    ]
