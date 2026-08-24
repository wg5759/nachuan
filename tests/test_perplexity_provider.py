from __future__ import annotations

import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.catalog import preset
from gateway.connections import normalize_connection_candidate
from gateway.providers.base import ProviderError
from gateway.providers.perplexity import (
    PERPLEXITY_CHAT_COMPLETIONS_URL,
    PERPLEXITY_MODEL_CATALOG_URL,
    PERPLEXITY_OFFICIAL_BASE_URL,
    PERPLEXITY_SONAR_API_URL,
    PerplexityProvider,
    perplexity_model_catalog_url,
)
from gateway.router import connection_independence_domain
from gateway.schemas import ChatCompletionRequest


def _candidate(
    *,
    provider_type: str = "perplexity",
    base_url: str = PERPLEXITY_OFFICIAL_BASE_URL,
    models: list[dict] | None = None,
) -> dict:
    return {
        "type": provider_type,
        "api_key": "pplx-test-key",
        "base_url": base_url,
        "enabled_models": models
        or [{"id": "sonar", "upstream_model": "sonar"}],
    }


def _request() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="sonar",
        messages=[{"role": "user", "content": "ping"}],
        stream=False,
        max_tokens=1,
    )


def _valid_chat_payload() -> dict:
    return {
        "id": "pplx-probe",
        "model": "sonar",
        "choices": [
            {"message": {"role": "assistant", "content": "ok"}}
        ],
    }


def test_perplexity_candidate_requires_the_dedicated_exact_official_target():
    normalized = normalize_connection_candidate("perplexity", _candidate())
    assert normalized["type"] == "perplexity"
    assert normalized["base_url"] == PERPLEXITY_OFFICIAL_BASE_URL

    with pytest.raises(ValueError, match="专用连接协议"):
        normalize_connection_candidate(
            "perplexity-generic",
            _candidate(provider_type="openai_compat"),
        )
    for unsafe_base in (
        "https://api.perplexity.ai/v1",
        "https://api.perplexity.ai:444",
    ):
        with pytest.raises(ValueError):
            normalize_connection_candidate(
                "perplexity-wrong-target",
                _candidate(base_url=unsafe_base),
            )


def test_perplexity_catalog_and_independence_domain_are_not_generic_aliases():
    catalog_entry = preset("perplexity")
    assert catalog_entry is not None
    assert catalog_entry["type"] == "perplexity"
    assert catalog_entry["base_url"] == PERPLEXITY_OFFICIAL_BASE_URL

    dedicated_domain = connection_independence_domain(_candidate())
    generic_alias = connection_independence_domain(
        _candidate(provider_type="openai_compat")
    )
    assert dedicated_domain is not None
    assert dedicated_domain == generic_alias


async def test_perplexity_endpoint_map_never_uses_generic_base_concatenation():
    assert (
        perplexity_model_catalog_url(PERPLEXITY_OFFICIAL_BASE_URL)
        == PERPLEXITY_MODEL_CATALOG_URL
        == "https://api.perplexity.ai/v1/models"
    )
    provider = PerplexityProvider(
        "perplexity", PERPLEXITY_OFFICIAL_BASE_URL, "pplx-test-key"
    )
    try:
        assert provider._endpoint == PERPLEXITY_CHAT_COMPLETIONS_URL
        assert provider.model_catalog_endpoint == PERPLEXITY_MODEL_CATALOG_URL
        assert provider.sonar_endpoint == PERPLEXITY_SONAR_API_URL
        assert provider.expected_model_family("sonar") == "perplexity-sonar"
    finally:
        await provider.aclose()


@respx.mock
async def test_perplexity_probe_uses_chat_alias_and_rejects_redirects():
    route = respx.post(PERPLEXITY_CHAT_COMPLETIONS_URL).mock(
        return_value=httpx.Response(200, json=_valid_chat_payload())
    )
    provider = PerplexityProvider(
        "perplexity", PERPLEXITY_OFFICIAL_BASE_URL, "pplx-test-key"
    )
    try:
        result = await provider.probe_chat(_request(), "sonar")
    finally:
        await provider.aclose()
    assert result["model"] == "sonar"
    assert route.called

    route.reset()
    route.mock(
        return_value=httpx.Response(
            307,
            headers={"location": "https://example.invalid/credential-capture"},
        )
    )
    provider = PerplexityProvider(
        "perplexity", PERPLEXITY_OFFICIAL_BASE_URL, "pplx-test-key"
    )
    try:
        with pytest.raises(ProviderError, match="拒绝重定向"):
            await provider.probe_chat(_request(), "sonar")
    finally:
        await provider.aclose()
    assert route.call_count == 1


def test_perplexity_zero_config_connect_uses_split_official_paths(
    approval_auth_headers, monkeypatch
):
    requested: list[tuple[str, str, str]] = []

    class _Response:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.status_code = status_code
            self._body = json.dumps(payload).encode("utf-8")
            self.headers = httpx.Headers(
                {"content-length": str(len(self._body))}
            )

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield self._body

    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args
            assert kwargs["follow_redirects"] is False
            assert kwargs["trust_env"] is True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url, *, headers, json=None):
            requested.append((method, url, headers.get("Authorization", "")))
            if method == "GET":
                assert json is None
                return _Response(
                    {
                        "data": [
                            {"id": "sonar"},
                            {"id": "text-embedding-perplexity"},
                        ]
                    }
                )
            assert method == "POST"
            assert json["model"] == "sonar"
            return _Response(_valid_chat_payload())

        async def aclose(self):
            return None

    monkeypatch.setattr(httpx, "AsyncClient", _ProviderClient)
    provider_name = "perplexity-adapter-test"
    with TestClient(app) as client:
        response = client.post(
            f"/admin/connections/{provider_name}",
            headers=approval_auth_headers,
            json={
                "type": "perplexity",
                "api_key": "pplx-test-key",
                "base_url": PERPLEXITY_OFFICIAL_BASE_URL,
                "enabled_models": [],
            },
        )
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert response.json()["models"] == ["sonar"]
        assert client.delete(
            f"/admin/connections/{provider_name}",
            headers=approval_auth_headers,
        ).status_code == 200

    assert requested == [
        ("GET", PERPLEXITY_MODEL_CATALOG_URL, "Bearer pplx-test-key"),
        ("POST", PERPLEXITY_CHAT_COMPLETIONS_URL, "Bearer pplx-test-key"),
    ]
    assert all(url != "https://api.perplexity.ai/models" for _, url, _ in requested)
    assert all(url != PERPLEXITY_SONAR_API_URL for _, url, _ in requested)
