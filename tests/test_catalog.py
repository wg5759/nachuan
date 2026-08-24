"""厂商预设目录测试：广覆盖（国内/海外/本地）+ 模型项结构。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.config import load_models_config

AUTH = {"Authorization": "Bearer test-key"}


def test_catalog_breadth_and_regions():
    with TestClient(app) as c:
        provs = c.get("/admin/catalog", headers=AUTH).json()["providers"]
        names = {p["name"] for p in provs}
        # 关键厂商：国内 + 海外 + 本地；停用厂商不作为预设暴露。
        assert {"volcano", "deepseek", "openai", "gemini", "ollama", "agnes"} <= names
        regions = {p["region"] for p in provs}
        assert {"cn", "intl", "local"} <= regions
        for p in provs:
            assert p.get("label") and p.get("auth")


def test_catalog_models_have_upstream():
    with TestClient(app) as c:
        provs = {p["name"]: p for p in c.get("/admin/catalog", headers=AUTH).json()["providers"]}
        assert any(m["upstream_model"] == "deepseek-chat" for m in provs["deepseek"]["models"])
        # 本地 Ollama 无需鉴权
        assert provs["ollama"]["auth"] == "none"


def test_catalog_exposes_safe_simple_discovery_and_international_endpoints():
    with TestClient(app) as c:
        provs = {
            p["name"]: p
            for p in c.get("/admin/catalog", headers=AUTH).json()["providers"]
        }
        for name in (
            "moonshot",
            "qianfan",
            "minimax_api",
            "xai",
            "mistral",
            "perplexity",
        ):
            assert provs[name]["auto_discover_models"] is True

        assert (
            provs["minimax_intl"]["default_base_url"]
            == "https://api.minimax.io/v1"
        )
        assert (
            provs["siliconflow_intl"]["default_base_url"]
            == "https://api.siliconflow.com/v1"
        )


def test_catalog_does_not_offer_disabled_claude_connections_or_models():
    with TestClient(app) as c:
        providers = c.get("/admin/catalog", headers=AUTH).json()["providers"]

    assert {provider["name"] for provider in providers}.isdisjoint(
        {"claude_code", "anthropic"}
    )
    exposed_models = [
        model
        for provider in providers
        for model in provider.get("models", [])
    ]
    assert all(
        "claude" not in str(model.get(field, "")).casefold()
        for model in exposed_models
        for field in ("id", "upstream_model", "description")
    )


def test_default_route_config_contains_no_claude_provider_or_model():
    configured = load_models_config()
    assert "claude_code" not in configured.get("providers", {})
    assert all(
        "claude" not in str(value).casefold()
        for model_id, model in configured.get("models", {}).items()
        for value in (model_id, model.get("provider"), model.get("upstream_model"))
    )
