"""用量看板：计费逻辑 + /admin/usage 聚合端点。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.pricing import cost_for

AUTH = {"Authorization": "Bearer test-key"}


def test_cost_for_billing_types():
    assert cost_for("agnes", 100, 100)["cost_usd"] == 0.0  # 免费
    assert cost_for("ollama", 100, 100)["cost_usd"] == 0.0  # 本地免费
    assert cost_for("claude_code", 0, 0, 0.047)["cost_usd"] == 0.047  # 自报实际
    assert cost_for("volcano", 100, 100)["cost_usd"] is None  # 套餐内不折算
    assert cost_for("codex", 100, 100)["cost_usd"] is None  # 套餐内
    c = cost_for("deepseek", 1_000_000, 1_000_000)
    assert c["cost_usd"] and c["cost_usd"] > 0 and "估算" in c["basis"]  # 按 token 估算


def test_usage_endpoint_aggregates_real_tokens():
    with TestClient(app) as c:
        # 产生两次 echo 调用 → 应被聚合
        for _ in range(2):
            c.post(
                "/v1/chat/completions",
                headers=AUTH,
                json={"model": "echo", "messages": [{"role": "user", "content": "hi"}]},
            )
        r = c.get("/admin/usage", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["financial_source"] is False
        assert data["financial_ledger_table"] == "provider_calls"
        assert data["total_cost_usd"] is None
        assert "legacy_estimated_cost_usd" in data
        echo = next((m for m in data["models"] if m["model"] == "echo"), None)
        assert echo is not None
        assert echo["calls"] >= 2
        assert echo["total_tokens"] > 0  # 真实 token，非空谈
        assert echo["cost_usd"] == 0.0  # echo 免费


def test_financial_usage_endpoint_reads_only_required_provider_call_ledger(
    tmp_path, monkeypatch
):
    ledger_path = tmp_path / "financial.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(ledger_path))

    with TestClient(app) as c:
        response = c.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={"model": "echo", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert response.status_code == 200
        result = c.get("/admin/financial-usage", headers=AUTH)

    assert result.status_code == 200
    data = result.json()
    assert data["financial_source"] is True
    assert data["ledger_table"] == "provider_calls"
    assert data["period"] == "month"
    assert data["period_start_utc"].endswith("Z")
    assert data["total_calls"] >= 1
    assert data["terminal_calls"] == data["total_calls"]
    assert data["in_flight_calls"] == 0
    assert data["unknown_cost_calls"] >= 1
    assert data["total_cost_usd"] is None
    echo = next(row for row in data["models"] if row["resolved_model"] == "echo")
    assert echo["identity_basis"] == "configured_upstream_unverified"
    assert echo["unknown_cost_calls"] >= 1
    assert echo["cost_usd"] is None


def test_financial_usage_period_is_a_closed_enum(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from gateway.app import app

    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(tmp_path / "period.db"))

    with TestClient(app) as client:
        assert client.get(
            "/admin/financial-usage?period=all", headers=AUTH
        ).json()["period"] == "all"
        invalid = client.get("/admin/financial-usage?period=quarter", headers=AUTH)

    assert invalid.status_code == 422
