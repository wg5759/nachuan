"""网关端到端测试（用 echo provider，无需任何上游密钥）。"""

from __future__ import annotations

import importlib
import hashlib
import hmac
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.config import get_settings
from gateway.secure_store import SecureStorageError

AUTH = {"Authorization": "Bearer test-key"}


def test_health():
    with TestClient(app) as c:
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_health_boot_proof_binds_the_desktop_child_without_disclosing_token(monkeypatch):
    token = "ab" * 32
    challenge = "cd" * 32
    monkeypatch.setenv("NACHUAN_ENGINE_BOOT_TOKEN", token)
    with TestClient(app) as c:
        body = c.get(f"/health?challenge={challenge}").json()
        missing = c.get("/health?challenge=not-hex").json()
    expected = hmac.new(
        bytes.fromhex(token), challenge.encode("ascii"), hashlib.sha256
    ).hexdigest()
    assert body["boot_proof"] == expected
    assert missing["boot_proof"] == ""
    assert token not in json.dumps(body)


def test_health_reports_database_provider_and_weixin_readiness_without_secrets():
    data_dir = Path(get_settings().usage_db_path).parent
    data_dir.mkdir(parents=True, exist_ok=True)
    token_file = data_dir / "ilink_token.json"
    health_file = data_dir / "weixin_bridge_health.json"
    token_file.write_text(json.dumps({"bot_token": "must-never-leak"}), encoding="utf-8")
    health_file.write_text(
        json.dumps(
            {
                "state": "healthy",
                "pid": 12345,
                "updated_at": time.time(),
                "pending_inbound": 2,
                "pending_outbound": 3,
                "dead_inbound": 4,
                "dead_outbound": 5,
                "last_error": "also-private-operational-detail",
            }
        ),
        encoding="utf-8",
    )
    try:
        with TestClient(app) as c:
            r = c.get("/health")
            assert r.status_code == 200
            body = r.json()
            assert body["checks"]["database"]["ready"] is True
            assert body["readiness"] == "degraded"
            assert body["checks"]["financial_ledger"]["required"] is False
            assert body["checks"]["financial_ledger"]["ready"] is False
            assert body["checks"]["financial_ledger"]["status"] == "disabled"
            provider_check = body["checks"]["providers"]
            live_models = app.state.router.list_models()
            live_providers = {
                str(model.get("owned_by") or "")
                for model in live_models
                if model.get("owned_by")
            }
            assert provider_check["count"] == len(live_providers)
            assert provider_check["ready"] is bool(live_providers)
            assert provider_check["model_count"] == len(live_models)
            weixin = body["checks"]["weixin"]
            assert {k: v for k, v in weixin.items() if k != "age_sec"} == {
                "configured": True,
                "state": "healthy",
                "fresh": True,
                "ready": False,
                "pending_inbound": 2,
                "pending_outbound": 3,
                "dead_inbound": 4,
                "dead_outbound": 5,
            }
            # TestClient startup can legitimately spend tens of seconds on slower
            # Windows builders.  Match the product's 120-second freshness policy
            # instead of imposing a stricter, timing-sensitive test-only limit.
            assert 0 <= weixin["age_sec"] <= 120
            raw = json.dumps(body)
            assert "must-never-leak" not in raw
            assert "also-private-operational-detail" not in raw
    finally:
        token_file.unlink(missing_ok=True)
        health_file.unlink(missing_ok=True)


def test_weixin_health_never_masks_secure_storage_failure_as_healthy(monkeypatch, tmp_path):
    gateway_app = importlib.import_module("gateway.app")
    (tmp_path / "weixin_bridge_health.json").write_text(
        json.dumps({"state": "healthy", "updated_at": time.time()}), encoding="utf-8"
    )

    def broken_store(*_args, **_kwargs):
        raise SecureStorageError("synthetic failure")

    monkeypatch.setattr(gateway_app, "read_protected_json", broken_store)
    result = gateway_app._weixin_readiness(tmp_path)

    assert result["configured"] is False
    assert result["state"] == "storage_error"
    assert result["ready"] is False


def test_models_requires_auth():
    with TestClient(app) as c:
        assert c.get("/v1/models").status_code == 401


def test_models_hides_echo():
    with TestClient(app) as c:
        r = c.get("/v1/models", headers=AUTH)
        assert r.status_code == 200
        ids = [m["id"] for m in r.json()["data"]]
        assert "echo" not in ids  # echo 仅作联通性兜底，不在模型列表露出（仍可直接调，见 test_echo_non_stream）


def test_echo_non_stream():
    with TestClient(app) as c:
        r = c.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={"model": "echo", "messages": [{"role": "user", "content": "你好"}]},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["object"] == "chat.completion"
        assert "你好" in data["choices"][0]["message"]["content"]
        assert data["usage"]["total_tokens"] > 0


def test_echo_stream():
    with TestClient(app) as c:
        with c.stream(
            "POST",
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "echo",
                "messages": [{"role": "user", "content": "hi there friend"}],
                "stream": True,
            },
        ) as r:
            assert r.status_code == 200
            body = "".join(list(r.iter_text()))
    assert "data:" in body
    assert "[DONE]" in body


def _stream_contract_request(client: TestClient, trace_id: str):
    return client.post(
        "/v1/chat/completions",
        headers={**AUTH, "X-Request-ID": trace_id},
        json={
            "model": "echo",
            "messages": [{"role": "user", "content": "stream contract"}],
            "stream": True,
        },
    )


def test_stream_provider_error_is_terminal_traced_and_not_recorded_as_ok(monkeypatch):
    gateway_app = importlib.import_module("gateway.app")
    statuses: list[str] = []
    memories: list[str] = []

    async def failed_stream(_router, _req):  # noqa: ANN001
        yield {"error": {"message": "all providers failed", "type": "provider_error"}}

    monkeypatch.setattr(gateway_app, "stream_with_fallback", failed_stream)
    monkeypatch.setattr(
        gateway_app,
        "_grow_memory",
        lambda _router, _user, assistant: memories.append(assistant),
    )
    with TestClient(app) as c:
        monkeypatch.setattr(
            c.app.state.usage,
            "log",
            lambda **kwargs: statuses.append(str(kwargs.get("status"))),
        )
        response = _stream_contract_request(c, "stream.full-fail")

    assert response.status_code == 200
    assert "all providers failed" in response.text
    assert '"trace_id": "stream.full-fail"' in response.text
    assert response.text.index("all providers failed") < response.text.index("data: [DONE]")
    assert statuses == ["error"]
    assert memories == []


def test_empty_stream_becomes_terminal_error_instead_of_ok(monkeypatch):
    gateway_app = importlib.import_module("gateway.app")
    statuses: list[str] = []
    memories: list[str] = []

    async def empty_stream(_router, _req):  # noqa: ANN001
        if False:
            yield {}

    monkeypatch.setattr(gateway_app, "stream_with_fallback", empty_stream)
    monkeypatch.setattr(
        gateway_app,
        "_grow_memory",
        lambda _router, _user, assistant: memories.append(assistant),
    )
    with TestClient(app) as c:
        monkeypatch.setattr(
            c.app.state.usage,
            "log",
            lambda **kwargs: statuses.append(str(kwargs.get("status"))),
        )
        response = _stream_contract_request(c, "stream.empty")

    assert '"type": "empty_stream"' in response.text
    assert '"trace_id": "stream.empty"' in response.text
    assert response.text.index('"type": "empty_stream"') < response.text.index("data: [DONE]")
    assert statuses == ["error"]
    assert memories == []


def test_midstream_error_never_falls_through_to_ok_or_partial_memory(monkeypatch):
    gateway_app = importlib.import_module("gateway.app")
    statuses: list[str] = []
    memories: list[str] = []

    async def broken_stream(_router, _req):  # noqa: ANN001
        yield {"choices": [{"delta": {"content": "partial"}}]}
        yield {"error": {"message": "idle timeout", "type": "stream_idle_timeout"}}

    monkeypatch.setattr(gateway_app, "stream_with_fallback", broken_stream)
    monkeypatch.setattr(
        gateway_app,
        "_grow_memory",
        lambda _router, _user, assistant: memories.append(assistant),
    )
    with TestClient(app) as c:
        monkeypatch.setattr(
            c.app.state.usage,
            "log",
            lambda **kwargs: statuses.append(str(kwargs.get("status"))),
        )
        response = _stream_contract_request(c, "stream.mid-fail")

    assert "partial" in response.text and "idle timeout" in response.text
    assert '"trace_id": "stream.mid-fail"' in response.text
    assert response.text.index("idle timeout") < response.text.index("data: [DONE]")
    assert statuses == ["error"]
    assert memories == []


def test_unknown_model_404():
    with TestClient(app) as c:
        r = c.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={"model": "does-not-exist", "messages": [{"role": "user", "content": "x"}]},
        )
        assert r.status_code == 404


def test_invalid_key_401():
    with TestClient(app) as c:
        r = c.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer wrong"},
            json={"model": "echo", "messages": [{"role": "user", "content": "x"}]},
        )
        assert r.status_code == 401


def test_chat_malformed_request_json_stays_client_400():
    """聊天接口收到客户端坏 JSON 时仍应明确归类为请求错误。"""

    with TestClient(app) as c:
        response = c.post(
            "/v1/chat/completions",
            headers={**AUTH, "Content-Type": "application/json"},
            content=b'{"model":"echo","messages":',
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "请求体不是合法 JSON"}


def test_chat_upstream_json_error_is_not_misclassified_as_client_400(monkeypatch):
    """上游解析错经 provider 规范化后必须保持 502，不能命中客户端坏 JSON handler。"""

    gateway_app = importlib.import_module("gateway.app")

    async def invalid_upstream(_router, _request):
        try:
            json.loads("<html>private upstream diagnostics: should-not-leak</html>")
        except json.JSONDecodeError as cause:
            from gateway.providers.base import ProviderError

            raise ProviderError("上游返回了无效 JSON", status_code=502) from cause
        raise AssertionError("fixture must raise JSONDecodeError")

    monkeypatch.setattr(gateway_app, "chat_with_fallback", invalid_upstream)
    with TestClient(app) as c:
        response = c.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "echo",
                "messages": [
                    {"role": "user", "content": "upstream-json-classification-boundary"}
                ],
            },
        )

    assert response.status_code == 502
    assert response.json() == {"detail": "上游服务异常（502）——上游临时故障，稍后重试"}
    assert "上游返回了无效 JSON" not in response.text
    assert "should-not-leak" not in response.text


def test_malformed_body_returns_clean_400():
    """坏 JSON / 非 UTF-8 请求体 → 干净的 400，而不是难看的 500（#22 稳健性）。"""
    with TestClient(app) as c:
        # 非法 JSON
        r1 = c.post("/v1/intent", headers=AUTH, content=b"{not json")
        assert r1.status_code == 400
        # 非 UTF-8 字节（GBK）
        r2 = c.post("/v1/intent", headers=AUTH, content=b'{"message": "\xb2\xe2"}')
        assert r2.status_code == 400
