"""P2 后端核心单元测试：跨平台 SecretStore、统一 OutboundGuard、隐私审计 API 与零遥测自证脚本。"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway import outbound_guard
from gateway.outbound_guard import (
    OutboundBlockedError,
    OutboundGuard,
    get_outbound_guard,
    install_httpx_outbound_guard,
    is_loopback_host,
)
from gateway.routes.privacy_audit import router as privacy_audit_router
from gateway.secret_store import (
    CrossPlatformSecretError,
    EncryptedFileSecretBackend,
    LinuxSecretServiceBackend,
    MacOSKeychainBackend,
    WindowsDPAPIBackend,
    read_secret_json,
    select_secret_store_backend,
    write_secret_json,
)


def test_is_loopback_host_blocks_spoofed_domains():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("127.77.77.77") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("LOCALHOST.") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("[::1]") is True

    assert is_loopback_host("127.0.0.1.evil.com") is False
    assert is_loopback_host("localhost.evil.com") is False
    assert is_loopback_host("api.openai.com") is False
    assert is_loopback_host("us.i.posthog.com") is False
    assert is_loopback_host("") is False


def test_outbound_guard_ring_buffer_and_offline_persistence(tmp_path: Path):
    state_file = tmp_path / "privacy_state.json"
    guard = OutboundGuard(max_entries=100, state_path=state_file)
    assert guard.is_offline_mode() is False

    # 正常模式记录一次外网与一次本地回环，且脱敏剥离 query 参数
    e1 = guard.record(
        method="POST",
        url="https://api.openai.com/v1/chat/completions?api_key=sk-secret-123",
        caller="gateway.providers.openai_compat:chat",
        status_code=200,
        latency_ms=123.456,
    )
    assert e1.path == "/v1/chat/completions"
    assert "sk-secret" not in e1.path
    assert e1.is_loopback is False
    assert e1.blocked is False

    e2 = guard.record(
        method="GET",
        url="http://127.0.0.1:11434/api/tags",
        caller="gateway.local_model:list",
        status_code=200,
        latency_ms=4.2,
    )
    assert e2.is_loopback is True

    # 开启纯离线模式：持久化落盘 + 拦截外网 + 放行回环
    res = guard.set_offline_mode(True, source="api", persist=True)
    assert res == {"enabled": True, "source": "api"}
    assert json.loads(state_file.read_text(encoding="utf-8")) == {"offline_mode": True}

    guard.check_allowed(method="GET", url="http://127.0.0.1:11434/api/tags", caller="test")
    with pytest.raises(OutboundBlockedError) as exc_info:
        guard.check_allowed(method="GET", url="https://cn.bing.com/search?q=secret", caller="gateway.websearch:search")
    assert exc_info.value.host == "cn.bing.com"

    snap = guard.snapshot(limit=10)
    assert snap["offline_mode"] is True
    assert snap["total_allowed"] == 2
    assert snap["total_blocked"] == 1
    assert snap["non_loopback_count"] == 1
    assert len(snap["items"]) == 3

    blocked_snap = guard.snapshot(blocked_only=True)
    assert len(blocked_snap["items"]) == 1
    assert blocked_snap["items"][0]["host"] == "cn.bing.com"
    assert blocked_snap["items"][0]["block_reason"] == "offline_mode"

    # 重建实例后应自动恢复持久化的纯离线状态
    guard_reloaded = OutboundGuard(max_entries=100, state_path=state_file)
    assert guard_reloaded.is_offline_mode() is True
    assert guard_reloaded.offline_mode_status()["source"] == "persisted"

    cleared = guard.clear()
    assert cleared == 3
    assert guard.snapshot()["items"] == []


@pytest.mark.asyncio
async def test_httpx_global_outbound_guard_blocks_sync_and_async():
    import httpx

    install_httpx_outbound_guard()
    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=True)
    try:
        with pytest.raises(OutboundBlockedError):
            with httpx.Client(timeout=1.0) as client:
                client.get("https://us.i.posthog.com/decide/")

        with pytest.raises(OutboundBlockedError):
            async with httpx.AsyncClient(timeout=1.0) as aclient:
                await aclient.post("https://api.anthropic.com/v1/messages", json={})

        snap = guard.snapshot()
        assert snap["total_blocked"] == 2
        assert snap["non_loopback_count"] == 0
        hosts = [item["host"] for item in snap["items"]]
        assert hosts == ["us.i.posthog.com", "api.anthropic.com"]
    finally:
        guard.reset_for_tests(offline_mode=False)


def test_privacy_audit_routes_contract(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from gateway import config as config_mod

    monkeypatch.setenv("GATEWAY_API_KEYS", "test-secret-key")
    config_mod.get_settings.cache_clear()

    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=False)
    guard.configure_state_path(tmp_path / "privacy_state.json")

    app = FastAPI()
    app.include_router(privacy_audit_router)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-secret-key"}

    try:
        # 未带 Key 必须 401 fail-closed
        assert client.get("/v1/privacy/outbound-audit").status_code == 401

        r_off = client.get("/v1/privacy/offline-mode", headers=headers)
        assert r_off.status_code == 200
        assert r_off.json()["enabled"] is False

        # 非法请求体（多余字段或非布尔）返回 422
        assert client.post("/v1/privacy/offline-mode", json={"enabled": "yes"}, headers=headers).status_code == 422
        assert client.post("/v1/privacy/offline-mode", json={"enabled": True, "extra": 1}, headers=headers).status_code == 422

        r_set = client.post("/v1/privacy/offline-mode", json={"enabled": True}, headers=headers)
        assert r_set.status_code == 200
        assert r_set.json()["enabled"] is True

        guard.record(method="GET", url="https://example.com/a", blocked=True, block_reason="offline_mode")
        r_audit = client.get("/v1/privacy/outbound-audit?blocked_only=true&limit=10", headers=headers)
        assert r_audit.status_code == 200
        body = r_audit.json()
        assert body["offline_mode"] is True
        assert body["total_blocked"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["host"] == "example.com"

        r_del = client.delete("/v1/privacy/outbound-audit", headers=headers)
        assert r_del.status_code == 200
        assert r_del.json() == {"ok": True, "cleared": 1}
    finally:
        guard.reset_for_tests(offline_mode=False)
        config_mod.get_settings.cache_clear()


def test_crossplatform_secret_store_all_backends(tmp_path: Path):
    # 1. EncryptedFileSecretBackend (headless Linux / container)
    key_file = tmp_path / "vault.key"
    doc_file = tmp_path / "connections.json"
    file_backend = EncryptedFileSecretBackend(key_file=key_file)
    write_secret_json(doc_file, {"openai": {"api_key": "sk-test-123"}}, purpose="nachuan/connections", backend=file_backend)
    raw_text = doc_file.read_text(encoding="utf-8")
    assert "sk-test-123" not in raw_text  # 绝不落明文
    loaded = read_secret_json(doc_file, purpose="nachuan/connections", backend=file_backend)
    assert loaded == {"openai": {"api_key": "sk-test-123"}}
    # purpose 域隔离：错误 purpose 解密必须 fail-closed
    with pytest.raises(CrossPlatformSecretError):
        read_secret_json(doc_file, purpose="nachuan/other", backend=file_backend)

    # 2. MacOSKeychainBackend（使用内存桩模拟 /usr/bin/security）
    fake_keychain: dict[tuple[str, str], str] = {}

    def fake_security_runner(cmd: list[str], **kwargs):
        sub = cmd[1]
        svc = cmd[cmd.index("-s") + 1]
        acc = cmd[cmd.index("-a") + 1]
        if sub == "find-generic-password":
            val = fake_keychain.get((svc, acc))
            if val is None:
                return subprocess.CompletedProcess(cmd, 44, "", "not found")
            return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
        if sub == "add-generic-password":
            val = cmd[cmd.index("-w") + 1]
            fake_keychain[(svc, acc)] = val
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(cmd)

    mac_backend = MacOSKeychainBackend(runner=fake_security_runner)
    mac_doc = tmp_path / "mac_conn.json"
    mac_backend.write_json(mac_doc, {"anthropic": {"key": "sk-ant-999"}}, purpose="nachuan/connections")
    assert "sk-ant-999" not in mac_doc.read_text(encoding="utf-8")
    assert mac_backend.read_json(mac_doc, purpose="nachuan/connections") == {"anthropic": {"key": "sk-ant-999"}}

    # 3. LinuxSecretServiceBackend（使用内存桩模拟 secret-tool）
    fake_libsecret: dict[tuple[str, str], str] = {}

    def fake_secret_tool(cmd: list[str], **kwargs):
        sub = cmd[1]
        svc = cmd[cmd.index("service") + 1]
        acc = cmd[cmd.index("account") + 1]
        if sub == "lookup":
            val = fake_libsecret.get((svc, acc))
            if val is None:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return subprocess.CompletedProcess(cmd, 0, val, "")
        if sub == "store":
            fake_libsecret[(svc, acc)] = str(kwargs.get("input") or "").strip()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(cmd)

    linux_backend = LinuxSecretServiceBackend(runner=fake_secret_tool)
    linux_doc = tmp_path / "linux_conn.json"
    linux_backend.write_json(linux_doc, {"deepseek": {"key": "sk-ds-888"}}, purpose="nachuan/connections")
    assert "sk-ds-888" not in linux_doc.read_text(encoding="utf-8")
    assert linux_backend.read_json(linux_doc, purpose="nachuan/connections") == {"deepseek": {"key": "sk-ds-888"}}

    # 4. 平台自动分发检查
    assert isinstance(select_secret_store_backend(platform_name="win32"), WindowsDPAPIBackend)
    assert isinstance(
        select_secret_store_backend(platform_name="darwin", which_fn=lambda _: "/usr/bin/security"),
        MacOSKeychainBackend,
    )
    assert isinstance(
        select_secret_store_backend(platform_name="linux", which_fn=lambda _: None),
        EncryptedFileSecretBackend,
    )


def test_verify_zero_telemetry_script_passes():
    from scripts.verify_zero_telemetry import run_all_checks

    report = run_all_checks()
    assert report["ok"] is True, json.dumps(report, ensure_ascii=False, indent=2)
    assert report["verdict"] == "ZERO_TELEMETRY_VERIFIED"
