"""P2 后端专项测试：跨平台 SecretStore、出站审计与纯离线硬拦截、隐私 API 与 8 项零遥测自证。"""

from __future__ import annotations

import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import urllib.request
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway import app as app_mod
from gateway import config as config_mod
from gateway import local_model
from gateway import secure_store
from gateway import websearch
from gateway.outbound_guard import (
    AuditedAsyncTransport,
    AuditedSyncTransport,
    OfflineModeBlockedError,
    OutboundAuditBuffer,
    OutboundBlockedError,
    OutboundGuard,
    check_outbound_allowed,
    create_async_client,
    create_sync_client,
    get_outbound_guard,
    install_httpx_outbound_guard,
    is_loopback_host,
    is_offline_mode,
    set_offline_mode,
    socket_offline_guard,
)
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.public_media import fetch_public_text
from gateway.schemas import ChatCompletionRequest, ChatMessage
from gateway.secret_store import (
    CrossPlatformSecretError,
    ENVELOPE_SCHEMA_V1,
    LinuxSecretServiceBackend,
    LocalKdfSecretBackend,
    MacOSKeychainBackend,
    PROTECTION_LINUX_SECRET_SERVICE,
    PROTECTION_LOCAL_KDF,
    PROTECTION_MACOS_KEYCHAIN,
    PROTECTION_WINDOWS_DPAPI,
    WindowsDPAPIBackend,
    backend_for_protection,
    read_secret_json,
    select_secret_store_backend,
    write_secret_json,
    write_secret_json_if_absent,
)
from orchestrator import cloud_sync, imagehost


# ── P2-1: 跨平台 SecretStore 四后端与 fail-closed 测试 ─────────────────────────


def _make_fake_security_runner(store: dict[tuple[str, str], str]):
    calls: list[list[str]] = []

    def _runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        sub = cmd[1]
        svc = cmd[cmd.index("-s") + 1]
        acc = cmd[cmd.index("-a") + 1]
        if sub == "find-generic-password":
            val = store.get((svc, acc))
            if val is None:
                return subprocess.CompletedProcess(cmd, 44, "", "not found")
            return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
        if sub == "add-generic-password":
            store[(svc, acc)] = cmd[cmd.index("-w") + 1]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected security cmd: {cmd}")

    return _runner, calls


def _make_fake_secret_tool_runner(store: dict[tuple[str, str, str], str]):
    calls: list[list[str]] = []

    def _runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        sub = cmd[1]
        app_name = cmd[cmd.index("app") + 1]
        svc = cmd[cmd.index("service") + 1]
        acc = cmd[cmd.index("account") + 1]
        if sub == "lookup":
            val = store.get((app_name, svc, acc))
            if val is None:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return subprocess.CompletedProcess(cmd, 0, val, "")
        if sub == "store":
            store[(app_name, svc, acc)] = str(kwargs.get("input") or "").strip()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected secret-tool cmd: {cmd}")

    return _runner, calls


def test_p2_1_macos_keychain_backend_roundtrip_tamper_and_no_plaintext(tmp_path: Path):
    keychain: dict[tuple[str, str], str] = {}
    runner, calls = _make_fake_security_runner(keychain)
    backend = MacOSKeychainBackend(runner=runner)

    target = tmp_path / "mac-secrets.json"
    payload = {"openai": {"api_key": "sk-mac-super-secret-001"}}
    backend.write_json(target, payload, purpose="nachuan/connections")

    raw_bytes = target.read_bytes()
    assert b"sk-mac-super-secret-001" not in raw_bytes
    doc = json.loads(raw_bytes.decode("utf-8"))
    assert doc["schema"] == ENVELOPE_SCHEMA_V1
    assert doc["protection"] == PROTECTION_MACOS_KEYCHAIN
    assert doc["kdf"] == "hkdf-sha256"
    # 验证 service 名严格对齐 com.nachuan.runtime-master-key
    assert any("com.nachuan.runtime-master-key" in c for c in calls)

    # 正常往返解密
    assert backend.read_json(target, purpose="nachuan/connections") == payload

    # purpose 域隔离：错误 purpose 必须 fail-closed
    with pytest.raises(CrossPlatformSecretError):
        backend.read_json(target, purpose="nachuan/wrong-purpose")

    # 篡改密文 1 bit 必须被 AES-256-GCM 认证拒绝
    tampered = dict(doc)
    raw_ct = bytearray(base64.b64decode(tampered["ciphertext"]))
    raw_ct[0] ^= 0x01
    tampered["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")
    tampered_path = tmp_path / "mac-tampered.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CrossPlatformSecretError, match="认证校验失败"):
        backend.read_json(tampered_path, purpose="nachuan/connections")


def test_p2_1_linux_secret_service_backend_roundtrip_and_tamper(tmp_path: Path):
    keyring: dict[tuple[str, str, str], str] = {}
    runner, calls = _make_fake_secret_tool_runner(keyring)
    backend = LinuxSecretServiceBackend(runner=runner)

    target = tmp_path / "linux-secrets.json"
    payload = {"deepseek": {"api_key": "sk-linux-secret-002"}}
    backend.write_json(target, payload, purpose="nachuan/connections")

    raw_bytes = target.read_bytes()
    assert b"sk-linux-secret-002" not in raw_bytes
    doc = json.loads(raw_bytes.decode("utf-8"))
    assert doc["schema"] == ENVELOPE_SCHEMA_V1
    assert doc["protection"] == PROTECTION_LINUX_SECRET_SERVICE
    assert doc["kdf"] == "hkdf-sha256"
    assert any("app" in c and "nachuan" in c for c in calls)

    assert backend.read_json(target, purpose="nachuan/connections") == payload

    # 原子 create-if-absent：绝不覆盖既有文档
    assert (
        backend.write_json_if_absent(
            target, {"deepseek": {"api_key": "sk-overwrite"}}, purpose="nachuan/connections"
        )
        is False
    )
    assert backend.read_json(target, purpose="nachuan/connections") == payload

    # 篡改 nonce 必须被拒绝
    tampered = dict(doc)
    raw_nonce = bytearray(base64.b64decode(tampered["nonce"]))
    raw_nonce[-1] ^= 0xFF
    tampered["nonce"] = base64.b64encode(bytes(raw_nonce)).decode("ascii")
    tampered_path = tmp_path / "linux-tampered.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CrossPlatformSecretError):
        backend.read_json(tampered_path, purpose="nachuan/connections")


def test_p2_1_local_kdf_scrypt_passphrase_keyfile_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("NACHUAN_SECRET_FALLBACK_PASSPHRASE", raising=False)
    monkeypatch.delenv("NACHUAN_MASTER_KEY", raising=False)
    monkeypatch.delenv("NACHUAN_SECRET_KEYFILE", raising=False)

    # 1) 未配置任何口令/keyfile 时严格 fail-closed，绝不回退明文！
    unconfigured = LocalKdfSecretBackend()
    assert unconfigured.is_configured() is False
    target_fail = tmp_path / "should-not-exist.json"
    with pytest.raises(CrossPlatformSecretError, match="fail-closed"):
        unconfigured.write_json(target_fail, {"k": "v"}, purpose="test/fail-closed")
    assert not target_fail.exists()

    with pytest.raises(CrossPlatformSecretError):
        select_secret_store_backend(
            platform_name="linux", which_fn=lambda _: None, strict=True
        )

    # 2) 通过 NACHUAN_SECRET_FALLBACK_PASSPHRASE 使用 scrypt + AES-256-GCM 加解密
    monkeypatch.setenv("NACHUAN_SECRET_FALLBACK_PASSPHRASE", "CorrectHorseBatteryStaple!2026")
    env_backend = LocalKdfSecretBackend()
    assert env_backend.is_configured() is True
    doc_path = tmp_path / "kdf-env.json"
    secret_payload = {"volcano": {"api_key": "sk-scrypt-secret-003"}}
    write_secret_json(doc_path, secret_payload, purpose="test/scrypt", backend=env_backend)

    raw_bytes = doc_path.read_bytes()
    assert b"sk-scrypt-secret-003" not in raw_bytes
    envelope = json.loads(raw_bytes.decode("utf-8"))
    assert envelope["schema"] == ENVELOPE_SCHEMA_V1
    assert envelope["protection"] == PROTECTION_LOCAL_KDF
    assert envelope["kdf"] == "scrypt"

    # 根据信封 protection 自动分发解密（无需手动传 backend）
    assert read_secret_json(doc_path, purpose="test/scrypt") == secret_payload

    # Windows 下通过 gateway.secure_store.read_protected_json 也能按 protection 字段分发解密
    if os.name == "nt":
        assert (
            secure_store.read_protected_json(doc_path, purpose="test/scrypt")
            == secret_payload
        )

    # 更换错误口令必须 fail-closed
    monkeypatch.setenv("NACHUAN_SECRET_FALLBACK_PASSPHRASE", "WrongPassphraseButLongEnough!")
    with pytest.raises(CrossPlatformSecretError):
        read_secret_json(doc_path, purpose="test/scrypt")

    # 3) 通过受控 keyfile 模式
    monkeypatch.delenv("NACHUAN_SECRET_FALLBACK_PASSPHRASE", raising=False)
    kf = tmp_path / "controlled.key"
    kf_backend = LocalKdfSecretBackend(key_file=kf)
    kf_doc = tmp_path / "kf-doc.json"
    assert write_secret_json_if_absent(
        kf_doc, {"claude": {"api_key": "sk-keyfile-004"}}, purpose="test/kf", backend=kf_backend
    ) is True
    assert write_secret_json_if_absent(
        kf_doc, {"claude": {"api_key": "sk-overwrite"}}, purpose="test/kf", backend=kf_backend
    ) is False
    assert b"sk-keyfile-004" not in kf_doc.read_bytes()
    assert kf_backend.read_json(kf_doc, purpose="test/kf") == {
        "claude": {"api_key": "sk-keyfile-004"}
    }

    # 4) backend_for_protection 分发映射与未知 protection 拒绝
    assert isinstance(backend_for_protection(PROTECTION_WINDOWS_DPAPI), WindowsDPAPIBackend)
    assert isinstance(backend_for_protection(PROTECTION_MACOS_KEYCHAIN), MacOSKeychainBackend)
    assert isinstance(
        backend_for_protection(PROTECTION_LINUX_SECRET_SERVICE), LinuxSecretServiceBackend
    )
    assert isinstance(backend_for_protection(PROTECTION_LOCAL_KDF), LocalKdfSecretBackend)
    with pytest.raises(CrossPlatformSecretError):
        backend_for_protection("plaintext-unsupported")


# ── P2-2: OutboundAuditBuffer、AuditedTransport、纯离线硬拦截与兜底 Socket ──


def test_p2_2_audit_buffer_ring_overflow_and_redaction():
    buf = OutboundAuditBuffer(maxlen=5)
    for idx in range(8):
        buf.record(
            method="POST",
            url=f"https://api.example.com/v1/item/{idx}?api_key=sk-secret-{idx}&token=xyz",
            caller="test.ring",
            status_code=200,
            latency_ms=10.5,
            error=f"Bearer sk-leak-{idx} failed at ?secret=123",
        )
    snap = buf.snapshot(limit=10)
    assert len(snap["items"]) == 5
    assert [it["id"] for it in snap["items"]] == [4, 5, 6, 7, 8]
    assert snap["total_allowed"] == 8
    assert snap["non_loopback_count"] == 8
    dumped = json.dumps(snap, ensure_ascii=False)
    assert "sk-secret" not in dumped
    assert "sk-leak" not in dumped
    assert "api_key=" not in dumped
    assert "?" not in dumped


class _MiniLoopbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@pytest.mark.asyncio
async def test_p2_2_audited_transports_single_record_and_offline_block():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MiniLoopbackHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    install_httpx_outbound_guard()
    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=False)
    try:
        # 1) 同步 AuditedSyncTransport 请求本地回环：仅记 1 条（不与全局钩子重复记账），且脱敏
        with create_sync_client(caller="test.sync_caller", timeout=5.0) as sc:
            assert isinstance(sc._transport, AuditedSyncTransport)
            r1 = sc.get(
                f"http://127.0.0.1:{port}/ping?api_key=leak-sync",
                headers={"Authorization": "Bearer sk-sync-secret"},
            )
            assert r1.status_code == 200

        # 2) 异步 AuditedAsyncTransport 请求本地回环：仅记 1 条
        async with create_async_client(caller="test.async_caller", timeout=5.0) as ac:
            assert isinstance(ac._transport, AuditedAsyncTransport)
            r2 = await ac.get(
                f"http://127.0.0.1:{port}/async-ping?token=leak-async",
                headers={"Authorization": "Bearer sk-async-secret"},
            )
            assert r2.status_code == 200

        snap = guard.snapshot(limit=20)
        assert snap["total_allowed"] == 2
        assert snap["non_loopback_count"] == 0
        assert [i["caller"] for i in snap["items"]] == [
            "test.sync_caller",
            "test.async_caller",
        ]
        assert [i["path"] for i in snap["items"]] == ["/ping", "/async-ping"]
        serialized = json.dumps(snap)
        assert "leak-sync" not in serialized
        assert "leak-async" not in serialized
        assert "sk-sync-secret" not in serialized
        assert "sk-async-secret" not in serialized

        # 3) 开启纯离线模式：本地回环仍放行，所有非回环立刻抛 OfflineModeBlockedError
        set_offline_mode(True, source="test", persist=False)
        assert is_offline_mode() is True
        assert OfflineModeBlockedError is OutboundBlockedError

        with create_sync_client(caller="test.sync_offline", timeout=2.0) as sc:
            assert sc.get(f"http://127.0.0.1:{port}/still-ok").status_code == 200
            with pytest.raises(OfflineModeBlockedError) as exc_sync:
                sc.get("https://api.openai.com/v1/models")
            assert exc_sync.value.host == "api.openai.com"

        async with create_async_client(caller="test.async_offline", timeout=2.0) as ac:
            with pytest.raises(OfflineModeBlockedError) as exc_async:
                await ac.post("https://api.anthropic.com/v1/messages", json={})
            assert exc_async.value.host == "api.anthropic.com"

        # 4) 进程级兜底 socket 离线保护：拦截绕过 httpx 的 urllib 与裸 socket.create_connection
        with socket_offline_guard():
            with pytest.raises(OfflineModeBlockedError):
                socket.create_connection(("93.184.216.34", 443), timeout=1.0)
            with pytest.raises(OfflineModeBlockedError):
                urllib.request.urlopen("https://example.com/bypass", timeout=1.0)
            # 本地回环 urllib 放行
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/urllib-ok", timeout=2.0) as resp:
                assert resp.status == 200

        blocked = guard.snapshot(blocked_only=True, limit=50)
        assert blocked["total_blocked"] >= 4
        assert blocked["non_loopback_count"] == 0
    finally:
        guard.reset_for_tests(offline_mode=False)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


@pytest.mark.asyncio
async def test_p2_2_all_core_outbound_wrappers_blocked_in_offline_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """验证 5 大核心外发封装点（openai_compat / public_media+websearch / cloud_sync / imagehost / local_model）均硬拦截。"""
    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=True)
    try:
        # 1. OpenAICompatProvider
        provider = OpenAICompatProvider("openai", "https://api.openai.com/v1", "sk-test")
        try:
            req = ChatCompletionRequest(
                model="gpt-5.4",
                messages=[ChatMessage(role="user", content="hello")],
            )
            with pytest.raises(OfflineModeBlockedError):
                await provider.chat(req, "gpt-5.4")
        finally:
            await provider.aclose()

        # 2. public_media & websearch
        with pytest.raises(OfflineModeBlockedError):
            fetch_public_text(
                "https://example.com/doc",
                max_bytes=1024,
                max_chars=1024,
                allowed_type_prefixes=("text/",),
            )
        with pytest.raises(OfflineModeBlockedError):
            await websearch.search("测试离线搜索", n=2, timeout=2.0)

        # 3. imagehost
        with pytest.raises(OfflineModeBlockedError):
            imagehost.upload_image(b"\x89PNG\r\n\x1a\n1234")

        # 4. cloud_sync
        monkeypatch.setattr(
            cloud_sync,
            "load_cfg",
            lambda: {
                "url": "https://demo.supabase.co",
                "anon_key": "anon-key",
                "access_token": "",
                "refresh_token": "",
                "user_id": "",
                "email": "",
                "local_user": "owner",
                "device_id": "dev-1",
                "enabled": False,
                "target_epoch": 1,
                "last_sync": {},
            },
        )
        with pytest.raises(OfflineModeBlockedError):
            cloud_sync.login("a@b.com", "pw")

        # 5. local_model.download_model
        monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD", "1")
        monkeypatch.setenv("LOCAL_MODEL_REVISION", "a" * 40)
        monkeypatch.setenv("LOCAL_MODEL_SHA256", "b" * 64)
        with pytest.raises(OfflineModeBlockedError):
            local_model.download_model("qwen2.5-0.5b", dest_dir=str(tmp_path / "models"))

        snap = guard.snapshot(blocked_only=True, limit=50)
        assert snap["total_blocked"] >= 6
        assert snap["non_loopback_count"] == 0
    finally:
        guard.reset_for_tests(offline_mode=False)


# ── P2-3: 隐私审计 HTTP API、privacy_prefs.json 持久化、/health 与 HTTP 503 ──


def test_p2_3_privacy_api_health_features_persistence_and_503_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("GATEWAY_API_KEYS", "p2-api-key")
    monkeypatch.setenv("NACHUAN_CONFIG_ENV_ONLY", "1")
    monkeypatch.delenv("NACHUAN_OFFLINE_MODE", raising=False)
    config_mod.get_settings.cache_clear()
    app_mod._public_fastapi_app.middleware_stack = None

    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=False)
    headers = {"Authorization": "Bearer p2-api-key"}
    try:
        with TestClient(app_mod.app) as client:
            # /health features 包含 offline_mode 与 outbound_audit
            h0 = client.get("/health").json()
            assert h0["features"]["offline_mode"] is False
            assert h0["features"]["outbound_audit"] is True

            # 未鉴权返回 401
            assert client.get("/v1/privacy/outbound-audit").status_code == 401
            assert client.get("/v1/privacy/offline-mode").status_code == 401

            # 热开启纯离线模式并持久化到 data_dir/privacy_prefs.json
            r_on = client.post(
                "/v1/privacy/offline-mode",
                headers=headers,
                json={"enabled": True},
            )
            assert r_on.status_code == 200
            assert r_on.json()["enabled"] is True

            prefs_file = tmp_path / "privacy_prefs.json"
            assert prefs_file.is_file()
            assert json.loads(prefs_file.read_text(encoding="utf-8"))["offline_mode"] is True

            # /health 实时反映 offline_mode=True
            assert client.get("/health").json()["features"]["offline_mode"] is True

            # 触发公网调用的聊天路由在纯离线模式下返回清晰 HTTP 503 offline_mode_blocked
            remote_provider = OpenAICompatProvider(
                "openai", "https://api.openai.com/v1", "sk-remote"
            )
            from types import SimpleNamespace

            class _RemoteRouter:
                def resolve(self, model: str):
                    return SimpleNamespace(
                        virtual_model=model,
                        provider=remote_provider,
                        upstream_model="gpt-5.4",
                        tier="premium",
                        rank=1,
                        independence_domain="dom:openai",
                    )

                def routes_info(self):
                    return [
                        {
                            "model": "gpt-5.4",
                            "tier": "premium",
                            "provider": "openai",
                            "upstream_model": "gpt-5.4",
                            "independence_domain": "dom:openai",
                            "modality": "chat",
                            "rank": 1,
                            "flagship": False,
                        }
                    ]

            prev_router = app_mod.app.state.router
            app_mod.app.state.router = _RemoteRouter()
            try:
                r_chat = client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "gpt-5.4",
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            finally:
                app_mod.app.state.router = prev_router
                asyncio.run(remote_provider.aclose())

            assert r_chat.status_code == 503
            err_body = r_chat.json()
            assert err_body["error"] == "offline_mode_blocked"
            assert err_body["host"] == "api.openai.com"

            # 查询审计日志：since_id / blocked_only / DELETE
            r_audit = client.get(
                "/v1/privacy/outbound-audit?limit=100&since_id=0&blocked_only=true",
                headers=headers,
            )
            assert r_audit.status_code == 200
            audit_json = r_audit.json()
            assert audit_json["offline_mode"] is True
            assert audit_json["total_blocked"] >= 1
            assert audit_json["non_loopback_count"] == 0
            assert any(i["host"] == "api.openai.com" for i in audit_json["items"])

            last_id = audit_json["items"][-1]["id"]
            r_since = client.get(
                f"/v1/privacy/outbound-audit?since_id={last_id}",
                headers=headers,
            )
            assert r_since.json()["items"] == []

            r_clear = client.delete("/v1/privacy/outbound-audit", headers=headers)
            assert r_clear.status_code == 200
            assert r_clear.json()["ok"] is True
            assert r_clear.json()["cleared"] >= 1

            # 关闭纯离线模式恢复
            r_off = client.post(
                "/v1/privacy/offline-mode",
                headers=headers,
                json={"enabled": False},
            )
            assert r_off.status_code == 200
            assert r_off.json()["enabled"] is False

        # 验证从持久化 privacy_prefs.json 重载恢复
        (tmp_path / "privacy_prefs.json").write_text(
            json.dumps({"offline_mode": True}), encoding="utf-8"
        )
        reloaded = OutboundGuard(state_path=tmp_path / "privacy_prefs.json")
        assert reloaded.is_offline_mode() is True
        assert reloaded.offline_mode_status() == {"enabled": True, "source": "persisted"}
    finally:
        guard.reset_for_tests(offline_mode=False)
        config_mod.get_settings.cache_clear()
        app_mod._public_fastapi_app.middleware_stack = None


# ── P2-4: 零遥测自证脚本 8/8 断言 CLI 验证 ───────────────────────────────────


def test_p2_4_verify_zero_telemetry_cli_passes_all_8_assertions():
    script = Path(__file__).resolve().parent.parent / "scripts" / "verify_zero_telemetry.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--json"],
        capture_output=True,
        text=True,
        timeout=240,
        **({"creationflags": 0x08000000} if os.name == "nt" else {}),
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    report = json.loads(proc.stdout)
    assert report["ok"] is True
    assert report["verdict"] == "ZERO_TELEMETRY_VERIFIED"
    assert report["passed"] == 8
    assert report["total"] == 8
    assert len(report["checks"]) == 8
    assert all(c["ok"] is True for c in report["checks"])
