"""纳川（Nachuan）一键自动化零遥测 & 空气间隙自证脚本（P2-4）。

面向全球开发者与 CI 的 8 项独立硬断言（退出码 0 = 8/8 PASS，1 = 存在失败）：
1. 静态代码与依赖零遥测 SDK（sentry/posthog/mixpanel/amplitude/segment/gtag/umami/plausible）
   与零外链 CDN 扫描（含第三方 CLI 凭据零窃取检查）；
2. 纯启动零外联断言（``sys.addaudithook`` 监控 ``socket.connect`` + ``socket.getaddrinfo``，
   启动完整 FastAPI lifespan 并请求 ``/health``、``/v1/models``、``/v1/privacy/outbound-audit``，
   断言非回环外联 == 0）；
3. 纯离线模式硬拦截断言（``POST /v1/privacy/offline-mode {"enabled": true}`` 后分别触发
   公网 URL 请求、``websearch.py``、``imagehost.py``，断言 100% 被 ``OfflineModeBlockedError``
   硬拦截、socket 非回环连接 == 0、且 ``/v1/privacy/outbound-audit?blocked_only=true`` 精确记账）；
4. 本地模型零隐式外发断言（真实 loopback HTTP mock 本地模型发一轮带“今天天气”触发词对话，
   断言非回环外联 == 0）；
5. 无痕模式（``incognito=True``）零持久化断言（带敏感暗号 + ``web_search=True`` 对话，
   断言不写库、不存记忆、不联网、磁盘 DB 与 WAL 原始字节不含敏感暗号）；
6. 出站审计日志脱敏断言（带 ``Authorization: Bearer sk-secret-leak`` 与 ``?api_key=leakme``
   请求本地 mock，断言审计输出零泄漏秘密与 query）；
7. Electron 自动更新默认关闭静态断言（校验 ``generated-update-trust.ts`` 与
   ``secure-auto-updater.ts`` 默认禁止后台自动外连）；
8. 跨平台 ``SecretStore`` 无明文落盘断言（写入测试密钥后直接扫描磁盘原始字节断言明文不可见）。

用法：
    python scripts/verify_zero_telemetry.py
    python scripts/verify_zero_telemetry.py --json
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
from typing import Any, Iterator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("NACHUAN_EMBED_DISABLED", "1")

from gateway.outbound_guard import (
    OfflineModeBlockedError,
    create_sync_client,
    get_outbound_guard,
    install_httpx_outbound_guard,
    install_socket_offline_guard,
    is_loopback_host,
)

# ── 1. 静态规则定义 ──────────────────────────────────────────────────────────

_TELEMETRY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("posthog", re.compile(r"\b(?:posthog|us\.i\.posthog\.com|app\.posthog\.com)\b", re.I)),
    ("sentry", re.compile(r"\b(?:sentry_sdk|@sentry/|ingest\.sentry\.io|sentry-cli)\b", re.I)),
    ("mixpanel", re.compile(r"\b(?:mixpanel|api\.mixpanel\.com)\b", re.I)),
    ("amplitude", re.compile(r"\b(?:amplitude-js|@amplitude/|api2\.amplitude\.com)\b", re.I)),
    ("segment", re.compile(r"\b(?:analytics-node|@segment/|api\.segment\.io)\b", re.I)),
    ("gtag", re.compile(r"\b(?:google-analytics\.com|googletagmanager\.com|gtag\()\b", re.I)),
    ("umami", re.compile(r"\b(?:umami\.is|analytics\.umami\.is|umami-js)\b", re.I)),
    ("plausible", re.compile(r"\b(?:plausible\.io/js|plausible-tracker)\b", re.I)),
    ("datadog_rum", re.compile(r"\b(?:@datadog/browser-rum|browser-intake-datadoghq)\b", re.I)),
    ("statsig", re.compile(r"\b(?:statsig-js|events\.statsigapi\.net)\b", re.I)),
)

_CDN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cdn_jsdelivr", re.compile(r"https?://cdn\.jsdelivr\.net/", re.I)),
    ("cdn_unpkg", re.compile(r"https?://unpkg\.com/", re.I)),
    ("cdn_cdnjs", re.compile(r"https?://cdnjs\.cloudflare\.com/", re.I)),
    ("cdn_google_fonts", re.compile(r"https?://fonts\.(?:googleapis|gstatic)\.com/", re.I)),
    ("cdn_bootcdn", re.compile(r"https?://cdn\.bootcdn\.net/", re.I)),
)

_EXTERNAL_CREDENTIAL_HARVEST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("claude_dot_json_read", re.compile(r"(?:open|read_text|readFileSync|readFile)\([^)]*\.claude\.json", re.I)),
    ("codex_auth_json_read", re.compile(r"(?:open|read_text|readFileSync|readFile)\([^)]*\.codex[/\\]+auth\.json", re.I)),
    ("cursor_state_db_read", re.compile(r"(?:open|read_text|readFileSync|readFile)\([^)]*Cursor[/\\]+User[/\\]+globalStorage", re.I)),
)

_SCAN_DIRS = ("gateway", "orchestrator", "storage", "bridge", "cli", "desktop/src")
_SCAN_EXTS = frozenset({".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".html", ".css"})
_IGNORE_PARTS = frozenset(
    {
        "node_modules",
        "__pycache__",
        ".venv",
        "dist",
        "out",
        "build",
        "web_ui",
        ".git",
        "tests",
    }
)

# ── 全局一次性 sys.addaudithook 网络连接探针 ─────────────────────────────────

_AUDIT_LOCK = threading.Lock()
_AUDIT_HOOK_INSTALLED = False
_AUDIT_CAPTURE_ACTIVE = False
_AUDIT_NON_LOOPBACK_EVENTS: list[dict[str, Any]] = []


def _is_local_bind_or_loopback(host: Any) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii", errors="ignore")
        except Exception:
            return False
    text = str(host).strip()
    if not text or text in {"0.0.0.0", "::", "*"}:
        return True
    return is_loopback_host(text)


def _sys_network_audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if not _AUDIT_CAPTURE_ACTIVE:
        return
    if event == "socket.connect":
        if len(args) >= 2:
            sock_obj, address = args[0], args[1]
            family = getattr(sock_obj, "family", None)
            if family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple) and address:
                host = address[0]
                if not _is_local_bind_or_loopback(host):
                    with _AUDIT_LOCK:
                        _AUDIT_NON_LOOPBACK_EVENTS.append(
                            {
                                "event": "socket.connect",
                                "host": str(host),
                                "port": address[1] if len(address) > 1 else None,
                            }
                        )
    elif event == "socket.getaddrinfo":
        if args:
            host = args[0]
            if not _is_local_bind_or_loopback(host):
                with _AUDIT_LOCK:
                    _AUDIT_NON_LOOPBACK_EVENTS.append(
                        {
                            "event": "socket.getaddrinfo",
                            "host": str(host),
                            "port": args[1] if len(args) > 1 else None,
                        }
                    )


def _ensure_audit_hook_installed() -> None:
    global _AUDIT_HOOK_INSTALLED
    with _AUDIT_LOCK:
        if not _AUDIT_HOOK_INSTALLED:
            sys.addaudithook(_sys_network_audit_hook)
            _AUDIT_HOOK_INSTALLED = True


@contextmanager
def _capture_non_loopback_network() -> Iterator[list[dict[str, Any]]]:
    global _AUDIT_CAPTURE_ACTIVE
    _ensure_audit_hook_installed()
    with _AUDIT_LOCK:
        _AUDIT_NON_LOOPBACK_EVENTS.clear()
        _AUDIT_CAPTURE_ACTIVE = True
    try:
        yield _AUDIT_NON_LOOPBACK_EVENTS
    finally:
        with _AUDIT_LOCK:
            _AUDIT_CAPTURE_ACTIVE = False


# ── 本地 loopback Mock HTTP 服务（供断言 4/5/6 真实走网络栈） ─────────────────


class _LoopbackMockServer:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parent.requests.append({"method": "GET", "path": self.path})
                payload = json.dumps({"ok": True, "echo_path": self.path.split("?", 1)[0]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b"{}"
                parent.requests.append({"method": "POST", "path": self.path, "size": len(raw)})
                reply = {
                    "id": "chatcmpl-local-mock",
                    "object": "chat.completion",
                    "created": 1700000000,
                    "model": "qwen-local",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "这是本地模型离线回复，未访问任何外部网络。",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 14, "total_tokens": 26},
                }
                payload = json.dumps(reply, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="nachuan-verify-loopback-mock",
            daemon=True,
        )

    def __enter__(self) -> "_LoopbackMockServer":
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3.0)


def _reset_fastapi_middleware_stack() -> None:
    app_module = sys.modules.get("gateway.app")
    if app_module is None:
        return
    public_app = getattr(app_module, "_public_fastapi_app", None)
    if public_app is not None and hasattr(public_app, "middleware_stack"):
        public_app.middleware_stack = None


@contextmanager
def _isolated_gateway_env(api_key: str = "verify-zero-telemetry-key") -> Iterator[tuple[Path, dict[str, str]]]:
    from gateway import config as config_mod

    guard = get_outbound_guard()
    prev_guard_status = guard.offline_mode_status()
    prev_env = {
        k: os.environ.get(k)
        for k in (
            "USAGE_DB_PATH",
            "GATEWAY_API_KEYS",
            "NACHUAN_CONFIG_ENV_ONLY",
            "NACHUAN_OFFLINE_MODE",
            "NACHUAN_DB_MODE",
        )
    }
    with tempfile.TemporaryDirectory(
        prefix="nachuan_zt_", ignore_cleanup_errors=True
    ) as tmp_str:
        tmp_dir = Path(tmp_str)
        os.environ["USAGE_DB_PATH"] = str(tmp_dir / "usage.db")
        os.environ["GATEWAY_API_KEYS"] = api_key
        os.environ["NACHUAN_CONFIG_ENV_ONLY"] = "1"
        os.environ["NACHUAN_DB_MODE"] = "unified"
        os.environ.pop("NACHUAN_OFFLINE_MODE", None)
        config_mod.get_settings.cache_clear()
        _reset_fastapi_middleware_stack()
        guard.reset_for_tests(offline_mode=False)
        guard.configure_state_path(tmp_dir / "privacy_prefs.json")
        try:
            yield tmp_dir, {"Authorization": f"Bearer {api_key}"}
        finally:
            guard.reset_for_tests(offline_mode=bool(prev_guard_status.get("enabled", False)))
            for k, v in prev_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            config_mod.get_settings.cache_clear()
            _reset_fastapi_middleware_stack()


class _LocalOnlyMockRouter:
    """挂载真实 OpenAICompatProvider（指向本地 loopback）的测试路由器。"""

    def __init__(self, provider: Any, model_id: str = "qwen-local") -> None:
        self._model_id = model_id
        self._route = SimpleNamespace(
            virtual_model=model_id,
            provider=provider,
            upstream_model="qwen2.5:local",
            tier="free",
            rank=1,
            independence_domain="dom:local",
            modality="chat",
        )

    def resolve(self, model: str) -> Any:
        return self._route if model == self._model_id else None

    def routes_info(self) -> list[dict[str, Any]]:
        return [
            {
                "model": self._model_id,
                "tier": "free",
                "provider": self._route.provider.name,
                "upstream_model": self._route.upstream_model,
                "independence_domain": "dom:local",
                "modality": "chat",
                "rank": 1,
                "flagship": False,
            }
        ]

    def list_models(self) -> list[str]:
        return [self._model_id]


# ── 8 项硬断言实现 ───────────────────────────────────────────────────────────


_ALL_STATIC_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    *[("telemetry_sdk", label, pat) for label, pat in _TELEMETRY_PATTERNS],
    *[("external_cdn", label, pat) for label, pat in _CDN_PATTERNS],
    *[("external_cli_harvest", label, pat) for label, pat in _EXTERNAL_CREDENTIAL_HARVEST_PATTERNS],
)
_FAST_STATIC_PREFILTER = re.compile(
    "|".join(f"(?:{pat.pattern})" for _, _, pat in _ALL_STATIC_RULES),
    re.I,
)
_FAST_TELEMETRY_PREFILTER = re.compile(
    "|".join(f"(?:{pat.pattern})" for _, pat in _TELEMETRY_PATTERNS),
    re.I,
)


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in _SCAN_DIRS:
        base = root / rel
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in _IGNORE_PARTS]
            dp = Path(dirpath)
            for fname in filenames:
                low = fname.lower()
                if low.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")) or low.startswith("test_"):
                    continue
                path = dp / fname
                if path.suffix.lower() not in _SCAN_EXTS:
                    continue
                files.append(path)
    return sorted(files)


def check_1_static_telemetry_and_cdn(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """断言 1：静态代码与依赖零遥测 SDK、零外链 CDN 与零第三方 CLI 凭据窃取。"""
    findings: list[dict[str, Any]] = []
    files = _iter_source_files(root)
    dep_files = [
        p
        for p in (root / "pyproject.toml", root / "desktop" / "package.json")
        if p.is_file()
    ]

    for fp in files:
        text = fp.read_text(encoding="utf-8", errors="ignore")
        if not _FAST_STATIC_PREFILTER.search(text):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue
            if not _FAST_STATIC_PREFILTER.search(line):
                continue
            for category, label, pat in _ALL_STATIC_RULES:
                if pat.search(line):
                    findings.append(
                        {
                            "category": category,
                            "rule": label,
                            "file": str(fp.relative_to(root)),
                            "line": line_no,
                            "snippet": stripped[:120],
                        }
                    )

    for dep in dep_files:
        text = dep.read_text(encoding="utf-8", errors="ignore")
        if not _FAST_TELEMETRY_PREFILTER.search(text):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for label, pat in _TELEMETRY_PATTERNS:
                if pat.search(line):
                    findings.append(
                        {
                            "category": "telemetry_dependency",
                            "rule": label,
                            "file": str(dep.relative_to(root)),
                            "line": line_no,
                            "snippet": stripped[:120],
                        }
                    )

    return {
        "id": 1,
        "name": "static_zero_telemetry_sdk_and_cdn",
        "ok": len(findings) == 0,
        "files_scanned": len(files) + len(dep_files),
        "findings": findings,
    }


def check_2_startup_zero_outbound() -> dict[str, Any]:
    """断言 2：完整 FastAPI lifespan 纯启动 + /health /v1/models /v1/privacy/outbound-audit 零外联。"""
    from fastapi.testclient import TestClient

    from gateway.app import app

    with _isolated_gateway_env() as (_tmp_dir, headers):
        with _capture_non_loopback_network() as net_events:
            with TestClient(app) as client:
                r_health = client.get("/health")
                r_models = client.get("/v1/models", headers=headers)
                r_audit = client.get("/v1/privacy/outbound-audit", headers=headers)
            captured = list(net_events)

    health_ok = (
        r_health.status_code == 200
        and bool((r_health.json().get("features") or {}).get("outbound_audit")) is True
    )
    models_ok = r_models.status_code == 200
    audit_body = r_audit.json() if r_audit.status_code == 200 else {}
    audit_ok = r_audit.status_code == 200 and audit_body.get("non_loopback_count") == 0
    zero_net = len(captured) == 0

    return {
        "id": 2,
        "name": "startup_zero_non_loopback_outbound",
        "ok": bool(health_ok and models_ok and audit_ok and zero_net),
        "health_status": r_health.status_code,
        "models_status": r_models.status_code,
        "audit_status": r_audit.status_code,
        "audit_non_loopback_count": audit_body.get("non_loopback_count"),
        "sys_audit_non_loopback_events": captured,
    }


def check_3_offline_mode_hard_block() -> dict[str, Any]:
    """断言 3：开启纯离线模式后，公网 URL / websearch / imagehost 100% 被硬拦截且精确记账。"""
    from fastapi.testclient import TestClient

    from gateway import websearch
    from gateway.app import app
    from gateway.public_media import fetch_public_text
    from orchestrator import imagehost

    install_httpx_outbound_guard()
    install_socket_offline_guard()

    blocked_results = {
        "httpx_public_url": False,
        "public_media_fetch": False,
        "websearch": False,
        "imagehost": False,
    }
    captured: list[dict[str, Any]] = []
    blocked_snapshot: dict[str, Any] = {}

    with _isolated_gateway_env() as (_tmp_dir, headers):
        with TestClient(app) as client:
            r_on = client.post(
                "/v1/privacy/offline-mode",
                headers=headers,
                json={"enabled": True},
            )
            client.delete("/v1/privacy/outbound-audit", headers=headers)

            with _capture_non_loopback_network() as net_events:
                try:
                    with create_sync_client(caller="verify.public_url", timeout=2.0) as c:
                        c.get("https://example.com/healthz")
                except OfflineModeBlockedError:
                    blocked_results["httpx_public_url"] = True

                try:
                    fetch_public_text(
                        "https://example.com/article",
                        max_bytes=4096,
                        max_chars=4096,
                        allowed_type_prefixes=("text/",),
                        total_timeout=2.0,
                        idle_timeout=2.0,
                    )
                except OfflineModeBlockedError:
                    blocked_results["public_media_fetch"] = True

                try:
                    asyncio.run(websearch.search("今日新闻", n=2, timeout=2.0))
                except OfflineModeBlockedError:
                    blocked_results["websearch"] = True

                try:
                    imagehost.upload_image(b"\x89PNG\r\n\x1a\n1234")
                except OfflineModeBlockedError:
                    blocked_results["imagehost"] = True

                captured = list(net_events)

            r_blocked = client.get(
                "/v1/privacy/outbound-audit?blocked_only=true&limit=50",
                headers=headers,
            )
            blocked_snapshot = r_blocked.json() if r_blocked.status_code == 200 else {}

            client.post(
                "/v1/privacy/offline-mode",
                headers=headers,
                json={"enabled": False},
            )

    items = blocked_snapshot.get("items") or []
    all_blocked_marked = len(items) >= 4 and all(
        item.get("blocked") is True and item.get("block_reason") == "offline_mode"
        for item in items
    )
    ok = (
        r_on.status_code == 200
        and r_on.json().get("enabled") is True
        and all(blocked_results.values())
        and len(captured) == 0
        and blocked_snapshot.get("non_loopback_count") == 0
        and all_blocked_marked
    )
    return {
        "id": 3,
        "name": "offline_mode_hard_block_and_audit",
        "ok": ok,
        "blocked_targets": blocked_results,
        "audit_total_blocked": blocked_snapshot.get("total_blocked"),
        "audit_non_loopback_count": blocked_snapshot.get("non_loopback_count"),
        "sys_audit_non_loopback_events": captured,
    }


def check_4_local_model_zero_implicit_outbound() -> dict[str, Any]:
    """断言 4：本地 loopback 模型发送含“今天天气”触发词对话，零隐式外发。"""
    from fastapi.testclient import TestClient

    from gateway.app import app
    from gateway.providers.openai_compat import OpenAICompatProvider

    with _LoopbackMockServer() as mock_srv:
        with _isolated_gateway_env() as (_tmp_dir, headers):
            provider = OpenAICompatProvider(
                "local-mock",
                f"http://127.0.0.1:{mock_srv.port}/v1",
                api_key="",
                timeout=10.0,
            )
            with TestClient(app) as client:
                prev_router = app.state.router
                app.state.router = _LocalOnlyMockRouter(provider, "qwen-local")
                client.delete("/v1/privacy/outbound-audit", headers=headers)
                try:
                    with _capture_non_loopback_network() as net_events:
                        resp = client.post(
                            "/v1/chat/completions",
                            headers=headers,
                            json={
                                "model": "qwen-local",
                                "messages": [
                                    {"role": "user", "content": "请问今天天气怎么样？顺便查最新热点新闻"}
                                ],
                            },
                        )
                        captured = list(net_events)
                    audit = client.get("/v1/privacy/outbound-audit", headers=headers).json()
                finally:
                    app.state.router = prev_router
                    asyncio.run(provider.aclose())

    has_loopback_audit = any(
        item.get("is_loopback") is True and item.get("host") == "127.0.0.1"
        for item in (audit.get("items") or [])
    )
    ok = (
        resp.status_code == 200
        and len(captured) == 0
        and audit.get("non_loopback_count") == 0
        and has_loopback_audit
    )
    return {
        "id": 4,
        "name": "local_model_zero_implicit_outbound",
        "ok": ok,
        "chat_status": resp.status_code,
        "audit_non_loopback_count": audit.get("non_loopback_count"),
        "loopback_recorded": has_loopback_audit,
        "sys_audit_non_loopback_events": captured,
    }


def check_5_incognito_zero_persistence() -> dict[str, Any]:
    """断言 5：无痕模式（incognito=True）零持久化、零记忆留痕、零外联。"""
    from fastapi.testclient import TestClient

    from gateway.app import app
    from gateway.providers.openai_compat import OpenAICompatProvider

    canary = "INCOGNITO-SECRET-CANARY-9527"
    canary_bytes = canary.encode("utf-8")

    with _LoopbackMockServer() as mock_srv:
        with _isolated_gateway_env() as (tmp_dir, headers):
            provider = OpenAICompatProvider(
                "local-mock",
                f"http://127.0.0.1:{mock_srv.port}/v1",
                api_key="",
                timeout=10.0,
            )
            with TestClient(app) as client:
                prev_router = app.state.router
                app.state.router = _LocalOnlyMockRouter(provider, "qwen-local")
                mem_before = len(app.state.memory.all_for("owner"))
                conv_before = len(app.state.conversations.list_conversations())
                client.delete("/v1/privacy/outbound-audit", headers=headers)
                try:
                    with _capture_non_loopback_network() as net_events:
                        resp = client.post(
                            "/v1/chat/completions",
                            headers=headers,
                            json={
                                "model": "qwen-local",
                                "messages": [
                                    {
                                        "role": "user",
                                        "content": f"请记住我的绝密暗号是 {canary}，我住在火星",
                                    }
                                ],
                                "incognito": True,
                                "web_search": True,
                            },
                        )
                        captured = list(net_events)
                    mem_after = len(app.state.memory.all_for("owner"))
                    conv_after = len(app.state.conversations.list_conversations())
                    audit = client.get("/v1/privacy/outbound-audit", headers=headers).json()
                finally:
                    app.state.router = prev_router
                    asyncio.run(provider.aclose())

            leaked_files: list[str] = []
            for fp in tmp_dir.rglob("*"):
                if not fp.is_file():
                    continue
                try:
                    if canary_bytes in fp.read_bytes():
                        leaked_files.append(fp.name)
                except OSError:
                    pass

    ok = (
        resp.status_code == 200
        and mem_after == mem_before
        and conv_after == conv_before
        and len(leaked_files) == 0
        and len(captured) == 0
        and audit.get("non_loopback_count") == 0
    )
    return {
        "id": 5,
        "name": "incognito_mode_zero_persistence",
        "ok": ok,
        "chat_status": resp.status_code,
        "memory_delta": mem_after - mem_before,
        "conversation_delta": conv_after - conv_before,
        "leaked_files": leaked_files,
        "audit_non_loopback_count": audit.get("non_loopback_count"),
        "sys_audit_non_loopback_events": captured,
    }


def check_6_outbound_audit_redaction() -> dict[str, Any]:
    """断言 6：出站审计日志严格脱敏，零泄漏 Authorization / Cookie / query string / API Key。"""
    from fastapi.testclient import TestClient

    from gateway.app import app

    secret_bearer = "sk-secret-leak-99999"
    secret_query = "leakme-query-88888"
    secret_cookie = "cookie-leak-77777"

    with _LoopbackMockServer() as mock_srv:
        with _isolated_gateway_env() as (_tmp_dir, headers):
            with TestClient(app) as client:
                client.delete("/v1/privacy/outbound-audit", headers=headers)
                with create_sync_client(caller="verify.redaction_probe", timeout=5.0) as c:
                    probe_resp = c.get(
                        f"http://127.0.0.1:{mock_srv.port}/v1/probe?api_key={secret_query}&token=topsecret",
                        headers={
                            "Authorization": f"Bearer {secret_bearer}",
                            "Cookie": f"session={secret_cookie}",
                        },
                    )
                r_audit = client.get("/v1/privacy/outbound-audit", headers=headers)
                audit_body = r_audit.json() if r_audit.status_code == 200 else {}

    serialized = json.dumps(audit_body, ensure_ascii=False)
    items = audit_body.get("items") or []
    matched = [
        item
        for item in items
        if item.get("host") == "127.0.0.1"
        and item.get("path") == "/v1/probe"
        and item.get("status_code") == 200
    ]
    no_leaks = all(
        needle not in serialized
        for needle in (
            secret_bearer,
            secret_query,
            secret_cookie,
            "api_key=",
            "topsecret",
            "Bearer ",
            "?",
        )
    )
    ok = probe_resp.status_code == 200 and len(matched) >= 1 and no_leaks
    return {
        "id": 6,
        "name": "outbound_audit_strict_redaction",
        "ok": ok,
        "probe_status": probe_resp.status_code,
        "matched_entries": len(matched),
        "no_secret_or_query_leaks": no_leaks,
    }


def check_7_electron_autoupdate_disabled_by_default(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """断言 7：Electron 自动更新默认关闭，禁止后台自动外连。"""
    trust_path = root / "desktop" / "src" / "main" / "generated-update-trust.ts"
    updater_path = root / "desktop" / "src" / "main" / "secure-auto-updater.ts"
    details: dict[str, bool] = {}

    if trust_path.is_file():
        trust_text = trust_path.read_text(encoding="utf-8", errors="ignore")
        details["trust_enabled_false"] = bool(re.search(r'"enabled"\s*:\s*false', trust_text))
        details["trust_release_tier_disabled"] = bool(
            re.search(r'"releaseTier"\s*:\s*"disabled"', trust_text)
        )
        details["trust_manifest_url_empty"] = bool(
            re.search(r'"manifestUrl"\s*:\s*""', trust_text)
        )
    else:
        details["trust_file_present"] = False

    if updater_path.is_file():
        updater_text = updater_path.read_text(encoding="utf-8", errors="ignore")
        details["auto_download_false"] = "updater.autoDownload = false" in updater_text
        details["auto_install_on_quit_false"] = "updater.autoInstallOnAppQuit = false" in updater_text
        details["disabled_trust_early_return"] = "if (!this.options.trust.enabled)" in updater_text
    else:
        details["updater_file_present"] = False

    return {
        "id": 7,
        "name": "electron_autoupdate_disabled_by_default",
        "ok": bool(details) and all(details.values()),
        "details": details,
    }


def check_8_secret_store_no_plaintext_on_disk() -> dict[str, Any]:
    """断言 8：跨平台 SecretStore 写入后扫描磁盘原始字节，绝无明文秘密落盘。"""
    from gateway.secret_store import (
        ENVELOPE_SCHEMA_V1,
        LinuxSecretServiceBackend,
        LocalKdfSecretBackend,
        MacOSKeychainBackend,
        WindowsDPAPIBackend,
    )

    canary = "sk" + "-nachuan-zero-plaintext-canary-778899"
    canary_bytes = canary.encode("utf-8")
    payload = {"provider": "openai", "api_key": canary}
    results: dict[str, bool] = {}

    with tempfile.TemporaryDirectory(
        prefix="nachuan_secret_zt_", ignore_cleanup_errors=True
    ) as tmp_str:
        tmp_dir = Path(tmp_str)

        # 1) local-kdf-aesgcm-v1
        kdf_file = tmp_dir / "kdf.json"
        kdf_backend = LocalKdfSecretBackend(master_passphrase="NachuanVerifyPassphrase!2026")
        kdf_backend.write_json(kdf_file, payload, purpose="verify/kdf")
        kdf_raw = kdf_file.read_bytes()
        kdf_doc = json.loads(kdf_raw.decode("utf-8"))
        results["local_kdf_no_plaintext"] = (
            canary_bytes not in kdf_raw
            and kdf_doc.get("schema") == ENVELOPE_SCHEMA_V1
            and kdf_backend.read_json(kdf_file, purpose="verify/kdf") == payload
        )

        # 2) macos-keychain-aesgcm (mock /usr/bin/security)
        mac_store: dict[tuple[str, str], str] = {}

        def _fake_security(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            sub = cmd[1]
            key = (cmd[cmd.index("-s") + 1], cmd[cmd.index("-a") + 1])
            if sub == "find-generic-password":
                val = mac_store.get(key)
                return (
                    subprocess.CompletedProcess(cmd, 0, val + "\n", "")
                    if val is not None
                    else subprocess.CompletedProcess(cmd, 44, "", "not found")
                )
            if sub == "add-generic-password":
                mac_store[key] = cmd[cmd.index("-w") + 1]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(cmd)

        mac_file = tmp_dir / "mac.json"
        mac_backend = MacOSKeychainBackend(runner=_fake_security)
        mac_backend.write_json(mac_file, payload, purpose="verify/mac")
        mac_raw = mac_file.read_bytes()
        mac_doc = json.loads(mac_raw.decode("utf-8"))
        results["macos_keychain_no_plaintext"] = (
            canary_bytes not in mac_raw
            and mac_doc.get("schema") == ENVELOPE_SCHEMA_V1
            and mac_backend.read_json(mac_file, purpose="verify/mac") == payload
        )

        # 3) linux-secret-service-aesgcm (mock /usr/bin/secret-tool)
        linux_store: dict[tuple[str, str, str], str] = {}

        def _fake_secret_tool(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            sub = cmd[1]
            key = (
                cmd[cmd.index("app") + 1],
                cmd[cmd.index("service") + 1],
                cmd[cmd.index("account") + 1],
            )
            if sub == "lookup":
                val = linux_store.get(key)
                return (
                    subprocess.CompletedProcess(cmd, 0, val, "")
                    if val is not None
                    else subprocess.CompletedProcess(cmd, 1, "", "")
                )
            if sub == "store":
                linux_store[key] = str(kwargs.get("input") or "").strip()
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(cmd)

        linux_file = tmp_dir / "linux.json"
        linux_backend = LinuxSecretServiceBackend(runner=_fake_secret_tool)
        linux_backend.write_json(linux_file, payload, purpose="verify/linux")
        linux_raw = linux_file.read_bytes()
        linux_doc = json.loads(linux_raw.decode("utf-8"))
        results["linux_secret_service_no_plaintext"] = (
            canary_bytes not in linux_raw
            and linux_doc.get("schema") == ENVELOPE_SCHEMA_V1
            and linux_backend.read_json(linux_file, purpose="verify/linux") == payload
        )

        # 4) Windows 原生 DPAPI 实测
        if os.name == "nt":
            win_file = tmp_dir / "win_dpapi.json"
            win_backend = WindowsDPAPIBackend()
            win_backend.write_json(win_file, payload, purpose="verify/win")
            win_raw = win_file.read_bytes()
            win_doc = json.loads(win_raw.decode("utf-8"))
            results["windows_dpapi_no_plaintext"] = (
                canary_bytes not in win_raw
                and win_doc.get("schema") == ENVELOPE_SCHEMA_V1
                and win_backend.read_json(win_file, purpose="verify/win") == payload
            )

    return {
        "id": 8,
        "name": "secret_store_zero_plaintext_on_disk",
        "ok": bool(results) and all(results.values()),
        "backends": results,
    }


def run_all_checks(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    checks = [
        check_1_static_telemetry_and_cdn(root),
        check_2_startup_zero_outbound(),
        check_3_offline_mode_hard_block(),
        check_4_local_model_zero_implicit_outbound(),
        check_5_incognito_zero_persistence(),
        check_6_outbound_audit_redaction(),
        check_7_electron_autoupdate_disabled_by_default(root),
        check_8_secret_store_no_plaintext_on_disk(),
    ]
    passed = sum(1 for c in checks if c["ok"])
    all_ok = passed == len(checks)
    return {
        "schema": "nachuan.zero-telemetry-attestation.v1",
        "ok": all_ok,
        "verdict": "ZERO_TELEMETRY_VERIFIED" if all_ok else "VERIFICATION_FAILED",
        "passed": passed,
        "total": len(checks),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Nachuan 8 zero-telemetry, air-gap & secret-store guarantees."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON attestation report.",
    )
    args = parser.parse_args(argv)
    report = run_all_checks(PROJECT_ROOT)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"Nachuan Zero-Telemetry Attestation: {report['verdict']} "
            f"({report['passed']}/{report['total']})"
        )
        for c in report["checks"]:
            mark = "PASS" if c["ok"] else "FAIL"
            print(f"  [{mark}] #{c['id']} {c['name']}")
            if not c["ok"]:
                print(f"         details={json.dumps(c, ensure_ascii=False)}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
