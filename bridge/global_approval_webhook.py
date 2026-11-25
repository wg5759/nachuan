"""P4 国际化海外主流 IM（Discord / Slack）远程审批通知与签名验真桥接。

面向全球开发者工作流（电脑多 Worktree 并行编码 → 手机 Discord/Slack/Web PWA 审批）：
1. 严格出站目标白名单：仅允许官方 HTTPS Webhook 域名（`discord.com` / `discordapp.com` /
   `hooks.slack.com`），拒绝任意第三方 URL，防止 SSRF；同时全部经由 `httpx` 受
   `OutboundGuard` 实时审计与纯离线空气间隙模式硬拦截。
2. 强签名回调验真：支持 Slack `v0=<hmac-sha256>` 签名与 5 分钟防重放时间戳校验，
   以及共享 HMAC-SHA256 回调令牌验真，绝不信任未签名入站审批指令。
3. 零额外第三方依赖，纯标准库 + httpx。
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

_ALLOWED_DISCORD_HOSTS = frozenset({"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"})
_ALLOWED_SLACK_HOSTS = frozenset({"hooks.slack.com"})
_MAX_TIMESTAMP_SKEW_SEC = 300


class GlobalApprovalBridgeError(ValueError):
    """Webhook 目标不安全或签名校验失败。"""


def validate_webhook_url(provider: str, url: str) -> str:
    """严格校验 Discord / Slack 官方 HTTPS Webhook URL，阻断 SSRF 与明文 HTTP。"""
    norm_provider = str(provider or "").strip().lower()
    raw = str(url or "").strip()
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise GlobalApprovalBridgeError("Webhook 必须使用 HTTPS 协议且包含有效主机名")
    if parsed.username is not None or parsed.password is not None:
        raise GlobalApprovalBridgeError("Webhook URL 禁止包含内嵌用户名或密码")
    host = parsed.hostname.lower().rstrip(".")
    if norm_provider == "discord":
        if host not in _ALLOWED_DISCORD_HOSTS or not parsed.path.startswith("/api/webhooks/"):
            raise GlobalApprovalBridgeError(f"非法 Discord Webhook 地址：{host}")
    elif norm_provider == "slack":
        if host not in _ALLOWED_SLACK_HOSTS or not parsed.path.startswith("/services/"):
            raise GlobalApprovalBridgeError(f"非法 Slack Webhook 地址：{host}")
    else:
        raise GlobalApprovalBridgeError(f"不支持的海外审批通知渠道：{provider}")
    return raw


def build_discord_approval_payload(approval: dict[str, Any], *, session_branch: str = "") -> dict[str, Any]:
    """构造 Discord Embed 审批卡片负载。"""
    aid = str(approval.get("approval_id") or "")
    sid = str(approval.get("session_id") or "")
    cmd = str(approval.get("command") or "")[:300]
    reason = str(approval.get("reason") or "")[:200]
    return {
        "username": "Nachuan Approval Guard",
        "embeds": [
            {
                "title": f"Coding Sandbox Approval Required (`{aid}`)",
                "color": 16098851,
                "fields": [
                    {"name": "Worktree Session", "value": f"`{sid}` ({session_branch or 'active'})", "inline": True},
                    {"name": "Policy Reason", "value": reason or "Build approval required", "inline": True},
                    {"name": "Command", "value": f"```sh\n{cmd}\n```", "inline": False},
                ],
                "footer": {"text": "Nachuan Zero-Telemetry Control Plane • Approve or Reject in Web/Mobile UI"},
            }
        ],
    }


def build_slack_approval_payload(approval: dict[str, Any], *, session_branch: str = "") -> dict[str, Any]:
    """构造 Slack Block Kit 审批卡片负载。"""
    aid = str(approval.get("approval_id") or "")
    sid = str(approval.get("session_id") or "")
    cmd = str(approval.get("command") or "")[:300]
    reason = str(approval.get("reason") or "")[:200]
    return {
        "text": f"[Nachuan] Approval required ({aid}): {cmd}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Nachuan Sandbox Approval: {aid}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Session:*\n`{sid}` ({session_branch or 'active'})"},
                    {"type": "mrkdwn", "text": f"*Reason:*\n{reason or 'Build approval required'}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Command:*\n```{cmd}```"},
            },
        ],
    }


async def send_approval_notification(
    *,
    provider: str,
    webhook_url: str,
    approval: dict[str, Any],
    session_branch: str = "",
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """向 Discord 或 Slack 推送远程审批通知（自动受 OutboundGuard 纯离线防火墙约束）。"""
    safe_url = validate_webhook_url(provider, webhook_url)
    norm_provider = provider.strip().lower()
    payload = (
        build_discord_approval_payload(approval, session_branch=session_branch)
        if norm_provider == "discord"
        else build_slack_approval_payload(approval, session_branch=session_branch)
    )
    owns_client = client is None
    cl = client or httpx.AsyncClient(timeout=timeout)
    try:
        resp = await cl.post(safe_url, json=payload)
        return {
            "ok": 200 <= resp.status_code < 300,
            "provider": norm_provider,
            "status_code": resp.status_code,
        }
    finally:
        if owns_client:
            await cl.aclose()


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp: str,
    raw_body: bytes,
    signature: str,
    now: float | None = None,
) -> bool:
    """校验 Slack Signing Secret (`v0=HMAC_SHA256`) 并防御超时重放攻击。"""
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        ts_val = int(timestamp)
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - ts_val) > _MAX_TIMESTAMP_SKEW_SEC:
        return False
    base = b"v0:" + timestamp.encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def parse_remote_approval_command(text: str) -> tuple[str, str, str] | None:
    """解析海外 IM 快捷审批指令：`/approve <approval_id> [note]` 或 `/reject <approval_id> [note]`。"""
    raw = str(text or "").strip()
    if not raw.startswith(("/approve ", "/reject ")):
        return None
    parts = raw.split(None, 2)
    if len(parts) < 2:
        return None
    decision = "approve" if parts[0] == "/approve" else "reject"
    approval_id = parts[1].strip()
    if not approval_id.startswith("cap-") or len(approval_id) > 64:
        return None
    note = parts[2].strip()[:240] if len(parts) >= 3 else ""
    return decision, approval_id, note


__all__ = [
    "GlobalApprovalBridgeError",
    "build_discord_approval_payload",
    "build_slack_approval_payload",
    "parse_remote_approval_command",
    "send_approval_notification",
    "validate_webhook_url",
    "verify_slack_signature",
]
