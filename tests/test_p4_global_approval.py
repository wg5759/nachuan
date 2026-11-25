"""P4 海外 IM 远程审批通知（Discord / Slack）与签名验真单元测试。"""

from __future__ import annotations

import hashlib
import hmac
import time
import pytest

from bridge.global_approval_webhook import (
    GlobalApprovalBridgeError,
    build_discord_approval_payload,
    build_slack_approval_payload,
    parse_remote_approval_command,
    send_approval_notification,
    validate_webhook_url,
    verify_slack_signature,
)
from gateway.outbound_guard import (
    OutboundBlockedError,
    get_outbound_guard,
    install_httpx_outbound_guard,
)


def test_webhook_url_ssrf_allowlist():
    assert validate_webhook_url("discord", "https://discord.com/api/webhooks/12345/abcdef").startswith("https://")
    assert validate_webhook_url("slack", "https://hooks.slack.com/services/T000/B000/XXXX").startswith("https://")

    for prov, bad_url in [
        ("discord", "http://discord.com/api/webhooks/1/a"),
        ("discord", "https://evil.example/api/webhooks/1/a"),
        ("discord", "https://discord.com/other/path"),
        ("slack", "https://169.254.169.254/latest/meta-data"),
        ("slack", "https://hooks.slack.com/wrong"),
        ("unknown", "https://discord.com/api/webhooks/1/a"),
    ]:
        with pytest.raises(GlobalApprovalBridgeError):
            validate_webhook_url(prov, bad_url)


def test_payload_builders_and_command_parser():
    approval = {
        "approval_id": "cap-a1b2c3d4e5",
        "session_id": "wt-12345678",
        "command": "npm run build",
        "reason": "Build requires approval",
    }
    d = build_discord_approval_payload(approval, session_branch="nachuan/feat-auth")
    assert "cap-a1b2c3d4e5" in d["embeds"][0]["title"]
    s = build_slack_approval_payload(approval, session_branch="nachuan/feat-auth")
    assert "cap-a1b2c3d4e5" in s["text"]

    assert parse_remote_approval_command("/approve cap-a1b2c3d4e5 ship it") == (
        "approve",
        "cap-a1b2c3d4e5",
        "ship it",
    )
    assert parse_remote_approval_command("/reject cap-a1b2c3d4e5") == (
        "reject",
        "cap-a1b2c3d4e5",
        "",
    )
    assert parse_remote_approval_command("/approve invalid_id") is None


def test_slack_signature_verification():
    secret = "test_slack_signing_secret"
    body = b'{"command":"/approve","text":"cap-12345"}'
    now = 1700000000.0
    ts = str(int(now))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()

    assert verify_slack_signature(signing_secret=secret, timestamp=ts, raw_body=body, signature=sig, now=now) is True
    # 篡改包体失败
    assert verify_slack_signature(signing_secret=secret, timestamp=ts, raw_body=body + b"x", signature=sig, now=now) is False
    # 超过 5 分钟重放失败
    assert verify_slack_signature(signing_secret=secret, timestamp=ts, raw_body=body, signature=sig, now=now + 400) is False


@pytest.mark.asyncio
async def test_webhook_respects_airgapped_offline_mode():
    install_httpx_outbound_guard()
    guard = get_outbound_guard()
    guard.reset_for_tests(offline_mode=True)
    try:
        with pytest.raises(OutboundBlockedError):
            await send_approval_notification(
                provider="discord",
                webhook_url="https://discord.com/api/webhooks/123456/abcdef",
                approval={"approval_id": "cap-001", "session_id": "wt-1", "command": "echo hi"},
            )
    finally:
        guard.reset_for_tests(offline_mode=False)
