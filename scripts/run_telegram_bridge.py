"""开发态 Telegram 实验桥；正式包/Supervisor 不包含，生产启动固定拒绝。"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bridge.access import ChannelAccessPolicy, explicit_development_allow_all  # noqa: E402
from bridge.telegram import TelegramBridge  # noqa: E402
from gateway.config import get_isolated_bridge_settings  # noqa: E402


_EXPERIMENTAL_CONFIRMATION = "I_UNDERSTAND_TELEGRAM_IS_NON_DURABLE"


def _experimental_enabled(environ: dict[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return (
        str(env.get("NACHUAN_ENV") or "").strip().lower() == "development"
        and str(env.get("NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM") or "").strip()
        == _EXPERIMENTAL_CONFIRMATION
    )


def main() -> int:
    # Telegram currently has no durable offset/inbox/outbox, channel-scoped key,
    # business health or Supervisor lifecycle.  Fail before loading credentials
    # or constructing a network client unless a developer explicitly accepts
    # that source-only experiment boundary.
    if not _experimental_enabled():
        print(
            "Telegram 正式渠道未启用：当前实现不具备持久投递和监督恢复。"
            "仅开发实验可设置 NACHUAN_ENV=development 且 "
            f"NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM={_EXPERIMENTAL_CONFIRMATION}。"
        )
        return 78
    s = get_isolated_bridge_settings()
    if not s.telegram_bot_token:
        print(
            "开发实验需在当前进程环境显式设置 TELEGRAM_BOT_TOKEN；"
            "隔离 runner 不读取项目 .env。Bot 由 @BotFather 创建。"
        )
        return 1
    key = str(s.bridge_api_key or "").strip()
    access = ChannelAccessPolicy(
        s.telegram_allowed_set,
        allow_all=explicit_development_allow_all("TELEGRAM"),
    )
    bridge = TelegramBridge(
        s.telegram_bot_token,
        engine_url=s.bridge_engine_url,
        engine_key=key,
        model=s.bridge_model,
        access=access,
    )
    if not access.configured:
        print(
            "Telegram 已锁定：先向 bot 发 /whoami，随后设置 TELEGRAM_ALLOWED_USERS。"
            "仅本地开发可同时设置 NACHUAN_ENV=development 与 TELEGRAM_ALLOW_ALL=1。"
        )
    print(f"Telegram 桥接已启动，默认模型 {s.bridge_model}。手机发消息试试，Ctrl+C 退出。")
    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        print("\n已退出。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
