"""Telegram 桥接：手机发消息 → 本地引擎处理 → 回复手机。

用长轮询（getUpdates），桥接进程主动外连 Telegram，**无需公网/webhook**。
需要一个 Bot Token（@BotFather 创建）。
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from typing import Any

import httpx

from bridge.access import ChannelAccessPolicy


class TelegramBridge:
    def __init__(
        self,
        token: str,
        *,
        engine_url: str = "http://127.0.0.1:8080",
        engine_key: str = "",
        model: str = "glm",
        access: ChannelAccessPolicy | None = None,
        max_session_models: int = 1024,
    ):
        if not 1 <= int(max_session_models) <= 100_000:
            raise ValueError("max_session_models must be between 1 and 100000")
        self.token = token
        self.api = f"https://api.telegram.org/bot{token}"
        self.engine_url = engine_url.rstrip("/")
        self.engine_key = engine_key
        # 桥进程默认值不可被 /model 原地改写，否则一个会话会切掉所有 Telegram 会话。
        self.model = model
        self.max_session_models = int(max_session_models)
        self._session_models: OrderedDict[tuple[str, str], str] = OrderedDict()
        # 默认空策略是 fail-closed；调用者必须给白名单或显式开发态 allow_all。
        self.access = access or ChannelAccessPolicy()
        self._offset = 0

    @staticmethod
    def _session_key(chat_id: int | str, sender_id: int | str) -> tuple[str, str]:
        return str(chat_id), str(sender_id)

    def _model_for(self, chat_id: int | str, sender_id: int | str) -> str:
        key = self._session_key(chat_id, sender_id)
        selected = self._session_models.get(key)
        if selected is None:
            return self.model
        self._session_models.move_to_end(key)
        return selected

    def _remember_session_model(
        self,
        chat_id: int | str,
        sender_id: int | str,
        model: str,
    ) -> None:
        key = self._session_key(chat_id, sender_id)
        self._session_models[key] = model
        self._session_models.move_to_end(key)
        while len(self._session_models) > self.max_session_models:
            self._session_models.popitem(last=False)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.engine_key}"} if self.engine_key else {}

    async def _available_models(self, client: httpx.AsyncClient) -> set[str]:
        """以引擎实时 Router 为准校验模型，不能信任 Telegram 传来的任意字符串。"""
        r = await client.get(
            f"{self.engine_url}/v1/models",
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        body = r.json()
        return {
            str(item.get("id") or "").strip()
            for item in body.get("data") or []
            if isinstance(item, dict) and str(item.get("id") or "").strip()
        }

    async def _engine_chat(
        self,
        client: httpx.AsyncClient,
        text: str,
        *,
        chat_id: int | str,
        sender_id: int | str,
    ) -> str:
        """与微信/飞书共用超级智能体入口，统一记忆、编排与渠道隔离。"""
        r = await client.post(
            f"{self.engine_url}/v1/agent/chat",
            headers=self._headers(),
            json={
                "message": text,
                "chat_id": str(chat_id),
                "user_id": str(sender_id),
                "channel": "telegram",
                "model": self._model_for(chat_id, sender_id),
            },
            timeout=300,
        )
        r.raise_for_status()
        d = r.json()
        return str(d.get("reply") or "(空回复)")

    async def _send(self, client: httpx.AsyncClient, chat_id: int, text: str) -> None:
        await client.post(f"{self.api}/sendMessage", json={"chat_id": chat_id, "text": text})

    async def handle_update(self, client: httpx.AsyncClient, update: dict[str, Any]) -> None:
        msg = update.get("message") or {}
        text = msg.get("text")
        chat_id = (msg.get("chat") or {}).get("id")
        sender_id = (msg.get("from") or {}).get("id")
        if not text or chat_id is None:
            return
        # 未配置白名单时仍允许无模型成本的身份自查，便于安全完成首次配置。
        if text.strip().lower() in ("/whoami", "whoami"):
            if sender_id is not None:
                await self._send(client, chat_id, f"你的 Telegram 标识：{sender_id}")
            return
        if not self.access.permits(sender_id):
            return
        # /model 只影响当前(chat, user)，并由服务端实时模型表确认存在。
        stripped = text.strip()
        parts = stripped.split(maxsplit=1)
        if parts and parts[0].lower() == "/model":
            requested = parts[1].strip() if len(parts) == 2 else ""
            if not requested:
                await self._send(client, chat_id, "用法：/model <模型ID>")
                return
            try:
                available = await self._available_models(client)
            except Exception as e:  # noqa: BLE001
                await self._send(client, chat_id, f"⚠️ 暂时无法校验模型：{e}")
                return
            if requested not in available:
                await self._send(client, chat_id, f"模型不可用：{requested}")
                return
            self._remember_session_model(chat_id, sender_id, requested)
            await self._send(client, chat_id, f"当前会话已切换模型：{requested}")
            return
        try:
            reply = await self._engine_chat(
                client,
                text,
                chat_id=chat_id,
                sender_id=sender_id,
            )
        except Exception as e:  # noqa: BLE001
            reply = f"⚠️ {e}"
        await self._send(client, chat_id, reply[:4000])

    async def run(self) -> None:
        async with httpx.AsyncClient(timeout=70) as client:
            while True:
                try:
                    r = await client.get(
                        f"{self.api}/getUpdates",
                        params={"offset": self._offset, "timeout": 60},
                    )
                    for upd in r.json().get("result", []):
                        self._offset = upd["update_id"] + 1
                        await self.handle_update(client, upd)
                except Exception:  # noqa: BLE001 — 网络抖动等，稍后重试
                    await asyncio.sleep(3)
