"""Legacy development-only Feishu webhook bridge.

Production uses ``scripts/run_feishu_bridge.py``.  This historical webhook path
still relies on ordinary async HTTP semantics and is therefore disabled unless a
developer enters an explicit double opt-in.  It must never be mounted or marketed
as a production alternative to the signed, AES-GCM sealed long-connection runner.

按用户隔离记忆：user_id 取发送者 open_id（机主归一为 'owner'，与桌面端共享记忆）。
群聊里他人 @ 机器人也能用，但受白名单 + 每用户限频约束，避免烧机主额度。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Any, Optional

import httpx

from bridge.policy import RateLimiter, is_allowed, parse_command, resolve_user_id

FEISHU_BASE = "https://open.feishu.cn"
_FEISHU_TURN_KEY_DOMAIN = b"nachuan-feishu-provider-message-v1\x00"


def _feishu_idempotency_key(message_id: object, chat_id: object) -> str:
    """Derive the same non-reversible durable turn key as the long-connection runner."""

    values = (str(chat_id or ""), str(message_id or ""))
    if not values[0] or not values[1] or any(len(v.encode("utf-8")) > 512 for v in values):
        raise ValueError("canonical Feishu chat_id and message_id are required")
    digest = hashlib.sha256(_FEISHU_TURN_KEY_DOMAIN)
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"fsmsg-v1:{digest.hexdigest()}"
_MAX_AUDIO_BYTES = 32 * 1024 * 1024
_LEGACY_WEBHOOK_OPT_IN = "I_ACCEPT_PLAINTEXT_DEVELOPMENT_LOOPBACK"


class FeishuBridge:
    def __init__(
        self,
        app_id: str,
        app_secret: str,
        *,
        engine_url: str = "http://127.0.0.1:8080",
        engine_key: str = "",
        model: str = "glm",
        base: str = FEISHU_BASE,
        allowed_users: Optional[set[str]] = None,
        owner_open_id: str = "",
        rate_per_min: int = 20,
        channel: str = "feishu",
    ):
        if not (
            os.getenv("NACHUAN_ENV", "production").strip().lower() == "development"
            and os.getenv("NACHUAN_ENABLE_LEGACY_FEISHU_WEBHOOK", "")
            == _LEGACY_WEBHOOK_OPT_IN
        ):
            raise RuntimeError(
                "legacy Feishu webhook is disabled; use scripts/run_feishu_bridge.py"
            )
        self.app_id = app_id
        self.app_secret = app_secret
        self.engine_url = engine_url.rstrip("/")
        self.engine_key = engine_key
        self.model = model
        self.base = base.rstrip("/")
        self.allowed = allowed_users or set()
        self.owner_open_id = owner_open_id
        self.channel = channel
        self._limiter = RateLimiter(rate_per_min)

    async def _token(self, client: httpx.AsyncClient) -> str:
        r = await client.post(
            f"{self.base}/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": self.app_id, "app_secret": self.app_secret},
            timeout=15,
        )
        return r.json().get("tenant_access_token", "")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.engine_key}"} if self.engine_key else {}

    async def _agent_chat(
        self,
        client: httpx.AsyncClient,
        *,
        message: str,
        user_id: str,
        chat_id: str,
        idempotency_key: str,
    ) -> str:
        r = await client.post(
            f"{self.engine_url}/v1/agent/chat",
            headers=self._headers(),
            json={
                "message": message,
                "user_id": user_id,
                "chat_id": chat_id,
                "channel": self.channel,
                "model": self.model,
                "idempotency_key": idempotency_key,
            },
            timeout=300,
        )
        r.raise_for_status()
        return r.json().get("reply") or "(空回复)"

    async def _feedback(
        self,
        client: httpx.AsyncClient,
        *,
        user_id: str,
        chat_id: str,
        rating: str,
        idempotency_key: str,
        note: str = "",
    ) -> None:
        try:
            await client.post(
                f"{self.engine_url}/v1/agent/feedback",
                headers=self._headers(),
                json={
                    "user_id": user_id,
                    "chat_id": chat_id,
                    "channel": self.channel,
                    "rating": rating,
                    "note": note,
                    "idempotency_key": idempotency_key,
                },
                timeout=30,
            )
        except Exception:  # noqa: BLE001
            pass

    async def _send(self, client: httpx.AsyncClient, chat_id: str, text: str, token: str) -> None:
        await client.post(
            f"{self.base}/open-apis/im/v1/messages",
            params={"receive_id_type": "chat_id"},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"receive_id": chat_id, "msg_type": "text", "content": json.dumps({"text": text})},
            timeout=15,
        )

    @staticmethod
    def _extract(event: dict[str, Any]) -> dict[str, str]:
        e = event.get("event") or {}
        msg = e.get("message") or {}
        mtype = msg.get("message_type") or ""
        content = json.loads(msg.get("content") or "{}")
        return {
            "text": (content.get("text") or "").strip() if mtype == "text" else "",
            "chat_id": msg.get("chat_id") or "",
            "open_id": (((e.get("sender") or {}).get("sender_id") or {}).get("open_id")) or "",
            "mtype": mtype,
            "rkey": content.get("image_key") or content.get("file_key") or "",
            "message_id": msg.get("message_id") or "",
        }

    # ── 文件收发（D4）──
    async def _download(
        self, client: httpx.AsyncClient, message_id: str, file_key: str, ftype: str, token: str
    ) -> bytes:
        async with asyncio.timeout(60.0):
            async with client.stream(
                "GET",
                f"{self.base}/open-apis/im/v1/messages/{message_id}/resources/{file_key}",
                params={"type": ftype},
                headers={"Authorization": f"Bearer {token}"},
                timeout=httpx.Timeout(60.0, read=20.0),
            ) as r:
                r.raise_for_status()
                content_type = (r.headers.get("content-type") or "").split(";", 1)[0].lower()
                if content_type and not (
                    content_type.startswith("audio/")
                    or content_type == "application/octet-stream"
                ):
                    raise ValueError("飞书语音资源 Content-Type 不允许")
                raw_length = (r.headers.get("content-length") or "").strip()
                declared = None
                if raw_length:
                    try:
                        declared = int(raw_length)
                    except ValueError as exc:
                        raise ValueError("飞书语音资源 Content-Length 无效") from exc
                    if declared < 0 or declared > _MAX_AUDIO_BYTES:
                        raise ValueError("飞书语音资源超过大小上限")
                out = bytearray()
                async for chunk in r.aiter_bytes(64 * 1024):
                    out.extend(chunk)
                    if len(out) > _MAX_AUDIO_BYTES:
                        raise ValueError("飞书语音资源超过大小上限")
                if declared is not None and len(out) != declared:
                    raise ValueError("飞书语音资源长度与 Content-Length 不一致")
                return bytes(out)

    async def _transcribe(self, client: httpx.AsyncClient, data: bytes) -> str:
        r = await client.post(
            f"{self.engine_url}/v1/audio/transcriptions",
            headers={**self._headers(), "Content-Type": "application/octet-stream"},
            content=data,
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("text", "")

    async def _upload_image(self, client: httpx.AsyncClient, data: bytes, token: str) -> str:
        r = await client.post(
            f"{self.base}/open-apis/im/v1/images",
            headers={"Authorization": f"Bearer {token}"},
            files={"image": ("img.png", data, "image/png")},
            data={"image_type": "message"},
            timeout=30,
        )
        return (r.json().get("data") or {}).get("image_key", "")

    async def _send_image(
        self, client: httpx.AsyncClient, chat_id: str, image_key: str, token: str
    ) -> None:
        await client.post(
            f"{self.base}/open-apis/im/v1/messages",
            params={"receive_id_type": "chat_id"},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"receive_id": chat_id, "msg_type": "image", "content": json.dumps({"image_key": image_key})},
            timeout=15,
        )

    async def _handle_file(
        self, client: httpx.AsyncClient, info: dict[str, str], user_id: str, token: str
    ) -> None:
        """非文本消息：语音→转写→对话（接 D1）；图片/文件→先确认（理解能力后续接）。"""
        chat_id, mtype, rkey, mid = info["chat_id"], info["mtype"], info["rkey"], info["message_id"]
        if mtype == "audio" and rkey:
            try:
                data = await self._download(client, mid, rkey, "file", token)
                transcript = (await self._transcribe(client, data)).strip()
            except Exception as ex:  # noqa: BLE001
                await self._send(client, chat_id, f"⚠️ 语音处理失败：{ex}", token)
                return
            if not transcript:
                await self._send(client, chat_id, "（没听清，请再说一遍或发文字）", token)
                return
            try:
                reply = await self._agent_chat(
                    client,
                    message=transcript,
                    user_id=user_id,
                    chat_id=chat_id,
                    idempotency_key=_feishu_idempotency_key(mid, chat_id),
                )
            except Exception as ex:  # noqa: BLE001
                reply = f"⚠️ {ex}"
            await self._send(client, chat_id, f"🎧 听到：{transcript}\n\n{reply}"[:4000], token)
        else:
            await self._send(client, chat_id, "📎 收到文件/图片（图片理解与文档总结即将支持）。", token)

    async def handle_event(
        self, client: httpx.AsyncClient, event: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """处理一个飞书事件。url_verification 返回 challenge；消息事件则回复，返回 None。"""
        if event.get("type") == "url_verification":
            return {"challenge": event.get("challenge")}
        info = self._extract(event)
        chat_id, open_id, mtype = info["chat_id"], info["open_id"], info["mtype"]
        if not chat_id:
            return None
        token = await self._token(client)
        user_id = resolve_user_id(open_id, self.owner_open_id)
        kind, payload = parse_command(info["text"]) if mtype == "text" else ("file", "")

        # /whoami 对所有人开放：方便用户拿到 open_id 去配白名单/机主
        if kind == "whoami":
            await self._send(client, chat_id, f"你的 open_id：{open_id or '(未取到)'}", token)
            return None

        is_owner = bool(self.owner_open_id) and open_id == self.owner_open_id
        if not (is_owner or is_allowed(open_id, self.allowed)):
            await self._send(client, chat_id, "抱歉，你暂未被授权使用本机器人。", token)
            return None

        if mtype != "text":  # 文件/图片/语音 → 下载并处理
            if not self._limiter.allow(open_id):
                await self._send(client, chat_id, "⏳ 你发得有点快，稍后再试。", token)
                return None
            await self._handle_file(client, info, user_id, token)
            return None

        if not info["text"]:
            return None
        if kind in ("up", "down"):
            await self._feedback(
                client,
                user_id=user_id,
                chat_id=chat_id,
                rating=kind,
                note=payload,
                idempotency_key=info["message_id"],
            )
            ack = "✅ 已记录，我会改进。" if kind == "down" else "👍 已记下，谢谢！"
            await self._send(client, chat_id, ack, token)
            return None

        if not self._limiter.allow(open_id):
            await self._send(client, chat_id, "⏳ 你发得有点快，稍后再试。", token)
            return None

        try:
            reply = await self._agent_chat(
                client,
                message=payload,
                user_id=user_id,
                chat_id=chat_id,
                idempotency_key=_feishu_idempotency_key(info["message_id"], chat_id),
            )
        except Exception as ex:  # noqa: BLE001
            reply = f"⚠️ {ex}"
        await self._send(client, chat_id, reply[:4000], token)
        return None
