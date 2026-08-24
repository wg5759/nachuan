"""echo provider：本地回显，用于在没有任何上游密钥时验证网关链路。"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

from gateway.providers.base import ChatProvider
from gateway.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    Usage,
    _gen_id,
    final_chunk,
    text_chunk,
)


class EchoProvider(ChatProvider):
    def __init__(self, name: str = "echo"):
        self.name = name
        self.enabled = True

    def _reply_text(self, req: ChatCompletionRequest) -> str:
        last_user = next(
            (m.content for m in reversed(req.messages) if m.role == "user"), None
        )
        text = last_user if isinstance(last_user, str) else req.prompt_text()
        return f"[echo:{req.model}] {text}"

    def _usage(self, req: ChatCompletionRequest, reply: str) -> Usage:
        # 注意：这里用字符长度近似 token 数，仅用于联通性测试，不代表真实计费
        p = len(req.prompt_text())
        c = len(reply)
        return Usage(prompt_tokens=p, completion_tokens=c, total_tokens=p + c)

    async def chat(self, req: ChatCompletionRequest, upstream_model: str) -> dict[str, Any]:
        reply = self._reply_text(req)
        return ChatCompletionResponse.from_text(
            model=req.model, text=reply, usage=self._usage(req, reply)
        ).model_dump()

    async def stream(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> AsyncIterator[dict[str, Any]]:
        reply = self._reply_text(req)
        cid = _gen_id("chatcmpl")
        first = True
        # 按空白切分逐块吐出；中文无空格则作为单块返回（echo 仅作联通性验证）
        for token in reply.split(" "):
            piece = token if first else " " + token
            yield text_chunk(
                model=req.model,
                delta_text=piece,
                chunk_id=cid,
                role="assistant" if first else None,
            )
            first = False
            await asyncio.sleep(0)  # 让出事件循环
        usage = self._usage(req, reply)
        yield final_chunk(model=req.model, chunk_id=cid, usage=usage.model_dump())
