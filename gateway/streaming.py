"""把 provider 产出的 chunk dict 编码成 SSE（Server-Sent Events）帧。"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator


async def sse_encode(chunks: AsyncIterator[dict[str, Any]]) -> AsyncIterator[bytes]:
    """OpenAI 流式协议：每个 chunk 一行 `data: {...}`，最后 `data: [DONE]`。"""
    try:
        async for chunk in chunks:
            payload = json.dumps(chunk, ensure_ascii=False)
            yield f"data: {payload}\n\n".encode("utf-8")
        yield b"data: [DONE]\n\n"
    finally:
        close = getattr(chunks, "aclose", None)
        if callable(close):
            await close()
