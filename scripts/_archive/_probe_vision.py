"""探针：测哪个已连模型真能看图。喂一张"上红下蓝"的图，直连各 provider（绕过失效转移）问颜色。

答对(上红下蓝)=该模型真能看图。用法：python scripts/_probe_vision.py
"""

from __future__ import annotations

import asyncio
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.config import get_settings
from gateway.connections import ConnectionStore
from gateway.router import Router
from gateway.schemas import ChatCompletionRequest
from orchestrator.vision import VISION_CANDIDATES, to_image_url


def _png_split(w: int = 48, h: int = 48) -> bytes:
    """生成上半红、下半蓝的 PNG（纯字节，无需 PIL）。"""
    raw = b""
    for y in range(h):
        raw += b"\x00"  # 每行 filter 0
        r, g, b = (220, 30, 30) if y < h // 2 else (30, 30, 220)
        raw += bytes((r, g, b)) * w

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


async def main() -> None:
    s = get_settings()
    router = Router(store=ConnectionStore(Path(s.usage_db_path).parent / "connections.json"))
    url = to_image_url(_png_split())
    q = "这张图上半部分和下半部分分别是什么颜色？只简短回答，例如：上红下蓝。"
    content = [{"type": "text", "text": q}, {"type": "image_url", "image_url": {"url": url}}]
    for m in ("agnes-flash", "kimi", "minimax", "glm"):  # 只测能透传多模态的 openai 兼容模型
        route = router.resolve(m)
        if route is None:
            print(f"{m:14} (未连)", flush=True)
            continue
        req = ChatCompletionRequest(model=m, messages=[{"role": "user", "content": content}])  # type: ignore[arg-type]
        try:
            res = await asyncio.wait_for(route.provider.chat(req, route.upstream_model), timeout=40)
            out = ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
            print(f"{m:14} -> {out[:90].replace(chr(10), ' ')}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"{m:14} ERR {type(e).__name__} {str(e)[:80]}", flush=True)
    await router.aclose()


if __name__ == "__main__":
    asyncio.run(main())
