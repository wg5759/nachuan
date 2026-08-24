"""视觉地基（#28）：把图片喂给"能看图"的模型，得到文字理解 / OCR。

供：飞书发图理解、截图 OCR、拉片逐帧理解 复用。走 OpenAI 多模态格式
（content=[{type:text}, {type:image_url}]），由 openai_compat provider 透传给上游视觉模型。
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Optional

from gateway.failover import (
    DEFAULT_ATTEMPT_TIMEOUT_SEC,
    DEFAULT_TOTAL_TIMEOUT_SEC,
    chat_once_with_deadline,
)
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.schemas import ChatCompletionRequest

# 偏好的"能看图"模型（按顺序探，实际以连接中心已连且支持视觉的为准）。
# 看图归 ChatGPT/Agnes：agnes-flash 免费/快(默认)；gpt(ChatGPT,额度大/质量) 做质量与兜底。
# Claude 不放进来——留它啃硬骨头，不做"看图"这种小事（用户编排）。两家 provider 都已能真传图。
VISION_CANDIDATES = ("agnes-flash", "gpt-5.4", "gpt-5.5", "kimi")

_DEFAULT_Q = "详细描述这张图片的内容；如果图中有文字，逐字准确识别出来（OCR）。"
_VISION_ATTEMPT_TIMEOUT_SEC = min(DEFAULT_ATTEMPT_TIMEOUT_SEC, 25.0)
_VISION_TOTAL_TIMEOUT_SEC = min(DEFAULT_TOTAL_TIMEOUT_SEC, 45.0)


def _guess_mime(path: str) -> str:
    p = path.lower()
    if p.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    if p.endswith(".webp"):
        return "image/webp"
    if p.endswith(".gif"):
        return "image/gif"
    return "image/png"


def _to_data_url(data: bytes, mime: str = "image/png") -> str:
    return f"data:{mime};base64," + base64.b64encode(data).decode()


def pick_vision_model(router: Any, prefer: Optional[str] = None) -> str:
    """选一个能看图的模型；prefer 优先，否则按候选表探已连接的。返回模型名或空串。"""
    def safe_route(model_id: str) -> bool:
        route = router.resolve(model_id)
        # Local CLI providers need a Read tool to inspect temporary image files;
        # that tool can also read same-user gateway credentials.  Vision is
        # therefore restricted to native multimodal API providers.
        return bool(
            route is not None
            and str(getattr(route.provider, "name", "")) not in {"claude_code", "codex"}
        )

    if prefer and safe_route(prefer):
        return prefer
    for m in VISION_CANDIDATES:
        if safe_route(m):
            return m
    return ""


def to_image_url(image: str | bytes) -> str:
    """把 URL / data: URI / 本地路径 / 原始字节 统一成可发给模型的 image_url。"""
    if isinstance(image, bytes):
        return _to_data_url(image)
    if isinstance(image, str) and not image.startswith(("http://", "https://", "data:")):
        try:  # 当作本地文件路径
            return _to_data_url(Path(image).read_bytes(), _guess_mime(image))
        except Exception:  # noqa: BLE001
            return image
    return image


async def describe_image(
    router: Any,
    image: str | bytes,
    *,
    question: str = _DEFAULT_Q,
    model: Optional[str] = None,
) -> str:
    """让视觉模型看图。image 可为 URL / data: URI / 本地路径 / 原始字节。返回文字理解（含 OCR）。"""
    m = pick_vision_model(router, model)
    route = router.resolve(m) if m else None
    if route is None:
        return ""
    content = [
        {"type": "text", "text": question},
        {"type": "image_url", "image_url": {"url": to_image_url(image)}},
    ]
    req = ChatCompletionRequest(model=m, messages=[{"role": "user", "content": content}])  # type: ignore[arg-type]
    # 直连该视觉模型、不走失效转移：回退到非视觉模型对"看图"无意义且更慢（实测默认链路会超时）。
    with bind_provider_call_scope(role="vision.describe"):
        res = await chat_once_with_deadline(
            route.provider,
            req,
            route.upstream_model,
            attempt_timeout=_VISION_ATTEMPT_TIMEOUT_SEC,
            total_timeout=_VISION_TOTAL_TIMEOUT_SEC,
        )
    return ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
