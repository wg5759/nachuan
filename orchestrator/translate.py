"""实时翻译（D2）：走自家免费/便宜模型（Agnes/火山），无需第三方翻译 API。

把翻译当成一次受约束的对话：要求模型只输出译文。默认用免费 Agnes，省额度。
"""

from __future__ import annotations

from typing import Any

from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.schemas import ChatCompletionRequest

_LANGS = {
    "zh": "中文",
    "en": "英文",
    "ja": "日文",
    "ko": "韩文",
    "fr": "法文",
    "de": "德文",
    "es": "西班牙文",
    "ru": "俄文",
}


def lang_name(code: str) -> str:
    return _LANGS.get((code or "").lower(), code)


async def translate(
    router: Any,
    *,
    text: str,
    target: str,
    model: str,
    include_author_evidence: bool = False,
) -> dict[str, Any]:
    """把 text 翻译成 target（语种码或名）。返回 {translated, model, target}。"""
    prompt = f"把下面文本翻译成{lang_name(target)}。只输出译文本身，不要解释、不要加引号：\n\n{text}"
    req = ChatCompletionRequest(model=model, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
    with bind_provider_call_scope(role="translate.answer"):
        res, served, route = await chat_with_fallback(router, req)
    out = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    result: dict[str, Any] = {
        "translated": out.strip(),
        "model": served,
        "target": target,
    }
    if include_author_evidence:
        # Internal-only evidence for Agent's final-author receipt.  Public
        # /v1/translate and tool callers keep the original closed projection.
        result["_response"] = res
        result["_route"] = route
        result["_requested_model"] = model
    return result
