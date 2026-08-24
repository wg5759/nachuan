"""各来源的计费方式与费率（用量看板按此计算，力求实事求是、不空谈）。

type：
- actual：provider 自报实际成本（如 Claude headless 返回 total_cost_usd）——最准。
- per_token：按 token 计；in/out = USD / 1M tokens；estimate=True 表示费率为估算、请核对。
- subscription：套餐内固定费用，不按 token（火山 Coding Plan / Codex ChatGPT 套餐）。
- free：免费（Agnes / 本地 Ollama / echo）。

⚠️ per_token 的费率随官方调整，请按各家最新价核对（这里给的是参考估算）。
"""

from __future__ import annotations

from typing import Any

PRICING: dict[str, dict[str, Any]] = {
    "claude_code": {"type": "actual"},
    "codex": {"type": "subscription", "note": "ChatGPT Pro 套餐内（有用量上限）"},
    "volcano": {"type": "subscription", "note": "火山 Coding Plan ¥200/月套餐内"},
    "deepseek": {"type": "per_token", "in": 0.27, "out": 1.10, "estimate": True},
    "agnes": {"type": "free", "note": "免费"},
    "ollama": {"type": "free", "note": "本地免费"},
    "echo": {"type": "free", "note": "本地回显"},
}


def cost_for(
    provider: str,
    prompt_tokens: int,
    completion_tokens: int,
    actual_cost_usd: float = 0.0,
) -> dict[str, Any]:
    """返回 {cost_usd, basis}。cost_usd 为 None 表示按套餐计/未知，不做虚假折算。"""
    p = PRICING.get(provider, {"type": "unknown"})
    t = p.get("type")
    if t == "actual":
        return {"cost_usd": round(actual_cost_usd, 4), "basis": "实际（provider 自报）"}
    if t == "per_token":
        c = prompt_tokens / 1e6 * p.get("in", 0.0) + completion_tokens / 1e6 * p.get("out", 0.0)
        return {"cost_usd": round(c, 4), "basis": "估算·请核对" if p.get("estimate") else "按量"}
    if t == "subscription":
        return {"cost_usd": None, "basis": p.get("note", "套餐内")}
    if t == "free":
        return {"cost_usd": 0.0, "basis": p.get("note", "免费")}
    return {"cost_usd": None, "basis": "未知费率"}
