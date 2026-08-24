"""长对话上下文压缩（滚动摘要）——长任务/长对话不丢主线、也不撑爆上下文。

机主实测反馈的正解：上下文满了不是"砍成最近几条"（长任务会死），而是把**较早的对话**
摘要成"主线要点"（做过什么决定 / 产出与路径 / 当前任务状态 / 关键事实），**近的原样保留**，
让模型带着主线继续干。这是业界的 rolling-summary / conversation-memory-compression 模式。

与项目已有的 `orchestrator/compress.py`（LLMLingua-2 逐 token 有损压缩，省 token）互补：
- compress.py 压的是"单条超长文本的冗余 token"；
- 本模块压的是"多轮对话历史"，做**语义摘要**保留主线，不是丢 token。

降级第一：摘要用便宜/免费模型，任何失败（无模型/超时/异常）→ 原样返回历史，绝不因压缩挡任务。
"""

from __future__ import annotations

import asyncio
from typing import Any

# 历史总字符超过此阈值才触发摘要压缩（短对话原样，零开销）。
_COMPRESS_THRESHOLD_CHARS = 8000
# 无论多长，最近这么多条原样保留（保证"上一句/最近几轮"永远精确不失真）。
_KEEP_RECENT = 8
# 摘要调用的硬超时（秒）。超时→原样返回（不拖累主流程）。
_SUMMARY_TIMEOUT = 60.0


def _history_chars(history: list[dict[str, Any]]) -> int:
    return sum(len(str(m.get("content") or "")) for m in history)


async def compress_history(
    router: Any,
    history: list[dict[str, Any]] | None,
    *,
    keep_recent: int = _KEEP_RECENT,
    threshold_chars: int = _COMPRESS_THRESHOLD_CHARS,
) -> list[dict[str, Any]] | None:
    """长对话历史压缩：老对话摘要成主线要点（system 消息），近的原样保留。

    返回新的 history 列表（[摘要 system 消息] + 最近 keep_recent 条）；不长或压缩失败 → 原样返回。
    """
    if not history or len(history) <= keep_recent + 2:
        return history
    if _history_chars(history) <= threshold_chars:
        return history  # 不长，原样（零开销）

    older = history[:-keep_recent]
    recent = history[-keep_recent:]

    # 把较早的对话铺成裸文本喂给便宜模型摘要（每条截断，防个别超长条撑爆摘要输入）。
    convo = "\n".join(
        f"{m.get('role', '?')}: {str(m.get('content') or '')[:1500]}" for m in older
    )[:16000]
    prompt = (
        "下面是一段较早的对话历史。请把它压缩成一份『对话主线摘要』，**只保留对后续继续工作有用的信息**：\n"
        "① 关键事实与结论；② 已做出的决定 / 已确认的方案；③ 已产生的产物、文件、路径、任务号；"
        "④ 当前未完成的任务及其进度状态；⑤ 用户明确的偏好/约束。\n"
        "丢掉寒暄、重复、跑偏的支线。用简洁要点列出，不要复述原文：\n\n" + convo
    )

    try:
        from gateway.failover import chat_with_fallback
        from gateway.provider_call_ledger import bind_provider_call_scope
        from gateway.schemas import ChatCompletionRequest
        from orchestrator.modes import pick_model

        cheap = "agnes-flash" if router.resolve("agnes-flash") else pick_model(router, "cheap")
        if not cheap:
            return history  # 没有可用便宜模型 → 原样（不升级烧强模型做摘要）
        req = ChatCompletionRequest(model=cheap, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
        with bind_provider_call_scope(role="history.compress"):
            res, _served, _route = await asyncio.wait_for(
                chat_with_fallback(router, req), timeout=_SUMMARY_TIMEOUT
            )
        summary = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        summary = summary.strip()
        if not summary:
            return history
    except Exception:  # noqa: BLE001 摘要失败一律降级原样，绝不因压缩挡任务
        return history

    note = {
        "role": "system",
        "content": (
            "【此前较长对话的主线摘要（引擎自动压缩，保留关键信息，近几轮在下方原样保留）】\n"
            + summary
        ),
    }
    return [note] + recent
