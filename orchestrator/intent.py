"""统一意图识别（#17）：用免费模型把用户消息分类到固定意图集，比关键词正则准。

任何端（桌面/飞书/API）共享这一套（配合 #15）。任何异常/超时都回退 'chat'——
最安全的降级（当普通对话处理，绝不因分类失败而卡住或误触发昂贵操作）。
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from orchestrator.modes import _ask, _text, pick_model

# 固定意图集合。frontend/agent_chat 据此分发。
INTENTS = ("image", "video", "lapian", "studio", "translate", "kb", "vision", "chat")

_PROMPT = (
    "你是意图分类器。判断用户这句话想做什么，只能回下面其中一个英文词：\n"
    "image=要画图/生成图片；video=要生成一段视频；lapian=要拆解分析一个视频链接(拉片)；"
    "studio=要做多镜头/分镜的成片(视频工作室)；translate=要翻译；kb=要根据"
    "「我的文档/知识库」回答；vision=要看图识图(提到图片但没链接)；chat=以上都不是、就是普通聊天/提问。\n"
    "只输出一个词，不要标点、不要解释。\n\n用户的话：「{msg}」\n意图："
)

# 兜底关键词规则（模型不可用/超时时用；与前端正则同源，保证最低可用）
_VID_URL = re.compile(
    r"https?://[^\s]*(douyin|tiktok|youtube|youtu\.be|bilibili|b23\.tv|kuaishou|"
    r"xiaohongshu|xhslink|weibo|v\.qq|ixigua|vimeo|\.mp4|\.mov)",
    re.I,
)


def _fallback_rule(message: str) -> str:
    """模型不可用时的关键词兜底——只认高置信度的几类，其余一律 chat。"""
    s = message or ""
    if _VID_URL.search(s) and re.search(r"拉片|拆解|复刻|逐帧|解析|分析", s):
        return "lapian"
    if re.search(r"多镜头|分镜|视频工作室|混剪|口播视频", s):
        return "studio"
    if re.search(r"翻译|翻成|译成|translate", s, re.I):
        return "translate"
    # 知识库要有「据/根据…文档/知识库」语境；光提到"知识库"（如"知识库是什么"）不算（Codex 审 #3）
    if re.search(r"(根据|据|按照|结合|参考).{0,6}(我的?|本地)?(文档|资料|知识库|笔记|档案)", s):
        return "kb"
    # 能力提问（"你能做视频吗""怎么画"）→ 交给对话，别误当成生成（Codex 审 #2）
    if re.search(r"能不能|能否|可以吗|是不是|怎么|如何|为什么|什么是|是什么|介绍|讲讲|教程|吗[?？]?$", s, re.I):
        return "chat"
    gen = re.search(r"生成|做|搞|来|给我|画|绘制|create|make|generate|draw|paint", s, re.I)
    if re.search(r"视频|短视频|video|短片|影片|动图", s, re.I) and gen:
        return "video"
    # 图：明确"画…"，或"海报/logo/图…"+生成动词（Codex 审 #1：补回旧检测器的广度）
    if re.search(r"画[个张幅只一条]|绘制|draw|paint", s, re.I) or (
        re.search(r"图片?|插画|海报|logo|头像|壁纸|配图|图标|image|picture", s, re.I) and gen
    ):
        return "image"
    return "chat"


async def classify_intent(
    router: Any, message: str, *, timeout: float = 8.0, prefilter: bool = False
) -> str:
    """把 message 分类为 INTENTS 之一。

    prefilter=True（agent_chat 每条消息都过这里用）：先关键词快筛，看不出特殊意图就直接 'chat'，
        省掉模型调用——纯聊天零开销、也不污染调用链。
    prefilter=False（/v1/intent 端点、前端确认用）：总是用模型判，因为调用方已自己预筛过。
    任何异常/超时/空回都回退关键词规则，绝不阻断主流程。
    """
    msg = (message or "").strip()
    if not msg:
        return "chat"
    hint = _fallback_rule(msg)
    if prefilter and hint == "chat":
        return "chat"
    try:
        model = "agnes-flash" if router.resolve("agnes-flash") else pick_model(router, "cheap")
        if model:
            resp = await asyncio.wait_for(
                _ask(router, model, [{"role": "user", "content": _PROMPT.format(msg=msg[:500])}]),
                timeout=timeout,
            )
            out = _text(resp).strip().lower()
            # 真实模型只回一个词；输出过长=没好好分类（或测试桩把提示词回显了）→ 不信它，走规则。
            if 0 < len(out) <= 16:
                for it in INTENTS:
                    if it in out:
                        return it
    except Exception:  # noqa: BLE001  分类失败绝不阻断主流程
        pass
    return hint
