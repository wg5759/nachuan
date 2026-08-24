"""多模态编排（#3）：聊天里说"画张图/做个视频"→ 识别意图 → 润色提示词 → 调生图/生视频模型 → 回媒体。

让超级体不再回"我不会做视频"，而是真的把图/视频做出来发回（用户已买 Agnes 套餐）。
纯能力提问（"你能做视频吗"）不直接生成，交给对话（persona 会说"能"）。
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from gateway.failover import chat_with_fallback
from gateway.media_call_metering import (
    PaidMediaAuthorityRequired,
    generate_image_with_accounting,
    generate_video_with_accounting,
    get_video_with_accounting,
)
from gateway.provider_call_ledger import ProviderCallLedgerUnavailable
from gateway.schemas import ChatCompletionRequest, ImageGenerationRequest, VideoGenerationRequest
from orchestrator.modes import pick_model

_VID = re.compile(r"视频|动画|短片|动图|video|animat", re.I)
_IMG = re.compile(r"画|绘|图片|海报|插画|配图|做.{0,3}图|生成.{0,3}图|draw|image|picture|logo", re.I)
_GEN = re.compile(r"生成|做|画|帮我|来个|来张|给我|搞个|create|make|generate|draw", re.I)
_QUESTION = re.compile(r"(能|可以|会|行|支持|是否).{0,8}(吗|么|嘛|\?|？)")


def detect_media_intent(message: str) -> Optional[str]:
    """返回 'image' / 'video' / None。能力提问→None（交给对话）。"""
    m = message or ""
    if _QUESTION.search(m):
        return None
    if _VID.search(m) and _GEN.search(m):
        return "video"
    if _IMG.search(m) and _GEN.search(m):
        return "image"
    return None


async def polish_prompt(router: Any, message: str, kind: str) -> str:
    """用便宜模型把用户需求润色成一句精炼的生成提示词。失败则原样返回。"""
    # 优先用 Agnes（token plan 套餐，稳）做润色，避免随机挑到慢的火山模型把整条链拖死
    cheap = "agnes-flash" if router.resolve("agnes-flash") else pick_model(router, "cheap")
    if kind == "video":
        guide = (
            "把下面的需求扩写成一段适合 AI 生视频的高质量提示词。在**严格保留用户要的主体与关键动作**的前提下，"
            "补充：镜头运动(推/拉/摇/移/跟随)、主体动作与节奏、画面构图、光线氛围、色调风格、画质(电影感/高清/流畅)。"
            "用一段连贯的中文描述、别用列表；绝不改变、替换或新增主体；只输出提示词本身，不解释、不加引号：\n"
        )
    else:
        guide = (
            "把下面的需求扩写成一句适合 AI 生图的提示词，**严格保留主体与关键要素**，"
            "只补充画面、风格、光线、构图细节，绝不改主体；只输出提示词本身，不解释、不加引号：\n"
        )
    ask = guide + message
    req = ChatCompletionRequest(model=cheap, messages=[{"role": "user", "content": ask}])  # type: ignore[arg-type]
    try:
        res, _served, _route = await chat_with_fallback(router, req)
        out = ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        return out or message
    except Exception:  # noqa: BLE001
        return message


async def gen_image(router: Any, prompt: str, model: str = "agnes-image") -> list[str]:
    route = router.resolve(model)
    if route is None:
        return []
    req = ImageGenerationRequest(model=model, prompt=prompt)  # type: ignore[call-arg]
    provider = route.provider
    upstream_model = str(route.upstream_model)
    res = await generate_image_with_accounting(
        provider,
        req,
        upstream_model,
        actual_model=model,
    )
    out: list[str] = []
    for d in res.get("data") or []:
        if d.get("url"):
            out.append(d["url"])
        elif d.get("b64_json"):
            out.append("data:image/png;base64," + d["b64_json"])
    return out


_IMG_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp")


def _find_media_url(obj: Any, exts: tuple[str, ...] = (".mp4", ".mov", ".webm", ".m4v")) -> str:
    """递归在响应里找**视频** URL。关键：dict 分支也必须校验是视频——图生视频响应里常回显
    输入图/首帧预览图的 url 字段，旧代码只要有 http url 就当成片返回 → 下成 PNG（机主实测：
    长视频 shot1~8 全是同一张 PNG 的根因）。明确图片扩展名一律排除。"""
    def _is_video(u: Any) -> bool:
        if not isinstance(u, str) or not u.startswith("http"):
            return False
        low = u.lower().split("?")[0]
        if low.endswith(_IMG_EXTS):
            return False  # 明确是图片 → 绝不当成片
        return low.endswith(exts) or "video" in u.lower()

    if isinstance(obj, str):
        return obj if _is_video(obj) else ""
    if isinstance(obj, dict):
        for k in ("url", "video_url", "videoUrl", "download_url", "play_url", "output_url"):
            if _is_video(obj.get(k)):
                return str(obj[k])
        for v in obj.values():
            u = _find_media_url(v, exts)
            if u:
                return u
    elif isinstance(obj, list):
        for v in obj:
            u = _find_media_url(v, exts)
            if u:
                return u
    return ""


async def gen_video(
    router: Any, prompt: str, model: str = "agnes-video", *, max_wait: float = 420.0,
    duration: Optional[int] = None, image: Optional[str] = None,
) -> str:
    """创建生视频任务并轮询到完成（封顶 max_wait 秒）。返回视频 URL 或空串。

    轮询 GET 容忍上游偶发 4xx/5xx；创建 POST 不自动重试，因为超时后供应商可能已接单，
    无可靠幂等键时重发会生成重复任务。URL 用递归查找，兼容上游不同嵌套字段名。
    """
    route = router.resolve(model)
    if route is None:
        return ""
    provider = route.provider
    upstream_model = str(route.upstream_model)
    extra = _frames_for_seconds(duration)
    req = VideoGenerationRequest(model=model, prompt=prompt, image=image, **extra)  # type: ignore[call-arg]
    try:
        created = await generate_video_with_accounting(
            provider,
            req,
            upstream_model,
            actual_model=model,
        )
    except (ProviderCallLedgerUnavailable, PaidMediaAuthorityRequired):
        raise
    except Exception:  # noqa: BLE001
        return ""
    early = _find_media_url(created)  # 有些上游创建即直接返回 URL
    if early:
        return early
    # video_id 优先：Agnes 轮询端点 agnesapi?video_id= 只认 video_id，拿 task_id 查会 404「task not found」
    _d = created.get("data") or {}
    tid = next((created.get(k) or _d.get(k)
                for k in ("video_id", "task_id", "id", "request_id")
                if created.get(k) or _d.get(k)), None)
    if not tid:
        return ""
    waited = 0.0
    poll_attempt = 0
    while waited < max_wait:
        await asyncio.sleep(6)
        waited += 6
        poll_attempt += 1
        try:
            st = await get_video_with_accounting(
                provider,
                str(tid),
                requested_model=model,
                actual_model=model,
                upstream_model=upstream_model,
                attempt=poll_attempt,
            )
        except ProviderCallLedgerUnavailable:
            raise
        except Exception:  # noqa: BLE001  上游处理中偶发 502 等 → 容忍、继续轮询
            continue
        url = _find_media_url(st)
        if url:
            return url
        status = str(st.get("status") or (st.get("data") or {}).get("status") or "").lower()
        if any(x in status for x in ("fail", "error", "cancel")):
            return ""
    return ""


def parse_duration(message: str) -> Optional[int]:
    """从消息里解析想要的视频时长(秒)："生成10秒"→10、"1分钟"→60；1-60 秒内有效，否则 None。"""
    import re

    m = re.search(r"(\d{1,3})\s*(?:秒|s\b|sec)", message or "", re.I)
    if m:
        n = int(m.group(1))
        return n if 1 <= n <= 60 else None
    m = re.search(r"(\d{1,2})\s*(?:分钟|分\b|min)", message or "", re.I)
    if m:
        n = int(m.group(1)) * 60
        return n if 1 <= n <= 60 else None
    return None


def _frames_for_seconds(duration: Optional[int]) -> dict[str, Any]:
    """把"想要的秒数"换成 Agnes 视频的 num_frames+frame_rate（agnes-video-v2.0 没有 duration 参数，
    时长=num_frames/frame_rate）。约束：num_frames 须 8n+1 且 ≤441，时长 ~3..18s。
    @24fps：81≈3s / 121≈5s / 241≈10s / 441≈18s。无 duration 返回空（用上游默认）。"""
    if not duration:
        return {}
    fps = 24
    target = max(3, min(int(duration), 18)) * fps
    num_frames = max(81, min(8 * round((target - 1) / 8) + 1, 441))
    return {"num_frames": num_frames, "frame_rate": fps}


async def create_video_task(
    router: Any, prompt: str, model: str = "agnes-video", duration: Optional[int] = None
) -> tuple[str, str]:
    """只创建生视频任务、不等待轮询。返回 (task_id, early_url)：
    early_url 非空=上游创建即给了结果；否则给 task_id 让调用方自己异步轮询（飞书桥就这么用，不卡）。
    duration=想要的秒数(如 10)，随 payload 传给上游：支持就按它出时长，不支持则被忽略。"""
    route = router.resolve(model)
    if route is None:
        return "", ""
    provider = route.provider
    upstream_model = str(route.upstream_model)
    extra = _frames_for_seconds(duration)
    req = VideoGenerationRequest(model=model, prompt=prompt, **extra)  # type: ignore[call-arg]
    try:
        created = await generate_video_with_accounting(
            provider,
            req,
            upstream_model,
            actual_model=model,
        )
    except (ProviderCallLedgerUnavailable, PaidMediaAuthorityRequired):
        raise
    except Exception:  # noqa: BLE001
        return "", ""
    early = _find_media_url(created)
    if early:
        return "", early
    # video_id 优先：Agnes 轮询端点只认 video_id，task_id 会 404
    _d = created.get("data") or {}
    tid = next((created.get(k) or _d.get(k)
                for k in ("video_id", "task_id", "id", "request_id")
                if created.get(k) or _d.get(k)), None)
    return (str(tid) if tid else ""), ""
