"""视频工作室（创作工作室线·第①②步）：导演给分镜方案、据反馈调教。

按 Codex 那套工作流：不直接生成视频，先出「可执行的分镜方案」让机主审/改，定稿后再执行（③在后）。
方案是结构化分镜（每镜画面/时长/运动），后续第③步逐镜生成+首尾帧衔接+拼接据此走。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
import uuid
from typing import Any, Optional

from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.media_binary import (
    MediaBinaryUnavailable,
    require_media_binary,
    run_media_binary,
)
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.public_media import (
    PublicFetchContentTypeError,
    PublicFetchError,
    PublicFetchSecurityError,
    PublicFetchTimeout,
    PublicFetchTooLarge,
    download_public_file,
)
from gateway.schemas import ChatCompletionRequest, ChatMessage
from orchestrator.modes import pick_model

_DIRECTOR = (
    "你是资深视频导演。给出**可执行的分镜方案**，只输出 JSON（不要解释、不要 markdown 代码块）。"
    "结构：{\"title\":\"片名\",\"style\":\"整体风格/配色/节奏，一句话\","
    "\"subject\":\"主角/主体的固定外观（长相/服装/配色/造型等，供每镜复用以保持人物物体一致），一句话\","
    "\"shots\":[{\"n\":1,\"desc\":\"画面描述（具体：主体/动作/场景/光线/构图）\","
    "\"seconds\":5,\"motion\":\"镜头运动（推/拉/摇/移/跟/固定）\"}]}。"
    "每镜时长 3–18 秒；镜头数按目标和总时长合理拆；desc 要具体到能直接拿去生成画面。"
)


def _parse_plan(txt: str) -> dict[str, Any]:
    """从模型输出里抠出 JSON 分镜方案，容错（抠不出就把原文放 raw）。"""
    m = re.search(r"\{.*\}", txt or "", re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            d.setdefault("title", "")
            d.setdefault("style", "")
            d.setdefault("subject", "")
            d.setdefault("shots", [])
            return d
        except Exception:  # noqa: BLE001
            pass
    return {"title": "", "style": "", "subject": "", "shots": [], "raw": (txt or "").strip()}


async def generate_plan(
    router: Any, goal: str, feedback: str = "", current_plan: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """出分镜方案：首次按 goal 出；带 feedback+current_plan 则据反馈改。返回 storyboard dict。"""
    model = pick_model(router, "premium") or pick_model(router, "cheap") or "agnes-flash"
    if current_plan and feedback:
        user = (
            f"目标：{goal}\n现有分镜方案：{json.dumps(current_plan, ensure_ascii=False)}\n"
            f"按这条反馈修改方案（只改需要改的，保留其余）：{feedback}"
        )
    else:
        user = f"目标：{goal}\n给出分镜方案。"
    req = ChatCompletionRequest(
        model=model,
        messages=[
            ChatMessage(role="system", content=_DIRECTOR),
            ChatMessage(role="user", content=user),
        ],
    )
    with bind_provider_call_scope(role="studio.storyboard.plan"):
        res, _served, _route = await chat_with_fallback(router, req)
    txt = (res.get("choices") or [{}])[0].get("message", {}).get("content", "")
    return _parse_plan(txt)


# ── ③ 执行：逐镜生成 → 下载 → ffmpeg 拼接（MVP：先各镜独立，首尾衔接/一致性版随后）──
# job 状态**落盘持久化**（机主实测灾难根修）：长视频要跑几分钟~十几分钟，纯内存 _JOBS 在
# dev 热更新/引擎重启时全丢——成片其实拼好了(final_{job_id}.mp4 在 data/studio/)、进度索引却蒸发，
# 前端永远拿不回、以为模型敷衍。落盘后 get_job 断电续命：内存没了就从磁盘 job 文件读，
# 连 job 文件都没但成片文件在 → 直接认成完成。
_JOBS: dict[str, dict[str, Any]] = {}
_DOWNLOAD_TIMEOUT_SECONDS = float(os.getenv("STUDIO_DOWNLOAD_TIMEOUT_SECONDS", "120"))
_FFMPEG_TIMEOUT_SECONDS = float(os.getenv("STUDIO_FFMPEG_TIMEOUT_SECONDS", "300"))
_FRAME_TIMEOUT_SECONDS = float(os.getenv("STUDIO_FRAME_TIMEOUT_SECONDS", "30"))
_MAX_CLIP_BYTES = 512 * 1024 * 1024


class StudioStageTimeout(RuntimeError):
    """Studio 的外部阶段超过硬时限；上层必须把 job 写入失败终态。"""


def _out_dir() -> str:
    from gateway.config import get_settings
    from pathlib import Path

    return str(Path(get_settings().usage_db_path).parent / "studio")


def _job_file(job_id: str) -> str:
    return os.path.join(_out_dir(), f"job_{job_id}.json")


def _persist(job_id: str, job: dict[str, Any]) -> None:
    """把 job 状态原子落盘（每次进度更新都写；失败静默不炸主流程）。"""
    try:
        os.makedirs(_out_dir(), exist_ok=True)
        p = _job_file(job_id)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(job, f, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def get_job(job_id: str) -> dict[str, Any]:
    """查 job：优先内存；内存丢了(重启)从磁盘 job 文件读；job 文件也没但成片已落盘 → 认完成。"""
    if job_id in _JOBS:
        return _JOBS[job_id]
    try:
        with open(_job_file(job_id), encoding="utf-8") as f:
            j = json.load(f)
        _JOBS[job_id] = j  # 回填内存
        return j
    except Exception:  # noqa: BLE001
        pass
    # 连 job 文件都没了，但成片在盘上 → 直接认完成（成片没白做，机主的片能取回）
    final = os.path.join(_out_dir(), f"final_{job_id}.mp4")
    if os.path.exists(final):
        return {"status": "done", "progress": 1, "total": 1, "video": final, "error": "", "msg": "完成(从磁盘恢复)"}
    return {"status": "unknown"}


async def _download(
    url: str,
    path: str,
    *,
    timeout_seconds: float = _DOWNLOAD_TIMEOUT_SECONDS,
) -> None:
    """下载镜头；DNS 验证结果固定到 socket，单一 deadline 覆盖所有网络阶段。"""
    total = max(float(timeout_seconds), 0.01)
    completed = False
    fetched_path = ""

    try:
        try:
            fetched = await asyncio.to_thread(
                download_public_file,
                url,
                max_bytes=_MAX_CLIP_BYTES,
                allowed_type_prefixes=("video/",),
                allowed_exact_types=("application/octet-stream",),
                total_timeout=total,
                idle_timeout=min(total, 20.0),
                max_redirects=5,
                headers={"Accept": "video/*, application/octet-stream;q=0.8"},
                temp_dir=os.path.dirname(os.path.abspath(path)),
            )
            fetched_path = fetched.path
            os.replace(fetched_path, path)
            fetched_path = ""
            completed = True
        except PublicFetchTimeout as exc:
            raise StudioStageTimeout(f"视频下载超时（硬时限 {total:g} 秒）") from exc
        except PublicFetchTooLarge as exc:
            raise ValueError("Studio 单镜超过 512MB 安全上限") from exc
        except PublicFetchContentTypeError as exc:
            raise ValueError("Studio 上游返回的不是视频") from exc
        except PublicFetchSecurityError as exc:
            raise ValueError("Studio 视频 URL 必须是可验证的公网 http/https") from exc
        except PublicFetchError as exc:
            raise RuntimeError("Studio 视频下载失败") from exc
    finally:
        if not completed:
            for candidate in (fetched_path,):
                if not candidate:
                    continue
                try:
                    os.remove(candidate)
                except OSError:
                    pass


def _looks_like_image(path: str) -> bool:
    """下载文件是不是图片（图生视频回显的图，不是视频）——看文件头魔数。
    第二道防线：万一 URL 校验漏网，也别把 PNG 塞进拼接/当末帧传给下一镜（污染全链）。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return True  # 读不了当坏文件
    return head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8"))  # PNG / JPEG / GIF


def _stitch(
    clips: list[str],
    out_path: str,
    *,
    timeout_seconds: float = _FFMPEG_TIMEOUT_SECONDS,
) -> None:
    """ffmpeg 把多个镜头 mp4 拼成一条。clips 都在 out_dir 内，用 cwd=out_dir + 纯 basename，
    让 ffmpeg 完全不碰非 ASCII 路径（Windows 上中文路径会让 ffmpeg 报错）。re-encode 保兼容。"""
    out_dir = os.path.dirname(os.path.abspath(out_path))
    out_name = os.path.basename(out_path)
    list_name = out_name + ".txt"
    with open(os.path.join(out_dir, list_name), "w", encoding="utf-8") as f:
        for p in clips:
            f.write("file '" + os.path.basename(p).replace("'", "'\\''") + "'\n")
    total = max(float(timeout_seconds), 0.01)
    completed = False
    try:
        try:
            r = run_media_binary(
                "ffmpeg",
                ["-nostdin", "-y", "-f", "concat", "-safe", "0", "-i", list_name,
                 "-c:v", "libx264", "-pix_fmt", "yuv420p", "-an", out_name],
                cwd=out_dir,
                capture_output=True,
                text=True,
                timeout=total,
            )
        except subprocess.TimeoutExpired as exc:
            raise StudioStageTimeout(f"ffmpeg 拼接超时（硬时限 {total:g} 秒）") from exc
        if r.returncode != 0:
            raise RuntimeError("ffmpeg 拼接失败：" + (r.stderr or "")[-400:])
        completed = True
    finally:
        # get_job 会把 final_*.mp4 当完成证据，所以失败时绝不能留下半成品。
        if not completed:
            try:
                os.remove(out_path)
            except OSError:
                pass


def _last_frame_png(
    clip_path: str,
    *,
    timeout_seconds: float = _FRAME_TIMEOUT_SECONDS,
) -> bytes:
    """ffmpeg 抽末帧；普通失败回退 b''，硬超时上抛并结束 job。"""
    out_dir = os.path.dirname(os.path.abspath(clip_path))
    out_name = os.path.basename(clip_path) + ".last.png"  # cwd=out_dir + basename，避开中文路径
    p = os.path.join(out_dir, out_name)
    try:
        os.remove(p)
    except OSError:
        pass
    try:
        try:
            r = run_media_binary(
                "ffmpeg",
                ["-nostdin", "-y", "-sseof", "-1", "-i", os.path.basename(clip_path),
                 "-update", "1", "-frames:v", "1", out_name],
                cwd=out_dir,
                capture_output=True,
                text=True,
                timeout=max(float(timeout_seconds), 0.01),
            )
        except subprocess.TimeoutExpired as exc:
            raise StudioStageTimeout(
                f"ffmpeg 抽帧超时（硬时限 {max(float(timeout_seconds), 0.01):g} 秒）"
            ) from exc
        if r.returncode == 0 and os.path.isfile(p):
            with open(p, "rb") as f:
                return f.read()
    except (StudioStageTimeout, MediaBinaryUnavailable):
        raise
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            os.remove(p)
        except OSError:
            pass
    return b""


# 全局串行锁：**同时只跑一个**长视频 job。Agnes 套餐视频每日额度有限(如 500/天)，长视频吃量大户
# (一片 6-9 镜)；多个 job 并发会更快烧完额度、且互相抢 TPS。排队串行、互不干扰、额度花在刀刃上。
_STUDIO_LOCK = asyncio.Lock()


async def _run_execution(job_id: str, router: Any, plan: dict[str, Any], out_dir: str) -> None:
    import base64

    from orchestrator.media import gen_video

    job = _JOBS[job_id]
    if _STUDIO_LOCK.locked():
        job["msg"] = "排队中：前面有长视频在生成，轮到就自动开始…"
        _persist(job_id, job)
    async with _STUDIO_LOCK:  # 前一个 job 没跑完就在此等待，绝不并发撞限流
        await _do_execution(job_id, router, plan, out_dir)


async def _do_execution(job_id: str, router: Any, plan: dict[str, Any], out_dir: str) -> None:
    import base64

    from orchestrator.media import gen_video

    job = _JOBS[job_id]
    try:
        os.makedirs(out_dir, exist_ok=True)
        shots = plan.get("shots") or []
        # 锁主体+风格，拼进每镜提示词 → 跨镜人物/物体/风格一致（文字级；像素级靠末帧→首帧衔接）
        lock = "，".join(x for x in [str(plan.get("subject", "")), str(plan.get("style", ""))] if x)
        job["total"] = len(shots)
        _persist(job_id, job)
        clips: list[str] = []
        # 上一镜末帧（**纯 base64 直传**当下一镜首帧——Agnes image 字段收纯 base64，
        # KB agnes-api-实战手册已真机验证；不再走图床：少一个外部依赖、帧不出本机）
        prev_frame_b64 = ""
        for i, shot in enumerate(shots):
            job["progress"] = i
            job["msg"] = f"第 {i + 1}/{len(shots)} 镜生成中（每镜约 1-2 分钟）…"
            _persist(job_id, job)
            if i > 0:
                await asyncio.sleep(2)  # 镜间小隔：错开 TPS 峰值，稳一点（套餐 TPS 高，不必久等）
            desc = (lock + "。" if lock else "") + str(shot.get("desc", ""))
            url = await gen_video(
                router, desc, duration=int(shot.get("seconds") or 5),
                image=prev_frame_b64 or None,
                max_wait=300,  # 每镜给足：生成 60-140s + 限流慢等余量（默认 420 也行，显式更清楚）
            )
            if not url:
                prev_frame_b64 = ""  # 本镜没出 → 下一镜回退文生，别接旧帧
                continue
            clip = os.path.join(out_dir, f"{job_id}_shot{i}.mp4")
            await _download(url, clip)
            # 第二道防线：下载的若是图片(图生视频回显图被误当成片)→ 删掉、别塞进拼接，
            # 更别把这张图当末帧传给下一镜（否则全链循环污染成同一张 PNG——机主实测根因）。
            if _looks_like_image(clip):
                try:
                    os.remove(clip)
                except OSError:
                    pass
                prev_frame_b64 = ""  # 回退：下一镜重新文生
                continue
            clips.append(clip)
            # 抽末帧 → 纯 base64 给下一镜当首帧；抽帧失败则退回文字级衔接（不炸整单）
            frame = await asyncio.to_thread(_last_frame_png, clip)
            prev_frame_b64 = base64.b64encode(frame).decode() if frame else ""
        n_ok, n_all = len(clips), len(shots)
        if not clips:
            job.update(status="error",
                       msg="失败",
                       finished_at=time.time(),
                       error=f"0/{n_all} 镜都没生成出来。最可能是 **Agnes 视频每日额度已用尽**（套餐视频有每日上限，"
                             "长视频一片就吃 6-9 次额度、很快烧完）——去 Agnes 后台看「视频生成」额度是否见底；"
                             "额度够的话则是上游繁忙，隔几分钟重试。")
            _persist(job_id, job)
            return
        job["msg"] = "拼接成片中…"
        _persist(job_id, job)
        out = os.path.join(out_dir, f"final_{job_id}.mp4")
        await asyncio.to_thread(_stitch, clips, out)
        if n_ok < n_all:
            # 部分镜失败 → 成片给你(能看)，但**如实标注不完整**，绝不假装"完成30秒"（机主实测:给3秒残片当done）
            job.update(status="done", progress=n_ok, video=out, partial=True,
                       msg=f"⚠️ 仅 {n_ok}/{n_all} 镜成功，成片偏短、不足目标时长（其余镜生成失败）")
        else:
            job.update(status="done", progress=n_all, video=out, msg="完成")
        _persist(job_id, job)
    except Exception as e:  # noqa: BLE001
        job.update(
            status="error",
            msg="失败",
            error=str(e),
            failure_kind="timeout" if isinstance(e, StudioStageTimeout) else "external_stage",
            finished_at=time.time(),
        )
        _persist(job_id, job)


def start_execution(router: Any, plan: dict[str, Any], out_dir: str) -> str:
    """起一个后台成片任务，返回 job_id（GET /v1/studio/execute/{id} 轮询进度）。"""
    if not current_runtime_profile().allows(RuntimeCapability.STUDIO_EXECUTION):
        raise PermissionError(
            "当前运行配置已关闭工作室执行；需要独立低权限 worker"
        )
    # Refuse before allocating a durable job/lease; every actual launch still
    # re-attests so a post-start replacement cannot bypass the boundary.
    require_media_binary("ffmpeg")
    from gateway.admission import (
        BackgroundJobLimitExceeded,
        get_background_job_pool,
    )

    job_id = uuid.uuid4().hex[:12]
    pool = get_background_job_pool()
    lease = pool.try_acquire(kind="studio", external_ids=(job_id,))
    if lease is None:
        raise BackgroundJobLimitExceeded("background studio capacity reached")
    _JOBS[job_id] = {
        "status": "running", "progress": 0, "total": 0, "video": "", "error": "", "msg": "开始…"
    }
    _persist(job_id, _JOBS[job_id])  # 建即落盘 → 重启后 get_job 能从磁盘查到

    async def tracked_execution() -> None:
        try:
            await _run_execution(job_id, router, plan, out_dir)
        finally:
            pool.release(lease)

    try:
        asyncio.create_task(tracked_execution())
    except Exception:
        pool.release(lease)
        _JOBS[job_id].update(status="error", error="failed to start background task")
        _persist(job_id, _JOBS[job_id])
        raise
    return job_id
