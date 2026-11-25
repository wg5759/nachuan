"""视频工作室与拉片路由（从 gateway/app.py 拆出，工作室受 enable_media_studio 门禁控制）。"""

from __future__ import annotations

import asyncio
import glob
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key, require_bridge_or_api_key
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import DurableMediaRequestClaim
from gateway.media_binary import MediaBinaryUnavailable, require_media_binary
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.routes.audio_vision import (
    _CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES,
    _abandon_channel_media_pre_provider,
    _channel_media_heartbeat_loop,
    _decode_bridge_channel_media,
    _persist_channel_media_success,
)
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.url_safety import is_public_http_url
from orchestrator.studio import generate_plan, get_job, start_execution
from orchestrator.vision import pick_vision_model

router = APIRouter(tags=["studio-lapian"])

_LAPIAN_OFFICIAL_HOSTS = frozenset({
    "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
    "bilibili.com", "www.bilibili.com", "b23.tv",
    "douyin.com", "www.douyin.com", "v.douyin.com", "iesdouyin.com",
    "vimeo.com", "www.vimeo.com", "player.vimeo.com",
    "ixigua.com", "www.ixigua.com",
    "kuaishou.com", "www.kuaishou.com", "v.kuaishou.com",
    "xiaohongshu.com", "www.xiaohongshu.com", "xhslink.com",
    "weibo.com", "www.weibo.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
})
_LAPIAN_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
_LAPIAN_YTDLP_RISK_ENV = "NACHUAN_ENABLE_UNPINNED_YTDLP"
_LAPIAN_YTDLP_RISK_ACCEPT = "I_ACCEPT_UNPINNED_YTDLP_NETWORK"


def _app_mod():
    import gateway.app as _mod

    return _mod


def _require_media_studio_enabled() -> None:
    if not _app_mod().get_settings().enable_media_studio:
        raise HTTPException(
            status_code=503,
            detail="视频工作室功能默认关闭，请设置 NACHUAN_ENABLE_MEDIA_STUDIO=1 后启用",
        )


def _lapian_ytdlp_enabled() -> bool:
    """Fail closed unless an operator accepts yt-dlp's unpinned network boundary."""

    if not current_runtime_profile().allows(RuntimeCapability.PLUGIN_AUTO_DISCOVERY):
        return False
    return os.getenv(_LAPIAN_YTDLP_RISK_ENV, "") == _LAPIAN_YTDLP_RISK_ACCEPT


def _safe_lapian_url(url: str) -> bool:
    """Accept only exact, reviewed HTTPS origins before the explicit risk opt-in."""

    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "\\" in parsed.netloc
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
        ):
            return False
        if parsed.port not in (None, 443):
            return False
        host = parsed.hostname.lower()
        if host not in _LAPIAN_OFFICIAL_HOSTS:
            return False
    except (UnicodeError, ValueError):
        return False
    return _app_mod().is_public_http_url(url)


def _attested_ytdlp_ffmpeg_location() -> str:
    """Require independently attested ffmpeg and ffprobe in one closed directory."""

    app_mod = _app_mod()
    ffmpeg = app_mod.require_media_binary("ffmpeg")
    ffprobe = app_mod.require_media_binary("ffprobe")
    ffmpeg_dir = os.path.normcase(os.path.abspath(os.path.dirname(ffmpeg.path)))
    ffprobe_dir = os.path.normcase(os.path.abspath(os.path.dirname(ffprobe.path)))
    if ffmpeg_dir != ffprobe_dir:
        raise MediaBinaryUnavailable(
            "yt-dlp 不可用：经认证的 ffmpeg 与 ffprobe 必须位于同一目录"
        )
    return ffmpeg_dir


def _ytdlp_download(url: str, out_tmpl: str) -> tuple[str, str]:
    """Development-only unpinned download with plugins and executable discovery off."""
    app_mod = _app_mod()
    if not app_mod._safe_lapian_url(url):  # noqa: SLF001
        return "", "仅允许固定官方站点的公网 HTTPS 视频 URL（仅默认 443 端口）"
    if not app_mod._lapian_ytdlp_enabled():  # noqa: SLF001
        return "", (
            "网址拉片默认关闭；仅开发环境可显式设置 "
            f"{_LAPIAN_YTDLP_RISK_ENV}={_LAPIAN_YTDLP_RISK_ACCEPT} 接受未固定网络风险"
        )
    ffmpeg_location = _attested_ytdlp_ffmpeg_location()
    os.environ["YTDLP_NO_PLUGINS"] = "1"
    try:
        import yt_dlp
    except ImportError:
        return "", "未安装 yt-dlp"
    base = {
        "outtmpl": out_tmpl,
        "quiet": True,
        "no_warnings": True,
        "format": "mp4[height<=720]/best[height<=720]/best",
        "merge_output_format": "mp4",
        "noplaylist": True,
        "max_filesize": _LAPIAN_MAX_DOWNLOAD_BYTES,
        "socket_timeout": 20,
        "retries": 2,
        "fragment_retries": 2,
        "js_runtimes": {},
        "remote_components": set(),
        "cachedir": False,
        "external_downloader": {},
        "external_downloader_args": {},
        "ffmpeg_location": ffmpeg_location,
    }
    err = ""
    try:
        with yt_dlp.YoutubeDL(base) as ydl:
            ydl.download([url])
    except Exception as exc:  # noqa: BLE001
        err = str(exc)[:300]
    files = glob.glob(out_tmpl.replace("%(ext)s", "*"))
    if files:
        try:
            if os.path.getsize(files[0]) > _LAPIAN_MAX_DOWNLOAD_BYTES:
                return "", "视频超过 512MB 安全上限"
        except OSError:
            return "", "下载结果不可读"
    return (files[0] if files else "", err)


async def lapian_url_report(
    router_obj: Any,
    url: str,
    *,
    vision_model: str = "agnes-flash",
    synth_model: Any = None,
    max_frames: int = 40,
    with_audio: bool = True,
) -> dict[str, Any]:
    """拉片·网址版内部函数：抠链接 → yt-dlp 下载 → run_lapian 出报告。"""
    app_mod = _app_mod()
    url = str(url or "").strip()
    if not url:
        return {"error": "需要 url"}
    _m = re.search(r"https?://[^\s，。、）)\]】「」'\"]+", url)
    if _m:
        url = _m.group(0).rstrip("，。、）)】],.;")
    if not app_mod._safe_lapian_url(url):  # noqa: SLF001
        return {
            "error": "仅允许固定官方站点的公网 HTTPS 视频 URL（仅默认 443 端口）",
            "unsafe_url": True,
        }
    if not app_mod._lapian_ytdlp_enabled():  # noqa: SLF001
        return {
            "error": (
                "网址拉片默认关闭；仅开发环境可显式设置 "
                f"{_LAPIAN_YTDLP_RISK_ENV}={_LAPIAN_YTDLP_RISK_ACCEPT} "
                "接受 yt-dlp 未固定网络风险"
            ),
            "unavailable": True,
            "status_code": 503,
        }
    max_frames = max(1, min(80, int(max_frames)))
    tmpdir = tempfile.mkdtemp(prefix="lapian_url_")
    try:
        try:
            path, dl_err = await run_in_threadpool(
                app_mod._ytdlp_download,  # noqa: SLF001
                url,
                os.path.join(tmpdir, "v.%(ext)s"),
            )
        except MediaBinaryUnavailable as exc:
            return {
                "error": str(exc),
                "unavailable": True,
                "status_code": 503,
            }
        if not path:
            return {"error": "下载失败：" + (dl_err or "网址不支持/网络/需登录")}
        return await app_mod.run_lapian(
            router_obj,
            path,
            vision_model=vision_model,
            synth_model=synth_model,
            max_frames=max_frames,
            with_audio=with_audio,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@router.post("/v1/workflows/daily-video/start")
async def daily_video_start(_: str = Depends(require_api_key)):
    """Disabled until an independently sandboxed, attested worker exists."""
    raise HTTPException(
        status_code=503,
        detail="日更 Python 启动器已关闭：需要独立低权限执行 worker 后才能启用",
    )


@router.post("/v1/studio/plan")
async def studio_plan(request: Request, _: str = Depends(require_api_key)):
    """出/改分镜方案：{goal, feedback?, plan?} → {plan}。只出方案、不生成视频。"""
    _require_media_studio_enabled()
    body = await request.json()
    goal = str(body.get("goal") or "").strip()
    if not goal:
        raise HTTPException(status_code=422, detail="需要 goal（视频目标）")
    plan = await generate_plan(
        request.app.state.router,
        goal,
        str(body.get("feedback") or ""),
        body.get("plan"),
    )
    return {"plan": plan}


@router.post("/v1/studio/execute")
async def studio_execute(request: Request, _: str = Depends(require_api_key)):
    """③ 按方案成片：{plan} → 起后台任务，返回 {job_id}（逐镜生成→拼接）。"""
    _require_media_studio_enabled()
    app_mod = _app_mod()
    if not current_runtime_profile().allows(RuntimeCapability.STUDIO_EXECUTION):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭工作室执行；需要独立低权限 worker",
        )
    body = await request.json()
    plan = body.get("plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("shots"), list):
        raise HTTPException(status_code=422, detail="plan 格式无效")
    if not plan["shots"]:
        raise HTTPException(status_code=422, detail="需要 plan（含 shots）")
    if len(plan["shots"]) > 100 or len(json.dumps(plan, ensure_ascii=False)) > 256_000:
        raise HTTPException(status_code=422, detail="plan 超过 100 个镜头或 256KB 安全上限")
    out_dir = str(Path(app_mod.get_settings().usage_db_path).parent / "studio")
    task = str(body.get("task") or f"执行视频方案：{str(plan.get('title') or '未命名')}")
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=out_dir,
        user_id=str(
            body.get("user_id") or app_mod.get_settings().agent_user_id or "owner"
        ),
        scope="studio_execute",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={"plan": plan},
    )
    if held is not None:
        return held
    try:
        job_id = start_execution(request.app.state.router, plan, out_dir)
    except Exception:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return {"job_id": job_id}


@router.get("/v1/studio/execute/{job_id}")
async def studio_execute_status(job_id: str, _: str = Depends(require_api_key)):
    """轮询成片进度：{status, progress, total, msg, video, error}。完成后视频在 /v1/studio/video/{id}。"""
    _require_media_studio_enabled()
    return get_job(job_id)


@router.get("/v1/studio/video/{job_id}")
async def studio_video(job_id: str, _: str = Depends(require_api_key)):
    """取成片结果（mp4）。"""
    _require_media_studio_enabled()
    job = get_job(job_id)
    vid = job.get("video") or ""
    if job.get("status") != "done" or not vid or not Path(vid).exists():
        raise HTTPException(status_code=404, detail="还没成片或文件不存在")
    return FileResponse(vid, media_type="video/mp4", filename="video.mp4")


@router.post("/v1/lapian")
async def lapian_endpoint(
    request: Request,
    vision_model: str = "agnes-flash",
    synth_model: str | None = None,
    max_frames: int = 40,
    with_audio: bool = True,
    credential: str = Depends(require_bridge_or_api_key),
):
    """拉片（#29）：请求体=视频字节 → 抽帧+逐帧看图(+台词转写) → 拉片报告+复现SOP。"""
    app_mod = _app_mod()
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="需要视频数据（请求体）")
    frame = _decode_bridge_channel_media(
        data,
        credential=credential,
        operation="lapian.analyze",
        expected_params={
            "vision_model": vision_model,
            "synth_model": synth_model or "",
            "max_frames": max_frames,
            "with_audio": with_audio,
        },
    )
    store: DurableChannelMediaRequestStore | None = None
    claim: DurableMediaRequestClaim | None = None
    payload = data
    if frame is not None:
        store, claim = await app_mod._claim_bridge_channel_media(  # noqa: SLF001
            frame,
            max_success_bytes=_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES,
        )
        if claim.state == "succeeded":
            if not isinstance(claim.response, dict):
                raise HTTPException(
                    status_code=503,
                    detail={"code": "channel_media_receipt_corrupt", "retryable": False},
                )
            return claim.response
        payload = frame.raw
        try:
            selected_vision_model = pick_vision_model(
                request.app.state.router, vision_model
            )
        except BaseException:
            await _abandon_channel_media_pre_provider(store, claim)
            raise
        if not selected_vision_model:
            await _abandon_channel_media_pre_provider(store, claim)
            raise HTTPException(
                status_code=503,
                detail={"code": "channel_media_vision_unavailable", "retryable": True},
            )
        vision_model = selected_vision_model
    fd, path = tempfile.mkstemp(suffix=".mp4", prefix="lapian_in_")
    os.close(fd)
    provider_started = False
    preprovider_abandoned = False
    heartbeat_lost = asyncio.Event()
    heartbeat_task: asyncio.Task[None] | None = None

    async def before_provider() -> None:
        nonlocal heartbeat_task, provider_started
        if provider_started or store is None or claim is None:
            return
        await app_mod._enter_channel_media_provider_phase(  # noqa: SLF001
            store,
            claim,
            max_success_bytes=_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES,
        )
        provider_started = True
        heartbeat_task = asyncio.create_task(
            _channel_media_heartbeat_loop(store, claim, heartbeat_lost)
        )

    async def abandon_before_provider() -> None:
        nonlocal preprovider_abandoned
        if (
            preprovider_abandoned
            or provider_started
            or store is None
            or claim is None
        ):
            return
        await _abandon_channel_media_pre_provider(store, claim)
        preprovider_abandoned = True

    try:
        with open(path, "wb") as f:
            f.write(payload)
        scope = (
            bind_provider_call_scope(
                turn_id=claim.turn_id,
                workflow_id=f"{frame.channel}:lapian.analyze",
                role="channel-media",
            )
            if frame is not None and claim is not None
            else bind_provider_call_scope()
        )
        with scope:
            run_task = asyncio.create_task(
                app_mod.run_lapian(
                    request.app.state.router,
                    path,
                    vision_model=vision_model,
                    synth_model=synth_model,
                    max_frames=max_frames,
                    with_audio=with_audio,
                    before_provider=before_provider if frame is not None else None,
                )
            )
            lost_task = asyncio.create_task(heartbeat_lost.wait())
            try:
                done, _pending = await asyncio.wait(
                    {run_task, lost_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if lost_task in done and lost_task.result():
                    run_task.cancel()
                    await asyncio.gather(run_task, return_exceptions=True)
                    raise HTTPException(
                        status_code=503,
                        detail={
                            "code": "channel_media_lease_lost",
                            "retryable": False,
                        },
                    )
                res = await run_task
            finally:
                if not run_task.done():
                    run_task.cancel()
                await asyncio.gather(run_task, return_exceptions=True)
                lost_task.cancel()
                if heartbeat_task is not None:
                    heartbeat_task.cancel()
                    await asyncio.gather(heartbeat_task, return_exceptions=True)
                await asyncio.gather(lost_task, return_exceptions=True)
        if res.get("error"):
            await abandon_before_provider()
            status = (
                503
                if res.get("unavailable") is True and res.get("status_code") == 503
                else 502
            )
            raise HTTPException(status_code=status, detail=res["error"])
        if store is not None and claim is not None:
            if not provider_started:
                await abandon_before_provider()
                raise HTTPException(
                    status_code=503,
                    detail={
                        "code": "channel_media_provider_fence_missing",
                        "retryable": True,
                    },
                )
            return await _persist_channel_media_success(store, claim, res)
        return res
    except BaseException:
        await abandon_before_provider()
        raise
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


@router.post("/v1/lapian/url")
async def lapian_url_endpoint(request: Request, _: str = Depends(require_api_key)):
    """拉片·网址版：默认关闭；显式开发风险开关后仅接受固定官方 HTTPS URL。"""
    app_mod = _app_mod()
    body = await request.json()
    url = str(body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=422, detail="需要 url")
    res = await app_mod.lapian_url_report(
        request.app.state.router,
        url,
        vision_model=str(body.get("vision_model") or "agnes-flash"),
        synth_model=body.get("synth_model"),
        max_frames=max(1, min(80, int(body.get("max_frames") or 40))),
        with_audio=bool(body.get("with_audio", True)),
    )
    if res.get("error"):
        if res.get("unsafe_url"):
            status = 422
        elif res.get("unavailable") is True and res.get("status_code") == 503:
            status = 503
        else:
            status = 502
        raise HTTPException(status_code=status, detail=res["error"])
    return res
