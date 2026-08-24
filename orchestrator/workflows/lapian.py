"""拉片（#29）：把任意视频拆成可复刻的 SOP。

工作流（对应用户给的 6 步）：抽帧(ffmpeg) → 逐帧看图(视觉) → 逐段排表 → 合成拉片报告 + 复现SOP。
成本策略(cascade)：批量帧默认走免费 agnes-flash 快扫；难帧/关键帧可指定 gpt 精看。
可选：自动抽音频转写(faster-whisper)，把台词并入分析。
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from typing import Any, Optional

from gateway.media_binary import (
    MediaBinaryUnavailable,
    require_media_binary,
    run_media_binary,
)
from orchestrator.modes import _ask, _text, pick_model
from orchestrator.vision import describe_image

_FRAME_Q = "简要描述这一帧：①画面内容 ②镜头/构图/景别 ③画面上的文字(逐字OCR) ④图形/特效/转场。每点一句、没有就略过。"


def video_duration(video_path: str) -> float:
    """ffprobe 取时长（秒）。失败返回 0。"""
    try:
        out = run_media_binary(
            "ffprobe",
            ["-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", video_path],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        return float(out)
    except MediaBinaryUnavailable:
        raise
    except Exception:  # noqa: BLE001
        return 0.0


def extract_frames(video_path: str, out_dir: str, *, fps: float, max_frames: int) -> list[tuple[float, str]]:
    """ffmpeg 均匀抽帧。返回 [(时间戳秒, 帧文件路径)]，按时间升序。"""
    pat = os.path.join(out_dir, "f_%04d.jpg")
    run_media_binary(
        "ffmpeg",
        ["-nostdin", "-i", video_path, "-vf", f"fps={fps}", "-frames:v", str(max_frames),
         "-q:v", "4", "-y", pat],
        capture_output=True,
        timeout=300,
    )
    names = sorted(f for f in os.listdir(out_dir) if f.startswith("f_") and f.endswith(".jpg"))
    return [(i / fps if fps else float(i), os.path.join(out_dir, n)) for i, n in enumerate(names)]


def extract_audio_text(video_path: str) -> str:
    """抽音频 → faster-whisper 转写（best-effort，失败返回空）。"""
    fd, wav = tempfile.mkstemp(prefix="lapian_audio_", suffix=".wav")
    os.close(fd)
    try:
        from gateway.audio import transcribe

        run_media_binary(
            "ffmpeg",
            ["-nostdin", "-i", video_path, "-vn", "-ar", "16000", "-ac", "1", "-y", wav],
            capture_output=True,
            timeout=300,
        )
        with open(wav, "rb") as f:
            data = f.read()
        return (transcribe(data) or "").strip()
    except MediaBinaryUnavailable:
        raise
    except Exception:  # noqa: BLE001
        return ""
    finally:
        try:
            os.remove(wav)
        except OSError:
            pass


async def analyze_frames(
    router: Any, frames: list[tuple[float, str]], *, model: str = "agnes-flash", concurrency: int = 4
) -> list[dict[str, Any]]:
    """逐帧看图（并发受限，免打爆免费额度）。返回 [{ts, desc}]，按时间排序。"""
    sem = asyncio.Semaphore(concurrency)

    async def one(ts: float, path: str) -> dict[str, Any]:
        async with sem:
            try:
                with open(path, "rb") as f:
                    data = f.read()
                desc = await describe_image(router, data, question=_FRAME_Q, model=model)
            except Exception as e:  # noqa: BLE001
                desc = f"(看图失败: {e})"
            return {"ts": round(ts, 1), "desc": (desc or "").strip()}

    out = await asyncio.gather(*[one(ts, p) for ts, p in frames])
    return sorted(out, key=lambda a: a["ts"])


async def run_lapian(
    router: Any,
    video_path: str,
    *,
    vision_model: str = "agnes-flash",
    synth_model: Optional[str] = None,
    max_frames: int = 40,
    with_audio: bool = True,
    before_provider: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """拉片主流程：抽帧 → 逐帧看图 → (可选)台词转写 → 合成拉片报告 + 复现SOP。"""
    if not os.path.exists(video_path):
        return {"error": f"视频不存在：{video_path}"}
    try:
        require_media_binary("ffmpeg")
        require_media_binary("ffprobe")
    except MediaBinaryUnavailable as exc:
        return {"error": str(exc), "unavailable": True, "status_code": 503}
    dur = video_duration(video_path)
    fps = min(1.0, max_frames / dur) if dur > 0 else 0.5  # 自适应：把 max_frames 均匀铺满全片
    tmp = tempfile.mkdtemp(prefix="lapian_")
    try:
        frames = extract_frames(video_path, tmp, fps=fps, max_frames=max_frames)
        if not frames:
            return {"error": "抽帧失败（视频无法读取或格式不支持）"}
        transcript = await asyncio.to_thread(extract_audio_text, video_path) if with_audio else ""
        # Local decoding, frame extraction and optional transcription are safe
        # to retry.  Cross the durable provider fence only after those steps
        # succeed and immediately before the first model invocation.
        if before_provider is not None:
            await before_provider()
        analyses = await analyze_frames(router, frames, model=vision_model)
        table = "\n".join(f"[{a['ts']}s] {a['desc']}" for a in analyses)
        # 合成是"硬推理+写报告"，由当前实时模型池按 premium 元数据选择；
        # 不再把任何已停用或按月订阅的具体型号写死为首选。
        synth = synth_model or pick_model(router, "premium")
        prompt = (
            f"下面是一条约 {dur:.0f} 秒视频按时间排列的逐帧观察（含画面/镜头/文字OCR/图形）。"
            + (f"\n\n【语音转写台词】\n{transcript}\n" if transcript else "")
            + f"\n\n【逐帧观察】\n{table}\n\n"
            "请产出两部分，全部中文、可直接复制：\n\n"
            "## 一、拉片报告\n"
            "- 一句话结论\n- 可复刻度评分（1-5 + 理由）\n- 关键发现（节奏/拍法/亮点）\n"
            "- 配帧逐段表（| 时间 | 画面 | 文字/图形 | 作用 |）\n- 工具链推断（拍摄/剪辑/AI工具）\n\n"
            "## 二、复现 SOP\n可执行分步流程（选题→口播稿→实拍/素材→剪辑→图形动效→导出），让别人能照着复刻。"
        )
        report = _text(
            await _ask(
                router,
                synth,
                [{"role": "user", "content": prompt}],
                role="lapian.synthesize",
            )
        )
        return {
            "duration": round(dur, 1),
            "frames": len(frames),
            "vision_model": vision_model,
            "synth_model": synth,
            "has_transcript": bool(transcript),
            "analyses": analyses,
            "report": report,
        }
    except MediaBinaryUnavailable as exc:
        return {"error": str(exc), "unavailable": True, "status_code": 503}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
