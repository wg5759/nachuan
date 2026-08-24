"""拉片工作流：真 ffmpeg 抽帧 + 编排(mock 视觉/合成)。"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile

import pytest

from orchestrator.workflows import lapian

_FFMPEG = shutil.which("ffmpeg")
_FFPROBE = shutil.which("ffprobe")
_HAS_MEDIA_TOOLS = _FFMPEG is not None and _FFPROBE is not None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _configure_media_attestation(monkeypatch) -> None:
    assert _FFMPEG and _FFPROBE
    monkeypatch.setenv("FFMPEG_BIN", os.path.abspath(_FFMPEG))
    monkeypatch.setenv("FFMPEG_SHA256", _sha256(_FFMPEG))
    monkeypatch.setenv("FFPROBE_BIN", os.path.abspath(_FFPROBE))
    monkeypatch.setenv("FFPROBE_SHA256", _sha256(_FFPROBE))


def _make_test_video(path: str, seconds: int = 4) -> None:
    assert _FFMPEG
    subprocess.run(
        [_FFMPEG, "-f", "lavfi", "-i", f"testsrc=duration={seconds}:size=128x128:rate=10",
         "-pix_fmt", "yuv420p", "-y", path],
        capture_output=True, timeout=60,
    )


@pytest.mark.skipif(not _HAS_MEDIA_TOOLS, reason="需要 ffmpeg + ffprobe")
def test_extract_frames_real(monkeypatch):
    _configure_media_attestation(monkeypatch)
    d = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    try:
        vid = os.path.join(d, "t.mp4")
        _make_test_video(vid, seconds=4)
        frames = lapian.extract_frames(vid, out, fps=1.0, max_frames=4)
        assert len(frames) >= 2  # 4秒@1fps ≈ 4帧
        assert all(os.path.exists(p) for _, p in frames)
        assert frames[0][0] < frames[-1][0]  # 时间戳递增
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)


@pytest.mark.skipif(not _HAS_MEDIA_TOOLS, reason="需要 ffmpeg + ffprobe")
async def test_run_lapian_orchestration(monkeypatch):
    """mock 视觉与合成，验证抽帧→逐帧→出报告整条串起来。"""
    _configure_media_attestation(monkeypatch)

    async def fake_describe(router, image, *, question="", model=""):
        return "画面是测试图案，无文字。"

    async def fake_ask(router, model, messages, *, role):
        assert role == "lapian.synthesize"
        return {"choices": [{"message": {"content": "## 一、拉片报告\n结论\n## 二、复现SOP\n步骤"}}]}

    monkeypatch.setattr(lapian, "describe_image", fake_describe)
    monkeypatch.setattr(lapian, "_ask", fake_ask)

    d = tempfile.mkdtemp()
    try:
        vid = os.path.join(d, "t.mp4")
        _make_test_video(vid, seconds=4)
        res = await lapian.run_lapian(None, vid, synth_model="fake", max_frames=4, with_audio=False)
        assert res.get("error") is None
        assert res["frames"] >= 2
        assert len(res["analyses"]) == res["frames"]
        assert "拉片报告" in res["report"]
        assert res["analyses"][0]["ts"] <= res["analyses"][-1]["ts"]  # 按时间排序
    finally:
        shutil.rmtree(d, ignore_errors=True)


async def test_run_lapian_missing_video():
    out = await lapian.run_lapian(None, "/no/such/video.mp4", synth_model="x", with_audio=False)
    assert "error" in out


async def test_run_lapian_enters_provider_phase_after_local_preflight(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(lapian.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(lapian, "require_media_binary", lambda _name: None)
    monkeypatch.setattr(lapian, "video_duration", lambda _path: 2.0)
    monkeypatch.setattr(
        lapian,
        "extract_frames",
        lambda *_args, **_kwargs: events.append("local-frames") or [(0.0, "f.jpg")],
    )

    async def before_provider() -> None:
        events.append("provider-fence")

    async def fake_analyze(*_args, **_kwargs):
        assert events == ["local-frames", "provider-fence"]
        events.append("vision-provider")
        return [{"ts": 0.0, "desc": "frame"}]

    async def fake_ask(_router, _model, _messages, *, role):
        assert role == "lapian.synthesize"
        events.append("synth-provider")
        return {"choices": [{"message": {"content": "report"}}]}

    monkeypatch.setattr(lapian, "analyze_frames", fake_analyze)
    monkeypatch.setattr(lapian, "_ask", fake_ask)

    result = await lapian.run_lapian(
        object(),
        "video.mp4",
        synth_model="synth",
        max_frames=1,
        with_audio=False,
        before_provider=before_provider,
    )

    assert result["report"] == "report"
    assert events == [
        "local-frames",
        "provider-fence",
        "vision-provider",
        "synth-provider",
    ]


async def test_run_lapian_never_prefers_a_disabled_claude_route(monkeypatch):
    class Router:
        @staticmethod
        def resolve(model):
            return object() if model in {"claude-opus", "glm", "agnes-flash"} else None

        @staticmethod
        def routes_info():
            return [
                {
                    "model": "glm",
                    "tier": "premium",
                    "rank": 1,
                    "flagship": False,
                }
            ]

    chosen: list[str] = []
    monkeypatch.setattr(lapian.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(lapian, "require_media_binary", lambda _name: None)
    monkeypatch.setattr(lapian, "video_duration", lambda _path: 2.0)
    monkeypatch.setattr(lapian, "extract_frames", lambda *_args, **_kwargs: [(0.0, "f.jpg")])

    async def fake_analyze(_router, _frames, *, model):
        del model
        return [{"ts": 0.0, "desc": "frame"}]

    async def fake_ask(_router, model, _messages, *, role):
        assert role == "lapian.synthesize"
        chosen.append(model)
        return {"choices": [{"message": {"content": "report"}}]}

    monkeypatch.setattr(lapian, "analyze_frames", fake_analyze)
    monkeypatch.setattr(lapian, "_ask", fake_ask)

    result = await lapian.run_lapian(
        Router(),
        "video.mp4",
        max_frames=1,
        with_audio=False,
    )

    assert result["synth_model"] == "glm"
    assert chosen == ["glm"]


async def test_run_lapian_local_preflight_failure_never_enters_provider_phase(
    monkeypatch,
):
    entered = False
    monkeypatch.setattr(lapian.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(lapian, "require_media_binary", lambda _name: None)
    monkeypatch.setattr(lapian, "video_duration", lambda _path: 0.0)
    monkeypatch.setattr(lapian, "extract_frames", lambda *_args, **_kwargs: [])

    async def before_provider() -> None:
        nonlocal entered
        entered = True

    result = await lapian.run_lapian(
        object(),
        "video.mp4",
        synth_model="synth",
        with_audio=False,
        before_provider=before_provider,
    )

    assert result == {"error": "抽帧失败（视频无法读取或格式不支持）"}
    assert entered is False
