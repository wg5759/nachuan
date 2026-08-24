"""Studio 外部 I/O 的硬超时与失败终态。"""

from __future__ import annotations

import subprocess

import pytest


async def test_download_stalled_body_hits_total_deadline_and_removes_partial(tmp_path, monkeypatch):
    """服务端发完响应头后永久停住，下载仍须在总时限内失败。"""
    from gateway.public_media import PublicFetchTimeout
    from orchestrator.studio import StudioStageTimeout, _download
    captured = {}

    def timed_out(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        raise PublicFetchTimeout("stalled body")

    monkeypatch.setattr("orchestrator.studio.download_public_file", timed_out)
    target = tmp_path / "shot.mp4"
    target.write_bytes(b"partial")
    with pytest.raises(StudioStageTimeout, match="下载超时"):
        await _download(
            "https://media.example/never-finishes.mp4",
            str(target),
            timeout_seconds=0.15,
        )

    assert captured["kwargs"]["total_timeout"] == 0.15
    assert captured["kwargs"]["idle_timeout"] == 0.15
    assert captured["kwargs"]["max_bytes"] == 512 * 1024 * 1024
    assert captured["kwargs"]["allowed_type_prefixes"] == ("video/",)
    assert target.read_bytes() == b"partial"  # 失败不能误删先前已存在的成片


def test_stitch_ffmpeg_timeout_is_bounded_and_explicit(tmp_path, monkeypatch):
    """拼接 ffmpeg 超时不能被当成普通返回码，更不能永久占住 Studio 锁。"""
    from orchestrator.studio import StudioStageTimeout, _stitch

    def timed_out(*_args, **kwargs):
        assert kwargs["timeout"] == 0.2
        raise subprocess.TimeoutExpired(cmd="ffmpeg", timeout=kwargs["timeout"])

    monkeypatch.setattr("orchestrator.studio.run_media_binary", timed_out)
    with pytest.raises(StudioStageTimeout, match="拼接超时"):
        _stitch([], str(tmp_path / "final.mp4"), timeout_seconds=0.2)


def test_last_frame_ffmpeg_timeout_is_not_silently_downgraded(tmp_path, monkeypatch):
    """抽末帧超时必须结束 job；不能吞掉后继续制造看似成功的残缺成片。"""
    from orchestrator.studio import StudioStageTimeout, _last_frame_png

    clip = tmp_path / "shot.mp4"
    clip.write_bytes(b"fake")
    partial = tmp_path / "shot.mp4.last.png"
    partial.write_bytes(b"partial")

    def timed_out(*_args, **kwargs):
        assert kwargs["timeout"] == 0.2
        raise subprocess.TimeoutExpired(cmd="ffmpeg", timeout=kwargs["timeout"])

    monkeypatch.setattr("orchestrator.studio.run_media_binary", timed_out)
    with pytest.raises(StudioStageTimeout, match="抽帧超时"):
        _last_frame_png(str(clip), timeout_seconds=0.2)
    assert not partial.exists()


async def test_external_stage_timeout_persists_explicit_error_terminal(tmp_path, monkeypatch):
    """任何外部阶段硬超时都必须把轮询状态从 running 写成明确失败。"""
    import orchestrator.media as media
    import orchestrator.studio as studio

    job_id = "timeoutjob01"
    studio._JOBS[job_id] = {
        "status": "running", "progress": 0, "total": 0, "video": "", "error": "", "msg": "开始…"
    }
    monkeypatch.setattr(studio, "_out_dir", lambda: str(tmp_path))

    async def generated(*_args, **_kwargs):
        return "https://example.invalid/shot.mp4"

    async def timed_out(*_args, **_kwargs):
        raise studio.StudioStageTimeout("视频下载超时（测试）")

    monkeypatch.setattr(media, "gen_video", generated)
    monkeypatch.setattr(studio, "_download", timed_out)
    try:
        await studio._do_execution(
            job_id,
            object(),
            {"shots": [{"desc": "镜头", "seconds": 5}]},
            str(tmp_path),
        )
        state = studio.get_job(job_id)
        assert state["status"] == "error"
        assert state["msg"] == "失败"
        assert "下载超时" in state["error"]
        assert state["finished_at"] > 0
    finally:
        studio._JOBS.pop(job_id, None)
