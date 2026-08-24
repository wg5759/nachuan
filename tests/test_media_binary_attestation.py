"""Supply-chain boundaries for ffmpeg/ffprobe process launches."""

from __future__ import annotations

import hashlib
import os
import subprocess

import pytest


_MEDIA_ENV = ("FFMPEG_BIN", "FFMPEG_SHA256", "FFPROBE_BIN", "FFPROBE_SHA256")


def _clear_media_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _MEDIA_ENV:
        monkeypatch.delenv(name, raising=False)


def _fake_executable(tmp_path, name: str, content: bytes = b"attested-v1"):
    suffix = ".exe" if os.name == "nt" else ""
    path = tmp_path / f"{name}{suffix}"
    path.write_bytes(content)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _attest(monkeypatch: pytest.MonkeyPatch, tool: str, path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setenv(f"{tool.upper()}_BIN", str(path.resolve()))
    monkeypatch.setenv(f"{tool.upper()}_SHA256", digest)
    return digest


def test_path_only_ffmpeg_is_never_executed(monkeypatch, tmp_path) -> None:
    """A malicious same-name binary on PATH is not an installation source."""
    from gateway import media_binary

    _clear_media_env(monkeypatch)
    malicious = _fake_executable(tmp_path, "ffmpeg", b"path-hijack")
    monkeypatch.setenv("PATH", str(tmp_path))

    def must_not_run(*_args, **_kwargs):
        raise AssertionError(f"PATH binary executed: {malicious}")

    monkeypatch.setattr(media_binary.subprocess, "run", must_not_run)
    with pytest.raises(media_binary.MediaBinaryUnavailable, match="FFMPEG_BIN") as exc:
        media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    assert exc.value.status_code == 503


def test_relative_path_and_wrong_hash_are_rejected_before_spawn(monkeypatch, tmp_path) -> None:
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    monkeypatch.setenv("FFMPEG_BIN", binary.name)
    monkeypatch.setenv("FFMPEG_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest())
    calls = 0

    def must_not_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("unattested process was spawned")

    monkeypatch.setattr(media_binary.subprocess, "run", must_not_run)
    with pytest.raises(media_binary.MediaBinaryUnavailable):
        media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)

    monkeypatch.setenv("FFMPEG_BIN", str(binary.resolve()))
    monkeypatch.setenv("FFMPEG_SHA256", "0" * 64)
    with pytest.raises(media_binary.MediaBinaryUnavailable):
        media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    assert calls == 0


def test_binary_hash_is_rechecked_immediately_before_every_launch(monkeypatch, tmp_path) -> None:
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)
    calls: list[tuple[list[str], dict]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(media_binary.subprocess, "run", fake_run)
    media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    binary.write_bytes(b"replaced-after-first-launch")
    with pytest.raises(media_binary.MediaBinaryUnavailable, match="SHA-256"):
        media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    assert len(calls) == 1
    assert calls[0][0][0] == str(binary.resolve())


@pytest.mark.skipif(os.name != "nt", reason="Windows executable sharing pin")
def test_windows_media_binary_pin_blocks_replacement_until_process_exit(
    monkeypatch, tmp_path
) -> None:
    """The hash-to-CreateProcess window stays closed for the whole launch."""
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)
    attempted = False

    def fake_run(command, **kwargs):
        nonlocal attempted
        attempted = True
        with pytest.raises(PermissionError):
            binary.write_bytes(b"replacement-during-process")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(media_binary.subprocess, "run", fake_run)
    media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    assert attempted is True

    # The restriction is scoped to the process lifetime, not a permanent ACL.
    binary.write_bytes(b"replacement-after-process")


@pytest.mark.skipif(os.name != "nt", reason="Windows executable sharing pin")
def test_windows_media_binary_pin_rejects_a_preexisting_writer(
    monkeypatch, tmp_path
) -> None:
    """A writer opened before attestation cannot race the verified bytes."""
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffprobe")
    _attest(monkeypatch, "ffprobe", binary)
    monkeypatch.setattr(
        media_binary.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("writer race must fail before spawn"),
    )

    with binary.open("r+b"):
        with pytest.raises(media_binary.MediaBinaryUnavailable, match="并发写入|钉住"):
            media_binary.run_media_binary("ffprobe", ["-version"], timeout=1)


@pytest.mark.skipif(os.name != "nt", reason="Windows executable pathname pin")
def test_windows_media_binary_pin_blocks_parent_directory_rename(
    monkeypatch, tmp_path
) -> None:
    """A directory swap cannot redirect the attested absolute launch path."""
    from gateway import media_binary

    binary_dir = tmp_path / "closed-bin"
    binary_dir.mkdir()
    binary = _fake_executable(binary_dir, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)
    renamed = tmp_path / "renamed-bin"

    def fake_run(command, **kwargs):
        with pytest.raises(PermissionError):
            binary_dir.rename(renamed)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(media_binary.subprocess, "run", fake_run)
    media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    assert binary.exists()
    assert not renamed.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows DLL sidecar search boundary")
def test_windows_media_directory_rejects_unreviewed_dll_sidecar(monkeypatch, tmp_path) -> None:
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)
    (tmp_path / "version.dll").write_bytes(b"unreviewed")
    monkeypatch.setattr(
        media_binary.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("sidecar directory must fail before spawn"),
    )
    with pytest.raises(media_binary.MediaBinaryUnavailable, match="sidecar"):
        media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)


def test_media_process_gets_minimal_environment_without_path_or_secrets(monkeypatch, tmp_path) -> None:
    from gateway import media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    captured: dict = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(media_binary.subprocess, "run", fake_run)
    media_binary.run_media_binary("ffmpeg", ["-version"], timeout=1)
    env = captured["env"]
    assert "PATH" not in {key.upper() for key in env}
    assert "OPENAI_API_KEY" not in {key.upper() for key in env}
    assert captured["shell"] is False
    assert captured["close_fds"] is True
    assert captured["stdin"] is subprocess.DEVNULL


def test_ffprobe_requires_its_own_explicit_attestation(monkeypatch, tmp_path) -> None:
    from gateway import media_binary

    _clear_media_env(monkeypatch)
    ffmpeg = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", ffmpeg)
    monkeypatch.setattr(
        media_binary.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("ffprobe must not reuse ffmpeg attestation"),
    )
    with pytest.raises(media_binary.MediaBinaryUnavailable, match="FFPROBE_BIN"):
        media_binary.run_media_binary("ffprobe", ["-version"], timeout=1)


def test_asr_decoders_fail_closed_without_attestation(monkeypatch) -> None:
    from gateway import asr_nemotron, asr_sensevoice

    _clear_media_env(monkeypatch)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("ASR resolved ffmpeg through PATH")

    monkeypatch.setattr(subprocess, "run", must_not_run)
    with pytest.raises(asr_sensevoice.SenseVoiceUnavailable, match="FFMPEG_BIN"):
        asr_sensevoice._decode_audio(b"untrusted-audio")
    with pytest.raises(asr_nemotron.NemotronUnavailable, match="FFMPEG_BIN"):
        asr_nemotron._decode_audio(b"untrusted-audio")


def test_asr_attested_ffmpeg_keeps_a_hard_decode_timeout(monkeypatch, tmp_path) -> None:
    from gateway import asr_nemotron, asr_sensevoice, media_binary

    binary = _fake_executable(tmp_path, "ffmpeg")
    _attest(monkeypatch, "ffmpeg", binary)

    def timed_out(command, **kwargs):
        assert command[0] == str(binary.resolve())
        assert kwargs["timeout"] == 60.0
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(media_binary.subprocess, "run", timed_out)
    with pytest.raises(asr_sensevoice.SenseVoiceUnavailable, match="硬时限 60 秒"):
        asr_sensevoice._decode_audio(b"audio")
    with pytest.raises(asr_nemotron.NemotronUnavailable, match="硬时限 60 秒"):
        asr_nemotron._decode_audio(b"audio")


def test_studio_fails_closed_without_attested_ffmpeg(monkeypatch, tmp_path) -> None:
    from gateway.media_binary import MediaBinaryUnavailable
    from orchestrator.studio import _stitch

    _clear_media_env(monkeypatch)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("Studio resolved ffmpeg through PATH")

    monkeypatch.setattr(subprocess, "run", must_not_run)
    with pytest.raises(MediaBinaryUnavailable, match="FFMPEG_BIN"):
        _stitch([], str(tmp_path / "final.mp4"), timeout_seconds=0.1)


def test_studio_start_reports_explicit_503_before_allocating_job(monkeypatch) -> None:
    from gateway.media_binary import MediaBinaryUnavailable
    from orchestrator import studio

    _clear_media_env(monkeypatch)
    before = set(studio._JOBS)
    with pytest.raises(MediaBinaryUnavailable) as exc:
        studio.start_execution(None, {"shots": [{}]}, ".")
    assert exc.value.status_code == 503
    assert set(studio._JOBS) == before


async def test_lapian_reports_explicit_unavailable_without_media_attestation(
    monkeypatch, tmp_path
) -> None:
    from orchestrator.workflows import lapian

    _clear_media_env(monkeypatch)
    video = tmp_path / "input.mp4"
    video.write_bytes(b"not-reached")

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("Lapian resolved media tools through PATH")

    monkeypatch.setattr(subprocess, "run", must_not_run)
    result = await lapian.run_lapian(None, str(video), with_audio=False)
    assert result.get("unavailable") is True
    assert "FFMPEG_BIN" in result.get("error", "")
