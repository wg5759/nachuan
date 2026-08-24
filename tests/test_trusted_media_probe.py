"""Full-decode gate for paid media before it enters the Desktop vault."""

from __future__ import annotations

import base64
import functools
import hashlib
import io
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest


_LIVE_MEDIA_CONFIG = Path(__file__).parents[1] / "data" / "media-binaries.json"
_MEDIA_ENV = ("FFMPEG_BIN", "FFMPEG_SHA256", "FFPROBE_BIN", "FFPROBE_SHA256")

# These are tiny, real files generated once with the pinned FFmpeg 8.0.1 build.
# Keeping the bytes in the test makes acceptance independent of a fixture
# generator and prevents a broken encoder and decoder from agreeing by accident.
_REAL_MEDIA = {
    "image/png": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAACXBIWXMAAAABAAAAAQBPJcTWAAAAIUlEQVR4nGP8y0AaYCFRPcOoBmIAC1GqkMCoBmIAyaEEAGgAATusqEGCAAAAAElFTkSuQmCC",
    "image/jpeg": "/9j/4AAQSkZJRgABAgAAAQABAAD//gAQTGF2YzYyLjExLjEwMAD/2wBDAAgEBAQEBAUFBQUFBQYGBgYGBgYGBgYGBgYHBwcICAgHBwcGBgcHCAgICAkJCQgICAgJCQoKCgwMCwsODg4RERT/xABMAAEBAAAAAAAAAAAAAAAAAAAABgEBAQAAAAAAAAAAAAAAAAAABgcQAQAAAAAAAAAAAAAAAAAAAAARAQAAAAAAAAAAAAAAAAAAAAD/wAARCAAQABADASIAAhEAAxEA/9oADAMBAAIRAxEAPwCLAE1/f//Z",
    "image/gif": "R0lGODlhEAAQAPcfMQAAACQAAEgAAGwAAJAAALQAANgAAPwAAAAkACQkAEgkAGwkAJAkALQkANgkAPwkAABIACRIAEhIAGxIAJBIALRIANhIAPxIAABsACRsAEhsAGxsAJBsALRsANhsAPxsAACQACSQAEiQAGyQAJCQALSQANiQAPyQAAC0ACS0AEi0AGy0AJC0ALS0ANi0APy0AADYACTYAEjYAGzYAJDYALTYANjYAPzYAAD8ACT8AEj8AGz8AJD8ALT8ANj8APz8AAAAVSQAVUgAVWwAVZAAVbQAVdgAVfwAVQAkVSQkVUgkVWwkVZAkVbQkVdgkVfwkVQBIVSRIVUhIVWxIVZBIVbRIVdhIVfxIVQBsVSRsVUhsVWxsVZBsVbRsVdhsVfxsVQCQVSSQVUiQVWyQVZCQVbSQVdiQVfyQVQC0VSS0VUi0VWy0VZC0VbS0Vdi0Vfy0VQDYVSTYVUjYVWzYVZDYVbTYVdjYVfzYVQD8VST8VUj8VWz8VZD8VbT8Vdj8Vfz8VQAAqiQAqkgAqmwAqpAAqrQAqtgAqvwAqgAkqiQkqkgkqmwkqpAkqrQkqtgkqvwkqgBIqiRIqkhIqmxIqpBIqrRIqthIqvxIqgBsqiRsqkhsqmxsqpBsqrRsqthsqvxsqgCQqiSQqkiQqmyQqpCQqrSQqtiQqvyQqgC0qiS0qki0qmy0qpC0qrS0qti0qvy0qgDYqiTYqkjYqmzYqpDYqrTYqtjYqvzYqgD8qiT8qkj8qmz8qpD8qrT8qtj8qvz8qgAA/yQA/0gA/2wA/5AA/7QA/9gA//wA/wAk/yQk/0gk/2wk/5Ak/7Qk/9gk//wk/wBI/yRI/0hI/2xI/5BI/7RI/9hI//xI/wBs/yRs/0hs/2xs/5Bs/7Rs/9hs//xs/wCQ/ySQ/0iQ/2yQ/5CQ/7SQ/9iQ//yQ/wC0/yS0/0i0/2y0/5C0/7S0/9i0//y0/wDY/yTY/0jY/2zY/5DY/7TY/9jY//zY/wD8/yT8/0j8/2z8/5D8/7T8/9j8//z8/yH/C05FVFNDQVBFMi4wAwEAAAAh+QQEBAAfACwAAAAAEAAQAAAIJwAPCBxIsKDBgwgTDjRwkKHChxAjQnRYkKLEixgXNszIsWPFjQIDAgA7",
    "image/webp": "UklGRjwAAABXRUJQVlA4IDAAAADQAQCdASoQABAAAgA0JaACdLoB+AADsAD+8Oj3/yC5YXXI1/8gP+QH/ID/+PIAAAA=",
    "video/mp4": "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAMUbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAAfQAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAj90cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAAfQAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAABAAAAAQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAH0AAAAAAABAAAAAAG3bWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAABAAAAAIABVxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAABYm1pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAASJzdGJsAAAAvnN0c2QAAAAAAAAAAQAAAK5hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAABAAEABIAAAASAAAAAAAAAABFUxhdmM2Mi4xMS4xMDAgbGlieDI2NAAAAAAAAAAAAAAAGP//AAAANGF2Y0MBZAAK/+EAF2dkAAqs2V7ARAAAAwAEAAADABA8SJZYAQAGaOvjyyLA/fj4AAAAABBwYXNwAAAAAQAAAAEAAAAUYnRydAAAAAAAACygAAAAAAAAABhzdHRzAAAAAAAAAAEAAAABAAAgAAAAABxzdHNjAAAAAAAAAAEAAAABAAAAAQAAAAEAAAAUc3RzegAAAAAAAALKAAAAAQAAABRzdGNvAAAAAAAAAAEAAANEAAAAYXVkdGEAAABZbWV0YQAAAAAAAAAhaGRscgAAAAAAAAAAbWRpcmFwcGwAAAAAAAAAAAAAAAAsaWxzdAAAACSpdG9vAAAAHGRhdGEAAAABAAAAAExhdmY2Mi4zLjEwMAAAAAhmcmVlAAAC0m1kYXQAAAKtBgX//6ncRem95tlIt5Ys2CDZI+7veDI2NCAtIGNvcmUgMTY1IHIzMjIzIDA0ODBjYjAgLSBILjI2NC9NUEVHLTQgQVZDIGNvZGVjIC0gQ29weWxlZnQgMjAwMy0yMDI1IC0gaHR0cDovL3d3dy52aWRlb2xhbi5vcmcveDI2NC5odG1sIC0gb3B0aW9uczogY2FiYWM9MSByZWY9MyBkZWJsb2NrPTE6MDowIGFuYWx5c2U9MHgzOjB4MTEzIG1lPWhleCBzdWJtZT03IHBzeT0xIHBzeV9yZD0xLjAwOjAuMDAgbWl4ZWRfcmVmPTEgbWVfcmFuZ2U9MTYgY2hyb21hX21lPTEgdHJlbGxpcz0xIDh4OGRjdD0xIGNxbT0wIGRlYWR6b25lPTIxLDExIGZhc3RfcHNraXA9MSBjaHJvbWFfcXBfb2Zmc2V0PS0yIHRocmVhZHM9MSBsb29rYWhlYWRfdGhyZWFkcz0xIHNsaWNlZF90aHJlYWRzPTAgbnI9MCBkZWNpbWF0ZT0xIGludGVybGFjZWQ9MCBibHVyYXlfY29tcGF0PTAgY29uc3RyYWluZWRfaW50cmE9MCBiZnJhbWVzPTMgYl9weXJhbWlkPTIgYl9hZGFwdD0xIGJfYmlhcz0wIGRpcmVjdD0xIHdlaWdodGI9MSBvcGVuX2dvcD0wIHdlaWdodHA9MiBrZXlpbnQ9MjUwIGtleWludF9taW49MiBzY2VuZWN1dD00MCBpbnRyYV9yZWZyZXNoPTAgcmNfbG9va2FoZWFkPTQwIHJjPWNyZiBtYnRyZWU9MSBjcmY9MjMuMCBxY29tcD0wLjYwIHFwbWluPTAgcXBtYXg9NjkgcXBzdGVwPTQgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAABVliIQAEv/+6Mn8yysv49Q3s0Yps00=",
    "video/webm": "GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwEAAAAAAAHzEU2bdLpNu4tTq4QVSalmU6yBoU27i1OrhBZUrmtTrIHWTbuMU6uEElTDZ1OsggEjTbuMU6uEHFO7a1OsggHd7AEAAAAAAABZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmsCrXsYMPQkBNgIxMYXZmNjIuMy4xMDBXQYxMYXZmNjIuMy4xMDBEiYhAf0AAAAAAABZUrmvIrgEAAAAAAAA/14EBc8WInxa9vqpEUQecgQAitZyDdW5kiIEAhoVWX1ZQOYOBASPjg4QdzWUA4JCwgRC6gRCagQJVsIRVuYEBElTDZ0B/c3OfY8CAZ8iZRaOHRU5DT0RFUkSHjExhdmY2Mi4zLjEwMHNz2mPAi2PFiJ8Wvb6qRFEHZ8ilRaOHRU5DT0RFUkSHmExhdmM2Mi4xMS4xMDAgbGlidnB4LXZwOWfIoUWjiERVUkFUSU9ORIeTMDA6MDA6MDAuNTAwMDAwMDAwAB9DtnWw54EAo6uBAACAgkmDQgAA8AD2ADgkHBhKAAAwYAAAEL//9x2v////X9/////yKsAAHFO7a5G7j7OBALeK94EB8YIBqPCBAw==",
}

# A separately generated seekable MP4 whose muxer wrote `moov` after `mdat`.
# It exercises the common camera/browser layout through the same pinned-stdin
# boundary; MP4 stdin is wrapped in a restricted seekable cache.
_MOOV_AT_END_MP4 = "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAtJtZGF0AAACrQYF//+p3EXpvebZSLeWLNgg2SPu73gyNjQgLSBjb3JlIDE2NSByMzIyMyAwNDgwY2IwIC0gSC4yNjQvTVBFRy00IEFWQyBjb2RlYyAtIENvcHlsZWZ0IDIwMDMtMjAyNSAtIGh0dHA6Ly93d3cudmlkZW9sYW4ub3JnL3gyNjQuaHRtbCAtIG9wdGlvbnM6IGNhYmFjPTEgcmVmPTMgZGVibG9jaz0xOjA6MCBhbmFseXNlPTB4MzoweDExMyBtZT1oZXggc3VibWU9NyBwc3k9MSBwc3lfcmQ9MS4wMDowLjAwIG1peGVkX3JlZj0xIG1lX3JhbmdlPTE2IGNocm9tYV9tZT0xIHRyZWxsaXM9MSA4eDhkY3Q9MSBjcW09MCBkZWFkem9uZT0yMSwxMSBmYXN0X3Bza2lwPTEgY2hyb21hX3FwX29mZnNldD0tMiB0aHJlYWRzPTEgbG9va2FoZWFkX3RocmVhZHM9MSBzbGljZWRfdGhyZWFkcz0wIG5yPTAgZGVjaW1hdGU9MSBpbnRlcmxhY2VkPTAgYmx1cmF5X2NvbXBhdD0wIGNvbnN0cmFpbmVkX2ludHJhPTAgYmZyYW1lcz0zIGJfcHlyYW1pZD0yIGJfYWRhcHQ9MSBiX2JpYXM9MCBkaXJlY3Q9MSB3ZWlnaHRiPTEgb3Blbl9nb3A9MCB3ZWlnaHRwPTIga2V5aW50PTI1MCBrZXlpbnRfbWluPTIgc2NlbmVjdXQ9NDAgaW50cmFfcmVmcmVzaD0wIHJjX2xvb2thaGVhZD00MCByYz1jcmYgbWJ0cmVlPTEgY3JmPTIzLjAgcWNvbXA9MC42MCBxcG1pbj0wIHFwbWF4PTY5IHFwc3RlcD00IGlwX3JhdGlvPTEuNDAgYXE9MToxLjAwAIAAAAAVZYiEABL//ujJ/MsteeZ1GomWWg+dAAADFG1vb3YAAABsbXZoZAAAAAAAAAAAAAAAAAAAA+gAAAH0AAEAAAEAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAI/dHJhawAAAFx0a2hkAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAH0AAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAQAAAAAAQAAAAEAAAAAAAJGVkdHMAAAAcZWxzdAAAAAAAAAABAAAB9AAAAAAAAQAAAAABt21kaWEAAAAgbWRoZAAAAAAAAAAAAAAAAAAAQAAAACAAVcQAAAAAAC1oZGxyAAAAAAAAAAB2aWRlAAAAAAAAAAAAAAAAVmlkZW9IYW5kbGVyAAAAAWJtaW5mAAAAFHZtaGQAAAABAAAAAAAAAAAAAAAkZGluZgAAABxkcmVmAAAAAAAAAAEAAAAMdXJsIAAAAAEAAAEic3RibAAAAL5zdHNkAAAAAAAAAAEAAACuYXZjMQAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAQABAASAAAAEgAAAAAAAAAARVMYXZjNjIuMTEuMTAwIGxpYngyNjQAAAAAAAAAAAAAABj//wAAADRhdmNDAWQACv/hABdnZAAKrNlewEQAAAMABAAAAwAQPEiWWAEABmjr48siwP34+AAAAAAQcGFzcAAAAAEAAAABAAAAFGJ0cnQAAAAAAAAsoAAAAAAAAAAYc3R0cwAAAAAAAAABAAAAAQAAIAAAAAAcc3RzYwAAAAAAAAABAAAAAQAAAAEAAAABAAAAFHN0c3oAAAAAAAACygAAAAEAAAAUc3RjbwAAAAAAAAABAAAAMAAAAGF1ZHRhAAAAWW1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAALGlsc3QAAAAkqXRvbwAAABxkYXRhAAAAAQAAAABMYXZmNjIuMy4xMDA="

# H.264 + AAC MP4, generated once by the pinned FFmpeg 8.0.1 build.  This
# guards the real two-stream path rather than only inspecting command flags.
_AUDIO_MP4 = "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"


def _clear_media_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _MEDIA_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def live_attestation(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    document = _verified_live_media_config()
    for tool in ("ffmpeg", "ffprobe"):
        monkeypatch.setenv(f"{tool.upper()}_BIN", str(document[f"{tool}_bin"]))
        monkeypatch.setenv(f"{tool.upper()}_SHA256", str(document[f"{tool}_sha256"]))
    return document


@functools.lru_cache(maxsize=1)
def _verified_live_media_config() -> dict[str, str]:
    try:
        document = json.loads(_LIVE_MEDIA_CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pytest.skip("the checked media-binary manifest is unavailable on this host")
    if document.get("schema") != "nachuan.media-binaries.v1":
        pytest.skip("the checked media-binary manifest schema is unavailable")
    for tool in ("ffmpeg", "ffprobe"):
        path = Path(str(document.get(f"{tool}_bin") or ""))
        digest = str(document.get(f"{tool}_sha256") or "").lower()
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            pytest.skip(f"the attested {tool} bytes are unavailable on this host")
        document[f"{tool}_bin"] = str(path.resolve())
        document[f"{tool}_sha256"] = digest
    return {str(key): str(value) for key, value in document.items()}


@contextmanager
def _private_spool(probe, raw: bytes):
    deadline = probe._new_deadline(30)
    with probe._private_temp_directory(deadline=deadline) as directory:
        path = directory / "http-spool.media"
        with path.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        probe._harden_staged_file(path, deadline=deadline)
        yield path.resolve(strict=True)


def test_preflight_fails_closed_without_attestation(monkeypatch, tmp_path) -> None:
    from gateway import trusted_media_probe as probe

    _clear_media_env(monkeypatch)
    monkeypatch.setenv("PATH", str(tmp_path))
    (tmp_path / ("ffmpeg.exe" if os.name == "nt" else "ffmpeg")).write_bytes(b"hijack")
    with pytest.raises(probe.MediaBinaryUnavailable):
        probe.preflight_trusted_media_probe()
    with pytest.raises(probe.MediaBinaryUnavailable):
        probe.probe_trusted_media_bytes(
            base64.b64decode(_REAL_MEDIA["image/png"], validate=True),
            expected_media_type="image/png",
            timeout_seconds=1,
        )


def test_live_preflight_launches_both_attested_tools(
    live_attestation, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway import trusted_media_probe as probe

    launches: list[str] = []
    run_attested_command = probe._run_attested_command

    def observe_launch(tool, *args, **kwargs):
        launches.append(str(tool))
        return run_attested_command(tool, *args, **kwargs)

    monkeypatch.setattr(probe, "_run_attested_command", observe_launch)
    # This is an attested-binary integration contract, not a five-second
    # latency SLO.  Hashing and launching both ~99 MiB tools competes for disk
    # and CPU in the full shard, so keep a local deadlock guard with headroom.
    readiness = probe.preflight_trusted_media_probe(timeout_seconds=30)
    assert launches == ["ffprobe", "ffmpeg"]
    assert readiness.ready is True
    assert readiness.schema == "nachuan.trusted-media-probe.readiness.v2"
    assert readiness.validator_version == probe.VALIDATOR_VERSION
    assert readiness.validation_policy == probe.VALIDATION_POLICY
    assert readiness.ffmpeg_sha256 == live_attestation["ffmpeg_sha256"]
    assert readiness.ffprobe_sha256 == live_attestation["ffprobe_sha256"]


@pytest.mark.parametrize("media_type", sorted(_REAL_MEDIA))
def test_real_fixture_is_fully_decoded_and_accepted(media_type, live_attestation) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA[media_type], validate=True)
    result = probe.probe_trusted_media_bytes(
        raw,
        expected_media_type=media_type,
        timeout_seconds=10,
    )
    assert result.schema == "nachuan.trusted-media-probe.result.v2"
    assert result.media_type == media_type
    assert result.byte_length == len(raw)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.width == 16
    assert result.height == 16
    assert result.decoded_frames >= 1
    assert result.fully_decoded is True
    assert result.validator_version == probe.VALIDATOR_VERSION
    assert result.validation_policy == probe.VALIDATION_POLICY
    assert result.video_stream_count == 1
    assert result.audio_stream_count == 0
    assert result.audio_codec_name is None
    assert result.ffmpeg_sha256 == live_attestation["ffmpeg_sha256"]
    assert result.ffprobe_sha256 == live_attestation["ffprobe_sha256"]


def test_moov_at_end_mp4_is_fully_decoded_from_pinned_seekable_cache(
    live_attestation,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_MOOV_AT_END_MP4, validate=True)
    assert raw.index(b"mdat") < raw.index(b"moov")
    result = probe.probe_trusted_media_bytes(
        raw,
        expected_media_type="video/mp4",
        timeout_seconds=10,
    )
    assert result.media_type == "video/mp4"
    assert result.byte_length == len(raw)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.decoded_frames >= 1
    assert result.fully_decoded is True


def test_large_moov_at_end_mp4_is_fully_decoded_from_pinned_seekable_cache(
    live_attestation,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_MOOV_AT_END_MP4, validate=True)
    moov_offset = raw.index(b"moov") - 4
    # The tiny fixture above fits inside FFmpeg's AVIO buffer, so a raw pipe can
    # accidentally look seekable.  A legal top-level `free` box leaves every
    # media sample offset unchanged while moving `moov` beyond that buffer,
    # matching ordinary camera/provider MP4 files without embedding a huge
    # opaque fixture.
    free_box_size = 256 * 1024 + 8
    free_box = (
        free_box_size.to_bytes(4, "big")
        + b"free"
        + bytes(free_box_size - 8)
    )
    padded = raw[:moov_offset] + free_box + raw[moov_offset:]
    assert padded.index(b"mdat") < padded.index(b"moov")
    assert padded.index(b"moov") > 256 * 1024

    result = probe.probe_trusted_media_bytes(
        padded,
        expected_media_type="video/mp4",
        timeout_seconds=10,
    )
    assert result.media_type == "video/mp4"
    assert result.byte_length == len(padded)
    assert result.sha256 == hashlib.sha256(padded).hexdigest()
    assert result.decoded_frames >= 1
    assert result.fully_decoded is True


def test_real_h264_aac_mp4_fully_decodes_both_streams(live_attestation) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_AUDIO_MP4, validate=True)
    result = probe.probe_trusted_media_bytes(
        raw,
        expected_media_type="video/mp4",
        timeout_seconds=10,
    )
    assert result.codec_name == "h264"
    assert result.audio_codec_name == "aac"
    assert result.video_stream_count == 1
    assert result.audio_stream_count == 1
    assert result.byte_length == len(raw)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.decoded_frames >= 1
    assert result.fully_decoded is True


def test_corrupted_aac_packet_is_rejected_even_when_video_still_decodes(
    live_attestation, tmp_path
) -> None:
    """Prove the A/V gate decodes audio instead of accepting video-only success."""

    from gateway import trusted_media_probe as probe

    original = base64.b64decode(_AUDIO_MP4, validate=True)
    source = tmp_path / "h264-aac.mp4"
    source.write_bytes(original)
    packet_probe = subprocess.run(
        [
            live_attestation["ffprobe_bin"],
            "-hide_banner",
            "-v",
            "error",
            "-select_streams",
            "a:0",
            "-show_entries",
            "packet=pos,size",
            "-of",
            "json=c=1",
            str(source),
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    packets = json.loads(packet_probe.stdout)["packets"]
    assert packets[0]["pos"] == "1477", "fixed A/V fixture packet position drifted"
    assert packets[0]["size"] == "370", "fixed A/V fixture packet size drifted"

    corrupted = bytearray(original)
    corrupted[1477 : 1477 + 370] = b"\xff" * 370
    candidate = tmp_path / "h264-corrupt-aac.mp4"
    candidate.write_bytes(corrupted)

    common = [
        live_attestation["ffmpeg_bin"],
        "-hide_banner",
        "-v",
        "error",
        "-xerror",
        "-err_detect",
        "explode",
        "-nostdin",
        "-i",
        str(candidate),
    ]
    video_only = subprocess.run(
        [*common, "-map", "0:v:0", "-an", "-f", "null", "-"],
        check=False,
        capture_output=True,
        timeout=10,
    )
    audio_only = subprocess.run(
        [*common, "-map", "0:a:0", "-vn", "-f", "null", "-"],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert video_only.returncode == 0
    assert audio_only.returncode != 0

    mutated = bytes(corrupted)
    with pytest.raises(probe.TrustedMediaRejected):
        probe.probe_trusted_media_file(
            candidate,
            expected_media_type="video/mp4",
            timeout_seconds=10,
            expected_byte_length=len(mutated),
            expected_sha256=hashlib.sha256(mutated).hexdigest(),
        )


def _fake_shells() -> dict[str, bytes]:
    return {
        "image/png": b"\x89PNG\r\n\x1a\n" + b"\0" * 40,
        "image/jpeg": b"\xff\xd8\xff" + b"not-a-scan" + b"\xff\xd9",
        "image/gif": b"GIF89a\x01\x00\x01\x00" + b"\0" * 16 + b";",
        "image/webp": b"RIFF\x0c\x00\x00\x00WEBP" + b"VP8 " + b"\0" * 4,
        "video/mp4": b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2",
        "video/webm": (
            b"\x1a\x45\xdf\xa3\x9fB\x82\x84webm"
            b"\x18\x53\x80\x67\x16\x54\xae\x6b\x1f\x43\xb6\x75"
        ),
    }


@pytest.mark.parametrize("media_type", sorted(_fake_shells()))
def test_magic_or_container_shell_without_decodable_frames_is_rejected(
    media_type, live_attestation, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway import trusted_media_probe as probe

    # This contract is about rejecting an undecodable container shell.  Freeze
    # the policy clock so Windows ACL/temp staging does not consume that
    # semantic budget; wall-clock deadline sharing has its own focused test.
    monkeypatch.setattr(probe, "_CLOCK", lambda: 0.0)
    with pytest.raises(probe.TrustedMediaRejected):
        probe.probe_trusted_media_bytes(
            _fake_shells()[media_type],
            expected_media_type=media_type,
            timeout_seconds=5,
        )


def test_input_cap_is_checked_before_any_binary_is_resolved(monkeypatch) -> None:
    from gateway import trusted_media_probe as probe

    calls = 0

    def must_not_resolve(_tool: str):
        nonlocal calls
        calls += 1
        raise AssertionError("oversized bytes reached the process boundary")

    monkeypatch.setattr(probe, "pin_media_binary", must_not_resolve)
    with pytest.raises(probe.TrustedMediaTooLarge):
        probe.probe_trusted_media_bytes(
            b"x" * 9,
            expected_media_type="image/png",
            max_input_bytes=8,
        )
    assert calls == 0


def test_receipt_length_and_digest_are_bound_before_decode(monkeypatch, tmp_path) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    target = (tmp_path / "asset.png").resolve()
    target.write_bytes(raw)
    calls = 0

    def must_not_launch(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("receipt mismatch reached decoder")

    monkeypatch.setattr(probe, "_run_attested_command", must_not_launch)
    with pytest.raises(probe.TrustedMediaRejected, match="byte length"):
        probe.probe_trusted_media_file(
            target,
            expected_media_type="image/png",
            expected_byte_length=len(raw) + 1,
        )
    with pytest.raises(probe.TrustedMediaRejected, match="digest"):
        probe.probe_trusted_media_file(
            target,
            expected_media_type="image/png",
            expected_byte_length=len(raw),
            expected_sha256="0" * 64,
        )
    assert calls == 0


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes,
        *,
        timeout: bool = False,
        returncode: int = 0,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None
        self._timeout = timeout
        self._final_returncode = int(returncode)
        self.killed = False
        self._wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        self._wait_calls += 1
        # A real killed process can be reaped even when the caller's deadline
        # elapsed before its first wait().  Model process state, not call order.
        if self._timeout and not self.killed:
            raise subprocess.TimeoutExpired("attested", timeout)
        self.returncode = -9 if self.killed else self._final_returncode
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def _install_scratch_boundary_fake(
    monkeypatch,
    tmp_path: Path,
    *,
    popen_outcome: _FakeProcess | BaseException,
) -> tuple[object, dict[str, object], tuple[Path, ...]]:
    from gateway import trusted_media_probe as probe
    from gateway.providers.attested_cli import AttestedCli

    executable = (tmp_path / ("ffmpeg.exe" if os.name == "nt" else "ffmpeg")).resolve()
    executable.write_bytes(b"attested")
    external_cwd = (tmp_path / "external-cwd").resolve()
    external_temp = (tmp_path / "external-temp").resolve()
    external_tmp = (tmp_path / "external-tmp").resolve()
    external_tmpdir = (tmp_path / "external-tmpdir").resolve()
    external_directories = (
        external_cwd,
        external_temp,
        external_tmp,
        external_tmpdir,
    )
    for directory in external_directories:
        directory.mkdir()

    @contextmanager
    def fake_pin(_tool):
        yield AttestedCli(str(executable), "1" * 64)

    monkeypatch.setattr(probe, "pin_media_binary", fake_pin)
    monkeypatch.setattr(
        probe,
        "minimal_media_env",
        lambda: {
            "Temp": str(external_temp),
            "tMp": str(external_tmp),
            "tmpdir": str(external_tmpdir),
        },
    )
    captured: dict[str, object] = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        environment = kwargs["env"]
        scratch = Path(str(environment["TEMP"]))
        captured["scratch"] = scratch
        child_cwd = Path(str(kwargs.get("cwd", external_cwd)))
        (child_cwd / "cwd-canary").write_bytes(b"child")
        for name, raw_path in environment.items():
            if str(name).upper() in {"TEMP", "TMP", "TMPDIR"}:
                (Path(str(raw_path)) / f"{name}-canary").write_bytes(b"child")
        if isinstance(popen_outcome, BaseException):
            raise popen_outcome
        return popen_outcome

    monkeypatch.setattr(probe.subprocess, "Popen", fake_popen)
    return probe, captured, external_directories


def test_bounded_runner_confines_and_removes_scratch_on_launch_failure(
    monkeypatch, tmp_path
) -> None:
    probe, captured, external_directories = _install_scratch_boundary_fake(
        monkeypatch,
        tmp_path,
        popen_outcome=OSError("launch failed"),
    )

    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:
        with pytest.raises(probe.MediaBinaryUnavailable, match="failed to launch"):
            probe._run_attested_command(
                "ffmpeg",
                ["-version"],
                timeout_seconds=1,
                output_limit_bytes=64,
                absolute_deadline=deadline,
                scratch_parent=parent,
            )
        scratch = Path(str(captured["scratch"]))
        assert scratch.parent == parent
        assert not scratch.exists()

    environment = captured["env"]
    assert isinstance(environment, dict)
    scratch_keys = [
        str(name)
        for name in environment
        if str(name).upper() in {"TEMP", "TMP", "TMPDIR"}
    ]
    assert set(scratch_keys) == {"TEMP", "TMP", "TMPDIR"}
    assert len(scratch_keys) == 3
    assert {str(environment[name]) for name in scratch_keys} == {str(scratch)}
    assert scratch.is_absolute()
    assert Path(str(captured["cwd"])) == scratch
    assert all(not any(directory.iterdir()) for directory in external_directories)


def test_bounded_runner_confines_and_removes_scratch_on_nonzero_exit(
    monkeypatch, tmp_path
) -> None:
    process = _FakeProcess(b"", b"decode failed", returncode=7)
    probe, captured, external_directories = _install_scratch_boundary_fake(
        monkeypatch,
        tmp_path,
        popen_outcome=process,
    )

    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:
        result = probe._run_attested_command(
            "ffmpeg",
            ["-version"],
            timeout_seconds=1,
            output_limit_bytes=64,
            absolute_deadline=deadline,
            scratch_parent=parent,
        )
        scratch = Path(str(captured["scratch"]))
        assert scratch.parent == parent
        assert not scratch.exists()

    assert result.returncode == 7
    assert all(not any(directory.iterdir()) for directory in external_directories)


def test_bounded_runner_confines_and_removes_scratch_on_timeout(
    monkeypatch, tmp_path
) -> None:
    process = _FakeProcess(b"", b"", timeout=True)
    probe, captured, external_directories = _install_scratch_boundary_fake(
        monkeypatch,
        tmp_path,
        popen_outcome=process,
    )

    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:
        with pytest.raises(probe.TrustedMediaProbeTimeout):
            probe._run_attested_command(
                "ffmpeg",
                ["-version"],
                timeout_seconds=0.01,
                output_limit_bytes=64,
                absolute_deadline=deadline,
                scratch_parent=parent,
            )
        scratch = Path(str(captured["scratch"]))
        assert scratch.parent == parent
        assert not scratch.exists()

    assert process.killed is True
    assert all(not any(directory.iterdir()) for directory in external_directories)


def test_bounded_runner_confines_and_removes_scratch_on_output_overflow(
    monkeypatch, tmp_path
) -> None:
    process = _FakeProcess(b"x" * 4096, b"y" * 4096)
    probe, captured, external_directories = _install_scratch_boundary_fake(
        monkeypatch,
        tmp_path,
        popen_outcome=process,
    )

    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:
        with pytest.raises(probe.TrustedMediaRejected, match="output budget"):
            probe._run_attested_command(
                "ffmpeg",
                ["-version"],
                timeout_seconds=1,
                output_limit_bytes=64,
                absolute_deadline=deadline,
                scratch_parent=parent,
            )
        scratch = Path(str(captured["scratch"]))
        assert scratch.parent == parent
        assert not scratch.exists()

    assert process.killed is True
    assert all(not any(directory.iterdir()) for directory in external_directories)


def test_process_scratch_cleanup_failure_is_unavailable(monkeypatch) -> None:
    from gateway import trusted_media_probe as probe

    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:

        class CleanupFailure:
            def __init__(self, *args, **kwargs) -> None:
                self.path = Path(kwargs["dir"]) / "nachuan-media-cache-cleanup-failure"

            def __enter__(self) -> str:
                self.path.mkdir()
                return str(self.path)

            def __exit__(self, *_exc_info) -> None:
                raise OSError("scratch cleanup failed")

        monkeypatch.setattr(probe.tempfile, "TemporaryDirectory", CleanupFailure)
        with pytest.raises(
            probe.TrustedMediaProbeUnavailable,
            match="could not be secured or removed",
        ):
            with probe._private_process_scratch_directory(parent, deadline=deadline):
                pass


def test_process_scratch_persists_exact_installation_generation_marker(
    tmp_path: Path,
) -> None:
    from gateway import trusted_media_probe as probe

    deadline = probe._new_deadline(5)
    owner = probe.TrustedMediaScratchOwner(
        installation_id="1" * 64,
        epoch=7,
        database_identity="d" * 64,
        generation="a" * 64,
    )
    with probe._private_temp_directory(deadline=deadline) as parent:
        with probe._private_process_scratch_directory(
            parent,
            deadline=deadline,
            scratch_owner=owner,
        ) as scratch:
            marker = scratch / ".nachuan-media-cache-owner.v1.json"
            assert marker.read_bytes() == (
                b'{"database_identity":"'
                + b"d" * 64
                + b'","epoch":7,"generation":"'
                + b"a" * 64
                + b'","installation_id":"'
                + b"1" * 64
                + b'","schema":"nachuan.trusted-media-cache-owner.v1"}'
            )
            probe._assert_private_staged_path(marker, deadline=deadline)
        assert not scratch.exists()


def test_bounded_runner_uses_minimal_environment_and_absolute_attested_path(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe
    from gateway.providers.attested_cli import AttestedCli

    executable = (tmp_path / ("ffprobe.exe" if os.name == "nt" else "ffprobe")).resolve()
    executable.write_bytes(b"attested")
    captured: dict[str, object] = {}
    fake = _FakeProcess(b"{}", b"")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    @contextmanager
    def fake_pin(_tool):
        yield AttestedCli(str(executable), "1" * 64)

    monkeypatch.setattr(probe, "pin_media_binary", fake_pin)

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return fake

    monkeypatch.setattr(probe.subprocess, "Popen", fake_popen)
    result = probe._run_attested_command(
        "ffprobe", ["-version"], timeout_seconds=1, output_limit_bytes=64
    )
    assert result.stdout == b"{}"
    assert result.attested_sha256 == "1" * 64
    assert captured["command"] == [str(executable), "-version"]
    assert Path(str(captured["command"][0])).is_absolute()
    assert captured["shell"] is False
    assert captured["close_fds"] is True
    assert captured["stdin"] is subprocess.DEVNULL
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert "PATH" not in {str(key).upper() for key in environment}
    assert "OPENAI_API_KEY" not in {str(key).upper() for key in environment}


def test_bounded_runner_confines_and_removes_ffmpeg_cache_scratch(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe
    from gateway.providers.attested_cli import AttestedCli

    executable = (tmp_path / ("ffmpeg.exe" if os.name == "nt" else "ffmpeg")).resolve()
    executable.write_bytes(b"attested")
    captured: dict[str, object] = {}
    fake = _FakeProcess(b"{}", b"")
    owner = probe.TrustedMediaScratchOwner(
        installation_id="1" * 64,
        epoch=7,
        database_identity="d" * 64,
        generation="a" * 64,
    )

    @contextmanager
    def fake_pin(_tool):
        yield AttestedCli(str(executable), "1" * 64)

    monkeypatch.setattr(probe, "pin_media_binary", fake_pin)

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        environment = kwargs["env"]
        scratch = Path(str(environment["TEMP"]))
        captured["scratch"] = scratch
        captured["owner_marker"] = (
            scratch / ".nachuan-media-cache-owner.v1.json"
        ).read_bytes()
        (scratch / "ffcache-leftover").write_bytes(b"paid-media-bytes")
        return fake

    monkeypatch.setattr(probe.subprocess, "Popen", fake_popen)
    deadline = probe._new_deadline(5)
    with probe._private_temp_directory(deadline=deadline) as parent:
        result = probe._run_attested_command(
            "ffmpeg",
            ["-version"],
            timeout_seconds=1,
            output_limit_bytes=64,
            absolute_deadline=deadline,
            scratch_parent=parent,
            scratch_owner=owner,
        )
        scratch = Path(str(captured["scratch"]))
        assert scratch.parent == parent
        assert scratch != parent
        assert not scratch.exists()

    assert result.stdout == b"{}"
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["TEMP"] == environment["TMP"] == environment["TMPDIR"]
    assert "PATH" not in {str(key).upper() for key in environment}
    owner_marker = captured["owner_marker"]
    assert isinstance(owner_marker, bytes)
    assert b'"generation":"' + b"a" * 64 + b'"' in owner_marker


def test_bounded_runner_kills_on_timeout_and_output_overflow(monkeypatch, tmp_path) -> None:
    from gateway import trusted_media_probe as probe
    from gateway.providers.attested_cli import AttestedCli

    executable = (tmp_path / ("ffmpeg.exe" if os.name == "nt" else "ffmpeg")).resolve()
    executable.write_bytes(b"attested")
    @contextmanager
    def fake_pin(_tool):
        yield AttestedCli(str(executable), "1" * 64)

    monkeypatch.setattr(probe, "pin_media_binary", fake_pin)

    timed_out = _FakeProcess(b"", b"", timeout=True)
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *_a, **_k: timed_out)
    with pytest.raises(probe.TrustedMediaProbeTimeout):
        probe._run_attested_command(
            "ffmpeg", ["-version"], timeout_seconds=0.01, output_limit_bytes=64
        )
    assert timed_out.killed is True

    overflowed = _FakeProcess(b"x" * 4096, b"y" * 4096)
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *_a, **_k: overflowed)
    with pytest.raises(probe.TrustedMediaRejected, match="output budget"):
        probe._run_attested_command(
            "ffmpeg", ["-version"], timeout_seconds=1, output_limit_bytes=64
        )
    assert overflowed.killed is True


def test_original_path_replace_and_restore_cannot_change_pinned_staged_bytes(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe

    target = (tmp_path / "asset.bin").resolve()
    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    target.write_bytes(raw)
    calls = 0

    def replace_after_first_stage(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        target.write_bytes(b"replaced")
        target.write_bytes(raw)
        if calls == 1:
            stdout = (
                b'{"streams":[{"index":0,"codec_name":"png","codec_type":"video",'
                b'"width":16,"height":16}],"format":{"format_name":"png_pipe"}}'
            )
        else:
            stdout = b"frame=1\nprogress=end\n"
        return probe._BoundedProcessResult(
            returncode=0,
            stdout=stdout,
            stderr=b"",
            attested_sha256="1" * 64,
        )

    monkeypatch.setattr(probe, "_run_attested_command", replace_after_first_stage)
    result = probe.probe_trusted_media_file(
        target,
        expected_media_type="image/png",
        expected_byte_length=len(raw),
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        timeout_seconds=10,
    )
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert calls == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows deny-write/delete sharing pin")
def test_windows_staged_handle_denies_write_while_both_decoders_run(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    target = (tmp_path / "asset.png").resolve()
    target.write_bytes(raw)
    captured: dict[str, Path] = {}
    original_pin = probe._pin_staged_file

    @contextmanager
    def capture_pin(path, *, expected):
        captured["path"] = Path(path)
        with original_pin(path, expected=expected) as pinned:
            yield pinned

    calls = 0

    def fake_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        with pytest.raises(PermissionError):
            captured["path"].write_bytes(b"replace-and-restore")
        stdout = (
            b'{"streams":[{"index":0,"codec_name":"png","codec_type":"video",'
            b'"width":16,"height":16}],"format":{"format_name":"png_pipe"}}'
            if calls == 1
            else b"frame=1\nprogress=end\n"
        )
        return probe._BoundedProcessResult(0, stdout, b"", "2" * 64)

    monkeypatch.setattr(probe, "_pin_staged_file", capture_pin)
    monkeypatch.setattr(probe, "_run_attested_command", fake_run)
    result = probe.probe_trusted_media_file(
        target,
        expected_media_type="image/png",
        expected_byte_length=len(raw),
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        timeout_seconds=10,
    )
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert calls == 2


def test_private_staged_file_is_decoded_without_a_second_copy(
    monkeypatch, live_attestation
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)

    def must_not_copy(*_args, **_kwargs):
        raise AssertionError("server-owned HTTP spool was copied a second time")

    monkeypatch.setattr(probe, "_copy_source_to_stage", must_not_copy)
    with _private_spool(probe, raw) as target:
        result = probe.probe_trusted_media_staged_file(
            target,
            expected_media_type="image/png",
            expected_byte_length=len(raw),
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            timeout_seconds=10,
        )
    assert result.byte_length == len(raw)
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.fully_decoded is True


def test_private_staged_path_replacement_with_restored_bytes_is_rejected(
    monkeypatch,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    real_assert_private = probe._assert_private_staged_path
    decoder_calls = 0

    def replace_after_acl(path, *, deadline):
        real_assert_private(path, deadline=deadline)
        replacement = path.with_name("replacement.media")
        with replacement.open("xb") as handle:
            # Restore the exact receipt bytes/digest under a different file-id.
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        probe._harden_staged_file(replacement, deadline=deadline)
        os.replace(replacement, path)

    def must_not_decode(*_args, **_kwargs):
        nonlocal decoder_calls
        decoder_calls += 1
        raise AssertionError("replaced staged path reached a decoder")

    monkeypatch.setattr(probe, "_assert_private_staged_path", replace_after_acl)
    monkeypatch.setattr(probe, "_run_attested_command", must_not_decode)
    with _private_spool(probe, raw) as target:
        with pytest.raises(probe.TrustedMediaRejected, match="changed"):
            probe.probe_trusted_media_staged_file(
                target,
                expected_media_type="image/png",
                expected_byte_length=len(raw),
                expected_sha256=hashlib.sha256(raw).hexdigest(),
                timeout_seconds=10,
            )
    assert decoder_calls == 0


def test_private_staged_receipt_mismatch_is_rejected_before_decoder(
    monkeypatch,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    decoder_calls = 0

    def must_not_decode(*_args, **_kwargs):
        nonlocal decoder_calls
        decoder_calls += 1
        raise AssertionError("receipt mismatch reached a decoder")

    monkeypatch.setattr(probe, "_run_attested_command", must_not_decode)
    with _private_spool(probe, raw) as target:
        with pytest.raises(probe.TrustedMediaRejected, match="digest"):
            probe.probe_trusted_media_staged_file(
                target,
                expected_media_type="image/png",
                expected_byte_length=len(raw),
                expected_sha256="0" * 64,
                timeout_seconds=10,
            )
    assert decoder_calls == 0


def test_one_total_deadline_is_shared_by_metadata_and_full_decode(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["image/png"], validate=True)
    target = (tmp_path / "asset.png").resolve()
    target.write_bytes(raw)

    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    timeouts: list[float] = []

    def fake_run(*_args, **kwargs):
        timeouts.append(float(kwargs["timeout_seconds"]))
        if len(timeouts) == 1:
            clock.value = 0.75
            stdout = (
                b'{"streams":[{"index":0,"codec_name":"png","codec_type":"video",'
                b'"width":16,"height":16}],"format":{"format_name":"png_pipe"}}'
            )
        else:
            stdout = b"frame=1\nprogress=end\n"
        return probe._BoundedProcessResult(0, stdout, b"", "3" * 64)

    monkeypatch.setattr(probe, "_CLOCK", clock)
    monkeypatch.setattr(probe, "_run_attested_command", fake_run)
    result = probe.probe_trusted_media_file(
        target,
        expected_media_type="image/png",
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        timeout_seconds=1,
    )
    assert result.fully_decoded is True
    assert len(timeouts) == 2
    assert timeouts[0] == pytest.approx(1.0)
    assert timeouts[1] == pytest.approx(0.25)


def test_zero_decoded_frames_is_rejected(monkeypatch, tmp_path) -> None:
    from gateway import trusted_media_probe as probe

    # Decoder output is fully mocked here: verify the zero-frame rejection,
    # independently of variable Windows ACL/temp staging latency.
    monkeypatch.setattr(probe, "_CLOCK", lambda: 0.0)
    target = (tmp_path / "asset.png").resolve()
    target.write_bytes(base64.b64decode(_REAL_MEDIA["image/png"], validate=True))
    responses = iter(
        [
            probe._BoundedProcessResult(
                0,
                (
                    b'{"streams":[{"index":1,"codec_name":"png","codec_type":"video",'
                    b'"width":16,"height":16}],"format":{"format_name":"png_pipe",'
                    b'"size":"111"}}'
                ),
                b"",
            ),
            probe._BoundedProcessResult(0, b"frame=0\nprogress=end\n", b""),
        ]
    )
    monkeypatch.setattr(probe, "_run_attested_command", lambda *_a, **_k: next(responses))
    with pytest.raises(probe.TrustedMediaRejected, match="zero decoded frames"):
        probe.probe_trusted_media_file(
            target,
            expected_media_type="image/png",
            timeout_seconds=1,
        )


def test_video_probe_inspects_all_streams_and_fully_decodes_allowed_audio(
    monkeypatch, tmp_path
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["video/mp4"], validate=True)
    target = (tmp_path / "with-audio.mp4").resolve()
    target.write_bytes(raw)
    calls: list[tuple[str, list[str]]] = []

    def fake_run(tool, args, **_kwargs):
        rendered = [str(value) for value in args]
        calls.append((tool, rendered))
        if tool == "ffprobe":
            stdout = json.dumps(
                {
                    "streams": [
                        {
                            "index": 0,
                            "codec_type": "video",
                            "codec_name": "h264",
                            "width": 16,
                            "height": 16,
                            "disposition": {"attached_pic": 0},
                        },
                        {
                            "index": 1,
                            "codec_type": "audio",
                            "codec_name": "aac",
                            "disposition": {"attached_pic": 0},
                        },
                    ],
                    "format": {"format_name": "mov,mp4", "duration": "0.5"},
                },
                separators=(",", ":"),
            ).encode("ascii")
        else:
            stdout = b"frame=1\nprogress=end\n"
        return probe._BoundedProcessResult(0, stdout, b"", "3" * 64)

    monkeypatch.setattr(probe, "_run_attested_command", fake_run)
    result = probe.probe_trusted_media_file(
        target,
        expected_media_type="video/mp4",
        expected_byte_length=len(raw),
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        timeout_seconds=10,
    )
    assert result.fully_decoded is True
    assert [tool for tool, _args in calls] == ["ffprobe", "ffmpeg"]
    probe_args = calls[0][1]
    decode_args = calls[1][1]
    assert "-select_streams" not in probe_args
    assert "-an" not in decode_args
    for rendered in (probe_args, decode_args):
        whitelist_index = rendered.index("-protocol_whitelist")
        assert rendered[whitelist_index + 1] == "cache,pipe"
        assert "cache:pipe:0" in rendered
        assert rendered[rendered.index("-read_ahead_limit") + 1] == "-1"
        assert "file" not in rendered[whitelist_index + 1].split(",")
        assert "http" not in rendered[whitelist_index + 1].split(",")
        assert "https" not in rendered[whitelist_index + 1].split(",")
    assert [decode_args[index + 1] for index, value in enumerate(decode_args) if value == "-map"] == [
        "0:0",
        "0:1",
    ]


def test_staged_mp4_forwards_the_bound_owner_to_both_cache_commands(
    monkeypatch,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = base64.b64decode(_REAL_MEDIA["video/mp4"], validate=True)
    owner = probe.TrustedMediaScratchOwner(
        installation_id="1" * 64,
        epoch=7,
        database_identity="d" * 64,
        generation="a" * 64,
    )
    observed: list[object] = []

    def fake_run(tool, _args, **kwargs):
        observed.append(kwargs.get("scratch_owner"))
        stdout = (
            json.dumps(
                {
                    "streams": [
                        {
                            "index": 0,
                            "codec_type": "video",
                            "codec_name": "h264",
                            "width": 16,
                            "height": 16,
                            "disposition": {"attached_pic": 0},
                        }
                    ],
                    "format": {"format_name": "mov,mp4", "duration": "0.5"},
                },
                separators=(",", ":"),
            ).encode("ascii")
            if tool == "ffprobe"
            else b"frame=1\nprogress=end\n"
        )
        return probe._BoundedProcessResult(0, stdout, b"", "3" * 64)

    monkeypatch.setattr(probe, "_run_attested_command", fake_run)
    with _private_spool(probe, raw) as target:
        result = probe.probe_trusted_media_staged_file(
            target,
            expected_media_type="video/mp4",
            expected_byte_length=len(raw),
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            timeout_seconds=10,
            scratch_owner=owner,
        )

    assert result.fully_decoded is True
    assert observed == [owner, owner]


@pytest.mark.parametrize(
    "streams",
    [
        [
            {
                "index": 0,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 16,
                "height": 16,
            },
            {"index": 1, "codec_type": "data", "codec_name": "bin_data"},
        ],
        [
            {
                "index": 0,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 16,
                "height": 16,
            },
            {
                "index": 1,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 16,
                "height": 16,
            },
        ],
        [
            {
                "index": 0,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 16,
                "height": 16,
            },
            {"index": 1, "codec_type": "audio", "codec_name": "flac"},
        ],
        [
            {
                "index": 0,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 16,
                "height": 16,
            },
            {
                "index": 1,
                "codec_type": "video",
                "codec_name": "mjpeg",
                "width": 16,
                "height": 16,
                "disposition": {"attached_pic": 1},
            },
        ],
    ],
)
def test_video_stream_set_rejects_data_extra_video_bad_audio_and_attachment(
    streams,
) -> None:
    from gateway import trusted_media_probe as probe

    raw = json.dumps(
        {
            "streams": streams,
            "format": {"format_name": "mov,mp4", "duration": "0.5"},
        },
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(probe.TrustedMediaRejected):
        probe._parse_probe_metadata(
            raw,
            policy=probe._policy("video/mp4"),
            byte_length=1024,
        )


def test_only_one_probe_can_own_a_slot_when_capacity_is_exhausted(monkeypatch) -> None:
    from gateway import trusted_media_probe as probe

    occupied = threading.BoundedSemaphore(1)
    assert occupied.acquire(blocking=False)
    monkeypatch.setattr(probe, "_PROBE_SLOTS", occupied)
    with pytest.raises(probe.TrustedMediaProbeBusy):
        probe.probe_trusted_media_bytes(
            base64.b64decode(_REAL_MEDIA["image/png"], validate=True),
            expected_media_type="image/png",
        )
