from __future__ import annotations

import sys
import types

import pytest

from gateway import audio
from orchestrator import embedder


def _reset_audio() -> None:
    audio._state["name"] = "base"
    audio._state["model"] = None


def test_whisper_runtime_never_downloads_by_model_name(tmp_path, monkeypatch):
    _reset_audio()
    monkeypatch.setenv("WHISPER_MODEL_DIR", str(tmp_path / "missing"))

    with pytest.raises(audio.AudioUnavailable, match="自动下载已禁用"):
        audio._model()


def test_whisper_loads_only_explicit_local_directory(tmp_path, monkeypatch):
    model_dir = tmp_path / "reviewed-whisper"
    model_dir.mkdir()
    seen: dict[str, object] = {}

    class FakeWhisperModel:
        def __init__(self, path: str, **kwargs: object) -> None:
            seen["path"] = path
            seen.update(kwargs)

    monkeypatch.setitem(
        sys.modules,
        "faster_whisper",
        types.SimpleNamespace(WhisperModel=FakeWhisperModel),
    )
    monkeypatch.setenv("WHISPER_MODEL_DIR", str(model_dir))
    _reset_audio()
    try:
        audio._model()
    finally:
        _reset_audio()

    assert seen["path"] == str(model_dir)
    assert seen["local_files_only"] is True
    assert audio.os.environ["HF_HUB_OFFLINE"] == "1"
    assert audio.os.environ["HF_HUB_DISABLE_TELEMETRY"] == "1"


def test_embedder_rejects_remote_model_identifiers(monkeypatch):
    monkeypatch.setenv("NACHUAN_EMBED_MODEL", "BAAI/bge-small-zh-v1.5")
    assert embedder._Embedder()._resolve_dir() is None


def test_embedder_requires_local_safetensors(tmp_path, monkeypatch):
    monkeypatch.setenv("NACHUAN_EMBED_MODEL", str(tmp_path))
    assert embedder._Embedder()._resolve_dir() is None
    (tmp_path / "model.safetensors").write_bytes(b"reviewed-placeholder")
    assert embedder._Embedder()._resolve_dir() == str(tmp_path.resolve())
