"""语音转文字端点（D1）：未装引擎时优雅降级 + 打桩验证成功路径。

音频以请求体原始字节传入（避免 multipart 依赖 python-multipart）。
"""

from __future__ import annotations

import gateway.audio as audio_mod
from fastapi.testclient import TestClient

from gateway.app import app

AUTH = {"Authorization": "Bearer test-key"}


def test_transcribe_unavailable_returns_503_without_internal_details(monkeypatch):
    """引擎未装 faster-whisper（或模型不可用）→ 503 + 友好提示（而不是 500 崩）。

    用打桩模拟"不可用"，这样无论本机是否已装 faster-whisper，此用例都稳定校验降级路径。
    """

    internal_detail = (
        r"C:\Users\owner\.cache\models\customer-secret\faster-whisper-base"
    )

    def _raise(data, language=None):
        raise audio_mod.AudioUnavailable(
            f"缺少已审本地 Whisper 模型目录：{internal_detail}"
        )

    monkeypatch.setattr(audio_mod, "transcribe", _raise)
    with TestClient(app) as c:
        r = c.post("/v1/audio/transcriptions", headers=AUTH, content=b"RIFFfakeaudio")
    assert r.status_code == 503
    assert r.json()["detail"] == "语音转写暂不可用；请检查本地模型与已锁定语音引擎"
    assert internal_detail not in r.text


def test_transcribe_success_when_patched(monkeypatch):
    monkeypatch.setattr(audio_mod, "transcribe", lambda data, language=None: "你好 世界")
    with TestClient(app) as c:
        r = c.post("/v1/audio/transcriptions?language=zh", headers=AUTH, content=b"audio-bytes")
    assert r.status_code == 200
    assert r.json()["text"] == "你好 世界"


def test_transcribe_requires_body():
    with TestClient(app) as c:
        r = c.post("/v1/audio/transcriptions", headers=AUTH, content=b"")
    assert r.status_code == 422
