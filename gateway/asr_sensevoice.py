"""本地语音转文字（主路径）：SenseVoice-Small（FunASR runtime），纯 CPU、离线、自带标点。

本模块仅供显式 ``asr`` extra 的本地评估。FunASR/torch/sentencepiece 及原生通知闭包完成前，
不得冻结进 lean/full 商业候选；发行版缺失时由 audio.py 明确降级为 503。

中英日韩粤多语，CPU 上 RTFx≈2（比 faster-whisper base 快且更准），原生输出标点 + ITN。
模型须由发布流程固定 revision/SHA-256 后放在 models/ 下（gitignore），推理 100% 本地、无外联；
运行期不会自动从 ModelScope 下载。

为什么不用 sherpa-onnx：本机上 sherpa 跑 SenseVoice 必崩（IndexError: invalid unordered_map key），
跨版本复现。改用 FunASR 官方 Python runtime（torch + sentencepiece），实测稳定。

缺模型文件 / 没装 funasr 时抛 SenseVoiceUnavailable —— audio.py 据此回退 whisper（不影响引擎）。

Windows 中文路径坑：sentencepiece 的 C++ 加载器读不了非 ASCII 路径（本仓库在 D:\\大模型聚合器）。
本模块在加载前打补丁：原生 Load 失败时改用 Python 读字节、走 model_proto= 内存加载，绕开该限制。
"""

from __future__ import annotations

import os
import subprocess
import threading
from typing import Any

from gateway.media_binary import MediaBinaryUnavailable, run_media_binary

SAMPLE_RATE = 16000
_FFMPEG_DECODE_TIMEOUT_SECONDS = 60.0

# 模型目录：默认指向 ModelScope 缓存里的 SenseVoiceSmall（与 .gitignore 一致），可用环境变量覆盖。
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_DIR = os.path.join(
    _REPO, "models", "modelscope_cache", "models", "iic", "SenseVoiceSmall"
)
MODEL_DIR = os.getenv("SENSEVOICE_DIR", _DEFAULT_DIR)

# CPU 线程数：实测 8 核机上 6 较优。可用环境变量调。
_THREADS = int(os.getenv("SENSEVOICE_THREADS", "6"))


class SenseVoiceUnavailable(RuntimeError):
    """模型文件缺失、依赖未装或加载失败。audio.py 捕获后回退 whisper。"""


_state: dict[str, Any] = {"loaded": False, "model": None, "postproc": None}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# sentencepiece 中文路径补丁：原生 Load(path) 在非 ASCII 路径上失败时，
# 改用 Python 读取字节、以 model_proto= 内存加载。只打一次，幂等。
# ---------------------------------------------------------------------------
def _patch_sentencepiece() -> None:
    import sentencepiece as spm

    if getattr(spm.SentencePieceProcessor.Load, "_sv_patched", False):
        return
    _orig_load = spm.SentencePieceProcessor.Load

    def _patched_load(self: Any, model_file: Any = None, model_proto: Any = None) -> Any:
        if model_file is not None and model_proto is None:
            try:
                return _orig_load(self, model_file=model_file)
            except Exception:  # noqa: BLE001  # 多半是中文/非 ASCII 路径，退回字节加载
                with open(model_file, "rb") as f:
                    data = f.read()
                return _orig_load(self, model_proto=data)
        return _orig_load(self, model_file=model_file, model_proto=model_proto)

    _patched_load._sv_patched = True  # type: ignore[attr-defined]
    spm.SentencePieceProcessor.Load = _patched_load
    spm.SentencePieceProcessor.load = _patched_load


# ---------------------------------------------------------------------------
# ffmpeg 解码：任意音频字节（webm/opus/wav/...） -> 16k 单声道 f32 numpy。
# 与 asr_nemotron._decode_audio 同一套（浏览器 MediaRecorder 发来的就是 webm/opus）。
# ---------------------------------------------------------------------------
def _decode_audio(data: bytes) -> Any:
    try:
        proc = run_media_binary(
            "ffmpeg",
            ["-nostdin", "-loglevel", "error", "-i", "pipe:0",
             "-ar", str(SAMPLE_RATE), "-ac", "1", "-f", "f32le", "pipe:1"],
            input=data,
            capture_output=True,
            check=True,
            timeout=_FFMPEG_DECODE_TIMEOUT_SECONDS,
        )
    except MediaBinaryUnavailable as e:
        raise SenseVoiceUnavailable(str(e)) from e
    except subprocess.TimeoutExpired as e:
        raise SenseVoiceUnavailable("ffmpeg 解码超时（硬时限 60 秒）") from e
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or b"").decode("utf-8", "ignore")[:200]
        raise SenseVoiceUnavailable(f"ffmpeg 解码失败：{msg}") from e
    # Keep optional ASR dependencies behind the attested decoder boundary.
    # A missing/changed ffmpeg must remain the authoritative fail-closed error
    # even in the lean runtime where numpy is deliberately absent.
    import numpy as np

    return np.frombuffer(proc.stdout, dtype="<f4").copy()


# ---------------------------------------------------------------------------
# 加载（懒加载、线程安全、只加载一次）
# ---------------------------------------------------------------------------
def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if _state["loaded"]:
            return

        # 模型目录必须齐全（关键文件：权重 + bpe 分词模型），否则直接判不可用。
        need = ("model.pt", "chn_jpn_yue_eng_ko_spectok.bpe.model", "config.yaml")
        for fn in need:
            if not os.path.exists(os.path.join(MODEL_DIR, fn)):
                raise SenseVoiceUnavailable(f"缺少模型文件：{os.path.join(MODEL_DIR, fn)}")

        # 离线优先：禁掉 HF（被墙）与各种联网检查；推理期 0 外联。
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

        try:
            import torch

            torch.set_num_threads(_THREADS)
            _patch_sentencepiece()
            from funasr import AutoModel
            from funasr.utils.postprocess_utils import rich_transcription_postprocess
        except ImportError as e:
            raise SenseVoiceUnavailable(
                "未安装 funasr / torch（pip install funasr torchaudio）"
            ) from e

        try:
            _state["model"] = AutoModel(
                model=MODEL_DIR,
                device="cpu",
                disable_update=True,   # 不联网查更新
                vad_model=None,        # 单段录音，无需 VAD（更快、依赖更少）
            )
        except Exception as e:  # noqa: BLE001
            raise SenseVoiceUnavailable(f"SenseVoice 加载失败：{type(e).__name__}: {e}") from e

        _state["postproc"] = rich_transcription_postprocess
        _state["loaded"] = True


def available() -> bool:
    """模型是否可用（文件齐全 + 依赖在）。不抛异常。"""
    try:
        _ensure_loaded()
        return True
    except Exception:  # noqa: BLE001
        return False


def warm() -> None:
    """预热：加载模型并跑一小段静音，让首次真实转写不卡在加载/首跑。"""
    try:
        _ensure_loaded()
        import numpy as np

        silent = np.zeros(SAMPLE_RATE // 2, dtype=np.float32)  # 0.5s 静音
        _state["model"].generate(input=silent, cache={}, language="auto", use_itn=True)
    except Exception:  # noqa: BLE001
        pass


# SenseVoice 语种码：auto 让模型自己判语种；显式更准。
_LANGS = {"zh", "en", "ja", "ko", "yue", "auto", "nospeech"}


def _lang_code(language: str | None) -> str:
    key = (language or "auto").strip().lower()
    if key in _LANGS:
        return key
    base = key.split("-")[0]  # zh-cn -> zh, en-us -> en
    return base if base in _LANGS else "auto"


def transcribe(data: bytes, language: str | None = None) -> str:
    """音频字节 -> 文字（自带标点）。language=None/auto 自动判语种；zh/en/ja/ko/yue 显式更准。

    返回的中文是简/繁取决于模型；调用方（audio.py）会再过 _to_simplified 统一成简体。
    """
    _ensure_loaded()
    audio = _decode_audio(data)
    import numpy as np

    if audio.size == 0:
        return ""
    audio = np.ascontiguousarray(audio, dtype=np.float32)
    res = _state["model"].generate(
        input=audio, cache={}, language=_lang_code(language), use_itn=True
    )
    if not res:
        return ""
    raw = res[0].get("text", "")
    return _state["postproc"](raw).strip()
