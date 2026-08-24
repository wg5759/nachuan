"""本地语音转文字（快速档）：NVIDIA Nemotron 3.5 ASR（INT4 ONNX）直接走 onnxruntime。

本模块仅供本地评估。onnxruntime 与模型的许可证/原生闭包完成前不得冻结进 lean/full 商业候选；
发行版缺失时由 audio.py 明确降级为 503。

中英双语（实际支持 40 种语言），纯 CPU，比 faster-whisper 快（RTFx > 1，whisper < 1）。
架构：Cache-Aware FastConformer 编码器 + RNNT（LSTM 预测网络 + joint）贪心解码，流式分块。

模型文件放在 `models/nemotron-asr/`（encoder/decoder/joint 各 .onnx + .data、vocab.txt）。
缺文件或没装 onnxruntime 时抛 NemotronUnavailable —— audio.py 据此回退到 whisper（不影响引擎）。

参考实现（权威）：altunenes/parakeet-rs（src/nemotron.rs），模型卡 onnx-community/
nemotron-3.5-asr-streaming-0.6b-onnx-int4。webm/opus 字节用 ffmpeg 解码成 16k 单声道 f32。
"""

from __future__ import annotations

import os
import subprocess
import threading
from typing import Any

from gateway.media_binary import MediaBinaryUnavailable, run_media_binary

# ---------------------------------------------------------------------------
# 常量（全部来自 model_config.json / audio_processor_config.json / 参考实现）
# ---------------------------------------------------------------------------
SAMPLE_RATE = 16000
_FFMPEG_DECODE_TIMEOUT_SECONDS = 60.0
N_FFT = 512
WIN = 400
HOP = 160
N_MELS = 128
PREEMPH = 0.97
LOG_GUARD = 5.9604645e-8  # genai_config log_eps；参考实现同值
CHUNK = 56                # 每个编码器步喂入的“新”mel 帧数（560ms）
PRE_ENCODE_CACHE = 9      # 从上一块带过来的 mel 帧
ENC_FRAMES_IN = PRE_ENCODE_CACHE + CHUNK  # 编码器固定输入时间维 = 65
BLANK_ID = 13087
MAX_SYMBOLS = 10
NUM_LAYERS = 24
HIDDEN = 1024
LEFT_CTX = 56
CONV_CTX = 8
LSTM_LAYERS = 2
LSTM_DIM = 640

# 模型目录：仓库内 models/nemotron-asr/（与 .gitignore 一致），可用环境变量覆盖
_DEFAULT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "nemotron-asr"
)
MODEL_DIR = os.getenv("NEMOTRON_ASR_DIR", _DEFAULT_DIR)

# 编码器线程数：实测 8 核机上 5~6 最佳（8 反而更慢，过订阅）。解码/joint 用 1。
_ENC_THREADS = int(os.getenv("NEMOTRON_ASR_THREADS", "6"))

# language → prompt_index（编码器 lang_id 输入；注意这是 prompt MLP 索引，不是词表下标）
# 取自参考实现 PROMPT_DICTIONARY。auto=101 让模型自己判语种。
_PROMPT = {
    "en": 0, "en-us": 0, "en-gb": 1,
    "zh": 4, "zh-cn": 4, "zh-tw": 5,
    "ja": 10, "ja-jp": 10, "ko": 14, "ko-kr": 14,
    "es": 3, "de": 9, "fr": 8, "it": 15, "pt": 13, "ru": 11,
    "nl": 16, "tr": 18, "ar": 7, "hi": 6, "vi-vn": 33, "uk": 19,
    "auto": 101,
}


class NemotronUnavailable(RuntimeError):
    """模型文件缺失、依赖未装或加载失败。audio.py 捕获后回退 whisper。"""


_state: dict[str, Any] = {"loaded": False, "enc": None, "dec": None, "joint": None,
                          "vocab": None, "lang_tag_ids": None, "mel_basis": None, "hann": None}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# mel 滤波器组（librosa Slaney 标度 + Slaney 归一，匹配参考实现 / NeMo 预处理）
# ---------------------------------------------------------------------------
_F_SP = 200.0 / 3.0
_MIN_LOG_HZ = 1000.0
_MIN_LOG_MEL = _MIN_LOG_HZ / _F_SP
_LOG_STEP = 0.06875177742094912


def _hz_to_mel(hz: Any) -> Any:
    import numpy as np

    hz = np.atleast_1d(np.asarray(hz, dtype=np.float64)).copy()
    mel = hz / _F_SP
    region = hz >= _MIN_LOG_HZ
    mel[region] = _MIN_LOG_MEL + np.log(hz[region] / _MIN_LOG_HZ) / _LOG_STEP
    return mel


def _mel_to_hz(mel: Any) -> Any:
    import numpy as np

    mel = np.atleast_1d(np.asarray(mel, dtype=np.float64)).copy()
    hz = mel * _F_SP
    region = mel >= _MIN_LOG_MEL
    hz[region] = _MIN_LOG_HZ * np.exp((mel[region] - _MIN_LOG_MEL) * _LOG_STEP)
    return hz


def _mel_filterbank() -> Any:
    import numpy as np

    freq_bins = N_FFT // 2 + 1
    fmax = SAMPLE_RATE / 2.0
    mmin = float(_hz_to_mel(0.0)[0])
    mmax = float(_hz_to_mel(fmax)[0])
    mel_pts = _mel_to_hz(mmin + (mmax - mmin) * np.arange(N_MELS + 2) / (N_MELS + 1))
    fft_freqs = np.arange(freq_bins) * SAMPLE_RATE / N_FFT
    fdiff = np.diff(mel_pts)
    fb = np.zeros((N_MELS, freq_bins), dtype=np.float64)
    for i in range(N_MELS):
        lower = (fft_freqs - mel_pts[i]) / fdiff[i]
        upper = (mel_pts[i + 2] - fft_freqs) / fdiff[i + 1]
        fb[i] = np.maximum(0.0, np.minimum(lower, upper))
        fb[i] *= 2.0 / (mel_pts[i + 2] - mel_pts[i])  # Slaney 归一
    return fb.astype(np.float32)


def _compute_mel(audio: Any) -> Any:
    """raw 16k 单声道 f32 -> [n_mels, frames] 对数 mel（不做归一，NeMo normalize=NA）。"""
    import numpy as np

    if audio.size == 0:
        return np.zeros((N_MELS, 0), dtype=np.float32)
    pe = np.empty_like(audio)
    pe[0] = audio[0]
    pe[1:] = audio[1:] - PREEMPH * audio[:-1]
    pad = N_FFT // 2
    padded = np.concatenate([np.zeros(pad, np.float32), pe, np.zeros(pad, np.float32)])
    num_frames = (len(padded) - N_FFT) // HOP + 1
    if num_frames <= 0:
        return np.zeros((N_MELS, 0), dtype=np.float32)
    idx = np.arange(N_FFT)[None, :] + HOP * np.arange(num_frames)[:, None]
    frames = padded[idx] * _state["hann"][None, :]
    spec = np.fft.rfft(frames, n=N_FFT, axis=1)
    power = (spec.real ** 2 + spec.imag ** 2).astype(np.float32)
    mel = power @ _state["mel_basis"].T
    mel = np.log(mel + LOG_GUARD)
    return mel.T.astype(np.float32)


# ---------------------------------------------------------------------------
# ffmpeg 解码：任意音频字节（webm/opus/wav/...） -> 16k 单声道 f32 numpy
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
        raise NemotronUnavailable(str(e)) from e
    except subprocess.TimeoutExpired as e:
        raise NemotronUnavailable("ffmpeg 解码超时（硬时限 60 秒）") from e
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or b"").decode("utf-8", "ignore")[:200]
        raise NemotronUnavailable(f"ffmpeg 解码失败：{msg}") from e
    # Keep optional ASR dependencies behind the attested decoder boundary.
    # A missing/changed ffmpeg must remain the authoritative fail-closed error
    # even in the lean runtime where numpy is deliberately absent.
    import numpy as np

    return np.frombuffer(proc.stdout, dtype="<f4").copy()


# ---------------------------------------------------------------------------
# 加载（懒加载、线程安全、只加载一次）
# ---------------------------------------------------------------------------
def _load_vocab(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().splitlines()


def _is_lang_tag(piece: str) -> bool:
    if len(piece) < 4 or piece[0] != "<" or piece[-1] != ">":
        return False
    inner = piece[1:-1]
    if len(inner) == 2:
        return inner.isalpha() and inner.islower()
    if len(inner) == 5:
        return (inner[0:2].isalpha() and inner[0:2].islower() and inner[2] == "-"
                and inner[3:5].isalpha() and inner[3:5].isupper())
    return False


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if _state["loaded"]:
            return
        try:
            import numpy as np  # noqa: F401
            import onnxruntime as rt
        except ImportError as e:
            raise NemotronUnavailable("未安装 onnxruntime / numpy") from e

        enc_p = os.path.join(MODEL_DIR, "encoder.onnx")
        dec_p = os.path.join(MODEL_DIR, "decoder.onnx")
        joint_p = os.path.join(MODEL_DIR, "joint.onnx")
        vocab_p = os.path.join(MODEL_DIR, "vocab.txt")
        for p in (enc_p, dec_p, joint_p, vocab_p):
            if not os.path.exists(p):
                raise NemotronUnavailable(f"缺少模型文件：{p}")

        def _opts(intra: int) -> Any:
            so = rt.SessionOptions()
            so.log_severity_level = 3
            so.intra_op_num_threads = intra
            so.inter_op_num_threads = 1
            so.graph_optimization_level = rt.GraphOptimizationLevel.ORT_ENABLE_ALL
            so.execution_mode = rt.ExecutionMode.ORT_SEQUENTIAL
            return so

        prov = ["CPUExecutionProvider"]
        try:
            _state["enc"] = rt.InferenceSession(enc_p, _opts(_ENC_THREADS), providers=prov)
            _state["dec"] = rt.InferenceSession(dec_p, _opts(1), providers=prov)
            _state["joint"] = rt.InferenceSession(joint_p, _opts(1), providers=prov)
        except Exception as e:  # noqa: BLE001
            raise NemotronUnavailable(f"ONNX 模型加载失败：{type(e).__name__}: {e}") from e

        vocab = _load_vocab(vocab_p)
        _state["vocab"] = vocab
        _state["lang_tag_ids"] = {i for i, p in enumerate(vocab) if _is_lang_tag(p)}
        _state["mel_basis"] = _mel_filterbank()
        _state["hann"] = _hann_in_fft()
        _state["loaded"] = True


def _hann_in_fft() -> Any:
    import numpy as np

    w = np.zeros(N_FFT, np.float32)
    w[:WIN] = (0.5 - 0.5 * np.cos(2 * np.pi * np.arange(WIN) / (WIN - 1))).astype(np.float32)
    return w


def available() -> bool:
    """模型是否可用（文件齐全 + 依赖在）。不抛异常。"""
    try:
        _ensure_loaded()
        return True
    except Exception:  # noqa: BLE001
        return False


def warm() -> None:
    """预热：加载会话并跑一个静音块，让首次真实转写不卡在加载/首跑。"""
    try:
        _ensure_loaded()
        import numpy as np

        silent = np.zeros(SAMPLE_RATE // 2, dtype=np.float32)  # 0.5s 静音
        _run_pipeline(silent, 101)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# 推理：mel -> 流式编码器（带 cache）-> RNNT 贪心解码
# ---------------------------------------------------------------------------
def _run_pipeline(audio: Any, lang_id: int) -> str:
    import numpy as np

    enc = _state["enc"]
    dec = _state["dec"]
    joint = _state["joint"]
    vocab = _state["vocab"]
    lang_tag_ids = _state["lang_tag_ids"]

    mel = _compute_mel(audio)  # [128, frames]
    total = mel.shape[1]
    if total == 0:
        return ""

    # 编码器 cache（batch-first：[1, layers, ...]）
    clc = np.zeros((1, NUM_LAYERS, LEFT_CTX, HIDDEN), np.float32)
    clt = np.zeros((1, NUM_LAYERS, HIDDEN, CONV_CTX), np.float32)
    cll = np.zeros((1,), np.int64)
    # 解码器 LSTM 状态
    h = np.zeros((LSTM_LAYERS, 1, LSTM_DIM), np.float32)
    c = np.zeros((LSTM_LAYERS, 1, LSTM_DIM), np.float32)
    last_token = BLANK_ID
    ids: list[int] = []

    lang_arr = np.array([lang_id], np.int64)
    enc_out_names = ["outputs", "encoded_lengths", "cache_last_channel_next",
                     "cache_last_time_next", "cache_last_channel_len_next"]

    buf = 0
    chunk_idx = 0
    while buf < total:
        chunk_end = min(buf + CHUNK, total)
        main_len = chunk_end - buf
        chunk_data = np.zeros((N_MELS, ENC_FRAMES_IN), np.float32)
        if chunk_idx > 0 and buf >= PRE_ENCODE_CACHE:
            cs = buf - PRE_ENCODE_CACHE
            chunk_data[:, 0:PRE_ENCODE_CACHE] = mel[:, cs:cs + PRE_ENCODE_CACHE]
        chunk_data[:, PRE_ENCODE_CACHE:PRE_ENCODE_CACHE + main_len] = mel[:, buf:buf + main_len]
        mel_in = np.ascontiguousarray(chunk_data.T[None, :, :], dtype=np.float32)  # [1,65,128]
        length = PRE_ENCODE_CACHE + main_len

        eo = enc.run(enc_out_names, {
            "audio_signal": mel_in,
            "length": np.array([length], np.int64),
            "cache_last_channel": clc,
            "cache_last_time": clt,
            "cache_last_channel_len": cll,
            "lang_id": lang_arr,
        })
        enc_out, enc_len = eo[0], int(eo[1][0])
        clc, clt, cll = eo[2], eo[3], eo[4]

        for t in range(enc_len):
            enc_frame = enc_out[:, t:t + 1, :]  # [1,1,1024]
            for _ in range(MAX_SYMBOLS):
                do = dec.run(["decoder_output", "h_out", "c_out"], {
                    "targets": np.array([[last_token]], np.int64),
                    "h_in": h, "c_in": c,
                })
                dec_out = do[0]  # [1,640,1]
                dec_out_j = np.ascontiguousarray(np.transpose(dec_out, (0, 2, 1)))  # [1,1,640]
                logits = joint.run(["joint_output"], {
                    "encoder_output": enc_frame,
                    "decoder_output": dec_out_j,
                })[0].reshape(-1)
                k = int(np.argmax(logits))
                if k == BLANK_ID:
                    break
                ids.append(k)
                last_token = k
                h, c = do[1], do[2]

        buf += CHUNK
        chunk_idx += 1

    valid = [i for i in ids if i < len(vocab) and i not in lang_tag_ids]
    out: list[str] = []
    for i in valid:
        out.append(vocab[i].replace("▁", " "))
    return "".join(out).strip()


def transcribe(data: bytes, language: str | None = None) -> str:
    """音频字节 -> 文字。language=None/auto 自动判语种；zh/en 等显式指定更准。

    注意：返回的中文是繁体/简体取决于模型；调用方（audio.py）会再过 _to_simplified。
    """
    _ensure_loaded()
    key = (language or "auto").strip().lower()
    lang_id = _PROMPT.get(key, _PROMPT.get(key.split("-")[0], 101))
    audio = _decode_audio(data)
    return _run_pipeline(audio, lang_id)
