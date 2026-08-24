"""本地语音转文字实验接口：依赖显式 voice-lab/asr extra，模型懒加载。

未安装 faster-whisper 或本地模型目录缺失时抛 AudioUnavailable，端点据此回友好提示（而不是崩）。
运行期强制离线，绝不按模型名从 Hugging Face 自动下载活载荷。
lean/full 商业候选在许可证与原生闭包完成前均不冻结这些实现；文字网关不依赖本模块的可选依赖。
"""

from __future__ import annotations

import io
import os
from typing import Any

# 可选档：tiny 最快(略糙) / base 均衡(默认) / small 最准(慢)。界面可直接切，引擎热加载。
WHISPER_MODELS = ("tiny", "base", "small")
_state: dict[str, Any] = {"name": os.getenv("WHISPER_MODEL", "base"), "model": None}
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AudioUnavailable(RuntimeError):
    """faster-whisper 未安装或模型不可用。"""


def current_model_name() -> str:
    return _state["name"]


def set_model(name: str) -> bool:
    """切换语音模型档（tiny/base/small）。下次转写按新档加载（warm() 可提前预热）。"""
    if name not in WHISPER_MODELS:
        return False
    if name != _state["name"]:
        _state["name"] = name
        _state["model"] = None  # 失效缓存，下次 _model() 重新加载
    return True


def _model() -> Any:
    if _state["model"] is None:
        model_dir = os.getenv("WHISPER_MODEL_DIR") or os.path.join(
            _REPO_ROOT, "models", f"faster-whisper-{_state['name']}"
        )
        if not os.path.isdir(model_dir):
            raise AudioUnavailable(
                f"缺少已审本地 Whisper 模型目录：{model_dir}（运行期自动下载已禁用）"
            )
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        try:
            from faster_whisper import WhisperModel  # 懒加载：未装也不影响引擎启动
        except ImportError as e:  # noqa: BLE001
            raise AudioUnavailable("未安装已锁定的 faster-whisper 语音引擎") from e
        threads = min(8, os.cpu_count() or 4)  # 多核并行，CPU 上更快
        _state["model"] = WhisperModel(
            model_dir,
            device="cpu",
            compute_type="int8",
            cpu_threads=threads,
            local_files_only=True,
        )
    return _state["model"]


def warm() -> None:
    """在显式本地语音实验环境中预热模型，让首次转写不卡在加载。

    主路径是 SenseVoice-Small（FunASR，自带标点、CPU 上 RTFx≈2、比 whisper 更准）；
    缺模型/依赖时它自动判不可用，仍预热 faster-whisper 作兜底。
    Nemotron 仅在 NEMOTRON_ASR=1 时才预热（旧的实验快速档，默认不用）。"""
    if os.getenv("SENSEVOICE_ASR") != "0":  # 默认开；设 0 可彻底关掉 SenseVoice
        try:
            from gateway import asr_sensevoice

            asr_sensevoice.warm()
        except Exception:  # noqa: BLE001
            pass
    # whisper 始终预热作兜底（即便 SenseVoice 可用，模型不可控时也能立刻回退）。
    try:
        _model()
    except Exception:  # noqa: BLE001
        pass
    if os.getenv("NEMOTRON_ASR") == "1":
        try:
            from gateway import asr_nemotron

            asr_nemotron.warm()
        except Exception:  # noqa: BLE001
            pass


def _to_simplified(text: str) -> str:
    """中文统一转简体（Whisper 有时会输出繁体）。zhconv 没装就原样返回；非中文不受影响。"""
    try:
        from zhconv import convert

        return convert(text, "zh-cn")
    except Exception:  # noqa: BLE001
        return text


def transcribe(data: bytes, language: str | None = None) -> str:
    """把音频字节转成文字。language 传 None 即自动识别语种。

    优先用 SenseVoice-Small（FunASR runtime，CPU 上 RTFx≈2、自带标点、中英日韩粤多语，
    实测比 whisper base 更快更准）；模型/依赖不可用或出错时，自动回退 faster-whisper（不影响可用性）。
    所有路径都过 _to_simplified 统一成简体。
    """
    # 主路径：SenseVoice-Small。缺模型/依赖会抛 SenseVoiceUnavailable，落到下面 whisper。
    # 想彻底关掉它（只用 whisper），设环境变量 SENSEVOICE_ASR=0。
    if os.getenv("SENSEVOICE_ASR") != "0":
        try:
            from gateway import asr_sensevoice

            text = asr_sensevoice.transcribe(data, language)
            if text:  # 空串当作未识别，落回 whisper 再试一次
                return _to_simplified(text)
        except Exception as e:  # noqa: BLE001  # 任何错误都回退 whisper，绝不让端点崩
            import logging

            logging.getLogger("uvicorn.error").warning("SenseVoice 转写失败，回退 whisper：%r", e)

    # 旧实验快速档：Nemotron 在本机 CPU 实测 RTFx<1（慢），默认不用；设 NEMOTRON_ASR=1 才走。
    if os.getenv("NEMOTRON_ASR") == "1":
        try:
            from gateway import asr_nemotron

            text = asr_nemotron.transcribe(data, language)
            if text:  # 空串当作未识别，落回 whisper 再试一次
                return _to_simplified(text)
        except Exception as e:  # noqa: BLE001  # 任何错误都回退 whisper
            import logging

            logging.getLogger("uvicorn.error").warning("Nemotron 转写失败，回退 whisper：%r", e)

    model = _model()
    # 诱导输出标点：whisper base 中文默认几乎不带标点，给一句含标点的中文提示来“带节奏”。
    # 英文本身就带标点，显式英文时不加中文提示以免干扰。
    lang = (language or "").lower()
    prompt = None if lang.startswith("en") else "以下是普通话的句子，包含标点符号。"
    segments, _info = model.transcribe(
        io.BytesIO(data), language=language or None, vad_filter=True, initial_prompt=prompt
    )
    return _to_simplified("".join(seg.text for seg in segments).strip())
