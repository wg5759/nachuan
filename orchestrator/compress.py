"""本地提示压缩（省 token）：microsoft LLMLingua-2，**torch-free**、离线、CPU。

只压**冗余上下文**（注入的长期记忆 / 案例解法 / 很长的历史或文档），
绝不压用户当前的真实问题/指令——压缩只为省 token，不能改变用户的话。

模型是个小的 token 分类器（bert-base-multilingual-cased 级），不是生成式 LLM，CPU 上很快。
逐 token 打“保留/丢弃”概率，删掉信息量低的词，中英都支持。**本实现只用 onnxruntime +
tokenizers**（不碰 torch/transformers），纯本地、零外发；但其许可证/原生闭包尚未完成，
当前仅供显式 ``compress`` extra 的本地评估，不冻结进 lean/full 商业候选。

模型文件放仓库内 `models/llmlingua-2-bert-base-multilingual-cased-meetingbank/`（与 .gitignore 一致）：
  - 必需：`tokenizer.json`（分词器）
  - 必需其一：`onnx/model_quantized.onnx`（~179MB，推荐）或 `onnx/model.onnx`（fp32）
本机已有 ModelScope 下来的 safetensors，可用 `scripts/_export_llmlingua2_onnx.py` 一次性导出 onnx
（导出用 torch，仅一次性开发步骤；运行期只需 onnxruntime）。空版/商用从图床/镜像下预导出的 onnx 即可。

缺文件/没装包/任何异常 → 安全降级：原样返回 text，绝不影响主流程。

开关（环境变量）：
  COMPRESS_ENABLED=0      关闭压缩（默认开）
  LLMLINGUA2_DIR=...      覆盖模型目录
  LLMLINGUA2_ONNX=...     覆盖 onnx 文件路径
  COMPRESS_MIN_CHARS=400  低于此长度不压（短文本压了反而亏，也更易失真）
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any, Optional

_MODEL_NAME = "llmlingua-2-bert-base-multilingual-cased-meetingbank"


def _resolve_model_dir() -> str:
    """模型目录：env 优先 → 打包版(PyInstaller)的 resources/models → 源码仓库 models/。"""
    env = os.getenv("LLMLINGUA2_DIR")
    if env:
        return env
    # PyInstaller 打包版：engine.exe 在 resources/engine/，模型(electron-builder extraResources)在 resources/models/
    if getattr(sys, "frozen", False):
        cand = os.path.normpath(
            os.path.join(os.path.dirname(sys.executable), "..", "models", _MODEL_NAME)
        )
        if os.path.isdir(cand):
            return cand
    # 源码/开发：仓库内 models/
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", _MODEL_NAME
    )


MODEL_DIR = _resolve_model_dir()

# 低于此字符数不压缩：短文本省不下多少、还更容易丢意思。
MIN_CHARS = int(os.getenv("COMPRESS_MIN_CHARS", "400"))

# BERT token-classifier 的窗口上限（max_position_embeddings=512，留 2 个给 [CLS]/[SEP]）。
_MAX_LEN = 512
_WINDOW = _MAX_LEN - 2


def enabled() -> bool:
    """压缩总开关（默认开；设 COMPRESS_ENABLED=0/false 关闭）。"""
    return os.getenv("COMPRESS_ENABLED", "1").strip().lower() not in {"0", "false", "no", ""}


class _CompressorUnavailable(RuntimeError):
    """模型缺失/依赖未装/加载失败。调用方据此安全降级（原样返回）。"""


# 加载好的会话缓存：session(onnxruntime) + tokenizer + 输入/输出名 + 特殊 token id。
_state: dict[str, Any] = {"engine": None, "failed": False}
_lock = threading.Lock()


def _find_onnx() -> Optional[str]:
    """按优先级找 onnx 文件：env → onnx/量化版 → onnx/fp32 → 目录根。找不到返回 None。"""
    env = os.getenv("LLMLINGUA2_ONNX")
    if env and os.path.isfile(env):
        return env
    for rel in (
        os.path.join("onnx", "model_quantized.onnx"),
        os.path.join("onnx", "model.onnx"),
        "model_quantized.onnx",
        "model.onnx",
    ):
        p = os.path.join(MODEL_DIR, rel)
        if os.path.isfile(p):
            return p
    return None


def _load() -> dict[str, Any]:
    """懒加载 onnxruntime 会话 + 分词器（线程安全、只加载一次；失败标记后不再重试）。"""
    if _state["engine"] is not None:
        return _state["engine"]
    if _state["failed"]:
        raise _CompressorUnavailable("先前加载失败")
    with _lock:
        if _state["engine"] is not None:
            return _state["engine"]
        if _state["failed"]:
            raise _CompressorUnavailable("先前加载失败")
        tok_path = os.path.join(MODEL_DIR, "tokenizer.json")
        onnx_path = _find_onnx()
        if not os.path.isfile(tok_path) or not onnx_path:
            _state["failed"] = True
            raise _CompressorUnavailable(
                f"缺模型文件（需 {tok_path} 与 onnx/model_quantized.onnx）"
            )
        try:
            import numpy as np  # noqa: F401  # 早失败：numpy 缺也降级
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except Exception as e:  # noqa: BLE001
            _state["failed"] = True
            raise _CompressorUnavailable(
                "未安装锁定的 compress 依赖（uv sync --locked --extra compress）"
            ) from e
        try:
            tok = Tokenizer.from_file(tok_path)
            so = ort.SessionOptions()
            so.log_severity_level = 3  # 静音 onnxruntime 警告
            sess = ort.InferenceSession(
                onnx_path, sess_options=so, providers=["CPUExecutionProvider"]
            )
        except Exception as e:  # noqa: BLE001
            _state["failed"] = True
            raise _CompressorUnavailable(f"ONNX 加载失败：{type(e).__name__}: {e}") from e
        input_names = [i.name for i in sess.get_inputs()]
        eng = {
            "sess": sess,
            "tok": tok,
            "inputs": input_names,
            "output": sess.get_outputs()[0].name,
            "cls": tok.token_to_id("[CLS]"),
            "sep": tok.token_to_id("[SEP]"),
        }
        _state["engine"] = eng
        return eng


def available() -> bool:
    """模型是否可用（文件齐全 + 依赖在 + 能加载）。不抛异常。"""
    try:
        _load()
        return True
    except Exception:  # noqa: BLE001
        return False


def warm() -> None:
    """预热：后台线程提前加载，首次真实压缩不卡在加载。"""
    try:
        _load()
    except Exception:  # noqa: BLE001
        pass


# ── 纯函数（不依赖模型，便于单测）────────────────────────────────────────────

def _aggregate_word_probs(
    word_ids: list[Optional[int]],
    offsets: list[tuple[int, int]],
    token_probs: list[float],
) -> tuple[list[tuple[int, int]], list[float]]:
    """把子词 token 的「保留概率」按词聚合（mean），返回 [(词的字符跨度), ...] 与 [词概率, ...]。

    word_ids[i] 是第 i 个 token 所属词的序号（None=特殊/无），与 LLMLingua-2 的 token_to_word="mean" 一致。
    保持词在原文里的出现顺序。
    """
    spans: dict[int, list[int]] = {}
    probs: dict[int, list[float]] = {}
    order: list[int] = []
    for wid, (s, e), p in zip(word_ids, offsets, token_probs):
        if wid is None or e <= s:
            continue
        if wid not in spans:
            spans[wid] = [s, e]
            probs[wid] = []
            order.append(wid)
        else:
            spans[wid][0] = min(spans[wid][0], s)
            spans[wid][1] = max(spans[wid][1], e)
        probs[wid].append(p)
    out_spans = [(spans[w][0], spans[w][1]) for w in order]
    out_probs = [sum(probs[w]) / len(probs[w]) for w in order]
    return out_spans, out_probs


def _keep_mask(word_probs: list[float], rate: float) -> list[bool]:
    """按 rate（保留比例）算阈值并选词：threshold=percentile(probs, 100*(1-rate))，≥ 阈值保留。

    与 LLMLingua-2 一致：对概率取分位数当阈值、保留高于阈值的词、保持原顺序。
    rate>=1 或词太少 → 全保留。
    """
    n = len(word_probs)
    if n == 0:
        return []
    if rate >= 1.0:
        return [True] * n
    # numpy 不属于 text-first 发行闭包；这里用与 numpy.percentile 默认 linear 方法等价的
    # 一维实现，让纯策略/安全降级测试不必安装本地模型运行库。
    ordered = sorted(float(value) for value in word_probs)
    position = (n - 1) * max(0.0, min(1.0, 1.0 - rate))
    lower = int(position)
    upper = min(n - 1, lower + 1)
    weight = position - lower
    thr = ordered[lower] * (1.0 - weight) + ordered[upper] * weight
    return [p >= thr for p in word_probs]


def _rebuild(text: str, spans: list[tuple[int, int]], keep: list[bool]) -> str:
    """按保留标记从原文跨度重建压缩文本：保留词原样取回，词间空白据原文还原（换行优先）。

    这样中文不会被插空格、英文保留空格、段落换行保留，删掉的词自然消失。
    """
    out: list[str] = []
    prev_end: Optional[int] = None
    for (s, e), k in zip(spans, keep):
        if not k:
            continue
        if prev_end is not None:
            gap = text[prev_end:s]
            if "\n" in gap:
                out.append("\n")
            elif any(ch.isspace() for ch in gap):
                out.append(" ")
        out.append(text[s:e])
        prev_end = e
    return "".join(out)


# ── 模型推理 ─────────────────────────────────────────────────────────────────

def _token_keep_probs(eng: dict[str, Any], text: str) -> tuple[
    list[Optional[int]], list[tuple[int, int]], list[float]
]:
    """对全文跑 onnx（按 512 窗口切分），返回每个内容 token 的 (word_id, offset, 保留概率)。"""
    import numpy as np

    tok = eng["tok"]
    enc = tok.encode(text, add_special_tokens=False)
    ids, offsets, word_ids = enc.ids, enc.offsets, enc.word_ids
    cls, sep = eng["cls"], eng["sep"]
    sess, out_name, input_names = eng["sess"], eng["output"], eng["inputs"]

    probs: list[float] = []
    for start in range(0, len(ids), _WINDOW):
        chunk = ids[start : start + _WINDOW]
        seq = [cls] + chunk + [sep] if cls is not None and sep is not None else chunk
        arr = np.asarray([seq], dtype=np.int64)
        feed: dict[str, Any] = {}
        for name in input_names:
            low = name.lower()
            if "type" in low or "segment" in low:
                feed[name] = np.zeros_like(arr)
            elif "mask" in low:
                feed[name] = np.ones_like(arr)
            else:  # input_ids
                feed[name] = arr
        logits = sess.run([out_name], feed)[0]  # [1, L, 2]
        logits = np.asarray(logits, dtype="float64")[0]
        # softmax → 取 label=1（保留）的概率
        m = logits.max(axis=-1, keepdims=True)
        ex = np.exp(logits - m)
        keep_p = (ex[:, 1] / ex.sum(axis=-1))
        # 去掉 [CLS]/[SEP] 两端，只留内容 token 概率
        content = keep_p[1:-1] if (cls is not None and sep is not None) else keep_p
        probs.extend(float(x) for x in content[: len(chunk)])
    return word_ids, offsets, probs


def _compress_core(eng: dict[str, Any], text: str, rate: float, force_tokens: list[str]) -> str:
    """完整压缩流程（已加载模型）：打分 → 聚合到词 → 选词 → 重建。"""
    word_ids, offsets, token_probs = _token_keep_probs(eng, text)
    spans, word_probs = _aggregate_word_probs(word_ids, offsets, token_probs)
    if not spans:
        return text
    keep = _keep_mask(word_probs, rate)
    # force_tokens：原文里等于这些字面的词强制保留（如代码符号），减少结构破坏。
    if force_tokens:
        fset = set(force_tokens)
        for i, (s, e) in enumerate(spans):
            if text[s:e] in fset:
                keep[i] = True
    return _rebuild(text, spans, keep)


# ── 对外 API（签名与旧版一致，4 个调用方零改动）────────────────────────────────

def compress_text(text: str, rate: float = 0.5, *, force_tokens: list[str] | None = None) -> str:
    """把一段冗余上下文压短，返回压缩后的文本。

    rate=0.5 约保留一半词。安全降级：未开启/太短/模型不可用/任何异常 → 原样返回 text。
    只该用于注入的记忆、案例解法、旧历史、长文档等“可有损”的内容；
    绝不要拿它压用户当前的问题/指令。
    """
    if not text or not isinstance(text, str):
        return text
    if not enabled() or len(text) < MIN_CHARS:
        return text
    try:
        eng = _load()
    except Exception:  # noqa: BLE001
        return text
    try:
        ft = force_tokens if force_tokens is not None else ["\n"]
        out = _compress_core(eng, text, rate, ft)
        # 兜底：压缩结果异常（空/反而更长）就用原文，绝不让“省 token”帮倒忙。
        if not out or not isinstance(out, str) or len(out) >= len(text):
            return text
        return out
    except Exception:  # noqa: BLE001
        return text


def compress_stats(text: str, rate: float = 0.5) -> dict[str, Any]:
    """压缩并返回度量（origin_tokens/compressed_tokens/rate/compressed）。供端点/测试/验证用。

    失败时返回 {"ok": False, ...}；不抛异常。
    """
    try:
        eng = _load()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "compressed": text}
    try:
        compressed = _compress_core(eng, text, rate, ["\n"])
        if not compressed or len(compressed) >= len(text):
            compressed = text
        tok = eng["tok"]
        origin = len(tok.encode(text, add_special_tokens=False).ids)
        comp = len(tok.encode(compressed, add_special_tokens=False).ids)
        return {
            "ok": True,
            "origin_tokens": origin,
            "compressed_tokens": comp,
            "rate": (comp / origin) if origin else 1.0,
            "compressed": compressed,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "compressed": text}
