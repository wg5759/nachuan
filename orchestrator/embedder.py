"""本地文本向量化（bge-small-zh-v1.5）：给知识库/长期记忆做 embedding 混合检索。

为什么这样选（对齐 YAGNI + 文字主线零强依赖 + 无独显低压 U 也要快）：
- torch / transformers / numpy 都是本地实验可选项；缺任一项就退回关键词检索。
- 懒加载 + 单例：引擎启动**不**加载；首次入库/检索才触发，加载一次常驻(~300MB)。
- 安全降级：模型下载/加载/编码任一步失败 → encode() 返回 None，调用方回退纯关键词，
  绝不因向量层出问题而让检索崩（纳川一贯风格）。
- 只加载预先审阅的本地 safetensors；运行期不访问 ModelScope/Hugging Face。
- bge 官方口径：CLS pooling + L2 归一化；query 端加检索指令前缀提升召回。
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_MODEL_DIR = os.path.join(_REPO_ROOT, "models", "bge-small-zh-v1.5")
# bge-zh 建议给「查询」加这段指令前缀（文档端不加），短查询召回更稳。
_QUERY_PREFIX = "为这个句子生成表示以用于检索相关文章："
EMBED_DIM = 512

_NUMPY: Any = None
_NUMPY_CHECKED = False


def _numpy() -> Any:
    """按需取得 numpy；text-first 发行版不携带时返回 None。"""
    global _NUMPY, _NUMPY_CHECKED
    if not _NUMPY_CHECKED:
        try:
            import numpy as module
        except ImportError:
            module = None
        _NUMPY = module
        _NUMPY_CHECKED = True
    return _NUMPY


class _Embedder:
    """进程内单例。第一次用到才加载模型；失败后永久降级、不反复重试拖慢每次检索。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tok: Any = None
        self._model: Any = None
        self._torch: Any = None
        self._worker: Any = None
        self._state = "idle"  # idle → loading → ready / failed

    def _ready(self) -> bool:
        """非阻塞就绪检查：ready→True；idle→**后台**起线程加载并立即返回 False。

        关键：加载 bge 在这台低压 U 上约 40-50s，绝不能让首次检索同步等它——
        加载期间一律返回 False（本次降级纯关键词），后台线程装好后续自动用向量。
        """
        if self._state == "ready":
            return True
        if self._state == "failed":
            return False
        with self._lock:
            if self._state == "idle":
                self._state = "loading"
                worker = threading.Thread(target=self._load, daemon=True)
                self._worker = worker
                try:
                    worker.start()
                except BaseException:
                    self._worker = None
                    self._state = "failed"
                    raise
        return False

    def start_warmup(self) -> Any:
        """Start the one-shot loader and return its retained worker handle."""

        self._ready()
        with self._lock:
            return self._worker

    def _load(self) -> None:
        try:
            if os.environ.get("NACHUAN_EMBED_DISABLED"):
                self._state = "failed"  # 显式禁用（测试/无网）→ 降级，不下载
                return
            if _numpy() is None:
                self._state = "failed"  # text-first 发行版：纯关键词检索
                return
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
            import torch
            from transformers import AutoModel, AutoTokenizer

            path = self._resolve_dir()
            if not path:
                self._state = "failed"
                return
            tok = AutoTokenizer.from_pretrained(
                path, local_files_only=True, trust_remote_code=False
            )
            model = AutoModel.from_pretrained(
                path,
                local_files_only=True,
                trust_remote_code=False,
                use_safetensors=True,
            )
            model.eval()
            self._tok, self._model, self._torch = tok, model, torch
            self._state = "ready"
        except Exception:  # noqa: BLE001  模型环境有问题 → 整体降级
            self._state = "failed"

    def _resolve_dir(self) -> Optional[str]:
        # 环境变量只接受本地目录。没有目录/没有 safetensors 就降级关键词检索，绝不联网。
        path = os.environ.get("NACHUAN_EMBED_MODEL") or _DEFAULT_MODEL_DIR
        if not os.path.isdir(path):
            return None
        try:
            if not any(name.endswith(".safetensors") for name in os.listdir(path)):
                return None
        except OSError:
            return None
        return os.path.abspath(path)

    def encode(self, texts: list[str], is_query: bool = False) -> Any | None:
        if not texts or not self._ready():
            return None
        torch = self._torch
        try:
            xs = [(_QUERY_PREFIX + t if is_query else t) for t in texts]
            enc = self._tok(
                xs, padding=True, truncation=True, max_length=512, return_tensors="pt"
            )
            with torch.no_grad():
                out = self._model(**enc)
            v = out.last_hidden_state[:, 0]  # CLS pooling
            v = torch.nn.functional.normalize(v, p=2, dim=1)
            return v.cpu().numpy().astype("float32")
        except Exception:  # noqa: BLE001
            return None


_INSTANCE = _Embedder()


def encode(texts: Any, is_query: bool = False) -> Any | None:
    """编码为 L2 归一化向量。texts 可为单条 str 或 list[str]。

    返回：单条→shape (512,)；多条→shape (n,512)；**不可用时返回 None**（调用方须回退）。
    向量已归一化，余弦相似度 = 点积。
    """
    single = isinstance(texts, str)
    arr = [texts] if single else [t for t in texts if isinstance(t, str)]
    if not arr:
        return None
    out = _INSTANCE.encode(arr, is_query=is_query)
    if out is None:
        return None
    return out[0] if single else out


def available() -> bool:
    """就绪返回 True；未就绪会**后台**触发一次加载并返回 False（不阻塞）。用于启动预热。"""
    return _INSTANCE._ready()


def start_warmup() -> Any:
    """Start background loading and expose its one process-owned worker."""

    return _INSTANCE.start_warmup()


def to_blob(vec: Any) -> bytes:
    """向量 → SQLite BLOB（float32 紧凑存储）。"""
    np = _numpy()
    if np is None:
        return b""
    return np.asarray(vec, dtype="float32").tobytes()


def from_blob(b: Optional[bytes]) -> Any | None:
    """SQLite BLOB → 向量；空/坏数据返回 None。"""
    if not b:
        return None
    np = _numpy()
    if np is None:
        return None
    try:
        v = np.frombuffer(b, dtype="float32")
        return v if v.size == EMBED_DIM else None
    except Exception:  # noqa: BLE001
        return None


def encode_query(text: str) -> Any | None:
    """便捷：把查询编码成向量（加 bge 检索指令前缀）；不可用返回 None。"""
    return encode(text, is_query=True)


def cosine_blobs(qvec: Any | None, blob: Any) -> Optional[float]:
    """query 向量与存储 BLOB 的余弦（向量已归一化→点积）。任一为空返回 None。"""
    cv = from_blob(blob)
    if qvec is None or cv is None:
        return None
    np = _numpy()
    if np is None:
        return None
    return max(0.0, float(np.dot(qvec, cv)))


def fuse(kw: float, vs: Optional[float], alpha: float = 0.5) -> float:
    """融合关键词分与向量余弦：无向量(降级)→纯关键词；有向量→加权和(两者同为 0..1)。"""
    if vs is None:
        return kw
    return alpha * kw + (1.0 - alpha) * vs
