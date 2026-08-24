"""本地语义缓存（省 token / 省额度）：zilliztech GPTCache，纯本地、离线。

同一个/语义相近的问题再次问到时，直接返回上次缓存的答案，不再调用大模型——省钱省时。
判“相近”靠**本地**句向量（bge-small-zh，~95MB，CPU），存储用**本地** SQLite + 本地 faiss。
绝不用 OpenAI/云端 embedding（那会把你的提问发出去，违反“绝对安全”）。

安全降级：未开启/没装包/模型缺失/任何异常 → 全部静默跳过，照常走正常 LLM 调用，绝不影响主流程。

embedding 模型放仓库内 `models/bge-small-zh-v1.5/`（.gitignore 已忽略 models/），
模型必须由发布流水线或机主离线审计后放入目录，并记录 SHA-256；运行期不会自动下载。

开关（环境变量）：
  SEMCACHE_ENABLED=1        开启语义缓存（默认关——加缓存属行为变化，显式开更稳）
  SEMCACHE_EMBED_DIR=...    覆盖 embedding 模型目录
  SEMCACHE_DB_DIR=...       覆盖缓存落盘目录（默认 data/semcache/）
  SEMCACHE_THRESHOLD=0.80   语义相似阈值（faiss 距离换算的命中门槛，越高越严）
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

# ── 路径约定（与 asr_nemotron / compress 同套：仓库内 models/，可用环境变量覆盖）──
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_EMBED_DIR = os.path.join(_REPO_ROOT, "models", "bge-small-zh-v1.5")
EMBED_DIR = os.getenv("SEMCACHE_EMBED_DIR", _DEFAULT_EMBED_DIR)
_DEFAULT_DB_DIR = os.path.join(_REPO_ROOT, "data", "semcache")
DB_DIR = os.getenv("SEMCACHE_DB_DIR", _DEFAULT_DB_DIR)

# 语义相似阈值：bge CLS 向量已归一，GPTCache 的 SearchDistanceEvaluation 把 L2 距离映成 0..1
# 相似度，threshold 越高越严。0.80 较稳（避免把不同问题误判成同一个）。
THRESHOLD = float(os.getenv("SEMCACHE_THRESHOLD", "0.80"))

# 缓存的 prompt 最长截断（太长的问题做语义缓存意义不大，也省 embedding 时间）。
_MAX_PROMPT = 4000


def enabled() -> bool:
    """语义缓存总开关（默认关；设 SEMCACHE_ENABLED=1/true 开启）。"""
    return os.getenv("SEMCACHE_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


class _SemCacheUnavailable(RuntimeError):
    """依赖未装 / 模型缺失 / 初始化失败。调用方据此安全降级（跳过缓存）。"""


_state: dict[str, Any] = {"cache": None, "tok": None, "mdl": None, "failed": False, "dim": 0}
_lock = threading.Lock()


def _embed_fn():
    """返回一个 (text)->np.float32[dim] 的本地句向量函数（bge CLS + L2 归一）。"""
    import numpy as np
    import torch

    tok = _state["tok"]
    mdl = _state["mdl"]

    def embed(text: str):
        with torch.no_grad():
            enc = tok([text], padding=True, truncation=True, max_length=512, return_tensors="pt")
            out = mdl(**enc)
            emb = out.last_hidden_state[:, 0]  # bge 用 [CLS]
            emb = torch.nn.functional.normalize(emb, p=2, dim=1)
            return emb[0].cpu().numpy().astype("float32")

    return embed


def _init() -> Any:
    """懒加载本地 embedding + 初始化 GPTCache（线程安全、只做一次；失败标记后不再重试）。"""
    if _state["cache"] is not None:
        return _state["cache"]
    if _state["failed"]:
        raise _SemCacheUnavailable("先前初始化失败")
    with _lock:
        if _state["cache"] is not None:
            return _state["cache"]
        if _state["failed"]:
            raise _SemCacheUnavailable("先前初始化失败")
        # 强制离线：embedding 全在本机，绝不向 huggingface.co 发请求（安全要求）。
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        if not os.path.isdir(EMBED_DIR):
            _state["failed"] = True
            raise _SemCacheUnavailable(f"embedding 模型目录不存在：{EMBED_DIR}")
        try:
            import torch  # noqa: F401
            from transformers import AutoModel, AutoTokenizer
        except Exception as e:  # noqa: BLE001
            _state["failed"] = True
            raise _SemCacheUnavailable("未安装 transformers/torch") from e
        try:
            from gptcache import Cache, Config
            from gptcache.manager import CacheBase, VectorBase, get_data_manager
            from gptcache.processor.pre import get_prompt
            from gptcache.similarity_evaluation.distance import SearchDistanceEvaluation
        except Exception as e:  # noqa: BLE001
            _state["failed"] = True
            raise _SemCacheUnavailable("未安装锁定的 savers 依赖（uv sync --locked --extra savers）") from e
        try:
            tok = AutoTokenizer.from_pretrained(
                EMBED_DIR, local_files_only=True, trust_remote_code=False
            )
            mdl = AutoModel.from_pretrained(
                EMBED_DIR,
                local_files_only=True,
                trust_remote_code=False,
                use_safetensors=True,
            )
            mdl.eval()
            _state["tok"], _state["mdl"] = tok, mdl
            embed = _embed_fn()
            dim = int(embed("dim probe").shape[0])
            _state["dim"] = dim

            os.makedirs(DB_DIR, exist_ok=True)
            sql_url = "sqlite:///" + os.path.join(DB_DIR, "cache.db").replace("\\", "/")
            faiss_path = os.path.join(DB_DIR, "faiss.index")
            data_manager = get_data_manager(
                CacheBase("sqlite", sql_url=sql_url),
                VectorBase("faiss", dimension=dim, index_path=faiss_path),
            )

            def embedding_func(prompt: str, **_: Any):
                return embed(prompt)

            cache = Cache()
            cache.init(
                pre_embedding_func=get_prompt,
                embedding_func=embedding_func,
                data_manager=data_manager,
                similarity_evaluation=SearchDistanceEvaluation(),
                config=Config(similarity_threshold=THRESHOLD),
            )
            _state["cache"] = cache
            return cache
        except Exception as e:  # noqa: BLE001
            _state["failed"] = True
            raise _SemCacheUnavailable(f"GPTCache 初始化失败：{type(e).__name__}: {e}") from e


def available() -> bool:
    """缓存是否可用（依赖在 + 模型在 + 能初始化）。不抛异常。"""
    try:
        _init()
        return True
    except Exception:  # noqa: BLE001
        return False


def warm() -> None:
    """预热：后台线程提前加载，首次查询不卡在加载。"""
    try:
        _init()
    except Exception:  # noqa: BLE001
        pass


def _key(model: str, prompt: str) -> str:
    """缓存键空间隔离：把 model 揉进 prompt，避免不同模型/不同语义空间互相串答。"""
    p = (prompt or "")[:_MAX_PROMPT]
    return f"[{model}] {p}"


def lookup(model: str, prompt: str) -> Optional[str]:
    """查语义缓存：命中返回缓存答案文本，未命中/不可用/异常 → None（调用方照常调模型）。"""
    if not enabled() or not prompt:
        return None
    try:
        cache = _init()
    except Exception:  # noqa: BLE001
        return None
    try:
        from gptcache.adapter.api import get as cache_get

        res = cache_get(_key(model, prompt), cache_obj=cache)
        return res if isinstance(res, str) and res else None
    except Exception:  # noqa: BLE001
        return None


def store(model: str, prompt: str, answer: str) -> None:
    """把一次问答写入语义缓存。安全降级：不可用/异常 → 静默跳过，绝不影响主流程。"""
    if not enabled() or not prompt or not answer or not isinstance(answer, str):
        return
    try:
        cache = _init()
    except Exception:  # noqa: BLE001
        return
    try:
        from gptcache.adapter.api import put as cache_put

        cache_put(_key(model, prompt), answer, cache_obj=cache)
    except Exception:  # noqa: BLE001
        return


def prompt_from_messages(messages: list[Any]) -> str:
    """从消息列表里取“可缓存的提问串”：拼最后一条 user 文本（够稳、够区分）。

    只看用户问题本身，不含被注入的记忆/历史（那些是上下文、不该决定缓存命中）。
    取不到则返回空串（调用方据此不查缓存）。
    """
    try:
        for m in reversed(messages):
            role = getattr(m, "role", None) if not isinstance(m, dict) else m.get("role")
            content = getattr(m, "content", None) if not isinstance(m, dict) else m.get("content")
            if role == "user" and isinstance(content, str) and content.strip():
                return content.strip()
    except Exception:  # noqa: BLE001
        return ""
    return ""
