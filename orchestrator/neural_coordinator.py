"""FUGU 三期批8③ · 神经点将（推理侧）——训练好的线性头按题选模型，~1s、零配额。

点将链的**训练先验**这一层：照 OpenFugu TRINITY 复刻思路，用冻结 Qwen3-0.6B 取 hidden state
+ 一个极小线性头（`train/train_coordinator.py` 产的 `models/coordinator/`）给当前题选个 worker。
排在点将链的：pick_by_record（实证冠军）→ **pick_neural（本模块，训练先验）**→ pick_next（LLM）→ 规则兜底。

对外只一个函数 `pick_neural(...)`。**降级第一**（与 coordinator/scoreboard 同律）：
- `models/coordinator/` 不在 / config 损坏 / head 形状不符 → 永远 None（组件缺失=静默不启用）；
- backbone（transformers）加载失败 → None，且置模块级 flag **不再重试**（打包版 excludes 掉
  transformers，import 必失败 → 天然降级，不拖累引擎）；
- 只对「当前在线(coordinator.pool_snapshot) ∩ config.model_ids ∩ 非 flagship ∩
  (need_tools→tool_capable)」的模型比分；softmax 最高 < confidence_floor → None（不硬选）；
- 全程 try/except 兜到 None。首调同步加载（耗时打日志），之后 ~1s。

**不进安装包**：`models/coordinator/` 不被 engine.spec / electron-builder 主动拷（见方案硬约束）；
引擎运行时探测到该目录且 transformers 可用才启用，否则这一层等于不存在（链路自动退到 LLM 点将）。
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

try:
    import numpy as np
except ImportError:  # text-first 发行版不携带本地神经点将运行库
    np = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

_REPO = Path(__file__).resolve().parent.parent
_MODEL_DIR = _REPO / "models" / "coordinator"

# ── 模块级懒加载单例（进程内只加载一次；线程安全）──
_lock = threading.Lock()
_loaded = False          # 是否已尝试加载（无论成败）
_head: Any = None                      # 线性头 W [n_models, hidden]
_config: dict[str, Any] | None = None  # config.json
_backbone_broken = False  # backbone 加载/前向曾失败 → 不再重试（省得每次点将都卡几秒）
_encoder: Any = None      # (tokenizer, model) 元组；mock/测试时可不需要


def _model_dir() -> Path:
    """产物目录（测试可 monkeypatch 指到 tmp_path）。"""
    return _MODEL_DIR


def _load_artifacts() -> bool:
    """加载 head.npy + config.json（不含 backbone）。成功→True 并填 _head/_config；否则 False。

    校验：config 必须含 model_ids/hidden_dim；head 形状须为 [len(model_ids), hidden_dim]。
    任何缺失/损坏/不匹配 → False（静默降级，绝不抛）。
    """
    global _head, _config
    if np is None:
        return False
    d = _model_dir()
    cfg_path = d / "config.json"
    head_path = d / "head.npy"
    if not cfg_path.exists() or not head_path.exists():
        return False
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model_ids = cfg.get("model_ids")
        hidden_dim = cfg.get("hidden_dim")
        if not isinstance(model_ids, list) or len(model_ids) < 2 or not isinstance(hidden_dim, int):
            return False
        if cfg.get("mock"):
            # mock 产物是冒烟用（hash 随机特征 + 假 backbone 名），生产推理绝不吃它——
            # 否则 _encode 会去下载名为 "mock(64)" 的模型必然失败。静默拒绝，等真训产物覆盖。
            log.info("neural_coordinator: 检出 mock 产物，生产不启用（等真训产物覆盖 models/coordinator/）。")
            return False
        W = np.load(head_path)
        if W.ndim != 2 or W.shape[0] != len(model_ids) or W.shape[1] != hidden_dim:
            log.warning("neural_coordinator: head 形状 %s 与 config(%d,%d) 不符，忽略",
                        W.shape, len(model_ids), hidden_dim)
            return False
        _head = W.astype(np.float64)
        _config = cfg
        return True
    except Exception:  # noqa: BLE001 config/head 损坏 → 静默降级
        return False


def _ensure_loaded() -> bool:
    """确保 artifacts 已尝试加载（只做一次）。返回是否可用（head+config 就绪）。"""
    global _loaded
    if _loaded:
        return _head is not None and _config is not None
    with _lock:
        if not _loaded:
            ok = False
            try:
                ok = _load_artifacts()
            except Exception:  # noqa: BLE001
                ok = False
            _loaded = True
            if ok:
                log.info("neural_coordinator: 已加载线性头 %s（%d 模型）",
                         _head.shape if _head is not None else None,
                         len(_config.get("model_ids", [])) if _config else 0)
    return _head is not None and _config is not None


def _encode(text: str) -> Any | None:
    """把「kind: ...\nuser: ...\n」裸文本编码成特征向量 h（与训练侧完全一致的取法）。

    首调同步加载冻结 backbone（transformers + Qwen3-0.6B），耗时打日志；之后复用单例、~1s。
    取**最后一个 token 的第 config.layer 层 hidden state**（训练侧默认倒数第二层 -2）。
    backbone 不可用（打包版 excludes / 未安装 / 本地目录缺失）→ 置 _backbone_broken，返回 None。

    **测试通过 monkeypatch 本函数**注入假特征，绝不真下 0.6B。
    """
    global _encoder, _backbone_broken
    if np is None or _backbone_broken or _config is None:
        return None
    try:
        if _encoder is None:
            with _lock:
                if _encoder is None:
                    import os

                    os.environ.setdefault("HF_HUB_OFFLINE", "1")
                    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
                    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
                    import torch  # noqa: F401 延迟导入：打包版无 transformers 时这里即失败降级
                    from transformers import AutoModel, AutoTokenizer

                    # config.backbone 只作训练溯源，不能作为运行期远程模型 ID。推理仅接受机主
                    # 明确提供的本地目录，避免被 config 注入任意 Hub 仓库/动态模型代码。
                    backbone = os.environ.get("NACHUAN_COORDINATOR_BACKBONE_DIR") or ""
                    if not os.path.isdir(backbone):
                        raise FileNotFoundError("缺少已审本地 coordinator backbone")
                    log.info("neural_coordinator: 首次加载 backbone %s（冻结，仅取特征，可能耗时）…", backbone)
                    tok = AutoTokenizer.from_pretrained(
                        backbone, local_files_only=True, trust_remote_code=False
                    )
                    mdl = AutoModel.from_pretrained(
                        backbone,
                        output_hidden_states=True,
                        local_files_only=True,
                        trust_remote_code=False,
                        use_safetensors=True,
                    )
                    mdl.eval()
                    _encoder = (tok, mdl)
        import torch

        tok, mdl = _encoder
        layer = int(_config.get("layer", -2))
        with torch.no_grad():
            enc = tok(text, return_tensors="pt", truncation=True, max_length=2048)
            out = mdl(**enc)
            hs = out.hidden_states[layer]      # [1, seq, hidden]
            v = hs[0, -1, :].to(torch.float32).cpu().numpy()
        return v.astype(np.float64)
    except Exception as e:  # noqa: BLE001 backbone 缺失/前向失败 → 永久降级，不再每次卡几秒
        _backbone_broken = True
        log.info("neural_coordinator: backbone 不可用（%r），本进程后续不再尝试神经点将。", e)
        return None


def _softmax(x: Any) -> Any:
    if np is None:
        return None
    x = x - x.max()
    e = np.exp(x)
    return e / e.sum()


def reset() -> None:
    """丢弃单例（测试隔离用：换了 _model_dir 后调它，下次 pick_neural 重新加载）。"""
    global _loaded, _head, _config, _backbone_broken, _encoder
    with _lock:
        _loaded = False
        _head = None
        _config = None
        _backbone_broken = False
        _encoder = None


def pick_neural(
    router: Any,
    transcript: str,
    *,
    task_kind: str = "general",
    need_tools: bool = False,
) -> dict[str, Any] | None:
    """神经点将：用训练好的线性头按当前题给池中选个 worker。返回 dict 或 None（降级）。

    命中返回 `{"model": <池中id>, "role": "worker", "instruction": "", "by": "neural"}`。
    以下任一 → None：产物不在/损坏；backbone 不可用；候选（在线∩训练列表∩非王牌∩需工具则可调工具）
    为空；softmax 最高分 < confidence_floor。全程 try/except 兜底 None（神经点将坏了绝不挡任务）。
    """
    try:
        if not _ensure_loaded():
            return None
        assert _config is not None and _head is not None
        model_ids: list[str] = _config["model_ids"]

        # 候选：当前在线 ∩ 训练列表 ∩ 非 flagship ∩ (need_tools→tool_capable)。
        from orchestrator import coordinator

        snap = coordinator.pool_snapshot(router, task_kind)
        if not snap:
            return None
        online = {e["model"]: e for e in snap}
        cand_idx: list[int] = []
        for j, mid in enumerate(model_ids):
            e = online.get(mid)
            if e is None:
                continue                          # 不在线 / 不在池
            if e.get("flagship"):
                continue                          # 自动路由不烧王牌
            if need_tools and not e.get("tool_capable", True):
                continue                          # 要动手就得能调工具
            cand_idx.append(j)
        if not cand_idx:
            return None                            # 训练列表与当前可用池无交集 → 交给下一级点将

        # 特征 → logits（只在候选下标上比分，softmax 归一化在候选内）。
        text = _format_input(task_kind, transcript)
        h = _encode(text)
        if h is None or h.shape[0] != _head.shape[1]:
            return None                            # backbone 不可用 / 维度不符 → 降级
        logits_all = _head @ h                     # [n_models]
        sub = np.array([logits_all[j] for j in cand_idx], dtype=np.float64)
        probs = _softmax(sub)
        best_local = int(probs.argmax())
        conf = float(probs[best_local])
        floor = float(_config.get("confidence_floor", 0.35))
        if conf < floor:
            log.debug("neural_coordinator: 置信 %.2f < floor %.2f → 降级", conf, floor)
            return None                            # 不够自信 → 不硬选，退回下一级

        model = model_ids[cand_idx[best_local]]
        return {"model": model, "role": "worker", "instruction": "", "by": "neural"}
    except Exception as e:  # noqa: BLE001 神经点将失败绝不挡任务，一律降级
        log.debug("neural_coordinator: 降级（%r）", e)
        return None


def _format_input(task_kind: str, transcript: str) -> str:
    """与训练侧同格式的裸文本输入（transcript 截断 ~2000 字，省 backbone 前向时间）。

    训练用「kind: {kind}\nuser: {题}\n」；推理时 transcript 就是当前对话裸文本，直接放到 user 段。
    """
    fmt = "kind: {kind}\nuser: {q}\n"
    if _config and isinstance(_config.get("input_format"), str):
        fmt = _config["input_format"]
    body = (transcript or "").strip()[:2000]
    try:
        return fmt.format(kind=task_kind or "general", q=body)
    except Exception:  # noqa: BLE001 format 占位不匹配 → 退回默认拼接
        return f"kind: {task_kind or 'general'}\nuser: {body}\n"
