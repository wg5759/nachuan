"""FUGU 三期批8② · 训练神经点将（冻结 Qwen3-0.6B + 线性头，CPU 分钟级）。

照 OpenFugu TRINITY 复刻思路：**冻结** backbone 只当特征提取器，训一个极小的线性头
`W ∈ R^{n_models × hidden}`（无 bias，~19.5K 参数）按题选模型。产物 `models/coordinator/`。

管线：
1. 读 `data/routing_dataset.jsonl` → 按题聚合软标签：每题对出现过的每个模型取 correct 均值，
   再对"该题出现过的模型"做 temperature-softmax（τ 可调）成目标分布；**缺席模型 mask 掉**
   （不参与该题 loss，避免"没评过=判它差"的错误信号）。
2. 特征：输入裸文本「kind: {kind}\nuser: {题}\n」→ 冻结 Qwen3-0.6B 前向 → 取**最后一个 token
   的倒数第二层 hidden state**（1024 维）当特征 h。backbone 全冻结，Adam 只训 W。
3. 目标：logits = W·h；对每题算 masked soft-label KL（只在该题出现过的模型上），乘样本权重
   （真评测 weight=1.0，战绩伪样本更低）。train/val 9:1，早停。
4. 产物：`head.npy`（W）+ `config.json`（model_ids 顺序 / backbone / hidden_dim / 层号 /
   温度 / confidence_floor / 训练时间 / val 指标）。打印 **val top-1 命中率 vs「always-最高均分
   模型」基线**——如实不粉饰。

开关：
- `--mock`：跳过 backbone，用 hash(题) 种子的确定性随机特征，秒级跑通整条管线（CI / 冒烟）。
- `--cmaes`：在 Adam 结果上再用 **numpy 手写 (μ,λ)-ES** 微调几代（致敬原版进化路线，不引第三方库）。
- `--backbone`：已审本地 backbone 目录；训练脚本不会自动访问模型 Hub。

**不真下 0.6B / 不烧配额**由调用者控制：CI 只跑 `--mock`；真训用真 backbone（作者手动）。
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_DATA_DIR = Path(os.getenv("DATA_DIR") or (_REPO / "data"))
_DATASET = _DATA_DIR / "routing_dataset.jsonl"
_OUT_DIR = _REPO / "models" / "coordinator"

_DEFAULT_BACKBONE = "Qwen/Qwen3-0.6B"
_MOCK_HIDDEN = 64          # mock 特征维度（小而快；真 backbone 是 1024）
_CONFIDENCE_FLOOR = 0.35   # 推理侧：softmax 最高分低于此 → 不信任、降级（写进 config）
_SECOND_TO_LAST = -2       # 取倒数第二层 hidden state（Fugu 经验：比最后一层更利于路由）


# ══════════════════════════════════════════════════════════════════════════
# 数据：读 jsonl → 按 (kind, 题) 聚合 → 软标签 + mask + 权重
# ══════════════════════════════════════════════════════════════════════════
def _load_rows(path: Path) -> list[dict[str, Any]]:
    """读 jsonl，容忍坏行；每行需含 q/kind/model/correct（weight 缺省 1.0）。"""
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001 坏行跳过
                continue
            if not all(k in r for k in ("q", "kind", "model", "correct")):
                continue
            r.setdefault("weight", 1.0)
            rows.append(r)
    return rows


class Sample:
    """一道题聚合成的训练样本：文本 + 每个出现过的模型的软目标 + mask + 权重。"""

    __slots__ = ("kind", "q", "text", "targets", "weight")

    def __init__(self, kind: str, q: str, targets: dict[str, float], weight: float):
        self.kind = kind
        self.q = q
        self.text = f"kind: {kind}\nuser: {q}\n"  # 训练=推理同格式（裸文本，Fugu 路由准）
        self.targets = targets  # {model_id: 平均 correct(0~1)}，只含该题出现过的模型
        self.weight = weight


def build_samples(rows: list[dict[str, Any]]) -> tuple[list[Sample], list[str]]:
    """按 (kind, q) 聚合成样本；返回 (samples, model_ids 排序列表)。

    - 每 (kind,q,model) 组内对 correct 取均值（多次评测/伪样本混合都稳）。
    - 样本权重 = 组内各条 weight 的均值（真评测 1.0，战绩伪样本更低 → 整题权重被拉低）。
    - model_ids：数据里出现过的所有模型，排序固定（决定 head 行顺序，须与 config 一致）。
    """
    # (kind, q, model) → [correct...], [weight...]
    agg: dict[tuple[str, str, str], list[list[float]]] = {}
    model_set: set[str] = set()
    for r in rows:
        key = (r["kind"], r["q"], r["model"])
        agg.setdefault(key, [[], []])
        agg[key][0].append(float(r["correct"]))
        agg[key][1].append(float(r.get("weight", 1.0)))
        model_set.add(r["model"])

    # (kind, q) → {model: mean_correct}, 以及题级权重
    per_q: dict[tuple[str, str], dict[str, float]] = {}
    per_q_w: dict[tuple[str, str], list[float]] = {}
    for (kind, q, model), (corrects, weights) in agg.items():
        qk = (kind, q)
        per_q.setdefault(qk, {})
        per_q[qk][model] = sum(corrects) / len(corrects)
        per_q_w.setdefault(qk, [])
        per_q_w[qk].append(sum(weights) / len(weights))

    samples: list[Sample] = []
    for (kind, q), targets in per_q.items():
        ws = per_q_w[(kind, q)]
        weight = sum(ws) / len(ws) if ws else 1.0
        samples.append(Sample(kind, q, targets, weight))
    model_ids = sorted(model_set)
    return samples, model_ids


def soft_label(targets: dict[str, float], model_ids: list[str], tau: float) -> tuple[np.ndarray, np.ndarray]:
    """把一题的 {model: mean_correct} 转成 (目标分布 y, mask)。

    - mask[j]=1 当且仅当 model_ids[j] 在该题出现过（只在这些位算 loss）。
    - y = softmax(mean_correct / tau) over 出现过的模型；缺席位 y=0（且 mask=0 不参与）。
    """
    n = len(model_ids)
    y = np.zeros(n, dtype=np.float64)
    mask = np.zeros(n, dtype=np.float64)
    idx = [j for j, m in enumerate(model_ids) if m in targets]
    if not idx:
        return y, mask
    vals = np.array([targets[model_ids[j]] for j in idx], dtype=np.float64) / max(tau, 1e-6)
    vals -= vals.max()  # 数值稳定
    ex = np.exp(vals)
    probs = ex / ex.sum()
    for k, j in enumerate(idx):
        y[j] = probs[k]
        mask[j] = 1.0
    return y, mask


# ══════════════════════════════════════════════════════════════════════════
# 特征：mock（hash 种子随机）或真 backbone（冻结 Qwen3-0.6B 倒数第二层最后 token）
# ══════════════════════════════════════════════════════════════════════════
def mock_features(texts: list[str], hidden: int = _MOCK_HIDDEN) -> np.ndarray:
    """确定性随机特征：每条文本用 hash 当种子生成固定向量（同文本永远同特征）。

    纯为秒级验证整条管线（聚合→软标签→Adam→产物）；与真 backbone 无关。
    """
    feats = np.zeros((len(texts), hidden), dtype=np.float32)
    for i, t in enumerate(texts):
        seed = int(hashlib_sha1_int(t))
        rng = np.random.default_rng(seed)
        v = rng.standard_normal(hidden).astype(np.float32)
        feats[i] = v / (np.linalg.norm(v) + 1e-8)  # 归一化，量纲稳定
    return feats


def hashlib_sha1_int(text: str) -> int:
    import hashlib

    return int(hashlib.sha1(text.encode("utf-8")).hexdigest()[:15], 16)


def backbone_features(texts: list[str], backbone: str, layer: int = _SECOND_TO_LAST) -> tuple[np.ndarray, int]:
    """真 backbone 特征（冻结前向，无梯度）：取每条文本**最后一个 token 的第 `layer` 层 hidden**。

    返回 (feats[N,hidden], hidden_dim)。仅真训时调用（会加载 transformers + 下载 Qwen3-0.6B）。
    ``backbone`` 必须是已审本地目录；训练脚本不会从 Hub 自动下载。
    """
    if not os.path.isdir(backbone):
        raise ValueError("--backbone 必须指向已审本地模型目录；运行期远程下载已禁用")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    import torch  # 延迟导入：mock 路径完全不碰 torch/transformers
    from transformers import AutoModel, AutoTokenizer

    print(f"[train] 加载 backbone {backbone}（冻结，仅取特征）…")
    tok = AutoTokenizer.from_pretrained(
        backbone, local_files_only=True, trust_remote_code=False
    )
    model = AutoModel.from_pretrained(
        backbone,
        output_hidden_states=True,
        torch_dtype=torch.float32,
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
    )
    model.eval()
    for p in model.parameters():  # 全冻结（保险，虽然 no_grad 已足够）
        p.requires_grad_(False)

    feats: list[np.ndarray] = []
    hidden_dim = 0
    with torch.no_grad():
        for t in texts:
            enc = tok(t, return_tensors="pt", truncation=True, max_length=2048)
            out = model(**enc)
            hs = out.hidden_states[layer]           # [1, seq, hidden]
            last_tok = hs[0, -1, :]                   # 最后一个 token
            v = last_tok.to(torch.float32).cpu().numpy()
            hidden_dim = v.shape[0]
            feats.append(v)
    arr = np.stack(feats).astype(np.float32)
    return arr, hidden_dim


# ══════════════════════════════════════════════════════════════════════════
# 训练：Adam 只训 W；masked soft-label KL × 样本权重；9:1；早停
# ══════════════════════════════════════════════════════════════════════════
def _softmax_rows(logits: np.ndarray) -> np.ndarray:
    m = logits.max(axis=1, keepdims=True)
    ex = np.exp(logits - m)
    return ex / ex.sum(axis=1, keepdims=True)


def _masked_kl_and_grad(
    W: np.ndarray, X: np.ndarray, Y: np.ndarray, M: np.ndarray, w: np.ndarray
) -> tuple[float, np.ndarray]:
    """masked soft-label 交叉熵（对每题只在 mask 位归一化），返回 (加权平均 loss, dW)。

    形式：对第 i 题，p = softmax(W·x_i)（全模型），但只把 mask 位的目标 y_i 与预测比对——
    等价于在 mask 位上算 CE。梯度用 softmax-CE 的经典 (p - y) 形式，再乘 mask 与样本权重。
    """
    logits = X @ W.T                       # [N, n_models]
    P = _softmax_rows(logits)              # [N, n_models]
    eps = 1e-9
    # 每题在 mask 位的交叉熵： -sum_j mask*y*log(p)
    ce = -(M * Y * np.log(P + eps)).sum(axis=1)   # [N]
    wsum = w.sum() + eps
    loss = float((w * ce).sum() / wsum)
    # 梯度： dLoss/dlogits = (P - Y) 在 mask 位（缺席位不回传）; 乘样本权重
    G = (P - Y) * M                         # [N, n_models]
    G = G * (w[:, None] / wsum)
    dW = G.T @ X                            # [n_models, hidden]
    return loss, dW


def train_head(
    X: np.ndarray, Y: np.ndarray, M: np.ndarray, w: np.ndarray, *,
    epochs: int = 400, lr: float = 0.05, patience: int = 40, seed: int = 0,
    val_idx: np.ndarray | None = None,
) -> np.ndarray:
    """Adam 训练线性头 W（[n_models, hidden]）。val_idx 给早停用（在验证子集上看 loss）。"""
    rng = np.random.default_rng(seed)
    n_models = Y.shape[1]
    hidden = X.shape[1]
    W = (rng.standard_normal((n_models, hidden)) * 0.01).astype(np.float64)

    # train / val 划分（早停）
    N = X.shape[0]
    all_idx = np.arange(N)
    if val_idx is None:
        val_idx = np.array([], dtype=int)
    tr_idx = np.setdiff1d(all_idx, val_idx)
    if tr_idx.size == 0:
        tr_idx = all_idx

    mt = np.zeros_like(W)
    vt = np.zeros_like(W)
    b1, b2, eps = 0.9, 0.999, 1e-8
    best_val = math.inf
    best_W = W.copy()
    bad = 0
    for ep in range(1, epochs + 1):
        loss, dW = _masked_kl_and_grad(W, X[tr_idx], Y[tr_idx], M[tr_idx], w[tr_idx])
        mt = b1 * mt + (1 - b1) * dW
        vt = b2 * vt + (1 - b2) * (dW * dW)
        mhat = mt / (1 - b1 ** ep)
        vhat = vt / (1 - b2 ** ep)
        W -= lr * mhat / (np.sqrt(vhat) + eps)
        # 早停：验证子集 loss（无验证集则用训练 loss 兜底）
        if val_idx.size > 0:
            vloss, _ = _masked_kl_and_grad(W, X[val_idx], Y[val_idx], M[val_idx], w[val_idx])
        else:
            vloss = loss
        if vloss + 1e-6 < best_val:
            best_val = vloss
            best_W = W.copy()
            bad = 0
        else:
            bad += 1
            if bad >= patience:
                break
    return best_W


# ══════════════════════════════════════════════════════════════════════════
# CMA-ES（可选，numpy 手写 (μ,λ)-ES；致敬原版进化路线，不引第三方库）
# ══════════════════════════════════════════════════════════════════════════
def cmaes_finetune(
    W0: np.ndarray, X: np.ndarray, Y: np.ndarray, M: np.ndarray, w: np.ndarray, *,
    generations: int = 8, lam: int = 16, mu: int = 8, sigma: float = 0.02, seed: int = 0,
) -> np.ndarray:
    """在 Adam 结果 W0 上做几代 (μ,λ)-ES 微调：每代采样 λ 个扰动、选 top-μ 求均值当新中心。

    极简版（非完整 CMA 协方差自适应，只做 rank-μ 均值更新 + 步长常数）——目的是"致敬 + 兜底
    微调"，不追求 SOTA。适应度 = 负 masked-KL（越小越好 → fitness 越大）。
    """
    rng = np.random.default_rng(seed)
    center = W0.astype(np.float64).copy()
    shape = center.shape

    def fitness(Wc: np.ndarray) -> float:
        loss, _ = _masked_kl_and_grad(Wc, X, Y, M, w)
        return -loss

    best = center.copy()
    best_fit = fitness(center)
    for _ in range(generations):
        samples = [center + sigma * rng.standard_normal(shape) for _ in range(lam)]
        scored = sorted(samples, key=fitness, reverse=True)[:mu]
        center = np.mean(scored, axis=0)
        f = fitness(center)
        if f > best_fit:
            best_fit = f
            best = center.copy()
    return best


# ══════════════════════════════════════════════════════════════════════════
# 评估：val top-1 命中率 vs「always-最高均分模型」基线
# ══════════════════════════════════════════════════════════════════════════
def _best_model_per_sample(Y: np.ndarray, M: np.ndarray) -> np.ndarray:
    """每题的"真最优模型"下标 = mask 位里软目标最大者（-1 表示该题无出现模型）。"""
    masked = np.where(M > 0, Y, -np.inf)
    out = masked.argmax(axis=1)
    out[np.isneginf(masked).all(axis=1)] = -1
    return out


def evaluate(
    W: np.ndarray, X: np.ndarray, Y: np.ndarray, M: np.ndarray, model_ids: list[str], global_best: int
) -> dict[str, Any]:
    """val top-1：预测（只在该题出现过的模型里 argmax）命中该题真最优的比例；对比全局基线。"""
    logits = X @ W.T
    pred_masked = np.where(M > 0, logits, -np.inf)
    pred = pred_masked.argmax(axis=1)
    truth = _best_model_per_sample(Y, M)
    valid = truth >= 0
    if valid.sum() == 0:
        return {"n": 0, "top1": 0.0, "baseline_top1": 0.0}
    top1 = float((pred[valid] == truth[valid]).mean())
    # 基线：永远选"全局最高均分模型" global_best（若该题它没出现，算未命中）。
    base_hit = ((truth[valid] == global_best) & (M[valid, global_best] > 0)).mean()
    return {"n": int(valid.sum()), "top1": round(top1, 4), "baseline_top1": round(float(base_hit), 4)}


def _global_best_model(samples: list[Sample], model_ids: list[str]) -> int:
    """全局"最高均分模型"下标：跨全体样本对每个模型的平均 correct 最大者（基线用）。"""
    n = len(model_ids)
    acc = np.zeros(n)
    cnt = np.zeros(n)
    for s in samples:
        for j, m in enumerate(model_ids):
            if m in s.targets:
                acc[j] += s.targets[m]
                cnt[j] += 1
    mean = np.where(cnt > 0, acc / np.maximum(cnt, 1), -1.0)
    return int(mean.argmax())


# ══════════════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════════════
def _make_mock_dataset(out: Path, seed: int = 0) -> None:
    """`--mock` 且数据集不存在时，合成一个小 jsonl，让管线独立于真数据也能跑通产物。

    造 3 个模型 × 4 kind × 3 题的确定性偏好（不同模型在不同 kind 上强弱不同），带一条战绩伪样本。
    """
    rng = np.random.default_rng(seed)
    models = ["mockCheapA", "mockPremB", "mockPremC"]
    kinds = ["chat", "code", "reason", "long"]
    # 每 (model,kind) 的"真实擅长度"，让数据有可学的结构。
    skill = {
        ("mockCheapA", "chat"): 0.9, ("mockCheapA", "code"): 0.4, ("mockCheapA", "reason"): 0.3, ("mockCheapA", "long"): 0.5,
        ("mockPremB", "chat"): 0.6, ("mockPremB", "code"): 0.9, ("mockPremB", "reason"): 0.7, ("mockPremB", "long"): 0.6,
        ("mockPremC", "chat"): 0.5, ("mockPremC", "code"): 0.7, ("mockPremC", "reason"): 0.9, ("mockPremC", "long"): 0.8,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    # 每 kind 多造几题（让 9:1 划分后 val 有多题，能体现"按 kind 选对模型"而非仅跑通管线）；
    # 每题对每模型重复采样几次（correct 均值更稳，软标签更贴近真实擅长度）。
    with out.open("w", encoding="utf-8") as f:
        for kind in kinds:
            for qi in range(8):
                q = f"[mock-{kind}-{qi}] 这是用于冒烟测试的 {kind} 题目 {qi}"
                for m in models:
                    p = skill[(m, kind)]
                    for _ in range(3):  # 同 (题,模型) 多评几次 → 组内均值稳
                        correct = int(rng.random() < p)
                        f.write(json.dumps(
                            {"q": q, "kind": kind, "model": m, "correct": correct, "weight": 1.0},
                            ensure_ascii=False) + "\n")
        # 一条战绩伪样本（低权重）
        f.write(json.dumps(
            {"q": "[scoreboard:code]", "kind": "code", "model": "mockPremB",
             "correct": 0.85, "weight": 0.3, "source": "scoreboard"}, ensure_ascii=False) + "\n")


def run(args: argparse.Namespace) -> int:
    t0 = time.time()
    dataset = Path(args.dataset)

    # --mock 且用的是**默认真数据集路径** → 改用独立的 .mock.jsonl，绝不占用/污染真数据集
    # （机主真跑 build_routing_dataset.py 写的 routing_dataset.jsonl 断点续跑不被 mock 行搅乱）。
    if args.mock and dataset == _DATASET:
        dataset = _DATA_DIR / "routing_dataset.mock.jsonl"
    if args.mock and not dataset.exists():
        print(f"[train] --mock 且数据集不存在 → 合成冒烟数据到 {dataset}")
        _make_mock_dataset(dataset)

    rows = _load_rows(dataset)
    if not rows:
        print(f"[train] 数据集为空或不存在：{dataset}（真训前请先跑 build_routing_dataset.py）")
        return 2

    samples, model_ids = build_samples(rows)
    if len(model_ids) < 2:
        print(f"[train] 模型种类不足（{len(model_ids)}）——至少需要 2 个模型才能学“派谁”。")
        return 2
    print(f"[train] 样本 {len(samples)} 题 · 模型 {len(model_ids)} 个：{', '.join(model_ids)}")

    # ── 特征 ──
    texts = [s.text for s in samples]
    if args.mock:
        X = mock_features(texts, _MOCK_HIDDEN)
        hidden_dim = _MOCK_HIDDEN
        backbone_name = f"mock({_MOCK_HIDDEN})"
        layer = 0
    else:
        X, hidden_dim = backbone_features(texts, args.backbone, _SECOND_TO_LAST)
        backbone_name = args.backbone
        layer = _SECOND_TO_LAST

    # ── 软标签 + mask + 权重 ──
    n = len(model_ids)
    Y = np.zeros((len(samples), n), dtype=np.float64)
    M = np.zeros((len(samples), n), dtype=np.float64)
    w = np.zeros(len(samples), dtype=np.float64)
    for i, s in enumerate(samples):
        y, mask = soft_label(s.targets, model_ids, args.tau)
        Y[i] = y
        M[i] = mask
        w[i] = s.weight

    # ── train/val 9:1（确定性划分）──
    rng = np.random.default_rng(args.seed)
    perm = rng.permutation(len(samples))
    n_val = max(1, int(round(len(samples) * 0.1)))
    val_idx = np.sort(perm[:n_val])

    # ── Adam 训头 ──
    W = train_head(X.astype(np.float64), Y, M, w,
                   epochs=args.epochs, lr=args.lr, patience=args.patience,
                   seed=args.seed, val_idx=val_idx)

    # ── 可选 CMA-ES 微调（在训练子集上）──
    if args.cmaes:
        tr_idx = np.setdiff1d(np.arange(len(samples)), val_idx)
        print("[train] CMA-ES 微调（numpy 手写 (μ,λ)-ES）…")
        W = cmaes_finetune(W, X[tr_idx].astype(np.float64), Y[tr_idx], M[tr_idx], w[tr_idx],
                           seed=args.seed)

    # ── 评估：val top-1 vs 全局基线 ──
    global_best = _global_best_model(samples, model_ids)
    metrics = evaluate(W, X[val_idx].astype(np.float64), Y[val_idx], M[val_idx], model_ids, global_best)
    elapsed = round(time.time() - t0, 2)
    print(f"[train] val(n={metrics['n']}) top-1={metrics['top1']:.1%} "
          f"vs 基线(always-{model_ids[global_best]})={metrics['baseline_top1']:.1%} · 用时 {elapsed}s")
    if metrics["top1"] < metrics["baseline_top1"]:
        print("[train] 注意 top-1 未超过“永远选最高均分模型”基线——数据太少或信号弱，如实记录（不粉饰）。")

    # ── 落盘产物 ──
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_dir / "head.npy", W.astype(np.float32))
    config = {
        "model_ids": model_ids,          # head 行顺序（推理侧据此对齐）
        "backbone": backbone_name,
        "hidden_dim": int(hidden_dim),
        "layer": int(layer),             # 取的 hidden state 层号（倒数第二层=-2）
        "temperature": float(args.tau),
        "confidence_floor": _CONFIDENCE_FLOOR,
        "input_format": "kind: {kind}\nuser: {q}\n",
        "mock": bool(args.mock),
        "cmaes": bool(args.cmaes),
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "train_seconds": elapsed,
        "n_samples": len(samples),
        "val": metrics,
    }
    (out_dir / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[train] 已保存：{out_dir/'head.npy'}（{W.shape}）+ {out_dir/'config.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="FUGU 批8② 训练神经点将（冻结 backbone + 线性头）")
    p.add_argument("--dataset", default=str(_DATASET), help="jsonl 数据集路径")
    p.add_argument("--out", default=str(_OUT_DIR), help="产物目录（head.npy + config.json）")
    p.add_argument("--backbone", default=_DEFAULT_BACKBONE, help="backbone 模型（默认 Qwen/Qwen3-0.6B）")
    p.add_argument("--tau", type=float, default=0.5, help="软标签 temperature（越小越尖锐）")
    p.add_argument("--epochs", type=int, default=400, help="Adam 最大轮数")
    p.add_argument("--lr", type=float, default=0.05, help="Adam 学习率")
    p.add_argument("--patience", type=int, default=40, help="早停耐心（验证 loss 不降的轮数）")
    p.add_argument("--seed", type=int, default=0, help="随机种子（划分/初始化/mock 特征）")
    p.add_argument("--mock", action="store_true", help="跳过 backbone，用 hash 随机特征秒级跑通管线")
    p.add_argument("--cmaes", action="store_true", help="在 Adam 结果上再做 numpy 手写 CMA-ES 微调")
    args = p.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
