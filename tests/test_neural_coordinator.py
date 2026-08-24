"""FUGU 批8④ · 神经点将 pick_neural 单测（全 mock，绝不真下 Qwen3-0.6B）。

手法：
- 用 tmp_path 写一份最小 `head.npy` + `config.json`，monkeypatch `neural_coordinator._model_dir`
  指过去；每个用例前 `reset()` 清单例，互不污染。
- monkeypatch `neural_coordinator._encode` 注入**确定性假特征**（不加载 transformers/backbone）。
- monkeypatch `orchestrator.coordinator.pool_snapshot` 控制"当前在线池"（含 flagship/tool_capable）。

覆盖：无目录→None；正常命中；置信不足→None；need_tools 过滤；flagship 排除；
在线但不在训练列表不参与；坏 config→None；backbone 不可用→None；候选与训练列表无交集→None。
外加 `train_coordinator.py --mock` 函数级跑通断言产物生成。
"""

from __future__ import annotations

import json

import pytest

np = pytest.importorskip(
    "numpy", reason="神经点将实验测试需 `uv sync --locked --extra savers`"
)

import orchestrator.coordinator as co
import orchestrator.neural_coordinator as nc

# 训练列表固定 3 个模型（head 行顺序 = 此顺序）；hidden=4 的极小头，便于手工构造可预测的胜出。
_MODEL_IDS = ["cheapA", "premB", "premC"]
_HIDDEN = 4


def _write_artifacts(tmp_path, head: np.ndarray, *, model_ids=None, hidden=_HIDDEN,
                     confidence_floor=0.35, layer=-2, backbone="Qwen/Qwen3-0.6B",
                     extra_config=None, bad_config=False, mock=False):
    """在 tmp_path 写 head.npy + config.json，返回目录 Path。bad_config=True 写坏 JSON。

    默认 mock=False（模拟"真训产物"，会被推理侧加载）；mock=True 用于测"mock 产物被生产拒绝"。
    """
    d = tmp_path / "coordinator"
    d.mkdir(parents=True, exist_ok=True)
    np.save(d / "head.npy", head.astype(np.float32))
    if bad_config:
        (d / "config.json").write_text("{ this is not valid json ", encoding="utf-8")
        return d
    cfg = {
        "model_ids": model_ids or _MODEL_IDS,
        "backbone": backbone,
        "hidden_dim": hidden,
        "layer": layer,
        "temperature": 0.5,
        "confidence_floor": confidence_floor,
        "input_format": "kind: {kind}\nuser: {q}\n",
        "mock": mock,
    }
    if extra_config:
        cfg.update(extra_config)
    (d / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    return d


def _use_dir(monkeypatch, d):
    """把 neural_coordinator 的产物目录指到 d，并清单例。"""
    monkeypatch.setattr(nc, "_model_dir", lambda: d)
    nc.reset()


def _patch_encode(monkeypatch, h):
    """让 _encode 返回固定假特征 h（不碰 backbone）。"""
    monkeypatch.setattr(nc, "_encode", lambda text: np.asarray(h, dtype=np.float64))


def _patch_pool(monkeypatch, snapshot):
    """控制'当前在线池'（pick_neural 内部经 coordinator.pool_snapshot 取）。"""
    monkeypatch.setattr(co, "pool_snapshot", lambda router, task_kind="general": [dict(e) for e in snapshot])


class _Router:  # pick_neural 只把 router 透传给 pool_snapshot（已被 mock），本身不被触碰
    pass


def _snap(*models, flagship=(), no_tools=()):
    """便捷构造在线池快照：每个 model 一条，flagship/no_tools 里的置对应标志。"""
    out = []
    for m in models:
        out.append({
            "model": m,
            "flagship": m in flagship,
            "tool_capable": m not in no_tools,
        })
    return out


# 一个让 "premB"（下标1）明显胜出的 head+特征组合：
# head 行 = 各模型的权重向量；特征 h=[1,0,0,0] → logit = head[:,0]。令 premB 的第0维最大。
_HEAD_PREM_B = np.array([
    [0.1, 0.0, 0.0, 0.0],   # cheapA
    [5.0, 0.0, 0.0, 0.0],   # premB  ← 第0维最大 → h=[1,0,0,0] 时 logit 最高
    [0.2, 0.0, 0.0, 0.0],   # premC
], dtype=np.float64)
_FEAT = [1.0, 0.0, 0.0, 0.0]


# ────────────────────────────── 无目录 / 坏产物 → None ──────────────────────────────
def test_none_when_dir_missing(monkeypatch, tmp_path):
    """models/coordinator 不存在 → 永远 None（组件缺失=静默不启用）。"""
    _use_dir(monkeypatch, tmp_path / "coordinator")  # 未创建
    _patch_pool(monkeypatch, _snap("cheapA", "premB"))
    assert nc.pick_neural(_Router(), "user: 写个爬虫\n", task_kind="code") is None


def test_none_when_bad_config(monkeypatch, tmp_path):
    """config.json 损坏（非法 JSON）→ None。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, bad_config=True)
    _use_dir(monkeypatch, d)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


def test_none_when_head_shape_mismatch(monkeypatch, tmp_path):
    """head 形状与 config(model_ids×hidden) 不符 → None（防加载到错配产物）。"""
    bad_head = np.zeros((2, _HIDDEN), dtype=np.float64)  # 只有 2 行，但 config 声明 3 个模型
    d = _write_artifacts(tmp_path, bad_head)
    _use_dir(monkeypatch, d)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


def test_none_when_mock_artifact(monkeypatch, tmp_path):
    """config 标 mock=true 的冒烟产物 → 生产拒绝加载（避免用假 backbone 名去点将）→ None。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, mock=True)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True) is None


# ────────────────────────────── 正常命中 ──────────────────────────────
def test_hit_returns_neural_pick(monkeypatch, tmp_path):
    """三模型都在线、都非王牌、都可调工具 → 神经头选 logit 最高的 premB，带 by=neural。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    out = nc.pick_neural(_Router(), "user: 实现一个复杂功能\n", task_kind="code", need_tools=True)
    assert out == {"model": "premB", "role": "worker", "instruction": "", "by": "neural"}


# ────────────────────────────── 置信不足 → None ──────────────────────────────
def test_none_when_confidence_below_floor(monkeypatch, tmp_path):
    """三模型 logit 几乎相等（softmax≈1/3 < floor 0.35）→ 不够自信 → None（退回下一级）。"""
    flat = np.array([[1.0, 0, 0, 0], [1.0, 0, 0, 0], [1.0, 0, 0, 0]], dtype=np.float64)
    d = _write_artifacts(tmp_path, flat, confidence_floor=0.35)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)   # 三者 logit 全相等 → 每个 prob≈0.333
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True) is None


def test_hit_when_floor_low_enough(monkeypatch, tmp_path):
    """把 floor 调到很低 → 即便分差不大也命中（验证 floor 阈值真正生效，不是恒 None）。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, confidence_floor=0.05)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    out = nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True)
    assert out is not None and out["model"] == "premB"


# ────────────────────────────── need_tools 过滤 ──────────────────────────────
def test_need_tools_excludes_incapable_winner(monkeypatch, tmp_path):
    """need_tools=True 时，logit 最高的 premB 若不可调工具 → 被排除，选次高的可调工具模型。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, confidence_floor=0.05)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    # premB 不可调工具 → 候选只剩 cheapA(0.1)/premC(0.2)，premC logit 更高 → 选 premC。
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC", no_tools=("premB",)))
    out = nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True)
    assert out is not None and out["model"] == "premC"


def test_need_tools_false_keeps_incapable_winner(monkeypatch, tmp_path):
    """need_tools=False 时不做工具过滤 → 即便 premB 不可调工具，纯思考仍可选它。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, confidence_floor=0.05)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC", no_tools=("premB",)))
    out = nc.pick_neural(_Router(), "x", task_kind="code", need_tools=False)
    assert out is not None and out["model"] == "premB"


# ────────────────────────────── flagship 排除 ──────────────────────────────
def test_flagship_excluded(monkeypatch, tmp_path):
    """logit 最高的 premB 是王牌 → 排除（自动路由不烧王牌），选非王牌里最高的 premC。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, confidence_floor=0.05)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC", flagship=("premB",)))
    out = nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True)
    assert out is not None and out["model"] == "premC"


# ────────────────────────────── 在线但不在训练列表 → 不参与 ──────────────────────────────
def test_online_model_not_in_training_list_ignored(monkeypatch, tmp_path):
    """池里有个训练时没见过的新模型（logit 无从算）→ 不参与比分；只在训练列表∩在线里选。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B, confidence_floor=0.05)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    # premB/premC 在训练列表；newX 不在 → 忽略 newX，仍在 premB/premC 里选 premB。
    _patch_pool(monkeypatch, _snap("newX", "premB", "premC"))
    out = nc.pick_neural(_Router(), "x", task_kind="code", need_tools=True)
    assert out is not None and out["model"] == "premB"


def test_none_when_no_overlap_with_pool(monkeypatch, tmp_path):
    """训练列表与当前在线池毫无交集 → None（交给下一级点将）。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, _snap("totallyOther1", "totallyOther2"))
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


def test_none_when_empty_pool(monkeypatch, tmp_path):
    """空在线池 → None。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)
    _patch_pool(monkeypatch, [])
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


# ────────────────────────────── backbone 不可用 → None ──────────────────────────────
def test_none_when_backbone_unavailable(monkeypatch, tmp_path):
    """_encode 返回 None（打包版无 transformers / 下载失败）→ None，不硬选。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    monkeypatch.setattr(nc, "_encode", lambda text: None)  # backbone 不可用
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


def test_none_when_feature_dim_mismatch(monkeypatch, tmp_path):
    """_encode 返回的特征维度与 head 列数不符 → None（防错配 backbone）。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    monkeypatch.setattr(nc, "_encode", lambda text: np.zeros(_HIDDEN + 3, dtype=np.float64))  # 维度错
    _patch_pool(monkeypatch, _snap("cheapA", "premB", "premC"))
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


# ────────────────────────────── 加载只发生一次 / reset 生效 ──────────────────────────────
def test_pick_neural_survives_pool_exception(monkeypatch, tmp_path):
    """pool_snapshot 抛异常 → 吞掉返回 None（神经点将坏了绝不挡任务）。"""
    d = _write_artifacts(tmp_path, _HEAD_PREM_B)
    _use_dir(monkeypatch, d)
    _patch_encode(monkeypatch, _FEAT)

    def boom(router, task_kind="general"):
        raise RuntimeError("snapshot down")

    monkeypatch.setattr(co, "pool_snapshot", boom)
    assert nc.pick_neural(_Router(), "x", task_kind="code") is None


# ══════════════════════════ train_coordinator --mock 跑通产物 ══════════════════════════
def test_train_coordinator_mock_produces_artifacts(tmp_path):
    """train/train_coordinator.py --mock 函数级跑通：合成数据→训头→出 head.npy + config.json。"""
    import argparse

    from train import train_coordinator as tc

    ds = tmp_path / "mock.jsonl"
    out = tmp_path / "coord"
    args = argparse.Namespace(
        dataset=str(ds), out=str(out), backbone="Qwen/Qwen3-0.6B",
        tau=0.5, epochs=100, lr=0.05, patience=20, seed=0, mock=True, cmaes=False,
    )
    rc = tc.run(args)
    assert rc == 0
    assert (out / "head.npy").exists()
    assert (out / "config.json").exists()
    cfg = json.loads((out / "config.json").read_text(encoding="utf-8"))
    assert cfg["mock"] is True
    assert len(cfg["model_ids"]) >= 2
    W = np.load(out / "head.npy")
    assert W.shape == (len(cfg["model_ids"]), cfg["hidden_dim"])
    # 端到端契约：训练产物的结构（model_ids/hidden_dim/head 形状）能被推理侧加载器读入。
    # mock 产物生产会被拒（config.mock=true），故先把标志改成 false 再验证纯结构契约。
    cfg_prod = dict(cfg)
    cfg_prod["mock"] = False
    (out / "config.json").write_text(json.dumps(cfg_prod, ensure_ascii=False), encoding="utf-8")
    original = nc._model_dir
    try:
        nc._model_dir = lambda: out  # 指到刚训出的产物目录
        nc.reset()
        assert nc._ensure_loaded() is True
        assert nc._config is not None and nc._config["model_ids"] == cfg["model_ids"]
    finally:
        nc._model_dir = original
        nc.reset()


def test_train_coordinator_mock_with_cmaes(tmp_path):
    """--cmaes 分支也能跑通出产物（numpy 手写 ES，不引第三方库）。"""
    import argparse

    from train import train_coordinator as tc

    ds = tmp_path / "mock_es.jsonl"
    out = tmp_path / "coord_es"
    args = argparse.Namespace(
        dataset=str(ds), out=str(out), backbone="Qwen/Qwen3-0.6B",
        tau=0.5, epochs=80, lr=0.05, patience=20, seed=1, mock=True, cmaes=True,
    )
    assert tc.run(args) == 0
    cfg = json.loads((out / "config.json").read_text(encoding="utf-8"))
    assert cfg["cmaes"] is True
