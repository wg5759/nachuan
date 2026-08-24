"""本地 embedder：blob 往返 / 融合 / 余弦 / 禁用降级——纯单元，不加载模型。"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

np = pytest.importorskip(
    "numpy", reason="本地向量实验测试需 `uv sync --locked --extra savers`"
)

from orchestrator import embedder as emb


def test_blob_roundtrip():
    v = np.arange(emb.EMBED_DIM, dtype="float32")
    back = emb.from_blob(emb.to_blob(v))
    assert back is not None and back.shape[0] == emb.EMBED_DIM
    assert np.allclose(back, v)
    assert emb.from_blob(None) is None  # 空 → None
    assert emb.from_blob(b"short") is None  # 长度不对的坏数据 → None（不抛）


def test_fuse():
    assert emb.fuse(0.8, None) == 0.8  # 无向量分（降级）→ 纯关键词
    assert abs(emb.fuse(0.6, 0.4) - 0.5) < 1e-9  # 0.5*0.6 + 0.5*0.4
    assert abs(emb.fuse(0.0, 1.0) - 0.5) < 1e-9


def test_cosine_blobs():
    q = np.zeros(emb.EMBED_DIM, dtype="float32")
    q[0] = 1.0
    assert emb.cosine_blobs(q, emb.to_blob(q)) == 1.0  # 同向 → 1
    o = np.zeros(emb.EMBED_DIM, dtype="float32")
    o[1] = 1.0
    assert emb.cosine_blobs(q, emb.to_blob(o)) == 0.0  # 正交 → 0
    assert emb.cosine_blobs(None, emb.to_blob(q)) is None  # 降级
    assert emb.cosine_blobs(q, None) is None


def test_encode_disabled_degrades():
    """conftest 设了 NACHUAN_EMBED_DISABLED=1 → 编码降级返回 None，绝不加载/下载模型。"""
    assert emb.encode("任意文本") is None
    assert emb.encode(["批量", "文本"]) is None
    assert emb.encode_query("查询") is None
    assert emb.available() is False


def test_ready_starts_only_one_background_load(monkeypatch):
    instance = emb._Embedder()
    started = 0

    class FakeThread:
        def __init__(self, *, target, daemon):
            assert daemon is True
            self._target = target

        def start(self):
            nonlocal started
            started += 1

    monkeypatch.setattr(emb, "threading", SimpleNamespace(Thread=FakeThread))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _idx: instance._ready(), range(32)))
    assert results == [False] * 32
    assert started == 1
