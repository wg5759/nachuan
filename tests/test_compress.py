"""LLMLingua-2 ONNX 压缩器测试。

纯算法（聚合/选词/重建）用合成概率测，不需要模型；降级路径在模型缺失时也稳；
真模型在位（导出过 onnx）时跑一个端到端冒烟（否则自动跳过）。
"""

from __future__ import annotations

import pytest

from orchestrator import compress


@pytest.fixture(autouse=True)
def _reset_state():
    """每个用例前重置加载缓存与开关，避免互相污染。"""
    compress._state.clear()
    compress._state.update(engine=None, failed=False)
    yield
    compress._state.clear()
    compress._state.update(engine=None, failed=False)


# ── 纯算法（不碰模型）──────────────────────────────────────────────────────

def test_aggregate_word_probs_mean_and_order():
    word_ids = [0, 0, 1, 2]
    offsets = [(0, 2), (2, 4), (5, 8), (9, 10)]
    token_probs = [0.4, 0.6, 0.9, 0.1]
    spans, probs = compress._aggregate_word_probs(word_ids, offsets, token_probs)
    assert spans == [(0, 4), (5, 8), (9, 10)]  # 跨度按词合并、保持顺序
    assert probs == pytest.approx([0.5, 0.9, 0.1])  # 子词概率取 mean


def test_aggregate_skips_specials():
    # word_id=None（特殊 token）与零宽跨度都应被跳过
    spans, probs = compress._aggregate_word_probs(
        [None, 0, None], [(0, 0), (0, 3), (3, 3)], [0.9, 0.7, 0.9]
    )
    assert spans == [(0, 3)]
    assert probs == pytest.approx([0.7])


def test_keep_mask_rate_selects_top_fraction():
    probs = [0.9, 0.1, 0.8, 0.2, 0.5]
    keep = compress._keep_mask(probs, rate=0.6)
    assert keep == [True, False, True, False, True]  # 保留概率最高的 ~60%
    assert compress._keep_mask(probs, rate=1.0) == [True] * 5  # rate=1 全保留
    assert compress._keep_mask([], 0.5) == []


def test_rebuild_english_keeps_spaces():
    text = "the quick brown fox"
    spans = [(0, 3), (4, 9), (10, 15), (16, 19)]
    keep = [True, False, True, True]
    assert compress._rebuild(text, spans, keep) == "the brown fox"


def test_rebuild_chinese_no_spaces():
    text = "我爱北京天安门"
    spans = [(i, i + 1) for i in range(len(text))]
    keep = [True, False, True, False, False, False, True]  # 我 北 门
    assert compress._rebuild(text, spans, keep) == "我北门"  # 中文不插空格


def test_rebuild_preserves_newline():
    text = "line one\nline two"
    spans = [(0, 4), (5, 8), (9, 13), (14, 17)]  # line one / line two
    keep = [True, False, True, False]
    assert compress._rebuild(text, spans, keep) == "line\nline"  # 换行优先于空格


def test_compress_core_with_mocked_probs(monkeypatch):
    text = "the quick brown fox jumps"
    word_ids = [0, 1, 2, 3, 4]
    offsets = [(0, 3), (4, 9), (10, 15), (16, 19), (20, 25)]
    probs = [0.9, 0.1, 0.8, 0.2, 0.7]
    monkeypatch.setattr(
        compress, "_token_keep_probs", lambda eng, t: (word_ids, offsets, probs)
    )
    out = compress._compress_core({}, text, rate=0.6, force_tokens=[])
    assert out == "the brown jumps"  # 概率最高的三词、保序


def test_compress_core_force_tokens(monkeypatch):
    text = "the quick brown fox jumps"
    word_ids = [0, 1, 2, 3, 4]
    offsets = [(0, 3), (4, 9), (10, 15), (16, 19), (20, 25)]
    probs = [0.9, 0.1, 0.8, 0.2, 0.7]
    monkeypatch.setattr(
        compress, "_token_keep_probs", lambda eng, t: (word_ids, offsets, probs)
    )
    # quick 概率最低本会被删，force_tokens 指定后强制保留
    out = compress._compress_core({}, text, rate=0.6, force_tokens=["quick"])
    assert "quick" in out


# ── 降级路径（模型不可用也绝不崩、原样返回）──────────────────────────────────

def test_degrades_when_model_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(compress, "MODEL_DIR", str(tmp_path))  # 空目录=无模型
    assert compress.available() is False
    long_text = "保留原文。" * 100  # 超过 MIN_CHARS
    assert compress.compress_text(long_text) == long_text  # 原样返回


def test_disabled_returns_original(monkeypatch):
    monkeypatch.setenv("COMPRESS_ENABLED", "0")
    long_text = "x" * 1000
    assert compress.compress_text(long_text) == long_text


def test_short_text_not_compressed(monkeypatch):
    # 即便模型可用，短于 MIN_CHARS 也不压（这里用 spy 确认没进加载）
    called = {"n": 0}
    monkeypatch.setattr(compress, "_load", lambda: called.__setitem__("n", called["n"] + 1))
    assert compress.compress_text("短文本") == "短文本"
    assert called["n"] == 0


def test_non_string_input_safe():
    assert compress.compress_text("") == ""
    assert compress.compress_text(None) is None  # type: ignore[arg-type]


# ── 端到端冒烟（仅在真模型/onnx 到位时跑，否则跳过）──────────────────────────

def test_end_to_end_if_model_present():
    if not compress.available():
        pytest.skip("LLMLingua-2 onnx 未就绪（先跑 scripts/_export_llmlingua2_onnx.py）")
    text = (
        "The meeting started at nine in the morning. The team discussed the quarterly "
        "budget, reviewed the marketing plan, and agreed to ship the new feature next "
        "week. Several action items were assigned to different members of the group. "
    ) * 2
    stats = compress.compress_stats(text, rate=0.5)
    assert stats["ok"] is True
    assert stats["compressed_tokens"] < stats["origin_tokens"]  # 真的省了 token
    assert stats["compressed"] and len(stats["compressed"]) < len(text)
