"""意图分类（#17 #15）：关键词兜底规则 + prefilter 短路（纯聊天不调模型）。"""

from __future__ import annotations

import asyncio

from orchestrator.intent import INTENTS, _fallback_rule, classify_intent


def test_fallback_rule_covers_main_intents():
    assert _fallback_rule("画一只赛博朋克的猫") == "image"
    assert _fallback_rule("翻译成英文：你好") == "translate"
    assert _fallback_rule("根据我的知识库回答定价") == "kb"
    assert _fallback_rule("做个多镜头短视频") == "studio"
    assert _fallback_rule("https://v.douyin.com/abc 帮我拉片拆解") == "lapian"
    # 普通聊天 / 成语提问 → chat（不误触发昂贵操作）
    assert _fallback_rule("画饼充饥是什么意思") == "chat"
    assert _fallback_rule("你好你是谁") == "chat"
    assert _fallback_rule("") == "chat"


def test_fallback_rule_codex_review_fixes():
    """Codex 互审揪出的回归：海报/logo 生图、能力提问别误判、光提知识库不算查库。"""
    # #1 海报/logo/图 + 生成 → image（补回旧检测器广度）
    assert _fallback_rule("生成一张海报") == "image"
    assert _fallback_rule("帮我做个 logo") == "image"
    # #2 能力提问别误当成生成
    assert _fallback_rule("你能做视频吗") == "chat"
    assert _fallback_rule("怎么画一只猫") == "chat"
    # #3 光提"知识库"不算查库；真带"据…文档"才算
    assert _fallback_rule("知识库是什么") == "chat"
    assert _fallback_rule("怎么搭建知识库") == "chat"
    assert _fallback_rule("根据我的文档回答") == "kb"


class _BoomRouter:
    """任何调用都炸——用来验证 classify_intent 绝不把异常抛给调用方。"""

    def resolve(self, _model):  # noqa: ANN001
        raise RuntimeError("boom")


def test_prefilter_short_circuits_plain_chat():
    """prefilter=True 且关键词看不出意图 → 直接 chat，不碰 router（不调模型）。"""
    out = asyncio.run(classify_intent(_BoomRouter(), "你好今天天气不错", prefilter=True))
    assert out == "chat"


def test_classify_never_raises_falls_back_to_rule():
    """模型不可用（router 炸）时回退关键词规则，绝不抛异常。"""
    out = asyncio.run(classify_intent(_BoomRouter(), "翻译成英文：hello", prefilter=False))
    assert out == "translate"  # 模型炸了 → 回退规则命中 translate


def test_intents_set_stable():
    assert "chat" in INTENTS and "image" in INTENTS and "kb" in INTENTS
