"""长对话上下文压缩（滚动摘要）：短的原样 / 长的老对话摘要+近的原样 / 失败降级原样。"""

from __future__ import annotations

from types import SimpleNamespace

import orchestrator.history_compress as hc


class _Router:
    def __init__(self, cheap="agnes-flash"):
        self._cheap = cheap

    def resolve(self, model):
        return SimpleNamespace(provider=None) if model == self._cheap else None

    def routes_info(self):
        return [{"model": self._cheap, "tier": "cheap", "provider": "p", "rank": 1, "flagship": False}]


def _patch_summary(monkeypatch, text="- 已做A\n- 产物在 D:/x\n- 任务B进行中"):
    async def fake_chat(router, req):
        return ({"choices": [{"message": {"content": text}}]}, req.model, None)

    monkeypatch.setattr(hc, "_history_chars", hc._history_chars)  # 保持真实
    import gateway.failover as fo
    monkeypatch.setattr(fo, "chat_with_fallback", fake_chat)


async def test_short_history_unchanged(monkeypatch):
    """短对话（未超阈值）→ 原样返回，0 次摘要调用。"""
    called = {"n": 0}

    async def fake_chat(router, req):
        called["n"] += 1
        return ({"choices": [{"message": {"content": "x"}}]}, req.model, None)

    import gateway.failover as fo
    monkeypatch.setattr(fo, "chat_with_fallback", fake_chat)
    hist = [{"role": "user", "content": "你好"}, {"role": "assistant", "content": "在"}]
    out = await hc.compress_history(_Router(), hist)
    assert out == hist and called["n"] == 0


async def test_long_history_summarized_recent_kept(monkeypatch):
    """长对话 → 老的压成一条 system 摘要，最近 keep_recent 条原样保留。"""
    _patch_summary(monkeypatch)
    # 造 40 轮、每条很长 → 超阈值
    hist = [{"role": "user" if i % 2 == 0 else "assistant", "content": f"第{i}轮内容" + "填充" * 200}
            for i in range(40)]
    out = await hc.compress_history(_Router(), hist, keep_recent=6)
    assert out[0]["role"] == "system" and "主线摘要" in out[0]["content"]
    assert "已做A" in out[0]["content"]  # 摘要内容进去了
    # 最近 6 条原样（内容一致）
    assert [m["content"] for m in out[1:]] == [m["content"] for m in hist[-6:]]
    assert len(out) == 7  # 1 摘要 + 6 近


async def test_summary_failure_falls_back_to_original(monkeypatch):
    """摘要调用抛异常 → 原样返回历史（降级第一，绝不因压缩挡任务）。"""
    async def boom(router, req):
        raise RuntimeError("上游挂了")

    import gateway.failover as fo
    monkeypatch.setattr(fo, "chat_with_fallback", boom)
    hist = [{"role": "user", "content": "长内容" + "x" * 500} for _ in range(40)]
    out = await hc.compress_history(_Router(), hist)
    assert out == hist  # 原样


async def test_no_cheap_model_returns_original(monkeypatch):
    """没有可用便宜模型 → 原样（不升级烧强模型做摘要）。"""
    hist = [{"role": "user", "content": "长内容" + "x" * 500} for _ in range(40)]
    r = _Router(cheap="nonexistent")  # resolve 都返回 None
    # pick_model 也选不到 → 原样
    import orchestrator.modes as modes
    monkeypatch.setattr(modes, "pick_model", lambda router, tier, **kw: None)
    out = await hc.compress_history(r, hist)
    assert out == hist
