"""服务端持久化滚动摘要：短对话原样 / 长对话增量折叠+跨请求累积 / 编辑重置 / 清除。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import orchestrator.conv_summary as cs


@pytest.fixture(autouse=True)
def _isolate_db(monkeypatch, tmp_path):
    db = tmp_path / "conv_summary.db"
    monkeypatch.setattr(cs, "_db_path", lambda: str(db))
    cs.reset()
    yield
    cs.reset()


class _Router:
    def resolve(self, model):
        return SimpleNamespace(provider=None) if model == "agnes-flash" else None

    def routes_info(self):
        return [{"model": "agnes-flash", "tier": "cheap", "provider": "p", "rank": 1, "flagship": False}]


def _patch_summary(monkeypatch, seq=None):
    """让摘要调用按序列返回；seq 用尽后重复最后一个。记录调用次数。"""
    calls = {"n": 0}
    outs = seq or ["主线v1"]

    async def fake_chat(router, req):
        i = min(calls["n"], len(outs) - 1)
        calls["n"] += 1
        return ({"choices": [{"message": {"content": outs[i]}}]}, req.model, None)

    import gateway.failover as fo
    monkeypatch.setattr(fo, "chat_with_fallback", fake_chat)
    return calls


def _long(n, tag="x"):
    return [{"role": "user" if i % 2 == 0 else "assistant", "content": f"{tag}{i}" + "填" * 200}
            for i in range(n)]


async def test_no_conv_id_falls_back_stateless(monkeypatch):
    """无 conv_id → 走无状态 compress_history（不报错，长的也能压）。"""
    _patch_summary(monkeypatch)
    out = await cs.rolling_compress(_Router(), "", _long(40))
    assert out and out[0]["role"] == "system"  # 无状态压缩也产出摘要头


async def test_short_conversation_unchanged(monkeypatch):
    calls = _patch_summary(monkeypatch)
    hist = [{"role": "user", "content": "你好"}, {"role": "assistant", "content": "在"}]
    out = await cs.rolling_compress(_Router(), "c1", hist)
    assert out == hist and calls["n"] == 0


async def test_rolling_accumulates_across_requests(monkeypatch):
    """跨请求累积：第一次折叠出摘要v1并持久化；第二次带更多历史→在v1基础上折叠出v2。"""
    calls = _patch_summary(monkeypatch, ["主线v1", "主线v2"])
    r = _Router()
    # 第一次：40 条 → 折叠前 32 条，保留最近 8
    out1 = await cs.rolling_compress(r, "c1", _long(40), keep_recent=8)
    assert out1[0]["content"].endswith("主线v1") or "主线v1" in out1[0]["content"]
    assert len(out1) == 9  # 1 摘要 + 8 近
    s1, cov1 = cs._get_store().get("c1")
    assert s1 == "主线v1" and cov1 == 32
    # 第二次：现在 60 条（含之前的）→ 在 v1 基础上把新中段折进 → v2
    out2 = await cs.rolling_compress(r, "c1", _long(60), keep_recent=8)
    assert "主线v2" in out2[0]["content"]
    s2, cov2 = cs._get_store().get("c1")
    assert s2 == "主线v2" and cov2 == 52  # 60 - 8
    assert calls["n"] == 2  # 每次请求只折叠一次（增量，不重算全部）


async def test_edited_history_resets(monkeypatch):
    """前端把历史裁短了（covered > len）→ 重置成无状态，不用错位的旧 covered。"""
    _patch_summary(monkeypatch, ["主线v1"])
    r = _Router()
    await cs.rolling_compress(r, "c1", _long(40), keep_recent=8)  # covered=32
    # 现在只发来 5 条（用户清空重开或裁剪）→ 不该用 covered=32 索引
    out = await cs.rolling_compress(r, "c1", _long(5), keep_recent=8)
    assert out == _long(5)  # 短 + 重置 → 原样


async def test_clear_removes_summary(monkeypatch):
    _patch_summary(monkeypatch, ["主线v1"])
    r = _Router()
    await cs.rolling_compress(r, "c1", _long(40))
    assert cs._get_store().get("c1")[0] == "主线v1"
    cs.clear("c1")
    assert cs._get_store().get("c1") == ("", 0)


async def test_summary_failure_keeps_previous(monkeypatch):
    """折叠调用失败 → 保留已有摘要、不推进 covered（不丢已攒的主线）。"""
    # 先攒一版
    _patch_summary(monkeypatch, ["主线v1"])
    r = _Router()
    await cs.rolling_compress(r, "c1", _long(40), keep_recent=8)

    async def boom(router, req):
        raise RuntimeError("挂了")

    import gateway.failover as fo
    monkeypatch.setattr(fo, "chat_with_fallback", boom)
    out = await cs.rolling_compress(r, "c1", _long(60), keep_recent=8)
    s, cov = cs._get_store().get("c1")
    assert s == "主线v1" and cov == 32  # 没推进，旧摘要保住
    assert out[0]["content"].endswith("主线v1") or "主线v1" in out[0]["content"]
