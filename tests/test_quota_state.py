"""额度/限流状态 + 兜底链额度感知（路由重构第1步：429标记兜底）。"""

from __future__ import annotations

import math
import threading

import pytest

from gateway import quota_state
from gateway.failover import chat_with_fallback, fallback_chain
from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.schemas import ChatCompletionRequest


def setup_function() -> None:
    quota_state.clear()  # 全局状态，每个测试前清干净


def teardown_function() -> None:
    quota_state.clear()  # 也清干净，别把冷却状态泄漏给别的测试文件（quota_state 是全局单例）


def test_is_quota_error():
    assert quota_state.is_quota_error(ProviderError("x", status_code=429))
    assert quota_state.is_quota_error(ProviderError("x", status_code=402))
    assert quota_state.is_quota_error(ProviderError("套餐余量不足"))  # 关键词兜底
    assert not quota_state.is_quota_error(ProviderError("网络超时", status_code=502))


def test_mark_available_clear():
    assert quota_state.available("glm")
    quota_state.mark_exhausted("glm", retry_after=30)
    assert not quota_state.available("glm")
    assert 0 < quota_state.cooldown_left("glm") <= 30
    assert "glm" in quota_state.snapshot()
    quota_state.clear("glm")
    assert quota_state.available("glm")


def test_cooldown_capped_at_one_hour():
    quota_state.mark_exhausted("glm", retry_after=999999)  # 上游给个离谱值
    assert quota_state.cooldown_left("glm") <= 3600.0  # 封顶 1 小时


def test_error_counter_serializes_concurrent_failures():
    class SlowGetDict(dict):
        def __init__(self):
            super().__init__()
            self._gate = threading.Barrier(2)

        def get(self, key, default=None):  # noqa: ANN001
            observed = super().get(key, default)
            try:
                self._gate.wait(timeout=0.1)
            except threading.BrokenBarrierError:
                pass
            return observed

    original = quota_state._err_count
    quota_state._err_count = SlowGetDict()
    start = threading.Barrier(3)

    def fail() -> None:
        start.wait()
        quota_state.mark_error("concurrent-model")

    workers = [threading.Thread(target=fail) for _ in range(2)]
    try:
        for worker in workers:
            worker.start()
        start.wait()
        for worker in workers:
            worker.join(timeout=1.0)

        assert all(not worker.is_alive() for worker in workers)
        assert not quota_state.available("concurrent-model")
    finally:
        quota_state._err_count = original
        quota_state.clear()


def test_quota_state_uses_monotonic_clock(monkeypatch):
    monkeypatch.setattr(
        quota_state.time,
        "time",
        lambda: (_ for _ in ()).throw(AssertionError("wall clock used")),
    )
    ticks = iter((100.0, 101.0, 101.0, 101.0))
    monkeypatch.setattr(quota_state.time, "monotonic", lambda: next(ticks))

    quota_state.mark_exhausted("glm", retry_after=30)
    assert not quota_state.available("glm")
    assert math.isclose(quota_state.cooldown_left("glm"), 29.0)


def test_quota_state_bounds_distinct_model_identities(monkeypatch):
    monkeypatch.setattr(quota_state, "_MAX_TRACKED_MODELS", 2)
    now = [1000.0]
    monkeypatch.setattr(quota_state.time, "monotonic", lambda: now[0])

    quota_state.mark_error("m1")
    quota_state.mark_error("m2")
    quota_state.mark_error("m3")

    assert len(set(quota_state._err_count) | set(quota_state._cooldown)) <= 2
    assert not quota_state.available("m3")  # capacity exhaustion fails closed

    now[0] += quota_state._ERR_COUNT_TTL + 0.1
    assert quota_state.available("m3")  # abandoned one-error identities age out


def test_non_finite_retry_after_falls_back_to_default():
    quota_state.mark_exhausted("glm", retry_after=float("nan"))

    left = quota_state.cooldown_left("glm")
    assert math.isfinite(left)
    assert 0 < left <= quota_state._DEFAULT_COOLDOWN


def test_fallback_chain_moves_exhausted_last():
    quota_state.mark_exhausted("glm")  # glm 冷却中
    chain = fallback_chain("glm")  # 原链: glm → gpt-5.4 → agnes-flash
    assert chain[-1] == "glm"  # 冷却的挪到最后
    assert chain[0] != "glm"  # 优先试还有额度的


class _Prov:
    def __init__(self, code: int):
        self.code = code

    async def chat(self, req, up):  # noqa: ANN001
        if self.code:
            raise ProviderError("超额", status_code=self.code)
        return {"choices": [{"message": {"content": "ok"}}]}


class _Route:
    def __init__(self, prov: _Prov):
        self.provider = prov
        self.upstream_model = "u"


class _Router:
    """glm → 429；其它模型正常。"""

    def __init__(self):
        self.resolved: list[str] = []

    def resolve(self, mid: str):  # noqa: ANN001
        self.resolved.append(mid)
        return _Route(_Prov(429 if mid == "glm" else 0))


async def test_chat_with_fallback_marks_429_and_stops_without_replay():
    req = ChatCompletionRequest(model="glm", messages=[{"role": "user", "content": "hi"}])
    router = _Router()

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(router, req)

    assert router.resolved == ["glm"]  # 429 不能证明未提交，禁止自动执行备用模型
    assert not quota_state.available("glm")  # glm 被标记冷却，下次直接跳过


class _InfoRouter:
    """两个同档 premium 模型，供测选模型时跳过冷却的。"""

    def routes_info(self):
        return [
            {"model": "strong-a", "tier": "premium", "rank": 1, "flagship": False},
            {"model": "strong-b", "tier": "premium", "rank": 2, "flagship": False},
        ]


def test_pick_model_skips_exhausted():
    from orchestrator.modes import pick_model

    r = _InfoRouter()
    assert pick_model(r, "premium") == "strong-a"  # rank1 优先
    quota_state.mark_exhausted("strong-a")  # strong-a 额度冷却
    assert pick_model(r, "premium") == "strong-b"  # → 选还有额度的 strong-b
    quota_state.mark_exhausted("strong-b")  # 全冷却
    assert pick_model(r, "premium") in ("strong-a", "strong-b")  # 仍兜底给一个,不返回 None
