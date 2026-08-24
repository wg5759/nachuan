"""桥接策略（M5）：白名单 / 限频 / 命令解析 / 机主归一。"""

from __future__ import annotations

import threading
from collections import deque

import bridge.policy as policy_module
from bridge.policy import RateLimiter, is_allowed, parse_command, resolve_user_id


def test_is_allowed():
    assert not is_allowed("a", set())  # 空白名单=默认拒绝
    assert is_allowed("a", {"a", "b"})
    assert not is_allowed("c", {"a", "b"})


def test_rate_limiter_window():
    rl = RateLimiter(per_min=2)
    assert rl.allow("u", now=1000.0)
    assert rl.allow("u", now=1000.5)
    assert not rl.allow("u", now=1001.0)  # 第三次被挡
    assert rl.allow("u", now=1061.1)  # 过 60s 窗口 → 放行
    assert rl.allow("v", now=1001.0)  # 不同用户互不影响
    assert RateLimiter(per_min=0).allow("u")  # 0=不限频


def test_rate_limiter_serializes_one_users_concurrent_admission():
    class SlowLengthDeque(deque):
        def __init__(self):
            super().__init__()
            self._gate = threading.Barrier(2)

        def __bool__(self):
            return False

        def __len__(self):
            observed = super().__len__()
            try:
                self._gate.wait(timeout=0.1)
            except threading.BrokenBarrierError:
                pass
            return observed

    limiter = RateLimiter(per_min=1)
    limiter._hits["u"] = SlowLengthDeque()
    start = threading.Barrier(3)
    results: list[bool] = []

    def attempt() -> None:
        start.wait()
        results.append(limiter.allow("u", now=1000.0))

    workers = [threading.Thread(target=attempt) for _ in range(2)]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=1.0)

    assert all(not worker.is_alive() for worker in workers)
    assert sorted(results) == [False, True]


def test_rate_limiter_default_clock_is_monotonic(monkeypatch):
    monkeypatch.setattr(
        policy_module.time,
        "time",
        lambda: (_ for _ in ()).throw(AssertionError("wall clock used")),
    )
    monkeypatch.setattr(policy_module.time, "monotonic", lambda: 123.0)

    assert RateLimiter(per_min=1).allow("u") is True


def test_rate_limiter_bounds_distinct_users_and_reclaims_expired_slots():
    limiter = RateLimiter(per_min=1, max_users=2)

    assert limiter.allow("u1", now=1000.0) is True
    assert limiter.allow("u2", now=1000.0) is True
    assert limiter.allow("u3", now=1001.0) is False
    assert len(limiter._hits) == 2

    assert limiter.allow("u3", now=1061.1) is True
    assert len(limiter._hits) == 2
    assert "u3" in limiter._hits


def test_rate_limiter_caps_each_users_retained_window():
    limiter = RateLimiter(per_min=10**9)

    assert limiter.per_min == 10_000


def test_parse_command():
    assert parse_command("/whoami") == ("whoami", "")
    assert parse_command("我是谁") == ("whoami", "")
    assert parse_command("👍") == ("up", "")
    assert parse_command("/good") == ("up", "")
    assert parse_command("👎 回答太长了") == ("down", "回答太长了")
    assert parse_command("/bad 不准确") == ("down", "不准确")
    assert parse_command("帮我写代码") == ("chat", "帮我写代码")


def test_resolve_user_id():
    assert resolve_user_id("ou_x", "ou_x") == "owner"  # 机主归一，与桌面共享记忆
    assert resolve_user_id("ou_y", "ou_x") == "ou_y"
    assert resolve_user_id("", "ou_x") == "anon"
