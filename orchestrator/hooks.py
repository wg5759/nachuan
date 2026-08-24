"""确定性 Hooks（C1）：成本闸 + 危险内容拦截 —— 运行时治理，不靠模型自觉。

借鉴 Claude Code 的“钩子流水线”原则（校验→前钩子→执行→后钩子），但只取确定性规则部分：
  · 成本闸：每非机主用户每日调用上限（防群里他人狂刷烧机主额度）；机主(owner)豁免。
  · 内容拦截：可配正则黑名单，命中即拒（默认空=不拦）。
确定性 = 纯规则、结果可预期、可单测；与模型“是否愿意”无关。
"""

from __future__ import annotations

import re
import time
from collections import defaultdict


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.localtime())


class HookGuard:
    """前置 check() + 后置 record() 两段式守门。"""

    def __init__(
        self,
        daily_cap: int = 0,
        denylist: list[str] | None = None,
        owner_id: str = "owner",
    ):
        self.daily_cap = daily_cap
        self.owner_id = owner_id
        self._deny = [re.compile(p, re.I) for p in (denylist or []) if p]
        self._counts: dict[str, int] = defaultdict(int)  # key = f"{date}:{user_id}"

    def check(self, user_id: str, message: str) -> tuple[bool, str]:
        """前钩子：内容黑名单 + 每日额度。返回 (放行?, 拦截语)。"""
        for rx in self._deny:
            if rx.search(message or ""):
                return False, "⛔ 内容被安全策略拦截。"
        if self.daily_cap > 0 and user_id and user_id != self.owner_id:
            if self._counts[f"{_today()}:{user_id}"] >= self.daily_cap:
                return False, "⏳ 你今天的使用额度已用完，明天再来吧。"
        return True, ""

    def record(self, user_id: str) -> None:
        """后钩子：累计该用户当日成功调用次数（机主不计）。"""
        if user_id and user_id != self.owner_id:
            self._counts[f"{_today()}:{user_id}"] += 1

    def used_today(self, user_id: str) -> int:
        return self._counts.get(f"{_today()}:{user_id}", 0)
