"""桥接策略：白名单、限频、命令解析（平台无关的纯逻辑，便于单测）。

用途：群聊里别人 @ 机器人也能用同样能力，但花的是机主额度 —— 所以：
  · 白名单：只允许指定用户（空=不限制）；
  · 限频：每用户每分钟上限，防止有人狂刷烧额度；
  · 命令：/whoami 查自己的 open_id（用于配“机主统一记忆”）、👍/👎 反馈。
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict, deque


def is_allowed(user_id: str, allowed: set[str]) -> bool:
    """白名单默认拒绝；/whoami 由各 Channel 在调用本函数前单独开放。"""
    return bool(allowed) and user_id in allowed


class RateLimiter:
    """每用户滑动窗口限频（每 60 秒最多 per_min 次）。per_min<=0 表示不限。"""

    def __init__(self, per_min: int = 20, *, max_users: int = 10_000):
        requested = int(per_min)
        self.per_min = requested if requested <= 0 else min(requested, 10_000)
        self.max_users = max(1, min(int(max_users), 100_000))
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, user_id: str, now: float | None = None) -> bool:
        if self.per_min <= 0:
            return True
        current = time.monotonic() if now is None else float(now)
        # ``allow`` is a compound prune/check/append operation.  Weixin and
        # Feishu workers share one limiter across threads, so the whole decision
        # must be serialized for the same process rather than relying on the GIL.
        with self._lock:
            dq = self._hits.get(user_id)
            if dq is None:
                # Unknown identities must not grow process memory forever.  Only
                # reclaim an oldest slot after its complete window expired;
                # otherwise deny the new identity without allocating state.
                while len(self._hits) >= self.max_users:
                    oldest_user, oldest_hits = next(iter(self._hits.items()))
                    while oldest_hits and current - oldest_hits[0] > 60:
                        oldest_hits.popleft()
                    if oldest_hits:
                        return False
                    del self._hits[oldest_user]
                dq = deque()
                self._hits[user_id] = dq
            else:
                self._hits.move_to_end(user_id)
            while dq and current - dq[0] > 60:
                dq.popleft()
            if len(dq) >= self.per_min:
                return False
            dq.append(current)
            return True


def parse_command(text: str) -> tuple[str, str]:
    """把用户文本解析成 (kind, payload)。

    kind ∈ {whoami, up, down, chat}。下游据此决定查 open_id / 反馈 / 正常对话。
    """
    t = (text or "").strip()
    low = t.lower()
    if low in ("/whoami", "whoami", "我是谁"):
        return ("whoami", "")
    if t in ("👍", "👍🏻") or low in ("/good", "/up", "好评", "赞"):
        return ("up", "")
    if t.startswith("👎") or low.startswith("/bad") or low.startswith("/down"):
        note = re.sub(r"^(👎🏻?|/bad|/down)\s*", "", t, flags=re.I).strip()
        return ("down", note)
    return ("chat", t)


def resolve_user_id(open_id: str, owner_open_id: str) -> str:
    """机主的 open_id 归一为 'owner'，与桌面端共用同一份记忆；其余用各自 open_id。"""
    if owner_open_id and open_id == owner_open_id:
        return "owner"
    return open_id or "anon"
