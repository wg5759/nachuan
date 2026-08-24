"""模型额度/限流状态（兜底路由第1层地基）。

某模型撞 429/超额 → 记一个"冷却到 T"的时间戳；兜底链会把冷却中的模型**挪到最后**
（优先试还有额度的，但不彻底剔除——全都冷却时仍兜底试一把）。到点自动恢复。

设计取舍：
- **in-memory 即可**。状态是瞬时的；引擎重启后最多对某模型多撞一次 429 就重新标记，代价可忽略。
- 冷却时长：有上游 Retry-After 就用它，否则用默认（不宜太长=过度封禁，不宜太短=狂撞）。
  单次冷却封顶 1 小时——防把"月额度真耗尽"误判成"永久封"，1 小时后重探一次即可（还耗尽就再标）。
- 429 既是"太频繁"也是"额度用完"，本层不区分：都当"这个先别用、试别的"，最兜底、最准、零配置。
"""

from __future__ import annotations

import math
import threading
import time
from typing import Optional

from gateway.providers.base import ProviderError

# model_id -> 冷却截止时间戳(秒)。now < 值 → 该模型暂不可用（额度/限流冷却中）。
_cooldown: dict[str, float] = {}
_state_lock = threading.RLock()

_DEFAULT_COOLDOWN = 90.0  # 撞 429 又拿不到 Retry-After 时的默认冷却
_MAX_COOLDOWN = 3600.0    # 单次冷却封顶 1 小时（防误判长封）
_MAX_TRACKED_MODELS = 10_000  # 防动态/恶意 model_id 让进程状态永久增长
# 判"这是额度/限流类错误"：429=太频繁/超额；402=欠费/额度；再兜底看消息关键词。
_QUOTA_STATUS = {429, 402}
_QUOTA_HINTS = ("超额", "额度", "配额", "quota", "exhaust", "insufficient", "rate limit", "too many requests", "余量")


def _prune_expired_locked(now: float) -> None:
    for model_id, deadline in list(_cooldown.items()):
        if deadline <= now:
            _cooldown.pop(model_id, None)
    for model_id in list(_err_count):
        seen_at = _err_seen_at.get(model_id)
        if seen_at is None:
            _err_seen_at[model_id] = now
        elif seen_at + _ERR_COUNT_TTL <= now:
            _err_count.pop(model_id, None)
            _err_seen_at.pop(model_id, None)


def _known_model_count_locked() -> int:
    return len(set(_cooldown) | set(_err_count))


def _can_track_locked(model_id: str, now: float) -> bool:
    _prune_expired_locked(now)
    if model_id in _cooldown or model_id in _err_count:
        return True
    return _known_model_count_locked() < _MAX_TRACKED_MODELS


def is_quota_error(e: BaseException) -> bool:
    """这个异常是不是"额度用完/限流"类（该记冷却、该兜底）？"""
    code = getattr(e, "status_code", None)
    if code in _QUOTA_STATUS:
        return True
    low = str(e).lower()
    return any(h in low for h in _QUOTA_HINTS)


def mark_exhausted(model_id: str, retry_after: Optional[float] = None) -> None:
    """标记某模型"额度/限流冷却"。retry_after 有就用（上游给的），否则默认；封顶 1 小时。"""
    if not model_id:
        return
    try:
        candidate = float(retry_after) if retry_after is not None else _DEFAULT_COOLDOWN
    except (TypeError, ValueError):
        candidate = _DEFAULT_COOLDOWN
    wait = candidate if math.isfinite(candidate) and candidate > 0 else _DEFAULT_COOLDOWN
    now = time.monotonic()
    with _state_lock:
        if not _can_track_locked(model_id, now):
            return
        _cooldown[model_id] = now + min(wait, _MAX_COOLDOWN)
        _err_count.pop(model_id, None)
        _err_seen_at.pop(model_id, None)


def mark_if_quota(model_id: str, e: BaseException, retry_after: Optional[float] = None) -> bool:
    """便捷：若 e 是额度/限流错，标记冷却并返回 True；否则不动、返回 False。"""
    if is_quota_error(e):
        mark_exhausted(model_id, retry_after)
        return True
    return False


# ── 通用失败熔断（不只额度错）：后端挂死/超时也得快速让路 ──
# 机主实测灾难：claude CLI 每跳 180s 超时，编排多轮反复撞同一堵墙 → 一个任务耗 15 分钟。
# 连续 _ERR_THRESHOLD 次任何失败 → 冷却 _ERR_COOLDOWN 秒（选将/兜底自动跳过）；一次成功即清零。
_err_count: dict[str, int] = {}
_err_seen_at: dict[str, float] = {}
_ERR_THRESHOLD = 2
_ERR_COOLDOWN = 600.0  # 10 分钟：够长让编排绕开，够短不至于误杀一晚上
_ERR_COUNT_TTL = 600.0  # 单次孤立失败不能永久占用身份容量


def mark_error(model_id: str) -> None:
    """记一次非额度失败（超时/进程挂/5xx…）。连续 ≥ 阈值 → 熔断冷却。"""
    if not model_id:
        return
    now = time.monotonic()
    with _state_lock:
        if not _can_track_locked(model_id, now):
            return
        n = _err_count.get(model_id, 0) + 1
        if n >= _ERR_THRESHOLD:
            _cooldown[model_id] = now + _ERR_COOLDOWN
            _err_count.pop(model_id, None)  # 已熔断，计数重来
            _err_seen_at.pop(model_id, None)
        else:
            _err_count[model_id] = n
            _err_seen_at[model_id] = now


def mark_ok(model_id: str) -> None:
    """成功一次 → 清连败计数（防偶发抖动累积成熔断）。"""
    with _state_lock:
        _err_count.pop(model_id, None)
        _err_seen_at.pop(model_id, None)


def available(model_id: str) -> bool:
    """该模型现在可用吗（不在额度/限流冷却中）？"""
    if not model_id:
        return True
    now = time.monotonic()
    with _state_lock:
        _prune_expired_locked(now)
        t = _cooldown.get(model_id)
        if t is not None:
            return False
        if model_id in _err_count:
            return True
        # 容量已经由活跃证据占满时，未知身份失败关闭；不能为了新身份
        # 驱逐一个仍在冷却/累计失败的模型并重新撞坏后端。
        return _known_model_count_locked() < _MAX_TRACKED_MODELS


def cooldown_left(model_id: str) -> float:
    """还要冷却多少秒（0=可用）。"""
    now = time.monotonic()
    with _state_lock:
        _prune_expired_locked(now)
        t = _cooldown.get(model_id)
        if t is not None:
            # Floating-point addition/subtraction can produce
            # 3600.0000000000005 for an exact one-hour cap.
            return min(_MAX_COOLDOWN, max(0.0, t - now))
        if model_id and model_id not in _err_count and _known_model_count_locked() >= _MAX_TRACKED_MODELS:
            return _DEFAULT_COOLDOWN
        return 0.0


def snapshot() -> dict[str, float]:
    """当前所有冷却中的模型 → 剩余秒数（供看板/调试；顺手清理过期）。"""
    now = time.monotonic()
    with _state_lock:
        _prune_expired_locked(now)
        return {model_id: round(deadline - now, 1) for model_id, deadline in _cooldown.items()}


def clear(model_id: str = "") -> None:
    """清冷却+连败计数（测试/手动恢复）。不传 = 全清。
    连败计数必须一起清——否则"清干净"后第一次失败会被当成连续第二次直接熔断（codex 审：状态泄漏）。"""
    with _state_lock:
        if model_id:
            _cooldown.pop(model_id, None)
            _err_count.pop(model_id, None)
            _err_seen_at.pop(model_id, None)
        else:
            _cooldown.clear()
            _err_count.clear()
            _err_seen_at.clear()


__all__ = [
    "ProviderError",
    "is_quota_error",
    "mark_exhausted",
    "mark_if_quota",
    "mark_error",
    "mark_ok",
    "available",
    "cooldown_left",
    "snapshot",
    "clear",
]
