"""运行中插话注入（Claude Code 式 steering）：agent 长任务跑着时用户发话——
不打断、不排队，话在 agent 下一步动作前被吸收进对话继续干（机主定案：插话=补充信息，任务别死、上下文要接上）。

机制：/v1/agent/run 进来时按 conversation_id 注册一个队列并设 contextvar；
run_tool_agent 每轮模型调用前 drain 队列 → 有插话就 append 成 user 消息。
contextvar 沿 async 调用链（含 create_task）自动传播，编排各层零签名改动。

该队列是进程内语义：生产网关必须只运行一个 worker。常见的多 worker
环境配置与 fork 继承状态会显式拒绝，不会静默把插话路由到错误进程。
"""

from __future__ import annotations

from collections import deque
from contextvars import ContextVar
import os
import threading

# 当前 agent 运行归属的对话 id（app.py 端点设置；深层 run_tool_agent 直接读）
conv_id_var: ContextVar[str] = ContextVar("nachuan_conv_id", default="")
principal_var: ContextVar[str] = ContextVar("nachuan_inject_principal", default="")

_MAX_QUEUE_MESSAGES = 16
_OWNER_PID = os.getpid()
_WORKER_COUNT_ENV = ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS")
_LOCK = threading.RLock()
_QUEUES: dict[tuple[str, str], deque[str]] = {}
_WRITABLE: set[tuple[str, str]] = set()


def _assert_single_process_deployment() -> None:
    if os.getpid() != _OWNER_PID:
        raise RuntimeError("插话队列仅支持 single-process；拒绝使用 fork 继承的队列")
    for name in _WORKER_COUNT_ENV:
        raw = str(os.environ.get(name) or "").strip()
        if not raw:
            continue
        try:
            workers = int(raw)
        except ValueError as exc:
            raise RuntimeError(f"{name} 必须明确设为 1（插话队列仅支持单进程）") from exc
        if workers != 1:
            raise RuntimeError("插话队列仅支持 single-process / 单进程网关")


def register(conv_id: str, principal: str = "", *, writable: bool = False) -> None:
    """Register one principal-owned run; concurrent reuse is fail-closed."""
    if not conv_id:
        return
    _assert_single_process_deployment()
    key = (principal, conv_id)
    with _LOCK:
        if key in _QUEUES:
            raise RuntimeError("该对话已有运行中的 Agent，不能复用插话队列")
        _QUEUES[key] = deque()
        if writable:
            _WRITABLE.add(key)


def unregister(conv_id: str, principal: str = "") -> None:
    """Remove exactly the principal-owned queue when its run ends."""
    if not conv_id:
        return
    _assert_single_process_deployment()
    key = (principal, conv_id)
    with _LOCK:
        _QUEUES.pop(key, None)
        _WRITABLE.discard(key)


def push(conv_id: str, text: str, principal: str = "") -> bool:
    """Inject only into the caller's read-only run; writable runs need re-approval."""
    _assert_single_process_deployment()
    key = (principal, conv_id or "")
    clean = (text or "").strip()
    if not clean or len(clean) > 8_000:
        return False
    with _LOCK:
        q = _QUEUES.get(key)
        if q is None or key in _WRITABLE or len(q) >= _MAX_QUEUE_MESSAGES:
            return False
        q.append(clean)
        return True


def drain(conv_id: str) -> list[str]:
    """agent 循环每轮取走全部待注入插话（非阻塞；无队列/无消息返回空）。"""
    _assert_single_process_deployment()
    with _LOCK:
        q = _QUEUES.get((principal_var.get(), conv_id or ""))
        if q is None:
            return []
        out = list(q)
        q.clear()
        return out
