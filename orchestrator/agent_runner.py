"""Fail-closed adapter for the retained native coding-agent slot.

Codex still executes under the gateway's Windows user. It therefore cannot be
used until a separate low-privilege worker/broker owns all model-controlled
process execution. Retired Claude is not registered as a selectable runner.
"""

from __future__ import annotations

from typing import Any


async def run_codex_agent(
    task: str, workdir: str, *, model: str = "", timeout: float = 600.0
) -> dict[str, Any]:
    del task, workdir, model, timeout
    return {
        "ok": False,
        "output": "",
        "error": "Codex coding agent 已关闭：需要独立低权限执行 worker",
    }


AGENT_RUNNERS = {"codex": run_codex_agent}
