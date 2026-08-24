"""coding_team（M4）：规划 → 并行实现(各 agent 一个 worktree) → 评审。

- planner / reviewer：用聊天模型（强模型即可）。
- implementers：每个用一个当前启用的编程 agent 在隔离的 worktree 里真实改代码。
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from gateway.failover import (
    DEFAULT_ATTEMPT_TIMEOUT_SEC,
    DEFAULT_TOTAL_TIMEOUT_SEC,
    chat_once_with_deadline,
)
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.schemas import ChatCompletionRequest
from orchestrator.agent_runner import AGENT_RUNNERS
from orchestrator.worktree import create_worktree, remove_worktree, worktree_diff

_CHAT_ATTEMPT_TIMEOUT_SEC = DEFAULT_ATTEMPT_TIMEOUT_SEC
_CHAT_TOTAL_TIMEOUT_SEC = DEFAULT_TOTAL_TIMEOUT_SEC


async def _chat(
    router: Any,
    model_id: str,
    prompt: str,
    *,
    role: str = "coding_team.chat",
) -> str:
    route = router.resolve(model_id)
    if route is None:
        return f"(未知模型 {model_id})"
    req = ChatCompletionRequest(model=model_id, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
    try:
        with bind_provider_call_scope(role=role):
            res = await chat_once_with_deadline(
                route.provider,
                req,
                route.upstream_model,
                attempt_timeout=_CHAT_ATTEMPT_TIMEOUT_SEC,
                total_timeout=_CHAT_TOTAL_TIMEOUT_SEC,
            )
        return (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    except asyncio.TimeoutError:
        return f"(失败: 模型 {model_id} 响应超时)"
    except Exception as e:  # noqa: BLE001
        return f"(失败: {e})"


def _review_prompt(task: str, impls: list[dict[str, Any]]) -> str:
    parts = [
        f"任务：\n{task}\n",
        "下面是多个 agent 各自的实现 diff。请评审：指出各自优劣、是否有 bug，并建议选哪个 / 如何集成。\n",
    ]
    for im in impls:
        diff = (im.get("diff") or "(无改动)")[:4000]
        parts.append(f"【{im['name']} · {im['agent']}】\n```diff\n{diff}\n```\n")
    return "\n".join(parts)


async def run_coding_team(
    router: Any,
    *,
    repo: str,
    task: str,
    planner: str,
    implementers: list[dict[str, Any]],
    reviewer: str,
    cleanup: bool = False,
) -> dict[str, Any]:
    """返回 {plan, implementations:[{name,agent,result,diff,worktree}], review}。"""
    if not 1 <= len(implementers) <= 4:
        raise ValueError("implementers 数量必须在 1-4 之间")
    seen: set[str] = set()
    for spec in implementers:
        name = str(spec.get("name") or "")
        agent = str(spec.get("agent") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,48}", name):
            raise ValueError("implementer name 不合法")
        if name.casefold() in seen:
            raise ValueError("implementer name 不得重复")
        if agent not in AGENT_RUNNERS:
            raise ValueError(f"未知 agent 类型 {agent}")
        seen.add(name.casefold())
    plan = await _chat(
        router,
        planner,
        f"为以下编程任务制定一个简洁的实现计划（要点式即可）：\n\n{task}",
        role="coding_team.plan",
    )

    async def implement(spec: dict[str, Any]) -> dict[str, Any]:
        name = spec["name"]
        agent = spec.get("agent", "codex")
        model = spec.get("model", "")
        runner = AGENT_RUNNERS.get(agent)
        if runner is None:
            return {"name": name, "agent": agent, "error": f"未知 agent 类型 {agent}", "diff": ""}
        try:
            wt = create_worktree(repo, name)
        except Exception as e:  # noqa: BLE001
            return {"name": name, "agent": agent, "error": f"创建 worktree 失败: {e}", "diff": ""}
        full = (
            f"任务：{task}\n\n参考计划：\n{plan}\n\n请在当前工作目录里实现它（直接新建/修改文件）。"
        )
        kwargs = {"model": model} if model else {}
        res = await runner(full, str(wt), **kwargs)
        diff = ""
        try:
            diff = worktree_diff(repo, wt)
        except Exception as e:  # noqa: BLE001
            res.setdefault("error", str(e))
        out = {"name": name, "agent": agent, "result": res, "diff": diff, "worktree": str(wt)}
        if cleanup:
            try:
                remove_worktree(repo, wt, f"agent/{name}")
            except Exception:  # noqa: BLE001
                pass
        return out

    impls = list(await asyncio.gather(*[implement(s) for s in implementers]))
    review = await _chat(
        router,
        reviewer,
        _review_prompt(task, impls),
        role="coding_team.review",
    )
    return {"plan": plan, "implementations": impls, "review": review}


def parse_files(text: str) -> list[tuple[str, str]]:
    """解析编辑模型输出的 `=== 路径 ===\\n内容` 文件块。带路径穿越防护。"""
    out: list[tuple[str, str]] = []
    parts = re.split(r"(?m)^===\s*(.+?)\s*===\s*$", text or "")
    for i in range(1, len(parts) - 1, 2):
        path = parts[i].strip().strip("`").replace("\\", "/")
        content = parts[i + 1].strip()
        content = re.sub(r"^```[\w.+-]*\n", "", content)
        content = re.sub(r"\n```$", "", content)
        # 安全：仅接受相对路径，拒绝绝对路径与 .. 穿越
        if path and not path.startswith("/") and ".." not in path.split("/"):
            out.append((path, content))
    return out


async def run_arch_editor(
    router: Any, *, repo: str, task: str, architect: str, editor: str
) -> dict[str, Any]:
    """架构师/编辑（省token编程）：architect 规划 → editor 出文件 → 写入隔离 worktree。"""
    plan = await _chat(
        router,
        architect,
        f"为下面编程任务制定详细实现计划：列出要新建/修改哪些文件、每个文件的关键函数与内容。\n任务：\n{task}",
        role="arch_editor.plan",
    )
    out = await _chat(
        router,
        editor,
        f"任务：{task}\n\n实现计划：\n{plan}\n\n"
        "请输出所有需要新建/修改文件的完整内容。每个文件严格用如下格式：\n"
        "=== 相对路径 ===\n<完整文件内容>\n\n只输出文件，不要解释。",
        role="arch_editor.edit",
    )
    files = parse_files(out)
    try:
        wt = create_worktree(repo, "arch-editor")
    except Exception as e:  # noqa: BLE001
        return {"plan": plan, "editor_output": out[:2000], "error": f"创建 worktree 失败: {e}", "files": []}
    written: list[str] = []
    for path, content in files:
        fp = Path(wt) / path
        try:
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            written.append(path)
        except OSError:
            pass
    diff = ""
    try:
        diff = worktree_diff(repo, wt)
    except Exception:  # noqa: BLE001
        pass
    return {
        "plan": plan,
        "architect": architect,
        "editor": editor,
        "files": written,
        "diff": diff,
        "worktree": str(wt),
    }
