"""P3 后端编码控制面 HTTP 路由（Worktree 并行调度 + Diff + Revert + Commit + Plan/Build 审批执行）。

严格对齐前端 CodingControlPane 与 Electron 代理白名单 7 条契约：
- GET    /v1/workspace/worktrees
- POST   /v1/workspace/worktrees
- POST   /v1/workspace/worktrees/remove  （含 DELETE /v1/workspace/worktrees 别名）
- GET    /v1/workspace/diff
- POST   /v1/workspace/revert-file
- POST   /v1/workspace/commit
- POST   /v1/workspace/exec-plan
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key
from gateway.workspace_control import (
    WorkspaceControlError,
    WorkspaceSecurityError,
    commit_workspace,
    create_worktree,
    get_workspace_diff,
    list_worktrees,
    remove_worktree,
    revert_workspace_file,
    run_workspace_exec_plan,
)

router = APIRouter(tags=["workspace-control"])


def _map_workspace_error(exc: Exception) -> HTTPException:
    if isinstance(exc, WorkspaceSecurityError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, WorkspaceControlError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=f"工作区控制面内部错误：{type(exc).__name__}")


async def _read_json_object(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=422, detail="请求体必须是合法 JSON 对象") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    return body


@router.get("/v1/workspace/worktrees")
async def api_list_worktrees(
    repo_path: str | None = Query(default=None),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """列出仓库的所有 Git Worktree 及脏文件数；非 Git 目录优雅降级。"""
    effective_path = (repo_path or "").strip() or os.environ.get("AGENT_EXEC_WORKDIR") or os.getcwd()
    try:
        return await run_in_threadpool(list_worktrees, effective_path)
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.post("/v1/workspace/worktrees")
async def api_create_worktree(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """在 `<repo_root>/.nachuan-worktrees/` 创建隔离任务分支与 Worktree。"""
    body = await _read_json_object(request)
    repo_path = body.get("repo_path")
    task_name = body.get("task_name")
    base_ref = body.get("base_ref")
    if not isinstance(repo_path, str) or not repo_path.strip():
        raise HTTPException(status_code=422, detail="repo_path 必须为非空字符串")
    if not isinstance(task_name, str) or not task_name.strip():
        raise HTTPException(status_code=422, detail="task_name 必须为非空字符串")
    if base_ref is not None and not isinstance(base_ref, str):
        raise HTTPException(status_code=422, detail="base_ref 必须为字符串")
    try:
        return await run_in_threadpool(create_worktree, repo_path, task_name, base_ref)
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.post("/v1/workspace/worktrees/remove")
async def api_remove_worktree(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """移除纳川托管 Worktree（禁止移除主仓库或非托管目录）。"""
    body = await _read_json_object(request)
    repo_path = body.get("repo_path")
    worktree_path = body.get("worktree_path")
    force = body.get("force", False)
    delete_branch = body.get("delete_branch", False)
    if not isinstance(repo_path, str) or not repo_path.strip():
        raise HTTPException(status_code=422, detail="repo_path 必须为非空字符串")
    if not isinstance(worktree_path, str) or not worktree_path.strip():
        raise HTTPException(status_code=422, detail="worktree_path 必须为非空字符串")
    if not isinstance(force, bool):
        raise HTTPException(status_code=422, detail="force 必须为布尔值")
    if not isinstance(delete_branch, bool):
        raise HTTPException(status_code=422, detail="delete_branch 必须为布尔值")
    try:
        return await run_in_threadpool(
            remove_worktree,
            repo_path,
            worktree_path,
            force=force,
            delete_branch=delete_branch,
        )
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.delete("/v1/workspace/worktrees")
async def api_delete_worktree_alias(
    request: Request,
    repo_path: str | None = Query(default=None),
    worktree_path: str | None = Query(default=None),
    force: bool = Query(default=False),
    delete_branch: bool = Query(default=False),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """REST 风格别名：DELETE /v1/workspace/worktrees（支持 Query 或 JSON Body）。"""
    rp = repo_path
    wp = worktree_path
    f_flag = force
    db_flag = delete_branch
    if not rp or not wp:
        raw_body = await request.body()
        if raw_body.strip():
            body = await _read_json_object(request)
            rp = rp or (body.get("repo_path") if isinstance(body.get("repo_path"), str) else None)
            wp = wp or (
                body.get("worktree_path") if isinstance(body.get("worktree_path"), str) else None
            )
            if isinstance(body.get("force"), bool):
                f_flag = body["force"]
            if isinstance(body.get("delete_branch"), bool):
                db_flag = body["delete_branch"]
    if not rp or not rp.strip():
        raise HTTPException(status_code=422, detail="repo_path 必须为非空字符串")
    if not wp or not wp.strip():
        raise HTTPException(status_code=422, detail="worktree_path 必须为非空字符串")
    try:
        return await run_in_threadpool(
            remove_worktree,
            rp,
            wp,
            force=f_flag,
            delete_branch=db_flag,
        )
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.get("/v1/workspace/diff")
async def api_get_workspace_diff(
    worktree_path: str = Query(..., min_length=1),
    staged: bool = Query(default=False),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """获取工作树逐文件结构化 Diff 与增删行统计。"""
    try:
        return await run_in_threadpool(get_workspace_diff, worktree_path, staged=staged)
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.post("/v1/workspace/revert-file")
async def api_revert_workspace_file(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """撤销工作树内单个文件改动（严格防路径穿越与 `.git` 修改）。"""
    body = await _read_json_object(request)
    worktree_path = body.get("worktree_path")
    file_path = body.get("file_path")
    if not isinstance(worktree_path, str) or not worktree_path.strip():
        raise HTTPException(status_code=422, detail="worktree_path 必须为非空字符串")
    if not isinstance(file_path, str) or not file_path.strip():
        raise HTTPException(status_code=422, detail="file_path 必须为非空字符串")
    try:
        return await run_in_threadpool(revert_workspace_file, worktree_path, file_path)
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.post("/v1/workspace/commit")
async def api_commit_workspace(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """在指定工作树执行本地 Git Commit（绝不 push）。"""
    body = await _read_json_object(request)
    worktree_path = body.get("worktree_path")
    message = body.get("message")
    files = body.get("files")
    if not isinstance(worktree_path, str) or not worktree_path.strip():
        raise HTTPException(status_code=422, detail="worktree_path 必须为非空字符串")
    if not isinstance(message, str) or not message.strip():
        raise HTTPException(status_code=422, detail="message 必须为非空字符串")
    if files is not None and (
        not isinstance(files, list) or not all(isinstance(item, str) for item in files)
    ):
        raise HTTPException(status_code=422, detail="files 必须为字符串数组")
    try:
        return await run_in_threadpool(commit_workspace, worktree_path, message, files)
    except Exception as exc:
        raise _map_workspace_error(exc) from exc


@router.post("/v1/workspace/exec-plan")
async def api_run_workspace_exec_plan(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Plan（只读探索白名单）/ Build（审批绑定单次消费执行）双模执行闸。"""
    body = await _read_json_object(request)
    worktree_path = body.get("worktree_path")
    mode = body.get("mode")
    command = body.get("command")
    approval_id = body.get("approval_id")
    if not isinstance(worktree_path, str) or not worktree_path.strip():
        raise HTTPException(status_code=422, detail="worktree_path 必须为非空字符串")
    if not isinstance(mode, str) or mode.strip().lower() not in {"plan", "build"}:
        raise HTTPException(status_code=422, detail="mode 必须为 'plan' 或 'build'")
    if not isinstance(command, str) or not command.strip():
        raise HTTPException(status_code=422, detail="command 必须为非空字符串")
    if approval_id is not None and not isinstance(approval_id, (str, int)):
        raise HTTPException(status_code=422, detail="approval_id 必须为字符串或整数")

    approval_store = getattr(request.app.state, "approvals", None)
    try:
        return await run_in_threadpool(
            run_workspace_exec_plan,
            worktree_path,
            mode,
            command,
            None if approval_id is None else str(approval_id),
            approval_store,
        )
    except Exception as exc:
        raise _map_workspace_error(exc) from exc
