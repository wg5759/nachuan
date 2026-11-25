"""P3 多 Git Worktree 并行编码控制面与跨端移动审批 HTTP 路由。

提供给桌面端 CodingStudioPane 及手机 Web PWA / IM 审批机器人的统一 API：
- GET    /v1/coding/sessions
- POST   /v1/coding/sessions
- GET    /v1/coding/sessions/{session_id}/diff
- POST   /v1/coding/sessions/{session_id}/mode
- POST   /v1/coding/sessions/{session_id}/revert
- POST   /v1/coding/sessions/{session_id}/commit
- DELETE /v1/coding/sessions/{session_id}
- POST   /v1/coding/sessions/{session_id}/exec
- GET    /v1/coding/approvals
- POST   /v1/coding/approvals/{approval_id}/resolve
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key
from gateway.config import get_settings
from orchestrator.coding_studio import (
    CodingSecurityError,
    CodingStudioError,
    CodingStudioManager,
)

router = APIRouter(tags=["coding-studio"])


def _get_manager(request: Request) -> CodingStudioManager:
    mgr = getattr(request.app.state, "coding_studio", None)
    if isinstance(mgr, CodingStudioManager):
        return mgr
    settings = get_settings()
    data_dir = Path(settings.usage_db_path).parent
    raw_roots = os.environ.get("NACHUAN_CODING_REPO_ROOTS", "").strip()
    allowed_roots = [r.strip() for r in raw_roots.split(os.pathsep) if r.strip()] if raw_roots else None
    mgr = CodingStudioManager(
        state_path=data_dir / "coding_studio_sessions.json",
        allowed_repo_roots=allowed_roots,
    )
    request.app.state.coding_studio = mgr
    return mgr


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, CodingSecurityError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, CodingStudioError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=500, detail=f"Coding Studio error: {type(exc).__name__}")


@router.get("/v1/coding/sessions")
async def list_coding_sessions(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    mgr = _get_manager(request)
    items = await run_in_threadpool(mgr.list_sessions)
    return {"sessions": items}


@router.post("/v1/coding/sessions")
async def create_coding_session(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=422, detail="请求体必须是合法 JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(
            mgr.create_session,
            repo_path=str(body.get("repo_path") or ""),
            title=str(body.get("title") or ""),
            base_ref=str(body.get("base_ref") or "HEAD"),
            mode=str(body.get("mode") or "plan"),
            agent_engine=str(body.get("agent_engine") or "codex"),
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/v1/coding/sessions/{session_id}/diff")
async def get_coding_session_diff(
    session_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(mgr.inspect_diff, session_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/v1/coding/sessions/{session_id}/mode")
async def switch_coding_session_mode(
    session_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(mgr.set_mode, session_id, str(body.get("mode") or ""))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/v1/coding/sessions/{session_id}/revert")
async def revert_coding_session_file(
    session_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(mgr.revert_file, session_id, str(body.get("path") or ""))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/v1/coding/sessions/{session_id}/commit")
async def commit_coding_session(
    session_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    files = body.get("files")
    if files is not None and (not isinstance(files, list) or not all(isinstance(x, str) for x in files)):
        raise HTTPException(status_code=422, detail="files 必须是字符串数组")
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(
            mgr.accept_and_commit,
            session_id,
            message=str(body.get("message") or ""),
            files=files,
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.delete("/v1/coding/sessions/{session_id}")
async def destroy_coding_session(
    session_id: str,
    delete_branch: bool = Query(default=True),
    request: Request = None,  # type: ignore[assignment]
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(mgr.destroy_session, session_id, delete_branch=delete_branch)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/v1/coding/sessions/{session_id}/exec")
async def exec_in_coding_session(
    session_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    timeout = float(body.get("timeout") or 60.0)
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(
            mgr.request_exec,
            session_id,
            command=str(body.get("command") or ""),
            timeout=timeout,
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/v1/coding/approvals")
async def list_coding_approvals(
    status: str | None = Query(default=None),
    request: Request = None,  # type: ignore[assignment]
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    mgr = _get_manager(request)
    items = await run_in_threadpool(mgr.list_approvals, status=status)
    return {"approvals": items}


@router.post("/v1/coding/approvals/{approval_id}/resolve")
async def resolve_coding_approval(
    approval_id: str,
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    mgr = _get_manager(request)
    try:
        return await run_in_threadpool(
            mgr.resolve_approval,
            approval_id,
            decision=str(body.get("decision") or ""),
            note=str(body.get("note") or ""),
        )
    except Exception as exc:
        raise _map_error(exc) from exc
