"""审批与跨设备/云同步路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key, require_approval_admin_key
from gateway.secure_store import SecureStorageError

router = APIRouter(tags=["approvals-sync"])


@router.get("/v1/approvals")
async def list_approvals(
    user_id: str,
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """机主待审清单（P5 重大动作 + P6 技能卡入库）。前端据此弹「动作摘要 + 同意/换方案/取消 + 自定义输入」。"""
    return {
        "user_id": user_id,
        "pending": request.app.state.approvals.list_pending(user_id),
    }


@router.post("/v1/approvals/{approval_id}/resolve")
async def resolve_approval(
    approval_id: int,
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """裁决一条待审：decision=approve(同意)/reject(取消)/revise(换方案，note=机主自定义说明)。"""
    body = await request.json()
    decision = str(body.get("decision") or "").lower()
    note = str(body.get("note") or "")
    rec = request.app.state.approvals.resolve(approval_id, decision, note)
    if rec is None:
        raise HTTPException(
            status_code=422, detail="decision 需为 approve/reject/revise，且待审项需存在"
        )
    if rec.get("status") == "expired":
        raise HTTPException(status_code=409, detail="审批已过期，请重新发起动作")
    result: dict[str, Any] = {
        "ok": True,
        "id": approval_id,
        "status": rec["status"],
        "kind": rec["kind"],
        "note": rec.get("note", ""),
    }
    if rec["kind"] == "skill_card" and rec["status"] == "approved":
        p = rec.get("payload") or {}
        result["case_id"] = request.app.state.cases.add(
            rec["user_id"],
            p.get("problem", ""),
            p.get("solution", ""),
            p.get("model", "user_approved"),
        )
    return JSONResponse(result)


@router.post("/v1/sync/cases/push")
async def sync_cases_push(request: Request, _: str = Depends(require_api_key)):
    """跨设备同步：把一台机器学到的案例合并进本服务器的共享库（去重幂等，不重复堆）。"""
    body = await request.json()
    user_id = str(body.get("user_id") or "")
    added = (
        request.app.state.cases.import_merge(user_id, body.get("items") or [])
        if user_id
        else 0
    )
    return {"ok": True, "added": added}


@router.get("/v1/sync/cases/pull")
async def sync_cases_pull(
    user_id: str, request: Request, _: str = Depends(require_api_key)
):
    """跨设备同步：拉取共享库全部案例，调用方 import_merge 到本地（各机各存全份=容灾）。"""
    return {"user_id": user_id, "items": request.app.state.cases.export_all(user_id)}


@router.get("/v1/sync/status")
async def cloud_sync_status(_: str = Depends(require_api_key)):
    """同步状态（不回显任何密钥/token）：是否配置/登录、邮箱、上次同步时间。"""
    from orchestrator import cloud_sync

    return cloud_sync.status()


@router.post("/v1/sync/config")
async def cloud_sync_config(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """录入 Supabase 项目 URL + anon key（不回显、存本地 data/sync.json）。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="同步配置必须是 JSON 对象")
    url = body.get("url")
    anon_key = body.get("anon_key")
    if not isinstance(url, str) or not isinstance(anon_key, str):
        raise HTTPException(status_code=422, detail="url/anon_key 必须是字符串")
    if len(url) > 2048 or len(anon_key) > 16384:
        raise HTTPException(status_code=413, detail="同步配置超过长度限制")
    try:
        target = cloud_sync.validate_target(url, anon_key)
        cloud_sync.configure(target["url"], anon_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Supabase 目标不符合安全策略") from exc
    except (OSError, SecureStorageError) as exc:
        raise HTTPException(status_code=503, detail="同步配置未能安全持久化") from exc
    return cloud_sync.status()


@router.post("/v1/sync/signup")
async def cloud_sync_signup(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """Supabase 注册（商用：终端用户自助开账户）。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="注册参数必须是 JSON 对象")
    email = body.get("email")
    password = body.get("password")
    if (
        not isinstance(email, str)
        or not isinstance(password, str)
        or not email.strip()
        or not password
        or len(email) > 320
        or len(password) > 1024
    ):
        raise HTTPException(status_code=422, detail="邮箱或密码格式无效")
    return await run_in_threadpool(cloud_sync.signup, email.strip(), password)


@router.post("/v1/sync/login")
async def cloud_sync_login(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """Supabase 邮箱密码登录（拿 token、定账户）。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="登录参数必须是 JSON 对象")
    email = body.get("email")
    password = body.get("password")
    if (
        not isinstance(email, str)
        or not isinstance(password, str)
        or not email.strip()
        or not password
        or len(email) > 320
        or len(password) > 1024
    ):
        raise HTTPException(status_code=422, detail="邮箱或密码格式无效")
    return await run_in_threadpool(cloud_sync.login, email.strip(), password)


@router.post("/v1/sync/toggle")
async def cloud_sync_toggle(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """同步总开关。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        raise HTTPException(status_code=422, detail="enabled 必须是布尔值")
    enabled = body["enabled"]
    current = cloud_sync.status()
    if enabled and not (current.get("configured") and current.get("logged_in")):
        raise HTTPException(status_code=409, detail="同步目标尚未配置并登录")
    try:
        cloud_sync.set_enabled(enabled)
    except (OSError, SecureStorageError) as exc:
        raise HTTPException(status_code=503, detail="同步开关未能安全持久化") from exc
    return cloud_sync.status()


@router.post("/v1/sync/run")
async def cloud_sync_run(
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """立即同步一次：四张表各 push 本地 + pull 远端合并。未就绪则安全跳过。"""
    from orchestrator import cloud_sync

    return await run_in_threadpool(cloud_sync.sync_all)
