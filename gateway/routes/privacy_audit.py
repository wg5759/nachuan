"""实时网络出站审计与纯离线（空气间隙）模式 API 路由（P2-3）。

严格对齐前端 OutboundAuditPane 与 Electron 主进程代理白名单契约：
- GET    /v1/privacy/outbound-audit  (limit=100, since_id=0, blocked_only=false)
- DELETE /v1/privacy/outbound-audit
- GET    /v1/privacy/offline-mode
- POST   /v1/privacy/offline-mode    ({ "enabled": boolean })
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from gateway.auth import require_api_key
from gateway.outbound_guard import get_outbound_guard

router = APIRouter(tags=["privacy-audit"])


@router.get("/v1/privacy/outbound-audit")
async def get_outbound_audit(
    limit: int = Query(default=100, ge=1, le=500),
    since_id: int = Query(default=0, ge=0),
    blocked_only: bool = Query(default=False),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """查询实时网络出站审计日志与汇总统计。"""
    guard = get_outbound_guard()
    return guard.snapshot(limit=limit, since_id=since_id, blocked_only=blocked_only)


@router.delete("/v1/privacy/outbound-audit")
async def clear_outbound_audit(
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """清空内存出站审计缓冲区并返回清理条数。"""
    guard = get_outbound_guard()
    cleared = guard.clear()
    return {"ok": True, "cleared": cleared}


@router.get("/v1/privacy/offline-mode")
async def get_offline_mode(
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """查询当前是否处于纯离线（空气间隙）模式及来源。"""
    guard = get_outbound_guard()
    return guard.offline_mode_status()


@router.post("/v1/privacy/offline-mode")
async def set_offline_mode(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """热切换纯离线（空气间隙）模式并持久化到 privacy_prefs.json。"""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=422, detail="请求体必须是合法 JSON 对象") from exc
    if not isinstance(body, dict) or set(body.keys()) != {"enabled"}:
        raise HTTPException(
            status_code=422,
            detail="请求体仅允许包含布尔字段 enabled",
        )
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(status_code=422, detail="enabled 必须是布尔值 (true/false)")
    guard = get_outbound_guard()
    return guard.set_offline_mode(enabled, source="api", persist=True)
