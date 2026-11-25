"""纳川网关模块化路由注册中心（P1-3：拆解 gateway/app.py）。"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

from gateway.routes.agent_ops import router as agent_ops_router
from gateway.routes.approvals_sync import router as approvals_sync_router
from gateway.routes.audio_vision import router as audio_vision_router
from gateway.routes.coding_studio import router as coding_studio_router
from gateway.routes.conversations import router as conversations_router
from gateway.routes.mcp import router as mcp_router
from gateway.routes.memory_kb import router as memory_kb_router
from gateway.routes.orchestrate import router as orchestrate_router
from gateway.routes.privacy_audit import router as privacy_audit_router
from gateway.routes.studio_lapian import router as studio_lapian_router
from gateway.routes.workspace import router as workspace_router

ALL_ROUTERS: tuple[APIRouter, ...] = (
    conversations_router,
    memory_kb_router,
    approvals_sync_router,
    agent_ops_router,
    audio_vision_router,
    mcp_router,
    orchestrate_router,
    studio_lapian_router,
    privacy_audit_router,
    coding_studio_router,
    workspace_router,
)


def register_gateway_routes(app: FastAPI) -> None:
    """将全部拆分后的模块化 APIRouter 统一挂载到 FastAPI 应用。"""

    for r in ALL_ROUTERS:
        app.include_router(r)


__all__ = [
    "ALL_ROUTERS",
    "agent_ops_router",
    "approvals_sync_router",
    "audio_vision_router",
    "coding_studio_router",
    "conversations_router",
    "mcp_router",
    "memory_kb_router",
    "orchestrate_router",
    "privacy_audit_router",
    "register_gateway_routes",
    "studio_lapian_router",
    "workspace_router",
]
