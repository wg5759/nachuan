"""MCP 注册表管理路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from gateway import mcp_registry
from gateway.auth import require_api_key
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile

router = APIRouter(tags=["mcp"])


def _app_mod():
    import gateway.app as _mod

    return _mod


@router.get("/v1/mcp")
async def mcp_list(_: str = Depends(require_api_key)):
    """List MCP definitions without exposing plaintext legacy env values."""
    servers = mcp_registry.public_servers()
    raw = mcp_registry.list_servers()
    status = {name: mcp_registry.probe(spec) for name, spec in raw.items()}
    return {
        "enabled": mcp_registry.verified_mcp_enabled(),
        "mcpServers": servers,
        "status": status,
    }


@router.get("/v1/mcp/presets")
async def mcp_presets(_: str = Depends(require_api_key)):
    """常用 MCP server 预设（#20）：一键挂载，附本机运行时是否就绪。"""
    return {
        "presets": [
            {
                **p,
                "available": False,
                "audited": False,
            }
            for p in mcp_registry.PRESETS
        ]
    }


@router.post("/v1/mcp")
async def mcp_add(request: Request, _: str = Depends(require_api_key)):
    """Register one hash-attested local MCP executable after exact approval."""
    app_mod = _app_mod()
    if not current_runtime_profile().allows(RuntimeCapability.MCP_PLUGIN_REGISTRY):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭 MCP 注册表；需要独立低权限 worker",
        )
    if not mcp_registry.verified_mcp_enabled():
        raise HTTPException(
            status_code=403,
            detail="可信 MCP 默认关闭；运维验收本地二进制后方可启用",
        )
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="需要 name")
    command = str(body.get("command") or "").strip()
    args = [str(v) for v in (body.get("args") or [])]
    sha256 = str(body.get("sha256") or "").strip().lower()
    if not command or body.get("url"):
        raise HTTPException(status_code=422, detail="只允许登记哈希证明的本地 stdio MCP")
    if body.get("env"):
        raise HTTPException(status_code=422, detail="禁止把 MCP 密钥作为明文 env 保存")
    candidate = {"command": command, "args": args, "sha256": sha256}
    attestation = mcp_registry.probe(candidate)
    if not attestation.get("ok"):
        raise HTTPException(
            status_code=422,
            detail=str(attestation.get("detail") or "MCP 证明无效"),
        )
    task = str(body.get("task") or f"登记并启用哈希证明 MCP：{name}")
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=str(app_mod.PROJECT_ROOT),
        user_id=str(
            body.get("user_id") or app_mod.get_settings().agent_user_id or "owner"
        ),
        scope="mcp_add",
        mode="full",
        require_explicit_capability=True,
        payload_extra={
            "name": name,
            "command": command,
            "args": args,
            "sha256": sha256,
        },
    )
    if held is not None:
        return held
    try:
        servers = mcp_registry.add_server(
            name, command=command, args=args, sha256=sha256
        )
    except ValueError as exc:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return {
        "ok": True,
        "mcpServers": servers,
        "probe": mcp_registry.probe(servers.get(name, {})),
    }


@router.delete("/v1/mcp/{name}")
async def mcp_remove(name: str, _: str = Depends(require_api_key)):
    """Legacy mutation contract had no approval body; use the scoped POST route."""
    del name
    raise HTTPException(
        status_code=410, detail="请使用 POST /v1/mcp/{name}/remove 走一次性审批"
    )


@router.post("/v1/mcp/{name}/remove")
async def mcp_remove_approved(
    name: str, request: Request, _: str = Depends(require_api_key)
):
    app_mod = _app_mod()
    if not current_runtime_profile().allows(RuntimeCapability.MCP_PLUGIN_REGISTRY):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭 MCP 注册表；需要独立低权限 worker",
        )
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    current = mcp_registry.list_servers().get(name)
    if not isinstance(current, dict):
        raise HTTPException(status_code=404, detail="MCP server 不存在")
    task = str(body.get("task") or f"移除 MCP：{name}")
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=str(app_mod.PROJECT_ROOT),
        user_id=str(
            body.get("user_id") or app_mod.get_settings().agent_user_id or "owner"
        ),
        scope="mcp_remove",
        mode="full",
        require_explicit_capability=True,
        payload_extra={"name": name, "spec": current},
    )
    if held is not None:
        return held
    try:
        servers = mcp_registry.remove_server(name)
    except Exception:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "mcpServers": servers}
