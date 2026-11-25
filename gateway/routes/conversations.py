"""P1-3 服务端会话真相源 CRUD API（`/v1/conversations*`）。

替代浏览器 localStorage 成为单一真相源，落库于 `nachuan_core.db`
（`conversation_meta` + `conversation_rich_messages`）。
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from gateway.auth import require_api_key
from gateway.config import get_settings

router = APIRouter(tags=["conversations"])


def _resolve_user_id(explicit: Any = None) -> str:
    raw = str(explicit or "").strip()
    if raw:
        return raw
    return str(get_settings().agent_user_id or "owner").strip() or "default"


async def _json_object(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="请求体必须是合法 JSON 对象") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    return body


@router.get("/v1/conversations")
async def list_conversations(
    request: Request,
    user_id: str | None = Query(default=None),
    include_archived: bool = Query(default=True),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    uid = _resolve_user_id(user_id)
    items = request.app.state.conversations.list_conversations(
        uid, include_archived=include_archived
    )
    return {"user_id": uid, "conversations": items, "items": items}


@router.post("/v1/conversations")
async def create_conversation(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await _json_object(request)
    uid = _resolve_user_id(body.get("user_id"))
    conv_id = body.get("id") or body.get("conv_id")
    created_at = body.get("created_at")
    if created_at is None:
        created_at = body.get("createdAt")
    updated_at = body.get("updated_at")
    if updated_at is None:
        updated_at = body.get("updatedAt")
    try:
        record = request.app.state.conversations.create_conversation(
            conv_id=str(conv_id).strip() if conv_id else None,
            user_id=uid,
            title=str(body.get("title") or ""),
            kind=str(body.get("kind") or "chat"),
            workdir=str(body.get("workdir") or ""),
            archived=bool(body.get("archived", False)),
            draft=body.get("draft") if isinstance(body.get("draft"), dict) else None,
            messages=body.get("messages")
            if isinstance(body.get("messages"), list)
            else None,
            created_at=float(created_at) if created_at is not None else None,
            updated_at=float(updated_at) if updated_at is not None else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return record


@router.post("/v1/conversations/import")
async def bulk_import_conversations(
    request: Request,
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await _json_object(request)
    uid = _resolve_user_id(body.get("user_id"))
    raw_items = body.get("items")
    if raw_items is None:
        raw_items = body.get("conversations")
    if not isinstance(raw_items, list):
        raise HTTPException(status_code=422, detail="需要 items 或 conversations 数组")
    if len(raw_items) > 5000:
        raise HTTPException(status_code=422, detail="单次批量导入最多支持 5000 条会话")
    try:
        stats = request.app.state.conversations.bulk_import_conversations(
            uid, raw_items
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"ok": True, "user_id": uid, **stats}


@router.get("/v1/conversations/{conv_id}")
async def get_conversation(
    conv_id: str,
    request: Request,
    user_id: str | None = Query(default=None),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    uid = _resolve_user_id(user_id)
    record = request.app.state.conversations.get_conversation(conv_id, uid)
    if record is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return record


@router.patch("/v1/conversations/{conv_id}")
async def patch_conversation(
    conv_id: str,
    request: Request,
    user_id: str | None = Query(default=None),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await _json_object(request)
    uid = _resolve_user_id(body.get("user_id") or user_id)
    updated_at = body.get("updated_at")
    if updated_at is None:
        updated_at = body.get("updatedAt")
    record = request.app.state.conversations.patch_conversation(
        conv_id,
        uid,
        title=body["title"] if "title" in body and body["title"] is not None else None,
        kind=body["kind"] if "kind" in body and body["kind"] is not None else None,
        workdir=body["workdir"]
        if "workdir" in body and body["workdir"] is not None
        else None,
        archived=bool(body["archived"])
        if "archived" in body and body["archived"] is not None
        else None,
        draft=body["draft"] if "draft" in body and isinstance(body["draft"], dict) else None,
        updated_at=float(updated_at) if updated_at is not None else None,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return record


@router.put("/v1/conversations/{conv_id}/messages")
async def upsert_conversation_messages(
    conv_id: str,
    request: Request,
    user_id: str | None = Query(default=None),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    body = await _json_object(request)
    uid = _resolve_user_id(body.get("user_id") or user_id)
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise HTTPException(status_code=422, detail="需要 messages 数组")
    updated_at = body.get("updated_at")
    if updated_at is None:
        updated_at = body.get("updatedAt")
    record = request.app.state.conversations.upsert_rich_messages(
        conv_id,
        uid,
        messages,
        updated_at=float(updated_at) if updated_at is not None else None,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return record


@router.delete("/v1/conversations/{conv_id}")
async def delete_conversation(
    conv_id: str,
    request: Request,
    user_id: str | None = Query(default=None),
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    uid = _resolve_user_id(user_id)
    deleted = request.app.state.conversations.delete_conversation(conv_id, uid)
    if not deleted:
        raise HTTPException(status_code=404, detail="会话不存在")
    return {"ok": True, "id": conv_id, "user_id": uid}
