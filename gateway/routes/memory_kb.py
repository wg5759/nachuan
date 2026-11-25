"""记忆、案例库、知识库、意图识别与网页阅读路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from gateway.auth import require_api_key
from gateway.schemas import ChatCompletionRequest, ChatMessage
from orchestrator.intent import classify_intent
from orchestrator.knowledge import build_context as kb_context
from orchestrator.modes import pick_model
from orchestrator.webread import read_and_summarize

router = APIRouter(tags=["memory-kb"])


def _app_mod():
    import gateway.app as _mod

    return _mod


def _normalized_mutation_id(value: Any, *, label: str, max_length: int = 256) -> str:
    """Canonicalize a destructive-operation target before capability binding."""
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail=f"{label} 必须是字符串")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized)
    ):
        raise HTTPException(status_code=422, detail=f"{label} 格式无效")
    return normalized


async def _destructive_request_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    return body


def _destructive_user_id(body: dict[str, Any]) -> str:
    raw = body.get("user_id")
    if raw in (None, ""):
        raw = _app_mod().get_settings().agent_user_id or "owner"
    return _normalized_mutation_id(raw, label="user_id", max_length=128)


def _has_approval_id(body: dict[str, Any]) -> bool:
    return body.get("approval_id") not in (None, "", 0, "0")


def _snapshot_hash(rows: Any) -> tuple[str, int]:
    """Hash ordered SQLite rows without putting deleted content in approval rows."""
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        encoded = json.dumps(
            list(row), ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return digest.hexdigest(), count


def _memory_clear_spec(user_id: str, app_state: Any | None = None) -> dict[str, Any]:
    state = app_state if app_state is not None else _app_mod().app.state
    store = state.memory
    with store._lock:  # noqa: SLF001 - same-process transactional snapshot
        rows = store._conn.execute(  # noqa: SLF001
            "SELECT id,text,kind,status,source,created_at,updated_at "
            "FROM user_memory WHERE user_id=? ORDER BY id",
            (user_id,),
        )
        state_sha256, records = _snapshot_hash(rows)
    return {
        "target": {"kind": "memory_user", "user_id": user_id},
        "snapshot": {"sha256": state_sha256, "records": records},
    }


def _knowledge_delete_spec(
    user_id: str, doc_id: int, app_state: Any | None = None
) -> dict[str, Any]:
    state = app_state if app_state is not None else _app_mod().app.state
    kb = state.kb
    with kb._lock:  # noqa: SLF001 - exact same-process document snapshot
        doc = kb._conn.execute(  # noqa: SLF001
            "SELECT id,user_id,title,source,chunks,created_at "
            "FROM kb_docs WHERE user_id=? AND id=?",
            (user_id, doc_id),
        ).fetchone()
        if doc is None:
            state_sha256, records = _snapshot_hash([])
            exists = False
        else:
            chunk_rows = kb._conn.execute(  # noqa: SLF001
                "SELECT id,user_id,doc_id,title,text FROM kb_chunks "
                "WHERE user_id=? AND doc_id=? ORDER BY id",
                (user_id, doc_id),
            ).fetchall()
            state_sha256, records = _snapshot_hash([("doc", *doc), *chunk_rows])
            exists = True
    return {
        "target": {
            "kind": "knowledge_document",
            "user_id": user_id,
            "doc_id": doc_id,
        },
        "snapshot": {
            "sha256": state_sha256,
            "records": records,
            "exists": exists,
        },
    }


@router.get("/v1/agent/memory")
async def list_memory(
    user_id: str, request: Request, _: str = Depends(require_api_key)
):
    """查看某用户已学到的长期记忆（供验证与“进化看板”）。"""
    return {"user_id": user_id, "memories": request.app.state.memory.all_for(user_id)}


@router.delete("/v1/agent/memory")
async def clear_memory_legacy(_: str = Depends(require_api_key)):
    """The legacy body-less DELETE cannot carry an exact one-time capability."""
    raise HTTPException(
        status_code=410,
        detail="请使用 POST /v1/agent/memory/clear 走一次性审批",
    )


@router.post("/v1/agent/memory/clear")
async def clear_memory_approved(request: Request, _: str = Depends(require_api_key)):
    """Clear one user's exact reviewed memory snapshot after one-time approval."""
    app_mod = _app_mod()
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _memory_clear_spec(user_id, request.app.state)
    if not _has_approval_id(body) and spec["snapshot"]["records"] == 0:
        return {"ok": True, "user_id": user_id, "already_empty": True}
    task = f"清空长期记忆：{user_id}"
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=str(Path(app_mod.get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="memory_clear",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _memory_clear_spec(user_id, request.app.state) != spec:
            raise HTTPException(status_code=409, detail="记忆已变化，请重新审批")
        request.app.state.memory.clear(user_id)
        if _memory_clear_spec(user_id, request.app.state)["snapshot"]["records"] != 0:
            raise RuntimeError("memory clear did not remove the reviewed target")
    except Exception:
        request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    request.app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "user_id": user_id}


@router.get("/v1/agent/cases")
async def list_cases(
    user_id: str, request: Request, _: str = Depends(require_api_key)
):
    """查看某用户的“技能/案例库”（强模型解过、可被免费模型复用的难题）。"""
    return {"user_id": user_id, "cases": request.app.state.cases.all_for(user_id)}


@router.get("/v1/kb/docs")
async def kb_list(user_id: str, request: Request, _: str = Depends(require_api_key)):
    """列出某用户知识库的文档。"""
    return {"user_id": user_id, "docs": request.app.state.kb.list_documents(user_id)}


@router.post("/v1/kb/docs")
async def kb_import(request: Request, _: str = Depends(require_api_key)):
    """导入一篇文档到知识库：{user_id,title,text,source}。分块入库。"""
    body = await request.json()
    text = str(body.get("text") or "")
    if not text.strip():
        raise HTTPException(status_code=422, detail="需要 text 文本内容")
    return request.app.state.kb.add_document(
        str(body.get("user_id") or "owner"),
        str(body.get("title") or "未命名"),
        text,
        str(body.get("source") or ""),
    )


@router.delete("/v1/kb/docs/{doc_id}")
async def kb_delete_legacy(doc_id: int, _: str = Depends(require_api_key)):
    """The legacy body-less DELETE cannot carry an exact one-time capability."""
    del doc_id
    raise HTTPException(
        status_code=410,
        detail="请使用 POST /v1/kb/docs/{doc_id}/delete 走一次性审批",
    )


@router.post("/v1/kb/docs/{doc_id}/delete")
async def kb_delete_approved(
    doc_id: int, request: Request, _: str = Depends(require_api_key)
):
    """Delete the exact reviewed document and chunk snapshot once."""
    app_mod = _app_mod()
    if doc_id <= 0:
        raise HTTPException(status_code=422, detail="doc_id 必须是正整数")
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _knowledge_delete_spec(user_id, doc_id, request.app.state)
    if not spec["snapshot"]["exists"] and not _has_approval_id(body):
        raise HTTPException(status_code=404, detail="知识库文档不存在")
    task = f"删除知识库文档：user={user_id}, doc_id={doc_id}"
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=str(Path(app_mod.get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="knowledge_document_delete",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _knowledge_delete_spec(user_id, doc_id, request.app.state) != spec:
            raise HTTPException(status_code=409, detail="知识库文档已变化，请重新审批")
        deleted = request.app.state.kb.delete_document(user_id, doc_id)
        if (
            not deleted
            or _knowledge_delete_spec(user_id, doc_id, request.app.state)["snapshot"][
                "exists"
            ]
        ):
            raise RuntimeError("knowledge document delete did not remove the reviewed target")
    except Exception:
        request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    request.app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "user_id": user_id, "doc_id": doc_id}


@router.post("/v1/kb/query")
async def kb_query(request: Request, _: str = Depends(require_api_key)):
    """问知识库：检索相关分块 → 模型据实带引用回答。返回 {answer, sources}。"""
    app_mod = _app_mod()
    body = await request.json()
    user_id = str(body.get("user_id") or "owner")
    query = str(body.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=422, detail="需要 query")
    router_obj = request.app.state.router
    hits = request.app.state.kb.search(user_id, query, k=int(body.get("k") or 5))
    if not hits:
        return {"answer": "知识库里没找到相关内容。", "sources": []}
    model = (
        "agnes-flash"
        if router_obj.resolve("agnes-flash")
        else (pick_model(router_obj, "cheap") or "echo")
    )
    req = ChatCompletionRequest(
        model=model,
        messages=[
            ChatMessage(
                role="system",
                content=kb_context(hits)
                + "\n\n只依据以上资料回答用户问题，引用处标[编号]；资料里没有就说「知识库里没有」、别编。",
            ),
            ChatMessage(role="user", content=query),
        ],
    )
    try:
        res, served, _route = await app_mod.chat_with_fallback(router_obj, req)
        answer = (res.get("choices") or [{}])[0].get("message", {}).get("content", "")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail="知识库回答失败，请到诊断中心查看详情",
            headers={"Cache-Control": "no-store"},
        ) from exc
    sources = [
        {"doc_id": h["doc_id"], "title": h["title"], "score": h["score"]} for h in hits
    ]
    return {
        "answer": answer,
        "sources": sources,
        "model": served,
        "usage": res.get("usage") or {},
    }


@router.post("/v1/intent")
async def intent_classify(request: Request, _: str = Depends(require_api_key)):
    """意图分类（#17）：{message} → {intent}。免费模型判，比正则准；任何端共享（#15）。"""
    body = await request.json()
    message = str(body.get("message") or "").strip()
    if not message:
        return {"intent": "chat"}
    intent = await classify_intent(request.app.state.router, message)
    return {"intent": intent}


@router.post("/v1/web/read")
async def web_read(request: Request, _: str = Depends(require_api_key)):
    """贴网页链接 → 抓正文 + 模型总结。body: {url, question?, model?}。视频链接请走 /v1/lapian/url。"""
    body = await request.json()
    raw = str(body.get("url") or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="需要 url")
    m = re.search(r"https?://[^\s，。、）)】」\"']+", raw)
    url = m.group(0) if m else raw
    try:
        return await read_and_summarize(
            request.app.state.router,
            url,
            question=str(body.get("question") or ""),
            model=str(body.get("model") or ""),
        )
    except Exception as e:  # noqa: BLE001
        from gateway.providers.base import friendly_error

        raise HTTPException(status_code=502, detail=f"网页抓取失败：{friendly_error(e)}")
