"""Enterprise RAG v2 API boundary; storage/authz remain deliberately closed."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key
from gateway.enterprise_context import (
    EnterpriseRequestContext,
    require_enterprise_context,
)
from gateway.enterprise_rag_query import (
    EnterpriseRagQueryBlocked,
    EnterpriseRagQueryCoordinator,
    EnterpriseRagQueryUnavailable,
)


router = APIRouter(
    prefix="/v1/enterprise/kb",
    dependencies=[Depends(require_api_key)],
)


class EnterpriseRagQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    query: str = Field(min_length=1, max_length=16_384)
    k: int = Field(default=5, ge=1, le=20)


@router.post("/query")
async def enterprise_rag_query(
    request: Request,
    body: EnterpriseRagQueryRequest,
    context: Annotated[EnterpriseRequestContext, Depends(require_enterprise_context)],
) -> dict[str, object]:
    coordinator = getattr(
        request.app.state, "enterprise_rag_query_coordinator", None
    )
    if not isinstance(coordinator, EnterpriseRagQueryCoordinator):
        # Never fall back to the personal KnowledgeBase. Production remains
        # closed until the app installs the exact trusted coordinator with
        # real enterprise identity/storage/Authz/DLP/model authorities.
        raise HTTPException(status_code=503, detail="enterprise_rag_not_ready")
    try:
        result = await run_in_threadpool(
            coordinator.execute,
            context=context,
            query=body.query,
            k=body.k,
        )
    except EnterpriseRagQueryBlocked:
        raise HTTPException(status_code=403, detail="enterprise_rag_blocked") from None
    except EnterpriseRagQueryUnavailable:
        raise HTTPException(
            status_code=503, detail="enterprise_rag_unavailable"
        ) from None
    return {
        "status": result.status,
        "answer": result.answer,
        "cited_chunk_ids": list(result.cited_chunk_ids),
        "model_id": result.model_id,
        "receipt_id": result.receipt_id,
    }


__all__ = ["EnterpriseRagQueryRequest", "router"]
