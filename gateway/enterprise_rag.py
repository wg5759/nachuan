"""Enterprise RAG v2 API boundary; storage/authz remain deliberately closed."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from gateway.auth import require_api_key
from gateway.enterprise_context import (
    EnterpriseRequestContext,
    require_enterprise_context,
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
    body: EnterpriseRagQueryRequest,
    context: Annotated[EnterpriseRequestContext, Depends(require_enterprise_context)],
) -> dict[str, object]:
    del body, context
    # Never fall back to the personal KnowledgeBase. RAG-ACL-002 through 007
    # must provide knowledge_v2, AuthzFacade, epoch fences and output controls.
    raise HTTPException(status_code=503, detail="enterprise_rag_not_ready")


__all__ = ["EnterpriseRagQueryRequest", "router"]
