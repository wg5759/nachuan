"""Trusted orchestration seam for the fail-closed enterprise RAG API.

The production app does not install this coordinator until real enterprise
identity, authorization, storage, vector, DLP and model-route authorities are
available.  Local acceptance can exercise the complete ACL-001..007 chain
without falling back to the personal knowledge base.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from gateway.enterprise_authz import EnterpriseAuthorizationFacade
from gateway.enterprise_context import EnterpriseRequestContext
from gateway.enterprise_rag_audit import (
    EnterpriseRagAuditEvent,
    EnterpriseRagAuditLog,
    EnterpriseRagAuditUnavailable,
)
from gateway.enterprise_generation import (
    EnterpriseGeneratedOutput,
    EnterpriseGenerationError,
    EnterpriseModelRoutePolicy,
)
from gateway.enterprise_rag_plugins import (
    EnterpriseRagPluginError,
    EnterpriseRagPluginRuntime,
)
from gateway.enterprise_retrieval import EnterpriseRetrievalError


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_QUERY_CHARS = 16_384
_MAX_MODEL_OUTPUT_BYTES = 4 * 1024 * 1024


class EnterpriseRagQueryError(RuntimeError):
    """Base error whose text is safe to expose only as a generic category."""


class EnterpriseRagQueryUnavailable(EnterpriseRagQueryError):
    pass


class EnterpriseRagQueryBlocked(EnterpriseRagQueryError):
    pass


class _EnterpriseRagAuditWriteFailed(EnterpriseRagQueryUnavailable):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseRagQueryBlocked(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EnterpriseRagQueryBlocked(f"{field} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EnterpriseRagModelChunk:
    chunk_id: str
    text: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "chunk_id", _identifier(self.chunk_id, "chunk_id"))
        if not isinstance(self.text, str) or not self.text:
            raise EnterpriseRagQueryBlocked("model chunk text is invalid")
        self.text.encode("utf-8", errors="strict")


@dataclass(frozen=True, slots=True)
class EnterpriseRagModelRequest:
    model_id: str
    query: str
    chunks: tuple[EnterpriseRagModelChunk, ...]
    obligations: tuple[str, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_id", _identifier(self.model_id, "model_id"))
        if not isinstance(self.query, str) or not 1 <= len(self.query) <= _MAX_QUERY_CHARS:
            raise EnterpriseRagQueryBlocked("model query is invalid")
        self.query.encode("utf-8", errors="strict")
        if not isinstance(self.chunks, tuple) or not self.chunks or any(
            not isinstance(chunk, EnterpriseRagModelChunk) for chunk in self.chunks
        ):
            raise EnterpriseRagQueryBlocked("model chunks are invalid")
        if not isinstance(self.obligations, tuple) or any(
            not isinstance(item, str) or _ID.fullmatch(item) is None
            for item in self.obligations
        ):
            raise EnterpriseRagQueryBlocked("model obligations are invalid")
        object.__setattr__(
            self, "manifest_digest", _digest(self.manifest_digest, "manifest_digest")
        )


@dataclass(frozen=True, slots=True)
class EnterpriseRagModelResponse:
    text: str
    cited_chunk_ids: tuple[str, ...]
    actual_model_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text:
            raise EnterpriseRagQueryBlocked("model response text is invalid")
        rendered = self.text.encode("utf-8", errors="strict")
        if len(rendered) > _MAX_MODEL_OUTPUT_BYTES:
            raise EnterpriseRagQueryBlocked("model response text is invalid")
        if not isinstance(self.cited_chunk_ids, tuple):
            raise EnterpriseRagQueryBlocked("model citations are invalid")
        citations = tuple(
            _identifier(value, "cited_chunk_id") for value in self.cited_chunk_ids
        )
        if len(set(citations)) != len(citations):
            raise EnterpriseRagQueryBlocked("model citations contain duplicates")
        object.__setattr__(self, "cited_chunk_ids", citations)
        object.__setattr__(
            self,
            "actual_model_id",
            _identifier(self.actual_model_id, "actual_model_id"),
        )


class EnterpriseRagModelAdapter(Protocol):
    def generate(
        self,
        *,
        request: EnterpriseRagModelRequest,
        deadline_monotonic: float,
    ) -> EnterpriseRagModelResponse: ...


@dataclass(frozen=True, slots=True)
class EnterpriseRagQueryResult:
    status: Literal["ok", "insufficient_authorized_context"]
    answer: str
    cited_chunk_ids: tuple[str, ...]
    model_id: str
    receipt_id: str


class EnterpriseRagQueryCoordinator:
    """Compose trusted RAG authorities while exposing only model-safe bytes."""

    def __init__(
        self,
        *,
        runtime: EnterpriseRagPluginRuntime,
        authorization: EnterpriseAuthorizationFacade,
        content_reader: object,
        fence_checker: object,
        route_resolver: Callable[
            [EnterpriseRequestContext], EnterpriseModelRoutePolicy
        ],
        corpus_epoch_resolver: Callable[[EnterpriseRequestContext], int],
        model: EnterpriseRagModelAdapter,
        audit_key: bytes,
        audit_log: EnterpriseRagAuditLog,
        model_timeout_seconds: float = 60.0,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(runtime, EnterpriseRagPluginRuntime):
            raise TypeError("enterprise RAG runtime is invalid")
        if not isinstance(authorization, EnterpriseAuthorizationFacade):
            raise TypeError("enterprise authorization is invalid")
        if not callable(getattr(content_reader, "read_many", None)):
            raise TypeError("enterprise content reader is invalid")
        if not callable(getattr(fence_checker, "is_scope_fenced", None)):
            raise TypeError("enterprise fence checker is invalid")
        if not callable(route_resolver) or not callable(corpus_epoch_resolver):
            raise TypeError("enterprise RAG resolvers are invalid")
        if not callable(getattr(model, "generate", None)):
            raise TypeError("enterprise model adapter is invalid")
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise TypeError("enterprise RAG audit key is invalid")
        if not isinstance(audit_log, EnterpriseRagAuditLog):
            raise TypeError("enterprise RAG audit log is invalid")
        if (
            isinstance(model_timeout_seconds, bool)
            or not isinstance(model_timeout_seconds, (int, float))
            or not math.isfinite(float(model_timeout_seconds))
            or not 0.01 <= float(model_timeout_seconds) <= 120.0
            or not callable(monotonic_clock)
        ):
            raise TypeError("enterprise model timeout is invalid")
        self._runtime = runtime
        self._authorization = authorization
        self._content_reader = content_reader
        self._fence_checker = fence_checker
        self._route_resolver = route_resolver
        self._corpus_epoch_resolver = corpus_epoch_resolver
        self._model = model
        self._audit_key = bytes(audit_key)
        self._audit_log = audit_log
        self._model_timeout_seconds = float(model_timeout_seconds)
        self._clock = monotonic_clock

    def execute(
        self,
        *,
        context: EnterpriseRequestContext,
        query: str,
        k: int,
    ) -> EnterpriseRagQueryResult:
        if not isinstance(context, EnterpriseRequestContext):
            raise EnterpriseRagQueryBlocked("enterprise context is invalid")
        if not isinstance(query, str) or not 1 <= len(query) <= _MAX_QUERY_CHARS:
            raise EnterpriseRagQueryBlocked("enterprise query is invalid")
        query.encode("utf-8", errors="strict")
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 20:
            raise EnterpriseRagQueryBlocked("enterprise query limit is invalid")
        query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        try:
            return self._execute_core(context=context, query=query, k=k)
        except _EnterpriseRagAuditWriteFailed:
            raise
        except EnterpriseRagQueryBlocked:
            self._append_failure_audit(
                context=context,
                query_digest=query_digest,
                requested_k=k,
                status="blocked",
                error_code="enterprise_rag_blocked",
            )
            raise
        except EnterpriseRagQueryUnavailable:
            self._append_failure_audit(
                context=context,
                query_digest=query_digest,
                requested_k=k,
                status="unavailable",
                error_code="enterprise_rag_unavailable",
            )
            raise

    def _execute_core(
        self,
        *,
        context: EnterpriseRequestContext,
        query: str,
        k: int,
    ) -> EnterpriseRagQueryResult:
        if not isinstance(context, EnterpriseRequestContext):
            raise EnterpriseRagQueryBlocked("enterprise context is invalid")
        if not isinstance(query, str) or not 1 <= len(query) <= _MAX_QUERY_CHARS:
            raise EnterpriseRagQueryBlocked("enterprise query is invalid")
        query.encode("utf-8", errors="strict")
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 20:
            raise EnterpriseRagQueryBlocked("enterprise query limit is invalid")
        readiness = self._runtime.readiness_snapshot()
        if (
            not isinstance(readiness, dict)
            or readiness.get("components_ready") is not True
            or readiness.get("dlp_mode") != "configured"
        ):
            raise EnterpriseRagQueryUnavailable("enterprise RAG components unavailable")
        try:
            retrieval = self._runtime.retrieve(
                context=context,
                query=query,
                k=k,
                authorization=self._authorization,
                content_reader=self._content_reader,
                fence_checker=self._fence_checker,
            )
        except (EnterpriseRetrievalError, EnterpriseRagPluginError):
            raise EnterpriseRagQueryUnavailable(
                "enterprise RAG retrieval unavailable"
            ) from None
        if not retrieval.chunks:
            result = EnterpriseRagQueryResult(
                status="insufficient_authorized_context",
                answer="",
                cited_chunk_ids=(),
                model_id="",
                receipt_id=self._insufficient_context_receipt(context, retrieval),
            )
            self._append_audit(
                context=context,
                query_digest=retrieval.query_digest,
                requested_k=k,
                authorized_chunk_count=0,
                result=result,
            )
            return result
        try:
            route = self._route_resolver(context)
            corpus_epoch = self._corpus_epoch_resolver(context)
        except Exception:
            raise EnterpriseRagQueryUnavailable(
                "enterprise RAG policy authority unavailable"
            ) from None
        if not isinstance(route, EnterpriseModelRoutePolicy):
            raise EnterpriseRagQueryUnavailable("enterprise model route unavailable")
        if (
            isinstance(corpus_epoch, bool)
            or not isinstance(corpus_epoch, int)
            or corpus_epoch < 1
        ):
            raise EnterpriseRagQueryUnavailable("enterprise corpus epoch unavailable")
        try:
            prepared = self._runtime.prepare_generation(
                context=context,
                retrieval=retrieval,
                corpus_epoch=corpus_epoch,
                route=route,
                authorization=self._authorization,
                fence_checker=self._fence_checker,
                audit_key=self._audit_key,
            )
        except (EnterpriseGenerationError, EnterpriseRagPluginError):
            raise EnterpriseRagQueryBlocked("enterprise context blocked") from None
        request = EnterpriseRagModelRequest(
            model_id=prepared.route.model_id,
            query=query,
            chunks=tuple(
                EnterpriseRagModelChunk(chunk_id=chunk.chunk_id, text=chunk.text)
                for chunk in prepared.context_chunks
            ),
            obligations=prepared.manifest.obligations,
            manifest_digest=prepared.manifest.manifest_digest,
        )
        deadline = self._clock() + self._model_timeout_seconds
        try:
            response = self._model.generate(
                request=request,
                deadline_monotonic=deadline,
            )
        except EnterpriseRagQueryBlocked:
            raise
        except Exception:
            raise EnterpriseRagQueryUnavailable(
                "enterprise model unavailable"
            ) from None
        if self._clock() > deadline:
            raise EnterpriseRagQueryUnavailable("enterprise model timed out")
        if not isinstance(response, EnterpriseRagModelResponse):
            raise EnterpriseRagQueryBlocked("enterprise model response blocked")
        if response.actual_model_id != route.model_id:
            raise EnterpriseRagQueryBlocked("enterprise model identity changed")
        try:
            output: EnterpriseGeneratedOutput = self._runtime.validate_output(
                context=context,
                prepared=prepared,
                text=response.text,
                cited_chunk_ids=response.cited_chunk_ids,
                authorization=self._authorization,
                fence_checker=self._fence_checker,
                audit_key=self._audit_key,
            )
        except (EnterpriseGenerationError, EnterpriseRagPluginError):
            raise EnterpriseRagQueryBlocked("enterprise output blocked") from None
        result = EnterpriseRagQueryResult(
            status="ok",
            answer=output.text,
            cited_chunk_ids=output.cited_chunk_ids,
            model_id=route.model_id,
            receipt_id=output.receipt_id,
        )
        self._append_audit(
            context=context,
            query_digest=retrieval.query_digest,
            requested_k=k,
            authorized_chunk_count=len(prepared.authorized_chunks),
            result=result,
        )
        return result

    def _insufficient_context_receipt(self, context, retrieval) -> str:
        subject_scope = self._subject_scope_fingerprint(context)
        receipt = {
            "status": "insufficient_authorized_context",
            "tenant_id": context.tenant_id,
            "subject_scope_fingerprint": subject_scope,
            "policy_epoch": context.policy_epoch,
            "session_epoch": context.session_epoch,
            "query_digest": _digest(retrieval.query_digest, "query_digest"),
            "pages_scanned": retrieval.pages_scanned,
            "exhausted": retrieval.exhausted,
            "reason_codes": retrieval.reason_codes,
        }
        return hmac.new(
            self._audit_key,
            _canonical_json(receipt),
            hashlib.sha256,
        ).hexdigest()

    def _subject_scope_fingerprint(self, context) -> str:
        return hmac.new(
            self._audit_key,
            _canonical_json(
                {
                    "subject_id": context.subject_id,
                    "session_id": context.session_id,
                    "groups": context.groups,
                    "roles": context.roles,
                    "attributes": dict(context.attributes),
                    "purpose": context.purpose,
                    "device_trust": context.device_trust,
                    "region": context.region,
                }
            ),
            hashlib.sha256,
        ).hexdigest()

    def _append_audit(
        self,
        *,
        context,
        query_digest,
        requested_k,
        authorized_chunk_count,
        result,
    ) -> None:
        try:
            self._audit_log.append(
                EnterpriseRagAuditEvent(
                    tenant_id=context.tenant_id,
                    subject_scope_fingerprint=self._subject_scope_fingerprint(context),
                    status=result.status,
                    policy_epoch=context.policy_epoch,
                    session_epoch=context.session_epoch,
                    query_digest=query_digest,
                    requested_k=requested_k,
                    authorized_chunk_count=authorized_chunk_count,
                    cited_chunk_ids=result.cited_chunk_ids,
                    model_id=result.model_id,
                    receipt_id=result.receipt_id,
                    error_code=(
                        "insufficient_authorized_context"
                        if result.status == "insufficient_authorized_context"
                        else ""
                    ),
                )
            )
        except EnterpriseRagAuditUnavailable:
            raise _EnterpriseRagAuditWriteFailed(
                "enterprise RAG audit unavailable"
            ) from None

    def _append_failure_audit(
        self,
        *,
        context,
        query_digest,
        requested_k,
        status,
        error_code,
    ) -> None:
        receipt_id = hmac.new(
            self._audit_key,
            _canonical_json(
                {
                    "status": status,
                    "tenant_id": context.tenant_id,
                    "subject_scope_fingerprint": self._subject_scope_fingerprint(
                        context
                    ),
                    "policy_epoch": context.policy_epoch,
                    "session_epoch": context.session_epoch,
                    "query_digest": query_digest,
                    "requested_k": requested_k,
                    "error_code": error_code,
                }
            ),
            hashlib.sha256,
        ).hexdigest()
        try:
            self._audit_log.append(
                EnterpriseRagAuditEvent(
                    tenant_id=context.tenant_id,
                    subject_scope_fingerprint=self._subject_scope_fingerprint(context),
                    status=status,
                    policy_epoch=context.policy_epoch,
                    session_epoch=context.session_epoch,
                    query_digest=query_digest,
                    requested_k=requested_k,
                    authorized_chunk_count=0,
                    cited_chunk_ids=(),
                    model_id="",
                    receipt_id=receipt_id,
                    error_code=error_code,
                )
            )
        except EnterpriseRagAuditUnavailable:
            raise _EnterpriseRagAuditWriteFailed(
                "enterprise RAG audit unavailable"
            ) from None


__all__ = [
    "EnterpriseRagModelAdapter",
    "EnterpriseRagModelChunk",
    "EnterpriseRagModelRequest",
    "EnterpriseRagModelResponse",
    "EnterpriseRagQueryBlocked",
    "EnterpriseRagQueryCoordinator",
    "EnterpriseRagQueryError",
    "EnterpriseRagQueryResult",
    "EnterpriseRagQueryUnavailable",
]
