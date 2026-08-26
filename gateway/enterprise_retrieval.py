"""Permission-aware enterprise retrieval that authorizes before plaintext reads."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from .enterprise_authz import (
    EnterpriseAuthorizationFacade,
    EnterpriseAuthorizationResource,
)
from .enterprise_context import EnterpriseRequestContext

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_QUERY_UTF8_BYTES = 64 * 1024
_MAX_AUTHORIZED_TEXT_UTF8_BYTES = 2 * 1024 * 1024


class EnterpriseRetrievalError(RuntimeError):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseRetrievalError(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EnterpriseRetrievalError(f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class EnterpriseVectorCandidate:
    tenant_id: str
    chunk_id: str
    document_id: str
    policy_id: str
    policy_epoch: int
    classification: int
    content_hash: str
    score: float

    def __post_init__(self) -> None:
        for field in ("tenant_id", "chunk_id", "document_id", "policy_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        object.__setattr__(self, "content_hash", _digest(self.content_hash, "content_hash"))
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseRetrievalError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise EnterpriseRetrievalError("classification is invalid")
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            raise EnterpriseRetrievalError("score is invalid")
        if not math.isfinite(float(self.score)):
            raise EnterpriseRetrievalError("score is invalid")


@dataclass(frozen=True, slots=True)
class EnterpriseCandidatePage:
    candidates: tuple[EnterpriseVectorCandidate, ...]
    next_cursor: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.candidates, tuple) or len(self.candidates) > 512:
            raise EnterpriseRetrievalError("candidate page is invalid")
        if self.next_cursor is not None:
            _identifier(self.next_cursor, "next_cursor")


class EnterpriseCandidateSource(Protocol):
    def search(
        self,
        *,
        tenant_id: str,
        query: str,
        limit: int,
        cursor: str | None,
    ) -> EnterpriseCandidatePage: ...


@dataclass(frozen=True, slots=True)
class EnterpriseContentRecord:
    tenant_id: str
    chunk_id: str
    content_hash: str
    text: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "chunk_id", _identifier(self.chunk_id, "chunk_id"))
        object.__setattr__(self, "content_hash", _digest(self.content_hash, "content_hash"))
        if not isinstance(self.text, str) or not self.text:
            raise EnterpriseRetrievalError("content text is invalid")
        self.text.encode("utf-8", errors="strict")


class EnterpriseContentReader(Protocol):
    def read_many(
        self, *, tenant_id: str, chunk_ids: tuple[str, ...]
    ) -> Sequence[EnterpriseContentRecord]: ...


class EnterpriseScopeFenceChecker(Protocol):
    def is_scope_fenced(
        self,
        *,
        tenant_id: str,
        resource_scope: str,
        expected_policy_epoch: int,
    ) -> bool: ...


class EnterpriseAuthorizedReranker(Protocol):
    def rerank(
        self,
        *,
        query: str,
        chunks: tuple[EnterpriseAuthorizedChunk, ...],
    ) -> Sequence[str]: ...


@dataclass(frozen=True, slots=True)
class EnterpriseAuthorizedChunk:
    tenant_id: str
    chunk_id: str
    document_id: str
    policy_id: str
    policy_epoch: int
    classification: int
    content_hash: str
    score: float
    text: str
    decision_id: str
    obligations: tuple[str, ...]

    def __post_init__(self) -> None:
        for field in ("tenant_id", "chunk_id", "document_id", "policy_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        object.__setattr__(self, "content_hash", _digest(self.content_hash, "content_hash"))
        object.__setattr__(self, "decision_id", _digest(self.decision_id, "decision_id"))
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseRetrievalError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise EnterpriseRetrievalError("classification is invalid")
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            raise EnterpriseRetrievalError("score is invalid")
        if not math.isfinite(float(self.score)):
            raise EnterpriseRetrievalError("score is invalid")
        if not isinstance(self.text, str) or not self.text:
            raise EnterpriseRetrievalError("authorized text is invalid")
        if hashlib.sha256(self.text.encode("utf-8", errors="strict")).hexdigest() != self.content_hash:
            raise EnterpriseRetrievalError("authorized content integrity failed")
        if not isinstance(self.obligations, tuple) or len(self.obligations) > 32:
            raise EnterpriseRetrievalError("obligations are invalid")
        normalized = tuple(sorted({_identifier(value, "obligation") for value in self.obligations}))
        if len(normalized) != len(self.obligations):
            raise EnterpriseRetrievalError("obligations contain duplicates")
        object.__setattr__(self, "obligations", normalized)


@dataclass(frozen=True, slots=True)
class EnterpriseRetrievalResult:
    chunks: tuple[EnterpriseAuthorizedChunk, ...]
    query_digest: str
    pages_scanned: int
    exhausted: bool
    reason_codes: tuple[str, ...]


class EnterpriseCitationAuthorizationGuard:
    """Kernel-owned citation recheck; plugins never decide authorization."""

    def __init__(
        self,
        *,
        authorization: EnterpriseAuthorizationFacade,
        fence_checker: EnterpriseScopeFenceChecker,
    ) -> None:
        if not isinstance(authorization, EnterpriseAuthorizationFacade):
            raise EnterpriseRetrievalError("authorization is invalid")
        if not callable(getattr(fence_checker, "is_scope_fenced", None)):
            raise EnterpriseRetrievalError("fence_checker is invalid")
        self._authorization = authorization
        self._fences = fence_checker

    def revalidate_citations(
        self,
        *,
        context: EnterpriseRequestContext,
        chunks: Iterable[EnterpriseAuthorizedChunk],
    ) -> tuple[EnterpriseAuthorizedChunk, ...]:
        candidates = tuple(chunks)
        if not candidates:
            return ()
        if any(chunk.tenant_id != context.tenant_id for chunk in candidates):
            raise EnterpriseRetrievalError("citation tenant boundary violated")
        unfenced: list[EnterpriseAuthorizedChunk] = []
        for chunk in candidates:
            try:
                fenced = self._fences.is_scope_fenced(
                    tenant_id=context.tenant_id,
                    resource_scope=chunk.document_id,
                    expected_policy_epoch=context.policy_epoch,
                )
            except Exception:  # noqa: BLE001 -- dependency errors fail closed
                raise EnterpriseRetrievalError(
                    "citation fence check unavailable"
                ) from None
            if not isinstance(fenced, bool):
                raise EnterpriseRetrievalError("citation fence result is invalid")
            if not fenced:
                unfenced.append(chunk)
        if not unfenced:
            return ()
        resources = tuple(
            EnterpriseAuthorizationResource(
                tenant_id=chunk.tenant_id,
                resource_type="chunk",
                resource_id=chunk.chunk_id,
                policy_id=chunk.policy_id,
                policy_epoch=chunk.policy_epoch,
                classification=chunk.classification,
            )
            for chunk in unfenced
        )
        decisions = self._authorization.batch_check(context, resources)
        return tuple(
            replace(
                chunk,
                decision_id=decision.decision_id,
                obligations=decision.obligations,
            )
            for chunk, decision in zip(unfenced, decisions, strict=True)
            if decision.allowed
        )


class EnterprisePermissionAwareRetriever:
    def __init__(
        self,
        *,
        candidate_source: EnterpriseCandidateSource,
        authorization: EnterpriseAuthorizationFacade,
        content_reader: EnterpriseContentReader,
        fence_checker: EnterpriseScopeFenceChecker,
        reranker: EnterpriseAuthorizedReranker | None = None,
        oversample_factor: int = 4,
        max_pages: int = 8,
    ):
        if not callable(getattr(candidate_source, "search", None)):
            raise EnterpriseRetrievalError("candidate_source is invalid")
        if not isinstance(authorization, EnterpriseAuthorizationFacade):
            raise EnterpriseRetrievalError("authorization is invalid")
        if not callable(getattr(content_reader, "read_many", None)):
            raise EnterpriseRetrievalError("content_reader is invalid")
        if not callable(getattr(fence_checker, "is_scope_fenced", None)):
            raise EnterpriseRetrievalError("fence_checker is invalid")
        if reranker is not None and not callable(getattr(reranker, "rerank", None)):
            raise EnterpriseRetrievalError("reranker is invalid")
        if (
            isinstance(oversample_factor, bool)
            or not isinstance(oversample_factor, int)
            or not 2 <= oversample_factor <= 10
        ):
            raise EnterpriseRetrievalError("oversample_factor is invalid")
        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or not 1 <= max_pages <= 20
        ):
            raise EnterpriseRetrievalError("max_pages is invalid")
        self._candidates = candidate_source
        self._authorization = authorization
        self._content = content_reader
        self._fences = fence_checker
        self._citation_guard = EnterpriseCitationAuthorizationGuard(
            authorization=authorization,
            fence_checker=fence_checker,
        )
        self._reranker = reranker
        self._oversample_factor = oversample_factor
        self._max_pages = max_pages

    def retrieve(
        self,
        *,
        context: EnterpriseRequestContext,
        query: str,
        k: int,
    ) -> EnterpriseRetrievalResult:
        if not isinstance(context, EnterpriseRequestContext):
            raise EnterpriseRetrievalError("context is invalid")
        if not isinstance(query, str) or not query.strip():
            raise EnterpriseRetrievalError("query is invalid")
        query_bytes = query.encode("utf-8", errors="strict")
        if len(query_bytes) > _MAX_QUERY_UTF8_BYTES:
            raise EnterpriseRetrievalError("query is invalid")
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 50:
            raise EnterpriseRetrievalError("k is invalid")

        query_digest = hashlib.sha256(query_bytes).hexdigest()
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_chunks: set[str] = set()
        authorized: list[EnterpriseAuthorizedChunk] = []
        pages_scanned = 0
        exhausted = False
        while len(authorized) < k and pages_scanned < self._max_pages:
            page = self._candidates.search(
                tenant_id=context.tenant_id,
                query=query,
                limit=min(512, max(k, (k - len(authorized)) * self._oversample_factor)),
                cursor=cursor,
            )
            if not isinstance(page, EnterpriseCandidatePage):
                raise EnterpriseRetrievalError("candidate source result is invalid")
            pages_scanned += 1
            if any(candidate.tenant_id != context.tenant_id for candidate in page.candidates):
                raise EnterpriseRetrievalError("candidate tenant boundary violated")
            page_ids = [candidate.chunk_id for candidate in page.candidates]
            if len(set(page_ids)) != len(page_ids) or any(
                chunk_id in seen_chunks for chunk_id in page_ids
            ):
                raise EnterpriseRetrievalError("candidate pagination closure drifted")
            seen_chunks.update(page_ids)
            if page.next_cursor is not None:
                if page.next_cursor in seen_cursors:
                    raise EnterpriseRetrievalError("candidate cursor cycle detected")
                seen_cursors.add(page.next_cursor)

            eligible_candidates: list[EnterpriseVectorCandidate] = []
            for candidate in page.candidates:
                try:
                    fenced = self._fences.is_scope_fenced(
                        tenant_id=context.tenant_id,
                        resource_scope=candidate.document_id,
                        expected_policy_epoch=context.policy_epoch,
                    )
                except Exception:  # noqa: BLE001 -- dependency errors fail closed
                    raise EnterpriseRetrievalError("policy fence check unavailable") from None
                if not isinstance(fenced, bool):
                    raise EnterpriseRetrievalError("policy fence result is invalid")
                if not fenced:
                    eligible_candidates.append(candidate)
            resources = tuple(
                EnterpriseAuthorizationResource(
                    tenant_id=candidate.tenant_id,
                    resource_type="chunk",
                    resource_id=candidate.chunk_id,
                    policy_id=candidate.policy_id,
                    policy_epoch=candidate.policy_epoch,
                    classification=candidate.classification,
                )
                for candidate in eligible_candidates
            )
            decisions = (
                self._authorization.batch_check(context, resources) if resources else ()
            )
            allowed = [
                (candidate, decision)
                for candidate, decision in zip(eligible_candidates, decisions, strict=True)
                if decision.allowed
            ]
            if allowed:
                records = self._read_authorized_page(context, allowed)
                authorized.extend(records)
                if self._authorized_bytes(authorized) > _MAX_AUTHORIZED_TEXT_UTF8_BYTES:
                    raise EnterpriseRetrievalError("authorized context exceeds size limit")
            cursor = page.next_cursor
            if cursor is None:
                exhausted = True
                break

        ordered = tuple(authorized)
        if self._reranker is not None and ordered:
            ordered = self._rerank_authorized(query, ordered)
        selected = ordered[:k]
        reason_codes = (
            ("insufficient_authorized_results",) if len(selected) < k else ()
        )
        return EnterpriseRetrievalResult(
            chunks=selected,
            query_digest=query_digest,
            pages_scanned=pages_scanned,
            exhausted=exhausted,
            reason_codes=reason_codes,
        )

    def revalidate_citations(
        self,
        *,
        context: EnterpriseRequestContext,
        chunks: Iterable[EnterpriseAuthorizedChunk],
    ) -> tuple[EnterpriseAuthorizedChunk, ...]:
        return self._citation_guard.revalidate_citations(
            context=context,
            chunks=chunks,
        )

    def _read_authorized_page(self, context, allowed):
        chunk_ids = tuple(candidate.chunk_id for candidate, _decision in allowed)
        returned = self._content.read_many(
            tenant_id=context.tenant_id,
            chunk_ids=chunk_ids,
        )
        if not isinstance(returned, Sequence) or isinstance(returned, (str, bytes)):
            raise EnterpriseRetrievalError("content reader result is invalid")
        if any(not isinstance(record, EnterpriseContentRecord) for record in returned):
            raise EnterpriseRetrievalError("content reader result is invalid")
        by_id = {record.chunk_id: record for record in returned}
        if len(by_id) != len(returned) or set(by_id) != set(chunk_ids):
            raise EnterpriseRetrievalError("content reader closure differs")
        output: list[EnterpriseAuthorizedChunk] = []
        for candidate, decision in allowed:
            record = by_id[candidate.chunk_id]
            if (
                record.tenant_id != context.tenant_id
                or record.content_hash != candidate.content_hash
                or hashlib.sha256(record.text.encode("utf-8")).hexdigest()
                != candidate.content_hash
            ):
                raise EnterpriseRetrievalError("authorized content integrity failed")
            output.append(
                EnterpriseAuthorizedChunk(
                    tenant_id=candidate.tenant_id,
                    chunk_id=candidate.chunk_id,
                    document_id=candidate.document_id,
                    policy_id=candidate.policy_id,
                    policy_epoch=candidate.policy_epoch,
                    classification=candidate.classification,
                    content_hash=candidate.content_hash,
                    score=float(candidate.score),
                    text=record.text,
                    decision_id=decision.decision_id,
                    obligations=decision.obligations,
                )
            )
        return output

    def _rerank_authorized(
        self, query: str, chunks: tuple[EnterpriseAuthorizedChunk, ...]
    ) -> tuple[EnterpriseAuthorizedChunk, ...]:
        assert self._reranker is not None
        ranked_ids = self._reranker.rerank(query=query, chunks=chunks)
        if not isinstance(ranked_ids, Sequence) or isinstance(ranked_ids, (str, bytes)):
            raise EnterpriseRetrievalError("reranker result is invalid")
        if any(not isinstance(chunk_id, str) for chunk_id in ranked_ids):
            raise EnterpriseRetrievalError("reranker result is invalid")
        by_id = {chunk.chunk_id: chunk for chunk in chunks}
        if len(set(ranked_ids)) != len(ranked_ids) or set(ranked_ids) != set(by_id):
            raise EnterpriseRetrievalError("reranker closure differs")
        return tuple(by_id[chunk_id] for chunk_id in ranked_ids)

    @staticmethod
    def _authorized_bytes(chunks: Iterable[EnterpriseAuthorizedChunk]) -> int:
        return sum(len(chunk.text.encode("utf-8")) for chunk in chunks)


__all__ = [
    "EnterpriseAuthorizedChunk",
    "EnterpriseAuthorizedReranker",
    "EnterpriseCandidatePage",
    "EnterpriseCandidateSource",
    "EnterpriseCitationAuthorizationGuard",
    "EnterpriseContentReader",
    "EnterpriseContentRecord",
    "EnterprisePermissionAwareRetriever",
    "EnterpriseRetrievalError",
    "EnterpriseRetrievalResult",
    "EnterpriseScopeFenceChecker",
    "EnterpriseVectorCandidate",
]
