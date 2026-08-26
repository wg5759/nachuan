from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from gateway.enterprise_authz import (
    EnterpriseAuthorizationFacade,
    EnterprisePolicyComponentDecision,
)
from gateway.enterprise_context import EnterpriseRequestContext
from gateway.enterprise_retrieval import (
    EnterpriseCandidatePage,
    EnterpriseContentRecord,
    EnterprisePermissionAwareRetriever,
    EnterpriseRetrievalError,
    EnterpriseVectorCandidate,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _context(*, epoch: int = 7) -> EnterpriseRequestContext:
    return EnterpriseRequestContext(
        tenant_id="tenant-a",
        subject_id="user-a",
        session_id="session-a",
        groups=("project-red",),
        roles=("employee",),
        attributes={"clearance": 4},
        purpose="support",
        device_trust="managed",
        region="cn-east",
        policy_epoch=epoch,
        session_epoch=3,
    )


def _candidate(
    chunk_id: str,
    text: str,
    *,
    tenant: str = "tenant-a",
    epoch: int = 7,
    score: float = 1.0,
) -> EnterpriseVectorCandidate:
    return EnterpriseVectorCandidate(
        tenant_id=tenant,
        chunk_id=chunk_id,
        document_id=f"document-{chunk_id}",
        policy_id="policy-a",
        policy_epoch=epoch,
        classification=3,
        content_hash=_hash(text),
        score=score,
    )


class _Evaluator:
    def __init__(self, allowed: set[str], *, error: Exception | None = None):
        self.allowed = allowed
        self.error = error
        self.calls = []

    def batch_check(self, *, context, resources, deadline_monotonic):
        self.calls.append(tuple(resource.resource_id for resource in resources))
        if self.error is not None:
            raise self.error
        return tuple(
            EnterprisePolicyComponentDecision(
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                policy_id=resource.policy_id,
                allowed=resource.resource_id in self.allowed,
                policy_epoch=resource.policy_epoch,
                engine_version="test-v1",
                reason_codes=(
                    () if resource.resource_id in self.allowed else ("not_allowed",)
                ),
            )
            for resource in resources
        )


def _authorization(relationship: _Evaluator, attribute: _Evaluator | None = None):
    return EnterpriseAuthorizationFacade(
        relationship_evaluator=relationship,
        attribute_evaluator=attribute or relationship,
        audit_key=b"enterprise-retrieval-test-audit-key-32-bytes",
    )


class _CandidateSource:
    def __init__(self, pages: list[EnterpriseCandidatePage]):
        self.pages = pages
        self.calls = []

    def search(self, *, tenant_id, query, limit, cursor):
        self.calls.append(
            {"tenant_id": tenant_id, "query": query, "limit": limit, "cursor": cursor}
        )
        index = len(self.calls) - 1
        if index >= len(self.pages):
            raise AssertionError("unexpected candidate page request")
        return self.pages[index]


class _ContentReader:
    def __init__(self, contents: dict[str, str], *, override=None):
        self.contents = contents
        self.override = override
        self.calls = []

    def read_many(self, *, tenant_id, chunk_ids):
        self.calls.append((tenant_id, chunk_ids))
        if self.override is not None:
            return self.override
        return tuple(
            EnterpriseContentRecord(
                tenant_id=tenant_id,
                chunk_id=chunk_id,
                content_hash=_hash(self.contents[chunk_id]),
                text=self.contents[chunk_id],
            )
            for chunk_id in chunk_ids
        )


class _FenceChecker:
    def __init__(self, fenced: set[str] | None = None, *, error=None):
        self.fenced = fenced or set()
        self.error = error
        self.calls = []

    def is_scope_fenced(
        self, *, tenant_id, resource_scope, expected_policy_epoch
    ):
        self.calls.append((tenant_id, resource_scope, expected_policy_epoch))
        if self.error is not None:
            raise self.error
        return resource_scope in self.fenced


class _Reranker:
    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def rerank(self, *, query, chunks):
        self.calls.append((query, tuple(chunk.chunk_id for chunk in chunks)))
        return self.result or tuple(reversed([chunk.chunk_id for chunk in chunks]))


def _retriever(
    pages,
    allowed,
    contents,
    *,
    attribute=None,
    reader=None,
    reranker=None,
    fence_checker=None,
    max_pages=8,
):
    relationship = _Evaluator(set(allowed))
    candidate_source = _CandidateSource(list(pages))
    content_reader = reader or _ContentReader(contents)
    retriever = EnterprisePermissionAwareRetriever(
        candidate_source=candidate_source,
        authorization=_authorization(relationship, attribute),
        content_reader=content_reader,
        fence_checker=fence_checker or _FenceChecker(),
        reranker=reranker,
        max_pages=max_pages,
    )
    return retriever, candidate_source, relationship, content_reader


def test_unauthorized_candidates_never_reach_plaintext_reader_or_reranker() -> None:
    contents = {"allowed": "visible", "denied": "secret"}
    reranker = _Reranker()
    retriever, _source, _authz, reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(
                    _candidate("denied", contents["denied"], score=2),
                    _candidate("allowed", contents["allowed"], score=1),
                ),
                next_cursor=None,
            )
        ],
        {"allowed"},
        contents,
        reranker=reranker,
    )

    result = retriever.retrieve(context=_context(), query="question", k=1)

    assert [chunk.chunk_id for chunk in result.chunks] == ["allowed"]
    assert reader.calls == [("tenant-a", ("allowed",))]
    assert reranker.calls == [("question", ("allowed",))]
    assert all("secret" not in chunk.text for chunk in result.chunks)


def test_retrieval_continues_pagination_until_k_authorized_chunks() -> None:
    contents = {"denied": "hidden", "one": "first", "two": "second"}
    retriever, source, _authz, reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("denied", contents["denied"]),),
                next_cursor="page-2",
            ),
            EnterpriseCandidatePage(
                candidates=(
                    _candidate("one", contents["one"]),
                    _candidate("two", contents["two"]),
                ),
                next_cursor=None,
            ),
        ],
        {"one", "two"},
        contents,
    )

    result = retriever.retrieve(context=_context(), query="question", k=2)

    assert [chunk.chunk_id for chunk in result.chunks] == ["one", "two"]
    assert result.pages_scanned == 2 and result.exhausted is True
    assert [call["cursor"] for call in source.calls] == [None, "page-2"]
    assert reader.calls == [("tenant-a", ("one", "two"))]


def test_cross_tenant_candidate_fails_before_authorization_or_content_read() -> None:
    contents = {"cross": "other tenant"}
    retriever, _source, authz, reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("cross", contents["cross"], tenant="tenant-b"),),
                next_cursor=None,
            )
        ],
        {"cross"},
        contents,
    )

    with pytest.raises(EnterpriseRetrievalError, match="tenant boundary"):
        retriever.retrieve(context=_context(), query="question", k=1)
    assert authz.calls == [] and reader.calls == []


def test_pending_or_failed_policy_fence_drops_candidate_before_authorization() -> None:
    contents = {"fenced": "must remain unavailable"}
    fences = _FenceChecker({"document-fenced"})
    retriever, _source, authz, reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("fenced", contents["fenced"]),),
                next_cursor=None,
            )
        ],
        {"fenced"},
        contents,
        fence_checker=fences,
    )

    result = retriever.retrieve(context=_context(), query="question", k=1)

    assert result.chunks == ()
    assert result.reason_codes == ("insufficient_authorized_results",)
    assert fences.calls == [("tenant-a", "document-fenced", 7)]
    assert authz.calls == [] and reader.calls == []


def test_policy_fence_checker_failure_blocks_the_entire_retrieval() -> None:
    contents = {"one": "content"}
    fences = _FenceChecker(error=RuntimeError("fence store down"))
    retriever, _source, authz, reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("one", contents["one"]),),
                next_cursor=None,
            )
        ],
        {"one"},
        contents,
        fence_checker=fences,
    )

    with pytest.raises(EnterpriseRetrievalError, match="fence check unavailable"):
        retriever.retrieve(context=_context(), query="question", k=1)
    assert authz.calls == [] and reader.calls == []


@pytest.mark.parametrize("failure", ["missing", "extra", "hash"])
def test_content_reader_missing_extra_or_hash_drift_fails_closed(failure: str) -> None:
    candidate = _candidate("one", "expected")
    if failure == "missing":
        records = ()
    elif failure == "extra":
        records = (
            EnterpriseContentRecord(
                tenant_id="tenant-a",
                chunk_id="one",
                content_hash=_hash("expected"),
                text="expected",
            ),
            EnterpriseContentRecord(
                tenant_id="tenant-a",
                chunk_id="extra",
                content_hash=_hash("extra"),
                text="extra",
            ),
        )
    else:
        records = (
            EnterpriseContentRecord(
                tenant_id="tenant-a",
                chunk_id="one",
                content_hash=_hash("changed"),
                text="changed",
            ),
        )
    reader = _ContentReader({"one": "expected"}, override=records)
    retriever, *_ = _retriever(
        [EnterpriseCandidatePage(candidates=(candidate,), next_cursor=None)],
        {"one"},
        {"one": "expected"},
        reader=reader,
    )

    with pytest.raises(EnterpriseRetrievalError, match="content reader|content integrity"):
        retriever.retrieve(context=_context(), query="question", k=1)


def test_authorization_dependency_failure_returns_no_plaintext() -> None:
    candidate = _candidate("one", "expected")
    relationship = _Evaluator({"one"}, error=RuntimeError("authz down"))
    source = _CandidateSource(
        [EnterpriseCandidatePage(candidates=(candidate,), next_cursor=None)]
    )
    reader = _ContentReader({"one": "expected"})
    retriever = EnterprisePermissionAwareRetriever(
        candidate_source=source,
        authorization=_authorization(relationship),
        content_reader=reader,
        fence_checker=_FenceChecker(),
    )

    result = retriever.retrieve(context=_context(), query="question", k=1)

    assert result.chunks == ()
    assert result.reason_codes == ("insufficient_authorized_results",)
    assert reader.calls == []


def test_reranker_must_return_exactly_the_authorized_chunk_closure() -> None:
    contents = {"one": "first"}
    reranker = _Reranker(result=("one", "not-authorized"))
    retriever, *_ = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("one", contents["one"]),),
                next_cursor=None,
            )
        ],
        {"one"},
        contents,
        reranker=reranker,
    )

    with pytest.raises(EnterpriseRetrievalError, match="reranker closure"):
        retriever.retrieve(context=_context(), query="question", k=1)


def test_citations_are_rechecked_against_the_current_policy_epoch() -> None:
    contents = {"one": "first"}
    retriever, *_ = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("one", contents["one"]),),
                next_cursor=None,
            )
        ],
        {"one"},
        contents,
    )
    original = retriever.retrieve(context=_context(), query="question", k=1)

    revalidated = retriever.revalidate_citations(
        context=_context(epoch=8), chunks=original.chunks
    )

    assert revalidated == ()


def test_citations_are_rechecked_against_a_new_revocation_fence() -> None:
    contents = {"one": "first"}
    fences = _FenceChecker()
    retriever, _source, authz, _reader = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("one", contents["one"]),),
                next_cursor=None,
            )
        ],
        {"one"},
        contents,
        fence_checker=fences,
    )
    original = retriever.retrieve(context=_context(), query="question", k=1)
    authorization_calls_before = len(authz.calls)
    fences.fenced.add("document-one")

    revalidated = retriever.revalidate_citations(
        context=_context(),
        chunks=original.chunks,
    )

    assert revalidated == ()
    assert len(authz.calls) == authorization_calls_before
    assert fences.calls[-1] == ("tenant-a", "document-one", 7)


def test_duplicate_candidates_across_pages_are_a_fail_closed_drift() -> None:
    contents = {"same": "text"}
    retriever, *_ = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("same", contents["same"]),),
                next_cursor="again",
            ),
            EnterpriseCandidatePage(
                candidates=(_candidate("same", contents["same"]),),
                next_cursor=None,
            ),
        ],
        set(),
        contents,
    )

    with pytest.raises(EnterpriseRetrievalError, match="pagination closure"):
        retriever.retrieve(context=_context(), query="question", k=1)


def test_cursor_cycle_is_rejected_without_unbounded_search() -> None:
    retriever, source, *_ = _retriever(
        [
            EnterpriseCandidatePage(candidates=(), next_cursor="cycle"),
            EnterpriseCandidatePage(candidates=(), next_cursor="cycle"),
        ],
        set(),
        {},
    )

    with pytest.raises(EnterpriseRetrievalError, match="cursor cycle"):
        retriever.retrieve(context=_context(), query="question", k=1)
    assert len(source.calls) == 2


def test_authorized_chunk_cannot_be_reused_after_plaintext_tampering() -> None:
    contents = {"one": "first"}
    retriever, *_ = _retriever(
        [
            EnterpriseCandidatePage(
                candidates=(_candidate("one", contents["one"]),),
                next_cursor=None,
            )
        ],
        {"one"},
        contents,
    )
    original = retriever.retrieve(context=_context(), query="question", k=1)

    with pytest.raises(EnterpriseRetrievalError, match="content integrity"):
        replace(original.chunks[0], text="changed after authorization")


@pytest.mark.parametrize(
    ("query", "k"),
    [("", 1), ("question", 0), ("question", 51)],
)
def test_query_and_result_limits_fail_before_candidate_search(query: str, k: int) -> None:
    retriever, source, *_ = _retriever([], set(), {})

    with pytest.raises(EnterpriseRetrievalError):
        retriever.retrieve(context=_context(), query=query, k=k)
    assert source.calls == []


def test_oversized_query_fails_before_candidate_search() -> None:
    retriever, source, *_ = _retriever([], set(), {})

    with pytest.raises(EnterpriseRetrievalError, match="query"):
        retriever.retrieve(context=_context(), query="x" * 70_000, k=1)
    assert source.calls == []
