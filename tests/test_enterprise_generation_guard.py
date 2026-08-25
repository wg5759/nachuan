from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from gateway.enterprise_context import EnterpriseRequestContext
from gateway.enterprise_generation import (
    EnterpriseDlpVerdict,
    EnterpriseGenerationError,
    EnterpriseGenerationGuard,
    EnterpriseModelRoutePolicy,
)
from gateway.enterprise_retrieval import (
    EnterpriseAuthorizedChunk,
    EnterpriseRetrievalResult,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _context(*, region: str = "cn-east", epoch: int = 7) -> EnterpriseRequestContext:
    return EnterpriseRequestContext(
        tenant_id="tenant-a",
        subject_id="user-a",
        session_id="session-a",
        groups=("project-red",),
        roles=("employee",),
        attributes={"clearance": 4},
        purpose="support",
        device_trust="managed",
        region=region,
        policy_epoch=epoch,
        session_epoch=3,
    )


def _chunk(
    chunk_id: str = "chunk-a",
    *,
    text: str = "authorized context",
    classification: int = 3,
    obligations: tuple[str, ...] = ("citation_required", "no_training"),
) -> EnterpriseAuthorizedChunk:
    return EnterpriseAuthorizedChunk(
        tenant_id="tenant-a",
        chunk_id=chunk_id,
        document_id=f"document-{chunk_id}",
        policy_id="policy-a",
        policy_epoch=7,
        classification=classification,
        content_hash=_hash(text),
        score=1.0,
        text=text,
        decision_id=_hash(f"decision:{chunk_id}"),
        obligations=obligations,
    )


def _retrieval(*chunks: EnterpriseAuthorizedChunk) -> EnterpriseRetrievalResult:
    return EnterpriseRetrievalResult(
        chunks=chunks or (_chunk(),),
        query_digest=_hash("query"),
        pages_scanned=1,
        exhausted=True,
        reason_codes=(),
    )


def _route(**changes) -> EnterpriseModelRoutePolicy:
    values = {
        "model_id": "enterprise-local",
        "local_execution": True,
        "allowed_regions": ("cn-east",),
        "max_classification": 5,
        "training_disabled": True,
    }
    values.update(changes)
    return EnterpriseModelRoutePolicy(**values)


class _Revalidator:
    def __init__(self, allowed: set[str] | None = None, *, error=None):
        self.allowed = allowed
        self.error = error
        self.calls = []

    def revalidate_citations(self, *, context, chunks):
        values = tuple(chunks)
        self.calls.append((context.policy_epoch, tuple(chunk.chunk_id for chunk in values)))
        if self.error is not None:
            raise self.error
        allowed = self.allowed
        return tuple(
            chunk
            for chunk in values
            if allowed is None or chunk.chunk_id in allowed
        )


class _Scanner:
    def __init__(self, context=None, output=None, *, error=None):
        self.context = context
        self.output = output
        self.error = error
        self.calls = []

    def scan(self, *, tenant_id, text, direction, classification):
        self.calls.append((tenant_id, direction, classification, _hash(text)))
        if self.error is not None:
            raise self.error
        configured = self.context if direction == "context" else self.output
        if callable(configured):
            return configured(text)
        if configured is not None:
            return configured
        return EnterpriseDlpVerdict(
            action="allow",
            text=text,
            risk_codes=(),
            scanner_version="dlp-v1",
        )


def _guard(revalidator=None, scanner=None):
    return EnterpriseGenerationGuard(
        citation_revalidator=revalidator or _Revalidator(),
        dlp_scanner=scanner or _Scanner(),
        audit_key=b"enterprise-generation-test-audit-key-32-bytes",
    )


def test_prepare_and_output_validation_bind_manifest_dlp_citations_and_receipt() -> None:
    guard = _guard()
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )

    output = guard.validate_output(
        context=_context(),
        prepared=prepared,
        text="safe answer",
        cited_chunk_ids=("chunk-a",),
    )

    assert prepared.manifest.policy_epoch == 7
    assert prepared.manifest.corpus_epoch == 9
    assert prepared.manifest.subject_scope_fingerprint != "user-a"
    assert output.text == "safe answer"
    assert output.cited_chunk_ids == ("chunk-a",)
    assert len(output.receipt_id) == 64


def test_context_is_revalidated_before_any_generation_context_is_prepared() -> None:
    revalidator = _Revalidator(set())
    scanner = _Scanner()

    with pytest.raises(EnterpriseGenerationError, match="context changed"):
        _guard(revalidator, scanner).prepare(
            context=_context(),
            retrieval=_retrieval(),
            corpus_epoch=9,
            route=_route(),
        )
    assert scanner.calls == []


@pytest.mark.parametrize(
    ("chunk", "route", "context", "message"),
    [
        (_chunk(classification=6), _route(), _context(), "classification"),
        (_chunk(), _route(allowed_regions=("us-east",)), _context(), "region"),
        (
            _chunk(obligations=("local_model_only",)),
            _route(local_execution=False),
            _context(),
            "local model",
        ),
        (
            _chunk(obligations=("no_training",)),
            _route(training_disabled=False),
            _context(),
            "training",
        ),
        (
            _chunk(obligations=("region_cn",)),
            _route(allowed_regions=("us-east",)),
            _context(region="us-east"),
            "region obligation",
        ),
    ],
)
def test_model_route_and_obligations_fail_closed(chunk, route, context, message) -> None:
    with pytest.raises(EnterpriseGenerationError, match=message):
        _guard().prepare(
            context=context,
            retrieval=_retrieval(chunk),
            corpus_epoch=9,
            route=route,
        )


def test_unknown_authorization_obligation_is_not_silently_ignored() -> None:
    with pytest.raises(EnterpriseGenerationError, match="unsupported"):
        _guard().prepare(
            context=_context(),
            retrieval=_retrieval(_chunk(obligations=("custom_unknown",))),
            corpus_epoch=9,
            route=_route(),
        )


def test_context_dlp_redaction_is_bound_separately_from_original_content() -> None:
    scanner = _Scanner(
        context=lambda text: EnterpriseDlpVerdict(
            action="redact",
            text=text.replace("secret", "[masked]"),
            risk_codes=(),
            scanner_version="dlp-v2",
        )
    )
    original = _chunk(text="customer secret")

    prepared = _guard(scanner=scanner).prepare(
        context=_context(),
        retrieval=_retrieval(original),
        corpus_epoch=9,
        route=_route(),
    )

    context_chunk = prepared.context_chunks[0]
    assert context_chunk.text == "customer [masked]"
    assert context_chunk.original_content_hash == original.content_hash
    assert context_chunk.prepared_content_hash == _hash("customer [masked]")
    assert context_chunk.prepared_content_hash != context_chunk.original_content_hash


@pytest.mark.parametrize("direction", ["context", "output"])
def test_dlp_deny_or_inference_risk_blocks_context_or_output(direction: str) -> None:
    denied = EnterpriseDlpVerdict(
        action="deny",
        text="",
        risk_codes=("inference_risk",),
        scanner_version="dlp-v1",
    )
    scanner = _Scanner(
        context=denied if direction == "context" else None,
        output=denied if direction == "output" else None,
    )
    guard = _guard(scanner=scanner)
    if direction == "context":
        with pytest.raises(EnterpriseGenerationError, match="context DLP"):
            guard.prepare(
                context=_context(),
                retrieval=_retrieval(),
                corpus_epoch=9,
                route=_route(),
            )
    else:
        prepared = guard.prepare(
            context=_context(),
            retrieval=_retrieval(),
            corpus_epoch=9,
            route=_route(),
        )
        with pytest.raises(EnterpriseGenerationError, match="output DLP"):
            guard.validate_output(
                context=_context(),
                prepared=prepared,
                text="risky aggregate",
                cited_chunk_ids=("chunk-a",),
            )


def test_dlp_dependency_failure_is_a_deny_not_an_unscanned_fallback() -> None:
    with pytest.raises(EnterpriseGenerationError, match="scanner unavailable"):
        _guard(scanner=_Scanner(error=RuntimeError("down"))).prepare(
            context=_context(),
            retrieval=_retrieval(),
            corpus_epoch=9,
            route=_route(),
        )


def test_manifest_tampering_or_subject_epoch_change_is_rejected() -> None:
    guard = _guard()
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )
    tampered = replace(
        prepared,
        manifest=replace(prepared.manifest, corpus_epoch=10),
    )

    with pytest.raises(EnterpriseGenerationError, match="manifest changed"):
        guard.validate_output(
            context=_context(),
            prepared=tampered,
            text="answer",
            cited_chunk_ids=("chunk-a",),
        )
    with pytest.raises(EnterpriseGenerationError, match="context changed"):
        guard.validate_output(
            context=_context(epoch=8),
            prepared=prepared,
            text="answer",
            cited_chunk_ids=("chunk-a",),
        )


def test_revoked_or_fabricated_citation_is_rejected_before_output_release() -> None:
    revalidator = _Revalidator()
    guard = _guard(revalidator=revalidator)
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )
    revalidator.allowed = set()

    with pytest.raises(EnterpriseGenerationError, match="context authorization changed"):
        guard.validate_output(
            context=_context(),
            prepared=prepared,
            text="answer",
            cited_chunk_ids=("chunk-a",),
        )
    with pytest.raises(EnterpriseGenerationError, match="citation closure"):
        guard.validate_output(
            context=_context(),
            prepared=prepared,
            text="answer",
            cited_chunk_ids=("fabricated",),
        )


def test_required_citation_cannot_be_omitted() -> None:
    guard = _guard()
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )

    with pytest.raises(EnterpriseGenerationError, match="required"):
        guard.validate_output(
            context=_context(),
            prepared=prepared,
            text="answer",
            cited_chunk_ids=(),
        )


def test_prepared_text_or_model_route_cannot_drift_after_manifest_creation() -> None:
    guard = _guard()
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )
    changed_context = replace(
        prepared,
        context_chunks=(replace(prepared.context_chunks[0], text="changed"),),
    )
    changed_route = replace(
        prepared,
        route=replace(prepared.route, local_execution=False),
    )

    with pytest.raises(EnterpriseGenerationError, match="prepared context"):
        guard.validate_output(
            context=_context(),
            prepared=changed_context,
            text="answer",
            cited_chunk_ids=("chunk-a",),
        )
    with pytest.raises(EnterpriseGenerationError, match="prepared route"):
        guard.validate_output(
            context=_context(),
            prepared=changed_route,
            text="answer",
            cited_chunk_ids=("chunk-a",),
        )


def test_non_cited_but_used_context_is_also_reauthorized_before_release() -> None:
    revalidator = _Revalidator()
    guard = _guard(revalidator=revalidator)
    first = _chunk("chunk-a")
    second = _chunk("chunk-b", text="second authorized context")
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(first, second),
        corpus_epoch=9,
        route=_route(),
    )
    revalidator.allowed = {"chunk-a"}

    with pytest.raises(EnterpriseGenerationError, match="context authorization changed"):
        guard.validate_output(
            context=_context(),
            prepared=prepared,
            text="answer using both chunks",
            cited_chunk_ids=("chunk-a",),
        )


def test_output_redaction_is_the_only_text_bound_to_the_release_receipt() -> None:
    scanner = _Scanner(
        output=lambda text: EnterpriseDlpVerdict(
            action="redact",
            text=text.replace("secret", "[masked]"),
            risk_codes=(),
            scanner_version="dlp-v3",
        )
    )
    guard = _guard(scanner=scanner)
    prepared = guard.prepare(
        context=_context(),
        retrieval=_retrieval(),
        corpus_epoch=9,
        route=_route(),
    )

    output = guard.validate_output(
        context=_context(),
        prepared=prepared,
        text="answer secret",
        cited_chunk_ids=("chunk-a",),
    )

    assert output.text == "answer [masked]"
    assert output.output_digest == _hash(output.text)
    assert output.dlp_version == "dlp-v3"
