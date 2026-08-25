"""Generation-side enterprise RAG guard over already-authorized context."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, Protocol

from .enterprise_context import EnterpriseRequestContext
from .enterprise_retrieval import (
    EnterpriseAuthorizedChunk,
    EnterpriseRetrievalResult,
)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_OUTPUT_UTF8_BYTES = 4 * 1024 * 1024
_SUPPORTED_OBLIGATIONS = frozenset(
    {
        "citation_required",
        "local_model_only",
        "mask_pii",
        "no_export",
        "no_training",
        "region_cn",
    }
)


class EnterpriseGenerationError(RuntimeError):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseGenerationError(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EnterpriseGenerationError(f"{field} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EnterpriseModelRoutePolicy:
    model_id: str
    local_execution: bool
    allowed_regions: tuple[str, ...]
    max_classification: int
    training_disabled: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_id", _identifier(self.model_id, "model_id"))
        if not isinstance(self.local_execution, bool) or not isinstance(
            self.training_disabled, bool
        ):
            raise EnterpriseGenerationError("model route booleans are invalid")
        if not isinstance(self.allowed_regions, tuple) or not self.allowed_regions:
            raise EnterpriseGenerationError("allowed_regions is invalid")
        normalized = tuple(
            sorted({_identifier(region, "allowed_region") for region in self.allowed_regions})
        )
        if len(normalized) != len(self.allowed_regions):
            raise EnterpriseGenerationError("allowed_regions contains duplicates")
        object.__setattr__(self, "allowed_regions", normalized)
        if (
            isinstance(self.max_classification, bool)
            or not isinstance(self.max_classification, int)
            or not 0 <= self.max_classification <= 10
        ):
            raise EnterpriseGenerationError("max_classification is invalid")


@dataclass(frozen=True, slots=True)
class EnterpriseDlpVerdict:
    action: Literal["allow", "redact", "deny"]
    text: str
    risk_codes: tuple[str, ...]
    scanner_version: str

    def __post_init__(self) -> None:
        if self.action not in {"allow", "redact", "deny"}:
            raise EnterpriseGenerationError("DLP action is invalid")
        if not isinstance(self.text, str):
            raise EnterpriseGenerationError("DLP text is invalid")
        self.text.encode("utf-8", errors="strict")
        if not isinstance(self.risk_codes, tuple) or len(self.risk_codes) > 32:
            raise EnterpriseGenerationError("DLP risk codes are invalid")
        normalized = tuple(
            sorted({_identifier(code, "risk_code") for code in self.risk_codes})
        )
        if len(normalized) != len(self.risk_codes):
            raise EnterpriseGenerationError("DLP risk codes contain duplicates")
        object.__setattr__(self, "risk_codes", normalized)
        object.__setattr__(
            self,
            "scanner_version",
            _identifier(self.scanner_version, "scanner_version"),
        )
        if self.action == "allow" and self.risk_codes:
            raise EnterpriseGenerationError("allow verdict carries risk codes")
        if self.action == "deny" and not self.risk_codes:
            raise EnterpriseGenerationError("deny verdict has no reason")
        if self.action == "redact" and not self.text:
            raise EnterpriseGenerationError("redacted text is empty")


class EnterpriseDlpScanner(Protocol):
    def scan(
        self,
        *,
        tenant_id: str,
        text: str,
        direction: Literal["context", "output"],
        classification: int,
    ) -> EnterpriseDlpVerdict: ...


class EnterpriseCitationRevalidator(Protocol):
    def revalidate_citations(
        self,
        *,
        context: EnterpriseRequestContext,
        chunks: Iterable[EnterpriseAuthorizedChunk],
    ) -> tuple[EnterpriseAuthorizedChunk, ...]: ...


@dataclass(frozen=True, slots=True)
class EnterprisePreparedContextChunk:
    chunk_id: str
    document_id: str
    original_content_hash: str
    prepared_content_hash: str
    classification: int
    text: str
    decision_id: str
    dlp_version: str


@dataclass(frozen=True, slots=True)
class EnterpriseContextManifestChunk:
    chunk_id: str
    document_id: str
    original_content_hash: str
    prepared_content_hash: str
    classification: int
    decision_id: str
    dlp_version: str


@dataclass(frozen=True, slots=True)
class EnterpriseAuthorizedContextManifest:
    tenant_id: str
    subject_scope_fingerprint: str
    policy_epoch: int
    corpus_epoch: int
    query_digest: str
    model_id: str
    route_policy_digest: str
    chunks: tuple[EnterpriseContextManifestChunk, ...]
    obligations: tuple[str, ...]
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class EnterprisePreparedGeneration:
    manifest: EnterpriseAuthorizedContextManifest
    route: EnterpriseModelRoutePolicy
    context_chunks: tuple[EnterprisePreparedContextChunk, ...]
    authorized_chunks: tuple[EnterpriseAuthorizedChunk, ...]


@dataclass(frozen=True, slots=True)
class EnterpriseGeneratedOutput:
    text: str
    cited_chunk_ids: tuple[str, ...]
    manifest_digest: str
    output_digest: str
    dlp_version: str
    receipt_id: str


class EnterpriseGenerationGuard:
    def __init__(
        self,
        *,
        citation_revalidator: EnterpriseCitationRevalidator,
        dlp_scanner: EnterpriseDlpScanner,
        audit_key: bytes,
    ):
        if not callable(getattr(citation_revalidator, "revalidate_citations", None)):
            raise EnterpriseGenerationError("citation_revalidator is invalid")
        if not callable(getattr(dlp_scanner, "scan", None)):
            raise EnterpriseGenerationError("dlp_scanner is invalid")
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise EnterpriseGenerationError("audit_key is invalid")
        self._revalidator = citation_revalidator
        self._dlp = dlp_scanner
        self._audit_key = bytes(audit_key)

    def prepare(
        self,
        *,
        context: EnterpriseRequestContext,
        retrieval: EnterpriseRetrievalResult,
        corpus_epoch: int,
        route: EnterpriseModelRoutePolicy,
    ) -> EnterprisePreparedGeneration:
        if not isinstance(context, EnterpriseRequestContext):
            raise EnterpriseGenerationError("context is invalid")
        if not isinstance(retrieval, EnterpriseRetrievalResult) or not retrieval.chunks:
            raise EnterpriseGenerationError("authorized retrieval is empty")
        if (
            isinstance(corpus_epoch, bool)
            or not isinstance(corpus_epoch, int)
            or corpus_epoch < 1
        ):
            raise EnterpriseGenerationError("corpus_epoch is invalid")
        if not isinstance(route, EnterpriseModelRoutePolicy):
            raise EnterpriseGenerationError("route is invalid")
        current = self._revalidate(context, retrieval.chunks)
        original_ids = tuple(chunk.chunk_id for chunk in retrieval.chunks)
        if tuple(chunk.chunk_id for chunk in current) != original_ids:
            raise EnterpriseGenerationError("authorized context changed before generation")

        obligations = tuple(
            sorted(
                {
                    obligation
                    for chunk in current
                    for obligation in chunk.obligations
                }
            )
        )
        unknown = set(obligations) - _SUPPORTED_OBLIGATIONS
        if unknown:
            raise EnterpriseGenerationError("unsupported authorization obligation")
        highest = max(chunk.classification for chunk in current)
        if highest > route.max_classification:
            raise EnterpriseGenerationError("model classification route rejected")
        if context.region not in route.allowed_regions:
            raise EnterpriseGenerationError("model region route rejected")
        if "region_cn" in obligations and not context.region.startswith("cn-"):
            raise EnterpriseGenerationError("region obligation rejected")
        if "local_model_only" in obligations and not route.local_execution:
            raise EnterpriseGenerationError("local model obligation rejected")
        if "no_training" in obligations and not route.training_disabled:
            raise EnterpriseGenerationError("training obligation rejected")

        prepared_chunks: list[EnterprisePreparedContextChunk] = []
        for chunk in current:
            verdict = self._scan(
                tenant_id=context.tenant_id,
                text=chunk.text,
                direction="context",
                classification=chunk.classification,
            )
            if verdict.action == "deny" or verdict.risk_codes:
                raise EnterpriseGenerationError("context DLP rejected")
            prepared_text = verdict.text
            if verdict.action == "allow" and prepared_text != chunk.text:
                raise EnterpriseGenerationError("allow DLP changed context")
            if verdict.action == "redact" and prepared_text == chunk.text:
                raise EnterpriseGenerationError("redact DLP changed nothing")
            prepared_chunks.append(
                EnterprisePreparedContextChunk(
                    chunk_id=chunk.chunk_id,
                    document_id=chunk.document_id,
                    original_content_hash=chunk.content_hash,
                    prepared_content_hash=hashlib.sha256(
                        prepared_text.encode("utf-8")
                    ).hexdigest(),
                    classification=chunk.classification,
                    text=prepared_text,
                    decision_id=chunk.decision_id,
                    dlp_version=verdict.scanner_version,
                )
            )

        subject_fingerprint = self._subject_fingerprint(context)
        chunk_manifest = tuple(
            EnterpriseContextManifestChunk(
                chunk_id=chunk.chunk_id,
                document_id=chunk.document_id,
                original_content_hash=chunk.original_content_hash,
                prepared_content_hash=chunk.prepared_content_hash,
                classification=chunk.classification,
                decision_id=chunk.decision_id,
                dlp_version=chunk.dlp_version,
            )
            for chunk in prepared_chunks
        )
        body = {
            "tenant_id": context.tenant_id,
            "subject_scope_fingerprint": subject_fingerprint,
            "policy_epoch": context.policy_epoch,
            "corpus_epoch": corpus_epoch,
            "query_digest": retrieval.query_digest,
            "model_id": route.model_id,
            "route_policy_digest": self._route_policy_digest(route),
            "chunks": self._manifest_chunks_body(chunk_manifest),
            "obligations": obligations,
        }
        manifest_digest = self._mac(body)
        manifest = EnterpriseAuthorizedContextManifest(
            tenant_id=context.tenant_id,
            subject_scope_fingerprint=subject_fingerprint,
            policy_epoch=context.policy_epoch,
            corpus_epoch=corpus_epoch,
            query_digest=retrieval.query_digest,
            model_id=route.model_id,
            route_policy_digest=body["route_policy_digest"],
            chunks=chunk_manifest,
            obligations=obligations,
            manifest_digest=manifest_digest,
        )
        return EnterprisePreparedGeneration(
            manifest=manifest,
            route=route,
            context_chunks=tuple(prepared_chunks),
            authorized_chunks=current,
        )

    def validate_output(
        self,
        *,
        context: EnterpriseRequestContext,
        prepared: EnterprisePreparedGeneration,
        text: str,
        cited_chunk_ids: Iterable[str],
    ) -> EnterpriseGeneratedOutput:
        if not isinstance(prepared, EnterprisePreparedGeneration):
            raise EnterpriseGenerationError("prepared generation is invalid")
        self._verify_manifest(context, prepared.manifest)
        self._verify_prepared_closure(prepared)
        if not isinstance(text, str) or not text:
            raise EnterpriseGenerationError("output is invalid")
        output_bytes = text.encode("utf-8", errors="strict")
        if len(output_bytes) > _MAX_OUTPUT_UTF8_BYTES:
            raise EnterpriseGenerationError("output is invalid")
        citations = tuple(_identifier(value, "cited_chunk_id") for value in cited_chunk_ids)
        if len(set(citations)) != len(citations):
            raise EnterpriseGenerationError("citations contain duplicates")
        allowed_ids = {chunk.chunk_id for chunk in prepared.authorized_chunks}
        if not set(citations).issubset(allowed_ids):
            raise EnterpriseGenerationError("citation closure differs")
        if "citation_required" in prepared.manifest.obligations and not citations:
            raise EnterpriseGenerationError("citation is required")
        current = self._revalidate(context, prepared.authorized_chunks)
        expected_ids = tuple(chunk.chunk_id for chunk in prepared.authorized_chunks)
        if tuple(chunk.chunk_id for chunk in current) != expected_ids:
            raise EnterpriseGenerationError("generation context authorization changed")

        highest = max(chunk.classification for chunk in prepared.authorized_chunks)
        verdict = self._scan(
            tenant_id=context.tenant_id,
            text=text,
            direction="output",
            classification=highest,
        )
        if verdict.action == "deny" or verdict.risk_codes:
            raise EnterpriseGenerationError("output DLP rejected")
        final_text = verdict.text
        if verdict.action == "allow" and final_text != text:
            raise EnterpriseGenerationError("allow DLP changed output")
        if verdict.action == "redact" and final_text == text:
            raise EnterpriseGenerationError("redact DLP changed nothing")
        output_digest = hashlib.sha256(final_text.encode("utf-8")).hexdigest()
        receipt = {
            "tenant_id": context.tenant_id,
            "subject_scope_fingerprint": prepared.manifest.subject_scope_fingerprint,
            "manifest_digest": prepared.manifest.manifest_digest,
            "output_digest": output_digest,
            "citations": citations,
            "dlp_version": verdict.scanner_version,
        }
        return EnterpriseGeneratedOutput(
            text=final_text,
            cited_chunk_ids=citations,
            manifest_digest=prepared.manifest.manifest_digest,
            output_digest=output_digest,
            dlp_version=verdict.scanner_version,
            receipt_id=self._mac(receipt),
        )

    def _revalidate(
        self,
        context: EnterpriseRequestContext,
        chunks: Iterable[EnterpriseAuthorizedChunk],
    ) -> tuple[EnterpriseAuthorizedChunk, ...]:
        try:
            result = self._revalidator.revalidate_citations(
                context=context,
                chunks=chunks,
            )
        except Exception:
            raise EnterpriseGenerationError("citation authorization unavailable") from None
        if not isinstance(result, tuple) or any(
            not isinstance(chunk, EnterpriseAuthorizedChunk) for chunk in result
        ):
            raise EnterpriseGenerationError("citation authorization result is invalid")
        return result

    def _scan(self, **kwargs) -> EnterpriseDlpVerdict:
        try:
            verdict = self._dlp.scan(**kwargs)
        except Exception:
            raise EnterpriseGenerationError("DLP scanner unavailable") from None
        if not isinstance(verdict, EnterpriseDlpVerdict):
            raise EnterpriseGenerationError("DLP scanner result is invalid")
        return verdict

    def _subject_fingerprint(self, context: EnterpriseRequestContext) -> str:
        body = {
            "tenant": context.tenant_id,
            "subject": context.subject_id,
            "session": context.session_id,
            "groups": context.groups,
            "roles": context.roles,
            "attributes": dict(context.attributes),
            "purpose": context.purpose,
            "device": context.device_trust,
            "region": context.region,
            "policy_epoch": context.policy_epoch,
            "session_epoch": context.session_epoch,
        }
        return self._mac(body)

    def _verify_manifest(
        self,
        context: EnterpriseRequestContext,
        manifest: EnterpriseAuthorizedContextManifest,
    ) -> None:
        if manifest.tenant_id != context.tenant_id or manifest.policy_epoch != context.policy_epoch:
            raise EnterpriseGenerationError("generation context changed")
        if manifest.subject_scope_fingerprint != self._subject_fingerprint(context):
            raise EnterpriseGenerationError("generation subject scope changed")
        body = {
            "tenant_id": manifest.tenant_id,
            "subject_scope_fingerprint": manifest.subject_scope_fingerprint,
            "policy_epoch": manifest.policy_epoch,
            "corpus_epoch": manifest.corpus_epoch,
            "query_digest": manifest.query_digest,
            "model_id": manifest.model_id,
            "route_policy_digest": manifest.route_policy_digest,
            "chunks": self._manifest_chunks_body(manifest.chunks),
            "obligations": manifest.obligations,
        }
        if not hmac.compare_digest(manifest.manifest_digest, self._mac(body)):
            raise EnterpriseGenerationError("generation manifest changed")

    def _verify_prepared_closure(self, prepared: EnterprisePreparedGeneration) -> None:
        manifest = prepared.manifest
        if (
            prepared.route.model_id != manifest.model_id
            or self._route_policy_digest(prepared.route)
            != manifest.route_policy_digest
        ):
            raise EnterpriseGenerationError("prepared route changed")
        if len(prepared.context_chunks) != len(manifest.chunks) or len(
            prepared.authorized_chunks
        ) != len(manifest.chunks):
            raise EnterpriseGenerationError("prepared context closure changed")
        for context_chunk, manifest_chunk, authorized in zip(
            prepared.context_chunks,
            manifest.chunks,
            prepared.authorized_chunks,
            strict=True,
        ):
            if (
                context_chunk.chunk_id != manifest_chunk.chunk_id
                or context_chunk.document_id != manifest_chunk.document_id
                or context_chunk.original_content_hash
                != manifest_chunk.original_content_hash
                or context_chunk.prepared_content_hash
                != manifest_chunk.prepared_content_hash
                or context_chunk.classification != manifest_chunk.classification
                or context_chunk.decision_id != manifest_chunk.decision_id
                or context_chunk.dlp_version != manifest_chunk.dlp_version
                or hashlib.sha256(context_chunk.text.encode("utf-8")).hexdigest()
                != manifest_chunk.prepared_content_hash
                or authorized.chunk_id != manifest_chunk.chunk_id
                or authorized.document_id != manifest_chunk.document_id
                or authorized.content_hash != manifest_chunk.original_content_hash
                or authorized.classification != manifest_chunk.classification
                or authorized.decision_id != manifest_chunk.decision_id
            ):
                raise EnterpriseGenerationError("prepared context closure changed")

    def _mac(self, value: object) -> str:
        return hmac.new(self._audit_key, _canonical_json(value), hashlib.sha256).hexdigest()

    def _route_policy_digest(self, route: EnterpriseModelRoutePolicy) -> str:
        return self._mac(
            {
                "model_id": route.model_id,
                "local_execution": route.local_execution,
                "allowed_regions": route.allowed_regions,
                "max_classification": route.max_classification,
                "training_disabled": route.training_disabled,
            }
        )

    @staticmethod
    def _manifest_chunks_body(
        chunks: tuple[EnterpriseContextManifestChunk, ...],
    ) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "chunk_id": chunk.chunk_id,
                "document_id": chunk.document_id,
                "original_content_hash": chunk.original_content_hash,
                "prepared_content_hash": chunk.prepared_content_hash,
                "classification": chunk.classification,
                "decision_id": chunk.decision_id,
                "dlp_version": chunk.dlp_version,
            }
            for chunk in chunks
        )


__all__ = [
    "EnterpriseAuthorizedContextManifest",
    "EnterpriseCitationRevalidator",
    "EnterpriseContextManifestChunk",
    "EnterpriseDlpScanner",
    "EnterpriseDlpVerdict",
    "EnterpriseGeneratedOutput",
    "EnterpriseGenerationError",
    "EnterpriseGenerationGuard",
    "EnterpriseModelRoutePolicy",
    "EnterprisePreparedContextChunk",
    "EnterprisePreparedGeneration",
]
