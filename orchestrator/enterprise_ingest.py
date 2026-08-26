"""Fail-closed enterprise RAG ingestion planner.

This module deliberately stops at isolated metadata plus transient payloads.  It
does not write plaintext, embeddings, or searchable rows.  An encrypted object
store and the authorization publication workflow are separate release gates.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from .enterprise_knowledge import (
    EnterpriseChunkMetadata,
    EnterpriseDocumentMetadata,
    EnterpriseKnowledgeError,
    EnterpriseKnowledgeStore,
)

_MAX_BLOCKS = 10_000
_MAX_TOTAL_UTF8_BYTES = 64 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _content_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _require_digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class EnterpriseSourceBlock:
    block_id: str
    tenant_id: str
    source_id: str
    source_version: str
    policy_id: str
    policy_epoch: int
    classification: int
    acl_digest: str
    text: str

    def __post_init__(self) -> None:
        for field in (
            "block_id",
            "tenant_id",
            "source_id",
            "source_version",
            "policy_id",
        ):
            _require_id(getattr(self, field), field)
        _require_digest(self.acl_digest, "acl_digest")
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise ValueError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise ValueError("classification is invalid")
        if not isinstance(self.text, str) or not self.text:
            raise ValueError("text is invalid")
        self.text.encode("utf-8", errors="strict")


@dataclass(frozen=True, slots=True)
class EnterpriseChunkPayload:
    chunk_id: str
    content_ref: str
    text: str


@dataclass(frozen=True, slots=True)
class EnterpriseIngestPlan:
    status: Literal["ready", "quarantined"]
    reason_codes: tuple[str, ...]
    tenant_id: str
    source_id: str
    source_version: str
    policy_epoch: int
    documents: tuple[EnterpriseDocumentMetadata, ...]
    payloads: tuple[EnterpriseChunkPayload, ...]
    plan_digest: str


class EnterpriseSemanticSplitter(Protocol):
    def split(self, *, text: str, max_chunk_chars: int) -> Sequence[str]: ...


class EnterpriseSecureIngestPlanner:
    def __init__(
        self,
        *,
        max_chunk_chars: int = 1_200,
        splitter: EnterpriseSemanticSplitter | None = None,
    ):
        if (
            isinstance(max_chunk_chars, bool)
            or not isinstance(max_chunk_chars, int)
            or not 128 <= max_chunk_chars <= 16_384
        ):
            raise ValueError("max_chunk_chars is invalid")
        if splitter is not None and not callable(getattr(splitter, "split", None)):
            raise ValueError("splitter is invalid")
        self._max_chunk_chars = max_chunk_chars
        self._splitter = splitter

    def plan_source_snapshot(
        self,
        *,
        tenant_id: str,
        source_id: str,
        source_version: str,
        expected_policy_epoch: int,
        blocks: Iterable[EnterpriseSourceBlock],
    ) -> EnterpriseIngestPlan:
        tenant = _require_id(tenant_id, "tenant_id")
        source = _require_id(source_id, "source_id")
        version = _require_id(source_version, "source_version")
        if (
            isinstance(expected_policy_epoch, bool)
            or not isinstance(expected_policy_epoch, int)
            or expected_policy_epoch < 1
        ):
            raise ValueError("expected_policy_epoch is invalid")
        source_blocks = tuple(blocks)
        if not source_blocks or len(source_blocks) > _MAX_BLOCKS:
            raise ValueError("blocks are invalid")
        if len({block.block_id for block in source_blocks}) != len(source_blocks):
            raise ValueError("block ids are duplicated")
        byte_count = sum(len(block.text.encode("utf-8")) for block in source_blocks)
        if byte_count > _MAX_TOTAL_UTF8_BYTES:
            raise ValueError("source snapshot is too large")

        reasons: list[str] = []
        if any(block.tenant_id != tenant for block in source_blocks):
            reasons.append("tenant_boundary_ambiguous")
        if any(block.source_id != source for block in source_blocks):
            reasons.append("source_boundary_ambiguous")
        if any(block.source_version != version for block in source_blocks):
            reasons.append("source_version_mismatch")
        if any(block.policy_epoch != expected_policy_epoch for block in source_blocks):
            reasons.append("policy_epoch_mismatch")
        if reasons:
            return self._quarantined(
                tenant=tenant,
                source=source,
                version=version,
                policy_epoch=expected_policy_epoch,
                reasons=tuple(reasons),
            )

        documents: list[EnterpriseDocumentMetadata] = []
        payloads: list[EnterpriseChunkPayload] = []
        domain_blocks: list[EnterpriseSourceBlock] = []
        previous_boundary: tuple[str, int, str] | None = None
        for block in source_blocks:
            boundary = (block.policy_id, block.classification, block.acl_digest)
            if previous_boundary is not None and boundary != previous_boundary:
                document, document_payloads = self._plan_domain(
                    tenant, source, version, domain_blocks, len(documents)
                )
                documents.append(document)
                payloads.extend(document_payloads)
                domain_blocks = []
            domain_blocks.append(block)
            previous_boundary = boundary
        document, document_payloads = self._plan_domain(
            tenant, source, version, domain_blocks, len(documents)
        )
        documents.append(document)
        payloads.extend(document_payloads)

        plan_digest = _digest(
            {
                "tenant": tenant,
                "source": source,
                "version": version,
                "policy_epoch": expected_policy_epoch,
                "documents": [
                    {
                        "document_id": document.document_id,
                        "policy_id": document.policy_id,
                        "classification": document.classification,
                        "content_hash": document.content_hash,
                        "chunks": [chunk.content_hash for chunk in document.chunks],
                    }
                    for document in documents
                ],
            }
        )
        return EnterpriseIngestPlan(
            status="ready",
            reason_codes=(),
            tenant_id=tenant,
            source_id=source,
            source_version=version,
            policy_epoch=expected_policy_epoch,
            documents=tuple(documents),
            payloads=tuple(payloads),
            plan_digest=plan_digest,
        )

    def plan_derived_artifact(
        self,
        *,
        tenant_id: str,
        derived_id: str,
        source_version: str,
        text: str,
        sources: Iterable[EnterpriseChunkMetadata],
    ) -> EnterpriseIngestPlan:
        """Plan a derived artifact without ever weakening source permissions.

        Until the authorization compiler can materialize policy intersections,
        sources with different policies or epochs are quarantined.  This is a
        deliberate deny-by-default boundary rather than an approximation.
        """

        tenant = _require_id(tenant_id, "tenant_id")
        derived = _require_id(derived_id, "derived_id")
        version = _require_id(source_version, "source_version")
        derived_source = "derived-" + _digest({"derived_id": derived})
        if not isinstance(text, str) or not text:
            raise ValueError("text is invalid")
        text.encode("utf-8", errors="strict")
        source_chunks = tuple(sources)
        if not source_chunks:
            raise ValueError("sources are invalid")
        epochs = {chunk.policy_epoch for chunk in source_chunks}
        policies = {chunk.policy_id for chunk in source_chunks}
        policy_epoch = max(epochs)
        if len(epochs) != 1:
            return self._quarantined(
                tenant=tenant,
                source=derived_source,
                version=version,
                policy_epoch=policy_epoch,
                reasons=("derived_policy_epoch_conflict",),
            )
        if len(policies) != 1:
            return self._quarantined(
                tenant=tenant,
                source=derived_source,
                version=version,
                policy_epoch=policy_epoch,
                reasons=("derived_policy_intersection_unavailable",),
            )
        classification = max(chunk.classification for chunk in source_chunks)
        acl_digest = _digest(
            {
                "policy_id": next(iter(policies)),
                "policy_epoch": policy_epoch,
                "sources": sorted(
                    (
                        chunk.chunk_id,
                        chunk.content_hash,
                        chunk.provenance_digest,
                        chunk.classification,
                    )
                    for chunk in source_chunks
                ),
            }
        )
        block = EnterpriseSourceBlock(
            block_id=derived_source,
            tenant_id=tenant,
            source_id=derived_source,
            source_version=version,
            policy_id=next(iter(policies)),
            policy_epoch=policy_epoch,
            classification=classification,
            acl_digest=acl_digest,
            text=text,
        )
        return self.plan_source_snapshot(
            tenant_id=tenant,
            source_id=block.source_id,
            source_version=version,
            expected_policy_epoch=policy_epoch,
            blocks=(block,),
        )

    @staticmethod
    def validate_plan(plan: EnterpriseIngestPlan) -> None:
        if not isinstance(plan, EnterpriseIngestPlan):
            raise EnterpriseKnowledgeError("ingest plan is invalid")
        if plan.status != "ready" or plan.reason_codes:
            raise EnterpriseKnowledgeError("quarantined ingest plan cannot be staged")
        if not plan.documents or len(plan.documents) != len(
            {document.document_id for document in plan.documents}
        ):
            raise EnterpriseKnowledgeError("ingest plan is invalid")
        metadata_by_id = {
            chunk.chunk_id: chunk
            for document in plan.documents
            for chunk in document.chunks
        }
        payload_by_id = {payload.chunk_id: payload for payload in plan.payloads}
        if len(payload_by_id) != len(plan.payloads) or set(payload_by_id) != set(metadata_by_id):
            raise EnterpriseKnowledgeError("ingest payload closure changed")
        for chunk_id, metadata in metadata_by_id.items():
            payload = payload_by_id[chunk_id]
            if (
                payload.content_ref != metadata.content_ref
                or _content_hash(payload.text) != metadata.content_hash
            ):
                raise EnterpriseKnowledgeError("ingest payload changed")
        expected_digest = _digest(
            {
                "tenant": plan.tenant_id,
                "source": plan.source_id,
                "version": plan.source_version,
                "policy_epoch": plan.policy_epoch,
                "documents": [
                    {
                        "document_id": document.document_id,
                        "policy_id": document.policy_id,
                        "classification": document.classification,
                        "content_hash": document.content_hash,
                        "chunks": [chunk.content_hash for chunk in document.chunks],
                    }
                    for document in plan.documents
                ],
            }
        )
        if expected_digest != plan.plan_digest:
            raise EnterpriseKnowledgeError("ingest plan digest changed")

    @staticmethod
    def stage_isolated(
        store: EnterpriseKnowledgeStore, plan: EnterpriseIngestPlan
    ) -> dict[str, object]:
        EnterpriseSecureIngestPlanner.validate_plan(plan)
        return store.stage_document_family(
            tenant_id=plan.tenant_id,
            expected_policy_epoch=plan.policy_epoch,
            documents=plan.documents,
        )

    def _plan_domain(
        self,
        tenant: str,
        source: str,
        version: str,
        blocks: list[EnterpriseSourceBlock],
        domain_ordinal: int,
    ) -> tuple[EnterpriseDocumentMetadata, tuple[EnterpriseChunkPayload, ...]]:
        if not blocks:
            raise EnterpriseKnowledgeError("permission domain is empty")
        policy_id = blocks[0].policy_id
        policy_epoch = blocks[0].policy_epoch
        classification = blocks[0].classification
        acl_digest = blocks[0].acl_digest
        if any(
            (
                block.policy_id,
                block.policy_epoch,
                block.classification,
                block.acl_digest,
            )
            != (policy_id, policy_epoch, classification, acl_digest)
            for block in blocks
        ):
            raise EnterpriseKnowledgeError("permission domain is not homogeneous")

        document_seed = {
            "tenant": tenant,
            "source": source,
            "version": version,
            "domain": domain_ordinal,
            "policy": policy_id,
            "classification": classification,
            "acl": acl_digest,
            "blocks": [block.block_id for block in blocks],
        }
        document_id = "doc-" + _digest(document_seed)
        chunks: list[EnterpriseChunkMetadata] = []
        payloads: list[EnterpriseChunkPayload] = []
        for block in blocks:
            for part_ordinal, part in enumerate(self._split_text(block.text)):
                content_hash = _content_hash(part)
                chunk_seed = {
                    "document": document_id,
                    "block": block.block_id,
                    "part": part_ordinal,
                    "content_hash": content_hash,
                }
                chunk_id = "chunk-" + _digest(chunk_seed)
                content_ref = "isolated-" + _digest(
                    {"tenant": tenant, "chunk": chunk_id, "content": content_hash}
                )
                provenance_digest = _digest(
                    {
                        "tenant": tenant,
                        "source": source,
                        "version": version,
                        "block": block.block_id,
                        "part": part_ordinal,
                        "acl": acl_digest,
                        "content_hash": content_hash,
                    }
                )
                chunks.append(
                    EnterpriseChunkMetadata(
                        chunk_id=chunk_id,
                        ordinal=len(chunks),
                        content_ref=content_ref,
                        content_hash=content_hash,
                        policy_id=policy_id,
                        policy_epoch=policy_epoch,
                        classification=classification,
                        provenance_digest=provenance_digest,
                    )
                )
                payloads.append(
                    EnterpriseChunkPayload(
                        chunk_id=chunk_id,
                        content_ref=content_ref,
                        text=part,
                    )
                )
        document_hash = _digest(
            {
                "source": source,
                "version": version,
                "chunks": [chunk.content_hash for chunk in chunks],
            }
        )
        return (
            EnterpriseDocumentMetadata(
                document_id=document_id,
                source_id=source,
                source_version=version,
                policy_id=policy_id,
                policy_epoch=policy_epoch,
                classification=classification,
                content_hash=document_hash,
                chunks=tuple(chunks),
            ),
            tuple(payloads),
        )

    def _split_text(self, text: str) -> tuple[str, ...]:
        if self._splitter is not None:
            try:
                result = self._splitter.split(
                    text=text,
                    max_chunk_chars=self._max_chunk_chars,
                )
            except Exception:  # noqa: BLE001 -- plugin details cannot cross the seam
                raise EnterpriseKnowledgeError(
                    "semantic splitter unavailable"
                ) from None
            if not isinstance(result, Sequence) or isinstance(result, (str, bytes)):
                raise EnterpriseKnowledgeError("semantic splitter result is invalid")
            parts = tuple(result)
            if (
                not parts
                or len(parts) > 100_000
                or any(
                    not isinstance(part, str)
                    or not part
                    or len(part) > self._max_chunk_chars
                    for part in parts
                )
                or "".join(parts) != text
            ):
                raise EnterpriseKnowledgeError(
                    "semantic splitter changed source content"
                )
            for part in parts:
                part.encode("utf-8", errors="strict")
            return parts
        parts: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + self._max_chunk_chars, len(text))
            if end < len(text):
                minimum = start + self._max_chunk_chars // 2
                choices = (
                    text.rfind("\n\n", minimum, end + 1),
                    text.rfind("\n", minimum, end + 1),
                    text.rfind(" ", minimum, end + 1),
                )
                boundary = max(choices)
                if boundary >= minimum:
                    end = boundary + (2 if text.startswith("\n\n", boundary) else 1)
            part = text[start:end]
            if not part:
                raise EnterpriseKnowledgeError("chunker made no progress")
            parts.append(part)
            start = end
        if "".join(parts) != text:
            raise EnterpriseKnowledgeError("chunker changed source content")
        return tuple(parts)

    @staticmethod
    def _quarantined(
        *,
        tenant: str,
        source: str,
        version: str,
        policy_epoch: int,
        reasons: tuple[str, ...],
    ) -> EnterpriseIngestPlan:
        unique_reasons = tuple(dict.fromkeys(reasons))
        return EnterpriseIngestPlan(
            status="quarantined",
            reason_codes=unique_reasons,
            tenant_id=tenant,
            source_id=source,
            source_version=version,
            policy_epoch=policy_epoch,
            documents=(),
            payloads=(),
            plan_digest=_digest(
                {
                    "tenant": tenant,
                    "source": source,
                    "version": version,
                    "policy_epoch": policy_epoch,
                    "reasons": unique_reasons,
                }
            ),
        )


__all__ = [
    "EnterpriseChunkPayload",
    "EnterpriseIngestPlan",
    "EnterpriseSecureIngestPlanner",
    "EnterpriseSemanticSplitter",
    "EnterpriseSourceBlock",
]
