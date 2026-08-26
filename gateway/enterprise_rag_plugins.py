"""PK-007 plugin seams around the kernel-owned enterprise RAG security path."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from gateway.enterprise_authz import EnterpriseAuthorizationFacade
from gateway.enterprise_context import EnterpriseRequestContext
from gateway.enterprise_generation import (
    EnterpriseDlpVerdict,
    EnterpriseGeneratedOutput,
    EnterpriseGenerationGuard,
    EnterpriseModelRoutePolicy,
    EnterprisePreparedGeneration,
)
from gateway.enterprise_retrieval import (
    EnterpriseAuthorizedChunk,
    EnterpriseCitationAuthorizationGuard,
    EnterpriseContentReader,
    EnterprisePermissionAwareRetriever,
    EnterpriseRetrievalError,
    EnterpriseRetrievalResult,
    EnterpriseScopeFenceChecker,
)
from orchestrator.enterprise_ingest import (
    EnterpriseIngestPlan,
    EnterpriseSecureIngestPlanner,
    EnterpriseSourceBlock,
)
from orchestrator.plugin_kernel import (
    PluginKernel,
    PluginManifestV1,
    ServiceDefinition,
    ServiceNotFound,
)

ENTERPRISE_RAG_SPLITTER_SERVICE = "enterprise.rag.splitter"
ENTERPRISE_RAG_EMBEDDER_SERVICE = "enterprise.rag.embedder"
ENTERPRISE_RAG_CANDIDATES_SERVICE = "enterprise.rag.candidates"
ENTERPRISE_RAG_RERANKER_SERVICE = "enterprise.rag.reranker"
ENTERPRISE_RAG_DLP_SERVICE = "enterprise.rag.dlp"
ENTERPRISE_RAG_RUNTIME_SERVICE = "enterprise.rag.runtime"

BUILTIN_ENTERPRISE_SPLITTER_PLUGIN_ID = "com.nachuan.enterprise-rag.splitter"
BUILTIN_ENTERPRISE_RERANKER_PLUGIN_ID = "com.nachuan.enterprise-rag.reranker"
BUILTIN_ENTERPRISE_DLP_PLUGIN_ID = "com.nachuan.enterprise-rag.dlp-deny"
BUILTIN_ENTERPRISE_RUNTIME_PLUGIN_ID = "com.nachuan.enterprise-rag.runtime"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_EMBEDDING_ITEMS = 4_096
_MAX_EMBEDDING_DIMENSION = 4_096
_MAX_EMBEDDING_VALUES = 2_000_000
_MAX_EMBEDDING_TEXT_BYTES = 64 * 1024 * 1024


class EnterpriseRagPluginError(RuntimeError):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseRagPluginError(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise EnterpriseRagPluginError(f"{field} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EnterpriseRagPluginError("enterprise RAG plugin value is invalid") from exc


@dataclass(frozen=True, slots=True)
class EnterpriseEmbeddingInput:
    tenant_id: str
    document_id: str
    chunk_id: str
    policy_id: str
    policy_epoch: int
    classification: int
    content_hash: str
    text: str

    def __post_init__(self) -> None:
        for field in ("tenant_id", "document_id", "chunk_id", "policy_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        object.__setattr__(
            self,
            "content_hash",
            _digest(self.content_hash, "content_hash"),
        )
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseRagPluginError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise EnterpriseRagPluginError("classification is invalid")
        if not isinstance(self.text, str) or not self.text:
            raise EnterpriseRagPluginError("embedding text is invalid")
        if hashlib.sha256(self.text.encode("utf-8", errors="strict")).hexdigest() != self.content_hash:
            raise EnterpriseRagPluginError("embedding content hash differs")


@dataclass(frozen=True, slots=True)
class EnterpriseEmbeddingVector:
    tenant_id: str
    document_id: str
    chunk_id: str
    policy_id: str
    policy_epoch: int
    classification: int
    content_hash: str
    model_id: str
    vector: tuple[float, ...]

    def __post_init__(self) -> None:
        for field in ("tenant_id", "document_id", "chunk_id", "policy_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseRagPluginError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise EnterpriseRagPluginError("classification is invalid")
        object.__setattr__(
            self,
            "content_hash",
            _digest(self.content_hash, "content_hash"),
        )
        object.__setattr__(self, "model_id", _identifier(self.model_id, "model_id"))
        if (
            not isinstance(self.vector, tuple)
            or not self.vector
            or len(self.vector) > _MAX_EMBEDDING_DIMENSION
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in self.vector
            )
        ):
            raise EnterpriseRagPluginError("embedding vector is invalid")
        object.__setattr__(self, "vector", tuple(float(value) for value in self.vector))


@dataclass(frozen=True, slots=True)
class EnterpriseEmbeddingBatch:
    tenant_id: str
    source_id: str
    source_version: str
    policy_epoch: int
    model_id: str
    dimension: int
    vectors: tuple[EnterpriseEmbeddingVector, ...]
    batch_digest: str


class EnterpriseEmbeddingProvider(Protocol):
    def embed(
        self,
        *,
        items: tuple[EnterpriseEmbeddingInput, ...],
        model_id: str,
        deadline_monotonic: float,
    ) -> Sequence[EnterpriseEmbeddingVector]: ...


class BuiltinEnterpriseSemanticSplitter:
    """Deterministic no-network splitter that never crosses a supplied block."""

    def split(self, *, text: str, max_chunk_chars: int) -> tuple[str, ...]:
        parts: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + max_chunk_chars, len(text))
            if end < len(text):
                minimum = start + max_chunk_chars // 2
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
                raise EnterpriseRagPluginError("splitter made no progress")
            parts.append(part)
            start = end
        return tuple(parts)


class BuiltinAuthorizedOrderReranker:
    """No-op baseline; it can only return the already-authorized closure."""

    def rerank(
        self,
        *,
        query: str,
        chunks: tuple[EnterpriseAuthorizedChunk, ...],
    ) -> tuple[str, ...]:
        del query
        return tuple(chunk.chunk_id for chunk in chunks)


class BuiltinDenyAllDlpScanner:
    """Production-safe placeholder until a real reviewed DLP provider is mounted."""

    def scan(
        self,
        *,
        tenant_id: str,
        text: str,
        direction: str,
        classification: int,
    ) -> EnterpriseDlpVerdict:
        del tenant_id, text, direction, classification
        return EnterpriseDlpVerdict(
            action="deny",
            text="",
            risk_codes=("dlp_not_configured",),
            scanner_version="deny-all-v1",
        )


class EnterpriseRagPluginRuntime:
    """Borrow replaceable components while retaining security gates in the caller."""

    def __init__(self, kernel: PluginKernel) -> None:
        if not isinstance(kernel, PluginKernel):
            raise TypeError("plugin kernel is invalid")
        self._kernel = kernel

    def readiness_snapshot(self) -> dict[str, object]:
        service_methods = {
            "splitter": (ENTERPRISE_RAG_SPLITTER_SERVICE, "split"),
            "embedder": (ENTERPRISE_RAG_EMBEDDER_SERVICE, "embed"),
            "candidates": (ENTERPRISE_RAG_CANDIDATES_SERVICE, "search"),
            "reranker": (ENTERPRISE_RAG_RERANKER_SERVICE, "rerank"),
            "dlp": (ENTERPRISE_RAG_DLP_SERVICE, "scan"),
        }
        providers: dict[str, bool] = {}
        owners: dict[str, str] = {}
        for component, (service, method) in service_methods.items():
            try:
                lease = self._kernel.borrow_service(service)
            except ServiceNotFound:
                providers[component] = False
                continue
            try:
                providers[component] = callable(getattr(lease.value, method, None))
                owners[component] = lease.owner_plugin_id
            finally:
                lease.release()
        dlp_mode = "unavailable"
        if providers["dlp"]:
            dlp_mode = (
                "deny_all"
                if owners.get("dlp") == BUILTIN_ENTERPRISE_DLP_PLUGIN_ID
                else "configured"
            )
        components_ready = bool(
            all(providers.values()) and dlp_mode == "configured"
        )
        return {
            "schema": "nachuan.enterprise-rag-plugin-readiness.v1",
            "components": providers,
            "dlp_mode": dlp_mode,
            "components_ready": components_ready,
            "api_enabled": False,
            "production_ready": False,
        }

    def plan_source_snapshot(
        self,
        *,
        tenant_id: str,
        source_id: str,
        source_version: str,
        expected_policy_epoch: int,
        blocks: Iterable[EnterpriseSourceBlock],
        max_chunk_chars: int = 1_200,
    ) -> EnterpriseIngestPlan:
        lease = self._borrow(ENTERPRISE_RAG_SPLITTER_SERVICE, "split")
        try:
            splitter = lease.value
            planner = EnterpriseSecureIngestPlanner(
                max_chunk_chars=max_chunk_chars,
                splitter=splitter,
            )
            return planner.plan_source_snapshot(
                tenant_id=tenant_id,
                source_id=source_id,
                source_version=source_version,
                expected_policy_epoch=expected_policy_epoch,
                blocks=blocks,
            )
        finally:
            lease.release()

    def embed_plan(
        self,
        plan: EnterpriseIngestPlan,
        *,
        model_id: str,
        expected_dimension: int,
        timeout_seconds: float = 10.0,
        monotonic_clock=time.monotonic,
    ) -> EnterpriseEmbeddingBatch:
        model = _identifier(model_id, "model_id")
        if (
            not isinstance(plan, EnterpriseIngestPlan)
            or plan.status != "ready"
            or plan.reason_codes
            or not plan.documents
        ):
            raise EnterpriseRagPluginError("embedding plan is unavailable")
        if (
            isinstance(expected_dimension, bool)
            or not isinstance(expected_dimension, int)
            or not 1 <= expected_dimension <= _MAX_EMBEDDING_DIMENSION
        ):
            raise EnterpriseRagPluginError("embedding dimension is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.001 <= float(timeout_seconds) <= 30.0
            or not callable(monotonic_clock)
        ):
            raise EnterpriseRagPluginError("embedding timeout is invalid")
        inputs = self._embedding_inputs(plan)
        if len(inputs) * expected_dimension > _MAX_EMBEDDING_VALUES:
            raise EnterpriseRagPluginError("embedding batch exceeds size limit")
        lease = self._borrow(ENTERPRISE_RAG_EMBEDDER_SERVICE, "embed")
        try:
            deadline = monotonic_clock() + float(timeout_seconds)
            try:
                raw = lease.value.embed(
                    items=inputs,
                    model_id=model,
                    deadline_monotonic=deadline,
                )
            except Exception:  # noqa: BLE001 -- plugin details cannot cross the seam
                raise EnterpriseRagPluginError("embedding provider unavailable") from None
            if monotonic_clock() > deadline:
                raise EnterpriseRagPluginError("embedding provider timed out")
            vectors = self._embedding_closure(
                raw,
                inputs=inputs,
                model_id=model,
                expected_dimension=expected_dimension,
            )
            body = {
                "tenant_id": plan.tenant_id,
                "source_id": plan.source_id,
                "source_version": plan.source_version,
                "policy_epoch": plan.policy_epoch,
                "model_id": model,
                "dimension": expected_dimension,
                "vectors": [
                    {
                        "chunk_id": vector.chunk_id,
                        "document_id": vector.document_id,
                        "policy_id": vector.policy_id,
                        "policy_epoch": vector.policy_epoch,
                        "classification": vector.classification,
                        "content_hash": vector.content_hash,
                        "vector": vector.vector,
                    }
                    for vector in vectors
                ],
            }
            return EnterpriseEmbeddingBatch(
                tenant_id=plan.tenant_id,
                source_id=plan.source_id,
                source_version=plan.source_version,
                policy_epoch=plan.policy_epoch,
                model_id=model,
                dimension=expected_dimension,
                vectors=vectors,
                batch_digest=hashlib.sha256(_canonical_json(body)).hexdigest(),
            )
        finally:
            lease.release()

    def retrieve(
        self,
        *,
        context: EnterpriseRequestContext,
        query: str,
        k: int,
        authorization: EnterpriseAuthorizationFacade,
        content_reader: EnterpriseContentReader,
        fence_checker: EnterpriseScopeFenceChecker,
    ) -> EnterpriseRetrievalResult:
        self._security_inputs(authorization, content_reader, fence_checker)
        candidate_lease = self._borrow(ENTERPRISE_RAG_CANDIDATES_SERVICE, "search")
        reranker_lease = self._borrow(ENTERPRISE_RAG_RERANKER_SERVICE, "rerank")
        try:
            retriever = EnterprisePermissionAwareRetriever(
                candidate_source=candidate_lease.value,
                authorization=authorization,
                content_reader=content_reader,
                fence_checker=fence_checker,
                reranker=reranker_lease.value,
            )
            try:
                return retriever.retrieve(context=context, query=query, k=k)
            except EnterpriseRetrievalError:
                raise
            except Exception:  # noqa: BLE001 -- plugin details cannot cross the seam
                raise EnterpriseRagPluginError(
                    "enterprise RAG retrieval component unavailable"
                ) from None
        finally:
            reranker_lease.release()
            candidate_lease.release()

    def prepare_generation(
        self,
        *,
        context: EnterpriseRequestContext,
        retrieval: EnterpriseRetrievalResult,
        corpus_epoch: int,
        route: EnterpriseModelRoutePolicy,
        authorization: EnterpriseAuthorizationFacade,
        fence_checker: EnterpriseScopeFenceChecker,
        audit_key: bytes,
    ) -> EnterprisePreparedGeneration:
        guard, lease = self._generation_guard(
            authorization=authorization,
            fence_checker=fence_checker,
            audit_key=audit_key,
        )
        try:
            return guard.prepare(
                context=context,
                retrieval=retrieval,
                corpus_epoch=corpus_epoch,
                route=route,
            )
        finally:
            lease.release()

    def validate_output(
        self,
        *,
        context: EnterpriseRequestContext,
        prepared: EnterprisePreparedGeneration,
        text: str,
        cited_chunk_ids: Iterable[str],
        authorization: EnterpriseAuthorizationFacade,
        fence_checker: EnterpriseScopeFenceChecker,
        audit_key: bytes,
    ) -> EnterpriseGeneratedOutput:
        guard, lease = self._generation_guard(
            authorization=authorization,
            fence_checker=fence_checker,
            audit_key=audit_key,
        )
        try:
            return guard.validate_output(
                context=context,
                prepared=prepared,
                text=text,
                cited_chunk_ids=cited_chunk_ids,
            )
        finally:
            lease.release()

    def _generation_guard(self, *, authorization, fence_checker, audit_key):
        if not isinstance(authorization, EnterpriseAuthorizationFacade):
            raise EnterpriseRagPluginError("authorization is invalid")
        citation_guard = EnterpriseCitationAuthorizationGuard(
            authorization=authorization,
            fence_checker=fence_checker,
        )
        lease = self._borrow(ENTERPRISE_RAG_DLP_SERVICE, "scan")
        try:
            guard = EnterpriseGenerationGuard(
                citation_revalidator=citation_guard,
                dlp_scanner=lease.value,
                audit_key=audit_key,
            )
        except BaseException:
            lease.release()
            raise
        return guard, lease

    def _borrow(self, service: str, method: str):
        try:
            lease = self._kernel.borrow_service(service)
        except ServiceNotFound:
            raise EnterpriseRagPluginError(
                f"enterprise RAG component unavailable: {service}"
            ) from None
        if not callable(getattr(lease.value, method, None)):
            lease.release()
            raise EnterpriseRagPluginError(
                f"enterprise RAG component invalid: {service}"
            )
        return lease

    @staticmethod
    def _security_inputs(authorization, content_reader, fence_checker) -> None:
        if not isinstance(authorization, EnterpriseAuthorizationFacade):
            raise EnterpriseRagPluginError("authorization is invalid")
        if not callable(getattr(content_reader, "read_many", None)):
            raise EnterpriseRagPluginError("content_reader is invalid")
        if not callable(getattr(fence_checker, "is_scope_fenced", None)):
            raise EnterpriseRagPluginError("fence_checker is invalid")

    @staticmethod
    def _embedding_inputs(
        plan: EnterpriseIngestPlan,
    ) -> tuple[EnterpriseEmbeddingInput, ...]:
        try:
            EnterpriseSecureIngestPlanner.validate_plan(plan)
        except Exception:  # noqa: BLE001 -- preserve a closed integrity error
            raise EnterpriseRagPluginError("embedding plan integrity failed") from None
        payloads = {payload.chunk_id: payload for payload in plan.payloads}
        metadata = [
            (document, chunk)
            for document in plan.documents
            for chunk in document.chunks
        ]
        if (
            not metadata
            or len(metadata) > _MAX_EMBEDDING_ITEMS
            or len(payloads) != len(plan.payloads)
            or set(payloads) != {chunk.chunk_id for _document, chunk in metadata}
        ):
            raise EnterpriseRagPluginError("embedding input closure differs")
        inputs = tuple(
            EnterpriseEmbeddingInput(
                tenant_id=plan.tenant_id,
                document_id=document.document_id,
                chunk_id=chunk.chunk_id,
                policy_id=chunk.policy_id,
                policy_epoch=chunk.policy_epoch,
                classification=chunk.classification,
                content_hash=chunk.content_hash,
                text=payloads[chunk.chunk_id].text,
            )
            for document, chunk in metadata
        )
        if sum(len(item.text.encode("utf-8")) for item in inputs) > _MAX_EMBEDDING_TEXT_BYTES:
            raise EnterpriseRagPluginError("embedding input exceeds size limit")
        return inputs

    @staticmethod
    def _embedding_closure(
        value: object,
        *,
        inputs: tuple[EnterpriseEmbeddingInput, ...],
        model_id: str,
        expected_dimension: int,
    ) -> tuple[EnterpriseEmbeddingVector, ...]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise EnterpriseRagPluginError("embedding result is invalid")
        vectors = tuple(value)
        if any(not isinstance(item, EnterpriseEmbeddingVector) for item in vectors):
            raise EnterpriseRagPluginError("embedding result is invalid")
        if len(vectors) != len(inputs):
            raise EnterpriseRagPluginError("embedding result closure differs")
        for source, vector in zip(inputs, vectors, strict=True):
            if (
                vector.chunk_id != source.chunk_id
                or vector.tenant_id != source.tenant_id
                or vector.document_id != source.document_id
                or vector.policy_id != source.policy_id
                or vector.policy_epoch != source.policy_epoch
                or vector.classification != source.classification
                or vector.content_hash != source.content_hash
                or vector.model_id != model_id
                or len(vector.vector) != expected_dimension
            ):
                raise EnterpriseRagPluginError("embedding result closure differs")
        return vectors


def _manifest(
    *,
    plugin_id: str,
    kind: str,
    capability: str,
    contract: str,
) -> PluginManifestV1:
    return PluginManifestV1.from_mapping(
        {
            "schema": "nachuan.plugin.v1",
            "id": plugin_id,
            "version": "1.0.0",
            "api_version": "1",
            "kind": kind,
            "capabilities": [capability],
            "artifact_sha256": hashlib.sha256(contract.encode("ascii")).hexdigest(),
            "execution": "in_process",
            "trust": "builtin",
            "publisher": "杭州灵界科技有限公司",
        }
    )


BUILTIN_ENTERPRISE_SPLITTER_MANIFEST = _manifest(
    plugin_id=BUILTIN_ENTERPRISE_SPLITTER_PLUGIN_ID,
    kind="rag_splitter",
    capability="enterprise.rag.split",
    contract="nachuan.enterprise.rag.splitter.v1",
)
BUILTIN_ENTERPRISE_RERANKER_MANIFEST = _manifest(
    plugin_id=BUILTIN_ENTERPRISE_RERANKER_PLUGIN_ID,
    kind="rag_reranker",
    capability="enterprise.rag.rerank.authorized",
    contract="nachuan.enterprise.rag.reranker.v1",
)
BUILTIN_ENTERPRISE_DLP_MANIFEST = _manifest(
    plugin_id=BUILTIN_ENTERPRISE_DLP_PLUGIN_ID,
    kind="rag_dlp",
    capability="enterprise.rag.dlp.deny",
    contract="nachuan.enterprise.rag.dlp-deny.v1",
)
BUILTIN_ENTERPRISE_RUNTIME_MANIFEST = _manifest(
    plugin_id=BUILTIN_ENTERPRISE_RUNTIME_PLUGIN_ID,
    kind="rag_runtime",
    capability="enterprise.rag.compose",
    contract="nachuan.enterprise.rag.runtime.v1",
)


def mount_builtin_enterprise_rag_plugins(kernel: PluginKernel) -> None:
    for name in (
        ENTERPRISE_RAG_SPLITTER_SERVICE,
        ENTERPRISE_RAG_EMBEDDER_SERVICE,
        ENTERPRISE_RAG_CANDIDATES_SERVICE,
        ENTERPRISE_RAG_RERANKER_SERVICE,
        ENTERPRISE_RAG_DLP_SERVICE,
        ENTERPRISE_RAG_RUNTIME_SERVICE,
    ):
        kernel.services.define(ServiceDefinition(name, "1"))

    def mount_component(manifest, capability, service, value) -> None:
        def apply(ctx) -> None:
            ctx.permit(capability)
            ctx.provide_service(service, value)

        kernel.mount(manifest, apply)

    mount_component(
        BUILTIN_ENTERPRISE_SPLITTER_MANIFEST,
        "enterprise.rag.split",
        ENTERPRISE_RAG_SPLITTER_SERVICE,
        BuiltinEnterpriseSemanticSplitter(),
    )
    mount_component(
        BUILTIN_ENTERPRISE_RERANKER_MANIFEST,
        "enterprise.rag.rerank.authorized",
        ENTERPRISE_RAG_RERANKER_SERVICE,
        BuiltinAuthorizedOrderReranker(),
    )
    mount_component(
        BUILTIN_ENTERPRISE_DLP_MANIFEST,
        "enterprise.rag.dlp.deny",
        ENTERPRISE_RAG_DLP_SERVICE,
        BuiltinDenyAllDlpScanner(),
    )
    mount_component(
        BUILTIN_ENTERPRISE_RUNTIME_MANIFEST,
        "enterprise.rag.compose",
        ENTERPRISE_RAG_RUNTIME_SERVICE,
        EnterpriseRagPluginRuntime(kernel),
    )


__all__ = [
    "BUILTIN_ENTERPRISE_DLP_MANIFEST",
    "BUILTIN_ENTERPRISE_DLP_PLUGIN_ID",
    "BUILTIN_ENTERPRISE_RERANKER_MANIFEST",
    "BUILTIN_ENTERPRISE_RERANKER_PLUGIN_ID",
    "BUILTIN_ENTERPRISE_RUNTIME_MANIFEST",
    "BUILTIN_ENTERPRISE_RUNTIME_PLUGIN_ID",
    "BUILTIN_ENTERPRISE_SPLITTER_MANIFEST",
    "BUILTIN_ENTERPRISE_SPLITTER_PLUGIN_ID",
    "ENTERPRISE_RAG_CANDIDATES_SERVICE",
    "ENTERPRISE_RAG_DLP_SERVICE",
    "ENTERPRISE_RAG_EMBEDDER_SERVICE",
    "ENTERPRISE_RAG_RERANKER_SERVICE",
    "ENTERPRISE_RAG_RUNTIME_SERVICE",
    "ENTERPRISE_RAG_SPLITTER_SERVICE",
    "BuiltinAuthorizedOrderReranker",
    "BuiltinDenyAllDlpScanner",
    "BuiltinEnterpriseSemanticSplitter",
    "EnterpriseEmbeddingBatch",
    "EnterpriseEmbeddingInput",
    "EnterpriseEmbeddingProvider",
    "EnterpriseEmbeddingVector",
    "EnterpriseRagPluginError",
    "EnterpriseRagPluginRuntime",
    "mount_builtin_enterprise_rag_plugins",
]
