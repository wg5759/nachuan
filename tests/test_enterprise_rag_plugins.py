from __future__ import annotations

import hashlib
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from gateway.enterprise_authz import (
    EnterpriseAuthorizationFacade,
    EnterprisePolicyComponentDecision,
)
from gateway.enterprise_context import EnterpriseRequestContext
from gateway.enterprise_generation import (
    EnterpriseDlpVerdict,
    EnterpriseGenerationError,
    EnterpriseModelRoutePolicy,
)
from gateway.enterprise_rag_plugins import (
    BUILTIN_ENTERPRISE_DLP_MANIFEST,
    BUILTIN_ENTERPRISE_DLP_PLUGIN_ID,
    BUILTIN_ENTERPRISE_RERANKER_PLUGIN_ID,
    BUILTIN_ENTERPRISE_RUNTIME_PLUGIN_ID,
    BUILTIN_ENTERPRISE_SPLITTER_MANIFEST,
    BUILTIN_ENTERPRISE_SPLITTER_PLUGIN_ID,
    ENTERPRISE_RAG_CANDIDATES_SERVICE,
    ENTERPRISE_RAG_DLP_SERVICE,
    ENTERPRISE_RAG_EMBEDDER_SERVICE,
    ENTERPRISE_RAG_RERANKER_SERVICE,
    ENTERPRISE_RAG_RUNTIME_SERVICE,
    ENTERPRISE_RAG_SPLITTER_SERVICE,
    EnterpriseEmbeddingVector,
    EnterpriseRagPluginError,
    EnterpriseRagPluginRuntime,
    mount_builtin_enterprise_rag_plugins,
)
from gateway.enterprise_retrieval import (
    EnterpriseCandidatePage,
    EnterpriseContentRecord,
    EnterpriseVectorCandidate,
)
from orchestrator.enterprise_ingest import EnterpriseSourceBlock
from orchestrator.enterprise_knowledge import EnterpriseKnowledgeError
from orchestrator.plugin_kernel import (
    PluginInUseError,
    PluginKernel,
    PluginManifestV1,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _context(epoch: int = 7) -> EnterpriseRequestContext:
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


def _block(
    block_id: str,
    text: str,
    *,
    policy: str = "policy-a",
    classification: int = 3,
) -> EnterpriseSourceBlock:
    return EnterpriseSourceBlock(
        block_id=block_id,
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        policy_id=policy,
        policy_epoch=7,
        classification=classification,
        acl_digest=_hash(f"acl:{policy}"),
        text=text,
    )


def _test_manifest(plugin_id: str, capability: str) -> PluginManifestV1:
    return PluginManifestV1.from_mapping(
        {
            "schema": "nachuan.plugin.v1",
            "id": plugin_id,
            "version": "1.0.0",
            "api_version": "1",
            "kind": "rag_test",
            "capabilities": [capability],
            "artifact_sha256": hashlib.sha256(plugin_id.encode()).hexdigest(),
            "execution": "in_process",
            "trust": "builtin",
            "publisher": "nachuan-tests",
        }
    )


def _mount_service(kernel, *, plugin_id, capability, service, value):
    manifest = _test_manifest(plugin_id, capability)

    def apply(ctx) -> None:
        ctx.permit(capability)
        ctx.provide_service(service, value)

    kernel.mount(manifest, apply)
    return manifest


def _runtime(kernel: PluginKernel):
    lease = kernel.borrow_service(ENTERPRISE_RAG_RUNTIME_SERVICE)
    assert isinstance(lease.value, EnterpriseRagPluginRuntime)
    return lease, lease.value


class _Evaluator:
    def __init__(self, allowed: set[str]):
        self.allowed = allowed
        self.calls: list[tuple[str, ...]] = []

    def batch_check(self, *, context, resources, deadline_monotonic):
        del context, deadline_monotonic
        self.calls.append(tuple(resource.resource_id for resource in resources))
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
                obligations=(
                    ("citation_required", "no_training")
                    if resource.resource_id in self.allowed
                    else ()
                ),
            )
            for resource in resources
        )


def _authorization(allowed: set[str]) -> EnterpriseAuthorizationFacade:
    evaluator = _Evaluator(allowed)
    return EnterpriseAuthorizationFacade(
        relationship_evaluator=evaluator,
        attribute_evaluator=evaluator,
        audit_key=b"enterprise-rag-plugin-authz-key-32-bytes",
    )


class _ContentReader:
    def __init__(self, contents: dict[str, str]):
        self.contents = contents
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def read_many(self, *, tenant_id, chunk_ids):
        self.calls.append((tenant_id, chunk_ids))
        return tuple(
            EnterpriseContentRecord(
                tenant_id=tenant_id,
                chunk_id=chunk_id,
                content_hash=_hash(self.contents[chunk_id]),
                text=self.contents[chunk_id],
            )
            for chunk_id in chunk_ids
        )


class _Fences:
    def __init__(self):
        self.fenced: set[str] = set()
        self.calls: list[str] = []

    def is_scope_fenced(self, *, tenant_id, resource_scope, expected_policy_epoch):
        del tenant_id, expected_policy_epoch
        self.calls.append(resource_scope)
        return resource_scope in self.fenced


class _Candidates:
    def __init__(self, contents: dict[str, str]):
        self.contents = contents
        self.calls: list[str] = []

    def search(self, *, tenant_id, query, limit, cursor):
        del limit, cursor
        self.calls.append(tenant_id)
        return EnterpriseCandidatePage(
            candidates=tuple(
                EnterpriseVectorCandidate(
                    tenant_id=tenant_id,
                    chunk_id=chunk_id,
                    document_id=f"document-{chunk_id}",
                    policy_id="policy-a",
                    policy_epoch=7,
                    classification=3,
                    content_hash=_hash(text),
                    score=2.0 if chunk_id == "denied" else 1.0,
                )
                for chunk_id, text in self.contents.items()
            ),
            next_cursor=None,
        )


class _Embedder:
    def __init__(self, *, tamper: bool = False):
        self.tamper = tamper
        self.seen = ()

    def embed(self, *, items, model_id, deadline_monotonic):
        del deadline_monotonic
        self.seen = items
        return tuple(
            EnterpriseEmbeddingVector(
                tenant_id=item.tenant_id,
                document_id=item.document_id,
                chunk_id=item.chunk_id,
                policy_id=item.policy_id,
                policy_epoch=item.policy_epoch,
                classification=item.classification,
                content_hash=("0" * 64 if self.tamper else item.content_hash),
                model_id=model_id,
                vector=(0.1, 0.2, 0.3),
            )
            for item in items
        )


class _Scanner:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    def scan(self, *, tenant_id, text, direction, classification):
        del tenant_id, classification
        self.calls.append((direction, _hash(text)))
        return EnterpriseDlpVerdict(
            action="allow",
            text=text,
            risk_codes=(),
            scanner_version="test-dlp-v1",
        )


def _route() -> EnterpriseModelRoutePolicy:
    return EnterpriseModelRoutePolicy(
        model_id="enterprise-local",
        local_execution=True,
        allowed_regions=("cn-east",),
        max_classification=5,
        training_disabled=True,
    )


def test_builtin_mount_defines_all_seams_but_keeps_search_and_embedding_disabled() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)

    assert kernel.active_plugin_ids() == (
        BUILTIN_ENTERPRISE_SPLITTER_PLUGIN_ID,
        BUILTIN_ENTERPRISE_RERANKER_PLUGIN_ID,
        BUILTIN_ENTERPRISE_DLP_PLUGIN_ID,
        BUILTIN_ENTERPRISE_RUNTIME_PLUGIN_ID,
    )
    assert kernel.services.has_provider(ENTERPRISE_RAG_SPLITTER_SERVICE)
    assert kernel.services.has_provider(ENTERPRISE_RAG_RERANKER_SERVICE)
    assert kernel.services.has_provider(ENTERPRISE_RAG_DLP_SERVICE)
    assert kernel.services.has_provider(ENTERPRISE_RAG_RUNTIME_SERVICE)
    assert not kernel.services.has_provider(ENTERPRISE_RAG_EMBEDDER_SERVICE)
    assert not kernel.services.has_provider(ENTERPRISE_RAG_CANDIDATES_SERVICE)
    runtime_lease, runtime = _runtime(kernel)
    try:
        assert runtime.readiness_snapshot() == {
            "schema": "nachuan.enterprise-rag-plugin-readiness.v1",
            "components": {
                "splitter": True,
                "embedder": False,
                "candidates": False,
                "reranker": True,
                "dlp": True,
            },
            "dlp_mode": "deny_all",
            "components_ready": False,
            "api_enabled": False,
            "production_ready": False,
        }
        _mount_service(
            kernel,
            plugin_id="com.nachuan.test.rag-embedder-invalid",
            capability="enterprise.rag.embed",
            service=ENTERPRISE_RAG_EMBEDDER_SERVICE,
            value=object(),
        )
        assert runtime.readiness_snapshot()["components"]["embedder"] is False
    finally:
        runtime_lease.release()


def test_health_projection_reports_components_without_claiming_enterprise_readiness() -> None:
    from gateway import app as gateway_app

    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)

    snapshot = gateway_app._enterprise_rag_plugin_readiness(
        SimpleNamespace(plugin_kernel=kernel)
    )

    assert snapshot["components"]["splitter"] is True
    assert snapshot["components"]["embedder"] is False
    assert snapshot["components"]["candidates"] is False
    assert snapshot["dlp_mode"] == "deny_all"
    assert snapshot["components_ready"] is False
    assert snapshot["api_enabled"] is False
    assert snapshot["production_ready"] is False


@pytest.mark.asyncio
async def test_splitter_is_replaceable_but_cannot_change_or_cross_source_text() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    runtime_lease, runtime = _runtime(kernel)
    try:
        plan = runtime.plan_source_snapshot(
            tenant_id="tenant-a",
            source_id="source-a",
            source_version="version-1",
            expected_policy_epoch=7,
            blocks=(
                _block("one", "visible " * 40),
                _block("two", "secret " * 40, policy="policy-b", classification=7),
            ),
            max_chunk_chars=128,
        )
        assert len(plan.documents) == 2
        assert {document.policy_id for document in plan.documents} == {
            "policy-a",
            "policy-b",
        }
    finally:
        runtime_lease.release()

    await kernel.unmount(BUILTIN_ENTERPRISE_SPLITTER_MANIFEST.plugin_id)

    class ChangedSplitter:
        def split(self, *, text, max_chunk_chars):
            del text, max_chunk_chars
            return ("changed",)

    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-splitter",
        capability="enterprise.rag.split",
        service=ENTERPRISE_RAG_SPLITTER_SERVICE,
        value=ChangedSplitter(),
    )
    runtime_lease, runtime = _runtime(kernel)
    try:
        with pytest.raises(EnterpriseKnowledgeError, match="changed source"):
            runtime.plan_source_snapshot(
                tenant_id="tenant-a",
                source_id="source-a",
                source_version="version-1",
                expected_policy_epoch=7,
                blocks=(_block("one", "original text"),),
            )
    finally:
        runtime_lease.release()


@pytest.mark.asyncio
async def test_embedding_is_disabled_by_default_then_accepts_only_exact_plan_closure() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    runtime_lease, runtime = _runtime(kernel)
    plan = runtime.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=7,
        blocks=(_block("one", "embedding input"),),
    )
    with pytest.raises(EnterpriseRagPluginError, match="component unavailable"):
        runtime.embed_plan(plan, model_id="embed-v1", expected_dimension=3)
    embedder = _Embedder()
    manifest = _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-embedder",
        capability="enterprise.rag.embed",
        service=ENTERPRISE_RAG_EMBEDDER_SERVICE,
        value=embedder,
    )
    batch = runtime.embed_plan(plan, model_id="embed-v1", expected_dimension=3)
    assert len(batch.vectors) == len(plan.payloads) == 1
    assert batch.vectors[0].content_hash == plan.documents[0].chunks[0].content_hash
    assert batch.tenant_id == "tenant-a" and batch.policy_epoch == 7
    assert len(batch.batch_digest) == 64
    assert embedder.seen[0].tenant_id == "tenant-a"
    runtime_lease.release()
    await kernel.unmount(manifest.plugin_id)


def test_embedding_provider_cannot_swap_chunk_hash_or_vector_dimension() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-embedder-bad",
        capability="enterprise.rag.embed",
        service=ENTERPRISE_RAG_EMBEDDER_SERVICE,
        value=_Embedder(tamper=True),
    )
    runtime_lease, runtime = _runtime(kernel)
    try:
        plan = runtime.plan_source_snapshot(
            tenant_id="tenant-a",
            source_id="source-a",
            source_version="version-1",
            expected_policy_epoch=7,
            blocks=(_block("one", "embedding input"),),
        )
        with pytest.raises(EnterpriseRagPluginError, match="plan integrity"):
            runtime.embed_plan(
                replace(plan, plan_digest="0" * 64),
                model_id="embed-v1",
                expected_dimension=3,
            )
        with pytest.raises(EnterpriseRagPluginError, match="closure"):
            runtime.embed_plan(plan, model_id="embed-v1", expected_dimension=3)
    finally:
        runtime_lease.release()


@pytest.mark.asyncio
async def test_only_authorized_plaintext_reaches_reranker_and_dlp() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    contents = {"denied": "never expose", "allowed": "authorized context"}
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-candidates",
        capability="enterprise.rag.candidates",
        service=ENTERPRISE_RAG_CANDIDATES_SERVICE,
        value=_Candidates(contents),
    )
    await kernel.unmount(BUILTIN_ENTERPRISE_DLP_MANIFEST.plugin_id)
    scanner = _Scanner()
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-dlp",
        capability="enterprise.rag.dlp",
        service=ENTERPRISE_RAG_DLP_SERVICE,
        value=scanner,
    )
    reader = _ContentReader(contents)
    fences = _Fences()
    authorization = _authorization({"allowed"})
    runtime_lease, runtime = _runtime(kernel)
    try:
        retrieval = runtime.retrieve(
            context=_context(),
            query="question",
            k=1,
            authorization=authorization,
            content_reader=reader,
            fence_checker=fences,
        )
        assert tuple(chunk.chunk_id for chunk in retrieval.chunks) == ("allowed",)
        assert reader.calls == [("tenant-a", ("allowed",))]
        prepared = runtime.prepare_generation(
            context=_context(),
            retrieval=retrieval,
            corpus_epoch=9,
            route=_route(),
            authorization=authorization,
            fence_checker=fences,
            audit_key=b"enterprise-rag-generation-audit-key-32-bytes",
        )
        output = runtime.validate_output(
            context=_context(),
            prepared=prepared,
            text="safe answer",
            cited_chunk_ids=("allowed",),
            authorization=authorization,
            fence_checker=fences,
            audit_key=b"enterprise-rag-generation-audit-key-32-bytes",
        )
        assert output.text == "safe answer"
        observed_hashes = {value for _direction, value in scanner.calls}
        assert _hash("authorized context") in observed_hashes
        assert _hash("never expose") not in observed_hashes
    finally:
        runtime_lease.release()


def test_default_dlp_provider_blocks_generation_instead_of_falling_back() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    contents = {"allowed": "authorized context"}
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-candidates-default-dlp",
        capability="enterprise.rag.candidates",
        service=ENTERPRISE_RAG_CANDIDATES_SERVICE,
        value=_Candidates(contents),
    )
    reader = _ContentReader(contents)
    fences = _Fences()
    authorization = _authorization({"allowed"})
    runtime_lease, runtime = _runtime(kernel)
    try:
        retrieval = runtime.retrieve(
            context=_context(),
            query="question",
            k=1,
            authorization=authorization,
            content_reader=reader,
            fence_checker=fences,
        )
        with pytest.raises(EnterpriseGenerationError, match="context DLP"):
            runtime.prepare_generation(
                context=_context(),
                retrieval=retrieval,
                corpus_epoch=9,
                route=_route(),
                authorization=authorization,
                fence_checker=fences,
                audit_key=b"enterprise-rag-generation-audit-key-32-bytes",
            )
    finally:
        runtime_lease.release()


@pytest.mark.asyncio
async def test_new_fence_after_prepare_blocks_output_before_dlp_release() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    contents = {"allowed": "authorized context"}
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-candidates-fence",
        capability="enterprise.rag.candidates",
        service=ENTERPRISE_RAG_CANDIDATES_SERVICE,
        value=_Candidates(contents),
    )
    await kernel.unmount(BUILTIN_ENTERPRISE_DLP_PLUGIN_ID)
    scanner = _Scanner()
    _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-dlp-fence",
        capability="enterprise.rag.dlp",
        service=ENTERPRISE_RAG_DLP_SERVICE,
        value=scanner,
    )
    reader = _ContentReader(contents)
    fences = _Fences()
    authorization = _authorization({"allowed"})
    runtime_lease, runtime = _runtime(kernel)
    try:
        retrieval = runtime.retrieve(
            context=_context(),
            query="question",
            k=1,
            authorization=authorization,
            content_reader=reader,
            fence_checker=fences,
        )
        prepared = runtime.prepare_generation(
            context=_context(),
            retrieval=retrieval,
            corpus_epoch=9,
            route=_route(),
            authorization=authorization,
            fence_checker=fences,
            audit_key=b"enterprise-rag-generation-audit-key-32-bytes",
        )
        calls_before = tuple(scanner.calls)
        fences.fenced.add("document-allowed")
        with pytest.raises(EnterpriseGenerationError, match="authorization changed"):
            runtime.validate_output(
                context=_context(),
                prepared=prepared,
                text="must not release",
                cited_chunk_ids=("allowed",),
                authorization=authorization,
                fence_checker=fences,
                audit_key=b"enterprise-rag-generation-audit-key-32-bytes",
            )
        assert tuple(scanner.calls) == calls_before
    finally:
        runtime_lease.release()


@pytest.mark.asyncio
async def test_component_lease_blocks_unmount_during_an_active_retrieval() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)
    started = threading.Event()
    release = threading.Event()

    class BlockingCandidates:
        def search(self, *, tenant_id, query, limit, cursor):
            del tenant_id, query, limit, cursor
            started.set()
            assert release.wait(5)
            return EnterpriseCandidatePage(candidates=(), next_cursor=None)

    candidate_manifest = _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-candidates-blocking",
        capability="enterprise.rag.candidates",
        service=ENTERPRISE_RAG_CANDIDATES_SERVICE,
        value=BlockingCandidates(),
    )
    runtime_lease, runtime = _runtime(kernel)
    errors: list[BaseException] = []

    def run() -> None:
        try:
            runtime.retrieve(
                context=_context(),
                query="question",
                k=1,
                authorization=_authorization(set()),
                content_reader=_ContentReader({}),
                fence_checker=_Fences(),
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert started.wait(5)
    with pytest.raises(PluginInUseError):
        await kernel.unmount(candidate_manifest.plugin_id)
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive() and errors == []
    await kernel.unmount(candidate_manifest.plugin_id)
    runtime_lease.release()


@pytest.mark.asyncio
async def test_component_failure_releases_lease_and_never_falls_back() -> None:
    kernel = PluginKernel()
    mount_builtin_enterprise_rag_plugins(kernel)

    class BrokenCandidates:
        def search(self, *, tenant_id, query, limit, cursor):
            del tenant_id, query, limit, cursor
            raise RuntimeError("secret backend detail")

    manifest = _mount_service(
        kernel,
        plugin_id="com.nachuan.test.rag-candidates-broken",
        capability="enterprise.rag.candidates",
        service=ENTERPRISE_RAG_CANDIDATES_SERVICE,
        value=BrokenCandidates(),
    )
    runtime_lease, runtime = _runtime(kernel)
    try:
        with pytest.raises(
            EnterpriseRagPluginError,
            match="retrieval component unavailable",
        ) as failure:
            runtime.retrieve(
                context=_context(),
                query="question",
                k=1,
                authorization=_authorization(set()),
                content_reader=_ContentReader({}),
                fence_checker=_Fences(),
            )
        assert "secret backend detail" not in str(failure.value)
    finally:
        runtime_lease.release()
    await kernel.unmount(manifest.plugin_id)
