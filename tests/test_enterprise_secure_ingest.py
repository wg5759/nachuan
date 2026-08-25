from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace

import pytest

from orchestrator.enterprise_ingest import (
    EnterpriseChunkPayload,
    EnterpriseSecureIngestPlanner,
    EnterpriseSourceBlock,
)
from orchestrator.enterprise_knowledge import (
    EnterpriseChunkMetadata,
    EnterpriseKnowledgeError,
    EnterpriseKnowledgeStore,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _block(
    block_id: str,
    text: str,
    *,
    tenant: str = "tenant-a",
    source: str = "source-a",
    version: str = "version-1",
    policy: str = "policy-a",
    epoch: int = 1,
    classification: int = 2,
    acl: str = "acl-a",
) -> EnterpriseSourceBlock:
    return EnterpriseSourceBlock(
        block_id=block_id,
        tenant_id=tenant,
        source_id=source,
        source_version=version,
        policy_id=policy,
        policy_epoch=epoch,
        classification=classification,
        acl_digest=_digest(acl),
        text=text,
    )


def _source_chunk(
    chunk_id: str, *, policy: str = "policy-a", epoch: int = 1, classification: int = 2
) -> EnterpriseChunkMetadata:
    return EnterpriseChunkMetadata(
        chunk_id=chunk_id,
        ordinal=0,
        content_ref=f"object:{chunk_id}",
        content_hash=_digest(f"content:{chunk_id}"),
        policy_id=policy,
        policy_epoch=epoch,
        classification=classification,
        provenance_digest=_digest(f"provenance:{chunk_id}"),
    )


def test_permission_boundaries_split_before_chunking_and_stage_as_one_family(tmp_path) -> None:
    planner = EnterpriseSecureIngestPlanner(max_chunk_chars=128)
    first_text = ("公开段落。" * 30) + "\n"
    second_text = "高密内容。" * 20
    plan = planner.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=1,
        blocks=(
            _block("block-1", first_text),
            _block("block-2", second_text, policy="policy-b", classification=6, acl="acl-b"),
        ),
    )

    assert plan.status == "ready"
    assert len(plan.documents) == 2
    assert {document.policy_id for document in plan.documents} == {"policy-a", "policy-b"}
    assert {document.classification for document in plan.documents} == {2, 6}
    first_payload_count = len(plan.documents[0].chunks)
    assert "".join(payload.text for payload in plan.payloads[:first_payload_count]) == first_text
    assert "".join(payload.text for payload in plan.payloads[first_payload_count:]) == second_text

    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")
    receipt = planner.stage_isolated(store, plan)

    assert receipt["status"] == "isolated"
    assert receipt["document_count"] == 2
    assert all(row["status"] == "isolated" for row in store.list_documents("tenant-a", 1))
    connection = sqlite3.connect(tmp_path / "knowledge-v2.db")
    assert connection.execute("SELECT COUNT(*) FROM kb_v2_policy_outbox").fetchone() == (1,)
    assert "公开段落" not in (tmp_path / "knowledge-v2.db").read_bytes().decode(
        "utf-8", errors="ignore"
    )
    connection.close()
    store.close()


def test_mismatched_identity_or_acl_snapshot_is_quarantined_without_metadata(tmp_path) -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=1,
        blocks=(
            _block("block-1", "safe"),
            _block("block-2", "wrong tenant", tenant="tenant-b", epoch=2),
        ),
    )

    assert plan.status == "quarantined"
    assert plan.documents == () and plan.payloads == ()
    assert plan.reason_codes == ("tenant_boundary_ambiguous", "policy_epoch_mismatch")

    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")
    with pytest.raises(EnterpriseKnowledgeError, match="quarantined"):
        planner.stage_isolated(store, plan)
    assert store.list_documents("tenant-a", 1) == []
    store.close()


def test_derived_artifact_inherits_highest_classification_and_never_lowers_it() -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_derived_artifact(
        tenant_id="tenant-a",
        derived_id="summary-a",
        source_version="version-1",
        text="derived summary",
        sources=(
            _source_chunk("source-1", classification=2),
            _source_chunk("source-2", classification=7),
        ),
    )

    assert plan.status == "ready"
    assert plan.documents[0].classification == 7
    assert {chunk.classification for chunk in plan.documents[0].chunks} == {7}


def test_derived_artifact_with_uncompiled_policy_intersection_is_quarantined() -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_derived_artifact(
        tenant_id="tenant-a",
        derived_id="summary-a",
        source_version="version-1",
        text="must not be searchable",
        sources=(
            _source_chunk("source-1", policy="policy-a"),
            _source_chunk("source-2", policy="policy-b"),
        ),
    )

    assert plan.status == "quarantined"
    assert plan.reason_codes == ("derived_policy_intersection_unavailable",)
    assert plan.documents == () and plan.payloads == ()


def test_plan_digest_prevents_metadata_tampering_before_staging(tmp_path) -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=1,
        blocks=(_block("block-1", "safe"),),
    )
    tampered = replace(plan, plan_digest="0" * 64)
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")

    with pytest.raises(EnterpriseKnowledgeError, match="digest changed"):
        planner.stage_isolated(store, tampered)
    assert store.list_documents("tenant-a", 1) == []
    store.close()


def test_payload_text_or_reference_tampering_is_rejected_before_staging(tmp_path) -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=1,
        blocks=(_block("block-1", "safe"),),
    )
    tampered_payload = EnterpriseChunkPayload(
        chunk_id=plan.payloads[0].chunk_id,
        content_ref=plan.payloads[0].content_ref,
        text="changed",
    )
    tampered = replace(plan, payloads=(tampered_payload,))
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")

    with pytest.raises(EnterpriseKnowledgeError, match="payload changed"):
        planner.stage_isolated(store, tampered)
    assert store.list_documents("tenant-a", 1) == []
    store.close()


def test_document_family_insert_is_atomic_on_collision(tmp_path) -> None:
    planner = EnterpriseSecureIngestPlanner()
    plan = planner.plan_source_snapshot(
        tenant_id="tenant-a",
        source_id="source-a",
        source_version="version-1",
        expected_policy_epoch=1,
        blocks=(_block("block-1", "one"),),
    )
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")
    planner.stage_isolated(store, plan)
    before_epochs = store.current_epochs("tenant-a")
    before_documents = store.list_documents("tenant-a", 1)

    with pytest.raises(sqlite3.IntegrityError):
        planner.stage_isolated(store, plan)

    assert store.current_epochs("tenant-a") == before_epochs
    assert store.list_documents("tenant-a", 1) == before_documents
    store.close()
