from __future__ import annotations

import hashlib
import sqlite3

import pytest

from orchestrator.enterprise_knowledge import (
    EnterpriseChunkMetadata,
    EnterpriseKnowledgeError,
    EnterpriseKnowledgeStalePolicy,
    EnterpriseKnowledgeStore,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _chunk(chunk_id: str, ordinal: int, *, epoch: int = 1, classification: int = 2):
    return EnterpriseChunkMetadata(
        chunk_id=chunk_id,
        ordinal=ordinal,
        content_ref=f"object:{chunk_id}",
        content_hash=_digest(f"content:{chunk_id}"),
        policy_id="policy-a",
        policy_epoch=epoch,
        classification=classification,
        provenance_digest=_digest(f"provenance:{chunk_id}"),
    )


def _stage(store: EnterpriseKnowledgeStore, tenant: str, document: str):
    return store.stage_document(
        tenant_id=tenant,
        expected_policy_epoch=1,
        document_id=document,
        source_id="source-a",
        source_version="version-1",
        policy_id="policy-a",
        classification=2,
        content_hash=_digest(f"document:{document}"),
        chunks=[_chunk("chunk-0", 0), _chunk("chunk-1", 1, classification=3)],
    )


def test_stage_is_tenant_scoped_metadata_only_with_pending_outbox(tmp_path) -> None:
    path = tmp_path / "knowledge-v2.db"
    store = EnterpriseKnowledgeStore(path)
    store.initialize_tenant("tenant-a")

    receipt = _stage(store, "tenant-a", "document-a")

    assert receipt["status"] == "isolated"
    assert receipt["chunk_count"] == 2
    assert store.list_documents("tenant-a", 1)[0]["document_id"] == "document-a"
    connection = sqlite3.connect(path)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(kb_v2_chunks)")
    }
    assert "text" not in columns and "text_ciphertext" not in columns
    assert connection.execute(
        "SELECT state FROM kb_v2_policy_outbox"
    ).fetchone() == ("pending",)
    connection.close()
    store.close()


def test_same_ids_are_isolated_by_tenant(tmp_path) -> None:
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    for tenant in ("tenant-a", "tenant-b"):
        store.initialize_tenant(tenant)
        _stage(store, tenant, "document-a")

    assert len(store.list_documents("tenant-a", 1)) == 1
    assert len(store.list_documents("tenant-b", 1)) == 1
    store.close()


def test_chunk_cannot_be_less_restricted_than_document(tmp_path) -> None:
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")

    with pytest.raises(EnterpriseKnowledgeError, match="wider"):
        store.stage_document(
            tenant_id="tenant-a",
            expected_policy_epoch=1,
            document_id="document-a",
            source_id="source-a",
            source_version="version-1",
            policy_id="policy-a",
            classification=4,
            content_hash=_digest("document"),
            chunks=[_chunk("chunk-a", 0, classification=3)],
        )
    assert store.list_documents("tenant-a", 1) == []
    store.close()


def test_chunk_policy_must_match_staged_document_epoch(tmp_path) -> None:
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")

    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.stage_document(
            tenant_id="tenant-a",
            expected_policy_epoch=1,
            document_id="document-a",
            source_id="source-a",
            source_version="version-1",
            policy_id="policy-a",
            classification=2,
            content_hash=_digest("document"),
            chunks=[_chunk("chunk-a", 0, epoch=2)],
        )
    store.close()


def test_policy_epoch_is_monotonic_and_stale_reads_fail(tmp_path) -> None:
    store = EnterpriseKnowledgeStore(tmp_path / "knowledge-v2.db")
    store.initialize_tenant("tenant-a")
    _stage(store, "tenant-a", "document-a")

    assert store.advance_policy_epoch("tenant-a", 1) == 2
    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.advance_policy_epoch("tenant-a", 1)
    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.list_documents("tenant-a", 1)
    assert len(store.list_documents("tenant-a", 2)) == 1
    store.close()


def test_schema_authority_rejects_an_unrelated_existing_database(tmp_path) -> None:
    path = tmp_path / "knowledge-v2.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE unrelated(value TEXT)")
    connection.commit()
    connection.close()

    with pytest.raises(EnterpriseKnowledgeError, match="schema authority"):
        EnterpriseKnowledgeStore(path)
