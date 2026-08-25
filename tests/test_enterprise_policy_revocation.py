from __future__ import annotations

import hashlib
import sqlite3

import pytest

from orchestrator.enterprise_knowledge import (
    EnterpriseChunkMetadata,
    EnterpriseKnowledgeError,
    EnterpriseKnowledgeFenced,
    EnterpriseKnowledgeStalePolicy,
    EnterpriseKnowledgeStore,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _stage(store: EnterpriseKnowledgeStore, document_id: str, chunk_id: str) -> None:
    store.stage_document(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id=document_id,
        source_id="source-a",
        source_version="version-1",
        policy_id="policy-a",
        classification=2,
        content_hash=_digest(f"document:{document_id}"),
        chunks=(
            EnterpriseChunkMetadata(
                chunk_id=chunk_id,
                ordinal=0,
                content_ref=f"object:{chunk_id}",
                content_hash=_digest(f"content:{chunk_id}"),
                policy_id="policy-a",
                policy_epoch=1,
                classification=2,
                provenance_digest=_digest(f"provenance:{chunk_id}"),
            ),
        ),
    )


def _store(tmp_path):
    path = tmp_path / "knowledge-v2.db"
    store = EnterpriseKnowledgeStore(path)
    store.initialize_tenant("tenant-a")
    _stage(store, "document-a", "chunk-a")
    _stage(store, "document-b", "chunk-b")
    return store, path


def test_revocation_epoch_metadata_status_and_fence_commit_atomically(tmp_path) -> None:
    store, path = _store(tmp_path)

    receipt = store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )

    assert receipt["policy_epoch"] == 2
    assert receipt["corpus_epoch"] == 4
    assert receipt["fenced"] is True and receipt["sync_state"] == "pending"
    assert store.current_epochs("tenant-a") == (2, 4)
    documents = {row["document_id"]: row for row in store.list_documents("tenant-a", 2)}
    assert documents["document-a"]["status"] == "revoked"
    assert documents["document-b"]["status"] == "isolated"
    assert {row["policy_epoch"] for row in documents.values()} == {2}
    connection = sqlite3.connect(path)
    chunks = connection.execute(
        "SELECT chunk_id,policy_epoch,revoked_at FROM kb_v2_chunks ORDER BY chunk_id"
    ).fetchall()
    connection.close()
    assert chunks[0][0:2] == ("chunk-a", 2) and chunks[0][2] is not None
    assert chunks[1] == ("chunk-b", 2, None)
    with pytest.raises(EnterpriseKnowledgeFenced):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-a",
            expected_policy_epoch=2,
        )
    store.assert_scope_unfenced(
        tenant_id="tenant-a",
        resource_scope="document-b",
        expected_policy_epoch=2,
    )
    store.close()


def test_old_epoch_reads_fail_immediately_after_revocation(tmp_path) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )

    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.list_documents("tenant-a", 1)
    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-a",
            expected_policy_epoch=1,
        )
    store.close()


def test_applied_sync_event_releases_fence_but_preserves_revoked_status(tmp_path) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )

    store.apply_policy_event(
        tenant_id="tenant-a",
        event_id="revoke-a-v2",
        expected_policy_epoch=2,
    )

    store.assert_scope_unfenced(
        tenant_id="tenant-a",
        resource_scope="document-a",
        expected_policy_epoch=2,
    )
    event = next(
        row
        for row in store.list_policy_events("tenant-a", 2)
        if row["event_id"] == "revoke-a-v2"
    )
    assert event["state"] == "applied" and event["applied_at"] is not None
    document = next(
        row
        for row in store.list_documents("tenant-a", 2)
        if row["document_id"] == "document-a"
    )
    assert document["status"] == "revoked"
    store.close()


def test_failed_sync_event_stays_fenced_until_explicit_recovery(tmp_path) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )
    store.mark_policy_event_failed(
        tenant_id="tenant-a",
        event_id="revoke-a-v2",
        expected_policy_epoch=2,
    )

    with pytest.raises(EnterpriseKnowledgeFenced):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-a",
            expected_policy_epoch=2,
        )
    store.apply_policy_event(
        tenant_id="tenant-a",
        event_id="revoke-a-v2",
        expected_policy_epoch=2,
    )
    store.assert_scope_unfenced(
        tenant_id="tenant-a",
        resource_scope="document-a",
        expected_policy_epoch=2,
    )
    store.close()


def test_stale_or_unknown_document_revocation_rolls_back_all_epoch_changes(tmp_path) -> None:
    store, _path = _store(tmp_path)

    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.begin_document_revocation(
            tenant_id="tenant-a",
            expected_policy_epoch=2,
            document_id="document-a",
            source_version="version-2",
            event_id="stale-event",
        )
    with pytest.raises(EnterpriseKnowledgeError, match="does not exist"):
        store.begin_document_revocation(
            tenant_id="tenant-a",
            expected_policy_epoch=1,
            document_id="missing-document",
            source_version="version-2",
            event_id="missing-event",
        )

    assert store.current_epochs("tenant-a") == (1, 3)
    assert {row["status"] for row in store.list_documents("tenant-a", 1)} == {"isolated"}
    assert all(
        row["event_id"] not in {"stale-event", "missing-event"}
        for row in store.list_policy_events("tenant-a", 1)
    )
    store.close()


def test_duplicate_revocation_event_rolls_back_the_second_scope(tmp_path) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="same-event",
    )

    with pytest.raises(EnterpriseKnowledgeError, match="already exists"):
        store.begin_document_revocation(
            tenant_id="tenant-a",
            expected_policy_epoch=2,
            document_id="document-b",
            source_version="version-3",
            event_id="same-event",
        )

    assert store.current_epochs("tenant-a") == (2, 4)
    document_b = next(
        row
        for row in store.list_documents("tenant-a", 2)
        if row["document_id"] == "document-b"
    )
    assert document_b["status"] == "isolated"
    store.close()


def test_event_transition_requires_current_epoch_and_valid_state(tmp_path) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )

    with pytest.raises(EnterpriseKnowledgeStalePolicy):
        store.apply_policy_event(
            tenant_id="tenant-a",
            event_id="revoke-a-v2",
            expected_policy_epoch=1,
        )
    store.apply_policy_event(
        tenant_id="tenant-a",
        event_id="revoke-a-v2",
        expected_policy_epoch=2,
    )
    with pytest.raises(EnterpriseKnowledgeError, match="transition rejected"):
        store.mark_policy_event_failed(
            tenant_id="tenant-a",
            event_id="revoke-a-v2",
            expected_policy_epoch=2,
        )
    store.close()


def test_pending_revocation_and_fence_survive_store_restart(tmp_path) -> None:
    store, path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )
    store.close()

    reopened = EnterpriseKnowledgeStore(path)
    with pytest.raises(EnterpriseKnowledgeFenced):
        reopened.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-a",
            expected_policy_epoch=2,
        )
    event = next(
        row
        for row in reopened.list_policy_events("tenant-a", 2)
        if row["event_id"] == "revoke-a-v2"
    )
    assert event["state"] == "pending"
    reopened.close()


def test_older_pending_fence_survives_later_epoch_and_can_close_at_current_epoch(
    tmp_path,
) -> None:
    store, _path = _store(tmp_path)
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=1,
        document_id="document-a",
        source_version="version-2",
        event_id="revoke-a-v2",
    )
    store.begin_document_revocation(
        tenant_id="tenant-a",
        expected_policy_epoch=2,
        document_id="document-b",
        source_version="version-3",
        event_id="revoke-b-v3",
    )

    assert store.current_epochs("tenant-a") == (3, 5)
    with pytest.raises(EnterpriseKnowledgeFenced):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-a",
            expected_policy_epoch=3,
        )
    with pytest.raises(EnterpriseKnowledgeFenced):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-b",
            expected_policy_epoch=3,
        )

    store.apply_policy_event(
        tenant_id="tenant-a",
        event_id="revoke-a-v2",
        expected_policy_epoch=3,
    )
    store.assert_scope_unfenced(
        tenant_id="tenant-a",
        resource_scope="document-a",
        expected_policy_epoch=3,
    )
    with pytest.raises(EnterpriseKnowledgeFenced):
        store.assert_scope_unfenced(
            tenant_id="tenant-a",
            resource_scope="document-b",
            expected_policy_epoch=3,
        )
    store.close()
