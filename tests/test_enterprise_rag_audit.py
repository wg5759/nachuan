from __future__ import annotations

import hashlib
import sqlite3

import pytest

from gateway.enterprise_rag_audit import (
    EnterpriseRagAuditEvent,
    EnterpriseRagAuditLog,
    EnterpriseRagAuditUnavailable,
)


_KEY = b"enterprise-rag-audit-test-key-32-bytes"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(*, receipt: str = "receipt-1") -> EnterpriseRagAuditEvent:
    return EnterpriseRagAuditEvent(
        tenant_id="tenant-a",
        subject_scope_fingerprint=_digest("anonymous-subject-scope"),
        status="ok",
        policy_epoch=7,
        session_epoch=3,
        query_digest=_digest("query bytes are not stored"),
        requested_k=2,
        authorized_chunk_count=2,
        cited_chunk_ids=("chunk-a",),
        model_id="enterprise-local",
        receipt_id=_digest(receipt),
    )


def test_audit_log_reopens_and_preserves_one_hmac_chain(tmp_path) -> None:
    path = tmp_path / "enterprise-rag-audit.db"
    first = EnterpriseRagAuditLog(path, audit_key=_KEY)
    first.append(_event())
    first.append(_event(receipt="receipt-2"))
    assert first.verify_chain() == 2
    first.close()

    reopened = EnterpriseRagAuditLog(path, audit_key=_KEY)
    records = reopened.list_records(tenant_id="tenant-a")
    assert reopened.verify_chain() == 2
    reopened.close()

    assert len(records) == 2
    assert records[0]["previous_hmac"] == "0" * 64
    assert records[1]["previous_hmac"] == records[0]["record_hmac"]
    assert "anonymous-subject-scope" not in repr(records)
    assert "query bytes are not stored" not in repr(records)


def test_audit_rows_are_append_only_and_wrong_key_cannot_reopen(tmp_path) -> None:
    path = tmp_path / "enterprise-rag-audit.db"
    log = EnterpriseRagAuditLog(path, audit_key=_KEY)
    log.append(_event())
    log.close()

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE enterprise_rag_audit_records SET status='blocked'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM enterprise_rag_audit_records")

    with pytest.raises(EnterpriseRagAuditUnavailable):
        EnterpriseRagAuditLog(path, audit_key=b"wrong-enterprise-audit-key-32-bytes")


def test_foreign_database_is_rejected_without_rewrite(tmp_path) -> None:
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE foreign_data(value TEXT NOT NULL)")
        connection.execute("INSERT INTO foreign_data VALUES('keep-me')")
    before = path.read_bytes()

    with pytest.raises(EnterpriseRagAuditUnavailable):
        EnterpriseRagAuditLog(path, audit_key=_KEY)

    assert path.read_bytes() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM foreign_data").fetchone() == (
            "keep-me",
        )
