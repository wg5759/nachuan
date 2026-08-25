"""Enterprise knowledge_v2 metadata store with tenant and epoch hard fences."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_APPLICATION_ID = 0x4E434B32  # NCK2
_USER_VERSION = 1
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = {"isolated", "searchable", "revoked"}


class EnterpriseKnowledgeError(RuntimeError):
    pass


class EnterpriseKnowledgeStalePolicy(EnterpriseKnowledgeError):
    pass


class EnterpriseKnowledgeFenced(EnterpriseKnowledgeError):
    pass


@dataclass(frozen=True, slots=True)
class EnterpriseChunkMetadata:
    chunk_id: str
    ordinal: int
    content_ref: str
    content_hash: str
    policy_id: str
    policy_epoch: int
    classification: int
    provenance_digest: str

    def __post_init__(self) -> None:
        for field in ("chunk_id", "content_ref", "policy_id"):
            _checked_id(getattr(self, field), field)
        for field in ("content_hash", "provenance_digest"):
            _checked_digest(getattr(self, field), field)
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 0:
            raise ValueError("ordinal is invalid")
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


@dataclass(frozen=True, slots=True)
class EnterpriseDocumentMetadata:
    document_id: str
    source_id: str
    source_version: str
    policy_id: str
    policy_epoch: int
    classification: int
    content_hash: str
    chunks: tuple[EnterpriseChunkMetadata, ...]

    def __post_init__(self) -> None:
        for field in ("document_id", "source_id", "source_version", "policy_id"):
            _checked_id(getattr(self, field), field)
        _checked_digest(self.content_hash, "content_hash")
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
        if not self.chunks or len(self.chunks) > 100_000:
            raise ValueError("chunks are invalid")
        if len({chunk.chunk_id for chunk in self.chunks}) != len(self.chunks):
            raise ValueError("chunk ids are duplicated")
        if {chunk.ordinal for chunk in self.chunks} != set(range(len(self.chunks))):
            raise ValueError("chunk ordinals must be contiguous")
        for chunk in self.chunks:
            if chunk.policy_epoch != self.policy_epoch or chunk.policy_id != self.policy_id:
                raise EnterpriseKnowledgeStalePolicy("chunk policy differs from document")
            if chunk.classification < self.classification:
                raise EnterpriseKnowledgeError("chunk classification is wider than document")


def _checked_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _checked_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class EnterpriseKnowledgeStore:
    def __init__(self, db_path: str | Path):
        path = Path(db_path).resolve(strict=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_symlink():
            raise EnterpriseKnowledgeError("knowledge_v2 database cannot be a symlink")
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            application_id = int(self._connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            existing = self._connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','index','trigger')"
            ).fetchone()[0]
            if existing and (application_id != _APPLICATION_ID or user_version != _USER_VERSION):
                raise EnterpriseKnowledgeError("knowledge_v2 schema authority is invalid")
            if not existing:
                self._connection.executescript(
                    f"""
                    PRAGMA application_id={_APPLICATION_ID};
                    PRAGMA user_version={_USER_VERSION};
                    CREATE TABLE kb_v2_tenant_epochs (
                        tenant_id TEXT PRIMARY KEY,
                        policy_epoch INTEGER NOT NULL CHECK(policy_epoch >= 1),
                        corpus_epoch INTEGER NOT NULL CHECK(corpus_epoch >= 1)
                    ) STRICT;
                    CREATE TABLE kb_v2_documents (
                        tenant_id TEXT NOT NULL,
                        document_id TEXT NOT NULL,
                        source_id TEXT NOT NULL,
                        source_version TEXT NOT NULL,
                        corpus_epoch INTEGER NOT NULL CHECK(corpus_epoch >= 1),
                        classification INTEGER NOT NULL CHECK(classification BETWEEN 0 AND 10),
                        policy_id TEXT NOT NULL,
                        policy_epoch INTEGER NOT NULL CHECK(policy_epoch >= 1),
                        status TEXT NOT NULL CHECK(status IN ('isolated','searchable','revoked')),
                        content_hash TEXT NOT NULL CHECK(length(content_hash)=64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
                        PRIMARY KEY(tenant_id, document_id),
                        FOREIGN KEY(tenant_id) REFERENCES kb_v2_tenant_epochs(tenant_id)
                    ) STRICT;
                    CREATE TABLE kb_v2_chunks (
                        tenant_id TEXT NOT NULL,
                        chunk_id TEXT NOT NULL,
                        document_id TEXT NOT NULL,
                        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                        content_ref TEXT NOT NULL,
                        content_hash TEXT NOT NULL CHECK(length(content_hash)=64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
                        policy_id TEXT NOT NULL,
                        policy_epoch INTEGER NOT NULL CHECK(policy_epoch >= 1),
                        classification INTEGER NOT NULL CHECK(classification BETWEEN 0 AND 10),
                        provenance_digest TEXT NOT NULL CHECK(length(provenance_digest)=64 AND provenance_digest NOT GLOB '*[^0-9a-f]*'),
                        revoked_at REAL,
                        PRIMARY KEY(tenant_id, chunk_id),
                        UNIQUE(tenant_id, document_id, ordinal),
                        FOREIGN KEY(tenant_id, document_id) REFERENCES kb_v2_documents(tenant_id, document_id)
                    ) STRICT;
                    CREATE TABLE kb_v2_policy_outbox (
                        tenant_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        source_version TEXT NOT NULL,
                        policy_epoch INTEGER NOT NULL CHECK(policy_epoch >= 1),
                        resource_scope TEXT NOT NULL,
                        operation TEXT NOT NULL CHECK(operation IN ('stage','activate','revoke')),
                        state TEXT NOT NULL CHECK(state IN ('pending','applied','failed')),
                        created_at REAL NOT NULL,
                        applied_at REAL,
                        PRIMARY KEY(tenant_id, event_id),
                        FOREIGN KEY(tenant_id) REFERENCES kb_v2_tenant_epochs(tenant_id)
                    ) STRICT;
                    CREATE INDEX idx_kb_v2_documents_policy ON kb_v2_documents(tenant_id, policy_epoch, status);
                    CREATE INDEX idx_kb_v2_chunks_document ON kb_v2_chunks(tenant_id, document_id, ordinal);
                    """
                )
                self._connection.commit()
            self._verify_schema()

    def _verify_schema(self) -> None:
        expected = {
            "kb_v2_tenant_epochs": {"tenant_id", "policy_epoch", "corpus_epoch"},
            "kb_v2_documents": {
                "tenant_id", "document_id", "source_id", "source_version", "corpus_epoch",
                "classification", "policy_id", "policy_epoch", "status", "content_hash",
            },
            "kb_v2_chunks": {
                "tenant_id", "chunk_id", "document_id", "ordinal", "content_ref", "content_hash",
                "policy_id", "policy_epoch", "classification", "provenance_digest", "revoked_at",
            },
            "kb_v2_policy_outbox": {
                "tenant_id", "event_id", "source_version", "policy_epoch", "resource_scope",
                "operation", "state", "created_at", "applied_at",
            },
        }
        actual_tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if actual_tables != set(expected):
            raise EnterpriseKnowledgeError("knowledge_v2 table closure drifted")
        for table, columns in expected.items():
            actual = {
                str(row[1]) for row in self._connection.execute(f"PRAGMA table_info({table})")
            }
            if actual != columns:
                raise EnterpriseKnowledgeError(f"knowledge_v2 table drifted: {table}")

    def initialize_tenant(self, tenant_id: str) -> None:
        tenant = _checked_id(tenant_id, "tenant_id")
        with self._lock:
            self._connection.execute(
                "INSERT OR IGNORE INTO kb_v2_tenant_epochs(tenant_id,policy_epoch,corpus_epoch) VALUES(?,1,1)",
                (tenant,),
            )
            self._connection.commit()

    def current_epochs(self, tenant_id: str) -> tuple[int, int]:
        tenant = _checked_id(tenant_id, "tenant_id")
        with self._lock:
            row = self._connection.execute(
                "SELECT policy_epoch,corpus_epoch FROM kb_v2_tenant_epochs WHERE tenant_id=?",
                (tenant,),
            ).fetchone()
        if row is None:
            raise EnterpriseKnowledgeError("tenant is not initialized")
        return int(row[0]), int(row[1])

    def advance_policy_epoch(self, tenant_id: str, expected_epoch: int) -> int:
        tenant = _checked_id(tenant_id, "tenant_id")
        if isinstance(expected_epoch, bool) or not isinstance(expected_epoch, int) or expected_epoch < 1:
            raise ValueError("expected_epoch is invalid")
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE kb_v2_tenant_epochs SET policy_epoch=policy_epoch+1 WHERE tenant_id=? AND policy_epoch=?",
                (tenant, expected_epoch),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
            self._connection.commit()
        return expected_epoch + 1

    def begin_document_revocation(
        self,
        *,
        tenant_id: str,
        expected_policy_epoch: int,
        document_id: str,
        source_version: str,
        event_id: str,
    ) -> dict[str, object]:
        """Fence and revoke one document in the same policy-epoch transaction.

        Unaffected local metadata advances to the new epoch atomically so a
        scoped revocation does not make every other document stale.  External
        indexes remain fenced for the target until the outbox event is applied.
        """

        tenant = _checked_id(tenant_id, "tenant_id")
        document = _checked_id(document_id, "document_id")
        version = _checked_id(source_version, "source_version")
        event = _checked_id(event_id, "event_id")
        if (
            isinstance(expected_policy_epoch, bool)
            or not isinstance(expected_policy_epoch, int)
            or expected_policy_epoch < 1
        ):
            raise ValueError("expected_policy_epoch is invalid")
        now = time.time()
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._connection.execute(
                    "SELECT policy_epoch,corpus_epoch FROM kb_v2_tenant_epochs WHERE tenant_id=?",
                    (tenant,),
                ).fetchone()
                if current is None or int(current[0]) != expected_policy_epoch:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                target = self._connection.execute(
                    "SELECT status FROM kb_v2_documents WHERE tenant_id=? AND document_id=?",
                    (tenant, document),
                ).fetchone()
                if target is None:
                    raise EnterpriseKnowledgeError("document does not exist")
                if str(target[0]) == "revoked":
                    raise EnterpriseKnowledgeError("document is already revoked")
                duplicate = self._connection.execute(
                    "SELECT 1 FROM kb_v2_policy_outbox WHERE tenant_id=? AND event_id=?",
                    (tenant, event),
                ).fetchone()
                if duplicate is not None:
                    raise EnterpriseKnowledgeError("policy event already exists")
                new_policy_epoch = expected_policy_epoch + 1
                new_corpus_epoch = int(current[1]) + 1
                advanced = self._connection.execute(
                    "UPDATE kb_v2_tenant_epochs SET policy_epoch=?,corpus_epoch=? "
                    "WHERE tenant_id=? AND policy_epoch=? AND corpus_epoch=?",
                    (
                        new_policy_epoch,
                        new_corpus_epoch,
                        tenant,
                        expected_policy_epoch,
                        int(current[1]),
                    ),
                )
                if advanced.rowcount != 1:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                self._connection.execute(
                    "UPDATE kb_v2_documents SET policy_epoch=? WHERE tenant_id=?",
                    (new_policy_epoch, tenant),
                )
                self._connection.execute(
                    "UPDATE kb_v2_chunks SET policy_epoch=? WHERE tenant_id=?",
                    (new_policy_epoch, tenant),
                )
                revoked = self._connection.execute(
                    "UPDATE kb_v2_documents SET status='revoked' "
                    "WHERE tenant_id=? AND document_id=? AND status<>'revoked'",
                    (tenant, document),
                )
                if revoked.rowcount != 1:
                    raise EnterpriseKnowledgeError("document revocation changed")
                self._connection.execute(
                    "UPDATE kb_v2_chunks SET revoked_at=? "
                    "WHERE tenant_id=? AND document_id=? AND revoked_at IS NULL",
                    (now, tenant, document),
                )
                self._connection.execute(
                    "INSERT INTO kb_v2_policy_outbox VALUES(?,?,?,?,?,'revoke','pending',?,NULL)",
                    (
                        tenant,
                        event,
                        version,
                        new_policy_epoch,
                        document,
                        now,
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return {
            "tenant_id": tenant,
            "document_id": document,
            "event_id": event,
            "policy_epoch": new_policy_epoch,
            "corpus_epoch": new_corpus_epoch,
            "status": "revoked",
            "sync_state": "pending",
            "fenced": True,
        }

    def mark_policy_event_failed(
        self,
        *,
        tenant_id: str,
        event_id: str,
        expected_policy_epoch: int,
    ) -> None:
        self._transition_policy_event(
            tenant_id=tenant_id,
            event_id=event_id,
            expected_policy_epoch=expected_policy_epoch,
            target_state="failed",
        )

    def apply_policy_event(
        self,
        *,
        tenant_id: str,
        event_id: str,
        expected_policy_epoch: int,
    ) -> None:
        self._transition_policy_event(
            tenant_id=tenant_id,
            event_id=event_id,
            expected_policy_epoch=expected_policy_epoch,
            target_state="applied",
        )

    def _transition_policy_event(
        self,
        *,
        tenant_id: str,
        event_id: str,
        expected_policy_epoch: int,
        target_state: str,
    ) -> None:
        tenant = _checked_id(tenant_id, "tenant_id")
        event = _checked_id(event_id, "event_id")
        if target_state not in {"applied", "failed"}:
            raise ValueError("target_state is invalid")
        if (
            isinstance(expected_policy_epoch, bool)
            or not isinstance(expected_policy_epoch, int)
            or expected_policy_epoch < 1
        ):
            raise ValueError("expected_policy_epoch is invalid")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._connection.execute(
                    "SELECT policy_epoch FROM kb_v2_tenant_epochs WHERE tenant_id=?",
                    (tenant,),
                ).fetchone()
                if current is None or int(current[0]) != expected_policy_epoch:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                allowed_states = ("pending", "failed") if target_state == "applied" else ("pending",)
                placeholders = ",".join("?" for _ in allowed_states)
                cursor = self._connection.execute(
                    "UPDATE kb_v2_policy_outbox SET state=?,applied_at=? "
                    f"WHERE tenant_id=? AND event_id=? AND operation='revoke' "
                    f"AND policy_epoch<=? AND state IN ({placeholders})",
                    (
                        target_state,
                        time.time() if target_state == "applied" else None,
                        tenant,
                        event,
                        expected_policy_epoch,
                        *allowed_states,
                    ),
                )
                if cursor.rowcount != 1:
                    raise EnterpriseKnowledgeError("policy event transition rejected")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def assert_scope_unfenced(
        self,
        *,
        tenant_id: str,
        resource_scope: str,
        expected_policy_epoch: int,
    ) -> None:
        if self.is_scope_fenced(
            tenant_id=tenant_id,
            resource_scope=resource_scope,
            expected_policy_epoch=expected_policy_epoch,
        ):
            raise EnterpriseKnowledgeFenced("resource scope is fenced")

    def is_scope_fenced(
        self,
        *,
        tenant_id: str,
        resource_scope: str,
        expected_policy_epoch: int,
    ) -> bool:
        tenant = _checked_id(tenant_id, "tenant_id")
        scope = _checked_id(resource_scope, "resource_scope")
        policy_epoch, _ = self.current_epochs(tenant)
        if policy_epoch != expected_policy_epoch:
            raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
        with self._lock:
            fenced = self._connection.execute(
                "SELECT 1 FROM kb_v2_policy_outbox WHERE tenant_id=? "
                "AND resource_scope=? AND operation='revoke' "
                "AND policy_epoch<=? AND state IN ('pending','failed') LIMIT 1",
                (tenant, scope, expected_policy_epoch),
            ).fetchone()
        return fenced is not None

    def list_policy_events(
        self,
        tenant_id: str,
        expected_policy_epoch: int,
    ) -> list[dict[str, object]]:
        tenant = _checked_id(tenant_id, "tenant_id")
        policy_epoch, _ = self.current_epochs(tenant)
        if policy_epoch != expected_policy_epoch:
            raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
        with self._lock:
            rows = self._connection.execute(
                "SELECT event_id,source_version,policy_epoch,resource_scope,operation,state,created_at,applied_at "
                "FROM kb_v2_policy_outbox WHERE tenant_id=? ORDER BY created_at,event_id",
                (tenant,),
            ).fetchall()
        keys = (
            "event_id",
            "source_version",
            "policy_epoch",
            "resource_scope",
            "operation",
            "state",
            "created_at",
            "applied_at",
        )
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def stage_document(
        self,
        *,
        tenant_id: str,
        expected_policy_epoch: int,
        document_id: str,
        source_id: str,
        source_version: str,
        policy_id: str,
        classification: int,
        content_hash: str,
        chunks: Iterable[EnterpriseChunkMetadata],
    ) -> dict[str, object]:
        tenant = _checked_id(tenant_id, "tenant_id")
        document = _checked_id(document_id, "document_id")
        source = _checked_id(source_id, "source_id")
        source_version = _checked_id(source_version, "source_version")
        policy = _checked_id(policy_id, "policy_id")
        _checked_digest(content_hash, "content_hash")
        if isinstance(classification, bool) or not isinstance(classification, int) or not 0 <= classification <= 10:
            raise ValueError("classification is invalid")
        staged = tuple(chunks)
        if not staged or len(staged) > 100_000:
            raise ValueError("chunks are invalid")
        if len({chunk.chunk_id for chunk in staged}) != len(staged):
            raise ValueError("chunk ids are duplicated")
        if {chunk.ordinal for chunk in staged} != set(range(len(staged))):
            raise ValueError("chunk ordinals must be contiguous")
        for chunk in staged:
            if chunk.policy_epoch != expected_policy_epoch or chunk.policy_id != policy:
                raise EnterpriseKnowledgeStalePolicy("chunk policy differs from document")
            if chunk.classification < classification:
                raise EnterpriseKnowledgeError("chunk classification is wider than document")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._connection.execute(
                    "SELECT policy_epoch,corpus_epoch FROM kb_v2_tenant_epochs WHERE tenant_id=?",
                    (tenant,),
                ).fetchone()
                if current is None or int(current[0]) != expected_policy_epoch:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                corpus_epoch = int(current[1]) + 1
                event_id = _canonical_digest(
                    {
                        "tenant": tenant,
                        "document": document,
                        "source_version": source_version,
                        "corpus": corpus_epoch,
                    }
                )
                advanced = self._connection.execute(
                    "UPDATE kb_v2_tenant_epochs SET corpus_epoch=? WHERE tenant_id=? AND policy_epoch=?",
                    (corpus_epoch, tenant, expected_policy_epoch),
                )
                if advanced.rowcount != 1:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                self._connection.execute(
                    "INSERT INTO kb_v2_documents VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant, document, source, source_version, corpus_epoch, classification,
                        policy, expected_policy_epoch, "isolated", content_hash,
                    ),
                )
                self._connection.executemany(
                    "INSERT INTO kb_v2_chunks VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                    [
                        (
                            tenant, chunk.chunk_id, document, chunk.ordinal, chunk.content_ref,
                            chunk.content_hash, chunk.policy_id, chunk.policy_epoch,
                            chunk.classification, chunk.provenance_digest,
                        )
                        for chunk in staged
                    ],
                )
                self._connection.execute(
                    "INSERT INTO kb_v2_policy_outbox VALUES(?,?,?,?,?,'stage','pending',?,NULL)",
                    (tenant, event_id, source_version, expected_policy_epoch, document, time.time()),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return {
            "tenant_id": tenant,
            "document_id": document,
            "policy_epoch": expected_policy_epoch,
            "corpus_epoch": corpus_epoch,
            "status": "isolated",
            "event_id": event_id,
            "chunk_count": len(staged),
        }

    def stage_document_family(
        self,
        *,
        tenant_id: str,
        expected_policy_epoch: int,
        documents: Iterable[EnterpriseDocumentMetadata],
    ) -> dict[str, object]:
        """Atomically stage all permission domains from one source snapshot.

        A source version may contain several policy/classification domains.  The
        caller must split those domains before this boundary.  This method gives
        them one corpus epoch and one outbox event so a partial family can never
        become visible after an insertion failure.
        """

        tenant = _checked_id(tenant_id, "tenant_id")
        if (
            isinstance(expected_policy_epoch, bool)
            or not isinstance(expected_policy_epoch, int)
            or expected_policy_epoch < 1
        ):
            raise ValueError("expected_policy_epoch is invalid")
        staged = tuple(documents)
        if not staged or len(staged) > 10_000:
            raise ValueError("documents are invalid")
        if len({document.document_id for document in staged}) != len(staged):
            raise ValueError("document ids are duplicated")
        if len({document.source_id for document in staged}) != 1:
            raise EnterpriseKnowledgeError("document family source differs")
        if len({document.source_version for document in staged}) != 1:
            raise EnterpriseKnowledgeError("document family source version differs")
        if any(document.policy_epoch != expected_policy_epoch for document in staged):
            raise EnterpriseKnowledgeStalePolicy("document family policy epoch differs")
        all_chunk_ids = [
            chunk.chunk_id for document in staged for chunk in document.chunks
        ]
        if len(all_chunk_ids) > 100_000:
            raise ValueError("document family has too many chunks")
        if len(set(all_chunk_ids)) != len(all_chunk_ids):
            raise ValueError("document family chunk ids are duplicated")

        source_id = staged[0].source_id
        source_version = staged[0].source_version
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._connection.execute(
                    "SELECT policy_epoch,corpus_epoch FROM kb_v2_tenant_epochs WHERE tenant_id=?",
                    (tenant,),
                ).fetchone()
                if current is None or int(current[0]) != expected_policy_epoch:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                corpus_epoch = int(current[1]) + 1
                event_id = _canonical_digest(
                    {
                        "tenant": tenant,
                        "source": source_id,
                        "source_version": source_version,
                        "documents": [document.document_id for document in staged],
                        "corpus": corpus_epoch,
                    }
                )
                advanced = self._connection.execute(
                    "UPDATE kb_v2_tenant_epochs SET corpus_epoch=? WHERE tenant_id=? AND policy_epoch=?",
                    (corpus_epoch, tenant, expected_policy_epoch),
                )
                if advanced.rowcount != 1:
                    raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
                self._connection.executemany(
                    "INSERT INTO kb_v2_documents VALUES(?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            tenant,
                            document.document_id,
                            document.source_id,
                            document.source_version,
                            corpus_epoch,
                            document.classification,
                            document.policy_id,
                            expected_policy_epoch,
                            "isolated",
                            document.content_hash,
                        )
                        for document in staged
                    ],
                )
                self._connection.executemany(
                    "INSERT INTO kb_v2_chunks VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                    [
                        (
                            tenant,
                            chunk.chunk_id,
                            document.document_id,
                            chunk.ordinal,
                            chunk.content_ref,
                            chunk.content_hash,
                            chunk.policy_id,
                            chunk.policy_epoch,
                            chunk.classification,
                            chunk.provenance_digest,
                        )
                        for document in staged
                        for chunk in document.chunks
                    ],
                )
                resource_scope = "source-" + _canonical_digest(
                    {"source": source_id, "source_version": source_version}
                )
                self._connection.execute(
                    "INSERT INTO kb_v2_policy_outbox VALUES(?,?,?,?,?,'stage','pending',?,NULL)",
                    (
                        tenant,
                        event_id,
                        source_version,
                        expected_policy_epoch,
                        resource_scope,
                        time.time(),
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return {
            "tenant_id": tenant,
            "source_id": source_id,
            "source_version": source_version,
            "policy_epoch": expected_policy_epoch,
            "corpus_epoch": corpus_epoch,
            "status": "isolated",
            "event_id": event_id,
            "document_count": len(staged),
            "chunk_count": len(all_chunk_ids),
        }

    def list_documents(self, tenant_id: str, expected_policy_epoch: int) -> list[dict[str, object]]:
        policy_epoch, _ = self.current_epochs(tenant_id)
        if policy_epoch != expected_policy_epoch:
            raise EnterpriseKnowledgeStalePolicy("policy epoch changed")
        tenant = _checked_id(tenant_id, "tenant_id")
        with self._lock:
            rows = self._connection.execute(
                "SELECT document_id,source_id,source_version,corpus_epoch,classification,policy_id,policy_epoch,status,content_hash "
                "FROM kb_v2_documents WHERE tenant_id=? ORDER BY document_id",
                (tenant,),
            ).fetchall()
        keys = (
            "document_id", "source_id", "source_version", "corpus_epoch", "classification",
            "policy_id", "policy_epoch", "status", "content_hash",
        )
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()


__all__ = [
    "EnterpriseChunkMetadata",
    "EnterpriseDocumentMetadata",
    "EnterpriseKnowledgeError",
    "EnterpriseKnowledgeFenced",
    "EnterpriseKnowledgeStalePolicy",
    "EnterpriseKnowledgeStore",
]
