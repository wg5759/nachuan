"""Privacy execution layer: per-store export/erase adapters and retention.

The rights ledger (gateway/privacy_rights.py) is the durable control plane;
these tests pin the execution slice that actually reads/writes the four
customer-content stores (conversations/memory/knowledge/cases) and records
honest NCPR receipts.  Unknown, retryable and permanent failures must never
be disguised as completion.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from gateway import privacy_admin
from gateway.auth import require_api_key, require_approval_admin_key
from gateway.privacy_execution import (
    PrivacyExecutionEngine,
    PrivacyTombstoneStore,
    delete_scope_steps,
    export_scope_steps,
    subject_digest_for,
)
from gateway.privacy_rights import PrivacyRightsLedger
from orchestrator.agent import ConversationStore
from orchestrator.cases import CaseLibrary
from orchestrator.knowledge import KnowledgeBase
from orchestrator.memory import MemoryStore


ALICE = "alice@example.com"
BOB = "bob@example.com"
ALICE_DIGEST = subject_digest_for(ALICE)
BOB_DIGEST = subject_digest_for(BOB)
CONV_KEY = "web:alice-session"
CONV_DIGEST = subject_digest_for(CONV_KEY)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request_id(label: str) -> str:
    return "dsr-v1:" + _digest(label)


@pytest.fixture
def stores(tmp_path):
    """Seed all four customer-content stores with alice/bob rows."""

    memory = MemoryStore(str(tmp_path / "memory.db"))
    assert memory.add(ALICE, "alice prefers dark mode", source="settings")
    assert memory.add(BOB, "bob likes tea", source="chat")

    cases = CaseLibrary(str(tmp_path / "cases.db"))
    assert cases.add(ALICE, "fix flaky test", "run it quietly", "model-a") > 0
    assert cases.add(BOB, "bob case", "bob solution", "model-b") > 0

    knowledge = KnowledgeBase(str(tmp_path / "knowledge.db"))
    alice_doc = knowledge.add_document(ALICE, "alice notes", "alice knowledge body text")
    assert alice_doc["chunks"] >= 1
    bob_doc = knowledge.add_document(BOB, "bob notes", "bob knowledge body text")
    assert bob_doc["chunks"] >= 1

    conversations = ConversationStore(db_path=str(tmp_path / "conversations.db"))
    conversations.append(CONV_KEY, "user", "alice hello")
    conversations.append(CONV_KEY, "assistant", "alice answer")
    conversations.append("web:bob-session", "user", "bob hello")

    yield tmp_path

    conversations.close()
    knowledge.close()
    cases.close()
    memory.close()


@pytest.fixture
def engine(stores):
    engine = PrivacyExecutionEngine(stores)
    try:
        yield engine
    finally:
        engine.close()


def _rows(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(str(db_path), timeout=5.0) as connection:
        return connection.execute(sql, params).fetchall()


# ── 导出适配器 ───────────────────────────────────────────────────────


def test_export_memory_writes_deterministic_bundle(engine, stores) -> None:
    result = engine.export_store(
        store_id="memory",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("export-memory"),
    )

    assert result.outcome == "completed"
    assert result.affected_count == 1
    export_file = (
        stores / "privacy-exports" / _request_id("export-memory")[7:] / "memory.json"
    )
    assert export_file.is_file()
    first_bytes = export_file.read_bytes()
    assert hashlib.sha256(first_bytes).hexdigest() == result.evidence_sha256
    document = json.loads(first_bytes)
    assert document["schema"] == "nachuan.privacy-export.v1"
    assert document["store_id"] == "memory"
    assert document["subject_digest"] == ALICE_DIGEST
    assert document["row_count"] == 1
    assert [row["text"] for row in document["rows"]] == ["alice prefers dark mode"]
    # 导出件对同一请求是确定性字节：重放逐字节相同（幂等证据）。
    replay = engine.export_store(
        store_id="memory",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("export-memory"),
    )
    assert replay.outcome == "completed"
    assert replay.evidence_sha256 == result.evidence_sha256
    assert export_file.read_bytes() == first_bytes


def test_export_never_includes_other_subjects(engine, stores) -> None:
    for store_id in ("memory", "cases", "knowledge"):
        result = engine.export_store(
            store_id=store_id,
            subject_digest=BOB_DIGEST,
            request_id=_request_id(f"export-bob-{store_id}"),
        )
        assert result.outcome == "completed"
        export_file = (
            stores
            / "privacy-exports"
            / _request_id(f"export-bob-{store_id}")[7:]
            / f"{store_id}.json"
        )
        document = json.loads(export_file.read_bytes())
        assert "alice" not in json.dumps(document)
        assert document["row_count"] >= 1


def test_export_conversations_by_session_key(engine, stores) -> None:
    result = engine.export_store(
        store_id="conversations",
        subject_digest=CONV_DIGEST,
        request_id=_request_id("export-conv"),
    )

    assert result.outcome == "completed"
    assert result.affected_count == 2
    export_file = (
        stores / "privacy-exports" / _request_id("export-conv")[7:] / "conversations.json"
    )
    document = json.loads(export_file.read_bytes())
    contents = [row["content"] for row in document["rows"]]
    assert contents == ["alice hello", "alice answer"]
    assert "bob hello" not in json.dumps(document)


def test_export_missing_store_is_provable_zero_not_an_error(tmp_path) -> None:
    # Windows 不能在句柄持有时删库；缺失场景用从未建库的独立数据根复现。
    empty_root = tmp_path / "empty-root"
    empty_root.mkdir()
    engine = PrivacyExecutionEngine(empty_root)
    try:
        result = engine.export_store(
            store_id="memory",
            subject_digest=ALICE_DIGEST,
            request_id=_request_id("export-absent"),
        )
    finally:
        engine.close()

    assert result.outcome == "completed"
    assert result.affected_count == 0
    document = json.loads(
        (
            empty_root
            / "privacy-exports"
            / _request_id("export-absent")[7:]
            / "memory.json"
        ).read_bytes()
    )
    assert document["row_count"] == 0
    assert document["store_absent"] is True


def test_export_schema_mismatch_is_permanent_not_silent(engine, stores) -> None:
    with sqlite3.connect(str(stores / "memory.db")) as connection:
        connection.execute("ALTER TABLE user_memory RENAME TO user_memory_old")
    result = engine.export_store(
        store_id="memory",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("export-broken"),
    )

    assert result.outcome == "permanent_error"
    assert result.error_code == "schema_mismatch"
    assert result.affected_count is None
    # 永久错误不得留下看似可用的导出件。
    assert not (
        stores / "privacy-exports" / _request_id("export-broken")[7:] / "memory.json"
    ).exists()


def test_export_rejects_unknown_store(engine) -> None:
    with pytest.raises(ValueError, match="store"):
        engine.export_store(
            store_id="usage",
            subject_digest=ALICE_DIGEST,
            request_id=_request_id("export-usage"),
        )


# ── 删除适配器（erase + tombstone） ─────────────────────────────────


def test_erase_memory_writes_tombstones_before_erasing(engine, stores) -> None:
    result = engine.erase_subject(
        store_id="memory",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("erase-memory"),
    )

    assert result.outcome == "completed"
    assert result.affected_count == 1
    assert result.affected_keys == (ALICE,)
    assert _rows(stores / "memory.db", "SELECT text FROM user_memory") == [
        ("bob likes tea",)
    ]
    # 墓碑库只有摘要，绝不含被删内容。
    tombstone_file = stores / "privacy_tombstones.db"
    assert tombstone_file.is_file()
    tombstones = _rows(
        tombstone_file,
        "SELECT store_id,table_name,subject_digest,kind,source_id "
        "FROM privacy_delete_tombstones",
    )
    assert tombstones == [
        ("memory", "user_memory", ALICE_DIGEST, "rights_request", _request_id("erase-memory"))
    ]
    runs = _rows(
        tombstone_file,
        "SELECT store_id,kind,row_count FROM privacy_tombstone_runs",
    )
    assert runs == [("memory", "rights_request", 1)]
    raw = tombstone_file.read_bytes()
    assert b"alice prefers dark mode" not in raw


def test_erase_replay_is_honest_about_prior_proof(engine, stores) -> None:
    request_id = _request_id("erase-replay")
    first = engine.erase_subject(
        store_id="cases", subject_digest=ALICE_DIGEST, request_id=request_id
    )
    assert first.outcome == "completed"
    assert first.affected_count == 1

    replay = engine.erase_subject(
        store_id="cases", subject_digest=ALICE_DIGEST, request_id=request_id
    )
    assert replay.outcome == "completed"
    assert replay.affected_count == 0
    assert replay.evidence_sha256 != first.evidence_sha256
    assert _rows(stores / "cases.db", "SELECT problem FROM cases") == [("bob case",)]


def test_erase_conversations_keeps_capacity_contract(engine, stores) -> None:
    result = engine.erase_subject(
        store_id="conversations",
        subject_digest=CONV_DIGEST,
        request_id=_request_id("erase-conv"),
    )

    assert result.outcome == "completed"
    assert result.affected_count == 2
    assert result.affected_keys == (CONV_KEY,)
    assert _rows(stores / "conversations.db", "SELECT content FROM conv") == [
        ("bob hello",)
    ]
    # 删除触发器保持容量元数据一致：应用的 ConversationStore 重开必须全量通过
    # 启动校验（schema 闭集 + 容量计数 + WAL 族）。
    reopened = ConversationStore(db_path=str(stores / "conversations.db"))
    try:
        assert reopened.get(CONV_KEY) == []
        assert reopened.get("web:bob-session") == [
            {"role": "user", "content": "bob hello"}
        ]
    finally:
        reopened.close()


def test_erase_knowledge_removes_documents_and_chunks(engine, stores) -> None:
    result = engine.erase_subject(
        store_id="knowledge",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("erase-kb"),
    )

    assert result.outcome == "completed"
    assert result.affected_count is not None and result.affected_count >= 2
    assert _rows(stores / "knowledge.db", "SELECT title FROM kb_docs") == [
        ("bob notes",)
    ]
    assert _rows(
        stores / "knowledge.db", "SELECT title FROM kb_chunks"
    ) == [("bob notes",)]


def test_erase_locked_store_is_retryable_never_completed(engine, stores) -> None:
    blocker = sqlite3.connect(str(stores / "cases.db"), timeout=5.0)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        blocker.execute("CREATE TABLE IF NOT EXISTS lock_holder (id INTEGER)")
        result = engine.erase_subject(
            store_id="cases",
            subject_digest=ALICE_DIGEST,
            request_id=_request_id("erase-locked"),
        )
    finally:
        blocker.rollback()
        blocker.close()

    assert result.outcome == "retryable_error"
    assert result.error_code == "store_locked"
    assert result.affected_count is None
    # 行仍在；但墓碑先行已持久化（重试可安全续跑）。
    assert _rows(stores / "cases.db", "SELECT problem FROM cases WHERE user_id=?", (ALICE,)) != []
    retry = engine.erase_subject(
        store_id="cases",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("erase-locked"),
    )
    assert retry.outcome == "completed"
    assert retry.affected_count == 1


def test_erase_schema_mismatch_is_permanent(engine, stores) -> None:
    with sqlite3.connect(str(stores / "cases.db")) as connection:
        connection.execute("ALTER TABLE cases RENAME TO cases_old")
    result = engine.erase_subject(
        store_id="cases",
        subject_digest=ALICE_DIGEST,
        request_id=_request_id("erase-broken"),
    )

    assert result.outcome == "permanent_error"
    assert result.error_code == "schema_mismatch"
    assert result.affected_count is None
    # 永久错误不得假装完成：行仍在原处（改名后的旧表）。
    assert _rows(stores / "cases.db", "SELECT problem FROM cases_old") != []


def test_unknown_store_rejected(engine) -> None:
    with pytest.raises(ValueError, match="store"):
        engine.erase_subject(
            store_id="semcache",
            subject_digest=ALICE_DIGEST,
            request_id=_request_id("erase-usage"),
        )


# ── 保留期执行器 ────────────────────────────────────────────────────


def test_retention_erases_expired_rows_and_writes_tombstones(engine, stores) -> None:
    now = time.time()
    old = now - 40 * 86400
    with sqlite3.connect(str(stores / "cases.db")) as connection:
        connection.execute("UPDATE cases SET created_at=? WHERE user_id=?", (old, ALICE))
        connection.commit()
    with sqlite3.connect(str(stores / "memory.db")) as connection:
        connection.execute(
            "UPDATE user_memory SET created_at=?,updated_at=? WHERE user_id=?",
            (old, old, ALICE),
        )
        connection.commit()

    cases_result = engine.run_retention(
        store_id="cases", max_age_seconds=30 * 86400, now=now
    )
    memory_result = engine.run_retention(
        store_id="memory", max_age_seconds=30 * 86400, now=now
    )

    assert cases_result.outcome == "completed"
    assert cases_result.affected_count == 1
    assert memory_result.outcome == "completed"
    assert memory_result.affected_count == 1
    assert _rows(stores / "cases.db", "SELECT problem FROM cases") == [("bob case",)]
    tombstones = _rows(
        stores / "privacy_tombstones.db",
        "SELECT store_id,kind FROM privacy_delete_tombstones ORDER BY store_id",
    )
    assert tombstones == [("cases", "retention"), ("memory", "retention")]
    # 每个库的保留期执行各有独立 run 封条。
    runs = _rows(
        stores / "privacy_tombstones.db",
        "SELECT store_id,kind,row_count FROM privacy_tombstone_runs ORDER BY store_id",
    )
    assert runs == [("cases", "retention", 1), ("memory", "retention", 1)]


def test_retention_keeps_fresh_and_ageless_rows(engine, stores) -> None:
    now = time.time()
    with sqlite3.connect(str(stores / "memory.db")) as connection:
        connection.execute(
            "UPDATE user_memory SET created_at=NULL,updated_at=NULL WHERE user_id=?",
            (ALICE,),
        )
        connection.commit()
    result = engine.run_retention(
        store_id="memory", max_age_seconds=30 * 86400, now=now
    )

    assert result.outcome == "completed"
    assert result.affected_count == 0
    # 时间戳缺失的行无法证明年龄：宁可保留，绝不猜删。
    assert _rows(stores / "memory.db", "SELECT COUNT(*) FROM user_memory") == [(2,)]


def test_retention_conversations_by_turn_timestamp(engine, stores) -> None:
    now = time.time()
    old = now - 40 * 86400
    with sqlite3.connect(str(stores / "conversations.db")) as connection:
        connection.execute("UPDATE conv SET ts=? WHERE key=?", (old, CONV_KEY))
        connection.commit()
    result = engine.run_retention(
        store_id="conversations", max_age_seconds=30 * 86400, now=now
    )

    assert result.outcome == "completed"
    assert result.affected_count == 2
    reopened = ConversationStore(db_path=str(stores / "conversations.db"))
    try:
        assert reopened.get(CONV_KEY) == []
        assert len(reopened.get("web:bob-session")) == 1
    finally:
        reopened.close()


def test_retention_locked_store_is_retryable(engine, stores) -> None:
    blocker = sqlite3.connect(str(stores / "memory.db"), timeout=5.0)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        blocker.execute("CREATE TABLE IF NOT EXISTS lock_holder (id INTEGER)")
        result = engine.run_retention(
            store_id="memory", max_age_seconds=1, now=time.time()
        )
    finally:
        blocker.rollback()
        blocker.close()

    assert result.outcome == "retryable_error"
    assert result.error_code == "store_locked"
    assert _rows(stores / "memory.db", "SELECT COUNT(*) FROM user_memory") == [(2,)]


def test_retention_rejects_invalid_limits(engine) -> None:
    with pytest.raises(ValueError):
        engine.run_retention(store_id="memory", max_age_seconds=0, now=time.time())
    with pytest.raises(ValueError):
        engine.run_retention(store_id="unknown", max_age_seconds=60, now=time.time())


# ── 权利请求执行（NCPR 回执链） ──────────────────────────────────────


def _app(tmp_path, engine) -> FastAPI:
    app = FastAPI()
    app.include_router(privacy_admin.router)
    app.dependency_overrides[require_api_key] = lambda: "runtime"
    app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    app.state.privacy_rights = PrivacyRightsLedger(tmp_path / "privacy_rights.db")
    app.state.privacy_execution = engine
    return app


def _open_request(
    client: TestClient, *, label: str, action: str, subject_digest: str, steps: list
) -> str:
    request_id = _request_id(label)
    assert client.post(
        "/admin/privacy-rights/requests",
        json={
            "request_id": request_id,
            "action": action,
            "subject_digest": subject_digest,
        },
    ).status_code == 200
    assert client.post(
        f"/admin/privacy-rights/requests/{request_id}/identity",
        json={"evidence_sha256": _digest(f"identity-{label}")},
    ).status_code == 200
    assert client.post(
        f"/admin/privacy-rights/requests/{request_id}/scope", json={"steps": steps}
    ).status_code == 200
    assert client.post(
        f"/admin/privacy-rights/requests/{request_id}/start", json={}
    ).status_code == 200
    return request_id


def test_export_request_executes_end_to_end_with_ncpr_receipts(engine, tmp_path) -> None:
    steps = [asdict(step) for step in export_scope_steps(("memory", "cases"))]
    with TestClient(_app(tmp_path, engine)) as client:
        request_id = _open_request(
            client,
            label="export-request",
            action="export",
            subject_digest=ALICE_DIGEST,
            steps=steps,
        )
        executed = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert executed.status_code == 200, executed.text
        report = executed.json()
        assert report["snapshot"]["completed_steps"] == 2
        assert report["snapshot"]["ready_to_finalize"] is True
        assert len(report["executed"]) == 2
        assert all(step["outcome"] == "completed" for step in report["executed"])
        assert all(
            step["evidence_sha256"] and len(step["evidence_sha256"]) == 64
            for step in report["executed"]
        )
        assert report["skipped"] == []

        # 精确重放同一请求（仍在 executing）：不新增回执、不重复执行。
        replay = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert replay.status_code == 200
        assert replay.json()["executed"] == []
        assert replay.json()["snapshot"]["completed_steps"] == 2

        finalized = client.post(
            f"/admin/privacy-rights/requests/{request_id}/finalize", json={}
        )
        assert finalized.status_code == 200
        assert finalized.json()["state"] == "completed"

        # 已完结的请求终态关闭：再执行是冲突，不得假装幂等成功。
        after_finalize = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert after_finalize.status_code == 409


def test_delete_request_erases_all_four_stores_with_receipts(engine, tmp_path) -> None:
    steps = [asdict(step) for step in delete_scope_steps()]
    with TestClient(_app(tmp_path, engine)) as client:
        request_id = _open_request(
            client,
            label="delete-request",
            action="delete",
            subject_digest=ALICE_DIGEST,
            steps=steps,
        )
        executed = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert executed.status_code == 200, executed.text
        report = executed.json()
        assert report["snapshot"]["ready_to_finalize"] is True
        assert report["skipped"] == []

        assert _rows(tmp_path / "memory.db", "SELECT COUNT(*) FROM user_memory") == [(1,)]
        assert _rows(tmp_path / "cases.db", "SELECT COUNT(*) FROM cases") == [(1,)]
        assert _rows(tmp_path / "knowledge.db", "SELECT COUNT(*) FROM kb_docs") == [(1,)]
        # 四库删除各自有 run 封条；源请求可溯源。
        runs = _rows(
            tmp_path / "privacy_tombstones.db",
            "SELECT store_id,source_id FROM privacy_tombstone_runs ORDER BY store_id",
        )
        assert runs == [
            ("cases", request_id),
            ("knowledge", request_id),
            ("memory", request_id),
        ]

        finalized = client.post(
            f"/admin/privacy-rights/requests/{request_id}/finalize", json={}
        )
        assert finalized.json()["state"] == "completed"


def test_execute_skips_unsupported_operations_without_fake_receipts(
    engine, tmp_path
) -> None:
    steps = [
        {"step_id": "erase-memory", "store_id": "memory", "operation": "erase"},
        {
            "step_id": "notify-processor",
            "store_id": "memory",
            "operation": "notify_processor",
            "depends_on": ["erase-memory"],
        },
    ]
    with TestClient(_app(tmp_path, engine)) as client:
        request_id = _open_request(
            client,
            label="mixed-scope",
            action="delete",
            subject_digest=ALICE_DIGEST,
            steps=steps,
        )
        executed = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert executed.status_code == 200, executed.text
        report = executed.json()
        assert [step["step_id"] for step in report["executed"]] == ["erase-memory"]
        assert report["skipped"] == [
            {"step_id": "notify-processor", "reason": "no_adapter"}
        ]
        snapshot = report["snapshot"]
        assert snapshot["completed_steps"] == 1
        assert snapshot["ready_to_finalize"] is False
        # 未被支持的步骤不得收到伪造回执，请求不得可完结。
        finalized = client.post(
            f"/admin/privacy-rights/requests/{request_id}/finalize", json={}
        )
        assert finalized.status_code == 409


def test_execute_records_unknown_outcome_for_internal_adapter_errors(
    engine, tmp_path, monkeypatch
) -> None:
    def explode(**_kwargs):  # noqa: ANN001, ANN202
        raise RuntimeError("synthetic adapter crash")

    monkeypatch.setattr(engine, "export_store", explode)
    steps = [{"step_id": "export-memory", "store_id": "memory", "operation": "export"}]
    with TestClient(_app(tmp_path, engine)) as client:
        request_id = _open_request(
            client,
            label="crash-request",
            action="export",
            subject_digest=ALICE_DIGEST,
            steps=steps,
        )
        executed = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert executed.status_code == 200, executed.text
        report = executed.json()
        assert report["executed"][0]["outcome"] == "unknown"
        assert report["executed"][0]["error_code"] == "adapter_internal_error"
        assert report["executed"][0]["affected_count"] is None
        snapshot = report["snapshot"]
        assert snapshot["unknown_steps"] == 1
        assert snapshot["ready_to_finalize"] is False


def test_execute_refused_before_start(engine, tmp_path) -> None:
    with TestClient(_app(tmp_path, engine)) as client:
        request_id = _request_id("not-started")
        assert client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": request_id,
                "action": "export",
                "subject_digest": ALICE_DIGEST,
            },
        ).status_code == 200
        response = client.post(
            f"/admin/privacy-rights/requests/{request_id}/execute", json={}
        )
        assert response.status_code == 409


# ── 保留期路由 ──────────────────────────────────────────────────────


def test_retention_route_runs_named_stores_with_dual_auth(engine, tmp_path) -> None:
    denied_app = FastAPI()
    denied_app.include_router(privacy_admin.router)

    def reject_runtime() -> str:
        raise HTTPException(status_code=401, detail="denied")

    denied_app.dependency_overrides[require_api_key] = reject_runtime
    denied_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    with TestClient(denied_app) as denied_client:
        denied = denied_client.post(
            "/admin/privacy-rights/retention/run",
            json={"stores": {"cases": {"max_age_seconds": 86400}}},
        )
        assert denied.status_code == 401

    with TestClient(_app(tmp_path, engine)) as client:
        extra = client.post(
            "/admin/privacy-rights/retention/run",
            json={
                "stores": {"cases": {"max_age_seconds": 86400}},
                "unexpected": True,
            },
        )
        assert extra.status_code == 422

        unknown_store = client.post(
            "/admin/privacy-rights/retention/run",
            json={"stores": {"usage": {"max_age_seconds": 86400}}},
        )
        assert unknown_store.status_code == 422

        ran = client.post(
            "/admin/privacy-rights/retention/run",
            json={"stores": {"cases": {"max_age_seconds": 30 * 86400}}},
        )
        assert ran.status_code == 200, ran.text
        report = ran.json()
        (store,) = report["stores"]
        assert store["store_id"] == "cases"
        assert store["outcome"] == "completed"
        assert store["affected_count"] == 0
        assert store["error_code"] is None
        assert len(store["evidence_sha256"]) == 64
        # bob 的案例未到期，必须仍在。
        assert _rows(tmp_path / "cases.db", "SELECT COUNT(*) FROM cases") == [(2,)]


def test_retention_route_reports_locked_store_honestly(engine, tmp_path) -> None:
    blocker = sqlite3.connect(str(tmp_path / "memory.db"), timeout=5.0)
    blocker.execute("BEGIN EXCLUSIVE")
    blocker.execute("CREATE TABLE IF NOT EXISTS lock_holder (id INTEGER)")
    try:
        with TestClient(_app(tmp_path, engine)) as client:
            ran = client.post(
                "/admin/privacy-rights/retention/run",
                json={"stores": {"memory": {"max_age_seconds": 1}}},
            )
    finally:
        blocker.rollback()
        blocker.close()

    assert ran.status_code == 200
    store = ran.json()["stores"][0]
    assert store["store_id"] == "memory"
    assert store["outcome"] == "retryable_error"
    assert store["error_code"] == "store_locked"
    assert store["affected_count"] is None
    assert _rows(tmp_path / "memory.db", "SELECT COUNT(*) FROM user_memory") == [(2,)]


# ── 墓碑库自身的纪律 ────────────────────────────────────────────────


def test_tombstone_store_rejects_foreign_schema(tmp_path) -> None:
    path = tmp_path / "privacy_tombstones.db"
    store = PrivacyTombstoneStore(path)
    store.close()
    with sqlite3.connect(str(path)) as connection:
        connection.execute("CREATE TABLE rogue (id INTEGER)")
    with pytest.raises(Exception):
        PrivacyTombstoneStore(path)
