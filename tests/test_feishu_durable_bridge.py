from __future__ import annotations

import ast
from contextlib import contextmanager
import importlib.util
import io
import json
import logging
import os
import queue
import re
import sqlite3
import sys
import threading
import time
import urllib.error
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _load_runner():
    path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
    spec = importlib.util.spec_from_file_location("run_feishu_durable_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_state_runner_without_sdk(monkeypatch):
    """Load durable-state logic without importing the very large Feishu SDK."""

    lark_module = ModuleType("lark_oapi")
    lark_module.Client = type("Client", (), {})
    lark_module.LogLevel = SimpleNamespace(ERROR="ERROR")
    lark_module.ws = SimpleNamespace(Client=type("WsClient", (), {}))
    core_module = ModuleType("lark_oapi.core")
    core_log_module = ModuleType("lark_oapi.core.log")
    core_log_module.logger = logging.getLogger("nachuan-feishu-state-test")
    api_module = ModuleType("lark_oapi.api")
    im_module = ModuleType("lark_oapi.api.im")
    im_v1_module = ModuleType("lark_oapi.api.im.v1")
    for name in (
        "CreateFileRequest",
        "CreateFileRequestBody",
        "CreateImageRequest",
        "CreateImageRequestBody",
        "CreateMessageRequest",
        "CreateMessageRequestBody",
        "GetMessageResourceRequest",
        "P2ImMessageReceiveV1",
    ):
        setattr(im_v1_module, name, type(name, (), {}))
    for name, module in (
        ("lark_oapi", lark_module),
        ("lark_oapi.core", core_module),
        ("lark_oapi.core.log", core_log_module),
        ("lark_oapi.api", api_module),
        ("lark_oapi.api.im", im_module),
        ("lark_oapi.api.im.v1", im_v1_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return _load_runner()


def _create_canonical_feishu_v2_database(
    path: Path,
    *,
    inbox_chat_id_definition: str = "chat_id TEXT NOT NULL",
    extra_schema: str = "",
) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            f"""
            CREATE TABLE feishu_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_uuid TEXT NOT NULL UNIQUE,
                chat_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at REAL NOT NULL,
                next_attempt_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT NOT NULL DEFAULT '',
                claimed_at REAL NOT NULL DEFAULT 0,
                claim_token TEXT NOT NULL DEFAULT '',
                claim_deadline REAL NOT NULL DEFAULT 0,
                heartbeat_at REAL NOT NULL DEFAULT 0,
                claim_epoch INTEGER NOT NULL DEFAULT 0,
                last_finish_token TEXT NOT NULL DEFAULT '',
                last_finish_epoch INTEGER NOT NULL DEFAULT 0,
                last_finish_outcome TEXT NOT NULL DEFAULT '',
                delivered_at REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_feishu_outbox_due
                ON feishu_outbox(status, next_attempt_at, id);
            CREATE TABLE feishu_inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                {inbox_chat_id_definition},
                payload TEXT NOT NULL,
                received_at REAL NOT NULL,
                next_attempt_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT NOT NULL DEFAULT '',
                claimed_at REAL NOT NULL DEFAULT 0,
                claim_token TEXT NOT NULL DEFAULT '',
                claim_deadline REAL NOT NULL DEFAULT 0,
                heartbeat_at REAL NOT NULL DEFAULT 0,
                claim_epoch INTEGER NOT NULL DEFAULT 0,
                last_finish_token TEXT NOT NULL DEFAULT '',
                last_finish_epoch INTEGER NOT NULL DEFAULT 0,
                last_finish_outcome TEXT NOT NULL DEFAULT '',
                finished_at REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_feishu_inbox_due
                ON feishu_inbox(status, next_attempt_at, id);
            PRAGMA user_version=2;
            {extra_schema}
            """
        )
        conn.commit()
    finally:
        conn.close()


def _create_canonical_feishu_v4_database(path: Path) -> None:
    _create_canonical_feishu_v2_database(path)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version=4")


def _create_canonical_feishu_v0_database(
    path: Path,
    *,
    inbox_chat_id_definition: str = "chat_id TEXT NOT NULL",
    extra_schema: str = "",
) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            f"""
            CREATE TABLE feishu_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_uuid TEXT NOT NULL UNIQUE,
                chat_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at REAL NOT NULL,
                next_attempt_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT NOT NULL DEFAULT '',
                claimed_at REAL NOT NULL DEFAULT 0,
                delivered_at REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE feishu_inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                {inbox_chat_id_definition},
                payload TEXT NOT NULL,
                received_at REAL NOT NULL,
                next_attempt_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT NOT NULL DEFAULT '',
                claimed_at REAL NOT NULL DEFAULT 0,
                finished_at REAL NOT NULL DEFAULT 0
            );
            {extra_schema}
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_feishu_v5_initializes_exact_manual_recovery_schema(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-v5-new.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)

    with runner._state_transaction() as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        inbox_columns = tuple(
            str(row[1]) for row in conn.execute("PRAGMA table_xinfo(feishu_inbox)")
        )
        outbox_columns = tuple(
            str(row[1]) for row in conn.execute("PRAGMA table_xinfo(feishu_outbox)")
        )
        objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in conn.execute(
                "SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name"
            )
        }

    assert version == 5
    assert inbox_columns[-2:] == ("terminal_verification", "closed_at")
    assert outbox_columns[-2:] == ("terminal_verification", "closed_at")
    assert {
        ("table", "feishu_recovery_receipt", "feishu_recovery_receipt"),
        (
            "index",
            "uq_feishu_recovery_receipt_operation",
            "feishu_recovery_receipt",
        ),
        (
            "index",
            "uq_feishu_recovery_receipt_decision",
            "feishu_recovery_receipt",
        ),
        (
            "index",
            "uq_feishu_recovery_receipt_sha256",
            "feishu_recovery_receipt",
        ),
        (
            "index",
            "uq_feishu_recovery_receipt_previous_sha256",
            "feishu_recovery_receipt",
        ),
        (
            "index",
            "idx_feishu_recovery_receipt_target",
            "feishu_recovery_receipt",
        ),
        (
            "trigger",
            "feishu_recovery_receipt_no_update",
            "feishu_recovery_receipt",
        ),
        (
            "trigger",
            "feishu_recovery_receipt_no_delete",
            "feishu_recovery_receipt",
        ),
        (
            "trigger",
            "feishu_recovery_receipt_no_replace",
            "feishu_recovery_receipt",
        ),
    }.issubset(objects)


@pytest.mark.parametrize(
    "conflict_column",
    ["operation", "decision", "receipt", "previous"],
)
def test_feishu_v5_recovery_receipt_insert_or_replace_cannot_overwrite_history(
    tmp_path: Path,
    monkeypatch,
    conflict_column: str,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / f"feishu-receipt-no-replace-{conflict_column}.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    columns = (
        "id,operation_digest,decision_id,target_kind,target_key_sha256,chat_sha256,"
        "actor,authorization,reason,decided_at_ms,closed_at_ms,"
        "affected_inbox_count,affected_outbox_count,before_digest,after_digest,"
        "affected_rows_json,previous_receipt_sha256,receipt_sha256"
    )
    original = (
        1,
        "1" * 64,
        "2" * 64,
        "inbox",
        "3" * 64,
        "4" * 64,
        "operator",
        "5" * 64,
        "verified close",
        1000,
        1001,
        1,
        0,
        "6" * 64,
        "7" * 64,
        "[]",
        "0" * 64,
        "8" * 64,
    )
    replacements = {
        "operation": (
            2, "1" * 64, "a" * 64, "outbox", "b" * 64, "c" * 64,
            "other", "d" * 64, "other reason", 2000, 2001, 0, 1,
            "e" * 64, "f" * 64, "[]", "9" * 64, "0" * 63 + "1",
        ),
        "decision": (
            2, "a" * 64, "2" * 64, "outbox", "b" * 64, "c" * 64,
            "other", "d" * 64, "other reason", 2000, 2001, 0, 1,
            "e" * 64, "f" * 64, "[]", "9" * 64, "0" * 63 + "1",
        ),
        "receipt": (
            2, "a" * 64, "b" * 64, "outbox", "c" * 64, "d" * 64,
            "other", "e" * 64, "other reason", 2000, 2001, 0, 1,
            "f" * 64, "9" * 64, "[]", "0" * 63 + "1", "8" * 64,
        ),
        "previous": (
            2, "a" * 64, "b" * 64, "outbox", "c" * 64, "d" * 64,
            "other", "e" * 64, "other reason", 2000, 2001, 0, 1,
            "f" * 64, "9" * 64, "[]", "0" * 64, "0" * 63 + "1",
        ),
    }
    with runner._state_transaction() as conn:
        conn.execute(
            f"INSERT INTO feishu_recovery_receipt({columns}) VALUES({','.join('?' for _ in original)})",
            original,
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with sqlite3.connect(state_db) as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO feishu_recovery_receipt({columns}) "
                f"VALUES({','.join('?' for _ in original)})",
                replacements[conflict_column],
            )
    with sqlite3.connect(state_db) as conn:
        rows = tuple(conn.execute("SELECT * FROM feishu_recovery_receipt"))
    assert len(rows) == 1
    assert rows[0][0] == 1
    assert rows[0][1] == "1" * 64
    assert rows[0][2] == "2" * 64
    assert rows[0][-1] == "8" * 64


def test_feishu_close_without_replay_closes_whole_chat_and_writes_receipt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-without-replay.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    tombstone = '{"state":"closed_without_replay","version":1}'
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status,last_error,claim_epoch,last_finish_token,"
            "last_finish_epoch,last_finish_outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "target-inbox",
                "chat-close",
                '{"secret":"inbox"}',
                10.0,
                10.0,
                "recovery_required",
                "provider_unknown",
                7,
                "inbox-finish-token",
                7,
                "recovery_required",
            ),
        )
        conn.execute(
            "INSERT INTO feishu_outbox(delivery_uuid,chat_id,msg_type,content,"
            "created_at,next_attempt_at,status,last_error,claim_epoch,"
            "last_finish_token,last_finish_epoch,last_finish_outcome) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "same-chat-outbox",
                "chat-close",
                "text",
                '{"text":"secret"}',
                11.0,
                11.0,
                "recovery_required",
                "provider_unknown",
                9,
                "outbox-finish-token",
                9,
                "recovery_required",
            ),
        )
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            (
                "other-chat-inbox",
                "chat-other",
                '{"secret":"other"}',
                12.0,
                12.0,
                "recovery_required",
            ),
        )

    expected_before = runner._recovery_target_before_digest(
        "inbox", "target-inbox"
    )
    fields = {
        "decision_id": "d" * 64,
        "target_kind": "inbox",
        "target_key": "target-inbox",
        "expected_before_digest": expected_before,
        "actor": "operator:alice",
        "authorization": "a" * 64,
        "reason": "verified provider outcome cannot be recovered safely",
        "decided_at_ms": 1_700_000_000_000,
    }
    operation_digest = runner._close_without_replay_operation_digest(**fields)
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=operation_digest,
        **fields,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("manual close must not call any external or enqueue seam")

    for name in (
        "_post",
        "_engine_open",
        "_send_outbox_claim",
        "_enqueue_outbox",
        "_enqueue_outbox_in_transaction",
    ):
        monkeypatch.setattr(runner, name, forbidden)

    result = runner._close_without_replay(
        request,
        closed_at_ms=1_700_000_000_123,
    )

    assert result.applied is True
    assert result.operation_digest == operation_digest
    assert result.affected_inbox_count == 1
    assert result.affected_outbox_count == 1
    assert len(result.receipt_sha256) == 64
    with sqlite3.connect(state_db) as conn:
        inbox = conn.execute(
            "SELECT status,chat_id,payload,claimed_at,claim_token,claim_deadline,"
            "heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,"
            "last_finish_outcome,terminal_verification,closed_at "
            "FROM feishu_inbox WHERE message_id='target-inbox'"
        ).fetchone()
        outbox = conn.execute(
            "SELECT status,chat_id,content,claimed_at,claim_token,claim_deadline,"
            "heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,"
            "last_finish_outcome,terminal_verification,closed_at "
            "FROM feishu_outbox WHERE delivery_uuid='same-chat-outbox'"
        ).fetchone()
        untouched = conn.execute(
            "SELECT status,chat_id,payload FROM feishu_inbox "
            "WHERE message_id='other-chat-inbox'"
        ).fetchone()
        receipt = conn.execute(
            "SELECT operation_digest,decision_id,target_kind,target_key_sha256,"
            "actor,authorization,reason,decided_at_ms,closed_at_ms,"
            "affected_inbox_count,affected_outbox_count,before_digest,"
            "after_digest,affected_rows_json,previous_receipt_sha256,receipt_sha256 "
            "FROM feishu_recovery_receipt"
        ).fetchone()

    assert inbox == (
        "closed",
        "",
        tombstone,
        0.0,
        "",
        0.0,
        0.0,
        7,
        "inbox-finish-token",
        7,
        "recovery_required",
        "closed_without_replay",
        pytest.approx(1_700_000_000.123),
    )
    assert outbox == (
        "closed",
        "",
        tombstone,
        0.0,
        "",
        0.0,
        0.0,
        9,
        "outbox-finish-token",
        9,
        "recovery_required",
        "closed_without_replay",
        pytest.approx(1_700_000_000.123),
    )
    assert untouched == (
        "recovery_required",
        "chat-other",
        '{"secret":"other"}',
    )
    assert receipt[:3] == (operation_digest, "d" * 64, "inbox")
    assert receipt[4:11] == (
        "operator:alice",
        "a" * 64,
        "verified provider outcome cannot be recovered safely",
        1_700_000_000_000,
        1_700_000_000_123,
        1,
        1,
    )
    assert receipt[11] == expected_before
    assert len(receipt[12]) == 64
    affected = json.loads(receipt[13])
    assert [(row["kind"], row["row_id"]) for row in affected] == [
        ("inbox", 1),
        ("outbox", 1),
    ]
    assert all(set(row) == {"after_sha256", "before_sha256", "kind", "row_id", "target_sha256"} for row in affected)
    assert receipt[14] == "0" * 64
    assert receipt[15] == result.receipt_sha256


def test_feishu_close_without_replay_response_loss_retry_uses_operation_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-response-loss.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("response-loss-target", "chat-a", "{}", 1.0, 1.0, "recovery_required"),
        )
    expected_before = runner._recovery_target_before_digest(
        "inbox", "response-loss-target"
    )
    fields = {
        "decision_id": "1" * 64,
        "target_kind": "inbox",
        "target_key": "response-loss-target",
        "expected_before_digest": expected_before,
        "actor": "operator:bob",
        "authorization": "2" * 64,
        "reason": "confirmed no automatic replay",
        "decided_at_ms": 5000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    first = runner._close_without_replay(request, closed_at_ms=5001)
    assert first.applied is True

    def forbidden_target_read(*_args, **_kwargs):
        raise AssertionError("response-loss retry must not re-read a closed target")

    monkeypatch.setattr(
        runner,
        "_recovery_target_rows_in_transaction",
        forbidden_target_read,
    )
    retry = runner._close_without_replay(request, closed_at_ms=9000)

    assert retry == runner._FeishuCloseWithoutReplayResult(
        operation_digest=first.operation_digest,
        receipt_sha256=first.receipt_sha256,
        affected_inbox_count=1,
        affected_outbox_count=0,
        affected_video_count=0,
        applied=False,
    )
    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 1


def test_feishu_close_without_replay_rejects_a_broken_existing_receipt_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-recovery-broken-chain.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("chain-target", "chat-chain", "{}", 1.0, 1.0, "recovery_required"),
        )
    before = runner._recovery_target_before_digest("inbox", "chain-target")
    fields = {
        "decision_id": "1" * 64,
        "target_kind": "inbox",
        "target_key": "chain-target",
        "expected_before_digest": before,
        "actor": "operator:chain",
        "authorization": "2" * 64,
        "reason": "validated close",
        "decided_at_ms": 20_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    assert runner._close_without_replay(request, closed_at_ms=20_001).applied is True

    target_sha256 = "3" * 64
    forged_manifest = runner._canonical_recovery_json(
        [
            {
                "after_sha256": "4" * 64,
                "before_sha256": "5" * 64,
                "kind": "inbox",
                "row_id": 999,
                "target_sha256": target_sha256,
            }
        ]
    )
    forged = {
        "id": 2,
        "operation_digest": "6" * 64,
        "decision_id": "7" * 64,
        "target_kind": "inbox",
        "target_key_sha256": target_sha256,
        "chat_sha256": "8" * 64,
        "actor": "operator:forged",
        "authorization": "9" * 64,
        "reason": "broken previous pointer",
        "decided_at_ms": 20_002,
        "closed_at_ms": 20_003,
        "affected_inbox_count": 1,
        "affected_outbox_count": 0,
        "before_digest": "a" * 64,
        "after_digest": "b" * 64,
        "affected_rows_json": forged_manifest,
        "previous_receipt_sha256": "c" * 64,
    }
    forged["receipt_sha256"] = runner._recovery_receipt_sha256(forged)
    columns = ",".join(runner._RECOVERY_RECEIPT_COLUMNS)
    with runner._state_write_transaction() as conn:
        conn.execute(
            f"INSERT INTO feishu_recovery_receipt({columns}) "
            f"VALUES({','.join('?' for _ in runner._RECOVERY_RECEIPT_COLUMNS)})",
            tuple(forged[name] for name in runner._RECOVERY_RECEIPT_COLUMNS),
        )

    with pytest.raises(runner.FeishuRecoveryConflict, match="receipt chain"):
        runner._close_without_replay(request, closed_at_ms=20_004)


def test_feishu_close_without_replay_rejects_an_invalid_receipt_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-recovery-invalid-manifest.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    forged = {
        "id": 1,
        "operation_digest": "1" * 64,
        "decision_id": "2" * 64,
        "target_kind": "inbox",
        "target_key_sha256": "3" * 64,
        "chat_sha256": "4" * 64,
        "actor": "operator:forged",
        "authorization": "5" * 64,
        "reason": "count does not match an empty manifest",
        "decided_at_ms": 30_000,
        "closed_at_ms": 30_001,
        "affected_inbox_count": 1,
        "affected_outbox_count": 0,
        "before_digest": "6" * 64,
        "after_digest": "7" * 64,
        "affected_rows_json": "[]",
        "previous_receipt_sha256": "0" * 64,
    }
    forged["receipt_sha256"] = runner._recovery_receipt_sha256(forged)
    columns = ",".join(runner._RECOVERY_RECEIPT_COLUMNS)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("manifest-target", "chat-manifest", "{}", 1.0, 1.0, "recovery_required"),
        )
        conn.execute(
            f"INSERT INTO feishu_recovery_receipt({columns}) "
            f"VALUES({','.join('?' for _ in runner._RECOVERY_RECEIPT_COLUMNS)})",
            tuple(forged[name] for name in runner._RECOVERY_RECEIPT_COLUMNS),
        )
    before = runner._recovery_target_before_digest("inbox", "manifest-target")
    fields = {
        "decision_id": "8" * 64,
        "target_kind": "inbox",
        "target_key": "manifest-target",
        "expected_before_digest": before,
        "actor": "operator:manifest",
        "authorization": "9" * 64,
        "reason": "validated close",
        "decided_at_ms": 30_002,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )

    with pytest.raises(runner.FeishuRecoveryConflict, match="receipt manifest"):
        runner._close_without_replay(request, closed_at_ms=30_003)
    with runner._state_transaction() as conn:
        assert conn.execute(
            "SELECT status FROM feishu_inbox WHERE message_id='manifest-target'"
        ).fetchone()[0] == "recovery_required"
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("ledger_kind", ["message", "video"])
def test_feishu_main_validates_recovery_receipt_chains_before_channel_client(
    tmp_path: Path,
    monkeypatch,
    ledger_kind: str,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu-startup-state.db")
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu-startup-videos.json")
    target_sha256 = "3" * 64
    manifest = runner._canonical_recovery_json(
        [
            {
                "after_sha256": "4" * 64,
                "before_sha256": "5" * 64,
                "kind": "inbox" if ledger_kind == "message" else "video",
                "row_id": 1,
                "target_sha256": target_sha256,
            }
        ]
    )
    common = {
        "id": 1,
        "operation_digest": "1" * 64,
        "decision_id": "2" * 64,
        "target_kind": "inbox" if ledger_kind == "message" else "video",
        "target_key_sha256": target_sha256,
        "chat_sha256": "6" * 64,
        "actor": "operator:startup-audit",
        "authorization": "7" * 64,
        "reason": "startup must reject a disconnected receipt head",
        "decided_at_ms": 40_000,
        "closed_at_ms": 40_001,
        "before_digest": "8" * 64,
        "after_digest": "9" * 64,
        "affected_rows_json": manifest,
        # A self-consistent first receipt with a non-zero predecessor is a
        # disconnected chain, even though its own digest is valid.
        "previous_receipt_sha256": "a" * 64,
    }
    if ledger_kind == "message":
        receipt = {
            **common,
            "affected_inbox_count": 1,
            "affected_outbox_count": 0,
        }
        receipt["receipt_sha256"] = runner._recovery_receipt_sha256(receipt)
        columns = ",".join(runner._RECOVERY_RECEIPT_COLUMNS)
        with runner._state_write_transaction() as conn:
            conn.execute(
                f"INSERT INTO feishu_recovery_receipt({columns}) "
                f"VALUES({','.join('?' for _ in runner._RECOVERY_RECEIPT_COLUMNS)})",
                tuple(receipt[name] for name in runner._RECOVERY_RECEIPT_COLUMNS),
            )
    else:
        receipt = {**common, "affected_video_count": 1}
        receipt["receipt_sha256"] = runner._pending_video_receipt_sha256(receipt)
        columns = ",".join(runner._PENDING_VIDEO_RECEIPT_COLUMNS)
        with runner._pending_state_transaction(write=True) as conn:
            conn.execute(
                f"INSERT INTO feishu_pending_video_recovery_receipt({columns}) "
                f"VALUES({','.join('?' for _ in runner._PENDING_VIDEO_RECEIPT_COLUMNS)})",
                tuple(
                    receipt[name] for name in runner._PENDING_VIDEO_RECEIPT_COLUMNS
                ),
            )

    external_calls: list[str] = []

    class _BoundSocket:
        def bind(self, _address) -> None:
            return None

    class _ForbiddenClient:
        @staticmethod
        def builder():
            external_calls.append("client_builder")
            raise AssertionError("Feishu client must not be built before ledger validation")

    def forbidden(*_args, **_kwargs):
        external_calls.append("channel_or_worker")
        raise AssertionError("channel activity must not precede ledger validation")

    monkeypatch.setattr(
        runner,
        "S",
        SimpleNamespace(
            feishu_app_id="test-app",
            feishu_app_secret="test-secret",
            usage_db_path=str(tmp_path / "usage.db"),
        ),
    )
    monkeypatch.setattr(runner.socket, "socket", lambda *_args, **_kwargs: _BoundSocket())
    monkeypatch.setattr(runner.lark, "Client", _ForbiddenClient)
    for name in (
        "_recover_inflight",
        "_start_inbound_workers",
        "_start_video_workers",
        "_feed_pending_videos",
    ):
        monkeypatch.setattr(runner, name, forbidden)

    with pytest.raises(runner.FeishuRecoveryConflict, match="receipt chain"):
        runner.main()
    assert external_calls == []


def test_feishu_close_without_replay_rejects_target_set_drift_atomically(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-target-drift.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("drift-target", "chat-drift", "{}", 1.0, 1.0, "recovery_required"),
        )
    expected_before = runner._recovery_target_before_digest("inbox", "drift-target")
    fields = {
        "decision_id": "3" * 64,
        "target_kind": "inbox",
        "target_key": "drift-target",
        "expected_before_digest": expected_before,
        "actor": "operator:carol",
        "authorization": "4" * 64,
        "reason": "close the adjudicated affected set only",
        "decided_at_ms": 6000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_outbox(delivery_uuid,chat_id,msg_type,content,"
            "created_at,next_attempt_at,status) VALUES(?,?,?,?,?,?,?)",
            (
                "drifted-sibling",
                "chat-drift",
                "text",
                "{}",
                2.0,
                2.0,
                "recovery_required",
            ),
        )

    with pytest.raises(runner.FeishuRecoveryConflict, match="drifted"):
        runner._close_without_replay(request, closed_at_ms=6001)

    with sqlite3.connect(state_db) as conn:
        assert tuple(
            conn.execute(
                "SELECT status FROM feishu_inbox WHERE message_id='drift-target'"
            ).fetchone()
        ) == ("recovery_required",)
        assert tuple(
            conn.execute(
                "SELECT status FROM feishu_outbox "
                "WHERE delivery_uuid='drifted-sibling'"
            ).fetchone()
        ) == ("recovery_required",)
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 0


def test_feishu_close_without_replay_rejects_decision_id_reuse(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-decision-conflict.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        for message_id, chat_id in (("decision-a", "chat-a"), ("decision-b", "chat-b")):
            conn.execute(
                "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
                "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
                (message_id, chat_id, "{}", 1.0, 1.0, "recovery_required"),
            )
    shared_decision = "5" * 64

    def request_for(message_id: str, actor: str):
        expected = runner._recovery_target_before_digest("inbox", message_id)
        fields = {
            "decision_id": shared_decision,
            "target_kind": "inbox",
            "target_key": message_id,
            "expected_before_digest": expected,
            "actor": actor,
            "authorization": "6" * 64,
            "reason": "one decision may authorize one operation only",
            "decided_at_ms": 7000,
        }
        return runner._FeishuCloseWithoutReplayRequest(
            operation_digest=runner._close_without_replay_operation_digest(**fields),
            **fields,
        )

    first = request_for("decision-a", "operator:first")
    second = request_for("decision-b", "operator:second")
    assert runner._close_without_replay(first, closed_at_ms=7001).applied is True
    with pytest.raises(runner.FeishuRecoveryConflict, match="decision id"):
        runner._close_without_replay(second, closed_at_ms=7002)

    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT status FROM feishu_inbox WHERE message_id='decision-b'"
        ).fetchone()[0] == "recovery_required"
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 1


def test_feishu_close_without_replay_rejects_any_active_claim_in_target_chat(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-active-claim.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("claim-target", "chat-claim", "{}", 1.0, 1.0, "recovery_required"),
        )
        conn.execute(
            "INSERT INTO feishu_outbox(delivery_uuid,chat_id,msg_type,content,"
            "created_at,next_attempt_at,status) VALUES(?,?,?,?,?,?,?)",
            (
                "claim-sibling",
                "chat-claim",
                "text",
                "{}",
                1.0,
                1.0,
                "recovery_required",
            ),
        )
    before = runner._recovery_target_before_digest("inbox", "claim-target")
    fields = {
        "decision_id": "7" * 64,
        "target_kind": "inbox",
        "target_key": "claim-target",
        "expected_before_digest": before,
        "actor": "operator:claim-check",
        "authorization": "8" * 64,
        "reason": "all affected rows must be unclaimed",
        "decided_at_ms": 8000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    with runner._state_write_transaction() as conn:
        conn.execute(
            "UPDATE feishu_outbox SET claimed_at=8,claim_token='active',"
            "claim_deadline=999,heartbeat_at=8 WHERE delivery_uuid='claim-sibling'"
        )

    with pytest.raises(runner.FeishuRecoveryConflict, match="actively claimed"):
        runner._close_without_replay(request, closed_at_ms=8001)

    with sqlite3.connect(state_db) as conn:
        assert tuple(
            conn.execute(
                "SELECT status,claim_token FROM feishu_outbox "
                "WHERE delivery_uuid='claim-sibling'"
            ).fetchone()
        ) == ("recovery_required", "active")
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("decision_id", "0" * 64, "decision id"),
        ("decision_id", "A" * 64, "decision id"),
        ("target_kind", "audio", "target kind"),
        ("target_key", " target", "target key"),
        ("expected_before_digest", "g" * 64, "before digest"),
        ("actor", "operator\nadmin", "actor"),
        ("authorization", "short", "authorization"),
        ("reason", " reason", "reason"),
        ("decided_at_ms", True, "millisecond"),
        ("decided_at_ms", 1.5, "millisecond"),
    ),
)
def test_feishu_close_without_replay_strictly_validates_decision_fields(
    field: str,
    value: object,
    message: str,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    fields: dict[str, object] = {
        "decision_id": "9" * 64,
        "target_kind": "inbox",
        "target_key": "valid-target",
        "expected_before_digest": "a" * 64,
        "actor": "operator:strict",
        "authorization": "b" * 64,
        "reason": "validated reason",
        "decided_at_ms": 9000,
    }
    fields[field] = value

    with pytest.raises(ValueError, match=message):
        runner._close_without_replay_operation_digest(**fields)


def test_feishu_close_without_replay_requires_typed_canonical_request(monkeypatch) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    fields = {
        "decision_id": "c" * 64,
        "target_kind": "inbox",
        "target_key": "typed-target",
        "expected_before_digest": "d" * 64,
        "actor": "operator:typed",
        "authorization": "e" * 64,
        "reason": "typed request only",
        "decided_at_ms": 10_000,
    }
    operation = runner._close_without_replay_operation_digest(**fields)

    with pytest.raises(TypeError, match="typed request"):
        runner._close_without_replay(
            {"operation_digest": operation, **fields},
            closed_at_ms=10_001,
        )
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest="f" * 64,
        **fields,
    )
    with pytest.raises(runner.FeishuRecoveryConflict, match="canonical request"):
        runner._close_without_replay(request, closed_at_ms=10_001)
    valid = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=operation,
        **fields,
    )
    with pytest.raises(ValueError, match="millisecond"):
        runner._close_without_replay(valid, closed_at_ms=True)
    with pytest.raises(ValueError, match="precedes"):
        runner._close_without_replay(valid, closed_at_ms=9999)


def test_feishu_close_without_replay_receipt_capacity_rolls_back_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    assert runner._MAX_RECOVERY_RECEIPTS == 50_000
    state_db = tmp_path / "feishu-close-capacity.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        for message_id, chat_id in (("cap-a", "chat-a"), ("cap-b", "chat-b")):
            conn.execute(
                "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
                "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
                (message_id, chat_id, "{}", 1.0, 1.0, "recovery_required"),
            )

    def make_request(message_id: str, marker: str):
        before = runner._recovery_target_before_digest("inbox", message_id)
        fields = {
            "decision_id": marker * 64,
            "target_kind": "inbox",
            "target_key": message_id,
            "expected_before_digest": before,
            "actor": f"operator:{marker}",
            "authorization": ("a" if marker != "a" else "b") * 64,
            "reason": "capacity must be reserved before mutation",
            "decided_at_ms": 11_000,
        }
        return runner._FeishuCloseWithoutReplayRequest(
            operation_digest=runner._close_without_replay_operation_digest(**fields),
            **fields,
        )

    assert runner._close_without_replay(
        make_request("cap-a", "1"),
        closed_at_ms=11_001,
    ).applied is True
    monkeypatch.setattr(runner, "_MAX_RECOVERY_RECEIPTS", 1)
    with pytest.raises(runner.FeishuQueueFull, match="receipt capacity"):
        runner._close_without_replay(
            make_request("cap-b", "2"),
            closed_at_ms=11_002,
        )

    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT status FROM feishu_inbox WHERE message_id='cap-b'"
        ).fetchone()[0] == "recovery_required"
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 1


def test_feishu_close_without_replay_receipt_insert_failure_rolls_back_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-close-insert-failure.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("insert-failure", "chat-failure", "{}", 1.0, 1.0, "recovery_required"),
        )
    before = runner._recovery_target_before_digest("inbox", "insert-failure")
    fields = {
        "decision_id": "3" * 64,
        "target_kind": "inbox",
        "target_key": "insert-failure",
        "expected_before_digest": before,
        "actor": "operator:failure",
        "authorization": "4" * 64,
        "reason": "receipt persistence is part of the same transaction",
        "decided_at_ms": 12_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    real_connect = runner._state_connect

    def deny_receipt_insert(*args, **kwargs):
        conn = real_connect(*args, **kwargs)

        def authorizer(action, arg1, _arg2, _database, _trigger):
            if action == sqlite3.SQLITE_INSERT and arg1 == "feishu_recovery_receipt":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorizer)
        return conn

    monkeypatch.setattr(runner, "_state_connect", deny_receipt_insert)
    with pytest.raises(sqlite3.DatabaseError):
        runner._close_without_replay(request, closed_at_ms=12_001)

    with sqlite3.connect(state_db) as conn:
        assert tuple(
            conn.execute(
                "SELECT status,chat_id,payload,terminal_verification,closed_at "
                "FROM feishu_inbox WHERE message_id='insert-failure'"
            ).fetchone()
        ) == ("recovery_required", "chat-failure", "{}", "", 0.0)
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 0


def test_feishu_close_without_replay_operation_digest_has_fixed_canonical_vector(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)

    assert runner._close_without_replay_operation_digest(
        decision_id="a" * 64,
        target_kind="inbox",
        target_key="message-fixture",
        expected_before_digest="c" * 64,
        actor="operator:fixture",
        authorization="b" * 64,
        reason="validated reason",
        decided_at_ms=1_234_567_890,
    ) == "7139bb891a59d0ff8ab47eaa2fbb4bcaa7750ac758618646a4c65245eeffa894"


def test_feishu_recovery_receipts_chain_and_reject_update_delete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-receipt-chain.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_write_transaction() as conn:
        for message_id, chat_id in (("chain-a", "chat-a"), ("chain-b", "chat-b")):
            conn.execute(
                "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
                "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
                (message_id, chat_id, "{}", 1.0, 1.0, "recovery_required"),
            )

    receipts = []
    for ordinal, (message_id, marker) in enumerate(
        (("chain-a", "5"), ("chain-b", "6")),
        start=1,
    ):
        before = runner._recovery_target_before_digest("inbox", message_id)
        fields = {
            "decision_id": marker * 64,
            "target_kind": "inbox",
            "target_key": message_id,
            "expected_before_digest": before,
            "actor": f"operator:chain-{ordinal}",
            "authorization": ("7" if ordinal == 1 else "8") * 64,
            "reason": "append one chained receipt",
            "decided_at_ms": 13_000 + ordinal,
        }
        request = runner._FeishuCloseWithoutReplayRequest(
            operation_digest=runner._close_without_replay_operation_digest(**fields),
            **fields,
        )
        receipts.append(
            runner._close_without_replay(
                request,
                closed_at_ms=13_010 + ordinal,
            ).receipt_sha256
        )

    with sqlite3.connect(state_db) as conn:
        chain = tuple(
            conn.execute(
                "SELECT id,previous_receipt_sha256,receipt_sha256 "
                "FROM feishu_recovery_receipt ORDER BY id"
            )
        )
        assert chain == (
            (1, "0" * 64, receipts[0]),
            (2, receipts[0], receipts[1]),
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE feishu_recovery_receipt SET reason='changed' WHERE id=1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM feishu_recovery_receipt WHERE id=1")
        conn.rollback()
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 2


def test_feishu_v4_to_v5_migration_preserves_provider_submission_states(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-v4-to-v5.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v4_database(state_db)
    with sqlite3.connect(state_db) as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status,claimed_at,claim_token,claim_deadline,"
            "heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,"
            "last_finish_outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "v4-processing-inbox",
                "chat-inbox",
                "{}",
                1.0,
                1.0,
                "processing",
                2.0,
                "v4-inbox-token",
                30.0,
                2.0,
                4,
                "old-inbox-finish",
                3,
                "retry",
            ),
        )
        for delivery_uuid, status, token, epoch in (
            ("v4-processing-outbox", "processing", "v4-processing-token", 5),
            ("v4-submitting-outbox", "submitting", "v4-submitting-token", 6),
            ("v4-recovery-outbox", "recovery_required", "", 7),
        ):
            conn.execute(
                "INSERT INTO feishu_outbox(delivery_uuid,chat_id,msg_type,content,"
                "created_at,next_attempt_at,status,claimed_at,claim_token,"
                "claim_deadline,heartbeat_at,claim_epoch,last_finish_token,"
                "last_finish_epoch,last_finish_outcome) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    delivery_uuid,
                    f"chat-{epoch}",
                    "text",
                    "{}",
                    1.0,
                    1.0,
                    status,
                    0.0 if not token else 2.0,
                    token,
                    0.0 if not token else 30.0,
                    0.0 if not token else 2.0,
                    epoch,
                    f"old-finish-{epoch}",
                    epoch - 1,
                    "recovery_required" if status == "recovery_required" else "",
                ),
            )
        conn.commit()

    provider_calls: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: provider_calls.append(str(claim["delivery_uuid"])),
    )
    with runner._state_connect() as migrated:
        assert int(migrated.execute("PRAGMA user_version").fetchone()[0]) == 5
        inbox = migrated.execute(
            "SELECT status,claim_token,claim_epoch,last_finish_token,"
            "last_finish_epoch,last_finish_outcome,terminal_verification,closed_at "
            "FROM feishu_inbox WHERE message_id='v4-processing-inbox'"
        ).fetchone()
        outbox = tuple(
            migrated.execute(
                "SELECT delivery_uuid,status,claim_token,claim_epoch,"
                "last_finish_token,last_finish_epoch,last_finish_outcome,"
                "terminal_verification,closed_at FROM feishu_outbox ORDER BY id"
            )
        )
        assert migrated.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 0

    assert inbox == (
        "processing",
        "v4-inbox-token",
        4,
        "old-inbox-finish",
        3,
        "retry",
        "",
        0.0,
    )
    assert outbox == (
        (
            "v4-processing-outbox",
            "processing",
            "v4-processing-token",
            5,
            "old-finish-5",
            4,
            "",
            "",
            0.0,
        ),
        (
            "v4-submitting-outbox",
            "submitting",
            "v4-submitting-token",
            6,
            "old-finish-6",
            5,
            "",
            "",
            0.0,
        ),
        (
            "v4-recovery-outbox",
            "recovery_required",
            "",
            7,
            "old-finish-7",
            6,
            "recovery_required",
            "",
            0.0,
        ),
    )
    assert runner._drain_outbox(now=3.0, limit=10) == 0
    assert provider_calls == []


def test_feishu_v4_to_v5_receipt_schema_failure_rolls_back_whole_migration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-v4-v5-rollback.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v4_database(state_db)
    real_connect = sqlite3.connect
    with real_connect(state_db) as conn:
        conn.execute(
            "INSERT INTO feishu_outbox(delivery_uuid,chat_id,msg_type,content,"
            "created_at,next_attempt_at,status,last_finish_token,"
            "last_finish_epoch,last_finish_outcome) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "v4-rollback-row",
                "chat-rollback",
                "text",
                "{}",
                1.0,
                1.0,
                "recovery_required",
                "preserved-token",
                9,
                "recovery_required",
            ),
        )
    with real_connect(state_db) as conn:
        before = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )

    class FailReceiptSchema(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            if " ".join(str(sql).split()).startswith(
                "CREATE TABLE feishu_recovery_receipt"
            ):
                raise sqlite3.OperationalError("synthetic v5 receipt schema failure")
            return super().execute(sql, parameters)

    monkeypatch.setattr(
        runner.sqlite3,
        "connect",
        lambda database, **kwargs: real_connect(
            database,
            factory=FailReceiptSchema,
            **kwargs,
        ),
    )
    with pytest.raises(sqlite3.OperationalError, match="receipt schema failure"):
        runner._state_connect()

    with real_connect(state_db) as conn:
        after = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )
    assert after == before


@pytest.mark.parametrize(
    "tamper_sql",
    (
        "ALTER TABLE feishu_recovery_receipt ADD COLUMN attacker_data TEXT",
        "DROP INDEX idx_feishu_recovery_receipt_target; "
        "CREATE INDEX idx_feishu_recovery_receipt_target "
        "ON feishu_recovery_receipt(target_key_sha256,target_kind,id)",
        "DROP INDEX uq_feishu_recovery_receipt_previous_sha256",
        "DROP TRIGGER feishu_recovery_receipt_no_update; "
        "CREATE TRIGGER feishu_recovery_receipt_no_update "
        "BEFORE UPDATE ON feishu_recovery_receipt BEGIN SELECT 1; END",
    ),
)
def test_feishu_v5_exact_schema_rejects_table_index_or_trigger_sql_drift(
    tmp_path: Path,
    monkeypatch,
    tamper_sql: str,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / (
        "feishu-v5-schema-drift-"
        + str(abs(hash(tamper_sql)))
        + ".db"
    )
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    with runner._state_connect() as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 5
    with sqlite3.connect(state_db) as conn:
        conn.executescript(tamper_sql)
        before = tuple(
            conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
            )
        )

    with pytest.raises(RuntimeError, match="version 5 state database schema"):
        runner._state_connect()

    with sqlite3.connect(state_db) as conn:
        after = tuple(
            conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
            )
        )
    assert after == before


def test_feishu_closed_rows_release_capacity_readiness_and_survive_retention(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-closed-policy.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_PER_CHAT", 1)
    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            ("policy-target", "chat-policy", "{}", 1.0, 1.0, "recovery_required"),
        )
    new_payload = {
        "message_id": "after-close",
        "chat_id": "chat-policy",
        "message_type": "text",
        "content": '{"text":"new"}',
        "open_id": "user-policy",
    }
    with pytest.raises(runner.FeishuQueueFull):
        runner._store_inbound(new_payload, now=2.0)
    before_health = runner._health_snapshot(now=2.0)
    assert before_health["recovery_required_inbound"] == 1
    assert "inbox_recovery_required" in before_health["readiness_reasons"]

    before = runner._recovery_target_before_digest("inbox", "policy-target")
    fields = {
        "decision_id": "9" * 64,
        "target_kind": "inbox",
        "target_key": "policy-target",
        "expected_before_digest": before,
        "actor": "operator:policy",
        "authorization": "a" * 64,
        "reason": "release only after a no-replay terminal decision",
        "decided_at_ms": 14_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    assert runner._close_without_replay(request, closed_at_ms=14_001).applied is True
    assert runner._store_inbound(new_payload, now=15.0) is True

    after_health = runner._health_snapshot(now=15.0)
    assert after_health["recovery_required_inbound"] == 0
    assert "inbox_recovery_required" not in after_health["readiness_reasons"]
    runner._maintain_state(
        now=10_000_000.0,
        done_ttl_seconds=0,
        dead_ttl_seconds=0,
        max_terminal_rows=0,
    )
    with sqlite3.connect(state_db) as conn:
        assert conn.execute(
            "SELECT status,terminal_verification FROM feishu_inbox "
            "WHERE message_id='policy-target'"
        ).fetchone() == ("closed", "closed_without_replay")
        assert conn.execute(
            "SELECT status FROM feishu_inbox WHERE message_id='after-close'"
        ).fetchone() == ("pending",)
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_recovery_receipt"
        ).fetchone()[0] == 1


def test_feishu_closed_row_stops_blocking_later_chat_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "feishu-closed-chat-order.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)

    def payload(message_id: str, chat_id: str) -> str:
        return json.dumps(
            {
                "message_id": message_id,
                "chat_id": chat_id,
                "message_type": "text",
                "content": "{}",
                "open_id": "user-order",
            },
            separators=(",", ":"),
        )

    with runner._state_write_transaction() as conn:
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            (
                "order-recovery",
                "chat-order",
                payload("order-recovery", "chat-order"),
                1.0,
                1.0,
                "recovery_required",
            ),
        )
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            (
                "order-later",
                "chat-order",
                payload("order-later", "chat-order"),
                2.0,
                2.0,
                "pending",
            ),
        )
        conn.execute(
            "INSERT INTO feishu_inbox(message_id,chat_id,payload,received_at,"
            "next_attempt_at,status) VALUES(?,?,?,?,?,?)",
            (
                "order-other",
                "chat-other",
                payload("order-other", "chat-other"),
                3.0,
                3.0,
                "pending",
            ),
        )

    other = runner._claim_inbound(now=100.0)
    assert other is not None
    assert other["payload"]["message_id"] == "order-other"
    assert runner._finish_inbound(other, ok=True, now=100.0) is True
    assert runner._claim_inbound(now=101.0) is None

    before = runner._recovery_target_before_digest("inbox", "order-recovery")
    fields = {
        "decision_id": "b" * 64,
        "target_kind": "inbox",
        "target_key": "order-recovery",
        "expected_before_digest": before,
        "actor": "operator:order",
        "authorization": "c" * 64,
        "reason": "closed history must not block a later turn",
        "decided_at_ms": 15_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    runner._close_without_replay(request, closed_at_ms=15_001)
    later = runner._claim_inbound(now=102.0)
    assert later is not None
    assert later["payload"]["message_id"] == "order-later"


def test_feishu_runner_has_no_direct_recovery_route_cli_or_background_caller() -> None:
    source_path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_close_without_replay"
    ]
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        str(node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    source = source_path.read_text(encoding="utf-8")

    assert calls == []
    assert {"argparse", "click", "fastapi", "typer"}.isdisjoint(imports)
    assert "MaintenanceTicket" not in source
    assert "ApprovalStore" not in source


def test_feishu_sdk_logs_are_error_only_and_redacted_before_handlers(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    logger = logging.getLogger("nachuan-test-feishu-redaction")
    logger.handlers.clear()
    logger.propagate = False
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    logger.addHandler(handler)
    logger.addFilter(runner.FeishuSecretRedactionFilter())

    logger.error(
        "connected to wss://example.invalid/ws?access_key=access-secret"
        "&ticket=ticket-secret&token=token-secret app_secret=app-secret"
    )

    rendered = output.getvalue()
    assert "access-secret" not in rendered
    assert "ticket-secret" not in rendered
    assert "token-secret" not in rendered
    assert "app-secret" not in rendered
    assert rendered.count("[redacted]") == 4
    assert runner._install_lark_log_security().level == logging.ERROR


def test_feishu_agent_endpoint_receives_stable_chat_scoped_provider_message_key(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    captured: dict[str, object] = {}

    def fake_post(path, payload, timeout=300):
        captured.update(path=path, payload=payload, timeout=timeout)
        return {"reply": "ok"}

    monkeypatch.setattr(runner, "_post", fake_post)
    key = runner._feishu_idempotency_key("provider-message-1", "chat-a")
    assert key == runner._feishu_idempotency_key("provider-message-1", "chat-a")
    assert key != runner._feishu_idempotency_key("provider-message-1", "chat-b")
    assert key != runner._feishu_idempotency_key("provider-message-2", "chat-a")
    assert len(key) == len("fsmsg-v1:") + 64

    assert runner._agent_chat(
        "hello", "user-a", "chat-a", idempotency_key=key
    ) == {"reply": "ok"}
    assert captured["path"] == "/v1/agent/chat"
    assert captured["payload"]["channel"] == "feishu"
    assert captured["payload"]["idempotency_key"] == key
    assert captured["timeout"] == 90.0


def test_feishu_agent_without_operator_model_delegates_routing_to_gateway(
    monkeypatch,
) -> None:
    """A library default must not freeze an obsolete model into every Turn."""

    monkeypatch.delenv("FEISHU_MODEL", raising=False)
    monkeypatch.delenv("BRIDGE_MODEL", raising=False)
    runner = _load_state_runner_without_sdk(monkeypatch)
    assert runner.MODEL == ""
    captured: dict[str, object] = {}

    def fake_post(path, payload, timeout=300):
        captured.update(path=path, payload=payload, timeout=timeout)
        return {"reply": "ok"}

    monkeypatch.setattr(runner, "_post", fake_post)
    key = runner._feishu_idempotency_key("provider-message-route", "chat-route")

    assert runner._agent_chat(
        "hello", "user-route", "chat-route", idempotency_key=key
    ) == {"reply": "ok"}
    assert "model" not in captured["payload"]


def test_feishu_agent_authenticated_ready_no_model_is_one_local_terminal_reply(
    monkeypatch,
) -> None:
    from gateway.bridge_protocol import HEADER_REQUEST_NONCE, seal_response

    runner = _load_state_runner_without_sdk(monkeypatch)
    secret = "feishu-test-secret-" + ("s" * 48)
    monkeypatch.setattr(runner, "ENGINE_KEY", secret)

    class AuthenticatedReadinessError:
        def open(self, request, **_kwargs):
            headers = {
                str(name).lower(): str(value)
                for name, value in request.header_items()
            }
            sealed_body, sealed_headers = seal_response(
                secret=secret,
                channel="feishu",
                request_nonce=headers[HEADER_REQUEST_NONCE.lower()],
                status=503,
                body=b'{"detail":{"code":"ready_no_model","retryable":false}}',
            )
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                sealed_headers,
                io.BytesIO(sealed_body),
            )

    monkeypatch.setattr(runner, "_ENGINE_OPENER", AuthenticatedReadinessError())
    key = runner._feishu_idempotency_key("provider-message-ready", "chat-ready")

    result = runner._agent_chat(
        "hello", "user-ready", "chat-ready", idempotency_key=key
    )
    assert result["outcome"] == "ready_no_model"
    assert result["blocked"] is True
    assert "连接中心" in result["reply"]
    assert runner._ENGINE_READINESS_REASON == "ready_no_model"


def test_feishu_agent_retryable_readiness_error_remains_a_durable_failure(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)

    def retryable_readiness(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            runner.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(
                b'{"detail":{"code":"ready_no_model","retryable":true}}'
            ),
        )

    monkeypatch.setattr(runner, "_post", retryable_readiness)
    key = runner._feishu_idempotency_key("provider-message-retry", "chat-retry")

    with pytest.raises(urllib.error.HTTPError) as raised:
        runner._agent_chat("hello", "user-retry", "chat-retry", idempotency_key=key)
    assert raised.value.code == 503


def test_feishu_agent_oversized_readiness_error_remains_a_durable_failure(
    monkeypatch,
) -> None:
    runner = _load_runner()
    oversized = (
        b'{"detail":{"code":"ready_no_model","retryable":false}}'
        + (b" " * (64 * 1024))
    )

    def oversized_readiness(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            runner.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(oversized),
        )

    monkeypatch.setattr(runner, "_post", oversized_readiness)
    key = runner._feishu_idempotency_key("provider-message-large", "chat-large")

    with pytest.raises(urllib.error.HTTPError) as raised:
        runner._agent_chat("hello", "user-large", "chat-large", idempotency_key=key)
    assert raised.value.code == 503


def test_feishu_agent_requested_model_unavailable_is_a_local_terminal_reply(
    monkeypatch,
) -> None:
    runner = _load_runner()

    def requested_model_unavailable(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            runner.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(
                b'{"detail":{"code":"requested_model_unavailable",'
                b'"retryable":false}}'
            ),
        )

    monkeypatch.setattr(runner, "_post", requested_model_unavailable)
    key = runner._feishu_idempotency_key("provider-message-pinned", "chat-pinned")

    result = runner._agent_chat(
        "hello", "user-pinned", "chat-pinned", idempotency_key=key
    )
    assert result["outcome"] == "requested_model_unavailable"
    assert result["blocked"] is True
    assert "重新验证" in result["reply"]
    assert runner._ENGINE_READINESS_REASON == "requested_model_unavailable"


def test_feishu_agent_rejects_an_unsealed_local_readiness_503(monkeypatch) -> None:
    from gateway.bridge_protocol import BridgeProtocolError

    runner = _load_runner()
    monkeypatch.setattr(runner, "ENGINE_KEY", "unsealed-test-secret-" + ("s" * 48))

    class UnsealedReadinessError:
        def open(self, request, **_kwargs):
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                {},
                io.BytesIO(
                    b'{"detail":{"code":"ready_no_model","retryable":false}}'
                ),
            )

    monkeypatch.setattr(runner, "_ENGINE_OPENER", UnsealedReadinessError())
    key = runner._feishu_idempotency_key("provider-message-unsealed", "chat-unsealed")

    with pytest.raises(BridgeProtocolError):
        runner._agent_chat(
            "hello", "user-unsealed", "chat-unsealed", idempotency_key=key
        )


@pytest.mark.parametrize(
    ("status", "code"),
    [(503, "provider_busy"), (502, "ready_no_model")],
    ids=["unclassified-code", "wrong-status"],
)
def test_feishu_agent_only_accepts_whitelisted_503_readiness_errors(
    monkeypatch, status: int, code: str
) -> None:
    runner = _load_runner()

    def rejected_error(*_args, **_kwargs):
        body = json.dumps(
            {"detail": {"code": code, "retryable": False}}
        ).encode("utf-8")
        raise urllib.error.HTTPError(
            runner.ENGINE + "/v1/agent/chat",
            status,
            "synthetic",
            {},
            io.BytesIO(body),
        )

    monkeypatch.setattr(runner, "_post", rejected_error)
    key = runner._feishu_idempotency_key("provider-message-rejected", "chat-rejected")

    with pytest.raises(urllib.error.HTTPError) as raised:
        runner._agent_chat(
            "hello", "user-rejected", "chat-rejected", idempotency_key=key
        )
    assert raised.value.code == status


def test_feishu_ready_no_model_finishes_durable_inbox_and_outbox_once(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner, "_HEALTH_FILE", tmp_path / "feishu_bridge_health.json"
    )
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"user-ready"}), "owner-user"),
    )
    engine_calls = 0

    def no_model(*_args, **_kwargs):
        nonlocal engine_calls
        engine_calls += 1
        raise urllib.error.HTTPError(
            runner.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(
                b'{"detail":{"code":"ready_no_model","retryable":false}}'
            ),
        )

    monkeypatch.setattr(runner, "_post", no_model)
    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(json.loads(str(claim["content"]))["text"]),
    )
    payload = {
        "message_id": "ready-no-model-1",
        "chat_id": "chat-ready",
        "message_type": "text",
        "content": '{"text":"你好"}',
        "open_id": "user-ready",
    }
    assert runner._store_inbound(payload) is True

    stop = runner.threading.Event()
    original_finish = runner._finish_inbound

    def finish_once(claim, **kwargs):
        result = original_finish(claim, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(runner, "_finish_inbound", finish_once)
    runner._inbound_worker(stop)

    with runner._state_transaction() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_error FROM feishu_inbox"
        ).fetchone()
        deliveries = conn.execute(
            "SELECT delivery_uuid,status,attempts,content FROM feishu_outbox ORDER BY id"
        ).fetchall()
    assert inbound == ("done", 0, "")
    assert len(deliveries) == 1
    assert deliveries[0][1:3] == ("done", 0)
    assert "连接中心" in json.loads(deliveries[0][3])["text"]
    assert sent == [json.loads(deliveries[0][3])["text"]]
    assert not any("正在自动重试" in text for text in sent)

    assert runner._store_inbound(payload) is False
    assert runner._claim_inbound(now=time.time() + 60) is None
    assert engine_calls == 1


def test_feishu_slow_authorized_text_persists_progress_before_final_reply(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"slow-user"}), "owner-user"),
    )
    timers: list[object] = []

    class FakeTimer:
        def __init__(self, interval, function, args=None, kwargs=None):
            self.interval = interval
            self.function = function
            self.args = tuple(args or ())
            self.kwargs = dict(kwargs or {})
            self.daemon = False
            self.cancelled = False
            timers.append(self)

        def start(self):
            return None

        def cancel(self):
            self.cancelled = True

        def fire(self):
            if not self.cancelled:
                return self.function(*self.args, **self.kwargs)
            return None

    monkeypatch.setattr(runner.threading, "Timer", FakeTimer)

    def slow_agent(*_args, **_kwargs):
        assert len(timers) == 1
        timers[0].fire()
        return {"reply": "final reply"}

    monkeypatch.setattr(runner, "_agent_chat", slow_agent)
    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(json.loads(str(claim["content"]))["text"]),
    )
    message_id = "slow-authorized-message"
    assert runner._store_inbound(
        {
            "message_id": message_id,
            "chat_id": "slow-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "slow-user",
        }
    )
    stop = runner.threading.Event()
    original_finish = runner._finish_inbound

    def finish_once(claim, **kwargs):
        result = original_finish(claim, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(runner, "_finish_inbound", finish_once)
    runner._inbound_worker(stop)

    assert len(timers) == 1
    assert timers[0].interval == pytest.approx(30.0)
    with runner._state_connect() as conn:
        deliveries = conn.execute(
            "SELECT delivery_uuid,status,content FROM feishu_outbox ORDER BY id"
        ).fetchall()
    assert len(deliveries) == 2
    assert deliveries[0][0] == runner._stable_delivery_uuid(
        f"inbound:{message_id}:notice:progress"
    )
    assert "还在处理" in json.loads(deliveries[0][2])["text"]
    assert json.loads(deliveries[1][2])["text"] == "final reply"

    assert runner._drain_outbox(now=time.time() + 10, limit=10) == 2
    assert sent == [json.loads(row[2])["text"] for row in deliveries]


def test_feishu_fast_authorized_text_cancels_progress_before_callback(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"fast-user"}), "owner-user"),
    )
    timers: list[object] = []

    class FakeTimer:
        def __init__(self, interval, function, args=None, kwargs=None):
            self.interval = interval
            self.function = function
            self.args = tuple(args or ())
            self.kwargs = dict(kwargs or {})
            self.daemon = False
            self.cancelled = False
            timers.append(self)

        def start(self):
            return None

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(runner.threading, "Timer", FakeTimer)
    monkeypatch.setattr(
        runner, "_agent_chat", lambda *_args, **_kwargs: {"reply": "fast reply"}
    )
    monkeypatch.setattr(runner, "_send_outbox_claim", lambda _claim: None)
    message_id = "fast-authorized-message"
    assert runner._store_inbound(
        {
            "message_id": message_id,
            "chat_id": "fast-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "fast-user",
        }
    )
    stop = runner.threading.Event()
    original_finish = runner._finish_inbound

    def finish_once(claim, **kwargs):
        result = original_finish(claim, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(runner, "_finish_inbound", finish_once)
    runner._inbound_worker(stop)

    assert len(timers) == 1
    assert timers[0].cancelled is True
    # Simulate a Timer callback that was already dispatched when cancel won.
    timers[0].function(*timers[0].args, **timers[0].kwargs)
    with runner._state_connect() as conn:
        deliveries = conn.execute(
            "SELECT delivery_uuid,content FROM feishu_outbox ORDER BY id"
        ).fetchall()
    assert len(deliveries) == 1
    assert json.loads(deliveries[0][1])["text"] == "fast reply"
    assert deliveries[0][0] != runner._stable_delivery_uuid(
        f"inbound:{message_id}:notice:progress"
    )


def test_feishu_progress_timer_start_failure_does_not_fail_the_turn(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"timer-user"}), "owner-user"),
    )

    class BrokenTimer:
        def __init__(self, *_args, **_kwargs):
            self.daemon = False

        def start(self):
            raise RuntimeError("synthetic timer exhaustion")

        def cancel(self):
            return None

    monkeypatch.setattr(runner.threading, "Timer", BrokenTimer)
    agent_calls = 0

    def fast_agent(*_args, **_kwargs):
        nonlocal agent_calls
        agent_calls += 1
        return {"reply": "timer fallback reply"}

    monkeypatch.setattr(runner, "_agent_chat", fast_agent)
    monkeypatch.setattr(runner, "_send_outbox_claim", lambda _claim: None)
    assert runner._store_inbound(
        {
            "message_id": "timer-start-failure",
            "chat_id": "timer-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "timer-user",
        }
    )
    stop = runner.threading.Event()
    original_finish = runner._finish_inbound

    def finish_once(claim, **kwargs):
        result = original_finish(claim, **kwargs)
        stop.set()
        return result

    monkeypatch.setattr(runner, "_finish_inbound", finish_once)
    runner._inbound_worker(stop)

    with runner._state_connect() as conn:
        inbox = conn.execute(
            "SELECT status,attempts,last_error FROM feishu_inbox"
        ).fetchone()
        deliveries = conn.execute(
            "SELECT content FROM feishu_outbox ORDER BY id"
        ).fetchall()
    assert agent_calls == 1
    assert inbox == ("done", 0, "")
    assert [json.loads(row[0])["text"] for row in deliveries] == [
        "timer fallback reply"
    ]


def test_feishu_outbox_retries_business_failure_with_one_stable_body_uuid(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_HEALTH_FILE", tmp_path / "feishu_bridge_health.json")
    requests: list[object] = []
    outcomes = [False, True]

    def create(request):
        requests.append(request)
        ok = outcomes.pop(0)
        return SimpleNamespace(success=lambda: ok, code=230001 if not ok else 0, msg="synthetic")

    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(create=create)))
    )

    assert runner._reply("chat-1", "hello", delivery_key="turn-1:reply") is False
    assert runner._outbox_status_counts(("pending",)) == 1

    assert runner._drain_outbox(now=time.time() + 10, limit=10) == 1
    assert runner._outbox_status_counts(("pending", "processing")) == 0
    assert runner._outbox_status_counts(("done",)) == 1
    assert len(requests) == 2
    first_uuid = requests[0].request_body.uuid
    assert first_uuid == requests[1].request_body.uuid
    assert len(first_uuid) == 36


def test_feishu_inbox_deduplicates_and_claims_in_chat_order_after_recovery(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = time.time()
    first = {
        "message_id": "m-1",
        "chat_id": "chat-a",
        "message_type": "text",
        "content": '{"text":"one"}',
        "open_id": "user-a",
    }
    second = {**first, "message_id": "m-2", "content": '{"text":"two"}'}
    other = {
        **first,
        "message_id": "m-3",
        "chat_id": "chat-b",
        "content": '{"text":"other"}',
    }

    assert runner._store_inbound(first, now=now) is True
    assert runner._store_inbound(first, now=now) is False
    assert runner._store_inbound(second, now=now) is True
    assert runner._store_inbound(other, now=now) is True

    claim_one = runner._claim_inbound(now=now)
    assert claim_one["payload"]["message_id"] == "m-1"
    claim_other = runner._claim_inbound(now=now)
    assert claim_other["payload"]["message_id"] == "m-3"
    runner._finish_inbound(claim_one, ok=True, now=now)
    claim_two = runner._claim_inbound(now=now)
    assert claim_two["payload"]["message_id"] == "m-2"

    assert runner._recover_inflight() >= 2
    recovered = runner._claim_inbound(now=now)
    assert recovered["payload"]["message_id"] in {"m-2", "m-3"}


def test_feishu_first_failed_text_turn_retries_silently(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 1_700_000_000.0
    message_id = "provider-message-first-failure"
    assert runner._store_inbound(
        {
            "message_id": message_id,
            "chat_id": "chat-first-failure",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "user-first-failure",
        },
        now=now,
    )

    first_claim = runner._claim_inbound(now=now)
    assert runner._finish_inbound(
        first_claim, ok=False, error_code="TimeoutError", now=now
    )
    # A replayed stale completion cannot create a duplicate notice.
    assert not runner._finish_inbound(
        first_claim, ok=False, error_code="TimeoutError", now=now + 1
    )

    second_claim = runner._claim_inbound(now=now + 2)
    assert runner._finish_inbound(
        second_claim, ok=False, error_code="TimeoutError", now=now + 2
    )
    with runner._state_connect() as conn:
        deliveries = conn.execute(
            "SELECT delivery_uuid,chat_id,status,content FROM feishu_outbox ORDER BY id"
        ).fetchall()

    assert deliveries == []


def test_feishu_dead_text_turn_persists_terminal_notice_before_tombstone(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    current = 1_700_000_000.0
    message_id = "provider-message-terminal-failure"
    assert runner._store_inbound(
        {
            "message_id": message_id,
            "chat_id": "chat-terminal-failure",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "user-terminal-failure",
        },
        now=current,
    )

    terminal_claim = None
    for attempt in range(8):
        claim = runner._claim_inbound(now=current)
        assert claim["attempts"] == attempt
        assert runner._finish_inbound(
            claim, ok=False, error_code="TimeoutError", now=current
        )
        terminal_claim = claim
        current += 2 ** (attempt + 1)

    assert terminal_claim is not None
    assert not runner._finish_inbound(
        terminal_claim, ok=False, error_code="TimeoutError", now=current
    )
    with runner._state_connect() as conn:
        inbox = conn.execute(
            "SELECT status,attempts,chat_id,payload FROM feishu_inbox"
        ).fetchone()
        deliveries = conn.execute(
            "SELECT delivery_uuid,chat_id,status,content FROM feishu_outbox ORDER BY id"
        ).fetchall()

    assert inbox == (
        "dead",
        8,
        "",
        '{"state":"dead_tombstone","version":1}',
    )
    assert len(deliveries) == 1
    terminal = deliveries[0]
    assert terminal[:3] == (
        runner._stable_delivery_uuid(
            f"inbound:{message_id}:notice:terminal"
        ),
        "chat-terminal-failure",
        "pending",
    )
    assert "本次请求未完成" in json.loads(terminal[3])["text"]


def test_feishu_dead_tombstone_rolls_back_if_terminal_notice_cannot_persist(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 1)
    current = 1_700_000_000.0
    original_payload = {
        "message_id": "provider-message-atomic-terminal",
        "chat_id": "chat-atomic-terminal",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "user-atomic-terminal",
    }
    assert runner._store_inbound(original_payload, now=current)
    runner._enqueue_outbox(
        "unrelated-chat",
        "text",
        json.dumps({"text": "occupy capacity"}),
        delivery_key="unrelated-capacity-occupier",
    )

    terminal_claim = None
    for attempt in range(8):
        claim = runner._claim_inbound(now=current)
        assert claim["attempts"] == attempt
        if attempt == 7:
            terminal_claim = claim
            break
        assert runner._finish_inbound(
            claim, ok=False, error_code="TimeoutError", now=current
        )
        current += 2 ** (attempt + 1)

    assert terminal_claim is not None
    with pytest.raises(runner.FeishuQueueFull):
        runner._finish_inbound(
            terminal_claim, ok=False, error_code="TimeoutError", now=current
        )
    with runner._state_connect() as conn:
        inbox = conn.execute(
            "SELECT status,attempts,chat_id,payload,claim_token FROM feishu_inbox"
        ).fetchone()
        outbox_count = conn.execute("SELECT COUNT(*) FROM feishu_outbox").fetchone()[0]

    assert inbox[:3] == ("processing", 7, "chat-atomic-terminal")
    assert json.loads(inbox[3]) == original_payload
    assert inbox[4] == terminal_claim["claim_token"]
    assert outbox_count == 1

    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 2)
    assert runner._finish_inbound(
        terminal_claim, ok=False, error_code="TimeoutError", now=current
    )


def test_feishu_event_entry_only_persists_and_worker_pool_is_hard_bounded(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"user-durable"}), "owner-user"),
    )
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="m-durable",
                chat_id="chat-durable",
                message_type="text",
                content='{"text":"hello"}',
            ),
            sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="user-durable")),
        )
    )

    runner.on_message(event)
    runner.on_message(event)
    assert runner._inbox_status_counts(("pending",)) == 1

    created: list[object] = []

    class FakeThread:
        def __init__(self, *, target, args, name, daemon):
            self.target = target
            self.args = args
            self.name = name
            self.daemon = daemon
            self.started = False
            created.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(runner.threading, "Thread", FakeThread)
    workers = runner._start_inbound_workers(runner.threading.Event(), worker_count=999)
    assert len(workers) == 8
    assert all(worker.started and worker.daemon for worker in workers)


def test_feishu_inbox_capacity_failure_is_propagated_for_upstream_redelivery(
    monkeypatch,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"authorized-user"}), "owner-user"),
    )
    monkeypatch.setattr(
        runner,
        "_store_inbound",
        lambda _payload: (_ for _ in ()).throw(
            runner.FeishuQueueFull("synthetic inbox capacity")
        ),
    )
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="capacity-message",
                chat_id="capacity-chat",
                message_type="text",
                content='{"text":"hello"}',
            ),
            sender=SimpleNamespace(
                sender_id=SimpleNamespace(open_id="authorized-user")
            ),
        )
    )

    with pytest.raises(runner.FeishuQueueFull):
        runner.on_message(event)
    assert runner._HEALTH_STATE["service_state"] == "degraded"
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_capacity"


def test_feishu_unauthorized_messages_never_consume_inbound_queue_capacity(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_ACCESS_FILE", tmp_path / "missing-access.json")
    monkeypatch.setenv("NACHUAN_ENV", "production")
    ordinary = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="unauthorized-message",
                chat_id="untrusted-chat",
                message_type="text",
                content='{"text":"hello"}',
            ),
            sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="untrusted-user")),
        )
    )
    whoami = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="whoami-message",
                chat_id="untrusted-chat",
                message_type="text",
                content='{"text":"/whoami"}',
            ),
            sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="untrusted-user")),
        )
    )

    runner.on_message(ordinary)
    assert runner._inbox_status_counts(("pending",)) == 0
    runner.on_message(whoami)
    assert runner._inbox_status_counts(("pending",)) == 1


def test_feishu_unauthorized_text_gets_one_generic_rate_limited_access_guidance(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"secret-allowed-user"}), "secret-owner"),
    )
    def event(message_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            event=SimpleNamespace(
                message=SimpleNamespace(
                    message_id=message_id,
                    chat_id="untrusted-chat",
                    message_type="text",
                    content='{"text":"hello"}',
                ),
                sender=SimpleNamespace(
                    sender_id=SimpleNamespace(open_id="untrusted-user")
                ),
            )
        )

    runner.on_message(event("unauthorized-message-1"))
    runner.on_message(event("unauthorized-message-2"))
    assert runner._inbox_status_counts(("pending", "processing")) == 0

    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(json.loads(str(claim["content"]))["text"]),
    )
    assert runner._drain_outbox(now=time.time() + 10, limit=10) == 1
    assert len(sent) == 1
    assert "联系管理员" in sent[0]
    assert "/whoami" in sent[0]
    assert "白名单" not in sent[0]
    assert "secret-allowed-user" not in sent[0]
    assert "secret-owner" not in sent[0]


def test_feishu_state_database_has_byte_and_active_row_budgets(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_ROWS", 1)
    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 1)
    first = {
        "message_id": "message-1",
        "chat_id": "chat-1",
        "message_type": "text",
        "content": '{"text":"one"}',
        "open_id": "user-1",
    }
    second = {**first, "message_id": "message-2", "content": '{"text":"two"}'}

    assert runner._store_inbound(first)
    with pytest.raises(runner.FeishuQueueFull):
        runner._store_inbound(second)
    assert runner._store_inbound(first) is False
    inbound_claim = runner._claim_inbound(now=time.time() + 1.0)
    assert inbound_claim is not None
    with pytest.raises(runner.FeishuQueueFull):
        runner._store_inbound(second)

    runner._enqueue_outbox("chat-1", "text", '{"text":"one"}', delivery_key="one")
    with pytest.raises(runner.FeishuQueueFull):
        runner._enqueue_outbox("chat-1", "text", '{"text":"two"}', delivery_key="two")
    outbox_claim = runner._claim_outbox(now=time.time() + 1.0)
    assert outbox_claim is not None
    with pytest.raises(runner.FeishuQueueFull):
        runner._enqueue_outbox("chat-1", "text", '{"text":"two"}', delivery_key="two")

    with runner._state_connect() as conn:
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        max_pages = int(conn.execute("PRAGMA max_page_count").fetchone()[0])
        journal_limit = int(conn.execute("PRAGMA journal_size_limit").fetchone()[0])
        auto_checkpoint = int(conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0])
    assert max_pages * page_size <= runner._STATE_DB_MAX_BYTES
    assert 0 <= journal_limit <= runner._STATE_WAL_MAX_BYTES
    assert 1 <= auto_checkpoint <= runner._STATE_WAL_AUTOCHECKPOINT_PAGES


def test_feishu_schedules_are_fail_closed_instead_of_impersonating_owner(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setenv("NACHUAN_ENV", "production")
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"member-user"}), "owner-user"),
    )
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat_id, text, **_kwargs: replies.append(text) or True,
    )
    monkeypatch.setattr(
        runner,
        "_agent_chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("disabled schedule called model as owner")
        ),
    )
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="schedule-message",
                chat_id="team-chat",
                message_type="text",
                content='{"text":"/定时 09:00 总结新闻"}',
            ),
            sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="member-user")),
        )
    )

    runner._handle_message(event)
    assert replies and "未启用" in replies[-1]
    assert runner._schedule_worker() is None


def test_feishu_outbox_cannot_overtake_an_earlier_delivery_in_the_same_chat(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    first_uuid = runner._enqueue_outbox(
        "chat-a", "text", '{"text":"first"}', delivery_key="first"
    )
    runner._enqueue_outbox(
        "chat-a", "text", '{"text":"second"}', delivery_key="second"
    )
    runner._enqueue_outbox(
        "chat-b", "text", '{"text":"other"}', delivery_key="other"
    )
    claim_time = time.time() + 10

    first = runner._claim_outbox(now=claim_time)
    assert first["delivery_uuid"] == first_uuid
    runner._finish_outbox(first, ok=False, error_code="synthetic", now=claim_time)

    # The first chat is in backoff, so only another chat may make progress.
    other = runner._claim_outbox(now=claim_time + 1)
    assert other["chat_id"] == "chat-b"
    runner._finish_outbox(other, ok=True, now=claim_time + 1)
    assert runner._claim_outbox(now=claim_time + 1) is None

    retry = runner._claim_outbox(now=claim_time + 3)
    assert retry["delivery_uuid"] == first_uuid
    runner._finish_outbox(retry, ok=True, now=claim_time + 3)
    assert runner._claim_outbox(now=claim_time + 3)["content"] == '{"text":"second"}'


def test_feishu_terminal_rows_are_bounded_and_dead_payloads_are_tombstoned(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = time.time()
    inbound = {
        "message_id": "private-message-id",
        "chat_id": "private-chat-id",
        "message_type": "text",
        "content": '{"text":"private-body"}',
        "open_id": "private-open-id",
    }
    runner._store_inbound(inbound, now=now - 100)
    inbox_claim = runner._claim_inbound(now=now)
    inbox_claim["attempts"] = 7
    runner._finish_inbound(inbox_claim, ok=False, error_code="synthetic", now=now)

    runner._enqueue_outbox(
        "private-chat-id",
        "text",
        '{"text":"private-reply"}',
        delivery_key="private-delivery",
    )
    outbox_claim = runner._claim_outbox(now=now + 10)
    outbox_claim["attempts"] = 11
    runner._finish_outbox(outbox_claim, ok=False, error_code="synthetic", now=now + 10)

    runner._maintain_state(
        now=now + 11,
        done_ttl_seconds=10,
        dead_ttl_seconds=100,
        max_terminal_rows=10,
    )
    with runner._state_connect() as conn:
        inbox_row = conn.execute(
            "SELECT chat_id,payload,status FROM feishu_inbox"
        ).fetchone()
        outbox_row = conn.execute(
            "SELECT chat_id,content,status FROM feishu_outbox"
        ).fetchone()
    assert inbox_row == ("", '{"state":"dead_tombstone","version":1}', "dead")
    assert outbox_row == ("", '{"state":"dead_tombstone","version":1}', "dead")

    runner._maintain_state(
        now=now + 30,
        done_ttl_seconds=10,
        dead_ttl_seconds=10,
        max_terminal_rows=10,
    )
    assert runner._inbox_status_counts(("dead",)) == 0
    assert runner._outbox_status_counts(("dead",)) == 0


def test_feishu_health_is_atomic_secret_free_and_reports_supervisor_fields(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    health_path = tmp_path / "feishu_bridge_health.json"
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_HEALTH_FILE", health_path)
    monkeypatch.setattr(runner, "_ACCESS_FILE", tmp_path / "feishu_access.json")
    monkeypatch.setenv("NACHUAN_ENV", "production")
    now = time.time()

    runner._mark_connected(now=now)
    snapshot = runner._update_health(now=now)
    persisted = json.loads(health_path.read_text("utf-8"))
    assert persisted == snapshot
    assert snapshot["schema"] == "nachuan.feishu-bridge-health.v1"
    assert snapshot["connected"] is True
    assert snapshot["fresh"] is True
    assert snapshot["ready"] is False
    assert snapshot["access_configured"] is False
    assert snapshot["bridge_key_configured"] is False
    assert snapshot["engine_available"] is False
    assert snapshot["readiness_reasons"] == [
        "access_locked",
        "bridge_key_missing",
        "engine_unavailable",
    ]
    assert snapshot["pid"] == os.getpid()
    assert snapshot["pending_inbound"] == 0
    assert snapshot["recovery_required_inbound"] == 0
    assert snapshot["pending_outbound"] == 0
    assert snapshot["dead_inbound"] == 0
    assert snapshot["dead_outbound"] == 0
    assert snapshot["processing_inbound"] == 0
    assert snapshot["processing_outbound"] == 0
    assert snapshot["oldest_processing_age_seconds"] == 0
    assert snapshot["next_claim_expiry_seconds"] == 0
    assert snapshot["expired_claims"] == 0
    assert snapshot["processing_stuck"] == 0
    assert snapshot["consecutive_reconnect_failures"] == 0
    assert snapshot["last_connected_at"] == now
    assert not list(tmp_path.glob("*.tmp"))

    runner._ACCESS_FILE.write_text(
        json.dumps(
            {
                "schema": "nachuan.feishu-access.v1",
                "allowed_users": ["allowed-user"],
                "owner": "",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "ENGINE_KEY", "bridge-key")
    runner._set_engine_available(True)
    configured = runner._update_health(now=now + 0.5)
    assert configured["ready"] is True
    assert configured["access_configured"] is True
    assert configured["bridge_key_configured"] is True
    assert configured["engine_available"] is True
    assert configured["readiness_reasons"] == []

    runner._mark_disconnected("access_key=must-not-leak", now=now + 1)
    degraded = runner._update_health(now=now + 1)
    rendered = health_path.read_text("utf-8")
    assert degraded["connected"] is False
    assert degraded["ready"] is False
    assert degraded["consecutive_reconnect_failures"] == 1
    assert degraded["last_error_code"] == "connection_error"
    assert "must-not-leak" not in rendered


def test_feishu_engine_probe_is_bounded_authenticated_and_channel_exact(
    monkeypatch,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(runner, "MODEL", "")
    captured: dict[str, object] = {}
    body = {
        "value": (
            b'{"status":"ok","channel":"feishu","chat_ready":true,'
            b'"reason":"ready"}'
        )
    }

    def fake_request(opener, **kwargs):
        captured["opener"] = opener
        captured.update(kwargs)
        return body["value"]

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    assert runner._probe_engine_available(timeout=20) is True
    assert captured == {
        "opener": runner._ENGINE_OPENER,
        "url": f"{runner.ENGINE}/v1/bridge/health",
        "secret": "bridge-key",
        "channel": "feishu",
        "method": "GET",
        "body": b"",
        "timeout": 5.0,
        "max_response_bytes": 64 * 1024,
    }
    assert runner._ENGINE_AVAILABLE is True
    assert runner._ENGINE_READINESS_REASON == "ready"

    body["value"] = (
        b'{"status":"ok","channel":"weixin","chat_ready":true,'
        b'"reason":"ready"}'
    )
    assert runner._probe_engine_available() is False
    assert runner._ENGINE_AVAILABLE is False
    assert runner._ENGINE_READINESS_REASON == "engine_unavailable"

    body["value"] = b'{"status":"ok","channel":"feishu"}'
    assert runner._probe_engine_available() is False
    assert runner._ENGINE_AVAILABLE is False
    assert runner._ENGINE_READINESS_REASON == "engine_unavailable"

    body["value"] = (
        b'{"status":"ok","channel":"feishu","chat_ready":false,'
        b'"reason":"ready_no_model"}'
    )
    assert runner._probe_engine_available() is False
    assert runner._ENGINE_AVAILABLE is False
    assert runner._ENGINE_READINESS_REASON == "ready_no_model"


def test_feishu_engine_probe_binds_explicit_model_and_preserves_health_reason(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(runner, "MODEL", "retired/model")
    captured: dict[str, object] = {}

    def fake_request(_opener, **kwargs):
        captured.update(kwargs)
        return (
            b'{"status":"ok","channel":"feishu","chat_ready":false,'
            b'"reason":"requested_model_unavailable"}'
        )

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)

    assert runner._probe_engine_available() is False
    assert captured["url"] == (
        f"{runner.ENGINE}/v1/bridge/health?model=retired%2Fmodel"
    )
    assert runner._ENGINE_READINESS_REASON == "requested_model_unavailable"

    monkeypatch.setattr(runner, "_ACCESS_CONFIGURED", True)
    runner._mark_connected()
    snapshot = runner._health_snapshot()
    assert snapshot["engine_available"] is False
    assert snapshot["engine_readiness_reason"] == "requested_model_unavailable"
    assert "requested_model_unavailable" in snapshot["readiness_reasons"]
    assert "engine_unavailable" not in snapshot["readiness_reasons"]


def test_feishu_maintenance_refreshes_access_and_authenticated_engine_probe(
    monkeypatch,
) -> None:
    runner = _load_runner()
    calls: list[str] = []

    class OneCycle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _timeout):
            self.stopped = True
            return True

    for name in (
        "_observe_ws_connection",
        "_recover_stale_inflight",
        "_drain_outbox",
        "_feed_pending_videos",
        "_maintain_state",
    ):
        monkeypatch.setattr(runner, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(
        runner,
        "_refresh_runtime_readiness",
        lambda: calls.append("readiness"),
    )
    monkeypatch.setattr(
        runner,
        "_update_health",
        lambda **_kwargs: calls.append("health"),
    )

    runner._maintenance_worker(OneCycle())
    assert calls == ["readiness", "health"]


def test_feishu_video_pending_over_capacity_uses_fixed_workers_and_refills(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    monkeypatch.setattr(runner, "_VIDEO_QUEUE", queue.Queue(maxsize=64), raising=False)
    monkeypatch.setattr(runner, "_VIDEO_QUEUED", set(), raising=False)
    monkeypatch.setattr(runner, "_VIDEO_ACTIVE", set(), raising=False)
    pending = {
        f"task-{index:03d}": {"chat_id": f"chat-{index:03d}", "ts": float(index)}
        for index in range(80)
    }
    runner._pending_save(pending)

    assert runner._feed_pending_videos() == 64
    assert runner._VIDEO_QUEUE.qsize() == 64
    assert len(runner._VIDEO_QUEUED) == 64
    assert len(runner._pending_load()) == 80
    assert runner._feed_pending_videos() == 0  # task_id de-dupe + full queue

    processed: list[str] = []

    def complete_one(task_id: str, _chat_id: str) -> None:
        processed.append(task_id)
        runner._pending_remove(task_id)

    monkeypatch.setattr(runner, "_video_worker", complete_one)
    assert runner._run_one_video_queue_item(timeout=0) is True
    assert processed == ["task-000"]
    assert runner._feed_pending_videos() == 1
    assert runner._VIDEO_QUEUE.qsize() == 64
    assert "task-064" in runner._VIDEO_QUEUED

    created: list[object] = []

    class FakeThread:
        def __init__(self, *, target, args, name, daemon):
            self.target = target
            self.args = args
            self.name = name
            self.daemon = daemon
            self.started = False
            created.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(runner.threading, "Thread", FakeThread)
    workers = runner._start_video_workers(runner.threading.Event(), worker_count=999)
    assert len(workers) == 4
    assert all(worker.started and worker.daemon for worker in workers)


def test_feishu_pending_video_upload_unknown_is_durable_and_never_replayed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    runner._pending_add("task-upload-unknown", "chat-upload-unknown")
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner.time, "time", lambda: 10_000.0)
    monkeypatch.setattr(
        runner,
        "_get",
        lambda _path: {"status": "succeeded", "url": "https://media.example/video.mp4"},
    )
    monkeypatch.setattr(
        sys.modules["orchestrator.media"],
        "_find_media_url",
        lambda _value: "https://media.example/video.mp4",
    )
    downloads: list[str] = []
    uploads: list[bytes] = []
    sends: list[str] = []
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_download_url",
        lambda url, _kind: (downloads.append(url), b"video-bytes")[1],
    )

    def lose_upload_response(data: bytes, _name: str, _ftype: str) -> str:
        uploads.append(data)
        raise runner.FeishuMediaUploadOutcomeUnknown(
            "Feishu file upload outcome is unknown"
        )

    monkeypatch.setattr(runner, "_upload_file", lose_upload_response)
    monkeypatch.setattr(
        runner,
        "_send_video",
        lambda _chat, key, **_kwargs: (sends.append(key), True)[1],
    )
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat, text, **_kwargs: (replies.append(text), True)[1],
    )

    runner._video_worker("task-upload-unknown", "chat-upload-unknown")
    runner._video_worker("task-upload-unknown", "chat-upload-unknown")

    pending = runner._pending_load()
    operation = pending["task-upload-unknown"]
    assert operation["state"] == "recovery_required"
    assert operation["last_error"] == "upload_outcome_unknown"
    assert len(operation["upload_request_sha256"]) == 64
    assert operation["upload_started_at"] == 10_000.0
    assert downloads == ["https://media.example/video.mp4"]
    assert uploads == [b"video-bytes"]
    assert sends == []
    assert replies == []


def test_feishu_pending_video_reuses_confirmed_upload_after_restart(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    clock = [0.0]
    monkeypatch.setattr(runner.time, "time", lambda: clock[0])
    monkeypatch.setattr(
        runner.time,
        "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + max(2_000.0, seconds)),
    )
    runner._pending_save(
        {
            "task-upload-confirmed": {
                "chat_id": "chat-upload-confirmed",
                "ts": 9_000.0,
                "state": "upload_confirmed",
                "upload_request_sha256": "a" * 64,
                "upload_started_at": 9_001.0,
                "file_key": "durable-file-key",
                "last_error": "",
            }
        }
    )
    monkeypatch.setattr(
        runner,
        "_get",
        lambda _path: (_ for _ in ()).throw(AssertionError("polled provider again")),
    )
    monkeypatch.setattr(
        runner,
        "_download_url",
        lambda *_args: (_ for _ in ()).throw(AssertionError("downloaded media again")),
    )
    monkeypatch.setattr(
        runner,
        "_upload_file",
        lambda *_args: (_ for _ in ()).throw(AssertionError("uploaded media again")),
    )
    sends: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        runner,
        "_send_video",
        lambda chat, key, *, delivery_key: (
            sends.append((chat, key, delivery_key)),
            True,
        )[1],
    )

    runner._video_worker("task-upload-confirmed", "chat-upload-confirmed")

    assert sends == [
        (
            "chat-upload-confirmed",
            "durable-file-key",
            "video-task:task-upload-confirmed:media",
        )
    ]
    assert "task-upload-confirmed" not in runner._pending_load()


def test_feishu_pending_video_interrupted_upload_is_quarantined_before_feeder(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    monkeypatch.setattr(runner, "_VIDEO_QUEUE", queue.Queue(maxsize=64), raising=False)
    monkeypatch.setattr(runner, "_VIDEO_QUEUED", set(), raising=False)
    monkeypatch.setattr(runner, "_VIDEO_ACTIVE", set(), raising=False)
    runner._pending_save(
        {
            "task-interrupted-upload": {
                "chat_id": "chat-interrupted-upload",
                "ts": 8_000.0,
                "state": "upload_submitting",
                "upload_request_sha256": "b" * 64,
                "upload_started_at": 8_001.0,
                "file_key": "",
                "last_error": "",
            }
        }
    )

    assert runner._feed_pending_videos() == 0
    assert runner._VIDEO_QUEUE.qsize() == 0
    operation = runner._pending_load()["task-interrupted-upload"]
    assert operation["state"] == "recovery_required"
    assert operation["last_error"] == "upload_interrupted"


def test_feishu_pending_video_recovery_blocks_readiness(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    runner._pending_save(
        {
            "task-readiness-recovery": {
                "chat_id": "chat-readiness-recovery",
                "ts": 7_000.0,
                "state": "recovery_required",
                "upload_request_sha256": "c" * 64,
                "upload_started_at": 7_001.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            }
        }
    )
    monkeypatch.setattr(runner, "ENGINE_KEY", "configured-test-key")
    runner._ACCESS_CONFIGURED = True
    runner._ENGINE_AVAILABLE = True
    runner._ENGINE_READINESS_REASON = "ready"
    runner._HEALTH_STATE.update(
        {
            "connected": True,
            "service_state": "healthy",
            "consecutive_reconnect_failures": 0,
        }
    )

    health = runner._health_snapshot(now=7_010.0)

    assert health["ready"] is False
    assert health["recovery_required_video"] == 1
    assert "video_recovery_required" in health["readiness_reasons"]


def test_feishu_pending_video_corruption_fails_closed_without_rewrite(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    pending_path = tmp_path / "feishu_pending_videos.json"
    monkeypatch.setattr(runner, "_PENDING", pending_path)
    corrupt = b'{"task":{"chat_id":"chat","state":"future_state"}}'
    pending_path.write_bytes(corrupt)

    with pytest.raises(RuntimeError, match="state is invalid"):
        runner._pending_load()
    with pytest.raises(RuntimeError, match="state is invalid"):
        runner._feed_pending_videos()

    assert pending_path.read_bytes() == corrupt


def test_feishu_pending_video_state_migrates_from_json_to_sqlite_authority(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    legacy_path = tmp_path / "feishu_pending_videos.json"
    monkeypatch.setattr(runner, "_PENDING", legacy_path)
    legacy_path.write_text(
        json.dumps(
            {
                "legacy-video-task": {
                    "chat_id": "legacy-video-chat",
                    "ts": 123.0,
                    "state": "upload_submitting",
                    "upload_request_sha256": "d" * 64,
                    "upload_started_at": 124.0,
                    "file_key": "",
                    "last_error": "",
                }
            }
        ),
        encoding="utf-8",
    )

    migrated = runner._pending_load()

    assert migrated["legacy-video-task"]["state"] == "recovery_required"
    assert migrated["legacy-video-task"]["last_error"] == "upload_interrupted"
    assert not legacy_path.exists()
    state_path = runner._pending_state_db_path()
    assert state_path.read_bytes()[:16] == b"SQLite format 3\x00"
    with sqlite3.connect(state_path) as conn:
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0x4E435646
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 1


def test_feishu_pending_video_protected_close_is_atomic_chained_and_idempotent(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    runner._pending_save(
        {
            "video-target": {
                "chat_id": "video-recovery-chat",
                "ts": 200.0,
                "state": "recovery_required",
                "upload_request_sha256": "a" * 64,
                "upload_started_at": 201.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            },
            "video-same-chat": {
                "chat_id": "video-recovery-chat",
                "ts": 202.0,
                "state": "recovery_required",
                "upload_request_sha256": "b" * 64,
                "upload_started_at": 203.0,
                "file_key": "",
                "last_error": "upload_interrupted",
            },
            "video-other-chat": {
                "chat_id": "other-video-chat",
                "ts": 204.0,
                "state": "recovery_required",
                "upload_request_sha256": "c" * 64,
                "upload_started_at": 205.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            },
        }
    )
    snapshot = runner._recovery_target_snapshot("video", "video-target")
    assert snapshot["affected_counts"] == {"inbox": 0, "outbox": 0, "video": 2}
    fields = {
        "decision_id": "1" * 64,
        "target_kind": "video",
        "target_key": "video-target",
        "expected_before_digest": snapshot["expected_before_digest"],
        "actor": "approval-admin:authenticated",
        "authorization": "2" * 64,
        "reason": "operator verified no automatic replay",
        "decided_at_ms": 300_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )

    first = runner._close_without_replay(request, closed_at_ms=300_001)
    retry = runner._close_without_replay(request, closed_at_ms=300_002)

    assert first.applied is True
    assert first.affected_inbox_count == 0
    assert first.affected_outbox_count == 0
    assert first.affected_video_count == 2
    assert retry == first._replace(applied=False)
    assert set(runner._pending_load()) == {"video-other-chat"}
    with sqlite3.connect(runner._pending_state_db_path()) as conn:
        closed = tuple(
            conn.execute(
                "SELECT task_id,state,chat_id,terminal_verification "
                "FROM feishu_pending_video ORDER BY id"
            )
        )
        assert closed[:2] == (
            ("video-target", "closed", "", "closed_without_replay"),
            ("video-same-chat", "closed", "", "closed_without_replay"),
        )
        receipts = tuple(
            conn.execute(
                "SELECT id,previous_receipt_sha256,receipt_sha256 "
                "FROM feishu_pending_video_recovery_receipt ORDER BY id"
            )
        )
        assert len(receipts) == 1
        assert receipts[0][0] == 1
        assert receipts[0][1] == "0" * 64
        assert receipts[0][2] == first.receipt_sha256


def test_feishu_pending_video_close_response_loss_retry_does_not_reread_target(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    runner._pending_save(
        {
            "video-response-loss": {
                "chat_id": "video-response-loss-chat",
                "ts": 400.0,
                "state": "recovery_required",
                "upload_request_sha256": "d" * 64,
                "upload_started_at": 401.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            }
        }
    )
    before = runner._recovery_target_before_digest("video", "video-response-loss")
    fields = {
        "decision_id": "3" * 64,
        "target_kind": "video",
        "target_key": "video-response-loss",
        "expected_before_digest": before,
        "actor": "approval-admin:authenticated",
        "authorization": "4" * 64,
        "reason": "operator verified no automatic replay",
        "decided_at_ms": 500_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    first = runner._close_without_replay(request, closed_at_ms=500_001)
    monkeypatch.setattr(
        runner,
        "_pending_recovery_rows_in_transaction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("response-loss retry must not reread the closed video target")
        ),
    )

    retry = runner._close_without_replay(request, closed_at_ms=500_002)

    assert retry == first._replace(applied=False)


def test_feishu_pending_video_receipt_insert_failure_rolls_back_close(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_PENDING", tmp_path / "feishu_pending_videos.json")
    runner._pending_save(
        {
            "video-receipt-failure": {
                "chat_id": "video-receipt-failure-chat",
                "ts": 600.0,
                "state": "recovery_required",
                "upload_request_sha256": "e" * 64,
                "upload_started_at": 601.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            }
        }
    )
    before = runner._recovery_target_before_digest("video", "video-receipt-failure")
    fields = {
        "decision_id": "5" * 64,
        "target_kind": "video",
        "target_key": "video-receipt-failure",
        "expected_before_digest": before,
        "actor": "approval-admin:authenticated",
        "authorization": "6" * 64,
        "reason": "operator verified no automatic replay",
        "decided_at_ms": 700_000,
    }
    request = runner._FeishuCloseWithoutReplayRequest(
        operation_digest=runner._close_without_replay_operation_digest(**fields),
        **fields,
    )
    original_open = runner._open_pending_state

    def denied_receipt_connection():
        conn = original_open()

        def authorizer(action, arg1, _arg2, _db_name, _trigger_name):
            if (
                action == sqlite3.SQLITE_INSERT
                and arg1 == "feishu_pending_video_recovery_receipt"
            ):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorizer)
        return conn

    monkeypatch.setattr(runner, "_open_pending_state", denied_receipt_connection)
    with pytest.raises(sqlite3.DatabaseError):
        runner._close_without_replay(request, closed_at_ms=700_001)
    monkeypatch.setattr(runner, "_open_pending_state", original_open)

    assert runner._pending_load()["video-receipt-failure"]["state"] == (
        "recovery_required"
    )
    with sqlite3.connect(runner._pending_state_db_path()) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM feishu_pending_video_recovery_receipt"
        ).fetchone()[0] == 0


def test_feishu_reclaimed_claim_tokens_fence_late_inbox_and_outbox_finish(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 10.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 2.0)
    now = time.time() + 10
    runner._store_inbound(
        {
            "message_id": "fenced-message",
            "chat_id": "fenced-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "fenced-user",
        },
        now=now,
    )
    old_inbox = runner._claim_inbound(now=now)
    runner._enqueue_outbox(
        "fenced-chat",
        "text",
        '{"text":"reply"}',
        delivery_key="fenced-delivery",
    )
    old_outbox = runner._claim_outbox(now=now)
    assert old_inbox["claim_token"]
    assert old_outbox["claim_token"]

    assert runner._recover_stale_inflight(now=now + 11.99) == 0
    assert runner._recover_stale_inflight(now=now + 12.01) == 2
    new_inbox = runner._claim_inbound(now=now + 12.01)
    new_outbox = runner._claim_outbox(now=now + 12.01)
    assert new_inbox["claim_token"] != old_inbox["claim_token"]
    assert new_outbox["claim_token"] != old_outbox["claim_token"]
    assert new_inbox["claim_epoch"] == old_inbox["claim_epoch"] + 1
    assert new_outbox["claim_epoch"] == old_outbox["claim_epoch"] + 1

    assert runner._finish_inbound(old_inbox, ok=True, now=now + 12.02) is False
    assert runner._finish_outbox(old_outbox, ok=True, now=now + 12.02) is False
    with runner._state_connect() as conn:
        inbox = conn.execute(
            "SELECT status,claim_token FROM feishu_inbox"
        ).fetchone()
        outbox = conn.execute(
            "SELECT status,claim_token FROM feishu_outbox"
        ).fetchone()
    assert inbox == ("processing", new_inbox["claim_token"])
    assert outbox == ("processing", new_outbox["claim_token"])
    assert runner._finish_inbound(new_inbox, ok=True, now=now + 12.02) is True
    assert runner._finish_outbox(new_outbox, ok=True, now=now + 12.02) is True


def test_feishu_inbound_claim_has_bounded_renewable_deadline_and_expiry_fence(
    monkeypatch, tmp_path: Path
) -> None:
    """A deterministic policy clock, not wall time, defines lease ownership."""

    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 12.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 3.0)
    now = 10_000.0
    assert runner._store_inbound(
        {
            "message_id": "lease-message",
            "chat_id": "lease-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "lease-user",
        },
        now=now,
    )

    first = runner._claim_inbound(now=now)
    assert first["claim_deadline"] == now + 12.0
    assert first["claim_epoch"] == 1
    assert runner._heartbeat_claim("inbox", first, now=now + 8.0) is True
    assert first["claim_deadline"] == now + 20.0

    # The lease is already lost at its deadline even though reclaim waits for
    # a short grace period to avoid racing an on-time heartbeat transaction.
    assert runner._claim_is_current("inbox", first, now=now + 20.01) is False
    assert runner._recover_stale_inflight(now=now + 22.99) == 0
    assert runner._recover_stale_inflight(now=now + 23.01) == 1
    second = runner._claim_inbound(now=now + 23.01)
    assert second["claim_epoch"] == 2
    assert second["claim_token"] != first["claim_token"]
    assert runner._heartbeat_claim("inbox", first, now=now + 23.02) is False
    assert runner._finish_inbound(first, ok=True, now=now + 23.02) is False
    assert runner._finish_inbound(second, ok=True, now=now + 23.02) is True


def test_feishu_outbox_expired_worker_cannot_send_and_chat_order_survives_reclaim(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 1.0)
    now = 20_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    first_uuid = runner._enqueue_outbox(
        "chat-a", "text", '{"text":"first"}', delivery_key="lease-first"
    )
    runner._enqueue_outbox(
        "chat-a", "text", '{"text":"second"}', delivery_key="lease-second"
    )
    runner._enqueue_outbox(
        "chat-b", "text", '{"text":"other"}', delivery_key="lease-other"
    )
    old = runner._claim_outbox(now=now)
    other = runner._claim_outbox(now=now)
    assert old["delivery_uuid"] == first_uuid
    assert other["chat_id"] == "chat-b"  # unrelated chats remain concurrent
    assert runner._claim_outbox(now=now) is None  # second chat-a row cannot overtake

    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )
    assert runner._deliver_outbox_claim(old, now=now + 5.01) is False
    assert sent == []
    assert runner._finish_outbox(old, ok=True, now=now + 5.01) is False
    assert runner._recover_stale_inflight(now=now + 6.01) == 2

    replacement = runner._claim_outbox(now=now + 6.01)
    assert replacement["delivery_uuid"] == first_uuid
    assert replacement["claim_epoch"] == 2
    assert runner._deliver_outbox_claim(replacement, now=now + 6.02) is True
    assert sent == [first_uuid]
    assert runner._finish_outbox(replacement, ok=True, now=now + 6.02) is True
    assert runner._claim_outbox(now=now + 6.02)["content"] == '{"text":"second"}'


def test_feishu_outbox_shared_first_pulse_failure_never_sends(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 25_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    delivery_uuid = runner._enqueue_outbox(
        "first-pulse-chat",
        "text",
        '{"text":"must wait"}',
        delivery_key="shared-outbox-first-pulse",
    )
    sent: list[str] = []
    created: list[object] = []

    class FirstPulseFailure:
        def __init__(self) -> None:
            self.closed = 0

        def start(self) -> bool:
            return False

        def close(self) -> bool:
            self.closed += 1
            return False

    def build_session(claim, **_kwargs):
        assert claim["delivery_uuid"] == delivery_uuid
        session = FirstPulseFailure()
        created.append(session)
        return session

    monkeypatch.setattr(
        runner,
        "_new_outbox_claim_session",
        build_session,
        raising=False,
    )
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )

    assert runner._drain_outbox(now=now, limit=1) == 0
    assert sent == []
    assert len(created) == 1
    assert created[0].closed == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone()[0] == "processing"


def test_feishu_outbox_post_provider_lease_loss_is_sticky_and_never_finishes(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 27_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    delivery_uuid = runner._enqueue_outbox(
        "post-provider-chat",
        "text",
        '{"text":"send once"}',
        delivery_key="shared-outbox-post-provider-loss",
    )
    created: list[object] = []
    original_factory = runner._new_outbox_claim_session

    def build_session(claim, **kwargs):
        session = original_factory(claim, **kwargs)
        created.append(session)
        return session

    sent: list[str] = []
    original_heartbeat = runner._heartbeat_claim
    outbox_pulses = 0

    def lose_only_post_provider(kind, claim, *, now=None):
        nonlocal outbox_pulses
        if kind == "outbox":
            outbox_pulses += 1
            if outbox_pulses == 3:
                return False
        return original_heartbeat(kind, claim, now=now)

    monkeypatch.setattr(runner, "_new_outbox_claim_session", build_session)
    monkeypatch.setattr(runner, "_heartbeat_claim", lose_only_post_provider)
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )

    assert runner._drain_outbox(now=now, limit=1) == 0
    assert sent == [delivery_uuid]
    assert len(created) == 1
    assert created[0].lost is True
    assert created[0].before_provider() is False
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", "recovery_required")


def test_feishu_outbox_shared_session_freezes_finish_retry_policy(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_FINISH_RETRY_DELAYS_SECONDS", (0.0, 0.1, 0.2))
    policy_now = [28_000.0]
    monkeypatch.setattr(runner.time, "time", lambda: policy_now[0])
    runner._enqueue_outbox(
        "outbox-policy-chat",
        "text",
        '{"text":"freeze policy"}',
        delivery_key="shared-outbox-policy-freeze",
    )
    claim = runner._claim_outbox(now=policy_now[0])
    assert claim is not None
    original_finish = runner._finish_outbox
    calls = 0

    def transient_then_commit(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise sqlite3.OperationalError("synthetic transient outbox finish")
        return original_finish(*args, **kwargs)

    waits: list[float] = []

    def advance(delay: float) -> None:
        waits.append(delay)
        policy_now[0] += delay

    session = runner._new_outbox_claim_session(
        claim,
        clock=lambda: policy_now[0],
        wait=advance,
    )
    assert session.start() is True
    monkeypatch.setattr(runner, "_finish_outbox", transient_then_commit)
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 300.0)
    monkeypatch.setattr(runner, "_CLAIM_HEARTBEAT_SECONDS", 299.0)
    monkeypatch.setattr(runner, "_FINISH_RETRY_DELAYS_SECONDS", (0.0, 9.0))
    try:
        assert session.finish((True, "")) is True
    finally:
        session.close()

    assert calls == 3
    # Retry sleeping now belongs to the shared session's monotonic deadline;
    # the adapter's historical wall-clock wait seam must not reset that budget.
    assert waits == []
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox"
        ).fetchone() == ("done", "done")


def test_feishu_outbox_shared_session_close_is_bounded_and_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 1.0)
    monkeypatch.setattr(runner, "_CLAIM_HEARTBEAT_SECONDS", 0.25)
    now = 29_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    runner._enqueue_outbox(
        "outbox-stop-chat",
        "text",
        '{"text":"bounded close"}',
        delivery_key="shared-outbox-bounded-close",
    )
    claim = runner._claim_outbox(now=now)
    assert claim is not None
    entered = threading.Event()
    release = threading.Event()
    original_heartbeat = runner._heartbeat_claim
    calls = 0

    def block_second_heartbeat(kind, owned_claim, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_heartbeat(kind, owned_claim, **kwargs)
        entered.set()
        release.wait(3.0)
        return True

    monkeypatch.setattr(runner, "_heartbeat_claim", block_second_heartbeat)
    session = runner._new_outbox_claim_session(claim, clock=lambda: now)
    assert session.start() is True
    assert entered.wait(1.5), "outbox heartbeat never reached the blocking seam"

    started = time.monotonic()
    assert session.close() is False
    elapsed = time.monotonic() - started
    assert elapsed < 1.5
    assert session.lost is True
    assert runner._HEALTH_STATE["last_error_code"] == "outbox_heartbeat_stop_timeout"
    release.set()
    session.close()


def test_feishu_outbox_production_has_no_legacy_lease_lifecycle_references() -> None:
    runner = _load_runner()
    source = Path(runner.__file__).read_text(encoding="utf-8")

    assert "_OutboxClaimLeaseHeartbeat" not in source
    assert "_finish_outbox_with_retry" not in source
    assert "_finish_outbox_commit_confirmed_after_error" not in source


def test_feishu_outbox_commit_fence_loss_never_writes_done(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 29_500.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    delivery_uuid = runner._enqueue_outbox(
        "commit-fence-chat",
        "text",
        '{"text":"fence before finish"}',
        delivery_key="shared-outbox-commit-fence",
    )
    sent: list[str] = []
    created: list[object] = []

    class LoseAtCommit:
        lost = False

        def __init__(self) -> None:
            self.provider_checks = 0
            self.commit_checks = 0
            self.closed = 0

        def start(self) -> bool:
            return True

        def before_provider(self) -> bool:
            self.provider_checks += 1
            return True

        @contextmanager
        def commit_fence(self):
            self.commit_checks += 1
            self.lost = True
            raise runner.ClaimLeaseLost("synthetic commit fence loss")
            yield

        def finish(self, _outcome) -> bool:
            raise AssertionError("lost outbox claim must not attempt durable finish")

        def close(self) -> bool:
            self.closed += 1
            return False

    def build_session(claim, **_kwargs):
        assert claim["delivery_uuid"] == delivery_uuid
        session = LoseAtCommit()
        created.append(session)
        return session

    monkeypatch.setattr(runner, "_new_outbox_claim_session", build_session)
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )

    assert runner._drain_outbox(now=now, limit=1) == 0
    assert sent == []
    assert len(created) == 1
    assert created[0].provider_checks == 1
    assert created[0].commit_checks == 1
    assert created[0].closed == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("processing", "")


def test_feishu_outbox_finish_does_not_repeat_ownership_probe() -> None:
    runner = _load_runner()
    events: list[object] = []

    class OrderedSession:
        @contextmanager
        def commit_fence(self):
            raise AssertionError("shared finish already owns the local gate")
            yield

        def finish(self, outcome) -> bool:
            events.append(("finish", outcome))
            return True

    assert runner._finish_outbox_session(OrderedSession(), ok=True) is True
    assert events == [("finish", (True, ""))]


def test_feishu_outbox_submission_phase_commits_inside_fence_before_provider(
    monkeypatch,
) -> None:
    runner = _load_runner()
    events: list[object] = []

    class OrderedSession:
        def before_provider(self) -> bool:
            events.append("pulse")
            return True

        @contextmanager
        def commit_fence(self):
            events.append("fence_enter")
            try:
                yield
            finally:
                events.append("fence_exit")

    def begin_submission(_claim, *, now=None) -> bool:
        events.append(("submission_committed", now))
        return True

    monkeypatch.setattr(runner, "_begin_outbox_submission", begin_submission)
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda _claim: events.append("provider_called"),
    )

    assert runner._deliver_outbox_claim(
        {"id": 1, "claim_token": "token", "claim_epoch": 1},
        now=123.0,
        lease_session=OrderedSession(),
    ) is True
    assert events == [
        "pulse",
        "fence_enter",
        ("submission_committed", 123.0),
        "fence_exit",
        "provider_called",
        "pulse",
    ]


def test_feishu_outbox_shared_session_renews_and_finishes_submitting_phase(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_725.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "shared-submitting-chat",
        "text",
        '{"text":"shared lifecycle owns submitting"}',
        delivery_key="shared-submitting-lifecycle",
    )
    claim = runner._claim_outbox(now=base)
    assert claim is not None
    session = runner._new_outbox_claim_session(claim, clock=lambda: base)
    assert session.start() is True
    try:
        with session.commit_fence():
            assert runner._begin_outbox_submission(claim, now=base) is True
        assert runner._claim_is_current("outbox", claim, now=base) is True
        assert session.before_provider() is True
        assert runner._finish_outbox_session(session, ok=True) is True
    finally:
        session.close()

    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "done",
            claim["claim_token"],
            claim["claim_epoch"],
            "done",
        )


def test_feishu_outbox_old_submission_epoch_cannot_overwrite_retry_owner(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_740.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "submission-epoch-chat",
        "text",
        '{"text":"exact epoch ownership"}',
        delivery_key="submission-epoch-owner",
    )
    old_claim = runner._claim_outbox(now=base)
    assert old_claim is not None
    assert runner._begin_outbox_submission(old_claim, now=base) is True
    assert runner._finish_outbox(
        old_claim,
        ok=False,
        error_code="FeishuProviderRejected",
        now=base,
    ) is True

    new_claim = runner._claim_outbox(now=base + 2.0)
    assert new_claim is not None
    assert new_claim["claim_epoch"] == old_claim["claim_epoch"] + 1
    assert new_claim["claim_token"] != old_claim["claim_token"]
    assert runner._begin_outbox_submission(new_claim, now=base + 2.0) is True
    assert runner._quarantine_outbox_submission(
        old_claim,
        error_code="stale_old_worker",
        now=base + 2.0,
    ) is False
    assert runner._finish_outbox(old_claim, ok=True, now=base + 2.0) is False
    assert runner._finish_outbox(new_claim, ok=True, now=base + 2.0) is True

    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "done",
            new_claim["claim_token"],
            new_claim["claim_epoch"],
            "done",
        )


def test_feishu_outbox_expired_quarantine_stays_submitting_until_stale_recovery(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 1.0)
    base = 29_745.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "expired-quarantine-chat",
        "text",
        '{"text":"deadline equality loses ownership"}',
        delivery_key="expired-submission-quarantine",
    )
    claim = runner._claim_outbox(now=base)
    assert claim is not None
    assert runner._begin_outbox_submission(claim, now=base) is True

    assert runner._quarantine_outbox_submission(
        claim,
        error_code="post_provider_lease_lost",
        now=base + 5.0,
    ) is False
    assert runner._recover_stale_inflight(now=base + 5.99) == 0
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token,claim_epoch FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "submitting",
            claim["claim_token"],
            claim["claim_epoch"],
        )

    assert runner._recover_stale_inflight(now=base + 6.01) == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "recovery_required",
            claim["claim_token"],
            claim["claim_epoch"],
            "recovery_required",
        )


def test_feishu_outbox_unknown_provider_outcome_requires_recovery_and_never_replays(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_750.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "unknown-outcome-chat",
        "text",
        '{"text":"accepted but response was lost"}',
        delivery_key="provider-outcome-unknown",
    )
    provider_calls: list[str] = []

    def accepted_then_timeout(claim) -> None:
        provider_calls.append(str(claim["delivery_uuid"]))
        raise TimeoutError("synthetic response loss after provider acceptance")

    monkeypatch.setattr(runner, "_send_outbox_claim", accepted_then_timeout)

    assert runner._drain_outbox(now=base, limit=1) == 0
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", 0, "recovery_required")

    # A restart and an elapsed upstream deduplication window must not turn an
    # unknown provider result back into an automatic send.
    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=base + 7_200.0) == 0
    assert runner._drain_outbox(now=base + 7_200.0, limit=1) == 0
    assert provider_calls == [delivery_uuid]


def test_feishu_outbox_accepted_timeout_plus_post_pulse_loss_never_replays(
    monkeypatch, tmp_path: Path
) -> None:
    """The provider boundary remains single-submit even when both signals fail."""

    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_800.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "compound-loss-chat",
        "text",
        '{"text":"accepted, response lost, then lease lost"}',
        delivery_key="compound-provider-and-lease-loss",
    )
    provider_calls: list[str] = []

    def accepted_then_timeout(claim) -> None:
        provider_calls.append(str(claim["delivery_uuid"]))
        raise TimeoutError("synthetic accepted response loss")

    original_heartbeat = runner._heartbeat_claim
    outbox_pulses = 0

    def lose_only_post_provider(kind, claim, *, now=None):
        nonlocal outbox_pulses
        if kind == "outbox":
            outbox_pulses += 1
            if outbox_pulses == 3:
                return False
        return original_heartbeat(kind, claim, now=now)

    monkeypatch.setattr(runner, "_send_outbox_claim", accepted_then_timeout)
    monkeypatch.setattr(runner, "_heartbeat_claim", lose_only_post_provider)

    assert runner._drain_outbox(now=base, limit=1) == 0
    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=base + 7_200.0) == 0
    assert runner._drain_outbox(now=base + 7_200.0, limit=1) == 0
    assert provider_calls == [delivery_uuid]
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", "recovery_required")


def test_feishu_outbox_accepted_then_process_crash_isolated_on_restart(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_825.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "crash-after-accept-chat",
        "text",
        '{"text":"accepted before process crash"}',
        delivery_key="accepted-before-process-crash",
    )
    provider_calls: list[str] = []

    def accepted_then_process_dies(claim) -> None:
        provider_calls.append(str(claim["delivery_uuid"]))
        raise SystemExit("synthetic process death after provider acceptance")

    monkeypatch.setattr(runner, "_send_outbox_claim", accepted_then_process_dies)

    with pytest.raises(SystemExit, match="process death"):
        runner._drain_outbox(now=base, limit=1)
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("submitting",)

    assert runner._recover_inflight() == 1
    assert runner._drain_outbox(now=base + 1.0, limit=1) == 0
    assert provider_calls == [delivery_uuid]
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", "recovery_required")


def test_feishu_outbox_crash_before_provider_call_stays_isolated_past_two_hours(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 30.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 5.0)
    base = 29_850.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "crash-before-call-chat",
        "text",
        '{"text":"submission phase committed before provider call"}',
        delivery_key="crash-before-provider-call",
    )
    wrapper_entries = 0
    provider_calls: list[str] = []

    def process_dies_before_provider_call(_claim) -> None:
        nonlocal wrapper_entries
        wrapper_entries += 1
        raise SystemExit("synthetic death before provider call")
        provider_calls.append("unreachable")

    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        process_dies_before_provider_call,
    )

    with pytest.raises(SystemExit, match="before provider call"):
        runner._drain_outbox(now=base, limit=1)
    assert wrapper_entries == 1
    assert provider_calls == []
    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 1)
    with pytest.raises(runner.FeishuQueueFull, match="queue is full"):
        runner._enqueue_outbox(
            "another-chat",
            "text",
            '{"text":"submitting rows consume capacity"}',
            delivery_key="submitting-capacity-block",
        )
    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 10)
    runner._enqueue_outbox(
        "crash-before-call-chat",
        "text",
        '{"text":"must not overtake a submitting predecessor"}',
        delivery_key="submitting-chat-order-block",
    )
    assert runner._claim_outbox(now=base) is None
    health = runner._health_snapshot(now=base)
    assert health["pending_outbound"] == 2
    assert "pending_outbound" in health["readiness_reasons"]
    runner._record_claim_health("outbox_heartbeat_lost")
    assert runner._claim_failure_still_active("outbox_heartbeat_lost") is True
    runner._maintain_state(
        now=base + 7_200.0,
        done_ttl_seconds=0,
        dead_ttl_seconds=0,
        max_terminal_rows=0,
    )
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("submitting",)

    assert runner._recover_stale_inflight(now=base + 7_200.0) == 1
    assert runner._recover_inflight() == 0
    assert runner._drain_outbox(now=base + 7_200.0, limit=1) == 0
    assert wrapper_entries == 1
    assert provider_calls == []
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", "recovery_required")


@pytest.mark.parametrize(
    "failure_kind", ["transport", "response_parse", "rejection_parse"]
)
def test_feishu_outbox_sdk_uncertainty_is_classified_as_unknown_provider_outcome(
    failure_kind: str,
) -> None:
    runner = _load_runner()

    class UnreadableResponse:
        @staticmethod
        def success() -> bool:
            raise ValueError("synthetic response parse failure")

    class UnreadableRejection:
        @staticmethod
        def success() -> bool:
            return False

        @property
        def code(self):
            raise ValueError("synthetic rejection code parse failure")

    def create(_request):
        if failure_kind == "transport":
            raise TimeoutError("synthetic transport response loss")
        if failure_kind == "rejection_parse":
            return UnreadableRejection()
        return UnreadableResponse()

    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(create=create)))
    )
    claim = {
        "chat_id": "sdk-uncertainty-chat",
        "msg_type": "text",
        "content": '{"text":"uncertain"}',
        "delivery_uuid": "f35af4fc-a1ba-4a60-85c4-5478f094cb2d",
    }

    with pytest.raises(runner.FeishuProviderOutcomeUnknown, match="outcome is unknown"):
        runner._send_outbox_claim(claim)


@pytest.mark.parametrize("ambiguous_code", [None, 0, True, False, -1, "7", ""])
def test_feishu_outbox_ambiguous_business_codes_are_unknown(
    ambiguous_code,
) -> None:
    runner = _load_runner()

    class AmbiguousResponse:
        code = ambiguous_code

        @staticmethod
        def success() -> bool:
            return False

    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(
            v1=SimpleNamespace(
                message=SimpleNamespace(create=lambda _request: AmbiguousResponse())
            )
        )
    )
    claim = {
        "chat_id": "ambiguous-business-code-chat",
        "msg_type": "text",
        "content": '{"text":"do not infer a rejection"}',
        "delivery_uuid": "6c53480e-c49d-4712-a3ea-84cd07c50221",
    }

    with pytest.raises(runner.FeishuProviderOutcomeUnknown, match="outcome is unknown"):
        runner._send_outbox_claim(claim)


def test_feishu_outbox_ambiguous_code_is_quarantined_without_retry(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_900.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "ambiguous-code-no-retry-chat",
        "text",
        '{"text":"never infer retryability"}',
        delivery_key="ambiguous-code-no-retry",
    )
    provider_calls = 0

    class AmbiguousResponse:
        code = 0

        @staticmethod
        def success() -> bool:
            return False

    def create(_request):
        nonlocal provider_calls
        provider_calls += 1
        return AmbiguousResponse()

    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(create=create)))
    )

    assert runner._drain_outbox(now=base, limit=1) == 0
    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=base + 7_200.0) == 0
    assert runner._drain_outbox(now=base + 7_200.0, limit=1) == 0
    assert provider_calls == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required", 0, "recovery_required")


def test_feishu_outbox_explicit_positive_business_code_retries_by_policy(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_950.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "explicit-rejection-retry-chat",
        "text",
        '{"text":"retry only after a proven rejection"}',
        delivery_key="explicit-positive-business-rejection",
    )
    provider_calls = 0

    class ExplicitRejection:
        code = 230_001

        @staticmethod
        def success() -> bool:
            return False

    class Success:
        code = 0

        @staticmethod
        def success() -> bool:
            return True

    def create(_request):
        nonlocal provider_calls
        provider_calls += 1
        return ExplicitRejection() if provider_calls == 1 else Success()

    runner._api["c"] = SimpleNamespace(
        im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(create=create)))
    )

    assert runner._drain_outbox(now=base, limit=1) == 0
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome,next_attempt_at "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("pending", 1, "retry", base + 2.0)

    assert runner._drain_outbox(now=base + 2.0, limit=1) == 1
    assert provider_calls == 2
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome FROM feishu_outbox "
            "WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("done", 1, "done")


def test_feishu_outbox_recovery_receipt_confirms_response_loss_and_fences_old_worker(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_875.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "recovery-receipt-chat",
        "text",
        '{"text":"unknown delivery receipt"}',
        delivery_key="provider-outcome-unknown-receipt",
    )
    claim = runner._claim_outbox(now=base)
    assert claim is not None
    session = runner._new_outbox_claim_session(claim, clock=lambda: base)
    assert session.start() is True
    original_finish = runner._finish_outbox
    original_confirm = runner._finish_was_committed
    finish_calls = 0
    observed_deadlines: dict[str, float] = {}

    def commit_then_lose_response(*args, deadline_monotonic, **kwargs):
        nonlocal finish_calls
        finish_calls += 1
        observed_deadlines["finish"] = deadline_monotonic
        assert original_finish(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        ) is True
        raise sqlite3.OperationalError("synthetic recovery response loss")

    def confirm_after_response_loss(
        *args, deadline_monotonic, **kwargs
    ) -> bool:
        observed_deadlines["confirm"] = deadline_monotonic
        return original_confirm(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        )

    monkeypatch.setattr(runner, "_finish_outbox", commit_then_lose_response)
    monkeypatch.setattr(runner, "_finish_was_committed", confirm_after_response_loss)
    try:
        assert runner._finish_outbox_session(
            session,
            ok=False,
            error_code="provider_outcome_unknown",
            recovery_required=True,
        ) is True
    finally:
        session.close()

    assert finish_calls == 1
    assert observed_deadlines["finish"] == observed_deadlines["confirm"]
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "recovery_required",
            claim["claim_token"],
            claim["claim_epoch"],
            "recovery_required",
        )
    assert original_finish(claim, ok=True, now=base) is False


def test_feishu_outbox_recovery_required_blocks_capacity_chat_order_and_health(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 29_925.0
    monkeypatch.setattr(runner.time, "time", lambda: base)
    delivery_uuid = runner._enqueue_outbox(
        "blocked-chat",
        "text",
        '{"text":"manual recovery required"}',
        delivery_key="recovery-blocker",
    )
    claim = runner._claim_outbox(now=base)
    assert claim is not None
    assert runner._finish_outbox(
        claim,
        ok=False,
        error_code="provider_outcome_unknown",
        recovery_required=True,
        now=base,
    ) is True

    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 1)
    with pytest.raises(runner.FeishuQueueFull, match="queue is full"):
        runner._enqueue_outbox(
            "another-chat",
            "text",
            '{"text":"must not bypass recovery capacity"}',
            delivery_key="recovery-capacity-bypass",
        )

    monkeypatch.setattr(runner, "_MAX_ACTIVE_OUTBOUND_ROWS", 10)
    runner._enqueue_outbox(
        "blocked-chat",
        "text",
        '{"text":"must not overtake unknown predecessor"}',
        delivery_key="recovery-chat-order",
    )
    assert runner._claim_outbox(now=base) is None

    health = runner._health_snapshot(now=base)
    assert health["pending_outbound"] == 2
    assert "pending_outbound" in health["readiness_reasons"]
    runner._record_claim_health("outbox_recovery_required")
    assert runner._claim_failure_still_active("outbox_recovery_required") is True
    runner._maintain_state(
        now=base + 365 * 24 * 60 * 60,
        done_ttl_seconds=0,
        dead_ttl_seconds=0,
        max_terminal_rows=0,
    )
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == ("recovery_required",)


def test_feishu_finish_response_loss_is_confirmed_without_waiting_for_reclaim(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 30_000.0
    assert runner._store_inbound(
        {
            "message_id": "finish-response-loss",
            "chat_id": "finish-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-user",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)
    original_finish = runner._finish_inbound
    calls = 0

    def commit_then_lose_response(*args, **kwargs):
        nonlocal calls
        calls += 1
        assert original_finish(*args, **kwargs) is True
        raise sqlite3.OperationalError("synthetic response loss")

    waits: list[float] = []
    session = runner._new_inbound_claim_session(
        claim,
        clock=lambda: now + 1.0,
        wait=waits.append,
    )
    assert session.start() is True
    monkeypatch.setattr(runner, "_finish_inbound", commit_then_lose_response)
    try:
        assert session.finish((True, "")) is True
    finally:
        session.close()
    assert calls == 1
    assert waits == []
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_inbox"
        ).fetchone() == ("done", "done")
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_finish_storage_retry"


def test_feishu_finish_and_response_loss_confirmation_share_one_deadline(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 30_500.0
    assert runner._store_inbound(
        {
            "message_id": "finish-one-deadline",
            "chat_id": "finish-one-deadline-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-one-deadline-user",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)
    assert claim is not None
    original_finish = runner._finish_inbound
    original_confirm = runner._finish_was_committed
    observed: dict[str, float] = {}

    def commit_then_lose_response(*args, deadline_monotonic, **kwargs):
        observed["finish"] = deadline_monotonic
        assert original_finish(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        ) is True
        raise sqlite3.OperationalError("synthetic response loss")

    def confirm_after_response_loss(
        *args, deadline_monotonic, **kwargs
    ) -> bool:
        observed["confirm"] = deadline_monotonic
        return original_confirm(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        )

    monkeypatch.setattr(runner, "_finish_inbound", commit_then_lose_response)
    monkeypatch.setattr(runner, "_finish_was_committed", confirm_after_response_loss)
    session = runner._new_inbound_claim_session(claim, clock=lambda: now + 1.0)
    assert session.start() is True
    started = time.monotonic()
    try:
        assert session.finish((True, "")) is True
    finally:
        session.close()

    assert observed["finish"] == observed["confirm"]
    assert started + 7.0 < observed["finish"] <= started + 8.0


def test_feishu_finish_begin_busy_obeys_total_wallclock(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 1.0)
    now = 31_000.0
    assert runner._store_inbound(
        {
            "message_id": "finish-begin-busy",
            "chat_id": "finish-begin-busy-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-begin-busy-user",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)
    assert claim is not None
    session = runner._new_inbound_claim_session(claim, clock=lambda: now + 0.1)
    assert session.start() is True
    blocker = sqlite3.connect(runner._STATE_DB, timeout=0)
    try:
        blocker.execute("PRAGMA busy_timeout=0")
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        assert session.finish((True, "")) is False
        elapsed = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()
        session.close()

    assert elapsed < 0.75
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM feishu_inbox"
        ).fetchone() == ("processing", "")


def test_feishu_finish_returning_true_at_deadline_is_rejected(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 1.0)
    now = 31_500.0
    assert runner._store_inbound(
        {
            "message_id": "finish-late-true",
            "chat_id": "finish-late-true-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-late-true-user",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)
    assert claim is not None
    session = runner._new_inbound_claim_session(claim, clock=lambda: now + 0.1)
    assert session.start() is True
    observed_deadlines: list[float] = []

    def late_true(*_args, deadline_monotonic, **_kwargs) -> bool:
        observed_deadlines.append(deadline_monotonic)
        remaining = deadline_monotonic - time.monotonic()
        if remaining > 0:
            threading.Event().wait(remaining)
        return True

    monkeypatch.setattr(runner, "_finish_inbound", late_true)
    started = time.monotonic()
    try:
        assert session.finish((True, "")) is False
        elapsed = time.monotonic() - started
    finally:
        session.close()

    assert len(observed_deadlines) == 1
    assert elapsed < 0.75
    # The adapter's post-return deadline check rejects the late True before it
    # escapes to the shared coordinator, so this is a storage timeout rather
    # than a healthy commit acknowledgement.
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_finish_storage_timeout"


def test_feishu_storage_rechecks_deadline_after_finish_and_confirmation_return(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    claim = {
        "id": 1,
        "attempts": 0,
        "claim_token": "deadline-storage-token",
        "claim_epoch": 1,
    }
    monkeypatch.setattr(runner, "_finish_outbox", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        runner,
        "_finish_was_committed",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(runner.time, "monotonic", lambda: 42.0)
    storage = runner._FeishuOutboxClaimStorage(claim)

    with pytest.raises(sqlite3.OperationalError, match="deadline exceeded"):
        storage.finish_before((True, ""), deadline_monotonic=42.0)
    with pytest.raises(sqlite3.OperationalError, match="deadline exceeded"):
        storage.confirm_finish_before((True, ""), deadline_monotonic=42.0)


def test_feishu_finish_fault_projection_never_waits_for_health_lock() -> None:
    runner = _load_runner()
    locked = threading.Event()
    release = threading.Event()

    def hold_health_lock() -> None:
        with runner._HEALTH_LOCK:
            locked.set()
            assert release.wait(1.0)

    holder = threading.Thread(target=hold_health_lock, daemon=True)
    holder.start()
    assert locked.wait(1.0)
    started = time.monotonic()
    try:
        for policy in (
            runner._FeishuInboxClaimPolicy(),
            runner._FeishuOutboxClaimPolicy(),
        ):
            for code in (
                "finish_gate_timeout",
                "finish_heartbeat_stop_after_deadline",
                "finish_commit_after_deadline",
                "finish_confirmation_after_deadline",
            ):
                policy.fault(code)
    finally:
        elapsed = time.monotonic() - started
        release.set()
        holder.join(timeout=1.0)

    assert not holder.is_alive()
    assert elapsed < 0.2


def test_feishu_deadline_transaction_constrains_busy_timeout_before_commit(
    monkeypatch,
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    events: list[str] = []

    class DeadlineConnection:
        def __enter__(self):
            events.append("enter")
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback
            events.append("commit")
            return False

        def execute(self, sql: str):
            events.append(sql)
            return SimpleNamespace()

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(
        runner,
        "_state_connect",
        lambda **_kwargs: DeadlineConnection(),
    )
    deadline = time.monotonic() + 1.0
    with runner._state_transaction(deadline_monotonic=deadline):
        events.append("body")

    busy_indexes = [
        index
        for index, event in enumerate(events)
        if event.startswith("PRAGMA busy_timeout=")
    ]
    assert busy_indexes
    assert busy_indexes[-1] < events.index("commit") < events.index("close")


def test_feishu_shared_inbox_finish_freezes_bounded_retry_policy(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_FINISH_RETRY_DELAYS_SECONDS", (0.0, 0.1, 0.2))
    policy_now = [35_000.0]
    assert runner._store_inbound(
        {
            "message_id": "finish-transient",
            "chat_id": "finish-transient-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-transient-user",
        },
        now=policy_now[0],
    )
    claim = runner._claim_inbound(now=policy_now[0])
    original_finish = runner._finish_inbound
    calls = 0

    def transient_then_commit(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise sqlite3.OperationalError("synthetic transient finish")
        return original_finish(*args, **kwargs)

    waits: list[float] = []

    def advance(delay: float) -> None:
        waits.append(delay)
        policy_now[0] += delay

    session = runner._new_inbound_claim_session(
        claim,
        clock=lambda: policy_now[0],
        wait=advance,
    )
    assert session.start() is True
    monkeypatch.setattr(runner, "_finish_inbound", transient_then_commit)
    # A running claim freezes the policy it started with.  Later mutable module
    # configuration must not stretch this worker's recovery window.
    monkeypatch.setattr(runner, "_FINISH_RETRY_DELAYS_SECONDS", (0.0, 9.0))
    try:
        assert session.finish((True, "")) is True
    finally:
        session.close()
    assert calls == 3
    assert waits == []
    with runner._state_connect() as conn:
        assert conn.execute("SELECT status FROM feishu_inbox").fetchone() == (
            "done",
        )


def test_feishu_shared_inbox_finish_retry_exhaustion_preserves_claim_for_recovery(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(runner, "_FINISH_RETRY_DELAYS_SECONDS", (0.0, 0.1, 0.2))
    policy_now = [36_000.0]
    assert runner._store_inbound(
        {
            "message_id": "finish-stuck",
            "chat_id": "finish-stuck-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "finish-stuck-user",
        },
        now=policy_now[0],
    )
    claim = runner._claim_inbound(now=policy_now[0])
    waits: list[float] = []

    def advance(delay: float) -> None:
        waits.append(delay)
        policy_now[0] += delay

    monkeypatch.setattr(
        runner,
        "_finish_inbound",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("synthetic persistent finish outage")
        ),
    )
    monkeypatch.setattr(
        runner,
        "_finish_was_committed",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("synthetic confirmation outage")
        ),
    )
    session = runner._new_inbound_claim_session(
        claim,
        clock=lambda: policy_now[0],
        wait=advance,
    )
    assert session.start() is True
    try:
        assert session.finish((True, "")) is False
    finally:
        session.close()
    assert waits == []
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_finish_storage_stuck"
    with runner._state_connect() as conn:
        assert conn.execute("SELECT status FROM feishu_inbox").fetchone() == (
            "processing",
        )
    assert runner._recover_stale_inflight(now=36_005.99) == 0
    assert runner._recover_stale_inflight(now=36_006.01) == 1
    replacement = runner._claim_inbound(now=36_006.01)
    assert replacement["claim_epoch"] == 2


def test_feishu_maintenance_does_not_clear_live_claim_storage_failure(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 37_000.0
    assert runner._store_inbound(
        {
            "message_id": "health-stuck",
            "chat_id": "health-stuck-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "health-stuck-user",
        },
        now=now,
    )
    runner._claim_inbound(now=now)
    runner._mark_connected(now=now)
    runner._record_claim_health("inbox_finish_storage_stuck")
    monkeypatch.setattr(runner.time, "time", lambda: now + 1.0)

    class OneCycle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    for name in (
        "_observe_ws_connection",
        "_refresh_runtime_readiness",
        "_drain_outbox",
        "_feed_pending_videos",
        "_maintain_state",
        "_update_health",
    ):
        monkeypatch.setattr(runner, name, lambda *args, **kwargs: None)
    runner._maintenance_worker(OneCycle())
    assert runner._HEALTH_STATE["service_state"] == "degraded"
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_finish_storage_stuck"


def test_feishu_sqlite_lock_wait_is_bounded_by_the_real_claim_ttl(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 4.0)
    with runner._state_connect() as conn:
        busy_timeout_ms = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    assert 1 <= busy_timeout_ms <= 1_000


def test_feishu_heartbeat_rechecks_deadline_after_transaction_lock_wait(
    monkeypatch,
) -> None:
    """A pre-lock clock sample must not resurrect a lease after lock wait."""

    runner = _load_runner()
    policy_now = [80_004.0]
    claim = {
        "id": 1,
        "claim_token": "lock-wait-token",
        "claim_epoch": 7,
        "claim_deadline": 80_005.0,
    }
    transaction_entered = threading.Event()
    release_transaction = threading.Event()
    observed_where_now: list[float] = []

    class ExecuteResult:
        def __init__(self, rowcount: int) -> None:
            self.rowcount = rowcount

    class FenceConnection:
        def execute(
            self, sql: str, params: tuple[object, ...] = ()
        ) -> ExecuteResult:
            if sql == "BEGIN IMMEDIATE":
                transaction_entered.set()
                assert release_transaction.wait(1.0), "test transaction was not released"
                return ExecuteResult(0)
            # The legacy implementation lets the UPDATE itself acquire the
            # writer lock.  Its parameters have already captured the stale
            # clock by then, so delay that first write as the real SQLite call
            # would and expose the old WHERE value below.
            if not transaction_entered.is_set():
                transaction_entered.set()
                assert release_transaction.wait(1.0), "test transaction was not released"
            where_now = float(params[-1])
            observed_where_now.append(where_now)
            still_owned = where_now <= float(claim["claim_deadline"])
            return ExecuteResult(1 if still_owned else 0)

    @contextmanager
    def delayed_transaction():
        yield FenceConnection()

    monkeypatch.setattr(runner.time, "time", lambda: policy_now[0])
    monkeypatch.setattr(runner, "_state_transaction", delayed_transaction)
    result: list[bool] = []
    errors: list[BaseException] = []

    def heartbeat() -> None:
        try:
            result.append(runner._heartbeat_claim("inbox", claim))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=heartbeat, daemon=True)
    worker.start()
    assert transaction_entered.wait(1.0), "heartbeat did not reach transaction seam"
    policy_now[0] = 80_006.0
    release_transaction.set()
    worker.join(timeout=1.0)

    assert not worker.is_alive(), "heartbeat remained blocked"
    assert errors == []
    assert observed_where_now == [80_006.0]
    assert result == [False]


def test_feishu_claim_deadline_is_exclusive_at_every_commit_boundary(
    monkeypatch, tmp_path: Path
) -> None:
    """At the exact deadline, no lease renewal or side effect may commit."""

    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    base = 90_000.0
    deadline = base + 5.0
    policy_now = [base]
    monkeypatch.setattr(runner.time, "time", lambda: policy_now[0])

    def inbound_claim(suffix: str) -> dict[str, object]:
        assert runner._store_inbound(
            {
                "message_id": f"deadline-equality-{suffix}",
                "chat_id": f"deadline-equality-chat-{suffix}",
                "message_type": "text",
                "content": '{"text":"hello"}',
                "open_id": f"deadline-equality-user-{suffix}",
            },
            now=base,
        )
        claim = runner._claim_inbound(now=base)
        assert claim is not None
        assert claim["claim_deadline"] == deadline
        return claim

    heartbeat_claim = inbound_claim("heartbeat")
    finish_claim = inbound_claim("finish")
    enqueue_claim = inbound_claim("enqueue")
    outbox_uuid = runner._enqueue_outbox(
        "deadline-equality-chat-outbox",
        "text",
        '{"text":"reply"}',
        delivery_key="deadline-equality-outbox-finish",
    )
    outbox_claim = runner._claim_outbox(now=base, delivery_uuid=outbox_uuid)
    assert outbox_claim is not None
    assert outbox_claim["claim_deadline"] == deadline

    policy_now[0] = deadline
    actual = {
        "heartbeat_renewed": runner._heartbeat_claim(
            "inbox", heartbeat_claim, now=deadline
        ),
        "inbound_finished": runner._finish_inbound(
            finish_claim, ok=True, now=deadline
        ),
    }
    payload = enqueue_claim["payload"]
    assert isinstance(payload, dict)
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = enqueue_claim["id"]
    runner._DELIVERY_CONTEXT.claim_token = enqueue_claim["claim_token"]
    runner._DELIVERY_CONTEXT.claim_epoch = enqueue_claim["claim_epoch"]
    runner._DELIVERY_CONTEXT.lease_guard = None
    try:
        try:
            runner._enqueue_outbox(
                str(payload["chat_id"]),
                "text",
                '{"text":"must not persist"}',
                delivery_key="deadline-equality-outbox-enqueue",
            )
        except runner.FeishuLeaseLost:
            actual["outbox_enqueue_rejected"] = True
        else:
            actual["outbox_enqueue_rejected"] = False
    finally:
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None
    actual["outbox_finished"] = runner._finish_outbox(
        outbox_claim, ok=True, now=deadline
    )

    assert actual == {
        "heartbeat_renewed": False,
        "inbound_finished": False,
        "outbox_enqueue_rejected": True,
        "outbox_finished": False,
    }


def test_feishu_inbound_worker_never_finishes_after_heartbeat_loss(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = time.time()
    payload = {
        "message_id": "heartbeat-loss",
        "chat_id": "heartbeat-chat",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "heartbeat-user",
    }
    assert runner._store_inbound(payload, now=now)
    claim = runner._claim_inbound(now=now)

    class OneClaim:
        def __init__(self):
            self.stopped = False
            self.claimed = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    stop = OneClaim()

    def claim_once():
        if stop.claimed:
            return None
        stop.claimed = True
        return claim

    finish_outcomes: list[tuple[bool, str]] = []

    class LostSession:
        lost = False

        def start(self):
            return True

        def finish(self, outcome):
            finish_outcomes.append(outcome)
            self.lost = True
            runner._record_claim_health("inbox_heartbeat_lost")
            return False

        def close(self):
            return False

    session = LostSession()

    monkeypatch.setattr(runner, "_claim_inbound", claim_once)
    monkeypatch.setattr(
        runner,
        "_new_inbound_claim_session",
        lambda owned_claim: session if owned_claim is claim else None,
    )
    monkeypatch.setattr(runner, "_handle_message", lambda _event: None)
    runner._inbound_worker(stop)
    assert finish_outcomes == [(True, "handler_failed")]
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token FROM feishu_inbox"
        ).fetchone() == ("processing", claim["claim_token"])
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_heartbeat_lost"


def test_feishu_inbound_worker_uses_shared_first_pulse_before_handler(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 40_500.0
    payload = {
        "message_id": "shared-first-pulse",
        "chat_id": "shared-first-pulse-chat",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "shared-first-pulse-user",
    }
    assert runner._store_inbound(payload, now=now)
    claim = runner._claim_inbound(now=now)

    class OneClaim:
        def __init__(self) -> None:
            self.stopped = False
            self.claimed = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, _seconds: float) -> bool:
            self.stopped = True
            return True

    stop = OneClaim()

    def claim_once():
        if stop.claimed:
            return None
        stop.claimed = True
        return claim

    handled: list[str] = []
    monkeypatch.setattr(runner, "_claim_inbound", claim_once)
    monkeypatch.setattr(
        runner,
        "_heartbeat_claim",
        lambda kind, owned_claim, **_kwargs: (
            kind == "inbox" and owned_claim is claim and False
        ),
    )
    monkeypatch.setattr(
        runner,
        "_handle_message",
        lambda _event: handled.append("handler-ran"),
    )

    runner._inbound_worker(stop)

    assert handled == []
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token FROM feishu_inbox"
        ).fetchone() == ("processing", claim["claim_token"])
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_heartbeat_lost"


def test_feishu_shared_inbox_finish_response_loss_does_not_rerun_handler(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = time.time()
    payload = {
        "message_id": "shared-finish-response-loss",
        "chat_id": "shared-finish-response-loss-chat",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "shared-finish-response-loss-user",
    }
    assert runner._store_inbound(payload, now=now)
    claim = runner._claim_inbound(now=now)

    class OneClaim:
        def __init__(self) -> None:
            self.stopped = False
            self.claimed = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, _seconds: float) -> bool:
            self.stopped = True
            return True

    stop = OneClaim()

    def claim_once():
        if stop.claimed:
            return None
        stop.claimed = True
        return claim

    handled: list[str] = []
    finish_calls = 0
    original_finish = runner._finish_inbound

    def commit_then_lose_response(*args, **kwargs):
        nonlocal finish_calls
        finish_calls += 1
        assert original_finish(*args, **kwargs) is True
        raise sqlite3.OperationalError("synthetic response loss")

    monkeypatch.setattr(runner, "_claim_inbound", claim_once)
    monkeypatch.setattr(runner, "_finish_inbound", commit_then_lose_response)
    monkeypatch.setattr(
        runner,
        "_handle_message",
        lambda _event: handled.append("handler-ran"),
    )

    runner._inbound_worker(stop)

    assert handled == ["handler-ran"]
    assert finish_calls == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_inbox"
        ).fetchone() == (
            "done",
            claim["claim_token"],
            claim["claim_epoch"],
            "done",
        )
    assert runner._HEALTH_STATE["last_error_code"] == "inbox_finish_storage_retry"


def test_feishu_outbox_finish_response_loss_never_resends_delivery(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 50_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    delivery_uuid = runner._enqueue_outbox(
        "response-loss-chat",
        "text",
        '{"text":"one"}',
        delivery_key="response-loss-outbox",
    )
    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )
    claims: list[dict[str, object]] = []
    original_claim = runner._claim_outbox

    def capture_claim(*args, **kwargs):
        claim = original_claim(*args, **kwargs)
        if claim is not None:
            claims.append(dict(claim))
        return claim

    monkeypatch.setattr(runner, "_claim_outbox", capture_claim)
    original_finish = runner._finish_outbox

    def finish_then_lose_response(*args, **kwargs):
        assert original_finish(*args, **kwargs) is True
        raise sqlite3.OperationalError("synthetic outbox response loss")

    monkeypatch.setattr(runner, "_finish_outbox", finish_then_lose_response)
    assert runner._drain_outbox(now=now, limit=1) == 1
    assert sent == [delivery_uuid]
    assert len(claims) == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM feishu_outbox WHERE delivery_uuid=?",
            (delivery_uuid,),
        ).fetchone() == (
            "done",
            claims[0]["claim_token"],
            claims[0]["claim_epoch"],
            "done",
        )
    assert runner._drain_outbox(now=now + 1.0, limit=1) == 0
    assert sent == [delivery_uuid]


def test_feishu_restart_requeues_abandoned_claims_with_new_fences(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    with runner._state_connect() as current:
        assert int(current.execute("PRAGMA user_version").fetchone()[0]) == 5
    now = 55_000.0
    monkeypatch.setattr(runner.time, "time", lambda: now)
    assert runner._store_inbound(
        {
            "message_id": "restart-message",
            "chat_id": "restart-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "restart-user",
        },
        now=now,
    )
    delivery_uuid = runner._enqueue_outbox(
        "restart-chat",
        "text",
        '{"text":"reply"}',
        delivery_key="restart-delivery",
    )
    old_inbox = runner._claim_inbound(now=now)
    old_outbox = runner._claim_outbox(now=now)

    # main() calls this only after acquiring the process singleton.  Simulate
    # the new process proving the prior workers are gone.
    assert runner._recover_inflight() == 2
    new_inbox = runner._claim_inbound(now=now)
    new_outbox = runner._claim_outbox(now=now)
    assert new_inbox["claim_epoch"] == old_inbox["claim_epoch"] + 1
    assert new_outbox["claim_epoch"] == old_outbox["claim_epoch"] + 1
    assert new_inbox["claim_token"] != old_inbox["claim_token"]
    assert new_outbox["claim_token"] != old_outbox["claim_token"]
    assert new_outbox["delivery_uuid"] == delivery_uuid
    assert runner._finish_inbound(old_inbox, ok=True, now=now) is False
    assert runner._finish_outbox(old_outbox, ok=True, now=now) is False


def test_feishu_lost_inbound_worker_cannot_persist_or_send_a_late_reply(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 1.0)
    now = 60_000.0
    payload = {
        "message_id": "late-reply",
        "chat_id": "late-chat",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "late-user",
    }
    assert runner._store_inbound(payload, now=now)
    old = runner._claim_inbound(now=now)
    assert runner._recover_stale_inflight(now=now + 6.01) == 1
    replacement = runner._claim_inbound(now=now + 6.01)
    monkeypatch.setattr(runner.time, "time", lambda: now + 6.02)
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = old["id"]
    runner._DELIVERY_CONTEXT.claim_token = old["claim_token"]
    runner._DELIVERY_CONTEXT.claim_epoch = old["claim_epoch"]
    sent: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: sent.append(str(claim["delivery_uuid"])),
    )

    with pytest.raises(runner.FeishuLeaseLost):
        runner._reply("late-chat", "late result", delivery_key="late-result")
    assert sent == []
    assert runner._outbox_status_counts(("pending", "processing", "done")) == 0
    assert runner._finish_inbound(old, ok=True, now=now + 6.02) is False
    assert runner._finish_inbound(replacement, ok=True, now=now + 6.02) is True


def test_feishu_heartbeat_failure_blocks_reply_before_deadline(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    now = 65_000.0
    payload = {
        "message_id": "heartbeat-fence-reply",
        "chat_id": "heartbeat-fence-chat",
        "message_type": "text",
        "content": '{"text":"hello"}',
        "open_id": "heartbeat-fence-user",
    }
    assert runner._store_inbound(payload, now=now)
    claim = runner._claim_inbound(now=now)
    monkeypatch.setattr(runner.time, "time", lambda: now + 1.0)
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = claim["id"]
    runner._DELIVERY_CONTEXT.claim_token = claim["claim_token"]
    runner._DELIVERY_CONTEXT.claim_epoch = claim["claim_epoch"]
    runner._DELIVERY_CONTEXT.lease_guard = SimpleNamespace(lost=True)

    with pytest.raises(runner.FeishuLeaseLost, match="heartbeat"):
        runner._reply(
            payload["chat_id"],
            "must not persist",
            delivery_key="heartbeat-fence-result",
        )
    assert runner._outbox_status_counts(("pending", "processing", "done")) == 0


def test_feishu_expired_claim_cannot_persist_a_late_progress_notice(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 5.0)
    now = 66_000.0
    message_id = "late-progress"
    chat_id = "late-progress-chat"
    assert runner._store_inbound(
        {
            "message_id": message_id,
            "chat_id": chat_id,
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "late-progress-user",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)
    assert runner._persist_text_progress_notice(
        message_id,
        chat_id,
        str(claim["claim_token"]),
        int(claim["claim_epoch"]),
        runner.threading.Event(),
        now=now + 5.01,
    ) is False
    assert runner._outbox_status_counts(("pending", "processing", "done")) == 0


def test_feishu_health_projects_secret_free_claim_expiry_and_stuck_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    monkeypatch.setattr(runner, "_ACCESS_FILE", tmp_path / "missing-access.json")
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 10.0)
    monkeypatch.setattr(runner, "_CLAIM_GRACE_SECONDS", 3.0)
    now = 70_000.0
    secret_message = "secret-message-id"
    secret_chat = "secret-chat-id"
    assert runner._store_inbound(
        {
            "message_id": secret_message,
            "chat_id": secret_chat,
            "message_type": "text",
            "content": '{"text":"private body"}',
            "open_id": "secret-user-id",
        },
        now=now,
    )
    claim = runner._claim_inbound(now=now)

    before_expiry = runner._health_snapshot(now=now + 8.0)
    assert before_expiry["schema"] == "nachuan.feishu-bridge-health.v1"
    assert before_expiry["processing_inbound"] == 1
    assert before_expiry["oldest_processing_age_seconds"] == pytest.approx(8.0)
    assert before_expiry["next_claim_expiry_seconds"] == pytest.approx(2.0)
    assert before_expiry["expired_claims"] == 0
    assert before_expiry["processing_stuck"] == 0

    expired = runner._health_snapshot(now=now + 12.0)
    assert expired["expired_claims"] == 1
    assert expired["processing_stuck"] == 0
    assert "claim_expired" in expired["readiness_reasons"]
    stuck = runner._health_snapshot(now=now + 13.01)
    assert stuck["processing_stuck"] == 1
    assert "processing_stuck" in stuck["readiness_reasons"]
    rendered = json.dumps(stuck, sort_keys=True)
    for secret in (
        secret_message,
        secret_chat,
        "secret-user-id",
        "private body",
        str(claim["claim_token"]),
    ):
        assert secret not in rendered


def test_feishu_existing_state_database_explicitly_migrates_claim_lease_schema_v5(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "legacy-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            CREATE TABLE feishu_inbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT NOT NULL UNIQUE,
              chat_id TEXT NOT NULL,payload TEXT NOT NULL,received_at REAL NOT NULL,
              next_attempt_at REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'pending',last_error TEXT NOT NULL DEFAULT '',
              claimed_at REAL NOT NULL DEFAULT 0,finished_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE feishu_outbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,delivery_uuid TEXT NOT NULL UNIQUE,
              chat_id TEXT NOT NULL,msg_type TEXT NOT NULL,content TEXT NOT NULL,
              created_at REAL NOT NULL,next_attempt_at REAL NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',
              last_error TEXT NOT NULL DEFAULT '',claimed_at REAL NOT NULL DEFAULT 0,
              delivered_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    conn = runner._state_connect()
    try:
        inbox_columns = {row[1] for row in conn.execute("PRAGMA table_info(feishu_inbox)")}
        outbox_columns = {row[1] for row in conn.execute("PRAGMA table_info(feishu_outbox)")}
        schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()
    lease_columns = {
        "claim_token",
        "claim_deadline",
        "heartbeat_at",
        "claim_epoch",
        "last_finish_token",
        "last_finish_epoch",
        "last_finish_outcome",
    }
    assert lease_columns <= inbox_columns
    assert lease_columns <= outbox_columns
    assert schema_version == 5


def test_feishu_v2_processing_outbox_is_quarantined_on_v5_upgrade_and_never_replayed(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "accepted-before-v4-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(state_db)
    accepted_at = 10_000.0
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,delivered_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "accepted-before-v4",
                "chat-history",
                "text",
                '{"text":"provider already accepted this"}',
                accepted_at - 1,
                accepted_at - 1,
                0,
                "processing",
                "",
                accepted_at,
                "historical-lease-token",
                accepted_at + 60,
                accepted_at,
                7,
                "",
                0,
                "",
                0,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with runner._state_connect() as migrated:
        assert int(migrated.execute("PRAGMA user_version").fetchone()[0]) == 5

    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=accepted_at + 7_201) == 0
    provider_calls: list[str] = []
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: provider_calls.append(str(claim["delivery_uuid"])),
    )
    assert runner._drain_outbox(now=accepted_at + 7_201, limit=10) == 0
    assert provider_calls == []

    conn = sqlite3.connect(state_db)
    try:
        row = conn.execute(
            """
            SELECT delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
                   attempts,status,last_error,claimed_at,claim_token,claim_deadline,
                   heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                   last_finish_outcome,delivered_at
            FROM feishu_outbox WHERE delivery_uuid='accepted-before-v4'
            """
        ).fetchone()
    finally:
        conn.close()
    assert row == (
        "accepted-before-v4",
        "chat-history",
        "text",
        '{"text":"provider already accepted this"}',
        accepted_at - 1,
        accepted_at - 1,
        0,
        "recovery_required",
        "legacy_processing_provider_outcome_unknown",
        0,
        "",
        0,
        0,
        7,
        "historical-lease-token",
        7,
        "recovery_required",
        0,
    )


def test_feishu_v2_processing_inbox_is_quarantined_on_upgrade_and_worker_never_replays(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "accepted-inbound-before-v4-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(state_db)
    accepted_at = 20_000.0
    payload = json.dumps(
        {
            "message_id": "accepted-inbound-before-v4",
            "chat_id": "legacy-inbound-chat",
            "message_type": "image",
            "content": '{"image_key":"legacy-image"}',
            "open_id": "legacy-user",
        },
        separators=(",", ":"),
    )
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,finished_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "accepted-inbound-before-v4",
                "legacy-inbound-chat",
                payload,
                accepted_at - 2,
                accepted_at - 1,
                3,
                "processing",
                "",
                accepted_at,
                "legacy-inbound-token",
                accepted_at + 60,
                accepted_at,
                7,
                "",
                0,
                "",
                0,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with runner._state_connect() as migrated:
        version = int(migrated.execute("PRAGMA user_version").fetchone()[0])
    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=accepted_at + 7_201) == 0
    assert runner._claim_inbound(now=accepted_at + 7_201) is None

    provider_calls: list[str] = []

    class StopAfterOneIdlePoll:
        stopped = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, _seconds: float) -> bool:
            self.stopped = True
            return True

    monkeypatch.setattr(
        runner,
        "_handle_message",
        lambda event: provider_calls.append(event.event.message.message_id),
    )
    runner._inbound_worker(StopAfterOneIdlePoll())
    assert provider_calls == []

    conn = sqlite3.connect(state_db)
    try:
        row = conn.execute(
            """
            SELECT message_id,chat_id,payload,received_at,next_attempt_at,attempts,
                   status,last_error,claimed_at,claim_token,claim_deadline,
                   heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                   last_finish_outcome,finished_at
            FROM feishu_inbox WHERE message_id='accepted-inbound-before-v4'
            """
        ).fetchone()
    finally:
        conn.close()
    assert version == 5
    assert row == (
        "accepted-inbound-before-v4",
        "legacy-inbound-chat",
        payload,
        accepted_at - 2,
        accepted_at - 1,
        3,
        "recovery_required",
        "legacy_processing_provider_outcome_unknown",
        0,
        "",
        0,
        0,
        7,
        "legacy-inbound-token",
        7,
        "recovery_required",
        0,
    )


def test_feishu_intermediate_v3_quarantines_inbox_but_preserves_safe_outbox_recovery(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "intermediate-v3-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(state_db)
    payload = json.dumps(
        {
            "message_id": "intermediate-v3-inbox",
            "chat_id": "v3-chat",
            "message_type": "text",
            "content": '{"text":"possibly handled"}',
            "open_id": "v3-user",
        },
        separators=(",", ":"),
    )
    conn = sqlite3.connect(state_db)
    try:
        conn.execute("PRAGMA user_version=3")
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,finished_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "intermediate-v3-inbox",
                "v3-chat",
                payload,
                1,
                1,
                2,
                "processing",
                "",
                2,
                "v3-inbox-token",
                30,
                2,
                5,
                "",
                0,
                "",
                0,
            ),
        )
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,delivered_at)
            VALUES ('intermediate-v3-outbox','v3-other-chat','text','{"text":"safe"}',
                    1,1,0,'processing','',2,'v3-outbox-token',30,2,6,'',0,'',0)
            """
        )
        conn.commit()
    finally:
        conn.close()

    with runner._state_connect() as migrated:
        assert int(migrated.execute("PRAGMA user_version").fetchone()[0]) == 5
        assert migrated.execute(
            """
            SELECT status,last_error,claim_token,claim_epoch,last_finish_token,
                   last_finish_epoch,last_finish_outcome
            FROM feishu_inbox WHERE message_id='intermediate-v3-inbox'
            """
        ).fetchone() == (
            "recovery_required",
            "legacy_processing_provider_outcome_unknown",
            "",
            5,
            "v3-inbox-token",
            5,
            "recovery_required",
        )
        assert migrated.execute(
            """
            SELECT status,claim_token,claim_epoch,last_finish_outcome
            FROM feishu_outbox WHERE delivery_uuid='intermediate-v3-outbox'
            """
        ).fetchone() == ("processing", "v3-outbox-token", 6, "")

    assert runner._recover_inflight() == 1
    with runner._state_connect() as recovered:
        assert recovered.execute(
            "SELECT status FROM feishu_inbox WHERE message_id='intermediate-v3-inbox'"
        ).fetchone() == ("recovery_required",)
        assert recovered.execute(
            "SELECT status FROM feishu_outbox "
            "WHERE delivery_uuid='intermediate-v3-outbox'"
        ).fetchone() == ("pending",)


def test_feishu_inbox_recovery_required_blocks_capacity_order_and_survives_retention(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "inbox-recovery-policy-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(state_db)
    legacy_payload = json.dumps(
        {
            "message_id": "legacy-inbox-recovery",
            "chat_id": "blocked-inbox-chat",
            "message_type": "text",
            "content": '{"text":"possibly handled"}',
            "open_id": "legacy-user",
        },
        separators=(",", ":"),
    )
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,finished_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "legacy-inbox-recovery",
                "blocked-inbox-chat",
                legacy_payload,
                100,
                100,
                4,
                "processing",
                "",
                101,
                "legacy-inbox-recovery-token",
                200,
                101,
                8,
                "",
                0,
                "",
                0,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    with runner._state_connect() as migrated:
        assert int(migrated.execute("PRAGMA user_version").fetchone()[0]) == 5

    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_ROWS", 1)
    with pytest.raises(runner.FeishuQueueFull, match="queue is full"):
        runner._store_inbound(
            {
                "message_id": "total-capacity-bypass",
                "chat_id": "another-chat",
                "message_type": "text",
                "content": '{"text":"must not bypass"}',
                "open_id": "other-user",
            },
            now=300,
        )

    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_ROWS", 10)
    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_PER_CHAT", 1)
    with pytest.raises(runner.FeishuQueueFull, match="queue is full"):
        runner._store_inbound(
            {
                "message_id": "chat-capacity-bypass",
                "chat_id": "blocked-inbox-chat",
                "message_type": "text",
                "content": '{"text":"must not overtake"}',
                "open_id": "legacy-user",
            },
            now=300,
        )

    monkeypatch.setattr(runner, "_MAX_ACTIVE_INBOUND_PER_CHAT", 10)
    assert runner._store_inbound(
        {
            "message_id": "same-chat-successor",
            "chat_id": "blocked-inbox-chat",
            "message_type": "text",
            "content": '{"text":"wait for operator"}',
            "open_id": "legacy-user",
        },
        now=300,
    )
    assert runner._store_inbound(
        {
            "message_id": "other-chat-progress",
            "chat_id": "unblocked-inbox-chat",
            "message_type": "text",
            "content": '{"text":"can progress"}',
            "open_id": "other-user",
        },
        now=300,
    )
    other = runner._claim_inbound(now=300)
    assert other is not None
    assert other["payload"]["message_id"] == "other-chat-progress"
    assert runner._finish_inbound(other, ok=True, now=301) is True
    assert runner._claim_inbound(now=301) is None

    stale_legacy_claim = {
        "id": 1,
        "payload": json.loads(legacy_payload),
        "attempts": 4,
        "claim_token": "legacy-inbox-recovery-token",
        "claim_deadline": 200,
        "claim_epoch": 8,
    }
    assert runner._heartbeat_claim("inbox", stale_legacy_claim, now=150) is False
    assert runner._finish_inbound(stale_legacy_claim, ok=True, now=150) is False

    health = runner._health_snapshot(now=400)
    assert health["pending_inbound"] == 2
    assert health["recovery_required_inbound"] == 1
    assert "pending_inbound" in health["readiness_reasons"]
    assert "inbox_recovery_required" in health["readiness_reasons"]
    assert runner._claim_failure_still_active("inbox_recovery_required") is True

    runner._maintain_state(
        now=365 * 24 * 60 * 60,
        done_ttl_seconds=0,
        dead_ttl_seconds=0,
        max_terminal_rows=0,
    )
    with runner._state_connect() as retained:
        assert retained.execute(
            """
            SELECT status,chat_id,payload,last_error,last_finish_token,
                   last_finish_epoch,last_finish_outcome
            FROM feishu_inbox WHERE message_id='legacy-inbox-recovery'
            """
        ).fetchone() == (
            "recovery_required",
            "blocked-inbox-chat",
            legacy_payload,
            "legacy_processing_provider_outcome_unknown",
            "legacy-inbox-recovery-token",
            8,
            "recovery_required",
        )


def test_feishu_v0_processing_rows_are_quarantined_while_legacy_data_is_preserved(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "v0-processing-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v0_database(state_db)
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,finished_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "v0-inbox-preserved",
                "chat-v0",
                '{"text":"inbound stays byte-for-byte logical data"}',
                100.0,
                101.0,
                2,
                "processing",
                "inbound-history",
                102.0,
                0,
            ),
        )
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,delivered_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "v0-outbox-unknown",
                "chat-v0",
                "text",
                '{"text":"possibly accepted under v0"}',
                102.0,
                103.0,
                4,
                "processing",
                "old-local-error",
                104.0,
                0,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with runner._state_connect() as migrated:
        version = int(migrated.execute("PRAGMA user_version").fetchone()[0])
        inbox = migrated.execute(
            """
            SELECT message_id,chat_id,payload,received_at,next_attempt_at,
                   attempts,status,last_error,claimed_at,claim_token,claim_deadline,
                   heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                   last_finish_outcome,finished_at
            FROM feishu_inbox
            """
        ).fetchone()
        outbox = migrated.execute(
            """
            SELECT delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
                   attempts,status,last_error,claimed_at,claim_token,claim_deadline,
                   heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
                   last_finish_outcome,delivered_at
            FROM feishu_outbox
            """
        ).fetchone()
    assert version == 5
    assert runner._recover_inflight() == 0
    assert runner._recover_stale_inflight(now=10_000.0) == 0
    assert runner._claim_inbound(now=10_000.0) is None
    provider_calls: list[str] = []

    class StopAfterOneIdlePoll:
        stopped = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, _seconds: float) -> bool:
            self.stopped = True
            return True

    monkeypatch.setattr(
        runner,
        "_handle_message",
        lambda event: provider_calls.append(event.event.message.message_id),
    )
    monkeypatch.setattr(
        runner,
        "_send_outbox_claim",
        lambda claim: provider_calls.append(str(claim["delivery_uuid"])),
    )
    runner._inbound_worker(StopAfterOneIdlePoll())
    assert runner._drain_outbox(now=10_000.0, limit=10) == 0
    assert provider_calls == []
    assert inbox == (
        "v0-inbox-preserved",
        "chat-v0",
        '{"text":"inbound stays byte-for-byte logical data"}',
        100.0,
        101.0,
        2,
        "recovery_required",
        "legacy_processing_provider_outcome_unknown",
        0,
        "",
        0,
        0,
        0,
        "",
        0,
        "recovery_required",
        0,
    )
    assert outbox == (
        "v0-outbox-unknown",
        "chat-v0",
        "text",
        '{"text":"possibly accepted under v0"}',
        102.0,
        103.0,
        4,
        "recovery_required",
        "legacy_processing_provider_outcome_unknown",
        0,
        "",
        0,
        0,
        0,
        "",
        0,
        "recovery_required",
        0,
    )


def test_feishu_v0_to_v5_migration_failure_rolls_back_schema_rows_and_version(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "v0-migration-rollback-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v0_database(state_db)
    real_connect = sqlite3.connect
    conn = real_connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,delivered_at)
            VALUES ('rollback-history','chat-r','text','{"text":"keep"}',
                    1,2,3,'processing','keep-error',4,0)
            """
        )
        conn.commit()
        before = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )
    finally:
        conn.close()

    class FailingMigrationConnection(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            normalized = " ".join(str(sql).split())
            if normalized.startswith(
                "ALTER TABLE feishu_outbox ADD COLUMN claim_deadline"
            ):
                raise sqlite3.OperationalError("synthetic migration interruption")
            return super().execute(sql, parameters)

    monkeypatch.setattr(
        runner.sqlite3,
        "connect",
        lambda database, **kwargs: real_connect(
            database, factory=FailingMigrationConnection, **kwargs
        ),
    )
    with pytest.raises(sqlite3.OperationalError, match="synthetic migration interruption"):
        runner._state_connect()

    conn = real_connect(state_db)
    try:
        after = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )
    finally:
        conn.close()
    assert after == before


def test_feishu_v3_to_v5_semantic_quarantine_failure_rolls_back_every_row(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "v3-semantic-rollback-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(state_db)
    real_connect = sqlite3.connect
    conn = real_connect(state_db)
    try:
        conn.execute("PRAGMA user_version=3")
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,finished_at)
            VALUES ('semantic-rollback-inbox','chat-r','{}',1,1,0,'processing','',
                    2,'semantic-token',30,2,4,'',0,'',0)
            """
        )
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,delivered_at)
            VALUES ('semantic-rollback-outbox','chat-r','text','{}',1,1,0,
                    'processing','',2,'safe-v3-outbox-token',30,2,5,'',0,'',0)
            """
        )
        conn.commit()
        before = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )
    finally:
        conn.close()

    class FailBeforeVersionCommit(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            if " ".join(str(sql).split()) == "PRAGMA user_version=5":
                raise sqlite3.OperationalError("synthetic semantic migration interruption")
            return super().execute(sql, parameters)

    monkeypatch.setattr(
        runner.sqlite3,
        "connect",
        lambda database, **kwargs: real_connect(
            database, factory=FailBeforeVersionCommit, **kwargs
        ),
    )
    with pytest.raises(
        sqlite3.OperationalError, match="synthetic semantic migration interruption"
    ):
        runner._state_connect()

    conn = real_connect(state_db)
    try:
        after = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(conn.execute("SELECT * FROM feishu_inbox ORDER BY id")),
            tuple(conn.execute("SELECT * FROM feishu_outbox ORDER BY id")),
        )
    finally:
        conn.close()
    assert after == before


def test_feishu_v2_to_v5_concurrent_initializers_converge_once_without_replay(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_state_runner_without_sdk(monkeypatch)
    state_db = tmp_path / "v2-concurrent-upgrade-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    monkeypatch.setattr(runner, "_CLAIM_TTL_SECONDS", 120.0)
    _create_canonical_feishu_v2_database(state_db)
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            INSERT INTO feishu_outbox
              (delivery_uuid,chat_id,msg_type,content,created_at,next_attempt_at,
               attempts,status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,delivered_at)
            VALUES ('concurrent-v2','chat-c','text','{"text":"accepted"}',
                    1,2,5,'processing','',3,'concurrent-token',4,3,9,'',0,'',0)
            """
        )
        conn.execute(
            """
            INSERT INTO feishu_inbox
              (message_id,chat_id,payload,received_at,next_attempt_at,attempts,
               status,last_error,claimed_at,claim_token,claim_deadline,
               heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,
               last_finish_outcome,finished_at)
            VALUES ('concurrent-v2-inbox','chat-in','{"message_id":"concurrent-v2-inbox"}',
                    1,2,6,'processing','',3,'concurrent-inbox-token',4,3,10,'',0,'',0)
            """
        )
        conn.commit()
    finally:
        conn.close()

    worker_count = 8
    barrier = threading.Barrier(worker_count)
    results: queue.Queue[object] = queue.Queue()

    def initialize() -> None:
        try:
            barrier.wait(timeout=10)
            with runner._state_connect() as opened:
                results.put(
                    (
                        int(opened.execute("PRAGMA user_version").fetchone()[0]),
                        opened.execute(
                            """
                            SELECT status,last_error,claimed_at,claim_token,
                                   claim_deadline,heartbeat_at,claim_epoch,
                                   last_finish_token,last_finish_epoch,
                                   last_finish_outcome
                            FROM feishu_outbox WHERE delivery_uuid='concurrent-v2'
                            """
                        ).fetchone(),
                        opened.execute(
                            """
                            SELECT status,last_error,claimed_at,claim_token,
                                   claim_deadline,heartbeat_at,claim_epoch,
                                   last_finish_token,last_finish_epoch,
                                   last_finish_outcome
                            FROM feishu_inbox WHERE message_id='concurrent-v2-inbox'
                            """
                        ).fetchone(),
                    )
                )
        except BaseException as exc:
            results.put(exc)

    threads = [threading.Thread(target=initialize) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not [thread for thread in threads if thread.is_alive()]

    observed = [results.get_nowait() for _ in range(worker_count)]
    errors = [value for value in observed if isinstance(value, BaseException)]
    assert errors == []
    assert observed == [
        (
            5,
            (
                "recovery_required",
                "legacy_processing_provider_outcome_unknown",
                0,
                "",
                0,
                0,
                9,
                "concurrent-token",
                9,
                "recovery_required",
            ),
            (
                "recovery_required",
                "legacy_processing_provider_outcome_unknown",
                0,
                "",
                0,
                0,
                10,
                "concurrent-inbox-token",
                10,
                "recovery_required",
            ),
        )
    ] * worker_count
    conn = sqlite3.connect(state_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM feishu_outbox").fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("case", "chat_id_definition", "extra_schema"),
    (
        (
            "unknown-trigger",
            "chat_id TEXT NOT NULL",
            "CREATE TRIGGER unexpected_v0_trigger AFTER INSERT ON feishu_inbox "
            "BEGIN SELECT 1; END;",
        ),
        (
            "extra-column",
            "chat_id TEXT NOT NULL, attacker_data TEXT",
            "",
        ),
        (
            "collation",
            "chat_id TEXT COLLATE NOCASE NOT NULL",
            "",
        ),
        (
            "check-constraint",
            "chat_id TEXT NOT NULL CHECK(length(chat_id) > 0)",
            "",
        ),
    ),
)
def test_feishu_rejects_malformed_v0_before_persisting_storage_pragmas(
    monkeypatch,
    tmp_path: Path,
    case: str,
    chat_id_definition: str,
    extra_schema: str,
) -> None:
    runner = _load_runner()
    state_db = tmp_path / f"malformed-v0-{case}-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    monkeypatch.setattr(runner, "_STATE_DB_MAX_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(runner, "_STATE_WAL_MAX_BYTES", 1_234_567)
    _create_canonical_feishu_v0_database(
        state_db,
        inbox_chat_id_definition=chat_id_definition,
        extra_schema=extra_schema,
    )

    def forensic_snapshot() -> tuple[object, ...]:
        conn = sqlite3.connect(state_db)
        try:
            return (
                str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                int(conn.execute("PRAGMA max_page_count").fetchone()[0]),
                int(conn.execute("PRAGMA journal_size_limit").fetchone()[0]),
                int(conn.execute("PRAGMA user_version").fetchone()[0]),
                tuple(
                    conn.execute(
                        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                        "ORDER BY type,name"
                    )
                ),
            )
        finally:
            conn.close()

    before = forensic_snapshot()
    assert before[0] == "delete"
    assert not Path(f"{state_db}-wal").exists()
    assert not Path(f"{state_db}-shm").exists()
    with pytest.raises(RuntimeError, match="unsupported.*schema"):
        runner._state_connect()
    after = forensic_snapshot()
    assert after == before
    assert not Path(f"{state_db}-wal").exists()
    assert not Path(f"{state_db}-shm").exists()


def test_feishu_state_database_rejects_unknown_version_and_extra_columns(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "unsupported-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    conn = sqlite3.connect(state_db)
    try:
        conn.execute("PRAGMA user_version=999")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(RuntimeError, match="unsupported.*schema version"):
        runner._state_connect()

    state_db.unlink()
    with runner._state_connect() as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 5
        conn.execute("ALTER TABLE feishu_inbox ADD COLUMN attacker_data TEXT")
        conn.commit()
    with pytest.raises(RuntimeError, match="unsupported.*table schema"):
        runner._state_connect()


@pytest.mark.parametrize(
    ("object_kind", "ddl"),
    (
        (
            "trigger",
            "CREATE TRIGGER unexpected_v2_trigger AFTER INSERT ON feishu_inbox "
            "BEGIN SELECT 1; END",
        ),
        (
            "view",
            "CREATE VIEW unexpected_v2_view AS SELECT id FROM feishu_inbox",
        ),
        (
            "index",
            "CREATE INDEX unexpected_v2_index ON feishu_inbox(chat_id)",
        ),
    ),
)
def test_feishu_schema_v2_rejects_unknown_schema_objects_without_mutation(
    monkeypatch,
    tmp_path: Path,
    object_kind: str,
    ddl: str,
) -> None:
    runner = _load_runner()
    state_db = tmp_path / f"unknown-{object_kind}-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    conn = runner._state_connect()
    conn.close()

    conn = sqlite3.connect(state_db)
    try:
        conn.execute(ddl)
        conn.commit()
        before = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
        )
    finally:
        conn.close()

    with pytest.raises(RuntimeError, match="unsupported.*schema"):
        reopened = runner._state_connect()
        reopened.close()

    conn = sqlite3.connect(state_db)
    try:
        after = (
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
            tuple(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                    "ORDER BY type,name"
                )
            ),
        )
    finally:
        conn.close()
    assert after == before


@pytest.mark.parametrize(
    "chat_id_definition",
    (
        "chat_id TEXT COLLATE NOCASE NOT NULL",
        "chat_id TEXT NOT NULL CHECK(length(chat_id) > 0)",
    ),
    ids=("collation", "check-constraint"),
)
def test_feishu_schema_v2_rejects_hidden_column_semantic_drift(
    monkeypatch,
    tmp_path: Path,
    chat_id_definition: str,
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "semantic-drift-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    _create_canonical_feishu_v2_database(
        state_db,
        inbox_chat_id_definition=chat_id_definition,
    )

    conn = sqlite3.connect(state_db)
    try:
        before = tuple(
            conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                "ORDER BY type,name"
            )
        )
    finally:
        conn.close()
    with pytest.raises(RuntimeError, match="unsupported.*schema"):
        reopened = runner._state_connect()
        reopened.close()
    conn = sqlite3.connect(state_db)
    try:
        after = tuple(
            conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                "ORDER BY type,name"
            )
        )
    finally:
        conn.close()
    assert after == before


def test_feishu_rejects_unknown_v2_before_persisting_storage_pragmas(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "preflight-order-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    monkeypatch.setattr(runner, "_STATE_DB_MAX_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(runner, "_STATE_WAL_MAX_BYTES", 1_234_567)
    _create_canonical_feishu_v2_database(
        state_db,
        extra_schema=(
            "CREATE TRIGGER unexpected_preflight_trigger "
            "AFTER INSERT ON feishu_inbox BEGIN SELECT 1; END;"
        ),
    )

    def storage_pragmas() -> tuple[str, int, int]:
        conn = sqlite3.connect(state_db)
        try:
            return (
                str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                int(conn.execute("PRAGMA max_page_count").fetchone()[0]),
                int(conn.execute("PRAGMA journal_size_limit").fetchone()[0]),
            )
        finally:
            conn.close()

    before = storage_pragmas()
    assert before[0] == "delete"
    with pytest.raises(RuntimeError, match="unsupported.*schema"):
        runner._state_connect()
    after = storage_pragmas()
    assert after == before


def test_feishu_schema_v2_never_silently_reinterprets_missing_lease_columns(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    state_db = tmp_path / "mislabelled-v2-feishu.db"
    monkeypatch.setattr(runner, "_STATE_DB", state_db)
    conn = sqlite3.connect(state_db)
    try:
        conn.execute(
            """
            CREATE TABLE feishu_inbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT NOT NULL UNIQUE,
              chat_id TEXT NOT NULL,payload TEXT NOT NULL,received_at REAL NOT NULL,
              next_attempt_at REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'pending',last_error TEXT NOT NULL DEFAULT '',
              claimed_at REAL NOT NULL DEFAULT 0,finished_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE feishu_outbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,delivery_uuid TEXT NOT NULL UNIQUE,
              chat_id TEXT NOT NULL,msg_type TEXT NOT NULL,content TEXT NOT NULL,
              created_at REAL NOT NULL,next_attempt_at REAL NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',
              last_error TEXT NOT NULL DEFAULT '',claimed_at REAL NOT NULL DEFAULT 0,
              delivered_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("PRAGMA user_version=2")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(RuntimeError, match="version 2.*table schema"):
        runner._state_connect()
    conn = sqlite3.connect(state_db)
    try:
        inbox_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(feishu_inbox)")
        }
    finally:
        conn.close()
    assert "claim_deadline" not in inbox_columns


def test_feishu_reconnect_backoff_resets_only_after_observed_connection() -> None:
    runner = _load_runner()
    assert runner._reconnect_backoff_step(24, observed_connected=False) == (24, 30)
    assert runner._reconnect_backoff_step(24, observed_connected=True) == (3, 6)

    before = runner._connection_generation()
    runner._mark_connected(now=123.0)
    assert runner._connection_generation() == before + 1


def test_feishu_engine_uses_sealed_bridge_transport_and_never_environment_proxy(
    monkeypatch,
) -> None:
    runner = _load_runner()
    assert runner.ENGINE_KEY == runner.S.bridge_api_key

    built: list[object] = []
    sentinel = object()

    def fake_build_opener(*handlers):
        built.extend(handlers)
        return sentinel

    monkeypatch.setattr(runner.urllib.request, "build_opener", fake_build_opener)
    assert runner._build_engine_opener() is sentinel
    assert len(built) == 1
    assert isinstance(built[0], runner.urllib.request.ProxyHandler)
    assert built[0].proxies == {}

    requests: list[tuple[object, dict[str, object]]] = []
    engine_opener = object()
    monkeypatch.setattr(runner, "_ENGINE_OPENER", engine_opener)
    monkeypatch.setattr(runner, "ENGINE_KEY", "bridge-only-test-key")

    def fake_request(opener, **kwargs):
        requests.append((opener, kwargs))
        return b'{"text":"ok","report":"ok"}'

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    monkeypatch.setattr(
        runner.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("engine request used proxy-aware urlopen")
        ),
    )
    runner._post("/v1/test", {"x": 1})
    runner._get("/v1/test")
    runner._transcribe(b"audio")
    media_identity = {
        "message_id": "transport-message",
        "user_id": "transport-user",
        "chat_id": "transport-chat",
    }
    runner._describe(b"image", **media_identity)
    runner._lapian(b"video", **media_identity)

    assert len(requests) == 5
    for opener, kwargs in requests:
        assert opener is engine_opener
        assert kwargs["secret"] == "bridge-only-test-key"
        assert kwargs["channel"] == "feishu"
        assert kwargs["method"] in {"GET", "POST"}
        assert "Authorization" not in kwargs.get("headers", {})


def test_feishu_all_inbound_provider_seams_fail_before_call_when_lease_is_lost(
    monkeypatch,
) -> None:
    runner = _load_runner()
    requests: list[str] = []

    def fake_request(_opener, **kwargs):
        requests.append(str(kwargs["url"]))
        if str(kwargs["url"]).endswith("/v1/audio/transcriptions"):
            return b'{"text":"heard"}'
        if str(kwargs["url"]).endswith("/v1/vision"):
            return b'{"text":"seen"}'
        if str(kwargs["url"]).endswith("/v1/lapian"):
            return b'{"report":"report"}'
        return b'{"reply":"ok"}'

    class LostGuard:
        lost = True

        def permits_provider(self) -> bool:
            return False

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    runner._DELIVERY_CONTEXT.message_id = "provider-fence-message"
    runner._DELIVERY_CONTEXT.lease_guard = LostGuard()
    operations = (
        lambda: runner._agent_chat(
            "hello",
            "provider-user",
            "provider-chat",
            idempotency_key=("fsmsg-v1:" + "1" * 64),
        ),
        lambda: runner._transcribe(b"audio"),
        lambda: runner._describe(
            b"image",
            message_id="provider-image-message",
            user_id="provider-user",
            chat_id="provider-chat",
        ),
        lambda: runner._lapian(
            b"video",
            message_id="provider-video-message",
            user_id="provider-user",
            chat_id="provider-chat",
        ),
        lambda: runner._feedback(
            "provider-user",
            "provider-chat",
            "up",
            message_id="provider-feedback-message",
        ),
    )
    try:
        for operation in operations:
            with pytest.raises(runner.FeishuLeaseLost, match="provider_fence_lost"):
                operation()
    finally:
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.lease_guard = None

    assert requests == []


def test_feishu_all_inbound_provider_seams_recheck_lease_after_response(
    monkeypatch,
) -> None:
    runner = _load_runner()
    requests: list[str] = []

    def fake_request(_opener, **kwargs):
        requests.append(str(kwargs["url"]))
        if str(kwargs["url"]).endswith("/v1/audio/transcriptions"):
            return b'{"text":"heard"}'
        if str(kwargs["url"]).endswith("/v1/vision"):
            return b'{"text":"seen"}'
        if str(kwargs["url"]).endswith("/v1/lapian"):
            return b'{"report":"report"}'
        return b'{"reply":"ok"}'

    class LoseAfterResponseGuard:
        lost = False

        def __init__(self) -> None:
            self.checks = 0

        def permits_provider(self) -> bool:
            self.checks += 1
            if self.checks == 1:
                return True
            self.lost = True
            return False

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    runner._DELIVERY_CONTEXT.message_id = "provider-fence-message"
    operations = (
        lambda: runner._agent_chat(
            "hello",
            "provider-user",
            "provider-chat",
            idempotency_key=("fsmsg-v1:" + "2" * 64),
        ),
        lambda: runner._transcribe(b"audio"),
        lambda: runner._describe(
            b"image",
            message_id="provider-image-message",
            user_id="provider-user",
            chat_id="provider-chat",
        ),
        lambda: runner._lapian(
            b"video",
            message_id="provider-video-message",
            user_id="provider-user",
            chat_id="provider-chat",
        ),
        lambda: runner._feedback(
            "provider-user",
            "provider-chat",
            "up",
            message_id="provider-feedback-message",
        ),
    )
    try:
        for index, operation in enumerate(operations, start=1):
            guard = LoseAfterResponseGuard()
            runner._DELIVERY_CONTEXT.lease_guard = guard
            with pytest.raises(runner.FeishuLeaseLost, match="provider_fence_lost"):
                operation()
            assert guard.lost is True
            assert guard.checks == 2
            assert len(requests) == index
    finally:
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.lease_guard = None


def test_feishu_media_external_seams_fail_before_network_when_inbound_lease_is_lost(
    monkeypatch,
) -> None:
    runner = _load_runner()
    calls: list[str] = []

    class LostGuard:
        lost = True

        def permits_provider(self) -> bool:
            return False

    class ResourceApi:
        def get(self, _request):
            calls.append("resource")
            return SimpleNamespace(file=io.BytesIO(b"image"))

    class ImageApi:
        def create(self, _request):
            calls.append("image-upload")
            return SimpleNamespace(
                success=lambda: True,
                data=SimpleNamespace(image_key="image-key"),
            )

    class FileApi:
        def create(self, _request):
            calls.append("file-upload")
            return SimpleNamespace(
                success=lambda: True,
                data=SimpleNamespace(file_key="file-key"),
            )

    monkeypatch.setattr(
        runner,
        "_api",
        {
            "c": SimpleNamespace(
                im=SimpleNamespace(
                    v1=SimpleNamespace(
                        message_resource=ResourceApi(),
                        image=ImageApi(),
                        file=FileApi(),
                    )
                )
            )
        },
    )
    monkeypatch.setattr(
        runner,
        "fetch_public_bytes",
        lambda *_args, **_kwargs: (
            calls.append("public-download"),
            SimpleNamespace(data=b"image"),
        )[1],
    )
    runner._DELIVERY_CONTEXT.message_id = "media-fence-message"
    runner._DELIVERY_CONTEXT.lease_guard = LostGuard()
    operations = (
        lambda: runner._download_resource(
            "media-fence-message", "resource-key", "image", media_kind="image"
        ),
        lambda: runner._download_url("https://media.example/image.png", "image"),
        lambda: runner._upload_image(b"image"),
        lambda: runner._upload_file(b"video", "video.mp4", "mp4"),
    )
    try:
        for operation in operations:
            with pytest.raises(runner.FeishuLeaseLost):
                operation()
    finally:
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.lease_guard = None

    assert calls == []


@pytest.mark.parametrize("kind", ["image", "file"])
def test_feishu_upload_post_response_lease_loss_is_outcome_unknown(
    monkeypatch,
    tmp_path: Path,
    kind: str,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / f"feishu-{kind}.db")
    base = time.time()
    payload = {
        "message_id": f"media-upload-message-{kind}",
        "chat_id": f"media-upload-chat-{kind}",
        "message_type": "text",
        "content": '{"text":"generate media"}',
        "open_id": "media-upload-user",
    }
    assert runner._store_inbound(payload, now=base)
    claim = runner._claim_inbound(now=base)
    assert claim is not None
    calls: list[str] = []

    class LoseAfterResponseGuard:
        lost = False

        def __init__(self) -> None:
            self.checks = 0

        def permits_provider(self) -> bool:
            self.checks += 1
            if self.checks == 1:
                return True
            self.lost = True
            return False

        @contextmanager
        def commit_fence(self):
            yield

    class UploadApi:
        def create(self, _request):
            calls.append(kind)
            key = (
                {"image_key": "accepted-image"}
                if kind == "image"
                else {"file_key": "accepted-file"}
            )
            return SimpleNamespace(
                success=lambda: True,
                data=SimpleNamespace(**key),
            )

    api = UploadApi()
    monkeypatch.setattr(
        runner,
        "_api",
        {
            "c": SimpleNamespace(
                im=SimpleNamespace(
                    v1=SimpleNamespace(
                        image=api,
                        file=api,
                    )
                )
            )
        },
    )
    guard = LoseAfterResponseGuard()
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = int(claim["id"])
    runner._DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
    runner._DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
    runner._DELIVERY_CONTEXT.lease_guard = guard
    try:
        operation = (
            (lambda: runner._upload_image(b"image"))
            if kind == "image"
            else (lambda: runner._upload_file(b"video", "video.mp4", "mp4"))
        )
        with pytest.raises(
            runner.FeishuMediaUploadOutcomeUnknown,
            match="upload outcome is unknown",
        ):
            operation()
    finally:
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None
        runner._DELIVERY_CONTEXT.media_submission_sha256 = ""

    assert calls == [kind]
    assert guard.lost is True
    assert guard.checks == 2


def test_feishu_media_upload_unknown_quarantines_inbox_without_retry(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    payload = {
        "message_id": "media-upload-unknown",
        "chat_id": "media-upload-chat",
        "message_type": "text",
        "content": '{"text":"make an image"}',
        "open_id": "media-upload-user",
    }
    assert runner._store_inbound(payload)

    class OneCycle:
        def __init__(self) -> None:
            self.stopped = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, _seconds: float) -> bool:
            self.stopped = True
            return True

    monkeypatch.setattr(
        runner,
        "_handle_message",
        lambda _event: (_ for _ in ()).throw(
            runner.FeishuMediaUploadOutcomeUnknown(
                "Feishu image upload outcome is unknown"
            )
        ),
    )

    runner._inbound_worker(OneCycle())

    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_error,last_finish_outcome "
            "FROM feishu_inbox WHERE message_id=?",
            (payload["message_id"],),
        ).fetchone() == (
            "recovery_required",
            0,
            "media_upload_outcome_unknown",
            "recovery_required",
        )
    assert runner._claim_inbound() is None


@pytest.mark.parametrize("kind", ["image", "video"])
def test_feishu_send_reply_never_converts_uncertain_upload_to_fallback(
    monkeypatch,
    kind: str,
) -> None:
    runner = _load_runner()
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat, text, **_kwargs: (replies.append(text), True)[1],
    )
    monkeypatch.setattr(runner, "_download_url", lambda *_args: b"media")
    monkeypatch.setattr(
        runner,
        "_upload_image",
        lambda _data: (_ for _ in ()).throw(
            runner.FeishuMediaUploadOutcomeUnknown(
                "Feishu image upload outcome is unknown"
            )
        ),
    )
    monkeypatch.setattr(
        runner,
        "_upload_file",
        lambda *_args: (_ for _ in ()).throw(
            runner.FeishuMediaUploadOutcomeUnknown(
                "Feishu file upload outcome is unknown"
            )
        ),
    )
    document = (
        {"reply": "text", "images": ["https://media.example/image.png"]}
        if kind == "image"
        else {"reply": "text", "video": "https://media.example/video.mp4"}
    )

    with pytest.raises(runner.FeishuMediaUploadOutcomeUnknown):
        runner._send_reply("media-chat", document)

    assert replies == ["text"]


def test_feishu_inbound_media_upload_boundary_survives_process_crash(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = time.time()
    payload = {
        "message_id": "media-upload-crash",
        "chat_id": "media-upload-crash-chat",
        "message_type": "text",
        "content": '{"text":"make a video"}',
        "open_id": "media-upload-crash-user",
    }
    assert runner._store_inbound(payload, now=base)
    claim = runner._claim_inbound(now=base)
    assert claim is not None
    guard = runner._new_inbound_claim_session(claim, clock=lambda: base + 1.0)
    assert guard.start() is True
    observed: list[tuple[str, str]] = []

    class CrashDuringUpload:
        def create(self, _request):
            with runner._state_connect() as conn:
                observed.append(
                    conn.execute(
                        "SELECT status,terminal_verification FROM feishu_inbox "
                        "WHERE message_id=?",
                        (payload["message_id"],),
                    ).fetchone()
                )
            raise KeyboardInterrupt("synthetic process crash")

    monkeypatch.setattr(
        runner,
        "_api",
        {
            "c": SimpleNamespace(
                im=SimpleNamespace(v1=SimpleNamespace(file=CrashDuringUpload()))
            )
        },
    )
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = int(claim["id"])
    runner._DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
    runner._DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
    runner._DELIVERY_CONTEXT.lease_guard = guard
    try:
        with pytest.raises(KeyboardInterrupt, match="synthetic process crash"):
            runner._upload_file(b"video", "video.mp4", "mp4")
    finally:
        guard.close()
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None
        runner._DELIVERY_CONTEXT.media_submission_sha256 = ""

    assert len(observed) == 1
    assert observed[0][0] == "submitting"
    assert re.fullmatch(
        r"feishu_media_upload_request_sha256:[0-9a-f]{64}", observed[0][1]
    )
    assert runner._recover_inflight() == 1
    with runner._state_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_error,last_finish_outcome "
            "FROM feishu_inbox WHERE message_id=?",
            (payload["message_id"],),
        ).fetchone() == (
            "recovery_required",
            0,
            "media_upload_interrupted",
            "recovery_required",
        )
    assert runner._claim_inbound(now=base + 2.0) is None


def test_feishu_confirmed_inbound_upload_returns_to_processing_after_durable_handoff(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = time.time()
    payload = {
        "message_id": "media-upload-confirmed",
        "chat_id": "media-upload-confirmed-chat",
        "message_type": "text",
        "content": '{"text":"make a video"}',
        "open_id": "media-upload-confirmed-user",
    }
    assert runner._store_inbound(payload, now=base)
    claim = runner._claim_inbound(now=base)
    assert claim is not None
    guard = runner._new_inbound_claim_session(claim, clock=lambda: base + 1.0)
    assert guard.start() is True

    class AcceptedUpload:
        def create(self, _request):
            return SimpleNamespace(
                success=lambda: True,
                data=SimpleNamespace(file_key="confirmed-file-key"),
            )

    monkeypatch.setattr(
        runner,
        "_api",
        {
            "c": SimpleNamespace(
                im=SimpleNamespace(v1=SimpleNamespace(file=AcceptedUpload()))
            )
        },
    )
    monkeypatch.setattr(runner, "_reply", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(runner, "_download_url", lambda *_args: b"video")
    monkeypatch.setattr(runner, "_send_video", lambda *_args, **_kwargs: True)
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = int(claim["id"])
    runner._DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
    runner._DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
    runner._DELIVERY_CONTEXT.lease_guard = guard
    try:
        runner._send_reply(
            payload["chat_id"],
            {"reply": "created", "video": "https://media.example/video.mp4"},
        )
        with runner._state_connect() as conn:
            assert conn.execute(
                "SELECT status,last_error,terminal_verification FROM feishu_inbox "
                "WHERE message_id=?",
                (payload["message_id"],),
            ).fetchone() == ("processing", "", "")
    finally:
        guard.close()
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None
        runner._DELIVERY_CONTEXT.media_submission_sha256 = ""


def test_feishu_explicit_upload_rejection_aborts_submission_before_fallback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = time.time()
    payload = {
        "message_id": "media-upload-rejected",
        "chat_id": "media-upload-rejected-chat",
        "message_type": "text",
        "content": '{"text":"make a video"}',
        "open_id": "media-upload-rejected-user",
    }
    assert runner._store_inbound(payload, now=base)
    claim = runner._claim_inbound(now=base)
    assert claim is not None
    guard = runner._new_inbound_claim_session(claim, clock=lambda: base + 1.0)
    assert guard.start() is True

    class RejectedUpload:
        def create(self, _request):
            return SimpleNamespace(
                success=lambda: False,
                code=234_001,
                msg="synthetic rejection",
                data=None,
            )

    monkeypatch.setattr(
        runner,
        "_api",
        {
            "c": SimpleNamespace(
                im=SimpleNamespace(v1=SimpleNamespace(file=RejectedUpload()))
            )
        },
    )
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat, text, **_kwargs: (replies.append(text), True)[1],
    )
    monkeypatch.setattr(runner, "_download_url", lambda *_args: b"video")
    runner._DELIVERY_CONTEXT.message_id = payload["message_id"]
    runner._DELIVERY_CONTEXT.claim_id = int(claim["id"])
    runner._DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
    runner._DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
    runner._DELIVERY_CONTEXT.lease_guard = guard
    try:
        runner._send_reply(
            payload["chat_id"],
            {"reply": "created", "video": "https://media.example/video.mp4"},
        )
        with runner._state_connect() as conn:
            assert conn.execute(
                "SELECT status,last_error,terminal_verification FROM feishu_inbox "
                "WHERE message_id=?",
                (payload["message_id"],),
            ).fetchone() == ("processing", "", "")
        assert len(replies) == 2
    finally:
        guard.close()
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None
        runner._DELIVERY_CONTEXT.media_submission_sha256 = ""


def test_feishu_shared_inbound_session_fences_provider_and_outbox_after_loss(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_STATE_DB", tmp_path / "feishu_bridge.db")
    base = 120_000.0
    assert runner._store_inbound(
        {
            "message_id": "provider-heartbeat-message",
            "chat_id": "provider-heartbeat-chat",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "provider-heartbeat-user",
        },
        now=base,
    )
    claim = runner._claim_inbound(now=base)
    assert claim is not None
    policy_now = [base + 1.0]
    guard = runner._new_inbound_claim_session(
        claim,
        clock=lambda: policy_now[0],
    )
    assert guard.start() is True
    requests: list[str] = []

    def fake_request(_opener, **kwargs):
        requests.append(str(kwargs["url"]))
        return b'{"reply":"ok"}'

    monkeypatch.setattr(runner, "request_bridge_bytes", fake_request)
    runner._DELIVERY_CONTEXT.message_id = "provider-heartbeat-message"
    runner._DELIVERY_CONTEXT.claim_id = int(claim["id"])
    runner._DELIVERY_CONTEXT.claim_token = str(claim["claim_token"])
    runner._DELIVERY_CONTEXT.claim_epoch = int(claim["claim_epoch"])
    runner._DELIVERY_CONTEXT.lease_guard = guard
    try:
        assert runner._post("/v1/agent/chat", {"message": "hello"}) == {
            "reply": "ok"
        }
        assert claim["claim_deadline"] == base + 1.0 + runner._CLAIM_TTL_SECONDS
        assert requests == [runner.ENGINE + "/v1/agent/chat"]

        # The real worker clears its delivery context before the separate
        # durable finish transaction.  Requeue the claim through that same
        # ordering, then reinstall only the stale worker's provider guard.
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.lease_guard = None
        assert runner._finish_inbound(
            claim,
            ok=False,
            error_code="synthetic_requeue",
            now=base + 2.0,
        ) is True
        runner._DELIVERY_CONTEXT.message_id = "provider-heartbeat-message"
        runner._DELIVERY_CONTEXT.lease_guard = guard
        with pytest.raises(runner.FeishuLeaseLost, match="no longer permits commit"):
            runner._enqueue_outbox(
                "provider-heartbeat-chat",
                "text",
                '{"text":"must not persist"}',
                delivery_key="shared-session-stale-outbox",
            )
        policy_now[0] = base + 3.0
        with pytest.raises(runner.FeishuLeaseLost, match="provider_fence_lost"):
            runner._post("/v1/agent/chat", {"message": "must not run"})
        with pytest.raises(runner.FeishuLeaseLost, match="provider_fence_lost"):
            runner._post("/v1/agent/chat", {"message": "still fenced"})
        assert guard.lost is True
        assert requests == [runner.ENGINE + "/v1/agent/chat"]
        with runner._state_connect() as conn:
            assert conn.execute(
                "SELECT COUNT(*) FROM feishu_outbox WHERE delivery_uuid=?",
                (runner._stable_delivery_uuid("shared-session-stale-outbox"),),
            ).fetchone() == (0,)
    finally:
        guard.close()
        runner._DELIVERY_CONTEXT.message_id = ""
        runner._DELIVERY_CONTEXT.claim_id = 0
        runner._DELIVERY_CONTEXT.claim_token = ""
        runner._DELIVERY_CONTEXT.claim_epoch = 0
        runner._DELIVERY_CONTEXT.lease_guard = None


def test_feishu_access_file_is_strict_and_legacy_env_is_development_only(
    monkeypatch, tmp_path: Path
) -> None:
    runner = _load_runner()
    access_file = tmp_path / "feishu_access.json"
    monkeypatch.setattr(runner, "_ACCESS_FILE", access_file)
    monkeypatch.setattr(runner.S, "feishu_allowed_users", "legacy-user")
    monkeypatch.setattr(runner.S, "feishu_owner_open_id", "legacy-owner")
    access_file.write_text(
        json.dumps(
            {
                "schema": "nachuan.feishu-access.v1",
                "allowed_users": ["file-user"],
                "owner": "file-owner",
            }
        ),
        "utf-8",
    )

    monkeypatch.setenv("NACHUAN_ENV", "production")
    allowed, owner = runner._load_feishu_access()
    assert allowed == frozenset({"file-user"})
    assert owner == "file-owner"

    monkeypatch.setenv("NACHUAN_ENV", "development")
    allowed, owner = runner._load_feishu_access()
    assert allowed == frozenset({"file-user", "legacy-user", "legacy-owner"})
    assert owner == "file-owner"

    access_file.write_bytes(b"{" + (b"x" * (64 * 1024)))
    monkeypatch.setenv("NACHUAN_ENV", "production")
    assert runner._load_feishu_access() == (frozenset(), "")

    target = tmp_path / "access-target.json"
    target.write_text(
        '{"schema":"nachuan.feishu-access.v1","allowed_users":[],"owner":"x"}',
        "utf-8",
    )
    try:
        access_file.unlink()
        access_file.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable in this Windows environment")
    assert runner._load_feishu_access() == (frozenset(), "")


def test_feishu_locked_whoami_never_calls_model(monkeypatch, tmp_path: Path) -> None:
    runner = _load_runner()
    monkeypatch.setattr(runner, "_ACCESS_FILE", tmp_path / "missing-access.json")
    monkeypatch.setenv("NACHUAN_ENV", "production")
    replies: list[str] = []
    monkeypatch.setattr(
        runner,
        "_reply",
        lambda _chat_id, text, **_kwargs: replies.append(text) or True,
    )
    monkeypatch.setattr(
        runner,
        "_agent_chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("locked /whoami called model")
        ),
    )
    limiter_calls: list[str] = []

    def allow_once(open_id: str) -> bool:
        limiter_calls.append(open_id)
        return len(limiter_calls) == 1

    monkeypatch.setattr(runner, "_allow_inbound", allow_once)
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="whoami-message",
                chat_id="locked-chat",
                message_type="text",
                content='{"text":"/whoami"}',
            ),
            sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="locked-user")),
        )
    )
    runner._handle_message(event)
    runner._handle_message(event)
    assert limiter_calls == ["locked-user", "locked-user"]
    assert len(replies) == 2
    assert "locked-user" in replies[0]
    assert "locked-user" not in replies[1]
