from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import urllib.error
import urllib.parse
from contextlib import contextmanager, nullcontext

import pytest

from bridge.access import ChannelAccessPolicy


def _load_bridge():
    path = Path(__file__).parents[1] / "scripts" / "run_weixin_ilink_bridge.py"
    spec = importlib.util.spec_from_file_location("run_weixin_ilink_bridge", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _replace_access(path: Path, users: list[str], owner: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(
            {
                "schema": "nachuan.weixin-access.v1",
                "allowed_users": users,
                "owner": owner,
            }
        ),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _create_weixin_state_v0(database: Path) -> None:
    statements = (
        """CREATE TABLE pending_delivery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        text TEXT NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending'
    )""",
        """CREATE TABLE inbound_message (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL UNIQUE,
        from_user_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        received_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT NOT NULL DEFAULT ''
    )""",
        """CREATE TABLE bridge_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    )""",
        """CREATE TABLE pending_video (
        task_id TEXT PRIMARY KEY,
        to_user_id TEXT NOT NULL,
        context_token TEXT NOT NULL,
        source_message_key TEXT NOT NULL,
        created_at REAL NOT NULL,
        deadline_at REAL NOT NULL,
        next_attempt_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        result_url TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT '',
        claim_token TEXT NOT NULL DEFAULT '',
        claimed_at REAL NOT NULL DEFAULT 0,
        finished_at REAL NOT NULL DEFAULT 0
    )""",
    )
    with sqlite3.connect(database) as conn:
        for statement in statements:
            conn.execute(statement)


def _create_weixin_state_previous_runtime_v0(database: Path) -> None:
    statements = (
        """CREATE TABLE IF NOT EXISTS pending_delivery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            to_user_id TEXT NOT NULL,
            context_token TEXT NOT NULL,
            text TEXT NOT NULL,
            last_error TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            delivery_id TEXT NOT NULL DEFAULT '',
            client_id TEXT NOT NULL DEFAULT '',
            chunk_index INTEGER NOT NULL DEFAULT 0,
            chunk_count INTEGER NOT NULL DEFAULT 1,
            claim_token TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0,
            delivered_at REAL NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS inbound_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key TEXT NOT NULL UNIQUE,
            from_user_id TEXT NOT NULL,
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
            request_sha256 TEXT NOT NULL DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS bridge_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at REAL NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS pending_video (
            task_id TEXT PRIMARY KEY,
            to_user_id TEXT NOT NULL,
            context_token TEXT NOT NULL,
            source_message_key TEXT NOT NULL,
            created_at REAL NOT NULL,
            deadline_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            result_url TEXT NOT NULL DEFAULT '',
            direct_attempted INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            claim_token TEXT NOT NULL DEFAULT '',
            claimed_at REAL NOT NULL DEFAULT 0,
            finished_at REAL NOT NULL DEFAULT 0
        )""",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_delivery_chunk "
        "ON pending_delivery(delivery_id, chunk_index) WHERE delivery_id <> ''",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_delivery_client "
        "ON pending_delivery(client_id) WHERE client_id <> ''",
        "CREATE INDEX IF NOT EXISTS idx_pending_delivery_claim "
        "ON pending_delivery(status, next_attempt_at, id)",
        "CREATE INDEX IF NOT EXISTS idx_pending_delivery_chat_order "
        "ON pending_delivery(to_user_id, status, id)",
        "CREATE INDEX IF NOT EXISTS idx_inbound_message_claim "
        "ON inbound_message(status, next_attempt_at, claim_deadline, id)",
        "CREATE INDEX IF NOT EXISTS idx_pending_video_claim "
        "ON pending_video(status, next_attempt_at, created_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_video_source "
        "ON pending_video(source_message_key)",
    )
    with sqlite3.connect(database) as conn:
        for statement in statements:
            conn.execute(statement)


class _TestInboundLeaseSession:
    lost = False

    @staticmethod
    def before_provider() -> bool:
        return True

    @staticmethod
    def commit_fence():
        return nullcontext()


@contextmanager
def _claimed_inbound_context(bridge, message: dict):
    assert bridge._store_updates(
        [message], f"test-cursor:{bridge._message_key(message)}"
    ) is True
    claimed = bridge._claim_inbound()
    assert claimed is not None
    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = bridge._message_key(message)
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        yield claimed
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)


def test_async_video_task_is_durable_before_weixin_acknowledgement(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    state_db = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", state_db)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-1"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(
        bridge,
        "_agent_chat",
        lambda *_args, **_kwargs: {
            "reply": "视频任务已创建",
            "video_task": "video-task-1",
        },
    )
    acknowledgements: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: acknowledgements.append(text)
        or True,
    )

    message = {
        "message_id": "message-1",
        "from_user_id": "wx-user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "生成一段视频"}}],
    }
    with _claimed_inbound_context(bridge, message):
        bridge._handle(message, "bot-token")

    with sqlite3.connect(state_db) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pending_video'"
        ).fetchone()
        assert table is not None
        row = conn.execute(
            "SELECT task_id,to_user_id,context_token,status FROM pending_video"
        ).fetchone()
    assert row == ("video-task-1", "wx-user-1", "context-1", "pending")
    assert acknowledgements[-1] == "视频任务已创建"
    assert acknowledgements in (
        ["视频任务已创建"],
        ["收到，正在处理中；完成后会继续回复你。", "视频任务已创建"],
    )


def test_async_video_queue_is_bounded_idempotent_and_chat_scoped(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    assert bridge._enqueue_pending_video(
        "video-task-1",
        "wx-user-1",
        "context-1",
        source_message_key="wxmsg-v1:one",
        now=1000.0,
        _internal_maintenance=True,
    ) is True
    assert bridge._enqueue_pending_video(
        "video-task-1",
        "wx-user-1",
        "context-1",
        source_message_key="wxmsg-v1:one",
        now=1001.0,
        _internal_maintenance=True,
    ) is False
    with pytest.raises(RuntimeError, match="另一会话冲突"):
        bridge._enqueue_pending_video(
            "video-task-1",
            "wx-user-2",
            "context-2",
            source_message_key="wxmsg-v1:two",
            now=1001.0,
            _internal_maintenance=True,
        )
    with pytest.raises(RuntimeError, match="容量已耗尽"):
        bridge._enqueue_pending_video(
            "video-task-2",
            "wx-user-2",
            "context-2",
            source_message_key="wxmsg-v1:two",
            now=1001.0,
            _internal_maintenance=True,
        )


def test_async_video_queue_has_a_per_user_fairness_budget(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 4)
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_PER_USER", 1, raising=False)
    assert bridge._enqueue_pending_video(
        "video-task-user-1",
        "wx-user-1",
        "context-1",
        source_message_key="wxmsg-v1:user-1",
        now=1000.0,
        _internal_maintenance=True,
    ) is True
    with pytest.raises(RuntimeError, match="单用户.*容量"):
        bridge._enqueue_pending_video(
            "video-task-user-2",
            "wx-user-1",
            "context-1",
            source_message_key="wxmsg-v1:user-2",
            now=1001.0,
            _internal_maintenance=True,
        )
    assert bridge._enqueue_pending_video(
        "video-task-other-user",
        "wx-user-2",
        "context-2",
        source_message_key="wxmsg-v1:other-user",
        now=1001.0,
        _internal_maintenance=True,
    ) is True


def test_full_video_capacity_fast_rejects_video_without_creating_an_upstream_task(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    bridge._enqueue_pending_video(
        "already-running-video",
        "wx-user-existing",
        "existing-context",
        source_message_key="wxmsg-v1:existing",
        now=1000.0,
        _internal_maintenance=True,
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-new"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    agent_calls = 0
    capacity_flags: list[bool] = []

    def capacity_aware_agent(*_args, **kwargs):
        nonlocal agent_calls
        agent_calls += 1
        capacity_flags.append(kwargs["video_async_capacity_available"])
        return {
            "reply": "当前异步视频队列已满，本次没有创建视频任务。",
            "video_rejected": "capacity",
        }

    monkeypatch.setattr(bridge, "_agent_chat", capacity_aware_agent)
    replies: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: replies.append(text) or True,
    )

    message = {
        "message_id": "new-message",
        "from_user_id": "wx-user-new",
        "context_token": "new-context",
        "item_list": [{"type": 1, "text_item": {"text": "生成视频"}}],
    }
    with _claimed_inbound_context(bridge, message):
        assert bridge._handle_safe(message, "bot-token") is True
    assert agent_calls == 1
    assert capacity_flags == [False]
    assert replies == ["当前异步视频队列已满，本次没有创建视频任务。"]
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT task_id,status FROM pending_video ORDER BY task_id"
        ).fetchall() == [("already-running-video", "pending")]


def test_full_video_capacity_does_not_block_ordinary_chat(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    bridge._enqueue_pending_video(
        "already-running-video",
        "wx-user-existing",
        "existing-context",
        source_message_key="wxmsg-v1:existing",
        now=1000.0,
        _internal_maintenance=True,
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-chat"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)

    def ordinary_chat(*_args, **kwargs):
        assert kwargs["video_async_capacity_available"] is False
        return {"reply": "你好！"}

    monkeypatch.setattr(bridge, "_agent_chat", ordinary_chat)
    replies: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: replies.append(text) or True,
    )

    message = {
        "message_id": "ordinary-message",
        "from_user_id": "wx-user-chat",
        "context_token": "chat-context",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    with _claimed_inbound_context(bridge, message):
        assert bridge._handle_safe(message, "bot-token") is True
    assert replies == ["你好！"]
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT task_id,status FROM pending_video ORDER BY task_id"
        ).fetchall() == [("already-running-video", "pending")]


def test_progress_delivery_cannot_overtake_the_final_reply(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-order"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)

    progress_started = threading.Event()
    release_progress = threading.Event()
    progress_finished = threading.Event()
    delivery_order: list[str] = []

    def delayed_progress(*_args, **_kwargs):
        progress_started.set()
        assert release_progress.wait(1.0)
        delivery_order.append("progress")
        progress_finished.set()

    def fast_agent(*_args, **_kwargs):
        assert progress_started.wait(1.0)
        return {"reply": "最终答案"}

    def release_video_reservation(*_args, **_kwargs):
        timer = threading.Timer(0.2, release_progress.set)
        timer.daemon = True
        timer.start()
        return True

    def record_delivery(_token, _to, _ctx, text, **_kwargs):
        delivery_order.append("final" if text == "最终答案" else "other")
        return True

    monkeypatch.setattr(bridge, "_progress_notice", delayed_progress)
    monkeypatch.setattr(bridge, "_agent_chat", fast_agent)
    monkeypatch.setattr(
        bridge, "_release_pending_video_reservation", release_video_reservation
    )
    monkeypatch.setattr(bridge, "_deliver_text", record_delivery)

    message = {
        "message_id": "ordered-message",
        "from_user_id": "wx-user-order",
        "context_token": "ordered-context",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    with _claimed_inbound_context(bridge, message):
        assert bridge._handle_safe(message, "bot-token") is True
    assert progress_finished.wait(2.0)
    assert delivery_order == ["progress", "final"]


def test_hung_provider_gets_a_durable_first_ack_within_three_seconds(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    # Exercise the strict 3-second SLA with the supported one-second policy;
    # the outer wall-clock allowance then measures delivery work, not scheduler
    # jitter around a two-second policy timer on a loaded Windows test host.
    monkeypatch.setenv("WEIXIN_PROGRESS_AFTER_SECONDS", "1")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-first-ack"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    provider_started = threading.Event()
    release_provider = threading.Event()
    first_ack = threading.Event()
    sent: list[str] = []

    def hung_provider(*_args, **_kwargs):
        provider_started.set()
        assert release_provider.wait(10.0)
        return {"reply": "最终回复"}

    def send(_token, _to, _ctx, text, _client_id):
        sent.append(text)
        if text.startswith("收到，正在处理中"):
            first_ack.set()
        return True

    monkeypatch.setattr(bridge, "_agent_chat", hung_provider)
    monkeypatch.setattr(bridge, "_send_chunk", send)
    # Keep the feedback loop about provider-to-first-ACK latency, not one-time
    # SQLite schema materialization on a busy Windows test host.
    with bridge._outbox_connect():
        pass
    failures: list[BaseException] = []
    message = {
        "message_id": "first-ack-hung-provider",
        "from_user_id": "wx-user-first-ack",
        "context_token": "first-ack-context",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }

    def run_handler() -> None:
        try:
            with _claimed_inbound_context(bridge, message):
                bridge._handle(message, "bot-token")
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    worker = threading.Thread(target=run_handler)
    worker.start()
    assert provider_started.wait(5.0)
    try:
        acknowledged = first_ack.wait(3.0)
    finally:
        release_provider.set()
        worker.join(10.0)

    assert acknowledged is True
    assert not worker.is_alive()
    assert failures == []
    assert sent[:2] == [
        "收到，正在处理中；完成后会继续回复你。",
        "最终回复",
    ]


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("999", 5.0), ("nan", 2.0), ("-10", 1.0)],
)
def test_first_ack_delay_configuration_cannot_recreate_a_silent_window(
    monkeypatch, configured, expected
):
    bridge = _load_bridge()
    monkeypatch.setenv("WEIXIN_PROGRESS_AFTER_SECONDS", configured)
    waits: list[float] = []

    class AlreadyDone:
        def wait(self, delay):
            waits.append(delay)
            return True

    bridge._progress_notice(
        AlreadyDone(),
        "bot-token",
        "user-1",
        "context-1",
        "message-1:progress",
    )

    assert waits == [expected]


def test_progress_response_loss_blocks_final_reply_without_automatic_replay(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setenv("WEIXIN_PROGRESS_AFTER_SECONDS", "1")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-progress"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)

    progress_attempted = threading.Event()
    sent: list[tuple[str, str]] = []

    def send_with_one_progress_failure(
        _token, _to_user_id, _context_token, text, client_id
    ):
        sent.append((text, client_id))
        if text.startswith("收到，正在处理中") and not progress_attempted.is_set():
            progress_attempted.set()
            raise OSError("progress response lost")
        return True

    def finish_after_progress(*_args, **_kwargs):
        assert progress_attempted.wait(10.0)
        return {"reply": "最终答案"}

    monkeypatch.setattr(bridge, "_send_chunk", send_with_one_progress_failure)
    monkeypatch.setattr(bridge, "_agent_chat", finish_after_progress)

    message = {
        "message_id": "progress-retry-message",
        "from_user_id": "wx-user-progress",
        "context_token": "progress-context",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    with _claimed_inbound_context(bridge, message):
        assert bridge._handle_safe(message, "bot-token") is True
    assert [text for text, _client_id in sent] == [
        "收到，正在处理中；完成后会继续回复你。"
    ]

    assert bridge._drain_outbox("bot-token", now=10**12, limit=2) == 0
    assert [text for text, _client_id in sent] == [
        "收到，正在处理中；完成后会继续回复你。"
    ]
    with bridge._outbox_connect() as conn:
        statuses = conn.execute(
            "SELECT status FROM pending_delivery ORDER BY chat_seq,id"
        ).fetchall()
    assert statuses == [("recovery_required",), ("pending",)]


def test_abandoned_video_reservation_expires_and_releases_capacity(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    monkeypatch.setattr(bridge, "_VIDEO_RESERVATION_TTL_SECONDS", 10.0)
    first = bridge._reserve_pending_video_capacity(
        "wx-user-crashed",
        "crashed-context",
        source_message_key="wxmsg-v1:crashed-reservation",
        now=1000.0,
        _internal_maintenance=True,
    )
    assert first.startswith("reservation:")

    second = bridge._reserve_pending_video_capacity(
        "wx-user-next",
        "next-context",
        source_message_key="wxmsg-v1:next-reservation",
        now=1011.0,
        _internal_maintenance=True,
    )
    assert second.startswith("reservation:")
    assert second != first
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT task_id,to_user_id,status FROM pending_video"
        ).fetchall() == [(second, "wx-user-next", "reserved")]


def test_inbound_video_reservation_crossing_claim_deadline_rolls_back_atomically(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "video-reserve-deadline",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "make a video"}}],
    }
    claimed_at = 10**12
    assert bridge._store_updates([message], "cursor-video-reserve") is True
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    clock = {"value": deadline - 1.0}
    real_connect = bridge._outbox_connect

    def hooked_connect():
        conn = real_connect()
        conn._nachuan_begin_immediate_hook = lambda: clock.update(value=deadline)
        return conn

    monkeypatch.setattr(bridge, "_outbox_connect", hooked_connect)
    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = bridge._message_key(message)
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._reserve_pending_video_capacity(
                "user-1",
                "context-1",
                source_message_key=bridge._message_key(message),
                now=lambda: clock["value"],
            )
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)

    with real_connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM pending_video").fetchone()[0] == 0


def test_inbound_video_reservation_rolls_back_cleanup_when_deadline_crosses_before_insert(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    claimed_at = 10**12
    old_source = "wxmsg-v1:expired-video-reservation"
    old_reservation = bridge._reserve_pending_video_capacity(
        "old-user",
        "old-context",
        source_message_key=old_source,
        now=claimed_at - bridge._VIDEO_RESERVATION_TTL_SECONDS - 10.0,
        _internal_maintenance=True,
    )
    message = {
        "message_id": "video-reserve-mid-transaction-deadline",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "make a video"}}],
    }
    source = bridge._message_key(message)
    assert bridge._store_updates([message], "cursor-video-reserve-mid-tx") is True
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    clock = iter([deadline - 1.0, deadline - 1.0, deadline])
    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = source
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._reserve_pending_video_capacity(
                "user-1",
                "context-1",
                source_message_key=source,
                now=lambda: next(clock),
            )
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)

    with bridge._outbox_connect() as conn:
        rows = conn.execute(
            "SELECT task_id,status,source_message_key FROM pending_video"
        ).fetchall()
    assert rows == [(old_reservation, "reserved", old_source)]


def test_inbound_video_promotion_crossing_claim_deadline_keeps_reservation(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "video-promote-deadline",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "make a video"}}],
    }
    source = bridge._message_key(message)
    claimed_at = 10**12
    assert bridge._store_updates([message], "cursor-video-promote") is True
    reservation_id = bridge._reserve_pending_video_capacity(
        "user-1",
        "context-1",
        source_message_key=source,
        now=claimed_at,
        _internal_maintenance=True,
    )
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    clock = iter([deadline - 1.0, deadline - 1.0, deadline])
    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = source
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._enqueue_pending_video(
                "upstream-video-task",
                "user-1",
                "context-1",
                source_message_key=source,
                now=lambda: next(clock),
            )
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)

    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT task_id,status,source_message_key FROM pending_video"
        ).fetchone()
    assert row == (reservation_id, "reserved", source)


def test_inbound_video_release_crossing_claim_deadline_keeps_reservation(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "video-release-deadline",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "ordinary chat"}}],
    }
    source = bridge._message_key(message)
    claimed_at = 10**12
    assert bridge._store_updates([message], "cursor-video-release") is True
    reservation_id = bridge._reserve_pending_video_capacity(
        "user-1",
        "context-1",
        source_message_key=source,
        now=claimed_at,
        _internal_maintenance=True,
    )
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    clock = {"value": deadline - 1.0}
    real_connect = bridge._outbox_connect

    def hooked_connect():
        conn = real_connect()
        conn._nachuan_begin_immediate_hook = lambda: clock.update(value=deadline)
        return conn

    monkeypatch.setattr(bridge, "_outbox_connect", hooked_connect)
    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = source
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._release_pending_video_reservation(
                source,
                now=lambda: clock["value"],
            )
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)

    with real_connect() as conn:
        row = conn.execute("SELECT task_id,status FROM pending_video").fetchone()
    assert row == (reservation_id, "reserved")


def test_pending_video_mutations_require_live_inbound_or_explicit_maintenance(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    source = "wxmsg-v1:explicit-maintenance"

    with pytest.raises(
        bridge.InboundFinishFenceLost, match="pending_video_inbound_fence_required"
    ):
        bridge._reserve_pending_video_capacity(
            "user-1", "context-1", source_message_key=source, now=1000.0
        )
    reservation = bridge._reserve_pending_video_capacity(
        "user-1",
        "context-1",
        source_message_key=source,
        now=1000.0,
        _internal_maintenance=True,
    )

    with pytest.raises(
        bridge.InboundFinishFenceLost, match="pending_video_inbound_fence_required"
    ):
        bridge._enqueue_pending_video(
            "video-task-maintenance",
            "user-1",
            "context-1",
            source_message_key=source,
            now=1001.0,
        )
    assert bridge._enqueue_pending_video(
        "video-task-maintenance",
        "user-1",
        "context-1",
        source_message_key=source,
        now=1001.0,
        _internal_maintenance=True,
    ) is True

    release_source = "wxmsg-v1:explicit-maintenance-release"
    release_reservation = bridge._reserve_pending_video_capacity(
        "user-1",
        "context-1",
        source_message_key=release_source,
        now=1002.0,
        _internal_maintenance=True,
    )
    active_message = {
        "message_id": "maintenance-cannot-bypass-live-inbound",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "ordinary chat"}}],
    }
    with _claimed_inbound_context(bridge, active_message):
        with pytest.raises(
            RuntimeError,
            match="inbound video mutation cannot bypass its claim fence",
        ):
            bridge._release_pending_video_reservation(
                release_source,
                now=1003.0,
                _internal_maintenance=True,
            )
    with pytest.raises(
        bridge.InboundFinishFenceLost, match="pending_video_inbound_fence_required"
    ):
        bridge._release_pending_video_reservation(release_source, now=1003.0)
    assert bridge._release_pending_video_reservation(
        release_source,
        now=1003.0,
        _internal_maintenance=True,
    ) is True
    assert reservation.startswith("reservation:")
    assert release_reservation.startswith("reservation:")


def test_inbound_video_mutation_cannot_cross_turn_source(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    other_source = "wxmsg-v1:" + ("b" * 64)
    reservation = bridge._reserve_pending_video_capacity(
        "user-1",
        "other-context",
        source_message_key=other_source,
        _internal_maintenance=True,
    )
    active_message = {
        "message_id": "active-turn-cannot-mutate-other-video",
        "from_user_id": "user-1",
        "context_token": "active-context",
        "item_list": [{"type": 1, "text_item": {"text": "ordinary chat"}}],
    }

    with _claimed_inbound_context(bridge, active_message):
        with pytest.raises(
            bridge.InboundFinishFenceLost,
            match="pending_video_source_fence_lost",
        ):
            bridge._release_pending_video_reservation(other_source)

    conn = bridge._outbox_connect()
    try:
        assert conn.execute(
            "SELECT task_id,status FROM pending_video WHERE source_message_key=?",
            (other_source,),
        ).fetchone() == (reservation, "reserved")
    finally:
        conn.close()


@pytest.mark.parametrize("operation", ["reserve", "promote", "release"])
def test_inbound_video_mutation_rolls_back_if_sticky_loss_arrives_at_sql(
    monkeypatch, tmp_path, operation
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    active_message = {
        "message_id": f"video-sticky-loss-{operation}",
        "from_user_id": "user-1",
        "context_token": "active-context",
        "item_list": [{"type": 1, "text_item": {"text": "video"}}],
    }
    source = bridge._message_key(active_message)
    reservation = None
    if operation != "reserve":
        reservation = bridge._reserve_pending_video_capacity(
            "user-1",
            "active-context",
            source_message_key=source,
            _internal_maintenance=True,
        )

    class StickySqlLease:
        lost = False
        commit_fence_entries = 0

        @contextmanager
        def commit_fence(self):
            self.commit_fence_entries += 1
            yield

    lease = StickySqlLease()
    real_connect = bridge._outbox_connect

    def hooked_connect():
        conn = real_connect()

        def lose_at_mutation(statement):
            normalized = " ".join(statement.upper().split())
            targets = {
                "reserve": "INSERT INTO PENDING_VIDEO",
                "promote": "UPDATE PENDING_VIDEO SET TASK_ID=",
                "release": "DELETE FROM PENDING_VIDEO WHERE SOURCE_MESSAGE_KEY=",
            }
            if normalized.startswith(targets[operation]):
                lease.lost = True

        conn.set_trace_callback(lose_at_mutation)
        return conn

    with _claimed_inbound_context(bridge, active_message):
        bridge._HANDLE_CONTEXT.lease_session = lease
        monkeypatch.setattr(bridge, "_outbox_connect", hooked_connect)
        with pytest.raises(
            bridge.InboundFinishFenceLost,
            match="inbound_outbox_fence_lost",
        ):
            if operation == "reserve":
                bridge._reserve_pending_video_capacity(
                    "user-1",
                    "active-context",
                    source_message_key=source,
                )
            elif operation == "promote":
                bridge._enqueue_pending_video(
                    "upstream-task",
                    "user-1",
                    "active-context",
                    source_message_key=source,
                )
            else:
                bridge._release_pending_video_reservation(source)

    assert lease.commit_fence_entries == 1
    conn = real_connect()
    try:
        rows = conn.execute(
            "SELECT task_id,status FROM pending_video WHERE source_message_key=?",
            (source,),
        ).fetchall()
    finally:
        conn.close()
    if operation == "reserve":
        assert rows == []
    else:
        assert rows == [(reservation, "reserved")]


def test_video_capacity_reservation_survives_retry_and_converts_to_same_task(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-retry"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    attempts = 0

    def replayable_agent(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("response lost after durable Turn started")
        return {"reply": "视频任务已恢复", "video_task": "video-task-replayed"}

    monkeypatch.setattr(bridge, "_agent_chat", replayable_agent)
    replies: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: replies.append(text) or True,
    )
    message = {
        "message_id": "retry-message",
        "from_user_id": "wx-user-retry",
        "context_token": "retry-context",
        "item_list": [{"type": 1, "text_item": {"text": "生成视频"}}],
    }

    with _claimed_inbound_context(bridge, message):
        assert bridge._handle_safe(message, "bot-token") is False
        with bridge._outbox_connect() as conn:
            reserved = conn.execute(
                "SELECT status,source_message_key FROM pending_video"
            ).fetchall()
        assert reserved == [("reserved", bridge._message_key(message))]

        assert bridge._handle_safe(message, "bot-token") is True
    with bridge._outbox_connect() as conn:
        converted = conn.execute(
            "SELECT task_id,status,source_message_key FROM pending_video"
        ).fetchall()
    assert converted == [
        ("video-task-replayed", "pending", bridge._message_key(message))
    ]
    assert replies == ["视频任务已恢复"]


def test_async_video_result_is_recovered_and_delivered_once_after_restart(
    monkeypatch, tmp_path
):
    state_db = tmp_path / "weixin_state.db"
    first = _load_bridge()
    monkeypatch.setattr(first, "_OUTBOX_DB", state_db)
    first._enqueue_pending_video(
        "video-task-restart",
        "wx-user-restart",
        "context-restart",
        source_message_key="wxmsg-v1:restart",
        now=1000.0,
        _internal_maintenance=True,
    )
    with first._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET status='processing',claim_token='crashed',"
            "claimed_at=1000 WHERE task_id='video-task-restart'"
        )

    restarted = _load_bridge()
    monkeypatch.setattr(restarted, "_OUTBOX_DB", state_db)
    assert restarted._recover_pending_video_claims(force=True) == 1
    monkeypatch.setattr(
        restarted,
        "_engine_get_json",
        lambda _path, **_kwargs: {
            "status": "succeeded",
            "data": {"output_url": "https://media.example/result.mp4"},
        },
    )
    monkeypatch.setattr(
        restarted,
        "_fetch_media",
        lambda url, kind: b"verified-mp4" if (url, kind) == (
            "https://media.example/result.mp4",
            "video",
        ) else (_ for _ in ()).throw(AssertionError("wrong media request")),
    )
    delivered: list[tuple[str, str, str, bytes, str, str]] = []
    monkeypatch.setattr(
        restarted,
        "_send_media",
        lambda token, to, ctx, data, kind, *, client_id: delivered.append(
            (token, to, ctx, data, kind, client_id)
        )
        or True,
    )

    assert restarted._drain_pending_videos("new-bot-token", limit=1, now=1001.0) == 1
    assert delivered == [
        (
            "new-bot-token",
            "wx-user-restart",
            "context-restart",
            b"verified-mp4",
            "video",
            delivered[0][5],
        )
    ]
    assert delivered[0][5].startswith("nachuan_video_task_")
    assert restarted._drain_pending_videos("new-bot-token", limit=1, now=1002.0) == 0
    assert len(delivered) == 1
    with restarted._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,result_url,claim_token FROM pending_video "
            "WHERE task_id='video-task-restart'"
        ).fetchone()
    assert row == ("done", "https://media.example/result.mp4", "")


def test_pending_video_claim_uses_epoch_deadline_and_fences_old_worker(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-lease",
        "wx-user-lease",
        "context-lease",
        source_message_key="wxmsg-v1:lease",
        now=1000.0,
        _internal_maintenance=True,
    )

    first = bridge._claim_pending_video(now=1001.0)
    assert first is not None
    assert first["claim_epoch"] == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token,claim_epoch,claimed_at,claim_deadline,heartbeat_at "
            "FROM pending_video WHERE task_id=?",
            ("video-task-lease",),
        ).fetchone() == (
            "processing",
            first["claim_token"],
            1,
            1001.0,
            1001.0 + bridge._VIDEO_CLAIM_TTL_SECONDS,
            1001.0,
        )

    assert bridge._renew_pending_video_claim(first, now=1002.0) is True
    assert bridge._recover_pending_video_claims(
        now=1002.0 + bridge._VIDEO_CLAIM_TTL_SECONDS + 1
    ) == 1
    second = bridge._claim_pending_video(
        now=1002.0 + bridge._VIDEO_CLAIM_TTL_SECONDS + 2
    )
    assert second is not None
    assert second["claim_epoch"] == 2
    assert bridge._store_pending_video_result(
        first,
        "https://media.example/stale.mp4",
        now=1002.0 + bridge._VIDEO_CLAIM_TTL_SECONDS + 2,
    ) is False
    assert bridge._finish_pending_video(
        first,
        terminal=True,
        now=1002.0 + bridge._VIDEO_CLAIM_TTL_SECONDS + 2,
    ) is False


def test_pending_video_finish_response_loss_uses_exact_receipt_and_one_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    base = time.time()
    bridge._enqueue_pending_video(
        "video-task-finish-receipt",
        "wx-user-finish-receipt",
        "context-finish-receipt",
        source_message_key="wxmsg-v1:finish-receipt",
        now=base,
        _internal_maintenance=True,
    )
    claim = bridge._claim_pending_video(now=base)
    assert claim is not None
    session = bridge._new_pending_video_lease_session(claim)
    assert session.start() is True
    real_finish = bridge._commit_pending_video_finish
    real_confirm = bridge._pending_video_finish_was_committed
    deadlines: dict[str, float] = {}

    def commit_then_lose_response(*args, deadline_monotonic, **kwargs):
        deadlines["finish"] = deadline_monotonic
        assert real_finish(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        ) is True
        raise sqlite3.OperationalError("synthetic video finish response loss")

    def confirm(*args, deadline_monotonic, **kwargs):
        deadlines["confirm"] = deadline_monotonic
        return real_confirm(
            *args,
            deadline_monotonic=deadline_monotonic,
            **kwargs,
        )

    monkeypatch.setattr(bridge, "_commit_pending_video_finish", commit_then_lose_response)
    monkeypatch.setattr(bridge, "_pending_video_finish_was_committed", confirm)
    outcome = bridge._PendingVideoFinishRequest(terminal=False, now=base)
    try:
        assert session.finish(outcome) is True
    finally:
        session.close()

    assert deadlines["finish"] == deadlines["confirm"]
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM pending_video WHERE task_id=?",
            ("video-task-finish-receipt",),
        ).fetchone() == (
            "pending",
            claim["claim_token"],
            claim["claim_epoch"],
            "pending",
        )


def test_pending_video_finish_samples_policy_time_at_commit_boundary(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    base = 10_000.0
    bridge._enqueue_pending_video(
        "video-task-finish-clock",
        "wx-user-finish-clock",
        "context-finish-clock",
        source_message_key="wxmsg-v1:finish-clock",
        now=base,
        _internal_maintenance=True,
    )
    claim = bridge._claim_pending_video(now=base)
    assert claim is not None
    policy_now = [base]
    session = bridge._new_pending_video_lease_session(
        claim, clock=lambda: policy_now[0]
    )
    assert session.start() is True
    policy_now[0] = base + bridge._VIDEO_CLAIM_TTL_SECONDS + 1
    try:
        assert session.finish(
            bridge._PendingVideoFinishRequest(terminal=False, now=base)
        ) is False
    finally:
        session.close()
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token,last_finish_outcome FROM pending_video "
            "WHERE task_id='video-task-finish-clock'"
        ).fetchone() == ("processing", claim["claim_token"], "")

def test_pending_video_drain_uses_its_own_lease_and_finish_receipt(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    base = time.time()
    bridge._enqueue_pending_video(
        "video-task-drain-lease",
        "wx-user-drain-lease",
        "context-drain-lease",
        source_message_key="wxmsg-v1:drain-lease",
        now=base,
        _internal_maintenance=True,
    )
    monkeypatch.setattr(
        bridge,
        "_engine_get_json",
        lambda *_args, **_kwargs: {"status": "processing"},
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=base) == 1
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,claim_token,claim_epoch,claim_deadline,heartbeat_at,"
            "last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM pending_video WHERE task_id=?",
            ("video-task-drain-lease",),
        ).fetchone()
    assert row[0:2] == ("pending", "")
    assert row[2] == 1
    assert row[3:5] == (0.0, 0.0)
    assert row[5]
    assert row[6:] == (1, "pending")


def test_persisted_video_result_is_delivered_even_after_generation_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-finished-before-crash",
        "wx-user-finished",
        "context-finished",
        source_message_key="wxmsg-v1:finished",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET result_url=?,deadline_at=?,next_attempt_at=? "
            "WHERE task_id=?",
            (
                "https://media.example/finished.mp4",
                2000.0,
                2000.0,
                "video-task-finished-before-crash",
            ),
        )
    monkeypatch.setattr(
        bridge,
        "_engine_get_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("persisted result must not be polled again")
        ),
    )
    monkeypatch.setattr(bridge, "_fetch_media", lambda _url, _kind: b"mp4")
    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_media",
        lambda _token, _to, _ctx, _data, _kind, *, client_id: sent.append(client_id)
        or True,
    )
    notices: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: notices.append(text) or True,
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=2001.0) == 1
    assert len(sent) == 1
    assert notices == []


def test_pending_video_real_media_sender_acceptance_does_not_fall_back(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-real-media-success",
        "wx-user-real-media-success",
        "context-real-media-success",
        source_message_key="wxmsg-v1:real-media-success",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET result_url=? WHERE task_id=?",
            (
                "https://media.example/real-media-success.mp4",
                "video-task-real-media-success",
            ),
        )

    monkeypatch.setattr(bridge, "_fetch_media", lambda _url, _kind: b"mp4")
    send_calls: list[dict] = []

    def accepted_send(method, path, body=None, token="", timeout=None):
        assert method == "POST"
        assert token == "bot-token"
        if path == "/ilink/bot/getuploadurl":
            assert timeout == 40
            return {
                "upload_full_url": (
                    "https://novac2c.cdn.weixin.qq.com/c2c?real-success=1"
                )
            }
        assert (path, timeout) == ("/ilink/bot/sendmessage", 60)
        send_calls.append(body)
        return {}

    monkeypatch.setattr(bridge, "_ilink", accepted_send)
    monkeypatch.setattr(
        bridge,
        "request_public_bytes",
        lambda *_args, **_kwargs: SimpleNamespace(
            headers={"x-encrypted-param": "opaque-query"}
        ),
    )
    real_send_media = bridge._send_media
    send_results: list[object] = []

    def observed_real_send(*args, **kwargs):
        result = real_send_media(*args, **kwargs)
        send_results.append(result)
        return result

    monkeypatch.setattr(bridge, "_send_media", observed_real_send)
    fallbacks: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallbacks.append(text) or True,
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=1001.0) == 1
    assert send_results == [True]
    assert len(send_calls) == 1
    assert fallbacks == []
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,last_error,submission_phase,"
            "length(upload_grant_request_sha256),length(upload_request_sha256),"
            "length(send_request_sha256),length(platform_response_sha256),"
            "terminal_verification FROM pending_video WHERE task_id=?",
            ("video-task-real-media-success",),
        ).fetchone()
    assert row == (
        "done",
        "",
        "send_confirmed",
        64,
        64,
        64,
        64,
        "ilink_sendmessage_response_sha256",
    )


def test_crash_after_direct_send_started_is_quarantined_without_second_media(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-ambiguous-send",
        "wx-user-ambiguous",
        "context-ambiguous",
        source_message_key="wxmsg-v1:ambiguous",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET result_url=?,status='processing',"
            "claim_token='crashed',claimed_at=1001,claim_deadline=2000,"
            "claim_epoch=1,direct_attempted=1,submission_phase='send_submitting',"
            "send_request_sha256=?,send_started_at=1001 WHERE task_id=?",
            (
                "https://media.example/ambiguous.mp4",
                "a" * 64,
                "video-task-ambiguous-send",
            ),
        )
    assert bridge._recover_pending_video_claims(force=True) == 1
    direct_calls = 0

    def forbidden_second_media(*_args, **_kwargs):
        nonlocal direct_calls
        direct_calls += 1
        raise AssertionError("ambiguous direct send must not be repeated")

    monkeypatch.setattr(bridge, "_send_media", forbidden_second_media)
    monkeypatch.setattr(
        bridge,
        "_fetch_media",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ambiguous direct send must not fetch media again")
        ),
    )
    fallbacks: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallbacks.append(text) or True,
    )

    assert bridge._drain_pending_videos("new-bot-token", limit=1, now=1002.0) == 0
    assert direct_calls == 0
    assert fallbacks == []
    with bridge._outbox_connect() as conn:
        status = conn.execute(
            "SELECT status,last_error,submission_phase,last_finish_token,"
            "last_finish_epoch,last_finish_outcome FROM pending_video WHERE task_id=?",
            ("video-task-ambiguous-send",),
        ).fetchone()
    assert status == (
        "recovery_required",
        "video_submission_outcome_unknown",
        "send_submitting",
        "crashed",
        1,
        "recovery_required",
    )


def test_pending_video_send_response_loss_is_quarantined_and_never_replayed(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-send-loss",
        "wx-user-send-loss",
        "context-send-loss",
        source_message_key="wxmsg-v1:send-loss",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET result_url=? WHERE task_id=?",
            (
                "https://media.example/send-loss.mp4",
                "video-task-send-loss",
            ),
        )
    monkeypatch.setattr(bridge, "_fetch_media", lambda *_args: b"mp4")
    ilink_calls: list[str] = []

    def ilink(_method, path, _body=None, **_kwargs):
        ilink_calls.append(path)
        if path == "/ilink/bot/getuploadurl":
            return {"upload_full_url": "https://novac2c.cdn.weixin.qq.com/c2c?grant=1"}
        raise OSError("synthetic send response loss")

    monkeypatch.setattr(bridge, "_ilink", ilink)
    monkeypatch.setattr(
        bridge,
        "request_public_bytes",
        lambda *_args, **_kwargs: SimpleNamespace(
            headers={"x-encrypted-param": "opaque-upload-result"}
        ),
    )
    fallbacks: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallbacks.append(text) or True,
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=1001.0) == 1
    assert ilink_calls == ["/ilink/bot/getuploadurl", "/ilink/bot/sendmessage"]
    assert fallbacks == []
    assert bridge._recover_pending_video_claims(force=True, now=1002.0) == 0
    assert bridge._drain_pending_videos("bot-token", limit=1, now=1002.0) == 0
    assert ilink_calls == ["/ilink/bot/getuploadurl", "/ilink/bot/sendmessage"]
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,direct_attempted,submission_phase,"
            "length(upload_grant_request_sha256),length(upload_request_sha256),"
            "length(send_request_sha256),last_finish_outcome "
            "FROM pending_video WHERE task_id=?",
            ("video-task-send-loss",),
        ).fetchone()
    assert row == (
        "recovery_required",
        1,
        "send_submitting",
        64,
        64,
        64,
        "recovery_required",
    )


def test_pending_video_expired_submission_is_isolated_by_claim_path(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-expired-submission",
        "wx-user-expired-submission",
        "context-expired-submission",
        source_message_key="wxmsg-v1:expired-submission",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET status='processing',claim_token='expired',"
            "claimed_at=1001,claim_deadline=1002,heartbeat_at=1001,claim_epoch=4,"
            "direct_attempted=1,submission_phase='upload_submitting',"
            "upload_request_sha256=? WHERE task_id=?",
            ("b" * 64, "video-task-expired-submission"),
        )

    assert bridge._claim_pending_video(now=1003.0) is None
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,last_error,last_finish_token,last_finish_epoch,"
            "last_finish_outcome FROM pending_video WHERE task_id=?",
            ("video-task-expired-submission",),
        ).fetchone()
    assert row == (
        "recovery_required",
        "video_submission_outcome_unknown",
        "expired",
        4,
        "recovery_required",
    )


def test_pending_video_confirmed_send_finishes_after_worker_crash(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-confirmed-crash",
        "wx-user-confirmed-crash",
        "context-confirmed-crash",
        source_message_key="wxmsg-v1:confirmed-crash",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET status='processing',claim_token='confirmed',"
            "claimed_at=1001,claim_deadline=2000,heartbeat_at=1001,claim_epoch=7,"
            "direct_attempted=1,submission_phase='send_confirmed',"
            "send_request_sha256=?,platform_response_sha256=? WHERE task_id=?",
            (
                "c" * 64,
                "d" * 64,
                "video-task-confirmed-crash",
            ),
        )

    assert bridge._recover_pending_video_claims(force=True, now=1002.0) == 1
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,claim_token,last_finish_token,last_finish_epoch,"
            "last_finish_outcome,terminal_verification FROM pending_video "
            "WHERE task_id=?",
            ("video-task-confirmed-crash",),
        ).fetchone()
    assert row == (
        "done",
        "",
        "confirmed",
        7,
        "done",
        "ilink_sendmessage_response_sha256",
    )


def test_pending_video_upload_response_loss_has_no_hidden_retry(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-upload-loss",
        "wx-user-upload-loss",
        "context-upload-loss",
        source_message_key="wxmsg-v1:upload-loss",
        now=1000.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET result_url=? WHERE task_id=?",
            ("https://media.example/upload-loss.mp4", "video-task-upload-loss"),
        )
    monkeypatch.setattr(bridge, "_fetch_media", lambda *_args: b"mp4")
    monkeypatch.setattr(
        bridge,
        "_ilink",
        lambda *_args, **_kwargs: {
            "upload_full_url": "https://novac2c.cdn.weixin.qq.com/c2c?grant=2"
        },
    )
    uploads = 0

    def lose_upload_response(*_args, **_kwargs):
        nonlocal uploads
        uploads += 1
        raise bridge.PublicFetchTimeout("synthetic upload response loss")

    monkeypatch.setattr(bridge, "request_public_bytes", lose_upload_response)
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("an uncertain upload must not emit an automatic fallback")
        ),
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=1001.0) == 1
    assert uploads == 1
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,submission_phase,last_finish_outcome "
            "FROM pending_video WHERE task_id=?",
            ("video-task-upload-loss",),
        ).fetchone()
    assert row == ("recovery_required", "upload_submitting", "recovery_required")


def test_completed_video_direct_send_failure_uses_durable_idempotent_fallback(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "video-task-fallback",
        "wx-user-fallback",
        "context-fallback",
        source_message_key="wxmsg-v1:fallback",
        now=1000.0,
        _internal_maintenance=True,
    )
    monkeypatch.setattr(
        bridge,
        "_engine_get_json",
        lambda *_args, **_kwargs: {
            "status": "succeeded",
            "output_url": "https://media.example/fallback.mp4",
        },
    )
    monkeypatch.setattr(
        bridge,
        "_fetch_media",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cdn unavailable")),
    )
    fallbacks: list[tuple[str, str]] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, *, delivery_key=None: fallbacks.append(
            (text, delivery_key)
        )
        or False,
    )

    assert bridge._drain_pending_videos("bot-token", limit=1, now=1001.0) == 1
    assert len(fallbacks) == 1
    assert "https://media.example/fallback.mp4" in fallbacks[0][0]
    assert fallbacks[0][1].endswith(":fallback")
    with bridge._outbox_connect() as conn:
        status = conn.execute(
            "SELECT status,last_error FROM pending_video "
            "WHERE task_id='video-task-fallback'"
        ).fetchone()
    assert status == ("done", "direct_delivery_OSError")


def test_async_video_workers_are_fixed_and_read_the_current_bot_token(monkeypatch):
    bridge = _load_bridge()
    created = []

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

    monkeypatch.setattr(bridge.threading, "Thread", FakeThread)
    stop = bridge.threading.Event()
    token_ref = {"value": "old-token"}
    workers = bridge._start_video_workers(token_ref, stop, worker_count=999)
    assert len(workers) == 4
    assert all(worker.started and worker.daemon for worker in workers)
    assert {worker.name for worker in workers} == {
        "weixin-video-1",
        "weixin-video-2",
        "weixin-video-3",
        "weixin-video-4",
    }

    used: list[str] = []

    class OneCycle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    token_ref["value"] = "rotated-token"
    monkeypatch.setattr(
        bridge,
        "_drain_pending_videos",
        lambda token, **_kwargs: used.append(token) or 0,
    )
    bridge._video_queue_worker(token_ref, OneCycle())
    assert used == ["rotated-token"]


def test_async_video_worker_survives_one_database_or_poll_failure(monkeypatch):
    bridge = _load_bridge()
    calls = 0

    class TwoCycles:
        waits = 0

        def is_set(self):
            return self.waits >= 2

        def wait(self, _seconds):
            self.waits += 1
            return self.is_set()

    def flaky_drain(_token, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is temporarily busy")
        return 0

    monkeypatch.setattr(bridge, "_drain_pending_videos", flaky_drain)
    stop = TwoCycles()
    bridge._video_queue_worker({"value": "bot-token"}, stop)
    assert calls == 2
    assert bridge._HEALTH_STATE["service_state"] == "degraded"
    assert bridge._HEALTH_STATE["last_error_code"] == "video_worker_error"


def test_agent_chat_passes_stable_message_key_as_idempotency_key_and_bounds_sla(
    monkeypatch,
):
    bridge = _load_bridge()
    captured = {}

    def fake_post(path, payload, timeout=120, **kwargs):
        captured.update(path=path, payload=payload, timeout=timeout, kwargs=kwargs)
        return {"reply": "ok"}

    monkeypatch.setattr(bridge, "_engine_post", fake_post)
    message_key = "wxmsg-v1:" + ("1" * 64)
    assert bridge._agent_chat("hello", "owner", "chat-1", message_key) == {
        "reply": "ok"
    }
    assert captured["path"] == "/v1/agent/chat"
    assert captured["payload"]["idempotency_key"] == message_key
    assert captured["payload"]["video_async_capacity_available"] is True
    assert captured["timeout"] == 90.0
    assert captured["kwargs"]["total_timeout"] == 90.0


def test_agent_chat_without_operator_model_delegates_routing_to_gateway(monkeypatch):
    """A channel must not freeze an obsolete concrete model into every Turn."""

    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "MODEL", "")
    captured = {}

    def fake_post(path, payload, timeout=120, **kwargs):
        captured.update(path=path, payload=payload, timeout=timeout, kwargs=kwargs)
        return {"reply": "ok"}

    monkeypatch.setattr(bridge, "_engine_post", fake_post)
    message_key = "wxmsg-v1:" + ("a" * 64)

    assert bridge._agent_chat("hello", "owner", "chat-1", message_key) == {
        "reply": "ok"
    }
    assert "model" not in captured["payload"]


def test_agent_chat_ready_no_model_returns_one_terminal_local_reply(monkeypatch):
    bridge = _load_bridge()

    def unavailable(*_args, **_kwargs):
        body = json.dumps(
            {"detail": {"code": "ready_no_model", "retryable": False}}
        ).encode("utf-8")
        raise urllib.error.HTTPError(
            bridge.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(body),
        )

    monkeypatch.setattr(bridge, "_engine_post", unavailable)
    result = bridge._agent_chat(
        "hello", "owner", "chat-1", "wxmsg-v1:" + ("b" * 64)
    )

    assert result["outcome"] == "ready_no_model"
    assert result["blocked"] is True
    assert bridge._ENGINE_AVAILABLE is False
    assert bridge._ENGINE_READINESS_REASON == "ready_no_model"
    assert "连接中心" in result["reply"]


def test_agent_chat_does_not_swallow_an_unclassified_engine_503(monkeypatch):
    bridge = _load_bridge()

    def unavailable(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            bridge.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b'{"detail":{"code":"provider_busy"}}'),
        )

    monkeypatch.setattr(bridge, "_engine_post", unavailable)
    with pytest.raises(urllib.error.HTTPError) as exc:
        bridge._agent_chat(
            "hello", "owner", "chat-1", "wxmsg-v1:" + ("c" * 64)
        )
    assert exc.value.code == 503


@pytest.mark.parametrize(
    "body",
    [
        b'{"detail":{"code":"ready_no_model","retryable":true}}',
        (
            b'{"detail":{"code":"ready_no_model","retryable":false}}'
            + (b" " * (64 * 1024))
        ),
    ],
    ids=["retryable", "oversized"],
)
def test_agent_chat_rejects_retryable_or_oversized_readiness_errors(
    monkeypatch, body: bytes
):
    bridge = _load_bridge()

    def unavailable(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            bridge.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(body),
        )

    monkeypatch.setattr(bridge, "_engine_post", unavailable)
    with pytest.raises(urllib.error.HTTPError):
        bridge._agent_chat(
            "hello", "owner", "chat-1", "wxmsg-v1:" + ("d" * 64)
        )


def test_ready_no_model_finishes_inbound_once_and_transfers_reply_to_outbox(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    engine_calls = 0

    def unavailable(*_args, **_kwargs):
        nonlocal engine_calls
        engine_calls += 1
        body = b'{"detail":{"code":"ready_no_model","retryable":false}}'
        raise urllib.error.HTTPError(
            bridge.ENGINE + "/v1/agent/chat",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(body),
        )

    monkeypatch.setattr(bridge, "_engine_post", unavailable)
    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, text, _client_id: sent.append(text) or True,
    )
    message = {
        "message_id": "ready-no-model-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True
    claimed = bridge._claim_inbound(now=1_000_000_000_000.0)
    assert claimed is not None

    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.claim_message_key = bridge._message_key(message)
    bridge._HANDLE_CONTEXT.lease_session = _TestInboundLeaseSession()
    try:
        ok, error = bridge._handle_result(claimed[1], "bot-token")
        assert (ok, error) == (True, None)
        bridge._finish_inbound(
            claimed[0], claim_token=claimed[2], claim_epoch=claimed[3], ok=True
        )
    finally:
        for name in (
            "claim_id",
            "claim_token",
            "claim_epoch",
            "claim_message_key",
            "lease_session",
        ):
            delattr(bridge._HANDLE_CONTEXT, name)

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_error FROM inbound_message"
        ).fetchone()
        pending_video = conn.execute("SELECT COUNT(*) FROM pending_video").fetchone()[0]
        deliveries = conn.execute(
            "SELECT delivery_id,status,text FROM pending_delivery ORDER BY id"
        ).fetchall()
    assert inbound == ("done", 0, "")
    assert pending_video == 0
    assert len(deliveries) == 1
    assert deliveries[0][0] == bridge._delivery_id(
        f"{bridge._message_key(message)}:reply"
    )
    assert deliveries[0][1] == "done"
    assert "连接中心" in deliveries[0][2]
    assert sent == [deliveries[0][2]]
    assert not any("正在自动重试" in text for text in sent)

    assert bridge._store_updates([message], "cursor-1") is True
    assert bridge._claim_inbound(now=1_000_000_000_000.0) is None
    assert engine_calls == 1


def test_agent_chat_socket_timeout_is_not_replayed_or_key_rediscovered(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "fixed-supervisor-key"
    calls = 0

    def timeout(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise socket.timeout("timed out")

    monkeypatch.setattr(bridge._ENGINE_OPENER, "open", timeout)
    monkeypatch.setattr(
        bridge,
        "_resolve_engine_key",
        lambda: (_ for _ in ()).throw(AssertionError("must not rediscover key")),
    )
    with pytest.raises(socket.timeout):
        bridge._agent_chat(
            "hello", "owner", "chat-1", "wxmsg-v1:" + ("2" * 64)
        )
    assert calls == 1


def test_agent_chat_http_budget_reserves_the_uncancellable_commit_tail(monkeypatch):
    bridge = _load_bridge()
    captured = {}

    def fake_engine_post(path, payload, **kwargs):
        captured.update(path=path, payload=payload, kwargs=kwargs)
        return {"reply": "ok"}

    monkeypatch.setattr(bridge, "_engine_post", fake_engine_post)
    result = bridge._agent_chat(
        "hello",
        "owner",
        "chat-budget",
        "wxmsg-v1:" + ("4" * 64),
    )

    assert result == {"reply": "ok"}
    assert captured["kwargs"]["timeout"] == 90.0
    assert captured["kwargs"]["total_timeout"] == 90.0


def test_async_video_status_uses_authenticated_encrypted_bridge_transport(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "scoped-weixin-key"
    captured = {}

    def fake_request(opener, **kwargs):
        captured.update(opener=opener, kwargs=kwargs)
        return b'{"status":"processing"}'

    monkeypatch.setattr(bridge, "request_bridge_bytes", fake_request)
    monkeypatch.setattr(
        bridge._ENGINE_OPENER,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("video status must not use plaintext urllib/Bearer")
        ),
    )

    assert bridge._engine_get_json(
        "/v1/videos/task-1?model=agnes-video", timeout=9
    ) == {"status": "processing"}
    assert captured["opener"] is bridge._ENGINE_OPENER
    assert captured["kwargs"] == {
        "url": f"{bridge.ENGINE}/v1/videos/task-1?model=agnes-video",
        "secret": "scoped-weixin-key",
        "channel": "weixin",
        "method": "GET",
        "body": b"",
        "timeout": 9.0,
        "max_response_bytes": bridge._STATE_FILE_MAX_BYTES,
    }


def test_engine_401_never_triggers_ambient_key_rediscovery(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "fixed-supervisor-key"
    calls = 0

    def unauthorized(_opener, **_kwargs):
        nonlocal calls
        calls += 1
        raise urllib.error.HTTPError(
            f"{bridge.ENGINE}/v1/agent/feedback",
            401,
            "Unauthorized",
            {},
            None,
        )

    monkeypatch.setattr(bridge, "request_bridge_bytes", unauthorized)
    monkeypatch.setattr(
        bridge,
        "_resolve_engine_key",
        lambda: (_ for _ in ()).throw(AssertionError("must not rediscover key")),
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        bridge._engine_post("/v1/agent/feedback", {"rating": "up"}, timeout=5)
    assert exc.value.code == 401
    assert calls == 1


def test_send_uses_complete_protocol_payload(monkeypatch):
    monkeypatch.delenv("WEIXIN_SEND_TIMEOUT_SECONDS", raising=False)
    bridge = _load_bridge()
    calls: list[tuple[str, str, dict, str, float | None]] = []

    def fake_ilink(method, path, body=None, token="", timeout=None):
        calls.append((method, path, body, token, timeout))
        return {}

    monkeypatch.setattr(bridge, "_ilink", fake_ilink)
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)

    assert bridge._send("bot-token", "user-1", "context-1", "你好") is True
    assert len(calls) == 1
    method, path, body, token, timeout = calls[-1]
    assert (method, path, token) == ("POST", "/ilink/bot/sendmessage", "bot-token")
    assert timeout == 10.0
    assert body["base_info"]["channel_version"]
    assert body["msg"]["from_user_id"] == ""
    assert body["msg"]["to_user_id"] == "user-1"
    assert body["msg"]["context_token"] == "context-1"
    assert body["msg"]["client_id"].startswith("nachuan_")
    assert calls[0][2]["msg"]["client_id"] == body["msg"]["client_id"]
    assert body["msg"]["item_list"][0]["text_item"]["text"] == "你好"


def test_send_timeout_configuration_is_bounded_to_a_short_contract(monkeypatch):
    monkeypatch.setenv("WEIXIN_SEND_TIMEOUT_SECONDS", "999")
    bridge = _load_bridge()

    assert bridge._SEND_ATTEMPT_TIMEOUT_SECONDS == 10.0
    assert bridge._OUTBOX_LOCAL_PREP_BUDGET_SECONDS == 10.0
    assert bridge._OUTBOX_DRAIN_WALL_BUDGET_SECONDS == 20.0


def test_progress_delivery_uses_short_network_budget_without_shrinking_final_reply(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    observed: list[tuple[str, float | None]] = []

    def fake_ilink(_method, _path, body=None, token="", timeout=None):
        observed.append(
            (body["msg"]["item_list"][0]["text_item"]["text"], timeout)
        )
        return {"ret": 0}

    monkeypatch.setattr(bridge, "_ilink", fake_ilink)

    assert bridge._deliver_text(
        "bot-token",
        "user-1",
        "context-1",
        "收到，正在处理中；完成后会继续回复你。",
        delivery_key="message-1:progress",
    )
    assert bridge._deliver_text(
        "bot-token",
        "user-1",
        "context-1",
        "最终答案",
        delivery_key="message-1:reply",
    )

    assert observed == [
        ("收到，正在处理中；完成后会继续回复你。", 2.0),
        ("最终答案", 10.0),
    ]


def test_send_business_error_is_one_bounded_outbox_attempt(monkeypatch):
    bridge = _load_bridge()
    calls = 0

    def fake_ilink(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {"ret": -1, "errcode": 45011, "errmsg": "busy"}

    monkeypatch.setattr(bridge, "_ilink", fake_ilink)
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)

    with pytest.raises(bridge.ILinkDeliveryError, match="sendmessage"):
        bridge._send("bot-token", "user-1", "context-1", "你好")
    assert calls == 1


def test_send_empty_json_response_follows_tencent_246_success_contract(monkeypatch):
    bridge = _load_bridge()
    calls = 0

    def official_empty_success(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {}

    monkeypatch.setattr(bridge, "_ilink", official_empty_success)

    assert bridge._send_chunk(
        "bot-token",
        "user-1",
        "context-1",
        "official-success",
        "client-1",
    ) == {}
    assert calls == 1


def test_text_outbox_marks_submitting_before_ilink_and_official_success_is_done(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_outbox.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key="message-1:reply"
    )
    observed: list[tuple[str, str, float, int, str]] = []

    def exact_success(_method, _path, body=None, **_kwargs):
        with sqlite3.connect(database) as conn:
            observed.append(
                conn.execute(
                    "SELECT status,request_sha256,submission_started_at,claim_epoch,"
                    "client_id FROM pending_delivery WHERE delivery_id=?",
                    (delivery_id,),
                ).fetchone()
            )
        assert body["msg"]["client_id"] == observed[-1][4]
        return {"ret": 0}

    monkeypatch.setattr(bridge, "_ilink", exact_success)

    assert bridge._drain_outbox("bot-token", delivery_id=delivery_id) == 1
    assert len(observed) == 1
    status, request_sha256, submission_started_at, claim_epoch, _client_id = observed[0]
    assert status == "submitting"
    assert len(request_sha256) == 64
    assert submission_started_at > 0
    assert claim_epoch == 1
    with sqlite3.connect(database) as conn:
        row = conn.execute(
            "SELECT status,request_sha256,platform_response_sha256,"
            "terminal_verification,last_finish_token,last_finish_epoch,"
            "last_finish_outcome FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()
    assert row[0] == "done"
    assert row[1] == request_sha256
    assert len(row[2]) == 64
    assert row[3] == "platform_response_observed_unverified"
    assert row[4]
    assert row[5:] == (1, "done")


@pytest.mark.parametrize(
    "failure_kind",
    ("oserror", "timeout", "http", "json", "business"),
)
def test_text_outbox_any_post_boundary_uncertainty_requires_recovery_without_replay(
    monkeypatch, tmp_path, failure_kind
):
    bridge = _load_bridge()
    database = tmp_path / f"weixin-{failure_kind}.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)
    calls = 0

    def uncertain(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if failure_kind == "oserror":
            raise OSError("connection reset after request submission")
        if failure_kind == "timeout":
            raise TimeoutError("response lost")
        if failure_kind == "http":
            raise urllib.error.HTTPError("https://invalid", 503, "busy", {}, None)
        if failure_kind == "json":
            raise json.JSONDecodeError("bad response", "{", 1)
        if failure_kind == "business":
            return {"ret": -2, "errmsg": "rejected or rate limited"}
        raise AssertionError(f"unexpected failure kind: {failure_kind}")

    monkeypatch.setattr(bridge, "_ilink", uncertain)
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key=f"uncertain:{failure_kind}"
    )

    assert bridge._drain_outbox("bot-token", delivery_id=delivery_id) == 0
    assert calls == 1
    with sqlite3.connect(database) as conn:
        row = conn.execute(
            "SELECT status,request_sha256,submission_started_at,claim_token,"
            "claim_deadline,last_finish_outcome FROM pending_delivery"
        ).fetchone()
    assert row[0] == "recovery_required"
    assert len(row[1]) == 64
    assert row[2] > 0
    assert row[3:5] == ("", 0.0)
    assert row[5] == "recovery_required"

    assert bridge._recover_delivery_claims(force=True, now=10**12) == 0
    assert bridge._drain_outbox("bot-token", now=10**12, delivery_id=delivery_id) == 0
    assert calls == 1


def test_text_outbox_finish_storage_failure_keeps_submission_non_replayable(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    with pytest.raises(ValueError, match="invalid delivery finish outcome"):
        bridge._DeliveryFinishRequest(outcome="retry")
    database = tmp_path / "weixin-finish-storage.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key="finish-storage-loss"
    )
    calls = 0

    def exact_success(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {"ret": 0}

    monkeypatch.setattr(bridge, "_ilink", exact_success)
    monkeypatch.setattr(
        bridge.ClaimLeaseSession,
        "finish",
        lambda _session, _outcome: False,
    )

    with pytest.raises(bridge.DeliveryAckStorageError):
        bridge._drain_outbox("bot-token", delivery_id=delivery_id)

    assert calls == 1
    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT status,request_sha256 FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()[0] == "submitting"
    assert bridge._recover_delivery_claims(force=True) == 1
    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone() == ("recovery_required",)
    assert bridge._drain_outbox("bot-token", now=10**12, delivery_id=delivery_id) == 0
    assert calls == 1


@pytest.mark.parametrize(
    ("recipient", "context", "text"),
    (
        ("other-user", "context-1", "reply"),
        ("user-1", "other-context", "reply"),
        ("user-1", "context-1", "different reply"),
        ("user-1", "context-1", "A" * 3501),
    ),
)
def test_stable_delivery_key_replay_requires_every_immutable_field_and_chunk(
    monkeypatch, tmp_path, recipient, context, text
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin.db")
    delivery_key = "stable-message:reply"
    first = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key=delivery_key
    )
    assert bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key=delivery_key
    ) == first

    with pytest.raises(
        bridge.DeliverySemanticConflict,
        match="delivery_semantic_conflict",
    ):
        bridge._enqueue_delivery(
            recipient,
            context,
            text,
            delivery_key=delivery_key,
        )


def test_delivery_claim_session_confirms_response_loss_with_one_finish_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin.db")
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "ctx", "reply", delivery_key="finish-response-loss"
    )
    claim = bridge._claim_delivery(delivery_id=delivery_id)
    assert claim is not None
    session = bridge._new_delivery_lease_session(claim)
    assert session.start() is True
    request_sha256 = bridge._canonical_json_sha256(
        bridge._sendmessage_body(
            claim["to_user_id"],
            claim["context_token"],
            claim["text"],
            claim["client_id"],
        )
    )
    with session.commit_fence():
        assert bridge._mark_delivery_submitting(claim, request_sha256) is True

    real_finish = bridge._finish_delivery
    real_confirm = bridge._delivery_finish_was_committed
    deadlines: dict[str, list[float]] = {"finish": [], "confirm": []}

    def commit_then_raise(*args, **kwargs):
        deadlines["finish"].append(kwargs["deadline_monotonic"])
        real_finish(*args, **kwargs)
        raise sqlite3.OperationalError("simulated commit response loss")

    def confirm(*args, **kwargs):
        deadlines["confirm"].append(kwargs["deadline_monotonic"])
        return real_confirm(*args, **kwargs)

    monkeypatch.setattr(bridge, "_finish_delivery", commit_then_raise)
    monkeypatch.setattr(bridge, "_delivery_finish_was_committed", confirm)
    outcome = bridge._DeliveryFinishRequest(
        outcome="done",
        platform_response_sha256="a" * 64,
    )
    try:
        assert session.finish(outcome) is True
    finally:
        session.close()

    assert deadlines["finish"] == deadlines["confirm"]
    assert len(deadlines["finish"]) == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM pending_delivery"
        ).fetchone() == ("done", "done")


def test_delivery_finish_sqlite_lock_obeys_single_total_wallclock_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    monkeypatch.setattr(bridge._DeliveryClaimPolicy, "finish_timeout", 0.2)
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "ctx", "reply", delivery_key="finish-lock"
    )
    claim = bridge._claim_delivery(delivery_id=delivery_id)
    assert claim is not None
    session = bridge._new_delivery_lease_session(claim)
    assert session.start() is True
    request_sha256 = bridge._canonical_json_sha256(
        bridge._sendmessage_body(
            claim["to_user_id"], claim["context_token"], claim["text"], claim["client_id"]
        )
    )
    with session.commit_fence():
        bridge._mark_delivery_submitting(claim, request_sha256)

    blocker = sqlite3.connect(database, timeout=1.0)
    blocker.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        assert session.finish(
            bridge._DeliveryFinishRequest(
                outcome="recovery_required",
                error=TimeoutError("unknown"),
            )
        ) is False
    finally:
        elapsed = time.monotonic() - started
        blocker.rollback()
        blocker.close()
        session.close()
    assert elapsed < 0.8


def test_delivery_recovery_distinguishes_pre_network_processing_from_submitting(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin.db")
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "ctx", "reply", delivery_key="processing-vs-submitting"
    )
    processing = bridge._claim_delivery(delivery_id=delivery_id)
    assert processing is not None
    assert bridge._recover_delivery_claims(force=True) == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone() == ("pending",)

    submitting = bridge._claim_delivery(delivery_id=delivery_id)
    assert submitting is not None
    request_sha256 = bridge._canonical_json_sha256(
        bridge._sendmessage_body(
            submitting["to_user_id"],
            submitting["context_token"],
            submitting["text"],
            submitting["client_id"],
        )
    )
    assert bridge._mark_delivery_submitting(submitting, request_sha256) is True
    assert bridge._recover_delivery_claims(force=True) == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,last_error FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone() == (
            "recovery_required",
            "submission_outcome_unknown_after_restart",
        )


def test_chat_sequence_claim_barrier_orders_inbound_delivery_and_video(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pending_delivery("
            "created_at,next_attempt_at,to_user_id,context_token,text,delivery_id,"
            "client_id,chat_seq) VALUES(1,1,'user-1','ctx','first','delivery-1',"
            "'client-1',1)"
        )
        conn.execute(
            "INSERT INTO inbound_message("
            "message_key,from_user_id,payload,received_at,next_attempt_at,chat_seq) "
            "VALUES('message-2','user-1','{}',1,1,2)"
        )
        conn.execute(
            "INSERT INTO pending_video("
            "task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,"
            "next_attempt_at,chat_seq) VALUES('video-3','user-1','ctx','message-3',"
            "1,999,1,3)"
        )

    assert bridge._claim_inbound(now=100) is None
    assert bridge._claim_pending_video(now=100) is None
    delivery = bridge._claim_delivery(now=100)
    assert delivery is not None
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE pending_delivery SET status='done',claim_token='',claim_deadline=0 "
            "WHERE id=?",
            (delivery["id"],),
        )
    inbound = bridge._claim_inbound(now=100)
    assert inbound is not None
    assert bridge._claim_pending_video(now=100) is None
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE inbound_message SET status='done',claim_token='',claim_deadline=0 "
            "WHERE id=?",
            (inbound[0],),
        )
    assert bridge._claim_pending_video(now=100) is not None


def test_failed_delivery_is_persisted_for_manual_recovery_without_restart_replay(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)

    def fail_send(*_args, **_kwargs):
        raise OSError("connection reset")

    monkeypatch.setattr(bridge, "_send_chunk", fail_send)
    assert bridge._deliver_text("bot-token", "user-1", "context-1", "reply") is False
    assert bridge._outbox_pending_count() == 1

    delivered: list[tuple[str, str, str, str, str]] = []

    def ok_send(token, to_user_id, context_token, text, client_id):
        delivered.append((token, to_user_id, context_token, text, client_id))
        return True

    monkeypatch.setattr(bridge, "_send_chunk", ok_send)
    assert bridge._drain_outbox("bot-token", now=10**12) == 0
    assert delivered == []
    assert bridge._outbox_pending_count() == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery"
        ).fetchone() == ("recovery_required",)


def test_same_chat_later_delivery_cannot_overtake_unknown_earlier_submission(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")

    attempts: list[tuple[str, str]] = []
    progress_attempts = 0

    def send_once_then_recover(_token, _to_user_id, _context, text, client_id):
        nonlocal progress_attempts
        attempts.append((text, client_id))
        if text == "正在处理" and progress_attempts == 0:
            progress_attempts += 1
            raise OSError("progress response lost")
        return True

    monkeypatch.setattr(bridge, "_send_chunk", send_once_then_recover)
    progress_id, _rows = bridge._enqueue_delivery(
        "user-1",
        "progress-context",
        "正在处理",
        delivery_key="message-1:progress",
    )
    assert bridge._drain_outbox(
        "bot-token", delivery_id=progress_id
    ) == 0

    final_id, _rows = bridge._enqueue_delivery(
        "user-1",
        "final-context",
        "最终答案",
        delivery_key="message-1:reply",
    )
    assert bridge._drain_outbox(
        "bot-token", delivery_id=final_id
    ) == 0
    assert [text for text, _client_id in attempts] == ["正在处理"]
    assert bridge._delivery_complete(final_id) is False

    assert bridge._drain_outbox("bot-token", now=10**12, limit=2) == 0
    assert [text for text, _client_id in attempts] == ["正在处理"]
    assert bridge._delivery_complete(progress_id) is False
    assert bridge._delivery_complete(final_id) is False
    with bridge._outbox_connect() as conn:
        statuses = conn.execute(
            "SELECT status FROM pending_delivery ORDER BY chat_seq,id"
        ).fetchall()
    assert statuses == [("recovery_required",), ("pending",)]


def test_processing_delivery_blocks_same_chat_but_not_another_chat(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    first_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "first reply", delivery_key="message-1:reply"
    )
    second_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-2", "second reply", delivery_key="message-2:reply"
    )
    other_id, _rows = bridge._enqueue_delivery(
        "user-2", "context-3", "other reply", delivery_key="message-3:reply"
    )

    first_send_started = threading.Event()
    release_first_send = threading.Event()
    sent: list[tuple[str, str]] = []
    worker_errors: list[BaseException] = []
    worker_results: list[int] = []

    def bounded_send(_token, to_user_id, _context_token, text, _client_id):
        sent.append((to_user_id, text))
        if text == "first reply":
            first_send_started.set()
            assert release_first_send.wait(10.0)
        return True

    def drain_first() -> None:
        try:
            worker_results.append(
                bridge._drain_outbox("bot-token", delivery_id=first_id)
            )
        except BaseException as exc:  # noqa: BLE001 - re-raised by the test thread
            worker_errors.append(exc)

    monkeypatch.setattr(bridge, "_send_chunk", bounded_send)
    worker = threading.Thread(target=drain_first, name="weixin-first-delivery-test")
    worker.start()
    try:
        assert first_send_started.wait(10.0)
        assert bridge._drain_outbox(
            "bot-token", delivery_id=second_id
        ) == 0
        assert bridge._drain_outbox(
            "bot-token", delivery_id=other_id
        ) == 1
        assert sent == [("user-1", "first reply"), ("user-2", "other reply")]
    finally:
        release_first_send.set()
        worker.join(10.0)

    assert worker.is_alive() is False
    assert worker_errors == []
    assert worker_results == [1]
    assert bridge._drain_outbox("bot-token", delivery_id=second_id) == 1
    assert sent == [
        ("user-1", "first reply"),
        ("user-2", "other reply"),
        ("user-1", "second reply"),
    ]


def test_restart_recovery_preserves_same_chat_delivery_order(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    first_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "first reply", delivery_key="message-1:reply"
    )
    second_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-2", "second reply", delivery_key="message-2:reply"
    )
    first_claim = bridge._claim_delivery(now=10**12, delivery_id=first_id)
    assert first_claim is not None

    assert bridge._recover_delivery_claims(force=True) == 1
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, text, client_id: sent.append(
            (text, client_id)
        )
        or True,
    )

    assert bridge._drain_outbox(
        "bot-token", now=10**12, delivery_id=second_id
    ) == 0
    delivered_count = bridge._drain_outbox("bot-token", now=10**12, limit=2)
    if delivered_count < 2:
        delivered_count += bridge._drain_outbox(
            "bot-token", now=10**12, limit=2 - delivered_count
        )
    assert delivered_count == 2
    assert [text for text, _client_id in sent] == ["first reply", "second reply"]
    assert sent[0][1] == first_claim["client_id"]


def test_failed_delivery_after_submission_never_enters_retry_backoff(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)
    clock = {"now": 100.0}
    attempted = threading.Event()
    monkeypatch.setattr(bridge.time, "time", lambda: clock["now"])
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key="m1:reply"
    )

    def slow_failure(*_args, **_kwargs):
        attempted.set()
        clock["now"] = 200.0
        raise OSError("network deadline")

    monkeypatch.setattr(bridge, "_send_chunk", slow_failure)
    assert bridge._drain_outbox(
        "bot-token", now=100.0, delivery_id=delivery_id
    ) == 0
    assert attempted.is_set()
    with bridge._outbox_connect() as conn:
        status, next_attempt_at = conn.execute(
            "SELECT status,next_attempt_at FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()

    assert status == "recovery_required"
    assert next_attempt_at == 100.0


def test_outbox_drain_uses_one_shared_wall_budget_not_n_send_timeouts(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    clock = {"monotonic": 0.0, "wall": 100.0}
    monkeypatch.setattr(bridge.time, "monotonic", lambda: clock["monotonic"])
    monkeypatch.setattr(bridge.time, "time", lambda: clock["wall"])
    for index in range(4):
        bridge._enqueue_delivery(
            f"user-{index}",
            f"context-{index}",
            f"reply-{index}",
            delivery_key=f"budget-{index}:reply",
        )

    calls: list[str] = []

    def one_full_timeout(_token, _to, _ctx, _text, client_id):
        calls.append(client_id)
        clock["monotonic"] += bridge._SEND_ATTEMPT_TIMEOUT_SECONDS
        clock["wall"] += bridge._SEND_ATTEMPT_TIMEOUT_SECONDS
        raise TimeoutError("one bounded network attempt")

    monkeypatch.setattr(bridge, "_send_chunk", one_full_timeout)
    monkeypatch.setattr(
        bridge.time,
        "sleep",
        lambda _seconds: (_ for _ in ()).throw(
            AssertionError("durable outbox must not sleep or retry inside one drain")
        ),
    )

    assert bridge._drain_outbox("bot-token", now=clock["wall"], limit=20) == 0
    assert len(calls) == 1
    assert clock["monotonic"] <= bridge._OUTBOX_DRAIN_WALL_BUDGET_SECONDS
    with bridge._outbox_connect() as conn:
        attempts = conn.execute(
            "SELECT attempts FROM pending_delivery ORDER BY id"
        ).fetchall()
    assert attempts == [(1,), (0,), (0,), (0,)]


def test_first_outbox_attempt_survives_bounded_cold_claim_delay(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    clock = {"monotonic": 0.0, "wall": 100.0}
    monkeypatch.setattr(bridge.time, "monotonic", lambda: clock["monotonic"])
    monkeypatch.setattr(bridge.time, "time", lambda: clock["wall"])
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key="cold-claim:reply"
    )
    real_claim = bridge._claim_delivery

    def bounded_cold_claim(**kwargs):
        claim = real_claim(**kwargs)
        clock["monotonic"] += 6.0
        return claim

    sent: list[str] = []
    monkeypatch.setattr(bridge, "_claim_delivery", bounded_cold_claim)
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, _text, client_id: sent.append(client_id)
        or {"ret": 0},
    )

    assert bridge._drain_outbox(
        "bot-token", now=clock["wall"], delivery_id=delivery_id
    ) == 1
    assert len(sent) == 1


def test_outbox_budget_exhausted_during_claim_releases_unsent_row_unchanged(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    clock = {"monotonic": 0.0, "wall": 100.0}
    monkeypatch.setattr(bridge.time, "monotonic", lambda: clock["monotonic"])
    monkeypatch.setattr(bridge.time, "time", lambda: clock["wall"])
    delivery_id, _rows = bridge._enqueue_delivery(
        "user-1", "context-1", "reply", delivery_key="slow-claim:reply"
    )
    real_claim = bridge._claim_delivery

    def slow_claim(**kwargs):
        claim = real_claim(**kwargs)
        clock["monotonic"] += (
            bridge._OUTBOX_DRAIN_WALL_BUDGET_SECONDS
            - bridge._SEND_ATTEMPT_TIMEOUT_SECONDS
            + 1.0
        )
        return claim

    monkeypatch.setattr(bridge, "_claim_delivery", slow_claim)
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("an attempt that no longer fits must not cross the network seam")
        ),
    )

    assert bridge._drain_outbox(
        "bot-token", now=clock["wall"], delivery_id=delivery_id
    ) == 0
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,attempts,claim_token,claimed_at FROM pending_delivery "
            "WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()
    assert row == ("pending", 0, "", 0.0)


def test_partial_chunk_response_loss_never_resends_unknown_suffix_or_done_prefix(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)
    text = "A" * 3500 + "B"
    first_round: list[tuple[str, str]] = []

    def partial_send(_token, _to, _ctx, chunk, client_id):
        if not first_round:
            # Every chunk must be durable before the first network send starts.
            with bridge._outbox_connect() as conn:
                assert conn.execute(
                    "SELECT COUNT(*) FROM pending_delivery"
                ).fetchone()[0] == 2
        first_round.append((chunk, client_id))
        if chunk == "B":
            raise OSError("response lost")
        return True

    monkeypatch.setattr(bridge, "_send_chunk", partial_send)
    assert bridge._deliver_text(
        "bot-token",
        "user-1",
        "context-1",
        text,
        delivery_key="message:m1:reply",
    ) is False
    with bridge._outbox_connect() as conn:
        rows = conn.execute(
            "SELECT text, client_id, chunk_index, status FROM pending_delivery "
            "ORDER BY chunk_index"
        ).fetchall()
    assert [(row[0], row[2], row[3]) for row in rows] == [
        ("A" * 3500, 0, "done"),
        ("B", 1, "recovery_required"),
    ]

    retried: list[tuple[str, str]] = []

    def retry_send(_token, _to, _ctx, chunk, client_id):
        retried.append((chunk, client_id))
        return True

    monkeypatch.setattr(bridge, "_send_chunk", retry_send)
    assert bridge._drain_outbox("bot-token", now=10**12) == 0
    assert retried == []
    assert bridge._outbox_pending_count() == 1

    # Reprocessing the same inbound message reuses its immutable delivery group.
    retried.clear()
    assert bridge._deliver_text(
        "bot-token",
        "user-1",
        "context-1",
        text,
        delivery_key="message:m1:reply",
    ) is False
    assert retried == []


def test_delivery_claim_is_atomic_across_bridge_instances(monkeypatch, tmp_path):
    first = _load_bridge()
    second = _load_bridge()
    db = tmp_path / "shared.db"
    monkeypatch.setattr(first, "_OUTBOX_DB", db)
    monkeypatch.setattr(second, "_OUTBOX_DB", db)
    first._enqueue_delivery("u1", "ctx", "reply", delivery_key="m1:reply")

    claim = first._claim_delivery(now=10**12)
    assert claim is not None
    assert second._claim_delivery(now=10**12) is None
    first._finish_delivery(claim, ok=True, now=10**12)
    assert second._claim_delivery(now=10**12) is None


def test_delivery_finish_rejects_lost_claim_then_ttl_reuses_client_id(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    delivery_id, _rows = bridge._enqueue_delivery(
        "u1", "ctx", "reply", delivery_key="lost-ack:reply"
    )
    claimed_at = 1_000_000_000_000.0
    claim = bridge._claim_delivery(now=claimed_at, delivery_id=delivery_id)
    assert claim is not None
    stale_claim = {**claim, "claim_token": "not-the-owner"}

    with pytest.raises(RuntimeError, match="delivery_finish_fence_lost"):
        bridge._finish_delivery(stale_claim, ok=True, now=claimed_at + 1)

    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,claim_token FROM pending_delivery WHERE id=?",
            (claim["id"],),
        ).fetchone() == ("processing", claim["claim_token"])

    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, _text, client_id: sent.append(client_id) or True,
    )
    recovered_at = claimed_at + bridge._DELIVERY_CLAIM_TTL_SECONDS + 1
    assert bridge._drain_outbox(
        "bot-token", now=recovered_at, delivery_id=delivery_id
    ) == 1
    assert sent == [claim["client_id"]]
    assert bridge._delivery_complete(delivery_id) is True


@pytest.mark.parametrize(
    ("send_succeeds", "expected_error_type", "expected_error_code"),
    [
        (True, "DeliveryAckStorageError", "delivery_ack_storage_failure"),
        (False, "DeliveryRequeueStorageError", "delivery_requeue_storage_failure"),
    ],
)
def test_delivery_finish_storage_failure_isolated_at_ttl_without_replay(
    monkeypatch,
    tmp_path,
    send_succeeds,
    expected_error_type,
    expected_error_code,
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)
    delivery_id, _rows = bridge._enqueue_delivery(
        "u1", "ctx", "reply", delivery_key=f"finish-io-{send_succeeds}:reply"
    )
    claimed_at = 1_000_000_000_000.0
    sent: list[str] = []

    def send_once_then_succeed(_token, _to, _ctx, _text, client_id):
        sent.append(client_id)
        if not send_succeeds and len(sent) == 1:
            raise TimeoutError("simulated send failure")
        return True

    real_finish = bridge._finish_delivery
    finish_calls = 0

    def fail_first_finish(*args, **kwargs):
        nonlocal finish_calls
        finish_calls += 1
        if finish_calls == 1:
            raise sqlite3.OperationalError("simulated finish storage failure")
        return real_finish(*args, **kwargs)

    monkeypatch.setattr(bridge, "_send_chunk", send_once_then_succeed)
    monkeypatch.setattr(bridge, "_finish_delivery", fail_first_finish)

    with pytest.raises(Exception) as error_info:
        bridge._drain_outbox(
            "bot-token", now=claimed_at, delivery_id=delivery_id
        )
    assert type(error_info.value).__name__ == expected_error_type
    assert str(error_info.value) == expected_error_code
    with bridge._outbox_connect() as conn:
        status, client_id = conn.execute(
            "SELECT status,client_id FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone()
    assert status == "submitting"

    recovered_at = claimed_at + bridge._DELIVERY_CLAIM_TTL_SECONDS + 1
    assert bridge._drain_outbox(
        "bot-token", now=recovered_at, delivery_id=delivery_id
    ) == 0
    assert sent == [client_id]
    assert bridge._delivery_complete(delivery_id) is False
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery WHERE delivery_id=?",
            (delivery_id,),
        ).fetchone() == ("recovery_required",)


def test_stale_processing_delivery_is_recovered_without_process_restart(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    assert bridge._DELIVERY_CLAIM_TTL_SECONDS <= 180
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_outbox.db")
    monkeypatch.setattr(bridge, "_SEND_ATTEMPT_TIMEOUT_SECONDS", 1.0)
    delivery_id, _rows = bridge._enqueue_delivery(
        "u1", "ctx", "reply", delivery_key="m1:reply"
    )
    abandoned = bridge._claim_delivery(now=10**12, delivery_id=delivery_id)
    assert abandoned is not None

    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, _text, client_id: sent.append(client_id) or True,
    )
    recovered_at = 10**12 + bridge._DELIVERY_CLAIM_TTL_SECONDS + 1
    assert bridge._drain_outbox(
        "bot-token", now=recovered_at, delivery_id=delivery_id
    ) == 1
    assert sent == [abandoned["client_id"]]
    assert bridge._delivery_complete(delivery_id) is True


def test_process_mutex_rejects_a_second_bridge_for_same_state_file(tmp_path):
    bridge = _load_bridge()
    path = tmp_path / "bridge.lock"
    first = bridge.BridgeInstanceLock(path)
    second = bridge.BridgeInstanceLock(path)
    assert first.acquire() is True
    try:
        assert second.acquire() is False
    finally:
        first.release()
        second.release()
    assert second.acquire() is True
    second.release()


def test_new_state_database_has_explicit_identity(monkeypatch, tmp_path):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    with bridge._outbox_connect() as conn:
        application_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])

    assert application_id == 0x4E435758  # NCWX
    assert user_version == 2


def test_schema_classifier_whitelists_only_the_six_frozen_generations(tmp_path):
    bridge = _load_bridge()
    cases: list[tuple[str, Path]] = []

    empty = tmp_path / "empty.db"
    empty.touch()
    cases.append(("empty", empty))

    v0_base = tmp_path / "v0-base.db"
    _create_weixin_state_v0(v0_base)
    cases.append(("v0_base", v0_base))

    v0_previous = tmp_path / "v0-previous.db"
    _create_weixin_state_previous_runtime_v0(v0_previous)
    cases.append(("v0_previous_runtime", v0_previous))

    v0_current = tmp_path / "v0-current.db"
    with sqlite3.connect(v0_current) as conn:
        for statement in bridge._OUTBOX_V1_SCHEMA_DDL:
            conn.execute(statement)
    cases.append(("v0_current_shape", v0_current))

    v1 = tmp_path / "v1.db"
    with sqlite3.connect(v1) as conn:
        for statement in bridge._OUTBOX_V1_SCHEMA_DDL:
            conn.execute(statement)
        conn.execute("PRAGMA application_id=0x4E435758")
        conn.execute("PRAGMA user_version=1")
    cases.append(("v1", v1))

    v2 = tmp_path / "v2.db"
    with sqlite3.connect(v2) as conn:
        for statement in bridge._OUTBOX_SCHEMA_DDL:
            conn.execute(statement)
        conn.execute("PRAGMA application_id=0x4E435758")
        conn.execute("PRAGMA user_version=2")
    cases.append(("v2", v2))

    for expected, database in cases:
        with sqlite3.connect(database) as conn:
            assert bridge._classify_outbox_schema(conn) == expected


def test_v1_to_v2_migration_is_one_conservative_chat_ordered_transaction(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "v1.db"
    with sqlite3.connect(database) as conn:
        for statement in bridge._OUTBOX_V1_SCHEMA_DDL:
            conn.execute(statement)
        conn.execute("PRAGMA application_id=0x4E435758")
        conn.execute("PRAGMA user_version=1")
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at,status) "
            "VALUES(200,'message-200','user-a','{}',9,9,'processing')"
        )
        conn.execute(
            "INSERT INTO pending_video"
            "(task_id,to_user_id,context_token,source_message_key,created_at,"
            "deadline_at,next_attempt_at,status,direct_attempted) "
            "VALUES('video-200','user-a','ctx','message-200',1,9,1,'processing',0)"
        )
        conn.execute(
            "INSERT INTO pending_video"
            "(task_id,to_user_id,context_token,source_message_key,created_at,"
            "deadline_at,next_attempt_at,status,direct_attempted) "
            "VALUES('video-done','user-z','ctx','message-z',1,9,1,'done',1)"
        )
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,to_user_id,context_token,text,status,"
            "delivery_id,client_id,chunk_index,chunk_count) "
            "VALUES(101,1,1,'user-b','ctx','deleted','pending',"
            "'delivery-high','client-high',0,1)"
        )
        conn.execute("DELETE FROM pending_delivery WHERE id=101")
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,to_user_id,context_token,text,status,"
            "delivery_id,client_id,chunk_index,chunk_count) "
            "VALUES(7,1,1,'user-b','ctx','reply-a','pending','delivery-a','client-7',0,1)"
        )
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,to_user_id,context_token,text,status,"
            "delivery_id,client_id,chunk_index,chunk_count) "
            "VALUES(8,1,1,'user-b','ctx','reply-b','processing','delivery-b','client-8',0,1)"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()

    with sqlite3.connect(database) as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 2
        inbound = conn.execute(
            "SELECT status,last_error,chat_seq FROM inbound_message WHERE id=200"
        ).fetchone()
        linked_video = conn.execute(
            "SELECT status,direct_attempted,chat_seq FROM pending_video "
            "WHERE task_id='video-200'"
        ).fetchone()
        done_video = conn.execute(
            "SELECT status,terminal_verification FROM pending_video "
            "WHERE task_id='video-done'"
        ).fetchone()
        ambiguous = conn.execute(
            "SELECT status,last_error,chat_seq FROM pending_delivery ORDER BY id"
        ).fetchall()
        allocator = conn.execute(
            "SELECT value FROM bridge_state WHERE key='__ncwx_chat_seq'"
        ).fetchone()
        max_seq = conn.execute(
            "SELECT MAX(chat_seq) FROM ("
            "SELECT chat_seq FROM inbound_message UNION ALL "
            "SELECT chat_seq FROM pending_delivery UNION ALL "
            "SELECT chat_seq FROM pending_video)"
        ).fetchone()[0]
        next_delivery_id = conn.execute(
            "INSERT INTO pending_delivery"
            "(created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(2,2,'user-next','ctx','next')"
        ).lastrowid

    assert inbound[:2] == ("recovery_required", "legacy_provider_outcome_unknown")
    assert linked_video[:2] == ("pending", 0)
    assert inbound[2] == linked_video[2] > 0
    assert done_video == ("done", "legacy_terminal_unverified")
    assert [row[:2] for row in ambiguous] == [
        ("recovery_required", "legacy_chat_order_ambiguous"),
        ("recovery_required", "legacy_chat_order_ambiguous"),
    ]
    assert int(allocator[0]) > int(max_seq)
    assert next_delivery_id == 102


@pytest.mark.parametrize("invalid_kind", ("status", "direct_attempted"))
def test_v1_illegal_values_roll_back_without_partial_v2_migration(
    monkeypatch, tmp_path, invalid_kind
):
    bridge = _load_bridge()
    database = tmp_path / f"v1-invalid-{invalid_kind}.db"
    with sqlite3.connect(database) as conn:
        for statement in bridge._OUTBOX_V1_SCHEMA_DDL:
            conn.execute(statement)
        conn.execute("PRAGMA application_id=0x4E435758")
        conn.execute("PRAGMA user_version=1")
        if invalid_kind == "status":
            conn.execute(
                "INSERT INTO inbound_message("
                "message_key,from_user_id,payload,received_at,next_attempt_at,status) "
                "VALUES('bad','user-1','{}',1,1,'submitting')"
            )
        else:
            conn.execute(
                "INSERT INTO pending_video("
                "task_id,to_user_id,context_token,source_message_key,created_at,"
                "deadline_at,next_attempt_at,direct_attempted) "
                "VALUES('bad','user-1','ctx','message-1',1,2,1,2)"
            )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    with pytest.raises(sqlite3.DatabaseError, match="Weixin v1"):
        bridge._outbox_connect()

    with sqlite3.connect(database) as conn:
        assert bridge._classify_outbox_schema(conn) == "v1"
        assert not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE '%_v1'"
        ).fetchall()


def test_concurrent_cold_start_converges_to_one_exact_current_schema(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    barrier = threading.Barrier(8)
    failures: list[BaseException] = []

    def connect_once() -> None:
        try:
            barrier.wait(timeout=10)
            bridge._outbox_connect().close()
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=connect_once) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert not any(worker.is_alive() for worker in workers)
    assert failures == []
    with sqlite3.connect(database) as conn:
        assert bridge._classify_outbox_schema(conn) == "v2"


def test_current_state_database_rejects_extra_schema_objects(monkeypatch, tmp_path):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE VIEW injected_delivery_view AS SELECT id FROM pending_delivery")

    with pytest.raises(sqlite3.DatabaseError, match="unknown Weixin state schema"):
        bridge._outbox_connect()

    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT type FROM sqlite_master WHERE name='injected_delivery_view'"
        ).fetchone() == ("view",)


def test_exact_v0_migration_is_transactional_idempotent_and_preserves_data(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,last_error,status) "
            "VALUES(7,1,2,3,'user-delivery','ctx-1','legacy reply','old error','pending')"
        )
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,status,last_error) "
            "VALUES(8,'message-8','user-1','{}',4,5,6,'processing','handler lost')"
        )
        conn.execute("INSERT INTO bridge_state VALUES('cursor','cursor-9',9)")
        conn.execute(
            "INSERT INTO pending_video"
            "(task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,next_attempt_at,status) "
            "VALUES('video-10','user-1','ctx-1','message-8',10,20,11,'pending')"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()
    bridge._outbox_connect().close()

    with sqlite3.connect(database) as conn:
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0x4E435758
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 2
        assert conn.execute(
            "SELECT id,attempts,to_user_id,text,last_error,status,delivery_id,client_id,"
            "chunk_index,chunk_count,claim_token,claimed_at,delivered_at "
            "FROM pending_delivery"
        ).fetchone() == (
            7,
            3,
            "user-delivery",
            "legacy reply",
            "old error",
            "pending",
            "legacy-7",
            "nachuan_legacy_7",
            0,
            1,
            "",
            0.0,
            0.0,
        )
        assert conn.execute(
            "SELECT id,message_key,status,last_error,attempts,claimed_at,claim_token,claim_deadline,"
            "heartbeat_at,claim_epoch,last_finish_token,last_finish_epoch,"
            "last_finish_outcome,request_sha256 FROM inbound_message"
        ).fetchone() == (
            8,
            "message-8",
            "recovery_required",
            "legacy_provider_outcome_unknown",
            6,
            0.0,
            "",
            0.0,
            0.0,
            0,
            "",
            0,
            "",
            "",
        )
        assert conn.execute("SELECT * FROM bridge_state").fetchone() == (
            "cursor",
            "cursor-9",
            9.0,
        )
        assert conn.execute(
            "SELECT task_id,source_message_key,status,direct_attempted FROM pending_video"
        ).fetchone() == ("video-10", "message-8", "pending", 0)


def test_oldest_v0_processing_delivery_requires_recovery_and_is_never_replayed(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,attempts,to_user_id,context_token,text,last_error,status) "
            "VALUES(7,1,1,0,'user-1','ctx-1','possibly delivered','','processing')"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()
    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda *_args, **_kwargs: sent.append("called") or True,
    )

    assert bridge._recover_delivery_claims(force=True, now=10**12) == 0
    assert bridge._drain_outbox("bot-token", now=10**12) == 0
    assert sent == []
    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT status,last_error,client_id FROM pending_delivery WHERE id=7"
        ).fetchone() == (
            "recovery_required",
            "legacy_provider_outcome_unknown",
            "nachuan_legacy_7",
        )


def test_oldest_v0_processing_inbound_and_video_require_recovery_and_never_replay(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,status,last_error) "
            "VALUES(8,'message-8','user-1','{}',1,1,0,'processing','handler lost')"
        )
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at,attempts,status,last_error) "
            "VALUES(9,'message-9','user-1','{}',2,2,0,'pending','')"
        )
        conn.execute(
            "INSERT INTO pending_video"
            "(task_id,to_user_id,context_token,source_message_key,created_at,deadline_at,"
            "next_attempt_at,attempts,status,result_url,last_error,claim_token,claimed_at,finished_at) "
            "VALUES('video-8','user-1','ctx-1','message-8',1,9999999999999,1,0,"
            "'processing','https://example.invalid/result.mp4','poll complete','old-claim',2,0)"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()
    processed_video: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_process_pending_video",
        lambda *_args, **_kwargs: processed_video.append("called"),
    )

    assert bridge._recover_inbound(force=True, now=10**12) == 0
    assert bridge._recover_pending_video_claims(force=True, now=10**12) == 0
    assert bridge._claim_inbound(now=10**12) is None
    assert bridge._drain_pending_videos("bot-token", now=10**12) == 0
    assert processed_video == []
    counts = bridge._queue_health_counts(now=10**12)
    assert counts[:5] == (2, 0, 1, 0, 0)
    # Two active inbound groups for one principal have no cross-table causal
    # proof in v0, so v2 conservatively isolates both instead of guessing by id/time.
    assert counts[5:8] == (2, 0, 1)
    assert bridge._inbox_pending_count() == 2
    monkeypatch.setattr(bridge, "_MAX_PENDING_VIDEO_ROWS", 1)
    with pytest.raises(bridge.VideoCapacityError):
        bridge._reserve_pending_video_capacity(
            "user-2",
            "ctx-2",
            source_message_key="message-other",
            now=3.0,
            _internal_maintenance=True,
        )
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (SimpleNamespace(configured=True), "user-1", ""),
    )
    health = bridge._update_health("healthy", consecutive_poll_failures=0)
    assert health["ready"] is False
    assert "recovery_required_inbound" in health["readiness_reasons"]
    assert "recovery_required_video" in health["readiness_reasons"]
    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT status,last_error,claim_token,claimed_at FROM inbound_message "
            "WHERE id=8"
        ).fetchone() == (
            "recovery_required",
            "legacy_chat_order_ambiguous",
            "",
            0.0,
        )
        assert conn.execute(
            "SELECT status,result_url,direct_attempted,last_error,claim_token,claimed_at "
            "FROM pending_video WHERE task_id='video-8'"
        ).fetchone() == (
            "recovery_required",
            "https://example.invalid/result.mp4",
            1,
            "legacy_chat_order_ambiguous",
            "",
            0.0,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows delete semantics prove handle closure")
def test_outbox_read_helper_closes_its_handle_without_cyclic_gc(monkeypatch, tmp_path):
    import gc

    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        assert bridge._outbox_pending_count() == 0
        database.unlink()
    finally:
        gc.collect()
        if database.exists():
            database.unlink()
        if gc_was_enabled:
            gc.enable()

    assert not database.exists()


def test_v0_migration_preserves_autoincrement_high_water_marks(monkeypatch, tmp_path):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(100,1,1,'user-1','ctx-1','deleted')"
        )
        conn.execute("DELETE FROM pending_delivery WHERE id=100")
        conn.execute(
            "INSERT INTO pending_delivery"
            "(id,created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(7,1,1,'user-1','ctx-1','kept')"
        )
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at) "
            "VALUES(200,'deleted','user-1','{}',1,1)"
        )
        conn.execute("DELETE FROM inbound_message WHERE id=200")
        conn.execute(
            "INSERT INTO inbound_message"
            "(id,message_key,from_user_id,payload,received_at,next_attempt_at) "
            "VALUES(8,'kept','user-1','{}',1,1)"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    with bridge._outbox_connect() as conn:
        pending_id = conn.execute(
            "INSERT INTO pending_delivery"
            "(created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(2,2,'user-2','ctx-2','next')"
        ).lastrowid
        inbound_id = conn.execute(
            "INSERT INTO inbound_message"
            "(message_key,from_user_id,payload,received_at,next_attempt_at) "
            "VALUES('next','user-2','{}',2,2)"
        ).lastrowid

    assert pending_id == 101
    assert inbound_id == 201


def test_current_state_schema_has_exact_inventory_constraints_and_defaults(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    with bridge._outbox_connect() as conn:
        inventory = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in conn.execute(
                "SELECT type,name,tbl_name FROM sqlite_master"
            ).fetchall()
        }
        schema_sql = tuple(
            str(row[0])
            for row in conn.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
        )
        delivery_columns = bridge._table_columns(conn, "pending_delivery")
        video_columns = bridge._table_columns(conn, "pending_video")
        receipt_columns = bridge._table_columns(conn, "recovery_receipt")
        conn.execute(
            "INSERT INTO pending_delivery"
            "(created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(1,1,'user-1','ctx-1','reply')"
        )
        defaults = conn.execute(
            "SELECT attempts,last_error,status,delivery_id,client_id,chunk_index,"
            "chunk_count,claim_token,claimed_at,delivered_at FROM pending_delivery"
        ).fetchone()
        conn.execute(
            "INSERT INTO inbound_message"
            "(message_key,from_user_id,payload,received_at,next_attempt_at) "
            "VALUES('message-1','user-1','{}',1,1)"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO inbound_message"
                "(message_key,from_user_id,payload,received_at,next_attempt_at) "
                "VALUES('message-1','user-2','{}',2,2)"
            )

    assert len(bridge._OUTBOX_SCHEMA_DDL) == 22
    assert len(inventory) == 26
    assert sum(kind == "table" for kind, _name, _table in inventory) == 6
    assert sum(kind == "index" for kind, _name, _table in inventory) == 17
    assert sum(name.startswith("sqlite_autoindex_") for _kind, name, _table in inventory) == 3
    assert sum(kind == "trigger" for kind, _name, _table in inventory) == 3
    assert {
        "recovery_receipt",
        "trg_recovery_receipt_no_delete",
        "trg_recovery_receipt_no_replace",
        "trg_recovery_receipt_no_update",
        "uq_recovery_receipt_decision_id",
        "uq_recovery_receipt_id",
        "uq_recovery_receipt_operation_digest",
        "uq_recovery_receipt_previous_sha256",
        "uq_recovery_receipt_sha256",
    } <= {name for _kind, name, _table in inventory}
    assert {
        "claim_deadline",
        "heartbeat_at",
        "claim_epoch",
        "last_finish_token",
        "last_finish_epoch",
        "last_finish_outcome",
        "request_sha256",
        "submission_started_at",
        "platform_response_sha256",
        "terminal_verification",
        "chat_seq",
        "parent_message_key",
    } <= delivery_columns
    assert {
        "chat_seq",
        "submission_phase",
        "upload_grant_request_sha256",
        "upload_grant_started_at",
        "upload_request_sha256",
        "upload_started_at",
        "send_request_sha256",
        "send_started_at",
        "platform_response_sha256",
        "terminal_verification",
    } <= video_columns
    assert receipt_columns == {
        "id",
        "created_at",
        "operation",
        "operation_digest",
        "decision_id",
        "principal_sha256",
        "row_before_sha256",
        "previous_receipt_sha256",
        "receipt_sha256",
        "record_json",
    }
    assert all("IF NOT EXISTS" not in sql.upper() for sql in schema_sql)
    assert defaults == (0, "", "pending", "", "", 0, 1, "", 0.0, 0.0)


def test_recovery_receipt_validator_rejects_malformed_rows_on_open(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO recovery_receipt("
            "id,created_at,operation,operation_digest,decision_id,principal_sha256,"
            "row_before_sha256,previous_receipt_sha256,receipt_sha256,record_json) "
            "VALUES(1,1,'','','','','','','','{}')"
        )

    with pytest.raises(sqlite3.DatabaseError, match="invalid Weixin recovery receipt"):
        bridge._outbox_connect()


def test_recovery_receipt_is_append_only_even_with_insert_or_replace(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    insert_sql = (
        "INSERT INTO recovery_receipt("
        "id,created_at,operation,operation_digest,decision_id,principal_sha256,"
        "row_before_sha256,previous_receipt_sha256,receipt_sha256,record_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)"
    )
    first = (
        1,
        1.0,
        "close_without_replay",
        "op-a",
        "decision-a",
        "principal-a",
        "row-a",
        "genesis",
        "receipt-a",
        "{}",
    )
    with sqlite3.connect(database) as conn:
        conn.execute(insert_sql, first)
        for position in (0, 3, 4, 7, 8):
            replacement = list(
                (
                    2,
                    2.0,
                    "close_without_replay",
                    "op-b",
                    "decision-b",
                    "principal-b",
                    "row-b",
                    "receipt-a",
                    "receipt-b",
                    "{}",
                )
            )
            replacement[position] = first[position]
            with pytest.raises(
                sqlite3.IntegrityError,
                match="recovery receipt replacement forbidden",
            ):
                conn.execute(insert_sql.replace("INSERT", "INSERT OR REPLACE", 1), replacement)
        with pytest.raises(sqlite3.IntegrityError, match="update forbidden"):
            conn.execute("UPDATE recovery_receipt SET operation='changed' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError, match="delete forbidden"):
            conn.execute("DELETE FROM recovery_receipt WHERE id=1")


def test_weixin_close_without_replay_closes_whole_principal_and_writes_receipt(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,last_error,claim_epoch,"
            "last_finish_token,last_finish_epoch,last_finish_outcome,chat_seq) "
            "VALUES(?,?,?,?,?,'recovery_required','provider_unknown',7,"
            "'inbound-finish',7,'recovery_required',1)",
            ("recover-message", "wx-recover-user", '{"secret":"inbound"}', 1, 1),
        )
        conn.execute(
            "INSERT INTO pending_delivery(created_at,next_attempt_at,to_user_id,"
            "context_token,text,status,last_error,delivery_id,client_id,chat_seq,"
            "claim_epoch,last_finish_token,last_finish_epoch,last_finish_outcome) "
            "VALUES(?,?,?,?,?,'recovery_required','provider_unknown',?,?,2,8,?,?,"
            "'recovery_required')",
            (
                2,
                2,
                "wx-recover-user",
                "secret-context",
                "secret reply",
                "recover-delivery",
                "recover-client",
                "delivery-finish",
                8,
            ),
        )
        conn.execute(
            "INSERT INTO pending_video(task_id,to_user_id,context_token,"
            "source_message_key,created_at,deadline_at,next_attempt_at,status,"
            "result_url,direct_attempted,last_error,claim_epoch,last_finish_token,"
            "last_finish_epoch,last_finish_outcome,chat_seq,submission_phase,"
            "send_request_sha256,send_started_at) VALUES(?,?,?,?,?,?,?,"
            "'recovery_required',?,1,'video_submission_outcome_unknown',9,?,9,"
            "'recovery_required',3,'send_submitting',?,3)",
            (
                "recover-video",
                "wx-recover-user",
                "secret-video-context",
                "recover-message",
                3,
                9999,
                3,
                "https://media.example/private.mp4",
                "video-finish",
                "a" * 64,
            ),
        )
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,chat_seq) "
            "VALUES('other-message','wx-other-user','{}',4,4,'recovery_required',4)"
        )

    expected_before = bridge._weixin_recovery_target_before_digest(
        "video", "recover-video"
    )
    fields = {
        "decision_id": "d" * 64,
        "target_kind": "video",
        "target_key": "recover-video",
        "expected_before_digest": expected_before,
        "actor": "operator:alice",
        "authorization": "e" * 64,
        "reason": "verified no automatic replay",
        "decided_at_ms": 1_700_000_000_000,
    }
    request = bridge._WeixinCloseWithoutReplayRequest(
        operation_digest=bridge._weixin_close_without_replay_operation_digest(
            **fields
        ),
        **fields,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("manual close must not call any external seam")

    for name in (
        "_engine_get_json",
        "_fetch_media",
        "_send_media",
        "_send_chunk",
        "_engine_post",
    ):
        monkeypatch.setattr(bridge, name, forbidden)

    result = bridge._weixin_close_without_replay(
        request, closed_at_ms=1_700_000_000_123
    )
    assert result.applied is True
    assert result.affected_inbound_count == 1
    assert result.affected_delivery_count == 1
    assert result.affected_video_count == 1
    with sqlite3.connect(database) as conn:
        inbound = conn.execute(
            "SELECT status,from_user_id,payload,last_error,claim_token,"
            "last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM inbound_message WHERE message_key='recover-message'"
        ).fetchone()
        delivery = conn.execute(
            "SELECT status,to_user_id,context_token,text,last_error,claim_token,"
            "last_finish_token,last_finish_epoch,last_finish_outcome,"
            "terminal_verification FROM pending_delivery "
            "WHERE delivery_id='recover-delivery'"
        ).fetchone()
        video = conn.execute(
            "SELECT status,to_user_id,context_token,result_url,last_error,"
            "claim_token,last_finish_token,last_finish_epoch,last_finish_outcome,"
            "submission_phase,send_request_sha256,terminal_verification "
            "FROM pending_video WHERE task_id='recover-video'"
        ).fetchone()
        untouched = conn.execute(
            "SELECT status,from_user_id FROM inbound_message "
            "WHERE message_key='other-message'"
        ).fetchone()
        receipt = conn.execute(
            "SELECT operation_digest,decision_id,principal_sha256,"
            "row_before_sha256,previous_receipt_sha256,receipt_sha256,record_json "
            "FROM recovery_receipt"
        ).fetchone()

    assert inbound == (
        "dead",
        bridge._opaque_identity("wx-recover-user"),
        bridge._RECOVERY_TOMBSTONE,
        "closed_without_replay",
        "",
        "inbound-finish",
        7,
        "recovery_required",
    )
    assert delivery == (
        "dead",
        bridge._opaque_identity("wx-recover-user"),
        "",
        "",
        "closed_without_replay",
        "",
        "delivery-finish",
        8,
        "recovery_required",
        "closed_without_replay",
    )
    assert video == (
        "dead",
        bridge._opaque_identity("wx-recover-user"),
        "",
        "",
        "closed_without_replay",
        "",
        "video-finish",
        9,
        "recovery_required",
        "send_submitting",
        "a" * 64,
        "closed_without_replay",
    )
    assert untouched == ("recovery_required", "wx-other-user")
    assert receipt[:2] == (request.operation_digest, "d" * 64)
    assert receipt[4] == "0" * 64
    assert receipt[5] == result.receipt_sha256
    record = json.loads(receipt[6])
    assert record["affected_counts"] == {
        "delivery": 1,
        "inbound": 1,
        "video": 1,
    }
    assert len(record["affected_rows"]) == 3


def test_weixin_close_without_replay_response_loss_retry_uses_operation_only(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,chat_seq) "
            "VALUES('retry-target','wx-retry','{}',1,1,'recovery_required',1)"
        )
    before = bridge._weixin_recovery_target_before_digest(
        "inbound", "retry-target"
    )
    fields = {
        "decision_id": "1" * 64,
        "target_kind": "inbound",
        "target_key": "retry-target",
        "expected_before_digest": before,
        "actor": "operator:bob",
        "authorization": "2" * 64,
        "reason": "confirmed no replay",
        "decided_at_ms": 5000,
    }
    request = bridge._WeixinCloseWithoutReplayRequest(
        operation_digest=bridge._weixin_close_without_replay_operation_digest(
            **fields
        ),
        **fields,
    )
    first = bridge._weixin_close_without_replay(request, closed_at_ms=5001)
    assert first.applied is True
    monkeypatch.setattr(
        bridge,
        "_weixin_recovery_target_rows_in_transaction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("idempotent retry must not re-read target")
        ),
    )

    retry = bridge._weixin_close_without_replay(request, closed_at_ms=9000)
    assert retry == bridge._WeixinCloseWithoutReplayResult(
        operation_digest=first.operation_digest,
        receipt_sha256=first.receipt_sha256,
        affected_inbound_count=1,
        affected_delivery_count=0,
        affected_video_count=0,
        applied=False,
    )


def test_weixin_close_without_replay_rejects_target_drift_atomically(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,chat_seq) "
            "VALUES('drift-target','wx-drift','{}',1,1,'recovery_required',1)"
        )
    before = bridge._weixin_recovery_target_before_digest(
        "inbound", "drift-target"
    )
    fields = {
        "decision_id": "3" * 64,
        "target_kind": "inbound",
        "target_key": "drift-target",
        "expected_before_digest": before,
        "actor": "operator:carol",
        "authorization": "4" * 64,
        "reason": "close exact affected set",
        "decided_at_ms": 6000,
    }
    request = bridge._WeixinCloseWithoutReplayRequest(
        operation_digest=bridge._weixin_close_without_replay_operation_digest(
            **fields
        ),
        **fields,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO pending_video(task_id,to_user_id,context_token,"
            "source_message_key,created_at,deadline_at,next_attempt_at,status,chat_seq) "
            "VALUES('drift-video','wx-drift','ctx','drift-target',2,9,2,"
            "'recovery_required',2)"
        )

    with pytest.raises(bridge.WeixinRecoveryConflict, match="drifted"):
        bridge._weixin_close_without_replay(request, closed_at_ms=6001)
    with sqlite3.connect(bridge._OUTBOX_DB) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM recovery_receipt"
        ).fetchone()[0] == 0
        assert set(
            row[0]
            for row in conn.execute(
                "SELECT status FROM inbound_message UNION ALL "
                "SELECT status FROM pending_video"
            )
        ) == {"recovery_required"}


def test_weixin_close_without_replay_rejects_active_claim_and_decision_reuse(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        for key, principal, seq in (
            ("decision-a", "wx-decision-a", 1),
            ("decision-b", "wx-decision-b", 2),
            ("active-target", "wx-active", 3),
        ):
            conn.execute(
                "INSERT INTO inbound_message(message_key,from_user_id,payload,"
                "received_at,next_attempt_at,status,chat_seq) "
                "VALUES(?,?,?,?,?,'recovery_required',?)",
                (key, principal, "{}", seq, seq, seq),
            )

    def make_request(key, decision, actor, decided):
        before = bridge._weixin_recovery_target_before_digest("inbound", key)
        fields = {
            "decision_id": decision,
            "target_kind": "inbound",
            "target_key": key,
            "expected_before_digest": before,
            "actor": actor,
            "authorization": "6" * 64,
            "reason": "one exact manual decision",
            "decided_at_ms": decided,
        }
        return bridge._WeixinCloseWithoutReplayRequest(
            operation_digest=bridge._weixin_close_without_replay_operation_digest(
                **fields
            ),
            **fields,
        )

    shared_decision = "5" * 64
    first = make_request("decision-a", shared_decision, "operator:first", 7000)
    second = make_request("decision-b", shared_decision, "operator:second", 7000)
    active = make_request("active-target", "7" * 64, "operator:active", 8000)
    assert bridge._weixin_close_without_replay(first, closed_at_ms=7001).applied
    with pytest.raises(bridge.WeixinRecoveryConflict, match="decision id"):
        bridge._weixin_close_without_replay(second, closed_at_ms=7002)
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE inbound_message SET claim_token='active',claimed_at=8,"
            "claim_deadline=999,heartbeat_at=8 WHERE message_key='active-target'"
        )
    with pytest.raises(bridge.WeixinRecoveryConflict, match="actively claimed"):
        bridge._weixin_close_without_replay(active, closed_at_ms=8001)
    with sqlite3.connect(bridge._OUTBOX_DB) as conn:
        assert conn.execute(
            "SELECT status FROM inbound_message WHERE message_key='decision-b'"
        ).fetchone() == ("recovery_required",)
        assert conn.execute(
            "SELECT status,claim_token FROM inbound_message "
            "WHERE message_key='active-target'"
        ).fetchone() == ("recovery_required", "active")
        assert conn.execute(
            "SELECT COUNT(*) FROM recovery_receipt"
        ).fetchone()[0] == 1


def test_weixin_close_without_replay_receipt_capacity_is_atomic(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_RECOVERY_RECEIPTS", 1)
    with bridge._outbox_connect() as conn:
        for key, principal, seq in (
            ("capacity-a", "wx-capacity-a", 1),
            ("capacity-b", "wx-capacity-b", 2),
        ):
            conn.execute(
                "INSERT INTO inbound_message(message_key,from_user_id,payload,"
                "received_at,next_attempt_at,status,chat_seq) "
                "VALUES(?,?,?,?,?,'recovery_required',?)",
                (key, principal, "{}", seq, seq, seq),
            )

    def request_for(key, marker):
        fields = {
            "decision_id": marker * 64,
            "target_kind": "inbound",
            "target_key": key,
            "expected_before_digest": (
                bridge._weixin_recovery_target_before_digest("inbound", key)
            ),
            "actor": f"operator:{marker}",
            "authorization": "9" * 64,
            "reason": "bounded receipt capacity",
            "decided_at_ms": 9000,
        }
        return bridge._WeixinCloseWithoutReplayRequest(
            operation_digest=bridge._weixin_close_without_replay_operation_digest(
                **fields
            ),
            **fields,
        )

    first = request_for("capacity-a", "a")
    second = request_for("capacity-b", "b")
    assert bridge._weixin_close_without_replay(first, closed_at_ms=9001).applied
    with pytest.raises(bridge.WeixinRecoveryConflict, match="capacity"):
        bridge._weixin_close_without_replay(second, closed_at_ms=9002)
    with sqlite3.connect(bridge._OUTBOX_DB) as conn:
        assert conn.execute(
            "SELECT status FROM inbound_message WHERE message_key='capacity-b'"
        ).fetchone() == ("recovery_required",)
        assert conn.execute(
            "SELECT COUNT(*) FROM recovery_receipt"
        ).fetchone()[0] == 1


def test_weixin_close_without_replay_strictly_validates_request_fields(
    monkeypatch,
):
    bridge = _load_bridge()
    baseline = {
        "decision_id": "1" * 64,
        "target_kind": "inbound",
        "target_key": "valid-target",
        "expected_before_digest": "2" * 64,
        "actor": "operator:strict",
        "authorization": "3" * 64,
        "reason": "validated reason",
        "decided_at_ms": 10_000,
    }
    invalid = (
        ("decision_id", "0" * 64),
        ("target_kind", "unknown"),
        ("target_key", " target"),
        ("expected_before_digest", "G" * 64),
        ("actor", "operator\nadmin"),
        ("authorization", "short"),
        ("reason", " reason"),
        ("decided_at_ms", True),
    )
    for field, value in invalid:
        fields = dict(baseline)
        fields[field] = value
        with pytest.raises(ValueError):
            bridge._weixin_close_without_replay_operation_digest(**fields)


def test_weixin_recovery_receipt_validator_rejects_invalid_manifest(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    digest, record = bridge._canonical_recovery_receipt_record(
        receipt_id=1,
        created_at=11.001,
        operation="close_without_replay",
        operation_digest="1" * 64,
        decision_id="2" * 64,
        principal_sha256="3" * 64,
        row_before_sha256="4" * 64,
        previous_receipt_sha256="0" * 64,
        target_kind="inbound",
        target_key_sha256="5" * 64,
        actor="operator:forged",
        authorization="6" * 64,
        reason="manifest count mismatch",
        decided_at_ms=11_000,
        closed_at_ms=11_001,
        after_sha256="7" * 64,
        affected_counts={"inbound": 1, "delivery": 0, "video": 0},
        affected_rows=[],
    )
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO recovery_receipt(id,created_at,operation,operation_digest,"
            "decision_id,principal_sha256,row_before_sha256,"
            "previous_receipt_sha256,receipt_sha256,record_json) "
            "VALUES(1,11.001,'close_without_replay',?,?,?,?,?,?,?)",
            (
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "0" * 64,
                digest,
                record,
            ),
        )

    with pytest.raises(sqlite3.DatabaseError, match="invalid Weixin recovery receipt"):
        bridge._outbox_connect()


def test_weixin_close_without_replay_receipt_failure_rolls_back_rows(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,chat_seq) "
            "VALUES('rollback-target','wx-rollback','{\"keep\":true}',1,1,"
            "'recovery_required',1)"
        )
    fields = {
        "decision_id": "8" * 64,
        "target_kind": "inbound",
        "target_key": "rollback-target",
        "expected_before_digest": (
            bridge._weixin_recovery_target_before_digest(
                "inbound", "rollback-target"
            )
        ),
        "actor": "operator:rollback",
        "authorization": "9" * 64,
        "reason": "receipt must commit with row changes",
        "decided_at_ms": 12_000,
    }
    request = bridge._WeixinCloseWithoutReplayRequest(
        operation_digest=bridge._weixin_close_without_replay_operation_digest(
            **fields
        ),
        **fields,
    )
    monkeypatch.setattr(
        bridge,
        "_canonical_recovery_receipt_record",
        lambda **_kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("synthetic receipt failure")
        ),
    )

    with pytest.raises(sqlite3.OperationalError, match="receipt failure"):
        bridge._weixin_close_without_replay(request, closed_at_ms=12_001)
    with sqlite3.connect(bridge._OUTBOX_DB) as conn:
        assert conn.execute(
            "SELECT status,from_user_id,payload FROM inbound_message "
            "WHERE message_key='rollback-target'"
        ).fetchone() == (
            "recovery_required",
            "wx-rollback",
            '{"keep":true}',
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM recovery_receipt"
        ).fetchone()[0] == 0


def test_unknown_higher_schema_version_is_rejected_without_rewrite(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA user_version=3")
    before = database.read_bytes()

    with pytest.raises(sqlite3.DatabaseError, match="unknown Weixin state schema"):
        bridge._outbox_connect()

    assert database.read_bytes() == before
    with sqlite3.connect(database) as conn:
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0x4E435758
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 3


def test_unknown_schema_is_rejected_before_any_readwrite_open(monkeypatch, tmp_path):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    bridge._outbox_connect().close()
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA user_version=3")

    real_connect = bridge.sqlite3.connect
    path_opens: list[bool] = []

    def readonly_guard(target, *args, **kwargs):
        rendered = str(target)
        decoded = urllib.parse.unquote(rendered)
        if rendered == str(database) or database.as_posix() in decoded:
            is_readonly_uri = bool(kwargs.get("uri")) and "mode=ro" in rendered
            path_opens.append(is_readonly_uri)
            if not is_readonly_uri:
                raise AssertionError("unknown schema reached a read-write SQLite open")
        return real_connect(target, *args, **kwargs)

    monkeypatch.setattr(bridge.sqlite3, "connect", readonly_guard)

    with pytest.raises(sqlite3.DatabaseError, match="unknown Weixin state schema"):
        bridge._outbox_connect()
    assert path_opens == [True]


def test_unknown_version_committed_in_wal_is_seen_by_readonly_preflight(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    writer = bridge._outbox_connect()
    try:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("PRAGMA user_version=3")
        writer.commit()
        assert Path(f"{database}-wal").is_file()
        assert Path(f"{database}-shm").is_file()

        real_connect = bridge.sqlite3.connect
        path_opens: list[bool] = []

        def readonly_guard(target, *args, **kwargs):
            rendered = str(target)
            decoded = urllib.parse.unquote(rendered)
            if rendered == str(database) or database.as_posix() in decoded:
                is_readonly_uri = bool(kwargs.get("uri")) and "mode=ro" in rendered
                path_opens.append(is_readonly_uri)
                if not is_readonly_uri:
                    raise AssertionError("unknown WAL schema reached a read-write open")
            return real_connect(target, *args, **kwargs)

        monkeypatch.setattr(bridge.sqlite3, "connect", readonly_guard)
        with pytest.raises(sqlite3.DatabaseError, match="unknown Weixin state schema"):
            bridge._outbox_connect()
        assert path_opens == [True]
    finally:
        writer.close()


def test_v0_migration_failure_rolls_back_the_entire_schema_and_all_rows(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        for task_id in ("video-1", "video-2"):
            conn.execute(
                "INSERT INTO pending_video"
                "(task_id,to_user_id,context_token,source_message_key,created_at,"
                "deadline_at,next_attempt_at,status) VALUES(?,?,?,?,1,2,1,'pending')",
                (task_id, "user-1", "ctx-1", "same-message"),
            )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    with pytest.raises(sqlite3.IntegrityError):
        bridge._outbox_connect()

    with sqlite3.connect(database) as conn:
        assert bridge._classify_outbox_schema(conn) == "v0_base"
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_video").fetchone()[0] == 2
        assert not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE '%_v0'"
        ).fetchall()


def test_exact_unversioned_current_v0_is_stamped_without_data_loss(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    with sqlite3.connect(database) as conn:
        for statement in bridge._OUTBOX_V1_SCHEMA_DDL:
            conn.execute(statement)
        conn.execute("INSERT INTO bridge_state VALUES('cursor','kept',1)")
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA application_id=0")
        conn.execute("PRAGMA user_version=0")

    bridge._outbox_connect().close()

    with sqlite3.connect(database) as conn:
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0x4E435758
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 2
        assert conn.execute(
            "SELECT key,value,updated_at FROM bridge_state WHERE key='cursor'"
        ).fetchone() == (
            "cursor",
            "kept",
            1.0,
        )


def test_previous_runtime_v0_is_explicitly_migrated_without_data_loss(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    _create_weixin_state_previous_runtime_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pending_delivery"
            "(created_at,next_attempt_at,to_user_id,context_token,text,delivery_id,client_id) "
            "VALUES(1,1,'user-1','ctx-1','old reply','delivery-1','client-1')"
        )
        conn.execute("INSERT INTO bridge_state VALUES('cursor','old-cursor',1)")
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)

    bridge._outbox_connect().close()

    with sqlite3.connect(database) as conn:
        assert int(conn.execute("PRAGMA application_id").fetchone()[0]) == 0x4E435758
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 2
        assert conn.execute(
            "SELECT text,delivery_id,client_id FROM pending_delivery"
        ).fetchone() == ("old reply", "delivery-1", "client-1")
        assert conn.execute(
            "SELECT value FROM bridge_state WHERE key='cursor'"
        ).fetchone() == (
            "old-cursor",
        )
        assert all(
            "IF NOT EXISTS" not in str(row[0]).upper()
            for row in conn.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
        )


def test_legacy_whole_message_outbox_is_migrated_to_one_stable_chunk(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    db = tmp_path / "legacy.db"
    _create_weixin_state_v0(db)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO pending_delivery(created_at,next_attempt_at,to_user_id,context_token,text) "
            "VALUES(1,1,'u1','ctx','legacy reply')"
        )
    monkeypatch.setattr(bridge, "_OUTBOX_DB", db)

    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT delivery_id,client_id,chunk_index,chunk_count,status "
            "FROM pending_delivery"
        ).fetchone()
    assert row is not None
    assert row[0].startswith("legacy-")
    assert row[1].startswith("nachuan_legacy_")
    assert row[2:] == (0, 1, "pending")


def test_legacy_inbound_table_gains_lease_columns_without_losing_rows(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            """
            INSERT INTO inbound_message
              (message_key,from_user_id,payload,received_at,next_attempt_at,status)
            VALUES ('legacy-inbound','user-1','{}',1,1,'processing')
            """
        )

    with bridge._outbox_connect() as conn:
        columns = bridge._table_columns(conn, "inbound_message")
        row = conn.execute(
            "SELECT message_key,status,last_error,claimed_at,claim_token,claim_deadline "
            "FROM inbound_message"
        ).fetchone()

    assert {"claimed_at", "claim_token", "claim_deadline"} <= columns
    assert row == (
        "legacy-inbound",
        "recovery_required",
        "legacy_provider_outcome_unknown",
        0.0,
        "",
        0.0,
    )


def test_unlisted_intermediate_schema_is_rejected_without_repair(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    database = tmp_path / "weixin_state.db"
    monkeypatch.setattr(bridge, "_OUTBOX_DB", database)
    _create_weixin_state_v0(database)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "ALTER TABLE inbound_message "
            "ADD COLUMN claimed_at REAL NOT NULL DEFAULT 0"
        )
        conn.execute(
            """
            INSERT INTO inbound_message
              (message_key,from_user_id,payload,received_at,next_attempt_at,status)
            VALUES ('legacy-audit','user-1','{}',1,1,'processing')
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="unknown Weixin state schema"):
        bridge._outbox_connect()

    with sqlite3.connect(database) as conn:
        assert bridge._table_columns(conn, "inbound_message") == {
            "id",
            "message_key",
            "from_user_id",
            "payload",
            "received_at",
            "next_attempt_at",
            "attempts",
            "status",
            "last_error",
            "claimed_at",
        }
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 0
        assert conn.execute(
            "SELECT message_key,status,claimed_at FROM inbound_message"
        ).fetchone() == ("legacy-audit", "processing", 0.0)


def test_inbound_claim_samples_policy_time_after_begin_immediate(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "lock-wait-claim",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    bridge._store_updates([message], "cursor-lock-wait")
    before_lock = time.time() + 10.0
    after_lock = before_lock + 100.0
    current = {"value": before_lock}
    real_connect = bridge._outbox_connect

    class BeginAdvancingConnection:
        def __init__(self):
            self._conn = real_connect()

        def execute(self, sql, parameters=()):
            result = self._conn.execute(sql, parameters)
            if sql == "BEGIN IMMEDIATE":
                current["value"] = after_lock
            return result

        def __getattr__(self, name):
            return getattr(self._conn, name)

    monkeypatch.setattr(bridge, "_outbox_connect", BeginAdvancingConnection)
    claimed = bridge._claim_inbound(now=lambda: current["value"])

    assert claimed is not None
    assert claimed[3] == 1
    with real_connect() as conn:
        row = conn.execute(
            "SELECT claimed_at,heartbeat_at,claim_epoch,claim_deadline "
            "FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
    assert row == (
        after_lock,
        after_lock,
        1,
        after_lock + bridge._INBOUND_CLAIM_TTL_SECONDS,
    )


def test_inbound_updates_are_durable_deduplicated_and_ordered_per_user(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    first = {"message_id": "m1", "from_user_id": "user-1", "item_list": [{"type": 1, "text_item": {"text": "one"}}]}
    second = {"message_id": "m2", "from_user_id": "user-1", "item_list": [{"type": 1, "text_item": {"text": "two"}}]}
    other = {"message_id": "m3", "from_user_id": "user-2", "item_list": [{"type": 1, "text_item": {"text": "other"}}]}

    bridge._store_updates([first, second, other], "cursor-1")
    bridge._store_updates([first], "cursor-1")
    assert bridge._load_cursor() == "cursor-1"
    assert bridge._inbox_pending_count() == 3

    claimed_first = bridge._claim_inbound()
    assert claimed_first and claimed_first[1]["message_id"] == "m1"
    claimed_other = bridge._claim_inbound()
    assert claimed_other and claimed_other[1]["message_id"] == "m3"
    assert bridge._claim_inbound() is None

    bridge._finish_inbound(
        claimed_first[0],
        claim_token=claimed_first[2],
        claim_epoch=claimed_first[3],
        ok=True,
    )
    claimed_second = bridge._claim_inbound()
    assert claimed_second and claimed_second[1]["message_id"] == "m2"


def test_inbound_provider_id_is_sender_scoped_and_semantic_conflicts_fail_closed(
    monkeypatch,
    tmp_path,
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    first = {
        "message_id": "provider-reused-id",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "first"}}],
    }
    other_principal = {
        **first,
        "from_user_id": "user-2",
    }
    conflicting = {
        **first,
        "item_list": [{"type": 1, "text_item": {"text": "changed"}}],
    }

    assert bridge._message_key(first) != bridge._message_key(other_principal)
    assert bridge._store_updates([first, other_principal], "cursor-1") is True
    with pytest.raises(bridge.InboundSemanticConflict, match="semantic_conflict"):
        bridge._store_updates([conflicting], "cursor-2")

    with bridge._outbox_connect() as conn:
        rows = conn.execute(
            "SELECT message_key,from_user_id,request_sha256,payload "
            "FROM inbound_message ORDER BY from_user_id"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] != rows[1][0]
    assert all(len(row[2]) == 64 for row in rows)
    assert json.loads(rows[0][3]) == first
    assert bridge._load_cursor() == "cursor-1"


def test_legacy_inbound_key_is_deduplicated_and_preserved_for_pending_replay(
    monkeypatch,
    tmp_path,
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "legacy-provider-id",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "legacy"}}],
    }
    payload, payload_digest = bridge._bounded_message_payload(message)
    assert payload is not None
    legacy_key = bridge._legacy_message_key(message, payload_digest=payload_digest)
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message "
            "(message_key,from_user_id,payload,received_at,next_attempt_at,status) "
            "VALUES (?,?,?,?,?,'pending')",
            (legacy_key, "user-1", payload, 1.0, 1.0),
        )

    assert bridge._store_updates([message], "cursor-legacy") is True
    with bridge._outbox_connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM inbound_message").fetchone()[0] == 1
    claimed = bridge._claim_inbound(now=2.0)
    assert claimed is not None
    assert claimed[1]["_nachuan_message_key"] == legacy_key


def test_expired_inbound_claim_is_reclaimed_before_same_chat_can_advance(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"user-1"}), "", ""),
    )
    first = {
        "message_id": "stuck-1",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "one"}}],
    }
    second = {
        "message_id": "stuck-2",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "two"}}],
    }
    bridge._store_updates([first, second], "cursor-stuck")
    claimed_at = 1_000_000_000_000.0

    abandoned = bridge._claim_inbound(now=claimed_at)
    assert abandoned is not None
    assert abandoned[1]["message_id"] == "stuck-1"
    assert bridge._claim_inbound(
        now=claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS - 0.001
    ) is None

    reclaimed_at = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS + 0.001
    reclaimed = bridge._claim_inbound(now=reclaimed_at)
    assert reclaimed is not None
    assert reclaimed[0] == abandoned[0]
    assert reclaimed[1]["message_id"] == "stuck-1"
    assert reclaimed[2] != abandoned[2]

    bridge._finish_inbound(
        reclaimed[0],
        claim_token=reclaimed[2],
        claim_epoch=reclaimed[3],
        ok=True,
        now=reclaimed_at + 1,
    )
    following = bridge._claim_inbound(now=reclaimed_at + 2)
    assert following is not None
    assert following[1]["message_id"] == "stuck-2"


def test_reclaimed_inbound_fences_old_token_from_finish_and_retry(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"user-1"}), "", ""),
    )
    message = {
        "message_id": "fenced-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    bridge._store_updates([message], "cursor-fenced")
    claimed_at = 1_000_000_000_000.0
    old_claim = bridge._claim_inbound(now=claimed_at)
    assert old_claim is not None
    reclaimed_at = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS + 1
    live_claim = bridge._claim_inbound(now=reclaimed_at)
    assert live_claim is not None

    with pytest.raises(bridge.InboundFinishFenceLost, match="inbound_finish_fence_lost"):
        bridge._finish_inbound(
            old_claim[0],
            claim_token=old_claim[2],
            claim_epoch=old_claim[3],
            ok=True,
            now=reclaimed_at + 1,
        )
    with pytest.raises(bridge.InboundFinishFenceLost, match="inbound_finish_fence_lost"):
        bridge._finish_inbound(
            old_claim[0],
            claim_token=old_claim[2],
            claim_epoch=old_claim[3],
            ok=False,
            error=TimeoutError("stale worker"),
            now=reclaimed_at + 1,
        )

    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,claim_token FROM inbound_message WHERE id=?",
            (live_claim[0],),
        ).fetchone() == ("processing", 0, live_claim[2])

    bridge._finish_inbound(
        live_claim[0],
        claim_token=live_claim[2],
        claim_epoch=live_claim[3],
        ok=False,
        error=TimeoutError("live worker retry"),
        now=reclaimed_at + 1,
    )
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,claim_token,claim_deadline "
            "FROM inbound_message WHERE id=?",
            (live_claim[0],),
        ).fetchone() == ("pending", 1, "", 0.0)


def test_inbound_claim_renewal_requires_live_owner_and_extends_from_current_time(
    monkeypatch,
    tmp_path,
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "heartbeat-1",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    bridge._store_updates([message], "cursor-heartbeat")
    claimed_at = 1_000_000_000_000.0
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None

    assert bridge._renew_inbound_claim(
        claimed[0],
        claimed[2],
        claimed[3],
        now=claimed_at + 1.0,
    ) is True
    with bridge._outbox_connect() as conn:
        heartbeat_at, deadline, epoch = conn.execute(
            "SELECT heartbeat_at,claim_deadline,claim_epoch "
            "FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
    assert heartbeat_at == claimed_at + 1.0
    assert epoch == claimed[3]
    assert deadline == pytest.approx(
        claimed_at + 1.0 + bridge._INBOUND_CLAIM_TTL_SECONDS
    )
    assert bridge._renew_inbound_claim(
        claimed[0],
        "not-the-owner",
        claimed[3],
        now=claimed_at + 2.0,
    ) is False


def test_inbound_finish_lock_wait_crossing_exact_deadline_loses_claim(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "finish-lock-wait",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-finish-lock") is True
    claimed_at = 10**12
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    current = {"value": deadline - 0.001}
    real_connect = bridge._outbox_connect

    def hooked_connect():
        conn = real_connect()
        conn._nachuan_begin_immediate_hook = lambda: current.update(value=deadline)
        return conn

    monkeypatch.setattr(bridge, "_outbox_connect", hooked_connect)
    with pytest.raises(
        bridge.InboundFinishFenceLost, match="inbound_finish_fence_lost"
    ):
        bridge._finish_inbound(
            claimed[0],
            claim_token=claimed[2],
            claim_epoch=claimed[3],
            ok=True,
            now=lambda: current["value"],
        )

    with real_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_token,last_finish_epoch,last_finish_outcome "
            "FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone() == ("processing", "", 0, "")
    assert bridge._renew_inbound_claim(
        claimed[0],
        claimed[2],
        claimed[3],
        now=deadline,
    ) is False


def test_blocked_access_reload_never_holds_sqlite_writer_and_revoke_stays_linearized(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    access_file = tmp_path / "weixin_access.json"
    monkeypatch.setattr(bridge, "_ACCESS_FILE", access_file)
    monkeypatch.setenv("NACHUAN_ENV", "production")
    _replace_access(access_file, ["user-1"])
    bridge._refresh_access()
    message = {
        "message_id": "access-reload-writer-isolation",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-access-reload") is True
    claimed = bridge._claim_inbound()
    assert claimed is not None

    load_started = threading.Event()
    release_load = threading.Event()
    finish_entered_refresh = threading.Event()
    writer_acquired = threading.Event()
    failures: list[BaseException] = []
    real_refresh = bridge._refresh_access

    def blocking_revoked_load(_path):
        load_started.set()
        if not release_load.wait(5.0):
            raise TimeoutError("test did not release access load")
        return set(), ""

    def observed_refresh():
        if threading.current_thread().name == "finish-after-reload":
            finish_entered_refresh.set()
        return real_refresh()

    monkeypatch.setattr(bridge, "_load_saved_access", blocking_revoked_load)
    monkeypatch.setattr(bridge, "_refresh_access", observed_refresh)

    def refresh_access() -> None:
        try:
            bridge._refresh_access()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def finish_inbound() -> None:
        try:
            bridge._finish_inbound(
                claimed[0],
                claim_token=claimed[2],
                claim_epoch=claimed[3],
                ok=True,
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def independent_writer() -> None:
        conn = bridge._outbox_connect()
        authority = None
        try:
            authority = bridge._begin_outbox_immediate_write(conn)
            writer_acquired.set()
            bridge._end_outbox_immediate_write(conn, authority)
            authority = None
            conn.commit()
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            if authority is not None:
                bridge._end_outbox_immediate_write(conn, authority)
            conn.close()

    refresh_thread = threading.Thread(target=refresh_access, name="blocked-access-reload")
    finish_thread = threading.Thread(target=finish_inbound, name="finish-after-reload")
    writer_thread = threading.Thread(target=independent_writer, name="independent-writer")
    refresh_thread.start()
    assert load_started.wait(2.0)
    finish_thread.start()
    assert finish_entered_refresh.wait(2.0)
    writer_thread.start()
    writer_was_free_while_load_blocked = writer_acquired.wait(1.0)
    release_load.set()
    for thread in (refresh_thread, finish_thread, writer_thread):
        thread.join(5.0)

    assert writer_was_free_while_load_blocked is True
    assert not failures
    assert all(not thread.is_alive() for thread in (refresh_thread, finish_thread, writer_thread))
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,from_user_id,payload FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
    assert row[0] == "done"
    assert row[1].startswith("sha256:")
    assert row[2] == bridge._UNAUTHORIZED_INBOUND_TOMBSTONE


def test_inbound_failure_finish_replay_is_fenced_and_sanitizes_error(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "finish-replay-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True
    claimed = bridge._claim_inbound(now=1_000_000_000_000.0)
    assert claimed is not None

    failure = ValueError("Bearer super-secret must never reach SQLite")
    bridge._finish_inbound(
        claimed[0],
        claim_token=claimed[2],
        claim_epoch=claimed[3],
        ok=False,
        error=failure,
    )
    with pytest.raises(
        bridge.InboundFinishFenceLost, match="inbound_finish_fence_lost"
    ):
        bridge._finish_inbound(
            claimed[0],
            claim_token=claimed[2],
            claim_epoch=claimed[3],
            ok=False,
            error=failure,
        )

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_error FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
        notices = conn.execute(
            "SELECT COUNT(*) FROM pending_delivery WHERE delivery_id=?",
            (bridge._delivery_id(f"{bridge._message_key(message)}:retrying"),),
        ).fetchone()[0]

    assert inbound == ("pending", 1, "ValueError")
    assert notices == 1


def test_terminal_inbound_failure_durably_notifies_user_exactly_once(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "terminal-failure-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True
    with bridge._outbox_connect() as conn:
        conn.execute("UPDATE inbound_message SET attempts=7")

    claimed = bridge._claim_inbound(now=1_000_000_000_000.0)
    assert claimed is not None
    bridge._finish_inbound(
        claimed[0],
        claim_token=claimed[2],
        claim_epoch=claimed[3],
        ok=False,
        error=TimeoutError("simulated provider deadline"),
    )
    with pytest.raises(
        bridge.InboundFinishFenceLost, match="inbound_finish_fence_lost"
    ):
        bridge._finish_inbound(
            claimed[0],
            claim_token=claimed[2],
            claim_epoch=claimed[3],
            ok=False,
            error=TimeoutError("simulated provider deadline"),
        )

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, text, client_id: sent.append((text, client_id)) or True,
    )
    assert bridge._drain_outbox("bot-token", now=1_000_000_000_000.0) == 1
    assert bridge._drain_outbox("bot-token", now=1_000_000_000_000.0) == 0

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_error FROM inbound_message"
        ).fetchone()
        notices = conn.execute(
            "SELECT status,text,client_id FROM pending_delivery ORDER BY id"
        ).fetchall()

    assert inbound == ("dead", 8, "TimeoutError")
    assert len(notices) == 1
    status, text, client_id = notices[0]
    assert status == "done"
    assert text == "⚠️ 这条消息暂时处理失败，纳川已停止自动重试，请稍后重新发送。"
    assert client_id.startswith("nachuan_")
    assert sent == [(text, client_id)]


def test_first_fast_inbound_failure_durably_notifies_user_that_retry_started(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "fast-failure-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True
    claimed = bridge._claim_inbound(now=1_000_000_000_000.0)
    assert claimed is not None
    bridge._finish_inbound(
        claimed[0],
        claim_token=claimed[2],
        claim_epoch=claimed[3],
        ok=False,
        error=ValueError("fast provider failure"),
    )

    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, text, _client_id: sent.append(text) or True,
    )
    assert bridge._drain_outbox("bot-token", now=1_000_000_000_000.0) == 1
    assert sent == [
        "⚠️ 本次处理遇到临时问题，纳川正在自动重试；稍后会给出最终结果。"
    ]
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts FROM inbound_message"
        ).fetchone() == ("pending", 1)


def test_inbound_worker_immediately_drains_the_first_failure_notice(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    monkeypatch.setattr(bridge, "_update_health", lambda *_args, **_kwargs: {})
    message = {
        "message_id": "worker-immediate-failure-notice",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    monkeypatch.setattr(
        bridge,
        "_handle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            TimeoutError("simulated provider deadline")
        ),
    )
    sent: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_send_chunk",
        lambda _token, _to, _ctx, text, _client_id: sent.append(text) or True,
    )

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert sent == [
        "⚠️ 本次处理遇到临时问题，纳川正在自动重试；稍后会给出最终结果。"
    ]
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery"
        ).fetchone() == ("done",)


def test_inbound_worker_first_pulse_failure_never_enters_handler(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "first-pulse-loss",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-first-pulse") is True
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: False)
    handler_calls = 0

    def handler(*_args, **_kwargs):
        nonlocal handler_calls
        handler_calls += 1
        return True, None

    monkeypatch.setattr(bridge, "_handle_result", handler)

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert handler_calls == 0
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome FROM inbound_message"
        ).fetchone() == ("processing", 0, "")


def test_inbound_finish_commit_then_raise_is_confirmed_without_handler_replay(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "finish-response-loss",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-response-loss") is True
    handler_calls = 0

    def handle_once(_message, _token):
        nonlocal handler_calls
        handler_calls += 1
        bridge._enqueue_delivery(
            "user-1",
            "context-1",
            "durable final reply",
            delivery_key="finish-response-loss:reply",
        )

    monkeypatch.setattr(bridge, "_handle", handle_once)
    real_finish = bridge._finish_inbound
    real_confirm = bridge._inbound_finish_was_committed
    real_preflight = bridge._stabilized_outbox_preflight
    finish_calls = 0
    confirm_calls = 0
    observed_deadlines: dict[str, list[float]] = {
        "finish": [],
        "confirm": [],
        "preflight": [],
    }

    def commit_then_raise(*args, deadline_monotonic, **kwargs):
        nonlocal finish_calls
        finish_calls += 1
        observed_deadlines["finish"].append(deadline_monotonic)
        result = real_finish(
            *args, deadline_monotonic=deadline_monotonic, **kwargs
        )
        if finish_calls == 1:
            raise sqlite3.OperationalError("simulated response loss after commit")
        return result

    def confirm_commit(*args, deadline_monotonic, **kwargs):
        nonlocal confirm_calls
        confirm_calls += 1
        observed_deadlines["confirm"].append(deadline_monotonic)
        return real_confirm(
            *args, deadline_monotonic=deadline_monotonic, **kwargs
        )

    def observed_preflight(*, deadline_monotonic=None):
        if deadline_monotonic is not None:
            observed_deadlines["preflight"].append(deadline_monotonic)
            return real_preflight(deadline_monotonic=deadline_monotonic)
        return real_preflight()

    monkeypatch.setattr(bridge, "_finish_inbound", commit_then_raise)
    monkeypatch.setattr(bridge, "_inbound_finish_was_committed", confirm_commit)
    monkeypatch.setattr(bridge, "_stabilized_outbox_preflight", observed_preflight)

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert handler_calls == 1
    assert finish_calls == 1
    assert confirm_calls == 1
    assert observed_deadlines["finish"] == observed_deadlines["confirm"]
    assert observed_deadlines["preflight"] == (
        observed_deadlines["finish"] + observed_deadlines["confirm"]
    )
    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,last_finish_outcome,last_finish_epoch "
            "FROM inbound_message"
        ).fetchone()
        deliveries = conn.execute(
            "SELECT COUNT(*) FROM pending_delivery WHERE delivery_id=?",
            (bridge._delivery_id("finish-response-loss:reply"),),
        ).fetchone()[0]
    assert inbound == ("done", "done", 1)
    assert deliveries == 1


def test_inbound_finish_budget_starts_after_access_refresh(monkeypatch):
    bridge = _load_bridge()
    message = {
        "message_id": "finish-after-access-refresh",
        "from_user_id": "user-1",
        "_nachuan_message_key": "finish-after-access-refresh",
    }
    claims = iter([(1, message, "claim-token", 1), None])
    monkeypatch.setattr(bridge, "_claim_inbound", lambda: next(claims))
    refresh_calls = 0
    handler_finished = False
    refreshed_after_handler = False

    def refresh_access():
        nonlocal refresh_calls, refreshed_after_handler
        refresh_calls += 1
        if handler_finished:
            refreshed_after_handler = True
        return ChannelAccessPolicy(allowed_users={"user-1"}), "", ""

    def handle_result(*_args, **_kwargs):
        nonlocal handler_finished
        handler_finished = True
        return True, None

    outcomes = []

    class ObservedSession:
        lost = False

        @staticmethod
        def start():
            return True

        @staticmethod
        def close():
            return True

        @staticmethod
        def finish(outcome):
            assert refreshed_after_handler is True
            outcomes.append(outcome)
            return True

    monkeypatch.setattr(
        bridge, "_new_inbound_lease_session", lambda *_a, **_k: ObservedSession()
    )
    monkeypatch.setattr(bridge, "_refresh_access", refresh_access)
    monkeypatch.setattr(bridge, "_handle_result", handle_result)
    health: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        bridge,
        "_update_health",
        lambda state, **fields: health.append((state, fields)) or {},
    )

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert refresh_calls == 2
    assert len(outcomes) == 1
    assert outcomes[0].refreshed_access.permits("user-1") is True
    assert bridge._InboundClaimPolicy().finish_timeout == 15.0
    assert any(fields.get("last_handler_ok") is True for _state, fields in health)


def test_inbound_finish_lock_wait_obeys_one_total_wallclock_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge._InboundClaimPolicy, "finish_timeout", 0.2)
    message = {
        "message_id": "finish-sqlite-lock-budget",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-lock-budget") is True
    claimed = bridge._claim_inbound()
    assert claimed is not None

    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_claim_is_current", lambda *_a, **_k: True
    )
    confirmations = 0

    def unexpected_confirmation(*_args, **_kwargs):
        nonlocal confirmations
        confirmations += 1
        return False

    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", unexpected_confirmation
    )
    with bridge._ACCESS_LOCK:
        access_generation = bridge._ACCESS_GENERATION
    access = ChannelAccessPolicy(allowed_users={"user-1"})
    outcome = bridge._InboundFinishRequest(
        ok=True,
        error=None,
        unauthorized_at_claim=False,
        access_generation_before_refresh=access_generation,
        refreshed_access=access,
    )
    session = bridge._new_inbound_lease_session(
        claimed[0], claimed[2], claimed[3], threading.Event()
    )
    assert session.start() is True

    blocker = sqlite3.connect(bridge._OUTBOX_DB, timeout=1, isolation_level=None)
    blocker.execute("PRAGMA journal_mode=WAL")
    blocker.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        assert session.finish(outcome) is False
    finally:
        elapsed = time.monotonic() - started
        blocker.rollback()
        blocker.close()
        session.close()

    assert elapsed < 0.8
    assert confirmations == 0


def test_inbound_finish_access_gate_obeys_total_wallclock_deadline(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge._InboundClaimPolicy, "finish_timeout", 0.2)
    message = {
        "message_id": "finish-access-gate-budget",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-access-gate") is True
    claimed = bridge._claim_inbound()
    assert claimed is not None
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_claim_is_current", lambda *_a, **_k: True
    )
    confirmations = 0

    def unexpected_confirmation(*_args, **_kwargs):
        nonlocal confirmations
        confirmations += 1
        return False

    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", unexpected_confirmation
    )
    with bridge._ACCESS_LOCK:
        access_generation = bridge._ACCESS_GENERATION
    outcome = bridge._InboundFinishRequest(
        ok=True,
        error=None,
        unauthorized_at_claim=False,
        access_generation_before_refresh=access_generation,
        refreshed_access=ChannelAccessPolicy(allowed_users={"user-1"}),
    )
    session = bridge._new_inbound_lease_session(
        claimed[0], claimed[2], claimed[3], threading.Event()
    )
    assert session.start() is True

    held = threading.Event()

    def hold_access_gate():
        with bridge._ACCESS_LOCK:
            held.set()
            threading.Event().wait(1.0)

    holder = threading.Thread(target=hold_access_gate)
    holder.start()
    assert held.wait(1.0)
    started = time.monotonic()
    try:
        assert session.finish(outcome) is False
    finally:
        elapsed = time.monotonic() - started
        holder.join(timeout=2.0)
        session.close()

    assert not holder.is_alive()
    assert elapsed < 0.8
    assert confirmations == 0
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,last_finish_outcome FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone() == ("processing", "")


def test_inbound_finish_early_deadline_error_never_enters_confirmation(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge._InboundClaimPolicy, "finish_timeout", 0.2)
    confirmations = 0

    class Storage:
        def renew(self):
            return True

        def owns(self):
            return True

        def finish_before(self, _outcome, *, deadline_monotonic):
            assert deadline_monotonic > time.monotonic()
            raise bridge._OutboxFinishDeadlineExceeded("access gate exhausted")

        def confirm_finish_before(self, _outcome, *, deadline_monotonic):
            nonlocal confirmations
            confirmations += 1
            return False

    session = bridge.ClaimLeaseSession(
        storage=Storage(),
        policy=bridge._InboundClaimPolicy(),
    )
    assert session.start() is True
    try:
        assert session.finish(object()) is False
    finally:
        session.close()

    assert confirmations == 0
    assert session.lost is True


def test_inbound_finish_late_success_fails_closed_without_confirmation(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge._InboundClaimPolicy, "finish_timeout", 0.05)
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_claim_is_current", lambda *_a, **_k: True
    )
    finish_deadlines: list[float] = []
    confirmations = 0

    def late_success(*_args, deadline_monotonic, **_kwargs):
        finish_deadlines.append(deadline_monotonic)
        time.sleep(0.08)
        return True

    def unexpected_confirmation(*_args, **_kwargs):
        nonlocal confirmations
        confirmations += 1
        return True

    monkeypatch.setattr(bridge, "_finish_inbound", late_success)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", unexpected_confirmation
    )
    with bridge._ACCESS_LOCK:
        access_generation = bridge._ACCESS_GENERATION
    outcome = bridge._InboundFinishRequest(
        ok=True,
        error=None,
        unauthorized_at_claim=False,
        access_generation_before_refresh=access_generation,
        refreshed_access=ChannelAccessPolicy(allowed_users={"user-1"}),
    )
    session = bridge._new_inbound_lease_session(
        1, "claim-token", 1, threading.Event()
    )
    assert session.start() is True
    started = time.monotonic()
    try:
        assert session.finish(outcome) is False
    finally:
        elapsed = time.monotonic() - started
        session.close()

    assert len(finish_deadlines) == 1
    assert confirmations == 0
    assert elapsed < 0.25


def test_inbound_finish_preflight_reuses_deadline_instead_of_resetting_ten_seconds(
    monkeypatch,
):
    bridge = _load_bridge()
    observed: list[float] = []

    def unstable_preflight(*, deadline_monotonic=None):
        observed.append(deadline_monotonic)
        raise bridge._OutboxDatabaseFamilyChanged("still changing")

    monkeypatch.setattr(bridge, "_preflight_outbox_schema", unstable_preflight)
    deadline = time.monotonic() + 0.05
    started = time.monotonic()
    with pytest.raises(sqlite3.DatabaseError, match="did not stabilize"):
        bridge._stabilized_outbox_preflight(deadline_monotonic=deadline)
    elapsed = time.monotonic() - started

    assert observed and set(observed) == {deadline}
    assert elapsed < 0.3


def test_inbound_finish_confirmation_cleanup_cannot_return_after_deadline(
    monkeypatch,
):
    bridge = _load_bridge()
    observed_deadlines: list[float] = []

    class SlowCloseReceipt:
        @staticmethod
        def execute(_sql, _parameters):
            return SlowCloseReceipt()

        @staticmethod
        def fetchone():
            return "done", "claim-token", 1, "done"

        @staticmethod
        def close():
            time.sleep(0.08)

    def connect(*, deadline_monotonic):
        observed_deadlines.append(deadline_monotonic)
        return SlowCloseReceipt()

    monkeypatch.setattr(bridge, "_outbox_connect", connect)
    deadline = time.monotonic() + 0.05
    with pytest.raises(sqlite3.OperationalError, match="deadline exceeded"):
        bridge._inbound_finish_was_committed(
            1,
            claim_token="claim-token",
            claim_epoch=1,
            ok=True,
            deadline_monotonic=deadline,
        )

    assert observed_deadlines == [deadline]


def test_inbound_finish_fault_projection_never_waits_or_calls_health_io(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(
        bridge,
        "_update_health",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("deadline fault must not call health I/O")
        ),
    )
    held = threading.Event()
    release = threading.Event()

    def hold_health_lock():
        with bridge._HEALTH_LOCK:
            held.set()
            release.wait(2.0)

    holder = threading.Thread(target=hold_health_lock)
    holder.start()
    assert held.wait(1.0)
    started = time.monotonic()
    try:
        bridge._InboundClaimPolicy.fault("finish_gate_timeout")
    finally:
        elapsed = time.monotonic() - started
        release.set()
        holder.join(timeout=2.0)

    assert not holder.is_alive()
    assert elapsed < 0.05


def test_inbound_worker_exhausts_bounded_finish_and_keeps_processing(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "finish-bounded",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-bounded") is True
    monkeypatch.setattr(bridge, "_handle_result", lambda *_a, **_k: (True, None))
    finish_calls = 0

    def unavailable(*_args, **_kwargs):
        nonlocal finish_calls
        finish_calls += 1
        raise sqlite3.OperationalError("simulated persistent finish outage")

    monkeypatch.setattr(bridge, "_finish_inbound", unavailable)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", lambda *_a, **_k: False
    )

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert finish_calls == len(bridge._INBOUND_FINISH_RETRY_DELAYS_SECONDS)
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status,attempts,last_finish_outcome FROM inbound_message"
        ).fetchone() == ("processing", 0, "")


def test_final_outbox_rechecks_exact_deadline_immediately_before_insert(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    message = {
        "message_id": "outbox-deadline-race",
        "from_user_id": "user-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-outbox-race") is True
    claimed = bridge._claim_inbound(now=10**12)
    assert claimed is not None
    deadline = 10**12 + bridge._INBOUND_CLAIM_TTL_SECONDS
    clock = iter([deadline - 1.0, deadline - 1.0, deadline])
    monkeypatch.setattr(bridge, "_policy_time", lambda _now=None: next(clock))

    class LocalFence:
        lost = False

        @staticmethod
        def commit_fence():
            return nullcontext()

    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.lease_session = LocalFence()
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._enqueue_delivery(
                "user-1",
                "context-1",
                "must not persist",
                delivery_key="outbox-deadline-race:reply",
            )
    finally:
        for name in ("claim_id", "claim_token", "claim_epoch", "lease_session"):
            delattr(bridge._HANDLE_CONTEXT, name)

    with bridge._outbox_connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM pending_delivery").fetchone()[0] == 0


def test_failure_finish_rolls_back_notice_when_deadline_crosses_before_insert(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "finish-notice-deadline-race",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-finish-notice-race") is True
    claimed_at = 10**12
    claimed = bridge._claim_inbound(now=claimed_at)
    assert claimed is not None
    deadline = claimed_at + bridge._INBOUND_CLAIM_TTL_SECONDS
    policy_times = iter(
        [deadline - 1.0, deadline - 1.0, deadline - 1.0, deadline]
    )

    bridge._HANDLE_CONTEXT.claim_id = claimed[0]
    bridge._HANDLE_CONTEXT.claim_token = claimed[2]
    bridge._HANDLE_CONTEXT.claim_epoch = claimed[3]
    bridge._HANDLE_CONTEXT.lease_session = SimpleNamespace(lost=False)
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._finish_inbound(
                claimed[0],
                claim_token=claimed[2],
                claim_epoch=claimed[3],
                ok=False,
                error=TimeoutError("provider timeout"),
                now=lambda: next(policy_times),
            )
    finally:
        for name in ("claim_id", "claim_token", "claim_epoch", "lease_session"):
            delattr(bridge._HANDLE_CONTEXT, name)

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_finish_token,last_finish_outcome "
            "FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
        notices = conn.execute("SELECT COUNT(*) FROM pending_delivery").fetchone()[0]
    assert inbound == ("processing", 0, "", "")
    assert notices == 0


def test_inbound_worker_uses_shared_claim_session_without_legacy_finish_loop() -> None:
    source = (
        Path(__file__).parents[1] / "scripts" / "run_weixin_ilink_bridge.py"
    ).read_text(encoding="utf-8")
    worker = source.split("def _inbound_worker(", 1)[1].split(
        "\ndef _start_inbound_workers(", 1
    )[0]

    assert "class _InboundLeaseGuard" not in source
    assert "ClaimLeaseSession" in source
    # One loop is the worker poll itself; finish retry lives inside the shared,
    # policy-bounded module and must never add another stop-controlled loop.
    assert worker.count("while not stop.is_set()") == 1
    assert "lease_session.finish(outcome)" in worker


@pytest.mark.parametrize(
    "partial_context",
    [
        {"lease_session": SimpleNamespace(lost=False)},
        {"claim_token": "partial-token"},
        {"claim_epoch": 1},
        {
            "claim_token": "partial-token",
            "claim_epoch": 1,
            "lease_session": SimpleNamespace(lost=False),
        },
    ],
)
def test_outbox_partial_inbound_context_fails_closed(
    monkeypatch, tmp_path, partial_context
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    conn = bridge._outbox_connect()
    authority = bridge._begin_outbox_immediate_write(conn)
    for name, value in partial_context.items():
        setattr(bridge._HANDLE_CONTEXT, name, value)
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_outbox_fence_lost"
        ):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "must not persist",
                delivery_key="partial-context",
                _write_authority=authority,
            )
    finally:
        conn.rollback()
        bridge._end_outbox_immediate_write(conn, authority)
        conn.close()
        for name in partial_context:
            delattr(bridge._HANDLE_CONTEXT, name)


def test_outbox_helper_requires_private_begin_immediate_authority(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    conn = bridge._outbox_connect()
    try:
        assert conn.in_transaction is False
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "fresh connection",
                delivery_key="fresh-connection",
                _write_authority=None,
            )
        conn.execute("BEGIN")
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "deferred transaction",
                delivery_key="deferred-transaction",
                _write_authority=None,
            )
        conn.rollback()

        authority = bridge._begin_outbox_immediate_write(conn)
        bridge._enqueue_delivery_in_transaction(
            conn,
            "user-1",
            "context-1",
            "authorized transaction",
            delivery_key="authorized-transaction",
            _write_authority=authority,
        )
        assert conn.execute("SELECT COUNT(*) FROM pending_delivery").fetchone()[0] == 1
        conn.rollback()
        bridge._end_outbox_immediate_write(conn, authority)
    finally:
        conn.close()


def test_outbox_authority_is_revoked_by_commit_and_cannot_cross_transaction(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    conn = bridge._outbox_connect()
    try:
        authority = bridge._begin_outbox_immediate_write(conn)
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "must not cross transaction",
                delivery_key="stale-authority",
                _write_authority=authority,
            )
        conn.rollback()
    finally:
        conn.close()


def test_outbox_authority_is_revoked_by_cursor_transaction_control(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    conn = bridge._outbox_connect()
    try:
        authority = bridge._begin_outbox_immediate_write(conn)
        cursor = conn.cursor()
        cursor.execute("COMMIT")
        cursor.execute("BEGIN IMMEDIATE")
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "must not cross cursor transaction",
                delivery_key="stale-cursor-authority",
                _write_authority=authority,
            )
        conn.rollback()
    finally:
        conn.close()


@pytest.mark.parametrize("end_sql", ["COMMIT;", "END;", "ROLLBACK;"])
def test_outbox_authority_parser_rejects_semicolon_transaction_reuse(
    monkeypatch, tmp_path, end_sql
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    conn = bridge._outbox_connect()
    try:
        authority = bridge._begin_outbox_immediate_write(conn)
        conn.cursor().execute(end_sql)
        conn.cursor().execute("BEGIN IMMEDIATE")
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._enqueue_delivery_in_transaction(
                conn,
                "user-1",
                "context-1",
                "must not cross semicolon transaction",
                delivery_key=f"stale-semicolon-{end_sql}",
                _write_authority=authority,
            )
        conn.rollback()
    finally:
        conn.close()


def test_outbox_authority_is_bound_to_connection_and_thread(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    owner = bridge._outbox_connect()
    other = bridge._outbox_connect()
    authority = bridge._begin_outbox_immediate_write(owner)
    errors: list[BaseException] = []

    def cross_thread_probe():
        try:
            bridge._require_outbox_immediate_write(owner, authority)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=cross_thread_probe)
    thread.start()
    thread.join(1.0)
    try:
        with pytest.raises(RuntimeError, match="immediate write authority"):
            bridge._require_outbox_immediate_write(other, authority)
        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)
        assert "immediate write authority" in str(errors[0])
    finally:
        owner.rollback()
        bridge._end_outbox_immediate_write(owner, authority)
        owner.close()
        other.close()


def test_fast_handler_exception_is_persisted_as_code_and_notified_once(
    monkeypatch, tmp_path, capsys
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    # The contract is about one immediate failure, not whether a real test run
    # happens to consume the two-second retry delay in local SQLite setup.
    monkeypatch.setattr(bridge.time, "time", lambda: 1_000_000_000_000.0)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    message = {
        "message_id": "fast-handler-exception-1",
        "from_user_id": "user-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "hello"}}],
    }
    assert bridge._store_updates([message], "cursor-1") is True

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    def fail_handle(_message, _token):
        raise json.JSONDecodeError("Bearer secret must not persist", "<secret>", 0)

    monkeypatch.setattr(bridge, "_handle", fail_handle)
    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,attempts,last_error FROM inbound_message"
        ).fetchone()
        notices = conn.execute(
            "SELECT COUNT(*) FROM pending_delivery"
        ).fetchone()[0]

    assert inbound == ("pending", 1, "JSONDecodeError")
    assert notices == 1
    output = capsys.readouterr().out
    assert "JSONDecodeError" in output
    assert "Bearer secret" not in output
    assert "<secret>" not in output


def test_inbound_worker_survives_finish_storage_failure(monkeypatch):
    bridge = _load_bridge()

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    claims = iter(
        [
            (
                7,
                {
                    "message_id": "finish-failure-1",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-7",
                    "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
                },
                "claim-7",
                1,
            ),
            None,
        ]
    )
    monkeypatch.setattr(bridge, "_claim_inbound", lambda: next(claims))
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(bridge, "_inbound_claim_is_current", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    monkeypatch.setattr(bridge, "_handle_safe", lambda _message, _token: True)
    finish_calls = 0

    def fail_finish(*_args, **_kwargs):
        nonlocal finish_calls
        finish_calls += 1
        raise OSError("simulated sqlite finish failure")

    monkeypatch.setattr(bridge, "_finish_inbound", fail_finish)
    projected: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_record_inbound_claim_health_nonblocking",
        projected.append,
    )

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert finish_calls == len(bridge._INBOUND_FINISH_RETRY_DELAYS_SECONDS)
    assert any("finish_" in code for code in projected)


def test_inbound_worker_retries_finish_errors_then_processes_next_claim(monkeypatch):
    bridge = _load_bridge()

    class StopOnIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, seconds):
            if seconds < 1.0:
                self.stopped = True
            return self.stopped

    claims = iter(
        [
            (
                1,
                {
                    "message_id": "m1",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-1",
                },
                "claim-1",
                1,
            ),
            (
                2,
                {
                    "message_id": "m2",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-2",
                },
                "claim-2",
                1,
            ),
            None,
        ]
    )
    monkeypatch.setattr(bridge, "_claim_inbound", lambda: next(claims))
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(bridge, "_inbound_claim_is_current", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    monkeypatch.setattr(
        bridge, "_handle_result", lambda _message, _token: (True, None)
    )
    finish_attempts: list[int] = []

    def flaky_finish(row_id, **_kwargs):
        finish_attempts.append(row_id)
        if row_id == 1 and finish_attempts.count(1) < 3:
            raise OSError("simulated persistent sqlite failure")
        return True

    monkeypatch.setattr(bridge, "_finish_inbound", flaky_finish)
    projected: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_record_inbound_claim_health_nonblocking",
        projected.append,
    )

    bridge._inbound_worker({"value": "bot-token"}, StopOnIdle())

    assert finish_attempts == [1, 1, 1, 2]
    assert projected.count("inbound_claim:finish_storage_retry:OSError") == 2


@pytest.mark.parametrize(
    ("send_succeeds", "expected_error_type", "expected_error_code"),
    [
        (True, "DeliveryAckStorageError", "delivery_ack_storage_failure"),
        (False, "DeliveryRequeueStorageError", "delivery_requeue_storage_failure"),
    ],
)
def test_inbound_worker_outlives_persistent_outbox_finish_storage_errors(
    monkeypatch,
    tmp_path,
    send_succeeds,
    expected_error_type,
    expected_error_code,
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")

    class StopOnIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, seconds):
            if seconds < 1.0:
                self.stopped = True
            return self.stopped

    claims = iter(
        [
            (
                1,
                {
                    "message_id": "outbox-io-1",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-1",
                },
                "claim-1",
                1,
            ),
            (
                2,
                {
                    "message_id": "outbox-io-2",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-2",
                },
                "claim-2",
                1,
            ),
            None,
        ]
    )
    monkeypatch.setattr(bridge, "_claim_inbound", lambda: next(claims))
    with bridge._outbox_connect() as conn:
        for row_id, token in ((1, "claim-1"), (2, "claim-2")):
            conn.execute(
                "INSERT INTO inbound_message "
                "(id,message_key,from_user_id,payload,received_at,next_attempt_at,"
                "status,claim_token,claim_epoch,claim_deadline) "
                "VALUES(?,?,?,?,?,?,'processing',?,?,?)",
                (
                    row_id,
                    f"mock-{row_id}",
                    "user-1",
                    "{}",
                    1.0,
                    1.0,
                    token,
                    1,
                    10**15,
                ),
            )
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(bridge, "_inbound_claim_is_current", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )

    def handle_with_durable_delivery(message, token):
        bridge._deliver_text(
            token,
            "user-1",
            "context-1",
            "reply",
            delivery_key=f"{message['message_id']}:reply",
        )

    monkeypatch.setattr(bridge, "_handle", handle_with_durable_delivery)
    sends: list[str] = []

    def send_or_fail(_token, _to, _ctx, _text, client_id):
        sends.append(client_id)
        if not send_succeeds:
            raise TimeoutError("simulated bounded send failure")
        return True

    monkeypatch.setattr(bridge, "_send_chunk", send_or_fail)
    monkeypatch.setattr(
        bridge,
        "_finish_delivery",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("simulated persistent outbox finish failure")
        ),
    )
    finished: list[tuple[int, bool, Exception | None]] = []
    monkeypatch.setattr(
        bridge,
        "_finish_inbound",
        lambda row_id, **kwargs: finished.append(
            (row_id, bool(kwargs["ok"]), kwargs.get("error"))
        )
        or True,
    )
    health: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        bridge,
        "_update_health",
        lambda state, **fields: health.append((state, fields)) or {},
    )

    bridge._inbound_worker({"value": "bot-token"}, StopOnIdle())

    # The worker still consumes the second inbound Turn, but its durable reply
    # must not cross the first reply whose network result could not be recorded.
    assert len(sends) == 1
    assert [row_id for row_id, _ok, _error in finished] == [1, 2]
    assert finished[0][1] is False
    assert type(finished[0][2]).__name__ == expected_error_type
    assert str(finished[0][2]) == expected_error_code
    assert finished[1] == (2, True, None)
    assert sum(state == "degraded" for state, _fields in health) == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT status FROM pending_delivery ORDER BY id"
        ).fetchall() == [("submitting",), ("pending",)]
    assert bridge._claim_delivery(
        now=10**12,
        delivery_id=bridge._delivery_id("outbox-io-2:reply"),
    ) is None


def test_inbound_worker_preserves_handler_root_error(monkeypatch):
    bridge = _load_bridge()

    class StopAfterIdle:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, _seconds):
            self.stopped = True
            return True

    claims = iter(
        [
            (
                8,
                {
                    "message_id": "decode-failure-1",
                    "from_user_id": "user-1",
                    "_nachuan_message_key": "mock-8",
                    "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
                },
                "claim-8",
                1,
            ),
            None,
        ]
    )
    monkeypatch.setattr(bridge, "_claim_inbound", lambda: next(claims))
    monkeypatch.setattr(bridge, "_renew_inbound_claim", lambda *_a, **_k: True)
    monkeypatch.setattr(bridge, "_inbound_claim_is_current", lambda *_a, **_k: True)
    monkeypatch.setattr(
        bridge, "_inbound_finish_was_committed", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )

    def fail_handle(_message, _token):
        raise json.JSONDecodeError("bad upstream JSON", "<html>", 0)

    monkeypatch.setattr(bridge, "_handle", fail_handle)
    finished: list[Exception | None] = []
    monkeypatch.setattr(
        bridge,
        "_finish_inbound",
        lambda _row_id, **kwargs: finished.append(kwargs.get("error")) or True,
    )
    health: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        bridge,
        "_update_health",
        lambda state, **fields: health.append((state, fields)) or {},
    )

    bridge._inbound_worker({"value": "bot-token"}, StopAfterIdle())

    assert len(finished) == 1
    assert isinstance(finished[0], json.JSONDecodeError)
    assert any(
        state == "degraded"
        and str(fields.get("last_error", "")).startswith("JSONDecodeError:")
        for state, fields in health
    )


def test_inbound_worker_handles_are_retained_and_health_reports_liveness(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"user-1"}), "", ""),
    )
    monkeypatch.setenv("WEIXIN_WORKERS", "2")

    class FakeThread:
        def __init__(self, *, target, args, name, daemon):
            self.target = target
            self.args = args
            self.name = name
            self.daemon = daemon
            self.started = False
            self.alive = True

        def start(self):
            self.started = True

        def is_alive(self):
            return self.alive

    monkeypatch.setattr(bridge.threading, "Thread", FakeThread)
    stop = bridge._start_inbound_workers({"value": "bot-token"})

    assert isinstance(stop, bridge.threading.Event)
    assert len(bridge._INBOUND_WORKERS) == 2
    assert all(worker.started and worker.daemon for worker in bridge._INBOUND_WORKERS)
    assert {worker.name for worker in bridge._INBOUND_WORKERS} == {
        "weixin-worker-1",
        "weixin-worker-2",
    }

    bridge._INBOUND_WORKERS[1].alive = False
    snapshot = bridge._update_health("healthy", consecutive_poll_failures=0)
    assert snapshot["workers_configured"] == 2
    assert snapshot["workers_alive"] == 1
    assert "inbound_workers_missing" in snapshot["readiness_reasons"]
    assert snapshot["ready"] is False


def test_health_cannot_be_healthy_while_delivery_work_is_pending_or_dead(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(allowed_users={"u1"}), "u1", ""),
    )

    with bridge._outbox_connect() as conn:
        conn.execute(
            """
            INSERT INTO inbound_message
              (message_key, from_user_id, payload, received_at, next_attempt_at, status)
            VALUES ('pending-in', 'u1', '{}', 1, 1, 'pending')
            """
        )
        conn.execute(
            """
            INSERT INTO inbound_message
              (message_key, from_user_id, payload, received_at, next_attempt_at, status)
            VALUES ('dead-in', 'u2', '{}', 1, 1, 'dead')
            """
        )
        conn.execute(
            """
            INSERT INTO pending_delivery
              (created_at, next_attempt_at, attempts, to_user_id, context_token, text, status)
            VALUES (1, 1, 1, 'u1', 'ctx', 'pending', 'pending')
            """
        )
        conn.execute(
            """
            INSERT INTO pending_delivery
              (created_at, next_attempt_at, attempts, to_user_id, context_token, text, status)
            VALUES (1, 1, 12, 'u2', 'ctx', 'dead', 'dead')
            """
        )

    bridge._update_health("healthy", consecutive_poll_failures=0)
    snapshot = json.loads(bridge._HEALTH_FILE.read_text("utf-8"))

    assert snapshot["state"] == "degraded"
    assert snapshot["ready"] is False
    assert snapshot["pending_inbound"] == 1
    assert snapshot["pending_outbound"] == 1
    assert snapshot["dead_inbound"] == 1
    assert snapshot["dead_outbound"] == 1
    assert set(snapshot["readiness_reasons"]) == {
        "pending_inbound",
        "pending_outbound",
        "dead_inbound",
        "dead_outbound",
        "inbound_workers_missing",
    }
    assert snapshot["workers_configured"] == 0
    assert snapshot["workers_alive"] == 0


def test_access_locked_is_not_ready_and_replies_without_calling_engine(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    delivered: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: delivered.append(text) or True,
    )
    monkeypatch.setattr(
        bridge,
        "_agent_chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("engine must not run")),
    )

    bridge._update_health("healthy", consecutive_poll_failures=0)
    snapshot = json.loads(bridge._HEALTH_FILE.read_text("utf-8"))
    assert snapshot["ready"] is False
    assert snapshot["state"] == "degraded"
    assert "access_locked" in snapshot["readiness_reasons"]

    bridge._handle(
        {
            "message_id": "locked-1",
            "from_user_id": "unknown-user",
            "context_token": "ctx",
            "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
        },
        "token",
    )
    assert len(delivered) == 1
    assert "/whoami" in delivered[0]


def test_terminal_maintenance_prunes_only_old_complete_groups_and_tombstones_dead(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    now = 10_000.0
    with bridge._outbox_connect() as conn:
        for message_key, status, received_at, payload, user in (
            ("old-done", "done", 1.0, '{"text":"old"}', "old-user"),
            ("fresh-done", "done", 9_999.0, '{"text":"fresh"}', "fresh-user"),
            ("live-pending", "pending", 1.0, '{"text":"live"}', "live-user"),
            ("fresh-dead", "dead", 9_999.0, '{"secret":"dead-body"}', "dead-user"),
        ):
            conn.execute(
                "INSERT INTO inbound_message"
                "(message_key,from_user_id,payload,received_at,next_attempt_at,status,last_error) "
                "VALUES(?,?,?,?,?,?,?)",
                (message_key, user, payload, received_at, received_at, status, "OSError: secret"),
            )

        def delivery(
            delivery_id, chunk_index, status, created_at, *, delivered_at=0.0, text="text"
        ):
            conn.execute(
                "INSERT INTO pending_delivery"
                "(created_at,next_attempt_at,to_user_id,context_token,text,status,delivery_id,"
                "client_id,chunk_index,chunk_count,delivered_at,last_error) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    created_at,
                    created_at,
                    "sensitive-user",
                    "sensitive-context",
                    text,
                    status,
                    delivery_id,
                    f"client-{delivery_id}-{chunk_index}",
                    chunk_index,
                    2,
                    delivered_at,
                    "OSError: sensitive-detail",
                ),
            )

        delivery("complete-old", 0, "done", 1.0, delivered_at=2.0)
        delivery("complete-old", 1, "done", 1.0, delivered_at=2.0)
        delivery("mixed-old", 0, "done", 1.0, delivered_at=2.0)
        delivery("mixed-old", 1, "pending", 1.0)
        delivery("dead-fresh", 0, "dead", 9_999.0, text="dead secret")

    result = bridge._terminal_maintenance(
        now=now,
        completed_retention_seconds=2_000,
        dead_retention_seconds=4_000,
        dead_max_rows=100,
    )
    assert result["done_inbound_deleted"] == 1
    assert result["done_outbound_deleted"] == 2
    assert result["inbound_tombstoned"] == 1
    assert result["outbound_tombstoned"] == 1

    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT message_key,status,from_user_id,payload,last_error "
            "FROM inbound_message ORDER BY message_key"
        ).fetchall()
        outbound = conn.execute(
            "SELECT delivery_id,status,to_user_id,context_token,text,last_error "
            "FROM pending_delivery ORDER BY delivery_id,chunk_index"
        ).fetchall()
    assert {row[0] for row in inbound} == {"fresh-dead", "fresh-done", "live-pending"}
    dead_inbound = next(row for row in inbound if row[0] == "fresh-dead")
    assert dead_inbound[2].startswith("sha256:")
    assert dead_inbound[3] == bridge._DEAD_INBOUND_TOMBSTONE
    assert "secret" not in dead_inbound[4]
    assert not any(row[0] == "complete-old" for row in outbound)
    assert sum(row[0] == "mixed-old" for row in outbound) == 2
    dead_outbound = next(row for row in outbound if row[0] == "dead-fresh")
    assert dead_outbound[2].startswith("sha256:")
    assert dead_outbound[3:5] == ("", "")
    assert "sensitive" not in dead_outbound[5]


def test_terminal_maintenance_caps_tombstoned_dead_inbound(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        for index in range(2):
            conn.execute(
                "INSERT INTO inbound_message"
                "(message_key,from_user_id,payload,received_at,next_attempt_at,status,last_error) "
                "VALUES(?,?,?,?,?,'dead','error')",
                (
                    f"dead-{index}",
                    f"sha256:{index}",
                    bridge._DEAD_INBOUND_TOMBSTONE,
                    9_000.0 + index,
                    9_000.0 + index,
                ),
            )
    result = bridge._terminal_maintenance(
        now=10_000.0,
        completed_retention_seconds=2_000,
        dead_retention_seconds=4_000,
        dead_max_rows=1,
    )
    assert result["dead_inbound_deleted"] == 1
    with bridge._outbox_connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM inbound_message WHERE status='dead'"
        ).fetchone()[0] == 1


def test_terminal_maintenance_prunes_completed_video_tasks_but_not_active_ones(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    bridge._enqueue_pending_video(
        "completed-video",
        "completed-user",
        "completed-context",
        source_message_key="completed-message",
        now=1.0,
        _internal_maintenance=True,
    )
    bridge._enqueue_pending_video(
        "active-video",
        "active-user",
        "active-context",
        source_message_key="active-message",
        now=1.0,
        _internal_maintenance=True,
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_video SET status='done',finished_at=2 "
            "WHERE task_id='completed-video'"
        )

    result = bridge._terminal_maintenance(
        now=10_000.0,
        completed_retention_seconds=2_000,
        dead_retention_seconds=4_000,
    )
    assert result["done_video_deleted"] == 1
    with bridge._outbox_connect() as conn:
        rows = conn.execute(
            "SELECT task_id,status FROM pending_video ORDER BY task_id"
        ).fetchall()
    assert rows == [("active-video", "pending")]


def test_rows_becoming_dead_are_immediately_tombstoned(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message"
            "(message_key,from_user_id,payload,received_at,next_attempt_at,attempts,"
            "status,claimed_at,claim_token,claim_deadline) "
            "VALUES('inbound-dead','private-user','{\"private\":true}',1,1,7,"
            "'processing',1,'dead-claim',1000000000000)"
        )
    bridge._finish_inbound(
        1,
        claim_token="dead-claim",
        claim_epoch=0,
        ok=False,
        error=OSError("private inbound detail"),
    )
    with bridge._outbox_connect() as conn:
        inbound = conn.execute(
            "SELECT status,from_user_id,payload,last_error FROM inbound_message WHERE id=1"
        ).fetchone()
    assert inbound[0] == "dead"
    assert inbound[1].startswith("sha256:")
    assert inbound[2] == bridge._DEAD_INBOUND_TOMBSTONE
    assert "private" not in inbound[3]

    delivery_id, _rows = bridge._enqueue_delivery(
        "private-user",
        "private-context",
        "A" * 3501,
        delivery_key="dead-delivery",
    )
    with bridge._outbox_connect() as conn:
        conn.execute(
            "UPDATE pending_delivery SET attempts=11 WHERE delivery_id=?",
            (delivery_id,),
        )
    claim = bridge._claim_delivery(now=10**12, delivery_id=delivery_id)
    assert claim is not None
    bridge._finish_delivery(
        claim,
        ok=False,
        error=OSError("private outbound detail"),
        now=10**12,
    )
    with bridge._outbox_connect() as conn:
        outbound = conn.execute(
            "SELECT status,to_user_id,context_token,text,last_error "
            "FROM pending_delivery WHERE delivery_id=? ORDER BY chunk_index",
            (delivery_id,),
        ).fetchall()
    assert len(outbound) == 2
    assert all(row[0] == "dead" for row in outbound)
    assert all(row[1].startswith("sha256:") for row in outbound)
    assert all(row[2] == "" and row[3] == "" for row in outbound)
    assert all("private" not in row[4] for row in outbound)


def test_generated_media_rejects_private_url_before_network(monkeypatch):
    bridge = _load_bridge()
    with pytest.raises(bridge.MediaFetchError, match="公网"):
        bridge._fetch_media("http://127.0.0.1:8080/secrets", "image")


def test_generated_media_lost_during_fetch_never_sends_media_or_fallback(monkeypatch):
    bridge = _load_bridge()

    class StickyLease:
        lost = False

        def before_provider(self) -> bool:
            return not self.lost

    lease = StickyLease()
    media_calls: list[bytes] = []
    fallback_calls: list[str] = []

    def lose_during_fetch(_url, _kind):
        lease.lost = True
        return b"fetched-after-lease-loss"

    monkeypatch.setattr(bridge, "_fetch_media", lose_during_fetch)
    monkeypatch.setattr(
        bridge,
        "_send_media",
        lambda _token, _to, _ctx, data, _kind, **_kwargs: media_calls.append(data),
    )
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallback_calls.append(text),
    )
    bridge._HANDLE_CONTEXT.lease_session = lease
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_provider_fence_lost"
        ):
            bridge._send_generated_media(
                "bot-token",
                "user-1",
                "context-1",
                {"images": ["https://media.example/image.png"]},
                delivery_key="generated-media-lease-loss",
            )
    finally:
        delattr(bridge._HANDLE_CONTEXT, "lease_session")

    assert media_calls == []
    assert fallback_calls == []


def test_media_upload_lease_loss_blocks_sendmessage(monkeypatch):
    bridge = _load_bridge()

    class StickyLease:
        lost = False

        def before_provider(self) -> bool:
            return not self.lost

    lease = StickyLease()
    send_calls: list[str] = []

    def upload_then_lose(*_args, **_kwargs):
        lease.lost = True
        return {
            "encrypt_query_param": "opaque-query",
            "aes_key": "opaque-key",
            "size": 3,
        }

    monkeypatch.setattr(bridge, "_upload_media", upload_then_lose)
    monkeypatch.setattr(
        bridge,
        "_ilink",
        lambda *_args, **_kwargs: send_calls.append("sendmessage") or {},
    )
    bridge._HANDLE_CONTEXT.lease_session = lease
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_provider_fence_lost"
        ):
            bridge._send_media(
                "bot-token",
                "user-1",
                "context-1",
                b"raw",
                "image",
                client_id="stable-client-id",
            )
    finally:
        delattr(bridge._HANDLE_CONTEXT, "lease_session")

    assert send_calls == []


def test_media_send_failure_after_lease_loss_never_falls_back_to_text(monkeypatch):
    bridge = _load_bridge()

    class StickyLease:
        lost = False

        def before_provider(self) -> bool:
            return not self.lost

    lease = StickyLease()
    fallback_calls: list[str] = []
    monkeypatch.setattr(bridge, "_fetch_media", lambda _url, _kind: b"raw")

    def lose_then_fail(*_args, **_kwargs):
        lease.lost = True
        raise OSError("send result unavailable after lease loss")

    monkeypatch.setattr(bridge, "_send_media", lose_then_fail)
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallback_calls.append(text),
    )
    bridge._HANDLE_CONTEXT.lease_session = lease
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost, match="inbound_provider_fence_lost"
        ):
            bridge._send_generated_media(
                "bot-token",
                "user-1",
                "context-1",
                {"images": ["https://media.example/image.png"]},
                delivery_key="media-send-failure-lease-loss",
            )
    finally:
        delattr(bridge._HANDLE_CONTEXT, "lease_session")

    assert fallback_calls == []


def test_media_send_success_then_lease_loss_is_propagated_without_fallback(
    monkeypatch,
):
    bridge = _load_bridge()

    class StickyLease:
        lost = False

        def before_provider(self) -> bool:
            return not self.lost

    lease = StickyLease()
    send_calls: list[str] = []
    fallback_calls: list[str] = []
    monkeypatch.setattr(bridge, "_fetch_media", lambda _url, _kind: b"raw")
    monkeypatch.setattr(
        bridge,
        "_upload_media",
        lambda *_args, **_kwargs: {
            "encrypt_query_param": "opaque-query",
            "aes_key": "opaque-key",
            "size": 3,
        },
    )

    def send_then_lose(_method, path, *_args, **_kwargs):
        assert path == "/ilink/bot/sendmessage"
        send_calls.append(path)
        lease.lost = True
        return {}

    monkeypatch.setattr(bridge, "_ilink", send_then_lose)
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: fallback_calls.append(text),
    )
    bridge._HANDLE_CONTEXT.lease_session = lease
    try:
        with pytest.raises(
            bridge.InboundFinishFenceLost,
            match="inbound_provider_fence_lost",
        ):
            bridge._send_generated_media(
                "bot-token",
                "user-1",
                "context-1",
                {"images": ["https://media.example/image.png"]},
                delivery_key="media-post-send-lease-loss",
            )
    finally:
        delattr(bridge._HANDLE_CONTEXT, "lease_session")

    assert send_calls == ["/ilink/bot/sendmessage"]
    assert fallback_calls == []


def test_weixin_inbound_media_requires_exact_official_cdn_host(monkeypatch):
    bridge = _load_bridge()
    opened = False

    def fail_open(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("untrusted CDN host must not reach the network")

    monkeypatch.setattr(bridge, "fetch_public_bytes", fail_open)
    with pytest.raises(bridge.MediaFetchError, match="不是官方 CDN URL"):
        bridge._cdn_download(
            {"url": "https://novac2c.cdn.weixin.qq.com.evil.test/c2c"}
        )
    with pytest.raises(bridge.MediaFetchError, match="不是官方 CDN URL"):
        bridge._cdn_download({"url": "http://novac2c.cdn.weixin.qq.com/c2c"})
    assert opened is False


def test_media_stream_limit_blocks_chunked_oom_without_content_length(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_MAX_GENERATED_IMAGE_BYTES", 8)
    captured = {}

    def too_large(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        raise bridge.PublicFetchError("streamed response exceeds cap")

    monkeypatch.setattr(bridge, "fetch_public_bytes", too_large)
    with pytest.raises(bridge.MediaFetchError, match="大小上限"):
        bridge._fetch_media("https://media.example.test/image", "image")
    assert captured["kwargs"]["max_bytes"] == 8
    assert captured["kwargs"]["allowed_type_prefixes"] == ("image/",)
    assert captured["kwargs"]["total_timeout"] == 120


def test_weixin_cdn_download_uses_exact_host_guard_on_every_helper_hop(monkeypatch):
    bridge = _load_bridge()
    captured = {}

    def fake_fetch(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return SimpleNamespace(data=b"encrypted")

    monkeypatch.setattr(bridge, "fetch_public_bytes", fake_fetch)
    assert bridge._cdn_download({"url": "https://novac2c.cdn.weixin.qq.com/c2c"}) == b"encrypted"
    guard = captured["kwargs"]["url_guard"]
    assert guard("https://novac2c.cdn.weixin.qq.com/c2c?x=1") is True
    assert guard("https://novac2c.cdn.weixin.qq.com.evil.test/c2c") is False
    assert captured["kwargs"]["require_content_type"] is False
    assert captured["kwargs"]["max_bytes"] == bridge._MAX_INBOUND_MEDIA_BYTES
    assert bridge._MAX_INBOUND_MEDIA_BYTES == 25 * 1024 * 1024 - 32 * 1024 - 4


def test_weixin_cdn_upload_uses_pinned_post_without_redirect_or_secret_header(monkeypatch):
    bridge = _load_bridge()
    monkeypatch.setattr(
        bridge,
        "_ilink",
        lambda *_args, **_kwargs: {
            "upload_full_url": "https://novac2c.cdn.weixin.qq.com/c2c?signature=opaque"
        },
    )
    captured = {}

    def fake_request(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return SimpleNamespace(headers={"x-encrypted-param": "receipt"})

    monkeypatch.setattr(bridge, "request_public_bytes", fake_request)
    got = bridge._upload_media("bot-secret", "user-1", b"image", 1)
    assert got["encrypt_query_param"] == "receipt"
    assert captured["kwargs"]["method"] == "POST"
    assert captured["kwargs"]["max_redirects"] == 0
    assert captured["kwargs"]["request_content_type"] == "application/octet-stream"
    assert captured["kwargs"]["max_request_bytes"] == len(captured["kwargs"]["request_body"])
    assert "headers" not in captured["kwargs"]
    guard = captured["kwargs"]["url_guard"]
    assert guard(captured["url"]) is True
    assert guard("https://evil.example/c2c") is False


def test_health_projects_oldest_processing_inbound_age(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"u1"}), "u1", ""),
        raising=False,
    )
    monkeypatch.setattr(bridge.time, "time", lambda: 1_000.0)
    with bridge._outbox_connect() as conn:
        conn.execute(
            """
            INSERT INTO inbound_message
              (message_key,from_user_id,payload,received_at,next_attempt_at,status,
               claimed_at,claim_token,claim_deadline)
            VALUES ('processing-in','u1','{}',900,900,'processing',958,'token',1100)
            """
        )

    snapshot = bridge._update_health("healthy", consecutive_poll_failures=0)

    assert snapshot["oldest_processing_age_seconds"] == pytest.approx(42.0)


def test_health_snapshot_is_exact_bounded_atomic_and_carries_expiry(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"u1"}), "u1", ""),
        raising=False,
    )
    bridge._HEALTH_FILE.write_text(
        json.dumps({"stale_secret": "must-disappear", "pending_inbound": -9}),
        encoding="utf-8",
    )

    before = time.time()
    snapshot = bridge._update_health(
        "healthy",
        consecutive_poll_failures=0,
        last_poll_ok_at=before,
        last_handler_ok=False,
        last_error="JSONDecodeError: invalid upstream response",
        arbitrary_old_field="must-not-survive",
    )
    disk = json.loads(bridge._HEALTH_FILE.read_text("utf-8"))
    expected_keys = {
        "schema",
        "state",
        "ready",
        "connected",
        "fresh",
        "pid",
        "updated_at",
        "heartbeat_at",
        "fresh_until",
        "freshness_ttl_seconds",
        "pending_inbound",
        "pending_outbound",
        "pending_video",
        "dead_inbound",
        "dead_outbound",
        "oldest_processing_age_seconds",
        "consecutive_poll_failures",
        "last_poll_ok_at",
        "last_message_finished_at",
        "last_error_code",
        "last_handler_ok",
        "last_handler_error_code",
        "workers_configured",
        "workers_alive",
        "access_configured",
        "bridge_key_configured",
        "engine_available",
        "engine_readiness_reason",
        "readiness_reasons",
    }
    assert snapshot == disk
    assert set(disk) == expected_keys
    assert disk["schema"] == "nachuan.weixin-bridge-health.v1"
    assert disk["fresh_until"] == pytest.approx(
        disk["updated_at"] + disk["freshness_ttl_seconds"]
    )
    assert disk["updated_at"] >= before
    assert disk["ready"] is False
    assert disk["last_handler_ok"] is False
    assert disk["last_handler_error_code"] == "JSONDecodeError"
    assert disk["engine_readiness_reason"] in {
        "ready",
        "ready_no_model",
        "requested_model_unavailable",
        "engine_unavailable",
    }
    assert "handler_failure" in disk["readiness_reasons"]
    for name in (
        "pending_inbound",
        "pending_outbound",
        "pending_video",
        "dead_inbound",
        "dead_outbound",
        "consecutive_poll_failures",
        "workers_configured",
        "workers_alive",
    ):
        assert type(disk[name]) is int and disk[name] >= 0
    assert type(disk["oldest_processing_age_seconds"]) is float
    assert disk["oldest_processing_age_seconds"] >= 0
    for name in (
        "ready",
        "connected",
        "fresh",
        "access_configured",
        "bridge_key_configured",
        "engine_available",
    ):
        assert type(disk[name]) is bool
    info = bridge._HEALTH_FILE.lstat()
    assert bridge._HEALTH_FILE.is_file() and not bridge._HEALTH_FILE.is_symlink()
    assert 0 < info.st_size <= 64 * 1024


def test_pending_async_video_is_visible_in_health_and_blocks_false_ready(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_health.json")
    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx-user-health"}), "", ""),
    )
    bridge._enqueue_pending_video(
        "video-task-health",
        "wx-user-health",
        "context-health",
        source_message_key="wxmsg-v1:health",
        now=1000.0,
        _internal_maintenance=True,
    )

    snapshot = bridge._update_health("healthy", consecutive_poll_failures=0)
    assert snapshot["ready"] is False
    assert snapshot["state"] == "degraded"
    assert snapshot["pending_video"] == 1
    assert "pending_video" in snapshot["readiness_reasons"]
    assert not list(tmp_path.glob("*.tmp"))


def test_health_never_reports_ready_without_bridge_key_or_engine(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"u1"}), "u1", ""),
        raising=False,
    )

    monkeypatch.setattr(bridge, "ENGINE_KEY", "")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", True, raising=False)
    missing_key = bridge._update_health("healthy", consecutive_poll_failures=0)
    assert missing_key["ready"] is False
    assert "bridge_key_missing" in missing_key["readiness_reasons"]

    monkeypatch.setattr(bridge, "ENGINE_KEY", "bridge-key")
    monkeypatch.setattr(bridge, "_ENGINE_AVAILABLE", False, raising=False)
    missing_engine = bridge._update_health("healthy", consecutive_poll_failures=0)
    assert missing_engine["ready"] is False
    assert "engine_unavailable" in missing_engine["readiness_reasons"]


def test_health_snapshot_preserves_chat_readiness_failure_reason(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_HEALTH_FILE", tmp_path / "weixin_bridge_health.json")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"u1"}), "u1", ""),
        raising=False,
    )
    bridge.ENGINE_KEY = "bridge-key"
    bridge._set_engine_available(False, "requested_model_unavailable")

    snapshot = bridge._update_health("healthy", consecutive_poll_failures=0)

    assert snapshot["engine_available"] is False
    assert snapshot["engine_readiness_reason"] == "requested_model_unavailable"
    assert "requested_model_unavailable" in snapshot["readiness_reasons"]
    assert "engine_unavailable" not in snapshot["readiness_reasons"]


def test_engine_availability_probe_is_bounded_and_verifies_bridge_key(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "bridge-key"
    bridge.MODEL = ""
    captured = {}

    def fake_request(opener, **kwargs):
        captured["opener"] = opener
        captured.update(kwargs)
        return (
            b'{"status":"ok","channel":"weixin","chat_ready":true,'
            b'"reason":"ready"}'
        )

    monkeypatch.setattr(bridge, "request_bridge_bytes", fake_request)
    assert bridge._probe_engine_available(timeout=20) is True
    assert captured["opener"] is bridge._ENGINE_OPENER
    assert captured["url"] == f"{bridge.ENGINE}/v1/bridge/health"
    assert captured["secret"] == "bridge-key"
    assert captured["channel"] == "weixin"
    assert captured["method"] == "GET"
    assert captured["body"] == b""
    assert captured["timeout"] == 5.0
    assert captured["max_response_bytes"] == bridge._STATE_FILE_MAX_BYTES
    captured_builder = {}
    sentinel_handler = object()
    sentinel_opener = object()

    def fake_proxy_handler(proxies):
        captured_builder["proxies"] = proxies
        return sentinel_handler

    def fake_build_opener(handler):
        captured_builder["handler"] = handler
        return sentinel_opener

    monkeypatch.setattr(bridge.urllib.request, "ProxyHandler", fake_proxy_handler)
    monkeypatch.setattr(bridge.urllib.request, "build_opener", fake_build_opener)
    assert bridge._build_engine_opener() is sentinel_opener
    assert captured_builder == {"proxies": {}, "handler": sentinel_handler}


def test_engine_availability_probe_fails_closed_without_chat_route(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "bridge-key"
    bridge.MODEL = ""
    monkeypatch.setattr(
        bridge,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: (
            b'{"status":"ok","channel":"weixin","chat_ready":false,'
            b'"reason":"ready_no_model"}'
        ),
    )

    assert bridge._probe_engine_available() is False
    assert bridge._ENGINE_AVAILABLE is False
    assert bridge._ENGINE_READINESS_REASON == "ready_no_model"


def test_engine_availability_probe_rejects_legacy_reachability_only_health(
    monkeypatch,
):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "bridge-key"
    bridge.MODEL = ""
    monkeypatch.setattr(
        bridge,
        "request_bridge_bytes",
        lambda *_args, **_kwargs: b'{"status":"ok","channel":"weixin"}',
    )

    assert bridge._probe_engine_available() is False
    assert bridge._ENGINE_AVAILABLE is False
    assert bridge._ENGINE_READINESS_REASON == "engine_unavailable"


def test_engine_availability_probe_checks_explicit_model_fail_closed(monkeypatch):
    bridge = _load_bridge()
    bridge.ENGINE_KEY = "bridge-key"
    bridge.MODEL = "retired/model"
    captured = {}

    def fake_request(_opener, **kwargs):
        captured.update(kwargs)
        return (
            b'{"status":"ok","channel":"weixin","chat_ready":false,'
            b'"reason":"requested_model_unavailable"}'
        )

    monkeypatch.setattr(bridge, "request_bridge_bytes", fake_request)

    assert bridge._probe_engine_available() is False
    assert captured["url"] == (
        f"{bridge.ENGINE}/v1/bridge/health?model=retired%2Fmodel"
    )
    assert captured["body"] == b""
    assert bridge._ENGINE_READINESS_REASON == "requested_model_unavailable"


def test_production_access_ignores_legacy_env_and_hot_reload_revokes_immediately(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    access_file = tmp_path / "weixin_access.json"
    monkeypatch.setattr(bridge, "_ACCESS_FILE", access_file)
    monkeypatch.setenv("NACHUAN_ENV", "production")
    monkeypatch.setenv("WEIXIN_ALLOWED", "legacy-user")
    monkeypatch.setenv("WEIXIN_OWNER", "legacy-owner")

    _replace_access(access_file, ["file-user"], "file-owner")
    policy, owner, error = bridge._refresh_access()
    assert error == ""
    assert owner == "file-owner"
    assert policy.permits("file-user") and policy.permits("file-owner")
    assert not policy.permits("legacy-user") and not policy.permits("legacy-owner")

    _replace_access(access_file, ["replacement-user"], "")
    policy, owner, error = bridge._refresh_access()
    assert error == ""
    assert owner == ""
    assert policy.permits("replacement-user")
    assert not policy.permits("file-user")

    access_file.write_text("{broken", encoding="utf-8")
    policy, owner, error = bridge._refresh_access()
    assert error == "access_invalid"
    assert owner == "" and policy.configured is False

def test_legacy_access_env_is_merged_only_in_exact_development_mode(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_ACCESS_FILE", tmp_path / "missing.json")
    monkeypatch.setenv("WEIXIN_ALLOWED", "legacy-user")
    monkeypatch.setenv("WEIXIN_OWNER", "legacy-owner")

    monkeypatch.setenv("NACHUAN_ENV", "dev")
    policy, owner, _error = bridge._refresh_access()
    assert not policy.permits("legacy-user") and owner == ""

    monkeypatch.setenv("NACHUAN_ENV", "development")
    policy, owner, error = bridge._refresh_access()
    assert error == ""
    assert policy.permits("legacy-user") and policy.permits("legacy-owner")
    assert owner == "legacy-owner"


def test_whoami_is_rate_limited_and_unauthorized_done_payload_is_tombstoned(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy(), "", ""),
        raising=False,
    )
    decisions = iter([True, False])
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: next(decisions))
    delivered: list[str] = []
    monkeypatch.setattr(
        bridge,
        "_deliver_text",
        lambda _token, _to, _ctx, text, **_kwargs: delivered.append(text) or True,
    )
    message = {
        "message_id": "whoami-1",
        "from_user_id": "unknown-user",
        "context_token": "private-context",
        "item_list": [{"type": 1, "text_item": {"text": "/whoami"}}],
    }
    bridge._handle(message, "token")
    bridge._handle({**message, "message_id": "whoami-2"}, "token")
    assert len(delivered) == 1

    bridge._store_updates([message], "cursor-1")
    claimed = bridge._claim_inbound()
    assert claimed is not None
    # A concurrent allowlist addition after handling must not resurrect the
    # body of a message that was unauthorized when claimed.
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"unknown-user"}), "", ""),
    )
    bridge._finish_inbound(
        claimed[0],
        claim_token=claimed[2],
        claim_epoch=claimed[3],
        ok=True,
        unauthorized_at_claim=True,
    )
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,from_user_id,payload FROM inbound_message WHERE id=?",
            (claimed[0],),
        ).fetchone()
    assert row[0] == "done"
    assert row[1].startswith("sha256:")
    assert row[2] == bridge._UNAUTHORIZED_INBOUND_TOMBSTONE
    assert "private-context" not in row[2]


def test_inbound_payload_and_row_budgets_prevent_durable_database_growth(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_MAX_INBOUND_PAYLOAD_BYTES", 256, raising=False)
    monkeypatch.setattr(bridge, "_MAX_INBOUND_ROWS", 2, raising=False)
    huge = {
        "message_id": "huge-1",
        "from_user_id": "unknown-user",
        "context_token": "private-context",
        "item_list": [{"type": 1, "text_item": {"text": "X" * 100_000}}],
    }
    assert bridge._store_updates([huge], "cursor-1") is True
    with bridge._outbox_connect() as conn:
        row = conn.execute(
            "SELECT status,from_user_id,payload,last_error FROM inbound_message"
        ).fetchone()
    assert row[0] == "dead"
    assert row[1].startswith("sha256:")
    assert row[2] == bridge._OVERSIZE_INBOUND_TOMBSTONE
    assert row[3] == "payload_too_large"
    assert len(row[2].encode("utf-8")) <= 256

    for index in range(2, 5):
        message = {
            "message_id": f"done-{index}",
            "from_user_id": "unknown-user",
            "item_list": [{"type": 1, "text_item": {"text": "ok"}}],
        }
        assert bridge._store_updates([message], f"cursor-{index}") is True
        claimed = bridge._claim_inbound()
        assert claimed is not None
        bridge._finish_inbound(
            claimed[0], claim_token=claimed[2], claim_epoch=claimed[3], ok=True
        )
    with bridge._outbox_connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM inbound_message").fetchone()[0] <= 2


def test_malformed_or_unsupported_inbound_is_dead_lettered_not_silently_done(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    missing_sender = {
        "message_id": "invalid-sender-1",
        "context_token": "context-1",
        "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
    }
    unsupported = {
        "message_id": "unsupported-item-1",
        "from_user_id": "user-1",
        "context_token": "context-2",
        "item_list": [{"type": 99, "unknown_item": {"value": "x"}}],
    }

    assert bridge._store_updates(
        [missing_sender, unsupported], "cursor-quarantine"
    ) is True
    assert bridge._store_updates([unsupported], "cursor-quarantine") is True

    with bridge._outbox_connect() as conn:
        rows = conn.execute(
            "SELECT status,from_user_id,payload,last_error "
            "FROM inbound_message ORDER BY message_key"
        ).fetchall()

    assert len(rows) == 2
    assert {row[0] for row in rows} == {"dead"}
    assert {row[3] for row in rows} == {"invalid_sender", "unsupported_items"}
    assert all(row[1].startswith("sha256:") for row in rows)
    assert all(row[2] == bridge._INVALID_INBOUND_TOMBSTONE for row in rows)
    assert bridge._load_cursor() == "cursor-quarantine"
    assert bridge._inbox_pending_count() == 0
    assert bridge._queue_health_counts()[3] == 2


def test_access_hot_reload_rejects_oversized_and_nonregular_files(
    monkeypatch, tmp_path
):
    bridge = _load_bridge()
    access_file = tmp_path / "weixin_access.json"
    monkeypatch.setattr(bridge, "_ACCESS_FILE", access_file)
    monkeypatch.setenv("NACHUAN_ENV", "production")

    access_file.write_bytes(b"x" * (64 * 1024 + 1))
    policy, owner, error = bridge._refresh_access()
    assert error == "access_invalid"
    assert owner == "" and policy.configured is False

    access_file.unlink()
    access_file.mkdir()
    policy, owner, error = bridge._refresh_access()
    assert error == "access_invalid"
    assert owner == "" and policy.configured is False

    access_file.rmdir()
    target = tmp_path / "redirected-access.json"
    _replace_access(target, ["must-not-be-trusted"])
    try:
        access_file.symlink_to(target)
    except OSError:
        return
    policy, owner, error = bridge._refresh_access()
    assert error == "access_invalid"
    assert owner == "" and policy.configured is False


def test_sqlite_state_has_hard_page_and_wal_budgets(monkeypatch, tmp_path):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(bridge, "_STATE_DB_MAX_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(bridge, "_STATE_DB_MAX_WAL_BYTES", 512 * 1024)

    with bridge._outbox_connect() as conn:
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        max_pages = int(conn.execute("PRAGMA max_page_count").fetchone()[0])
        wal_limit = int(conn.execute("PRAGMA journal_size_limit").fetchone()[0])
    assert max_pages * page_size <= bridge._STATE_DB_MAX_BYTES
    assert wal_limit == bridge._STATE_DB_MAX_WAL_BYTES


def test_login_qrcode_falls_back_to_svg_without_pillow(monkeypatch, tmp_path, capsys):
    bridge = _load_bridge()
    monkeypatch.setattr(bridge, "_TOKEN_FILE", tmp_path / "ilink_token.json")
    monkeypatch.setattr(bridge.os, "startfile", lambda _path: None, raising=False)

    bridge._show_qrcode("https://example.test/weixin-login")

    svg = tmp_path / "ilink_qrcode.svg"
    assert svg.is_file()
    assert "<svg" in svg.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert str(svg) in output
    assert "https://example.test/weixin-login" not in output
