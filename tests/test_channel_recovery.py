from __future__ import annotations

import importlib
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway import channel_recovery
from gateway.auth import require_api_key, require_approval_admin_key


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(channel_recovery.router)
    app.dependency_overrides[require_api_key] = lambda: "runtime"
    app.dependency_overrides[require_approval_admin_key] = lambda: "approval-admin"
    return app


def test_channel_recovery_routes_require_both_authorities() -> None:
    routes = {
        route.path: {
            dependency.call
            for dependency in route.dependant.dependencies
            if dependency.call is not None
        }
        for route in channel_recovery.router.routes
    }
    expected = {require_api_key, require_approval_admin_key}
    assert routes["/admin/channel-recovery/weixin/inspect"] >= expected
    assert routes["/admin/channel-recovery/weixin/close-without-replay"] >= expected
    assert routes["/admin/channel-recovery/feishu/inspect"] >= expected
    assert routes["/admin/channel-recovery/feishu/close-without-replay"] >= expected


def test_feishu_recovery_state_loader_does_not_import_lark_sdk(monkeypatch) -> None:
    for name in tuple(sys.modules):
        if name == "lark_oapi" or name.startswith("lark_oapi."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(channel_recovery, "_FEISHU_BRIDGE_MODULE", None)

    bridge = channel_recovery._feishu_bridge()

    assert bridge._NACHUAN_FEISHU_STATE_ONLY is True
    assert not any(
        name == "lark_oapi" or name.startswith("lark_oapi.")
        for name in sys.modules
    )


def test_weixin_channel_recovery_inspect_double_confirm_and_idempotent_close(
    monkeypatch, tmp_path
) -> None:
    bridge = importlib.import_module("scripts.run_weixin_ilink_bridge")
    monkeypatch.setattr(bridge, "_OUTBOX_DB", tmp_path / "weixin_state.db")
    monkeypatch.setattr(channel_recovery, "_weixin_bridge", lambda: bridge)
    with bridge._outbox_connect() as conn:
        conn.execute(
            "INSERT INTO inbound_message(message_key,from_user_id,payload,"
            "received_at,next_attempt_at,status,chat_seq) "
            "VALUES('coordinator-target','wx-coordinator','{}',1,1,"
            "'recovery_required',1)"
        )

    with TestClient(_app()) as client:
        inspected = client.post(
            "/admin/channel-recovery/weixin/inspect",
            json={"target_kind": "inbound", "target_key": "coordinator-target"},
        )
        assert inspected.status_code == 200
        snapshot = inspected.json()
        assert snapshot["affected_counts"] == {
            "inbound": 1,
            "delivery": 0,
            "video": 0,
        }
        assert len(snapshot["decision_id"]) == 64
        assert "coordinator-target" not in inspected.text

        decision = {
            "target_kind": "inbound",
            "target_key": "coordinator-target",
            "expected_before_digest": snapshot["expected_before_digest"],
            "decision_id": snapshot["decision_id"],
            "decided_at_ms": snapshot["decided_at_ms"],
            "reason": "operator verified no automatic replay",
            "user_confirmed": True,
            "confirm_final": False,
        }
        rejected = client.post(
            "/admin/channel-recovery/weixin/close-without-replay",
            json=decision,
        )
        assert rejected.status_code == 422
        decision["confirm_final"] = True
        first = client.post(
            "/admin/channel-recovery/weixin/close-without-replay",
            json=decision,
        )
        assert first.status_code == 200
        assert first.json()["applied"] is True
        retry = client.post(
            "/admin/channel-recovery/weixin/close-without-replay",
            json=decision,
        )
        assert retry.status_code == 200
        assert retry.json() == {**first.json(), "applied": False}


def test_channel_recovery_rejects_duplicate_json_fields(monkeypatch) -> None:
    bridge = importlib.import_module("scripts.run_weixin_ilink_bridge")
    monkeypatch.setattr(channel_recovery, "_weixin_bridge", lambda: bridge)
    with TestClient(_app()) as client:
        response = client.post(
            "/admin/channel-recovery/weixin/inspect",
            content='{"target_kind":"inbound","target_kind":"video","target_key":"x"}',
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "channel_recovery_invalid_body"


def test_channel_recovery_rejects_far_future_decision_before_loading_bridge(
    monkeypatch,
) -> None:
    monkeypatch.setattr(channel_recovery.time, "time", lambda: 1_000.0)
    monkeypatch.setattr(
        channel_recovery,
        "_weixin_bridge",
        lambda: (_ for _ in ()).throw(AssertionError("Weixin bridge must not load")),
    )
    monkeypatch.setattr(
        channel_recovery,
        "_feishu_bridge",
        lambda: (_ for _ in ()).throw(AssertionError("Feishu bridge must not load")),
    )
    decision = {
        "target_kind": "inbox",
        "target_key": "target",
        "expected_before_digest": "a" * 64,
        "decision_id": "b" * 64,
        "decided_at_ms": 1_030_001,
        "reason": "operator decision",
        "user_confirmed": True,
        "confirm_final": True,
    }
    with TestClient(_app()) as client:
        for channel in ("weixin", "feishu"):
            response = client.post(
                f"/admin/channel-recovery/{channel}/close-without-replay",
                json=decision,
            )
            assert response.status_code == 422
            assert response.json()["detail"]["code"] == (
                "channel_recovery_invalid_decision"
            )


def test_feishu_channel_recovery_inspect_double_confirm_and_idempotent_close(
    monkeypatch, tmp_path
) -> None:
    bridge = channel_recovery._feishu_bridge()
    monkeypatch.setattr(bridge, "_STATE_DB", tmp_path / "feishu_state.db")
    monkeypatch.setattr(channel_recovery, "_feishu_bridge", lambda: bridge)
    assert bridge._store_inbound(
        {
            "message_id": "feishu-coordinator-target",
            "chat_id": "feishu-chat-1",
            "message_type": "text",
            "content": '{"text":"hello"}',
            "open_id": "open-id-1",
        },
        now=1.0,
    )
    with bridge._state_write_transaction() as conn:
        conn.execute(
            "UPDATE feishu_inbox SET status='recovery_required' "
            "WHERE message_id='feishu-coordinator-target'"
        )

    with TestClient(_app()) as client:
        inspected = client.post(
            "/admin/channel-recovery/feishu/inspect",
            json={"target_kind": "inbox", "target_key": "feishu-coordinator-target"},
        )
        assert inspected.status_code == 200
        snapshot = inspected.json()
        assert snapshot["affected_counts"] == {"inbox": 1, "outbox": 0, "video": 0}
        assert len(snapshot["decision_id"]) == 64
        assert "feishu-coordinator-target" not in inspected.text

        decision = {
            "target_kind": "inbox",
            "target_key": "feishu-coordinator-target",
            "expected_before_digest": snapshot["expected_before_digest"],
            "decision_id": snapshot["decision_id"],
            "decided_at_ms": snapshot["decided_at_ms"],
            "reason": "operator verified no automatic replay",
            "user_confirmed": True,
            "confirm_final": False,
        }
        rejected = client.post(
            "/admin/channel-recovery/feishu/close-without-replay",
            json=decision,
        )
        assert rejected.status_code == 422
        decision["confirm_final"] = True
        first = client.post(
            "/admin/channel-recovery/feishu/close-without-replay",
            json=decision,
        )
        assert first.status_code == 200
        assert first.json()["applied"] is True
        retry = client.post(
            "/admin/channel-recovery/feishu/close-without-replay",
            json=decision,
        )
        assert retry.status_code == 200
        assert retry.json() == {**first.json(), "applied": False}


def test_feishu_video_recovery_uses_same_dual_confirmation_route(
    monkeypatch, tmp_path
) -> None:
    bridge = channel_recovery._feishu_bridge()
    monkeypatch.setattr(bridge, "_STATE_DB", tmp_path / "feishu_state.db")
    monkeypatch.setattr(
        bridge,
        "_PENDING",
        tmp_path / "feishu_pending_videos.json",
    )
    monkeypatch.setattr(channel_recovery, "_feishu_bridge", lambda: bridge)
    bridge._pending_save(
        {
            "coordinator-video-target": {
                "chat_id": "coordinator-video-chat",
                "ts": 10.0,
                "state": "recovery_required",
                "upload_request_sha256": "a" * 64,
                "upload_started_at": 11.0,
                "file_key": "",
                "last_error": "upload_outcome_unknown",
            }
        }
    )

    with TestClient(_app()) as client:
        inspected = client.post(
            "/admin/channel-recovery/feishu/inspect",
            json={"target_kind": "video", "target_key": "coordinator-video-target"},
        )
        assert inspected.status_code == 200
        snapshot = inspected.json()
        assert snapshot["affected_counts"] == {"inbox": 0, "outbox": 0, "video": 1}
        assert "coordinator-video-target" not in inspected.text
        decision = {
            "target_kind": "video",
            "target_key": "coordinator-video-target",
            "expected_before_digest": snapshot["expected_before_digest"],
            "decision_id": snapshot["decision_id"],
            "decided_at_ms": snapshot["decided_at_ms"],
            "reason": "operator verified unknown upload will not be replayed",
            "user_confirmed": True,
            "confirm_final": True,
        }
        first = client.post(
            "/admin/channel-recovery/feishu/close-without-replay",
            json=decision,
        )
        assert first.status_code == 200
        assert first.json()["affected_counts"] == {
            "inbox": 0,
            "outbox": 0,
            "video": 1,
        }
        assert first.json()["applied"] is True
        retry = client.post(
            "/admin/channel-recovery/feishu/close-without-replay",
            json=decision,
        )
        assert retry.status_code == 200
        assert retry.json() == {**first.json(), "applied": False}
