from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from bridge.access import ChannelAccessPolicy


def _load_bridge():
    path = Path(__file__).parents[1] / "scripts" / "run_weixin_ilink_bridge.py"
    spec = importlib.util.spec_from_file_location("run_weixin_feedback_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_weixin_feedback_binds_gateway_idempotency_to_message_key(monkeypatch):
    bridge = _load_bridge()
    calls: list[tuple[str, dict, float]] = []
    monkeypatch.setattr(
        bridge,
        "_engine_post",
        lambda path, body, timeout: calls.append((path, body, timeout)),
    )

    bridge._feedback(
        "wx_feedback",
        "wx_chat",
        "up",
        message_key="wxmsg-v1:feedback-001",
    )

    assert calls == [
        (
            "/v1/agent/feedback",
            {
                "user_id": "wx_feedback",
                "chat_id": "wx_chat",
                "channel": "weixin",
                "rating": "up",
                "note": "",
                "idempotency_key": "wxmsg-v1:feedback-001",
            },
            30,
        )
    ]


def test_weixin_feedback_transport_failure_keeps_inbound_retryable(monkeypatch):
    bridge = _load_bridge()

    def unavailable(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise TimeoutError("gateway response lost")

    monkeypatch.setattr(bridge, "_engine_post", unavailable)

    with pytest.raises(TimeoutError, match="gateway response lost"):
        bridge._feedback(
            "wx_feedback",
            "wx_chat",
            "down",
            "please fix",
            message_key="wxmsg-v1:feedback-002",
        )


def test_weixin_feedback_handler_forwards_stable_message_key(monkeypatch):
    bridge = _load_bridge()
    calls: list[dict[str, str]] = []
    monkeypatch.setattr(
        bridge,
        "_refresh_access",
        lambda: (ChannelAccessPolicy({"wx_feedback"}), "", ""),
    )
    monkeypatch.setattr(bridge._limiter, "allow", lambda _user: True)
    monkeypatch.setattr(
        bridge,
        "_feedback",
        lambda user_id, chat_id, rating, note, *, message_key: calls.append(
            {
                "user_id": user_id,
                "chat_id": chat_id,
                "rating": rating,
                "note": note,
                "message_key": message_key,
            }
        ),
    )
    monkeypatch.setattr(bridge, "_deliver_text", lambda *_args, **_kwargs: True)
    message = {
        "message_id": "wx_feedback_003",
        "from_user_id": "wx_feedback",
        "context_token": "wx_chat",
        "item_list": [{"type": 1, "text_item": {"text": "👍"}}],
    }

    bridge._handle(message, "bot-token")

    assert calls == [
        {
            "user_id": "wx_feedback",
            "chat_id": "wx_feedback",
            "rating": "up",
            "note": "",
            "message_key": bridge._message_key(message),
        }
    ]
