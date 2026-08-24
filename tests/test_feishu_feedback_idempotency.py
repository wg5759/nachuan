from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_runner():
    path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
    spec = importlib.util.spec_from_file_location("run_feishu_feedback_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_feishu_feedback_binds_gateway_idempotency_to_message_id(monkeypatch):
    runner = _load_runner()
    calls: list[tuple[str, dict, float]] = []
    monkeypatch.setattr(
        runner,
        "_post",
        lambda path, body, timeout: calls.append((path, body, timeout)),
    )

    runner._feedback(
        "ou_feedback",
        "oc_feedback",
        "up",
        message_id="om_feedback_001",
    )

    assert calls == [
        (
            "/v1/agent/feedback",
            {
                "user_id": "ou_feedback",
                "chat_id": "oc_feedback",
                "channel": "feishu",
                "rating": "up",
                "note": "",
                "idempotency_key": "om_feedback_001",
            },
            30,
        )
    ]


def test_feishu_feedback_transport_failure_keeps_inbound_claim_retryable(monkeypatch):
    runner = _load_runner()

    def unavailable(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise TimeoutError("gateway response lost")

    monkeypatch.setattr(runner, "_post", unavailable)

    with pytest.raises(TimeoutError, match="gateway response lost"):
        runner._feedback(
            "ou_feedback",
            "oc_feedback",
            "down",
            "please fix",
            message_id="om_feedback_002",
        )


def test_feishu_feedback_handler_forwards_event_message_id(monkeypatch):
    runner = _load_runner()
    calls: list[dict] = []
    monkeypatch.setattr(
        runner,
        "_load_feishu_access",
        lambda: (frozenset({"ou_feedback"}), ""),
    )
    monkeypatch.setattr(
        runner,
        "_feedback",
        lambda user_id, chat_id, rating, note, *, message_id: calls.append(
            {
                "user_id": user_id,
                "chat_id": chat_id,
                "rating": rating,
                "note": note,
                "message_id": message_id,
            }
        ),
    )
    monkeypatch.setattr(runner, "_reply", lambda *_args, **_kwargs: True)
    event = SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id="om_feedback_003",
                chat_id="oc_feedback",
                message_type="text",
                content='{"text":"👍"}',
            ),
            sender=SimpleNamespace(
                sender_id=SimpleNamespace(open_id="ou_feedback")
            ),
        )
    )

    runner._handle_message(event)

    assert calls == [
        {
            "user_id": "ou_feedback",
            "chat_id": "oc_feedback",
            "rating": "up",
            "note": "",
            "message_id": "om_feedback_003",
        }
    ]
