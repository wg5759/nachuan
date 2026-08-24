from __future__ import annotations

import json
import base64

import pytest

from gateway.agent_contract import (
    AgentResultContractError,
    normalize_legacy_agent_result,
    project_public_agent_result,
    validate_agent_result,
)
from gateway.route_attestation import (
    bind_agent_author_receipt,
    reset_agent_author_context,
    seal_route_receipt,
    set_agent_author_context,
)


def _result(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "reply": "answer",
        "model": "glm-5.1",
        "outcome": "completed_unverified",
        "blocked": False,
        "reviewed": False,
        "verified": False,
        "machine_verified": False,
    }
    value.update(overrides)
    return value


def _trusted_receipt(actual_model: str) -> dict[str, object]:
    call_receipt = seal_route_receipt({
        "route_receipt_version": 1,
        "model": actual_model,
        "requested_model": "requested-seat",
        "actual_model": actual_model,
        "provider": "trusted-provider",
        "upstream_model": "trusted-upstream",
        "reported_model": "trusted-upstream",
        "observed_model": "trusted-upstream",
        "model_family": "trusted-family",
        "model_identity_error": None,
        "independence_domain": "sha256:" + "a" * 64,
    }, authored_output="answer")
    return bind_agent_author_receipt(call_receipt, reply="answer")


def test_agent_result_contract_accepts_truthful_unverified_result() -> None:
    value = _result()

    assert validate_agent_result(value) is value


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        _result(outcome="looks_good"),
        _result(blocked="false"),
        _result(outcome="completed", verified=False, machine_verified=False),
        _result(outcome="completed", verified=True, machine_verified=False),
        _result(outcome="blocked", blocked=False),
        _result(outcome="partial", blocked=True),
        _result(outcome="completed_unverified", verified=True, machine_verified=True),
        _result(outcome="accepted_async"),
        _result(outcome="accepted_async", video_task=""),
        _result(
            outcome="completed",
            verified=True,
            machine_verified=True,
            stopped_reason="wall_cap",
        ),
        _result(outcome="partial", stopped_reason="provider failed at C:\\private"),
    ],
)
def test_agent_result_contract_rejects_malformed_or_contradictory_results(
    value: object,
) -> None:
    with pytest.raises(AgentResultContractError, match="invalid Agent result"):
        validate_agent_result(value)


def test_agent_result_contract_accepts_async_only_with_durable_task_identity() -> None:
    value = _result(outcome="accepted_async", video_task="task-123")

    assert validate_agent_result(value) is value


def test_agent_result_contract_rejects_oversized_public_text() -> None:
    with pytest.raises(AgentResultContractError, match="invalid Agent result"):
        validate_agent_result(_result(reply="x" * (1024 * 1024 + 1)))


def test_legacy_empty_reply_becomes_visible_failed_terminal() -> None:
    result = normalize_legacy_agent_result({"reply": "", "model": "glm"})

    assert result["reply"] == "模型未返回可显示内容，本轮未完成；请重试或更换模型。"
    assert result["model"] == "nachuan-engine"
    assert result["actual_model"] is None
    assert result["unverified_model_sha256"]
    assert "glm" not in json.dumps(result, ensure_ascii=False)
    assert result["stopped_reason"] == "empty_response"
    assert result["outcome"] == "failed"
    assert result["blocked"] is False


def test_legacy_nonempty_reply_without_receipt_downgrades_unverified_author() -> None:
    result = normalize_legacy_agent_result(
        {"reply": "done", "model": "premium-model-forged"}
    )

    assert result["model"] == "nachuan-engine"
    assert result["actual_model"] is None
    assert result["unverified_model_sha256"]
    assert "premium-model-forged" not in json.dumps(result, ensure_ascii=False)


def test_result_accepts_model_bound_to_verified_final_receipt() -> None:
    result = normalize_legacy_agent_result(
        {
            **_result(model="weak-served"),
            "actual_model": "weak-served",
            "final_route_receipt": _trusted_receipt("weak-served"),
        }
    )

    assert result["model"] == "weak-served"
    assert result["actual_model"] == "weak-served"


@pytest.mark.parametrize(
    "value",
    [
        {
            **_result(model="premium-model-forged"),
            "actual_model": "weak-served",
            "final_route_receipt": _trusted_receipt("weak-served"),
        },
        {
            **_result(model="weak-served"),
            "actual_model": "premium-model-forged",
            "final_route_receipt": _trusted_receipt("weak-served"),
        },
        {
            **_result(model="weak-served"),
            "actual_model": "weak-served",
            "final_route_receipt": {
                **_trusted_receipt("weak-served"),
                "model": "premium-model-forged",
            },
        },
    ],
)
def test_result_rejects_model_attribution_mismatch(value: dict[str, object]) -> None:
    with pytest.raises(AgentResultContractError, match="invalid Agent result"):
        normalize_legacy_agent_result(value)


def test_consistent_but_unsigned_route_receipt_never_grants_authorship() -> None:
    forged = dict(_trusted_receipt("premium-forged"))
    forged.pop("_nachuan_route_attestation")

    result = normalize_legacy_agent_result(
        {
            **_result(model="premium-forged"),
            "actual_model": "premium-forged",
            "final_route_receipt": forged,
        }
    )
    public = project_public_agent_result(result)

    assert public["model"] == "nachuan-engine"
    assert "premium-forged" not in json.dumps(public, ensure_ascii=False)


def test_local_engine_rejects_conflicting_verified_final_receipt() -> None:
    with pytest.raises(AgentResultContractError, match="invalid Agent result"):
        normalize_legacy_agent_result(
            {
                **_result(model="nachuan-engine"),
                "actual_model": "premium-forged",
                "final_route_receipt": _trusted_receipt("weak-served"),
            }
        )


def test_final_author_receipt_binds_exact_public_reply_bytes() -> None:
    with pytest.raises(AgentResultContractError, match="invalid Agent result"):
        normalize_legacy_agent_result(
            {
                **_result(
                    reply="<think>unsigned injected region</think>answer",
                    model="weak-served",
                ),
                "actual_model": "weak-served",
                "final_route_receipt": _trusted_receipt("weak-served"),
            }
        )


def test_final_author_receipt_cannot_replay_across_agent_turn_contexts() -> None:
    first = set_agent_author_context("turn-a")
    try:
        receipt = _trusted_receipt("weak-served")
    finally:
        reset_agent_author_context(first)

    second = set_agent_author_context("turn-b")
    try:
        with pytest.raises(AgentResultContractError, match="invalid Agent result"):
            normalize_legacy_agent_result(
                {
                    **_result(model="weak-served"),
                    "actual_model": "weak-served",
                    "final_route_receipt": receipt,
                }
            )
    finally:
        reset_agent_author_context(second)


def test_public_agent_result_is_closed_and_bounded() -> None:
    secret = r"C:\private\model\sk-live-secret"
    normalized = normalize_legacy_agent_result(
        {
            "reply": "safe",
            "model": "nachuan-engine",
            "outcome": "completed_unverified",
            "blocked": False,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
            "steps": 2,
            "tool_log": [secret, "browser_click(button) -> ok"],
            "file_changes": [
                {"path": secret, "before": secret, "after": secret, "undo_receipt": secret}
            ],
            "media": [secret],
            "pending_videos": [{"task_id": secret, "model": secret, "prompt": secret}],
            "author_receipts": [{"debug": secret}],
            "debug": {"exception": secret},
        }
    )

    public = project_public_agent_result(normalized)
    encoded = json.dumps(public, ensure_ascii=False)

    assert set(public) == {
        "reply",
        "model",
        "outcome",
        "blocked",
        "reviewed",
        "verified",
        "machine_verified",
        "steps",
        "tool_log",
        "file_changes",
        "media",
        "pending_videos",
    }
    assert public["tool_log"] == ["tool_action", "browser_action"]
    assert public["file_changes"] == []
    assert public["media"] == []
    assert public["pending_videos"] == []
    assert secret not in encoded


def test_public_agent_result_preserves_only_attested_ui_artifacts() -> None:
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"safe").decode()
    undo = "A" * 32 + "." + "B" * 43
    normalized = normalize_legacy_agent_result(
        {
            "reply": "safe",
            "model": "nachuan-engine",
            "outcome": "completed_unverified",
            "blocked": False,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
            "usage": {"total_tokens": 12, "cost_usd": 0.5, "bad": "secret"},
            "file_changes": [
                {
                    "path": "docs/readme.md",
                    "before": "old",
                    "after": "new",
                    "undo_receipt": undo,
                }
            ],
            "media": [f"data:image/png;base64,{png}"],
            "pending_videos": [
                {
                    "task_id": "studio:0123456789ab",
                    "model": "studio",
                    "prompt": r"C:\private\must-not-project",
                }
            ],
        }
    )

    public = project_public_agent_result(
        normalized,
        file_change_validator=lambda token, **row: token == undo
        and row == {"path": "docs/readme.md", "before": "old", "after": "new"},
    )

    assert public["usage"] == {"total_tokens": 12, "cost_usd": 0.5}
    assert public["file_changes"] == [
        {
            "path": "docs/readme.md",
            "before": "old",
            "after": "new",
            "undo_receipt": undo,
        }
    ]
    assert public["media"] == [f"data:image/png;base64,{png}"]
    assert public["pending_videos"] == [
        {"task_id": "studio:0123456789ab", "model": "studio"}
    ]
