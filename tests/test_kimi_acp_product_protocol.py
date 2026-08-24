from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from gateway.kimi_acp_product_protocol import (
    KimiAcpProductError,
    KimiAcpProtocolRequest,
    run_kimi_acp_product_protocol,
)


def _line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _model_options(current: str = "kimi-code/k3") -> list[dict[str, object]]:
    return [
        {
            "id": "model",
            "name": "Model",
            "category": "model",
            "type": "select",
            "currentValue": current,
            "options": [
                {"value": "kimi-code/k3", "name": "Kimi K3"},
                {"value": "other", "name": "Other"},
            ],
        }
    ]


def _thinking_option(
    current: str,
    choices: list[tuple[str, str]],
) -> dict[str, object]:
    return {
        "id": "thinking",
        "name": "Thinking",
        "category": "thought_level",
        "type": "select",
        "currentValue": current,
        "options": [
            {"value": value, "name": name}
            for value, name in choices
        ],
    }


def _success_messages(
    *,
    version: str = "0.27.0",
    session_id: str = "session-0123456789abcdef",
    stop_reason: str = "end_turn",
) -> list[bytes]:
    return [
        _line(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "protocolVersion": 1,
                    "agentCapabilities": {},
                    "agentInfo": {
                        "name": "Kimi Code CLI",
                        "version": version,
                    },
                    "authMethods": [],
                },
            }
        ),
        _line(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "sessionId": session_id,
                    "configOptions": _model_options(),
                },
            }
        ),
        _line(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "configOptions": _model_options(),
                },
            }
        ),
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": session_id,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "messageId": "message-1",
                        "content": {"type": "text", "text": "hello "},
                    },
                },
            }
        ),
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": session_id,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "messageId": "message-1",
                        "content": {"type": "text", "text": "world"},
                    },
                },
            }
        ),
        _line(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "result": {"stopReason": stop_reason},
            }
        ),
    ]


class _ScriptedChannel:
    def __init__(
        self,
        messages: list[bytes],
        *,
        trailing: list[bytes] | None = None,
    ) -> None:
        self.messages = list(messages)
        self.trailing = list(trailing or [])
        self.sent: list[bytes] = []
        self.input_closed = False

    def write_line(self, payload: bytes) -> None:
        assert not self.input_closed
        self.sent.append(payload)

    def read_line(self) -> bytes:
        if not self.messages:
            raise EOFError
        return self.messages.pop(0)

    def close_input(self) -> None:
        self.input_closed = True

    def read_trailing_line(self) -> bytes | None:
        if self.trailing:
            return self.trailing.pop(0)
        return None


def _request(tmp_path: Path) -> KimiAcpProtocolRequest:
    cwd = tmp_path / "empty"
    cwd.mkdir()
    return KimiAcpProtocolRequest(
        prompt="PRIVATE_PRODUCT_PROMPT",
        cwd=str(cwd.resolve()),
        bound_version="0.27.0",
    )


def test_success_transcript_is_exact_and_prompt_only_enters_session_prompt(
    tmp_path: Path,
) -> None:
    channel = _ScriptedChannel(_success_messages())
    request = _request(tmp_path)

    result = run_kimi_acp_product_protocol(request, channel)

    assert result.text == "hello world"
    assert result.session_id == "session-0123456789abcdef"
    assert result.stop_reason == "end_turn"
    assert result.requested_alias == "kimi-code/k3"
    assert result.actual_served_model is None
    assert channel.input_closed is True
    sent = [json.loads(payload) for payload in channel.sent]
    assert sent == [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientCapabilities": {},
                "clientInfo": {
                    "name": "Nachuan",
                    "version": "0.1",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/new",
            "params": {
                "cwd": request.cwd,
                "mcpServers": [],
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/set_config_option",
            "params": {
                "sessionId": "session-0123456789abcdef",
                "configId": "model",
                "value": "kimi-code/k3",
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": {
                "sessionId": "session-0123456789abcdef",
                "prompt": [
                    {
                        "type": "text",
                        "text": "PRIVATE_PRODUCT_PROMPT",
                    }
                ],
            },
        },
    ]
    assert all(
        "PRIVATE_PRODUCT_PROMPT" not in json.dumps(item, ensure_ascii=False)
        for item in sent[:3]
    )


def test_config_option_update_before_set_model_response_is_accepted(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages.insert(
        2,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": {
                        "sessionUpdate": "config_option_update",
                        "configOptions": _model_options(),
                    },
                },
            }
        ),
    )

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.text == "hello world"


def test_available_commands_update_after_session_new_is_accepted(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages.insert(
        2,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": {
                        "sessionUpdate": "available_commands_update",
                        "availableCommands": [
                            {
                                "name": "compact",
                                "description": "Compact the current context.",
                            },
                            {
                                "name": "init",
                                "description": "Initialize project guidance.",
                                "input": {
                                    "hint": "Optional initialization goal."
                                },
                            },
                        ],
                    },
                },
            }
        ),
    )

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.text == "hello world"


def test_available_commands_update_delayed_until_prompt_is_accepted(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages.insert(
        3,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": {
                        "sessionUpdate": "available_commands_update",
                        "availableCommands": [
                            {
                                "name": "compact",
                                "description": "Compact the current context.",
                            }
                        ],
                    },
                },
            }
        ),
    )

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.text == "hello world"


@pytest.mark.parametrize(
    "update",
    [
        {
            "sessionUpdate": "available_commands_update",
            "availableCommands": [
                {
                    "name": "compact",
                    "description": "Compact the current context.",
                }
            ],
        },
        {
            "sessionUpdate": "config_option_update",
            "configOptions": _model_options(),
        },
    ],
)
def test_duplicate_metadata_update_is_rejected(
    tmp_path: Path,
    update: dict[str, object],
) -> None:
    notification = _line(
        {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session-0123456789abcdef",
                "update": update,
            },
        }
    )
    messages = _success_messages()
    messages[2:2] = [notification, notification]

    with pytest.raises(
        KimiAcpProductError,
        match="metadata_update_rejected",
    ):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


def test_config_option_update_after_set_model_response_is_rejected(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages.insert(
        3,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": {
                        "sessionUpdate": "config_option_update",
                        "configOptions": _model_options(),
                    },
                },
            }
        ),
    )

    with pytest.raises(KimiAcpProductError, match="update_type_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("session_id", "update", "code"),
    [
        (
            "session-stale",
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": [],
            },
            "session_binding_rejected",
        ),
        (
            "session-0123456789abcdef",
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": [],
                "extra": True,
            },
            "available_commands_rejected",
        ),
        (
            "session-0123456789abcdef",
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": [
                    {
                        "name": "init",
                        "description": "Initialize.",
                        "extra": True,
                    }
                ],
            },
            "available_commands_rejected",
        ),
        (
            "session-0123456789abcdef",
            {
                "sessionUpdate": "available_commands_update",
                "availableCommands": [
                    {
                        "name": "init",
                        "description": "Initialize.",
                        "input": {"hint": "Goal", "extra": True},
                    }
                ],
            },
            "available_commands_rejected",
        ),
        (
            "session-0123456789abcdef",
            {
                "sessionUpdate": "config_option_update",
                "configOptions": _model_options(),
                "extra": True,
            },
            "model_confirmation_rejected",
        ),
        (
            "session-0123456789abcdef",
            {
                "sessionUpdate": "config_option_update",
                "configOptions": _model_options()
                + [
                    {
                        "id": "unknown",
                        "name": "Unknown",
                        "category": "unknown",
                        "type": "select",
                        "currentValue": "on",
                        "options": [{"value": "on", "name": "On"}],
                    }
                ],
            },
            "model_selector_rejected",
        ),
    ],
)
def test_invalid_metadata_update_is_rejected(
    tmp_path: Path,
    session_id: str,
    update: dict[str, object],
    code: str,
) -> None:
    messages = _success_messages()
    messages.insert(
        2,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": session_id,
                    "update": update,
                },
            }
        ),
    )

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


def test_prompt_thought_chunk_is_validated_but_not_returned(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages.insert(
        3,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": {
                        "sessionUpdate": "agent_thought_chunk",
                        "content": {
                            "type": "text",
                            "text": "private chain of thought",
                        },
                    },
                },
            }
        ),
    )

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.text == "hello world"
    assert "private chain of thought" not in result.text


@pytest.mark.parametrize(
    "update",
    [
        {
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "too early"},
        },
        {
            "sessionUpdate": "agent_thought_chunk",
            "content": {"type": "text", "text": "too early"},
        },
    ],
)
def test_agent_text_updates_before_prompt_are_rejected(
    tmp_path: Path,
    update: dict[str, object],
) -> None:
    messages = _success_messages()
    messages.insert(
        2,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": update,
                },
            }
        ),
    )

    with pytest.raises(KimiAcpProductError, match="update_type_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    "update",
    [
        {
            "sessionUpdate": "agent_thought_chunk",
            "content": {"type": "text", "text": "hidden"},
            "extra": True,
        },
        {
            "sessionUpdate": "agent_thought_chunk",
            "content": {"type": "image", "text": "hidden"},
        },
        {
            "sessionUpdate": "agent_thought_chunk",
            "content": {"type": "text", "text": 7},
        },
    ],
)
def test_invalid_thought_chunk_shape_is_rejected(
    tmp_path: Path,
    update: dict[str, object],
) -> None:
    messages = _success_messages()
    messages.insert(
        3,
        _line(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "update": update,
                },
            }
        ),
    )

    with pytest.raises(KimiAcpProductError, match="agent_thought_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


def test_thought_chunks_have_a_cumulative_output_bound(
    tmp_path: Path,
) -> None:
    thought = {
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-0123456789abcdef",
            "update": {
                "sessionUpdate": "agent_thought_chunk",
                "content": {"type": "text", "text": "abc"},
            },
        },
    }
    messages = _success_messages()
    messages[3:3] = [_line(thought), _line(thought)]

    with pytest.raises(KimiAcpProductError, match="output_size_rejected"):
        run_kimi_acp_product_protocol(
            replace(_request(tmp_path), max_output_bytes=5),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda messages: messages.__setitem__(
                0,
                _line(
                    {
                        "jsonrpc": "2.0",
                        "id": 0,
                        "result": {
                            "protocolVersion": 1,
                            "agentCapabilities": {},
                            "agentInfo": {
                                "name": "Kimi Code CLI",
                                "version": "0.27.0",
                            },
                            "authMethods": [],
                        },
                        "extra": True,
                    }
                ),
            ),
            "response_shape_rejected",
        ),
        (
            lambda messages: messages.__setitem__(
                0,
                b'{"jsonrpc":"2.0","id":0,"id":0,"result":{}}\n',
            ),
            "invalid_json",
        ),
        (
            lambda messages: messages.__setitem__(
                0,
                _line(
                    {
                        "jsonrpc": "2.0",
                        "id": 99,
                        "result": {},
                    }
                ),
            ),
            "response_id_rejected",
        ),
    ],
)
def test_non_closed_jsonrpc_is_rejected(
    tmp_path: Path,
    mutate,
    code: str,
) -> None:
    messages = _success_messages()
    mutate(messages)

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocolVersion", 2),
        ("agent_name", "Other CLI"),
        ("agent_version", "0.28.0"),
    ],
)
def test_initialize_identity_drift_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = json.loads(_success_messages()[0])
    if field == "protocolVersion":
        document["result"]["protocolVersion"] = value
    elif field == "agent_name":
        document["result"]["agentInfo"]["name"] = value
    else:
        document["result"]["agentInfo"]["version"] = value
    messages = _success_messages()
    messages[0] = _line(document)

    with pytest.raises(KimiAcpProductError, match="agent_identity_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    "error",
    [
        {"code": -32000, "message": "Authentication required"},
        {
            "code": -32000,
            "message": "Authentication required",
            "data": {"login": "required"},
        },
    ],
)
def test_auth_rpc_error_maps_to_stable_prompt_free_code(
    tmp_path: Path,
    error: dict[str, object],
) -> None:
    messages = _success_messages()
    messages[-1] = _line(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "error": error,
        }
    )

    with pytest.raises(KimiAcpProductError) as caught:
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )

    assert caught.value.code == "auth_required"
    assert str(caught.value) == "auth_required"
    assert error["message"] not in str(caught.value)


def test_non_auth_rpc_error_keeps_generic_stable_code(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    messages[-1] = _line(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "error": {
                "code": -32603,
                "message": "PRIVATE_REMOTE_FAILURE_DETAIL",
            },
        }
    )

    with pytest.raises(KimiAcpProductError) as caught:
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )

    assert caught.value.code == "agent_rpc_error"
    assert str(caught.value) == "agent_rpc_error"
    assert "PRIVATE_REMOTE_FAILURE_DETAIL" not in str(caught.value)


@pytest.mark.parametrize(
    "error",
    [
        {"code": True, "message": "Authentication required"},
        {"code": -32000},
        {
            "code": -32000,
            "message": "Authentication required",
            "extra": True,
        },
    ],
)
def test_malformed_rpc_error_is_rejected_before_auth_classification(
    tmp_path: Path,
    error: dict[str, object],
) -> None:
    messages = _success_messages()
    messages[-1] = _line(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "error": error,
        }
    )

    with pytest.raises(KimiAcpProductError, match="response_shape_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("invalid_session", "session_rejected"),
        ("multiple_model_selectors", "model_selector_rejected"),
        ("unconfirmed_model", "model_confirmation_rejected"),
    ],
)
def test_session_and_model_binding_drift_is_rejected(
    tmp_path: Path,
    mutation: str,
    code: str,
) -> None:
    messages = _success_messages()
    session = json.loads(messages[1])
    configured = json.loads(messages[2])
    if mutation == "invalid_session":
        session["result"]["sessionId"] = "../escape"
        messages[1] = _line(session)
    elif mutation == "multiple_model_selectors":
        session["result"]["configOptions"].append(
            copy.deepcopy(session["result"]["configOptions"][0])
        )
        messages[1] = _line(session)
    else:
        configured["result"]["configOptions"][0]["currentValue"] = "other"
        messages[2] = _line(configured)

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


def test_one_model_selector_among_profiled_non_model_options_is_accepted(
    tmp_path: Path,
) -> None:
    non_model_option = {
        "id": "mode",
        "name": "Mode",
        "category": "mode",
        "type": "select",
        "currentValue": "normal",
        "options": [
            {
                "value": "normal",
                "name": "Normal",
                "description": "Balanced autonomous execution.",
            },
            {
                "value": "fast",
                "name": "Fast",
                "description": "Prefer a shorter execution path.",
            },
        ],
    }
    messages = _success_messages()
    created = json.loads(messages[1])
    configured = json.loads(messages[2])
    created["result"]["configOptions"].insert(0, copy.deepcopy(non_model_option))
    configured["result"]["configOptions"].insert(
        0,
        copy.deepcopy(non_model_option),
    )
    messages[1] = _line(created)
    messages[2] = _line(configured)

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.requested_alias == "kimi-code/k3"
    assert result.actual_served_model is None


def test_config_confirmation_cannot_change_selector_or_option_set(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    configured = json.loads(messages[2])
    configured["result"]["configOptions"][0]["name"] = "Changed model selector"
    messages[2] = _line(configured)

    with pytest.raises(
        KimiAcpProductError,
        match="model_confirmation_rejected",
    ):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("created_thinking", "configured_thinking"),
    [
        (
            None,
            _thinking_option(
                "enabled",
                [("disabled", "Disabled"), ("enabled", "Enabled")],
            ),
        ),
        (
            _thinking_option(
                "disabled",
                [("disabled", "Disabled"), ("enabled", "Enabled")],
            ),
            _thinking_option(
                "high",
                [("low", "Low"), ("high", "High")],
            ),
        ),
        (
            _thinking_option(
                "enabled",
                [("disabled", "Disabled"), ("enabled", "Enabled")],
            ),
            None,
        ),
    ],
)
def test_model_switch_allows_valid_thinking_option_to_change(
    tmp_path: Path,
    created_thinking: dict[str, object] | None,
    configured_thinking: dict[str, object] | None,
) -> None:
    messages = _success_messages()
    created = json.loads(messages[1])
    configured = json.loads(messages[2])
    if created_thinking is not None:
        created["result"]["configOptions"].append(
            copy.deepcopy(created_thinking)
        )
    if configured_thinking is not None:
        configured["result"]["configOptions"].append(
            copy.deepcopy(configured_thinking)
        )
    messages[1] = _line(created)
    messages[2] = _line(configured)

    result = run_kimi_acp_product_protocol(
        _request(tmp_path),
        _ScriptedChannel(messages),
    )

    assert result.text == "hello world"


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("wrong_session", "session_binding_rejected"),
        ("non_text", "agent_message_rejected"),
        ("changed_message_id", "message_id_rejected"),
        ("empty_output", "empty_output_rejected"),
    ],
)
def test_non_text_stale_or_multiple_agent_messages_are_rejected(
    tmp_path: Path,
    mutation: str,
    code: str,
) -> None:
    messages = _success_messages()
    if mutation == "wrong_session":
        update = json.loads(messages[3])
        update["params"]["sessionId"] = "session-stale"
        messages[3] = _line(update)
    elif mutation == "non_text":
        update = json.loads(messages[3])
        update["params"]["update"]["content"] = {
            "type": "image",
            "data": "no",
        }
        messages[3] = _line(update)
    elif mutation == "changed_message_id":
        update = json.loads(messages[4])
        update["params"]["update"]["messageId"] = "message-2"
        messages[4] = _line(update)
    else:
        messages = messages[:3] + messages[-1:]

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("method", "expected_code", "response_kind"),
    [
        ("fs/read_text_file", "reverse_method_rejected", "method_not_found"),
        ("terminal/create", "reverse_method_rejected", "method_not_found"),
        ("unknown/reverse", "reverse_method_rejected", "method_not_found"),
    ],
)
def test_reverse_rpc_is_answered_then_the_whole_turn_fails(
    tmp_path: Path,
    method: str,
    expected_code: str,
    response_kind: str,
) -> None:
    messages = _success_messages()[:3]
    messages.append(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 91,
                "method": method,
                "params": {"sessionId": "session-0123456789abcdef"},
            }
        )
    )
    channel = _ScriptedChannel(messages)

    with pytest.raises(KimiAcpProductError, match=expected_code):
        run_kimi_acp_product_protocol(_request(tmp_path), channel)

    response = json.loads(channel.sent[-1])
    assert response["id"] == 91
    if response_kind == "cancelled":
        assert response["result"] == {"outcome": {"outcome": "cancelled"}}
    else:
        assert response["error"]["code"] == -32601


def test_real_shape_permission_is_cancelled_then_turn_fails(
    tmp_path: Path,
) -> None:
    messages = _success_messages()[:3]
    messages.append(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 91,
                "method": "session/request_permission",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "toolCall": {"toolCallId": "call-1"},
                    "options": [
                        {
                            "optionId": "allow-once",
                            "name": "Allow once",
                            "kind": "allow_once",
                        }
                    ],
                },
            }
        )
    )
    channel = _ScriptedChannel(messages)

    with pytest.raises(
        KimiAcpProductError,
        match="permission_request_rejected",
    ):
        run_kimi_acp_product_protocol(_request(tmp_path), channel)

    assert json.loads(channel.sent[-1]) == {
        "jsonrpc": "2.0",
        "id": 91,
        "result": {"outcome": {"outcome": "cancelled"}},
    }


def test_realistic_reverse_method_params_get_method_not_found(
    tmp_path: Path,
) -> None:
    messages = _success_messages()[:3]
    messages.append(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 92,
                "method": "fs/read_text_file",
                "params": {
                    "sessionId": "session-0123456789abcdef",
                    "path": "C:/must-not-read",
                    "line": 1,
                },
            }
        )
    )
    channel = _ScriptedChannel(messages)

    with pytest.raises(
        KimiAcpProductError,
        match="reverse_method_rejected",
    ):
        run_kimi_acp_product_protocol(_request(tmp_path), channel)

    response = json.loads(channel.sent[-1])
    assert response["id"] == 92
    assert response["error"]["code"] == -32601


def test_tool_update_is_rejected_without_execution(tmp_path: Path) -> None:
    messages = _success_messages()
    update = json.loads(messages[3])
    update["params"]["update"] = {
        "sessionUpdate": "tool_call",
        "toolCallId": "call-1",
        "title": "run",
    }
    messages[3] = _line(update)

    with pytest.raises(KimiAcpProductError, match="tool_activity_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


def test_plan_update_is_rejected(tmp_path: Path) -> None:
    messages = _success_messages()
    update = json.loads(messages[3])
    update["params"]["update"] = {
        "sessionUpdate": "plan",
        "entries": [],
    }
    messages[3] = _line(update)

    with pytest.raises(KimiAcpProductError, match="update_type_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize("stop_reason", ["refusal", "cancelled", "max_tokens"])
def test_only_end_turn_is_accepted(
    tmp_path: Path,
    stop_reason: str,
) -> None:
    with pytest.raises(KimiAcpProductError, match="stop_reason_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(_success_messages(stop_reason=stop_reason)),
        )


def test_end_turn_drains_official_late_prompt_updates_before_accepting(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    channel = _ScriptedChannel(
        messages[:3] + messages[-1:],
        trailing=[
            _line(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "session-0123456789abcdef",
                        "update": {
                            "sessionUpdate": "agent_thought_chunk",
                            "content": {"type": "text", "text": "private thought"},
                        },
                    },
                }
            ),
            _line(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "session-0123456789abcdef",
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "messageId": "message-late",
                            "content": {"type": "text", "text": "late answer"},
                        },
                    },
                }
            ),
            _line(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "session-0123456789abcdef",
                        "update": {
                            "sessionUpdate": "available_commands_update",
                            "availableCommands": [
                                {
                                    "name": "compact",
                                    "description": "Compact the current context.",
                                }
                            ],
                        },
                    },
                }
            ),
        ],
    )

    result = run_kimi_acp_product_protocol(_request(tmp_path), channel)

    assert result.text == "late answer"
    assert channel.input_closed is True


@pytest.mark.parametrize(
    ("update", "code"),
    [
        (
            {
                "sessionUpdate": "tool_call",
                "toolCallId": "call-late",
                "title": "run",
            },
            "tool_activity_rejected",
        ),
        (
            {
                "sessionUpdate": "plan",
                "entries": [],
            },
            "update_type_rejected",
        ),
        (
            {
                "sessionUpdate": "config_option_update",
                "configOptions": _model_options(),
            },
            "update_type_rejected",
        ),
    ],
)
def test_end_turn_still_rejects_unapproved_late_updates(
    tmp_path: Path,
    update: dict[str, object],
    code: str,
) -> None:
    channel = _ScriptedChannel(
        _success_messages(),
        trailing=[
            _line(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "session-0123456789abcdef",
                        "update": update,
                    },
                }
            )
        ],
    )

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(_request(tmp_path), channel)


def test_end_turn_rejects_a_second_response_on_the_trailing_wire(
    tmp_path: Path,
) -> None:
    channel = _ScriptedChannel(
        _success_messages(),
        trailing=[
            _line(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "result": {},
                }
            )
        ],
    )

    with pytest.raises(KimiAcpProductError, match="trailing_wire_rejected"):
        run_kimi_acp_product_protocol(_request(tmp_path), channel)


def test_boolean_protocol_version_is_rejected(tmp_path: Path) -> None:
    messages = _success_messages()
    initialized = json.loads(messages[0])
    initialized["result"]["protocolVersion"] = True
    messages[0] = _line(initialized)

    with pytest.raises(KimiAcpProductError, match="agent_identity_rejected"):
        run_kimi_acp_product_protocol(
            _request(tmp_path),
            _ScriptedChannel(messages),
        )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("max_message_bytes", None, "message_bound_rejected"),
        ("max_message_bytes", True, "message_bound_rejected"),
        ("max_message_bytes", "1024", "message_bound_rejected"),
        ("max_message_bytes", 1024.5, "message_bound_rejected"),
        ("max_prompt_bytes", None, "prompt_bound_rejected"),
        ("max_output_bytes", float("nan"), "output_bound_rejected"),
    ],
)
def test_protocol_bounds_require_exact_integer_types(
    tmp_path: Path,
    field: str,
    value: object,
    code: str,
) -> None:
    request = replace(_request(tmp_path), **{field: value})

    with pytest.raises(KimiAcpProductError, match=code):
        run_kimi_acp_product_protocol(
            request,
            _ScriptedChannel(_success_messages()),
        )


def test_cleanup_failure_does_not_replace_primary_protocol_error(
    tmp_path: Path,
) -> None:
    messages = _success_messages()
    update = json.loads(messages[3])
    update["params"]["sessionId"] = "session-stale"
    messages[3] = _line(update)
    channel = _ScriptedChannel(messages)

    def fail_close() -> None:
        raise OSError("simulated close failure")

    channel.close_input = fail_close  # type: ignore[method-assign]

    with pytest.raises(KimiAcpProductError) as caught:
        run_kimi_acp_product_protocol(_request(tmp_path), channel)

    assert caught.value.code == "session_binding_rejected"


def test_protocol_module_is_product_only() -> None:
    source = (
        Path(__file__).parents[1]
        / "gateway"
        / "kimi_acp_product_protocol.py"
    ).read_text(encoding="utf-8")
    assert "scripts.kimi_acp_private_client" not in source
    assert "xreview" not in source.lower()
