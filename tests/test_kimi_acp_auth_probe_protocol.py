from __future__ import annotations

import json

import pytest

from gateway.kimi_acp_auth_probe_protocol import (
    KimiAcpAuthProbeRequest,
    run_kimi_acp_auth_probe_protocol,
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
        assert self.input_closed is False
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


def test_auth_probe_sends_only_initialize_then_authenticate() -> None:
    channel = _ScriptedChannel(
        [
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
                        "authMethods": [
                            {
                                "id": "login",
                                "name": "Log in to Kimi Code",
                                "description": "Authenticate with Kimi Code.",
                                "type": "terminal",
                                "args": ["--login"],
                            }
                        ],
                    },
                }
            ),
            _line({"jsonrpc": "2.0", "id": 1, "result": None}),
        ]
    )

    result = run_kimi_acp_auth_probe_protocol(
        KimiAcpAuthProbeRequest(bound_version="0.27.0"),
        channel,
    )

    assert result.token_present is True
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
            "method": "authenticate",
            "params": {"methodId": "login"},
        },
    ]
    wire = json.dumps(sent, ensure_ascii=False)
    for forbidden in (
        "session/new",
        "session/set_config_option",
        "session/prompt",
        '"prompt"',
    ):
        assert forbidden not in wire


def test_auth_probe_maps_exact_minus_32000_to_token_absent() -> None:
    channel = _ScriptedChannel(
        [
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
                }
            ),
            _line(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {
                        "code": -32000,
                        "message": "Authentication required",
                    },
                }
            ),
        ]
    )

    result = run_kimi_acp_auth_probe_protocol(
        KimiAcpAuthProbeRequest(bound_version="0.27.0"),
        channel,
    )

    assert result.token_present is False
    assert channel.input_closed is True


@pytest.mark.parametrize("result", [{}, {"token": "must-not-be-accepted"}])
def test_auth_probe_accepts_only_empty_success_result(
    result: dict[str, str],
) -> None:
    channel = _ScriptedChannel(
        [
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
                }
            ),
            _line({"jsonrpc": "2.0", "id": 1, "result": result}),
        ]
    )

    if result == {}:
        assert run_kimi_acp_auth_probe_protocol(
            KimiAcpAuthProbeRequest(bound_version="0.27.0"),
            channel,
        ).token_present is True
    else:
        with pytest.raises(RuntimeError, match="auth_result_rejected"):
            run_kimi_acp_auth_probe_protocol(
                KimiAcpAuthProbeRequest(bound_version="0.27.0"),
                channel,
            )


def test_auth_probe_rejects_any_trailing_wire() -> None:
    channel = _ScriptedChannel(
        [
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
                }
            ),
            _line({"jsonrpc": "2.0", "id": 1, "result": None}),
        ],
        trailing=[
            _line(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {},
                }
            )
        ],
    )

    with pytest.raises(RuntimeError, match="trailing_wire_rejected"):
        run_kimi_acp_auth_probe_protocol(
            KimiAcpAuthProbeRequest(bound_version="0.27.0"),
            channel,
        )
