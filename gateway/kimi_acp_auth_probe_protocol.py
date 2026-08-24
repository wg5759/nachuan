"""Prompt-free ACP authentication probe for the Kimi Code connector.

The official ``authenticate`` method only confirms that Kimi Code can find a
local token record.  It does not refresh the token, call the provider, or prove
model access, so a successful result remains ``token_present_unprobed``.
"""

from __future__ import annotations

from dataclasses import dataclass

from gateway.kimi_acp_product_protocol import (
    KimiAcpChannel,
    KimiAcpProductError,
    _CLIENT_INFO,
    _MAX_MESSAGE_BYTES,
    _PROTOCOL_VERSION,
    _Protocol,
    _VERSION_PATTERN,
    _validate_initialize,
)


@dataclass(frozen=True)
class KimiAcpAuthProbeRequest:
    bound_version: str
    max_message_bytes: int = _MAX_MESSAGE_BYTES


@dataclass(frozen=True)
class KimiAcpAuthProbeResult:
    token_present: bool


def _validate_request(request: KimiAcpAuthProbeRequest) -> None:
    if not isinstance(request, KimiAcpAuthProbeRequest):
        raise KimiAcpProductError("request_rejected")
    if (
        not isinstance(request.bound_version, str)
        or not _VERSION_PATTERN.fullmatch(request.bound_version)
    ):
        raise KimiAcpProductError("agent_identity_rejected")
    if (
        type(request.max_message_bytes) is not int
        or not 256 <= request.max_message_bytes <= 8 * 1024 * 1024
    ):
        raise KimiAcpProductError("message_bound_rejected")


def run_kimi_acp_auth_probe_protocol(
    request: KimiAcpAuthProbeRequest,
    channel: KimiAcpChannel,
) -> KimiAcpAuthProbeResult:
    """Run initialize/authenticate without creating a session or sending text."""

    _validate_request(request)
    protocol = _Protocol(request, channel)  # type: ignore[arg-type]
    try:
        protocol.send_request(
            0,
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "clientCapabilities": {},
                "clientInfo": dict(_CLIENT_INFO),
            },
        )
        _validate_initialize(protocol.await_response(0), request.bound_version)
        protocol.send_request(
            1,
            "authenticate",
            {"methodId": "login"},
        )
        try:
            result = protocol.await_response(1)
        except KimiAcpProductError as exc:
            if exc.code != "auth_required":
                raise
            token_present = False
        else:
            if result is not None and result != {}:
                raise KimiAcpProductError("auth_result_rejected")
            token_present = True
        protocol.close_input()
        try:
            trailing = channel.read_trailing_line()
        except Exception:
            raise KimiAcpProductError("trailing_wire_rejected") from None
        if trailing is not None:
            raise KimiAcpProductError("trailing_wire_rejected")
        return KimiAcpAuthProbeResult(token_present=token_present)
    except BaseException:
        try:
            protocol.close_input()
        except KimiAcpProductError:
            pass
        raise


__all__ = [
    "KimiAcpAuthProbeRequest",
    "KimiAcpAuthProbeResult",
    "run_kimi_acp_auth_probe_protocol",
]
