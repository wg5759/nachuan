"""Closed, text-only ACP transcript for the Kimi Code product connector.

This module owns only protocol serialization and validation.  Process creation,
environment isolation, executable attestation, and process-tree containment are
the controller's responsibility.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol


_PROTOCOL_VERSION = 1
_CLIENT_INFO = {"name": "Nachuan", "version": "0.1"}
_SESSION_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z")
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
_ALIAS_PATTERN = re.compile(r"[A-Za-z0-9._:/-]{1,128}\Z")
_MAX_MESSAGE_BYTES = 5 * 1024 * 1024
_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_OPTION_PROFILES = {
    ("model", "model"),
    ("thinking", "thought_level"),
    ("mode", "mode"),
}


class KimiAcpProductError(RuntimeError):
    """Stable, prompt-free failure raised for a rejected ACP transcript."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class KimiAcpProtocolRequest:
    prompt: str
    cwd: str
    bound_version: str
    requested_alias: str = "kimi-code/kimi-for-coding"
    max_message_bytes: int = _MAX_MESSAGE_BYTES
    max_prompt_bytes: int = _MAX_PROMPT_BYTES
    max_output_bytes: int = _MAX_OUTPUT_BYTES


@dataclass(frozen=True)
class KimiAcpProtocolResult:
    text: str
    session_id: str
    stop_reason: str
    requested_alias: str
    actual_served_model: None = None


class KimiAcpChannel(Protocol):
    def write_line(self, payload: bytes) -> None: ...

    def read_line(self) -> bytes: ...

    def close_input(self) -> None: ...

    def read_trailing_line(self) -> bytes | None: ...


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _exact_keys(value: Mapping[str, Any], expected: set[str]) -> bool:
    return set(value) == expected


def _is_bounded_utf8_text(value: object, *, max_bytes: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= max_bytes
    except UnicodeEncodeError:
        return False


def _validate_request(request: KimiAcpProtocolRequest) -> Path:
    if not isinstance(request, KimiAcpProtocolRequest):
        raise KimiAcpProductError("request_rejected")
    if not isinstance(request.prompt, str):
        raise KimiAcpProductError("prompt_rejected")
    try:
        prompt_size = len(request.prompt.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise KimiAcpProductError("prompt_rejected") from None
    if (
        type(request.max_prompt_bytes) is not int
        or not 1 <= request.max_prompt_bytes <= _MAX_PROMPT_BYTES
    ):
        raise KimiAcpProductError("prompt_bound_rejected")
    if not prompt_size or prompt_size > request.max_prompt_bytes:
        raise KimiAcpProductError("prompt_rejected")
    if (
        type(request.max_message_bytes) is not int
        or not 256 <= request.max_message_bytes <= 8 * 1024 * 1024
    ):
        raise KimiAcpProductError("message_bound_rejected")
    if (
        type(request.max_output_bytes) is not int
        or not 1 <= request.max_output_bytes <= _MAX_OUTPUT_BYTES
    ):
        raise KimiAcpProductError("output_bound_rejected")
    if (
        not isinstance(request.bound_version, str)
        or not _VERSION_PATTERN.fullmatch(request.bound_version)
    ):
        raise KimiAcpProductError("agent_identity_rejected")
    if (
        not isinstance(request.requested_alias, str)
        or not _ALIAS_PATTERN.fullmatch(request.requested_alias)
    ):
        raise KimiAcpProductError("model_selector_rejected")
    if not isinstance(request.cwd, str) or not request.cwd:
        raise KimiAcpProductError("cwd_rejected")
    try:
        supplied = Path(request.cwd)
        cwd = supplied.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise KimiAcpProductError("cwd_rejected") from None
    if (
        not supplied.is_absolute()
        or not cwd.is_dir()
        or supplied.is_symlink()
        or str(cwd) != request.cwd
    ):
        raise KimiAcpProductError("cwd_rejected")
    try:
        if next(cwd.iterdir(), None) is not None:
            raise KimiAcpProductError("cwd_rejected")
    except OSError:
        raise KimiAcpProductError("cwd_rejected") from None
    return cwd


class _Protocol:
    def __init__(
        self,
        request: KimiAcpProtocolRequest,
        channel: KimiAcpChannel,
    ) -> None:
        self.request = request
        self.channel = channel
        self.session_id: str | None = None
        self.message_id: str | None = None
        self.message_id_presence: bool | None = None
        self.chunks: list[str] = []
        self.output_size = 0
        self.thought_size = 0
        self.input_closed = False
        self.created_options: list[dict[str, Any]] | None = None
        self.model_option_id: str | None = None
        self.metadata_update_counts = {
            "available_commands_update": 0,
            "config_option_update": 0,
        }

    def send_request(
        self,
        request_id: int,
        method: str,
        params: Mapping[str, object],
    ) -> None:
        self._write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": dict(params),
            }
        )

    def await_response(
        self,
        request_id: int,
        *,
        allowed_update_types: frozenset[str] = frozenset(),
    ) -> object:
        while True:
            message = self._read()
            if "method" in message:
                if "id" in message:
                    self._reject_reverse_request(message)
                self._handle_update(message, allowed_update_types)
                continue
            return self._validate_response(message, request_id)

    def close_input(self) -> None:
        if self.input_closed:
            return
        try:
            self.channel.close_input()
        except Exception:
            raise KimiAcpProductError("transport_failed") from None
        self.input_closed = True

    def drain_prompt_updates_to_eof(
        self,
        *,
        allowed_update_types: frozenset[str],
    ) -> None:
        """Drain only official prompt notifications that raced the response.

        Kimi Code dispatches prompt updates asynchronously and does not prove
        that they are flushed before the ``session/prompt`` response.  stdin is
        already closed here, so the bounded channel deadline and process EOF
        form the terminal boundary.  A second response, reverse request, tool
        activity, or any update outside the explicit prompt allowlist remains
        fail-closed.
        """

        while True:
            try:
                trailing = self.channel.read_trailing_line()
            except Exception:
                raise KimiAcpProductError("trailing_wire_rejected") from None
            if trailing is None:
                return
            message = self._decode_message(trailing)
            if "method" not in message or "id" in message:
                raise KimiAcpProductError("trailing_wire_rejected")
            self._handle_update(message, allowed_update_types)

    def output_text(self) -> str:
        text = "".join(self.chunks)
        if not text:
            raise KimiAcpProductError("empty_output_rejected")
        return text

    def _write(self, message: Mapping[str, object]) -> None:
        try:
            payload = (
                json.dumps(
                    message,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8", errors="strict")
                + b"\n"
            )
        except (TypeError, ValueError, UnicodeEncodeError):
            raise KimiAcpProductError("request_encoding_failed") from None
        if len(payload) > int(self.request.max_message_bytes):
            raise KimiAcpProductError("message_size_rejected")
        try:
            self.channel.write_line(payload)
        except Exception:
            raise KimiAcpProductError("transport_failed") from None

    def _read(self) -> dict[str, Any]:
        try:
            raw = self.channel.read_line()
        except EOFError:
            raise KimiAcpProductError("unexpected_eof") from None
        except Exception:
            raise KimiAcpProductError("transport_failed") from None
        return self._decode_message(raw)

    def _decode_message(self, raw: object) -> dict[str, Any]:
        if not isinstance(raw, bytes):
            raise KimiAcpProductError("wire_framing_rejected")
        if not raw or len(raw) > int(self.request.max_message_bytes):
            raise KimiAcpProductError("message_size_rejected")
        if raw.endswith(b"\r\n"):
            body = raw[:-2]
        elif raw.endswith(b"\n"):
            body = raw[:-1]
        else:
            raise KimiAcpProductError("wire_framing_rejected")
        if not body or b"\n" in body or b"\r" in body:
            raise KimiAcpProductError("wire_framing_rejected")
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise KimiAcpProductError("message_utf8_rejected") from None
        try:
            message = json.loads(
                text,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, _DuplicateJsonKey, TypeError, ValueError):
            raise KimiAcpProductError("invalid_json") from None
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise KimiAcpProductError("response_shape_rejected")
        return message

    def _validate_response(
        self,
        message: Mapping[str, Any],
        request_id: int,
    ) -> object:
        if _exact_keys(message, {"jsonrpc", "id", "result"}):
            self._validate_response_id(message.get("id"), request_id)
            return message["result"]
        if _exact_keys(message, {"jsonrpc", "id", "error"}):
            self._validate_response_id(message.get("id"), request_id)
            error = message.get("error")
            allowed_error_keys = (
                {"code", "message", "data"}
                if isinstance(error, dict) and "data" in error
                else {"code", "message"}
            )
            if (
                not isinstance(error, dict)
                or not _exact_keys(error, allowed_error_keys)
                or isinstance(error.get("code"), bool)
                or not isinstance(error.get("code"), int)
                or not -(2**31) <= error["code"] <= 2**31 - 1
                or not _is_bounded_utf8_text(
                    error.get("message"),
                    max_bytes=4096,
                )
            ):
                raise KimiAcpProductError("response_shape_rejected")
            if error["code"] == -32000:
                raise KimiAcpProductError("auth_required")
            raise KimiAcpProductError("agent_rpc_error")
        raise KimiAcpProductError("response_shape_rejected")

    @staticmethod
    def _validate_response_id(value: object, expected: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise KimiAcpProductError("response_id_rejected")

    def _handle_update(
        self,
        message: Mapping[str, Any],
        allowed_update_types: frozenset[str],
    ) -> None:
        if not _exact_keys(message, {"jsonrpc", "method", "params"}):
            raise KimiAcpProductError("response_shape_rejected")
        if message.get("method") != "session/update":
            raise KimiAcpProductError("unexpected_notification")
        params = message.get("params")
        if not isinstance(params, dict) or not _exact_keys(
            params, {"sessionId", "update"}
        ):
            raise KimiAcpProductError("update_shape_rejected")
        if params.get("sessionId") != self.session_id:
            raise KimiAcpProductError("session_binding_rejected")
        update = params.get("update")
        if not isinstance(update, dict):
            raise KimiAcpProductError("agent_message_rejected")
        update_type = update.get("sessionUpdate")
        if update_type in {"tool_call", "tool_call_update"}:
            raise KimiAcpProductError("tool_activity_rejected")
        if update_type not in allowed_update_types:
            raise KimiAcpProductError("update_type_rejected")
        if update_type in self.metadata_update_counts:
            self.metadata_update_counts[update_type] += 1
            if self.metadata_update_counts[update_type] > 1:
                raise KimiAcpProductError("metadata_update_rejected")
        if update_type == "config_option_update":
            self._handle_config_option_update(update)
            return
        if update_type == "available_commands_update":
            self._handle_available_commands_update(update)
            return
        if update_type == "agent_thought_chunk":
            self._handle_thought_chunk(update)
            return
        if update_type != "agent_message_chunk":
            raise KimiAcpProductError("update_type_rejected")
        allowed_without_id = {"sessionUpdate", "content"}
        allowed_with_id = {"sessionUpdate", "messageId", "content"}
        keys = set(update)
        if keys not in (allowed_without_id, allowed_with_id):
            raise KimiAcpProductError("agent_message_rejected")
        content = update.get("content")
        if (
            not isinstance(content, dict)
            or not _exact_keys(content, {"type", "text"})
            or content.get("type") != "text"
            or not isinstance(content.get("text"), str)
        ):
            raise KimiAcpProductError("agent_message_rejected")
        chunk = content["text"]
        try:
            size = len(chunk.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise KimiAcpProductError("agent_message_rejected") from None
        self.output_size += size
        if self.output_size > int(self.request.max_output_bytes):
            raise KimiAcpProductError("output_size_rejected")
        has_message_id = "messageId" in update
        if self.message_id_presence is None:
            self.message_id_presence = has_message_id
        elif self.message_id_presence != has_message_id:
            raise KimiAcpProductError("message_id_rejected")
        if has_message_id:
            message_id = update.get("messageId")
            if (
                not isinstance(message_id, str)
                or not _SESSION_PATTERN.fullmatch(message_id)
            ):
                raise KimiAcpProductError("message_id_rejected")
            if self.message_id is None:
                self.message_id = message_id
            elif self.message_id != message_id:
                raise KimiAcpProductError("message_id_rejected")
        self.chunks.append(chunk)

    def _handle_thought_chunk(
        self,
        update: Mapping[str, Any],
    ) -> None:
        if not _exact_keys(update, {"sessionUpdate", "content"}):
            raise KimiAcpProductError("agent_thought_rejected")
        content = update.get("content")
        if (
            not isinstance(content, dict)
            or not _exact_keys(content, {"type", "text"})
            or content.get("type") != "text"
            or not isinstance(content.get("text"), str)
        ):
            raise KimiAcpProductError("agent_thought_rejected")
        try:
            size = len(content["text"].encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise KimiAcpProductError("agent_thought_rejected") from None
        self.thought_size += size
        if self.thought_size > int(self.request.max_output_bytes):
            raise KimiAcpProductError("output_size_rejected")

    @staticmethod
    def _handle_available_commands_update(
        update: Mapping[str, Any],
    ) -> None:
        if not _exact_keys(
            update,
            {"sessionUpdate", "availableCommands"},
        ):
            raise KimiAcpProductError("available_commands_rejected")
        commands = update.get("availableCommands")
        if not isinstance(commands, list) or len(commands) > 256:
            raise KimiAcpProductError("available_commands_rejected")
        names: list[str] = []
        for command in commands:
            command_keys = (
                {"name", "description", "input"}
                if isinstance(command, dict) and "input" in command
                else {"name", "description"}
            )
            if (
                not isinstance(command, dict)
                or not _exact_keys(command, command_keys)
                or not _is_bounded_utf8_text(
                    command.get("name"),
                    max_bytes=256,
                )
                or not _is_bounded_utf8_text(
                    command.get("description"),
                    max_bytes=4096,
                )
            ):
                raise KimiAcpProductError("available_commands_rejected")
            command_input = command.get("input")
            if "input" in command and (
                not isinstance(command_input, dict)
                or not _exact_keys(command_input, {"hint"})
                or not _is_bounded_utf8_text(
                    command_input.get("hint"),
                    max_bytes=1024,
                )
            ):
                raise KimiAcpProductError("available_commands_rejected")
            names.append(command["name"])
        if len(names) != len(set(names)):
            raise KimiAcpProductError("available_commands_rejected")

    def _handle_config_option_update(
        self,
        update: Mapping[str, Any],
    ) -> None:
        if not _exact_keys(
            update,
            {"sessionUpdate", "configOptions"},
        ):
            raise KimiAcpProductError("model_confirmation_rejected")
        if self.created_options is None or self.model_option_id is None:
            raise KimiAcpProductError("model_confirmation_rejected")
        confirmed = _validate_model_options(
            update.get("configOptions"),
            self.request.requested_alias,
        )
        if (
            confirmed.get("id") != self.model_option_id
            or confirmed.get("currentValue") != self.request.requested_alias
            or _config_projection(
                update["configOptions"],
                model_option_id=self.model_option_id,
            )
            != _config_projection(
                self.created_options,
                model_option_id=self.model_option_id,
            )
        ):
            raise KimiAcpProductError("model_confirmation_rejected")

    def _reject_reverse_request(self, message: Mapping[str, Any]) -> None:
        if not _exact_keys(message, {"jsonrpc", "id", "method", "params"}):
            raise KimiAcpProductError("response_shape_rejected")
        request_id = message.get("id")
        if (
            isinstance(request_id, bool)
            or not isinstance(request_id, int)
            or not (0 <= request_id <= 2_147_483_647)
        ):
            raise KimiAcpProductError("reverse_request_shape_rejected")
        method = message.get("method")
        params = message.get("params")
        if (
            not isinstance(method, str)
            or not isinstance(params, dict)
            or params.get("sessionId") != self.session_id
        ):
            raise KimiAcpProductError("reverse_request_shape_rejected")
        if method == "session/request_permission":
            _validate_permission_params(
                params,
                session_id=str(self.session_id),
            )
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "cancelled"}},
                }
            )
            raise KimiAcpProductError("permission_request_rejected")
        self._write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": "Method not supported by this client",
                },
            }
        )
        raise KimiAcpProductError("reverse_method_rejected")


def _validate_initialize(result: object, bound_version: str) -> None:
    if not isinstance(result, dict) or not _exact_keys(
        result,
        {"protocolVersion", "agentCapabilities", "agentInfo", "authMethods"},
    ):
        raise KimiAcpProductError("agent_identity_rejected")
    agent_info = result.get("agentInfo")
    if (
        type(result.get("protocolVersion")) is not int
        or result.get("protocolVersion") != _PROTOCOL_VERSION
        or not isinstance(result.get("agentCapabilities"), dict)
        or not isinstance(result.get("authMethods"), list)
        or not isinstance(agent_info, dict)
        or not _exact_keys(agent_info, {"name", "version"})
        or agent_info.get("name") != "Kimi Code CLI"
        or agent_info.get("version") != bound_version
    ):
        raise KimiAcpProductError("agent_identity_rejected")


def _validate_model_options(
    value: object,
    requested_alias: str,
) -> dict[str, Any]:
    if not isinstance(value, list) or not (1 <= len(value) <= 64):
        raise KimiAcpProductError("model_selector_rejected")
    candidates: list[dict[str, Any]] = []
    option_ids: list[str] = []
    for option in value:
        if (
            not isinstance(option, dict)
            or not _exact_keys(
                option,
                {
                    "id",
                    "name",
                    "category",
                    "type",
                    "currentValue",
                    "options",
                },
            )
            or not isinstance(option.get("id"), str)
            or not _ALIAS_PATTERN.fullmatch(option["id"])
            or not isinstance(option.get("category"), str)
            or not _ALIAS_PATTERN.fullmatch(option["category"])
            or option.get("type") != "select"
            or not isinstance(option.get("name"), str)
            or not (1 <= len(option["name"]) <= 256)
            or not isinstance(option.get("currentValue"), str)
            or not _ALIAS_PATTERN.fullmatch(option["currentValue"])
            or (option["id"], option["category"]) not in _OPTION_PROFILES
        ):
            raise KimiAcpProductError("model_selector_rejected")
        option_ids.append(option["id"])
        choices = option.get("options")
        if not isinstance(choices, list) or not (1 <= len(choices) <= 256):
            raise KimiAcpProductError("model_selector_rejected")
        values: list[str] = []
        for choice in choices:
            choice_keys = (
                {"value", "name", "description"}
                if isinstance(choice, dict) and "description" in choice
                else {"value", "name"}
            )
            if (
                not isinstance(choice, dict)
                or not _exact_keys(choice, choice_keys)
                or not isinstance(choice.get("value"), str)
                or not _ALIAS_PATTERN.fullmatch(choice["value"])
                or not isinstance(choice.get("name"), str)
                or not (1 <= len(choice["name"]) <= 256)
                or (
                    "description" in choice
                    and (
                        not isinstance(choice.get("description"), str)
                        or not (1 <= len(choice["description"]) <= 1024)
                    )
                )
            ):
                raise KimiAcpProductError("model_selector_rejected")
            values.append(choice["value"])
        if (
            len(values) != len(set(values))
            or option["currentValue"] not in values
        ):
            raise KimiAcpProductError("model_selector_rejected")
        if (option["id"], option["category"]) == ("model", "model"):
            if values.count(requested_alias) != 1:
                raise KimiAcpProductError("model_selector_rejected")
            candidates.append(option)
    if len(option_ids) != len(set(option_ids)) or len(candidates) != 1:
        raise KimiAcpProductError("model_selector_rejected")
    return candidates[0]


def _config_projection(
    value: list[dict[str, Any]],
    *,
    model_option_id: str,
) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for option in value:
        if (
            option.get("id"),
            option.get("category"),
        ) == ("thinking", "thought_level"):
            continue
        projected = dict(option)
        if option.get("id") == model_option_id:
            projected.pop("currentValue", None)
        projection.append(projected)
    return projection


def _validate_permission_params(
    params: Mapping[str, Any],
    *,
    session_id: str,
) -> None:
    if not _exact_keys(params, {"sessionId", "toolCall", "options"}):
        raise KimiAcpProductError("reverse_request_shape_rejected")
    if params.get("sessionId") != session_id:
        raise KimiAcpProductError("reverse_request_shape_rejected")
    tool_call = params.get("toolCall")
    if (
        not isinstance(tool_call, dict)
        or not _exact_keys(tool_call, {"toolCallId"})
        or not isinstance(tool_call.get("toolCallId"), str)
        or not _SESSION_PATTERN.fullmatch(tool_call["toolCallId"])
    ):
        raise KimiAcpProductError("reverse_request_shape_rejected")
    options = params.get("options")
    if not isinstance(options, list) or not (1 <= len(options) <= 32):
        raise KimiAcpProductError("reverse_request_shape_rejected")
    option_ids: list[str] = []
    for option in options:
        if (
            not isinstance(option, dict)
            or not _exact_keys(option, {"optionId", "name", "kind"})
            or not isinstance(option.get("optionId"), str)
            or not _ALIAS_PATTERN.fullmatch(option["optionId"])
            or not isinstance(option.get("name"), str)
            or not (1 <= len(option["name"]) <= 256)
            or option.get("kind")
            not in {"allow_once", "allow_always", "reject_once", "reject_always"}
        ):
            raise KimiAcpProductError("reverse_request_shape_rejected")
        option_ids.append(option["optionId"])
    if len(option_ids) != len(set(option_ids)):
        raise KimiAcpProductError("reverse_request_shape_rejected")


def run_kimi_acp_product_protocol(
    request: KimiAcpProtocolRequest,
    channel: KimiAcpChannel,
) -> KimiAcpProtocolResult:
    """Run one closed text-only ACP transcript over an already isolated channel."""

    cwd = _validate_request(request)
    protocol = _Protocol(request, channel)
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
            "session/new",
            {"cwd": str(cwd), "mcpServers": []},
        )
        created = protocol.await_response(1)
        if not isinstance(created, dict) or not _exact_keys(
            created, {"sessionId", "configOptions"}
        ):
            raise KimiAcpProductError("session_rejected")
        session_id = created.get("sessionId")
        if (
            not isinstance(session_id, str)
            or not _SESSION_PATTERN.fullmatch(session_id)
        ):
            raise KimiAcpProductError("session_rejected")
        protocol.session_id = session_id
        model_option = _validate_model_options(
            created.get("configOptions"),
            request.requested_alias,
        )
        created_options = created["configOptions"]
        protocol.created_options = created_options
        protocol.model_option_id = str(model_option["id"])

        protocol.send_request(
            2,
            "session/set_config_option",
            {
                "sessionId": session_id,
                "configId": model_option["id"],
                "value": request.requested_alias,
            },
        )
        configured = protocol.await_response(
            2,
            allowed_update_types=frozenset(
                {"available_commands_update", "config_option_update"}
            ),
        )
        if not isinstance(configured, dict) or not _exact_keys(
            configured, {"configOptions"}
        ):
            raise KimiAcpProductError("model_confirmation_rejected")
        confirmed = _validate_model_options(
            configured.get("configOptions"),
            request.requested_alias,
        )
        if (
            confirmed.get("id") != model_option.get("id")
            or confirmed.get("currentValue") != request.requested_alias
            or _config_projection(
                configured["configOptions"],
                model_option_id=str(model_option["id"]),
            )
            != _config_projection(
                created_options,
                model_option_id=str(model_option["id"]),
            )
        ):
            raise KimiAcpProductError("model_confirmation_rejected")

        protocol.send_request(
            3,
            "session/prompt",
            {
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": request.prompt}],
            },
        )
        prompt_result = protocol.await_response(
            3,
            allowed_update_types=frozenset(
                {
                    "agent_message_chunk",
                    "agent_thought_chunk",
                    "available_commands_update",
                }
            ),
        )
        if not isinstance(prompt_result, dict) or not _exact_keys(
            prompt_result, {"stopReason"}
        ):
            raise KimiAcpProductError("stop_reason_rejected")
        stop_reason = prompt_result.get("stopReason")
        if stop_reason != "end_turn":
            raise KimiAcpProductError("stop_reason_rejected")
        protocol.close_input()
        protocol.drain_prompt_updates_to_eof(
            allowed_update_types=frozenset(
                {
                    "agent_message_chunk",
                    "agent_thought_chunk",
                    "available_commands_update",
                }
            )
        )
        text = protocol.output_text()
        return KimiAcpProtocolResult(
            text=text,
            session_id=session_id,
            stop_reason=stop_reason,
            requested_alias=request.requested_alias,
        )
    except BaseException:
        try:
            protocol.close_input()
        except KimiAcpProductError:
            pass
        raise


__all__ = [
    "KimiAcpChannel",
    "KimiAcpProductError",
    "KimiAcpProtocolRequest",
    "KimiAcpProtocolResult",
    "run_kimi_acp_product_protocol",
]
