"""Secret-free controller contract for a user-owned Codex subscription.

The gateway never reads Codex's login store and never places a user prompt in a
process command line.  Process creation is delegated through ``CodexWorkerRunner``
so the concrete helper can live in a separately contained child process.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from gateway.providers.cli_env import sanitized_cli_env
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_STDOUT_BYTES = 4 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_EVENTS = 4096
_MAX_TEXT_BYTES = 4 * 1024 * 1024
_AUTHENTICATED_STATUS = "Logged in using ChatGPT"
_LOGGED_OUT_STATUS = "Not logged in"
_ALLOWED_EVENT_TYPES = frozenset(
    {
        "thread.started",
        "turn.started",
        "item.started",
        "item.updated",
        "item.completed",
        "turn.completed",
        "turn.failed",
        "error",
    }
)
_IGNORED_ITEM_TYPES = frozenset({"reasoning"})
_FORBIDDEN_ITEM_TYPES = frozenset(
    {
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "web_search",
        "todo_list",
        "error",
    }
)


class CodexSubscriptionError(RuntimeError):
    """Prompt-redacted, stable worker failure."""

    def __init__(self, code: str, *, process_exit_verified: bool = True) -> None:
        self.code = code
        self.process_exit_verified = process_exit_verified
        super().__init__(code)


@dataclass(frozen=True)
class CodexWorkerRequest:
    """Internal request.  Sensitive fields are deliberately absent from repr."""

    operation: Literal["status", "invoke", "logout"]
    executable_path: str = field(repr=False)
    executable_sha256: str = field(repr=False)
    prompt: str = field(default="", repr=False)
    timeout_seconds: float = 180.0

    def prompt_bytes(self) -> bytes:
        try:
            payload = self.prompt.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise CodexSubscriptionError("prompt_encoding_rejected") from None
        if self.operation == "invoke" and (
            not payload or len(payload) > _MAX_PROMPT_BYTES
        ):
            raise CodexSubscriptionError("prompt_size_rejected")
        if self.operation in {"status", "logout"} and payload:
            raise CodexSubscriptionError(f"{self.operation}_prompt_rejected")
        return payload


@dataclass(frozen=True)
class CodexWorkerResult:
    returncode: int
    stdout: str
    stderr: str
    process_tree_exit_verified: bool


class CodexWorkerRunner(Protocol):
    def __call__(self, request: CodexWorkerRequest) -> CodexWorkerResult: ...


@dataclass(frozen=True)
class CodexInvocation:
    text: str
    thread_id: str
    prompt_tokens: int
    cached_tokens: int
    completion_tokens: int


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def codex_worker_environment(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the shared secret-free CLI environment allowlist."""

    return sanitized_cli_env(source)


def _runner_environment(source: Mapping[str, str]) -> dict[str, str] | None:
    prepared = dict(source)
    raw_root = str(source.get("CODEX_CLI_TEMP_ROOT") or "").strip()
    if raw_root:
        root = Path(raw_root)
        try:
            if not root.is_absolute() or not root.is_dir():
                return None
            for component in reversed((root, *root.parents)):
                info = os.lstat(component)
                attributes = int(getattr(info, "st_file_attributes", 0))
                if component.is_symlink() or (
                    attributes
                    & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                ):
                    return None
            canonical = root.resolve(strict=True)
            if os.path.normcase(os.path.abspath(str(root))) != os.path.normcase(
                os.path.abspath(str(canonical))
            ):
                return None
        except OSError:
            return None
        prepared["TEMP"] = str(canonical)
        prepared["TMP"] = str(canonical)
    return codex_worker_environment(prepared)


def codex_cli_argv(
    request: CodexWorkerRequest,
    blank_workdir: str | Path,
) -> tuple[str, ...]:
    """Build the only accepted official CLI commands."""

    workdir = str(blank_workdir)
    if request.operation == "status":
        request.prompt_bytes()
        return (request.executable_path, "login", "status")
    if request.operation == "logout":
        request.prompt_bytes()
        return (request.executable_path, "logout")
    if request.operation != "invoke":
        raise CodexSubscriptionError("operation_rejected")
    request.prompt_bytes()
    return (
        request.executable_path,
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "-C",
        workdir,
        "-",
    )


def _bounded_output(result: CodexWorkerResult) -> tuple[str, str]:
    if not isinstance(result, CodexWorkerResult):
        raise CodexSubscriptionError("worker_result_rejected")
    if not result.process_tree_exit_verified:
        raise CodexSubscriptionError(
            "process_cleanup_unverified",
            process_exit_verified=False,
        )
    try:
        stdout_bytes = result.stdout.encode("utf-8", errors="strict")
        stderr_bytes = result.stderr.encode("utf-8", errors="strict")
    except (AttributeError, UnicodeEncodeError):
        raise CodexSubscriptionError("worker_output_rejected") from None
    if len(stdout_bytes) > _MAX_STDOUT_BYTES or len(stderr_bytes) > _MAX_STDERR_BYTES:
        raise CodexSubscriptionError("worker_output_rejected")
    if "\x00" in result.stdout or "\x00" in result.stderr:
        raise CodexSubscriptionError("worker_output_rejected")
    return result.stdout, result.stderr


def _reported_tokens(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CodexSubscriptionError("protocol_rejected")
    if value < 0 or value > (1 << 63) - 1:
        raise CodexSubscriptionError("protocol_rejected")
    return value


def _parse_item(item: object, messages: list[str]) -> None:
    if not isinstance(item, Mapping):
        raise CodexSubscriptionError("protocol_rejected")
    item_type = item.get("type")
    if item_type == "agent_message":
        text = item.get("text")
        if not isinstance(text, str) or not text:
            raise CodexSubscriptionError("protocol_rejected")
        try:
            if len(text.encode("utf-8", errors="strict")) > _MAX_TEXT_BYTES:
                raise CodexSubscriptionError("protocol_rejected")
        except UnicodeEncodeError:
            raise CodexSubscriptionError("protocol_rejected") from None
        messages.append(text)
        return
    if item_type in _IGNORED_ITEM_TYPES:
        return
    if item_type in _FORBIDDEN_ITEM_TYPES:
        raise CodexSubscriptionError("tool_activity_rejected")
    raise CodexSubscriptionError("protocol_rejected")


def _parse_jsonl(stdout: str) -> CodexInvocation:
    if not stdout or stdout.startswith("\ufeff"):
        raise CodexSubscriptionError("protocol_rejected")
    lines = stdout.splitlines()
    if not lines or len(lines) > _MAX_EVENTS or any(not line for line in lines):
        raise CodexSubscriptionError("protocol_rejected")

    thread_id: str | None = None
    thread_started = 0
    turn_started = 0
    turn_completed = 0
    messages: list[str] = []
    usage: tuple[int, int, int] | None = None
    terminal_seen = False

    for index, line in enumerate(lines):
        try:
            event = json.loads(line, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, TypeError, ValueError):
            raise CodexSubscriptionError("protocol_rejected") from None
        if not isinstance(event, dict):
            raise CodexSubscriptionError("protocol_rejected")
        event_type = event.get("type")
        if event_type not in _ALLOWED_EVENT_TYPES or terminal_seen:
            raise CodexSubscriptionError("protocol_rejected")

        if event_type == "thread.started":
            thread_started += 1
            candidate = event.get("thread_id")
            if (
                index != 0
                or thread_started != 1
                or not isinstance(candidate, str)
                or not candidate
                or len(candidate) > 256
            ):
                raise CodexSubscriptionError("protocol_rejected")
            thread_id = candidate
        elif event_type == "turn.started":
            turn_started += 1
            if thread_started != 1 or turn_started != 1:
                raise CodexSubscriptionError("protocol_rejected")
        elif event_type in {"item.started", "item.updated"}:
            if turn_started != 1 or turn_completed:
                raise CodexSubscriptionError("protocol_rejected")
            item = event.get("item")
            if not isinstance(item, Mapping):
                raise CodexSubscriptionError("protocol_rejected")
            item_type = item.get("type")
            if item_type in _FORBIDDEN_ITEM_TYPES:
                raise CodexSubscriptionError("tool_activity_rejected")
            if item_type not in _IGNORED_ITEM_TYPES | {"agent_message"}:
                raise CodexSubscriptionError("protocol_rejected")
        elif event_type == "item.completed":
            if turn_started != 1 or turn_completed:
                raise CodexSubscriptionError("protocol_rejected")
            _parse_item(event.get("item"), messages)
        elif event_type == "turn.completed":
            turn_completed += 1
            terminal_seen = True
            raw_usage = event.get("usage")
            if (
                turn_started != 1
                or turn_completed != 1
                or not isinstance(raw_usage, Mapping)
            ):
                raise CodexSubscriptionError("protocol_rejected")
            prompt_tokens = _reported_tokens(raw_usage.get("input_tokens"))
            cached_tokens = _reported_tokens(raw_usage.get("cached_input_tokens", 0))
            completion_tokens = _reported_tokens(raw_usage.get("output_tokens"))
            if cached_tokens > prompt_tokens:
                raise CodexSubscriptionError("protocol_rejected")
            usage = (prompt_tokens, cached_tokens, completion_tokens)
        else:
            # A failed/error terminal is never accepted as a successful answer.
            raise CodexSubscriptionError("protocol_rejected")

    if (
        thread_id is None
        or thread_started != 1
        or turn_started != 1
        or turn_completed != 1
        or usage is None
        or not messages
        or not terminal_seen
    ):
        raise CodexSubscriptionError("protocol_rejected")
    text = "\n".join(messages)
    if len(text.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise CodexSubscriptionError("protocol_rejected")
    return CodexInvocation(
        text=text,
        thread_id=thread_id,
        prompt_tokens=usage[0],
        cached_tokens=usage[1],
        completion_tokens=usage[2],
    )


def _default_runner(
    request: CodexWorkerRequest,
    source_environment: Mapping[str, str],
) -> CodexWorkerResult:
    # Imported lazily so the pure protocol tests never start a process.
    from cli.codex_worker_entrypoint import run_codex_worker_request

    return run_codex_worker_request(
        request,
        source_environment=source_environment,
    )


def _classify_status_result(stdout: str, stderr: str, returncode: int) -> str:
    """Map one official `codex login status` outcome to the closed state set."""

    clean_stdout = stdout.strip()
    clean_stderr = stderr.strip()
    if (
        returncode == 0
        and (
            (clean_stdout == _AUTHENTICATED_STATUS and not clean_stderr)
            or (clean_stderr == _AUTHENTICATED_STATUS and not clean_stdout)
        )
    ):
        return "authenticated_unprobed"
    if (
        returncode != 0
        and clean_stderr == _LOGGED_OUT_STATUS
        and not clean_stdout
    ):
        return "logged_out"
    return "unavailable"


class CodexSubscriptionWorker:
    """Attest the official CLI on every operation and parse only closed results."""

    def __init__(
        self,
        *,
        environment: Mapping[str, str],
        runner: CodexWorkerRunner | None = None,
    ) -> None:
        self._environment = dict(environment)
        self._runner_environment = _runner_environment(self._environment)
        self._runner: CodexWorkerRunner = runner or (
            lambda request: _default_runner(
                request,
                self._runner_environment or {},
            )
        )
        self._operation_lock = threading.Lock()

    def _attested_request(
        self,
        operation: Literal["status", "invoke", "logout"],
        *,
        prompt: str = "",
    ) -> CodexWorkerRequest | str:
        if self._runner_environment is None:
            return "unavailable"
        descriptor = SubscriptionCliDiscovery(
            environment=self._environment
        ).list_public()[0]
        state = str(descriptor.get("state") or "unavailable")
        if state != "installed_unprobed":
            return state
        path = str(self._environment.get("CODEX_CLI_PATH") or "").strip()
        digest = str(self._environment.get("CODEX_CLI_SHA256") or "").strip().lower()
        return CodexWorkerRequest(
            operation=operation,
            executable_path=path,
            executable_sha256=digest,
            prompt=prompt,
        )

    def probe_status(self) -> str:
        request = self._attested_request("status")
        if isinstance(request, str):
            return request
        try:
            with self._operation_lock:
                result = self._runner(request)
                stdout, stderr = _bounded_output(result)
        except Exception:
            return "unavailable"
        return _classify_status_result(stdout, stderr, result.returncode)

    def logout(self) -> str:
        """Run official ``codex logout``; trust only a post-logout status proof.

        A zero exit without an official ``logged_out`` status afterwards is
        never reported as success, and a failed logout process stays failed
        even when the credential state later reads as logged out.
        """

        request = self._attested_request("logout")
        if isinstance(request, str):
            raise CodexSubscriptionError(
                "binary_untrusted"
                if request == "untrusted_binary"
                else "worker_unavailable"
            )
        with self._operation_lock:
            result = self._runner(request)
            _bounded_output(result)
            status_request = self._attested_request("status")
            if isinstance(status_request, str):
                after = "unavailable"
            else:
                try:
                    status_result = self._runner(status_request)
                    status_stdout, status_stderr = _bounded_output(status_result)
                except CodexSubscriptionError:
                    raise
                except Exception:
                    after = "unavailable"
                else:
                    after = _classify_status_result(
                        status_stdout, status_stderr, status_result.returncode
                    )
        if result.returncode != 0:
            if after == "logged_out":
                raise CodexSubscriptionError("logout_process_failed_logged_out")
            raise CodexSubscriptionError("logout_failed")
        if after != "logged_out":
            raise CodexSubscriptionError("logout_unverified")
        return "logged_out"

    def invoke(self, prompt: str) -> CodexInvocation:
        if not isinstance(prompt, str):
            raise CodexSubscriptionError("prompt_encoding_rejected")
        try:
            prompt_bytes = prompt.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise CodexSubscriptionError("prompt_encoding_rejected") from None
        if not prompt_bytes or len(prompt_bytes) > _MAX_PROMPT_BYTES:
            raise CodexSubscriptionError("prompt_size_rejected")

        request = self._attested_request("invoke", prompt=prompt)
        if isinstance(request, str):
            raise CodexSubscriptionError(
                "binary_untrusted" if request == "untrusted_binary" else "worker_unavailable"
            )
        with self._operation_lock:
            result = self._runner(request)
        stdout, _stderr = _bounded_output(result)
        if result.returncode != 0:
            raise CodexSubscriptionError("cli_failed")
        return _parse_jsonl(stdout)


__all__ = [
    "CodexInvocation",
    "CodexSubscriptionError",
    "CodexSubscriptionWorker",
    "CodexWorkerRequest",
    "CodexWorkerResult",
    "CodexWorkerRunner",
    "codex_cli_argv",
    "codex_worker_environment",
]
