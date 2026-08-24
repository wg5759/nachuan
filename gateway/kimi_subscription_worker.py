"""Contained controller contract for a user-owned Kimi Code subscription.

The gateway supplies an explicitly bound native executable and a product-owned
Kimi data directory.  Prompts are represented only in the internal request and
are delivered to the future ACP helper over anonymous stdin, never argv.
"""

from __future__ import annotations

import os
import re
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from gateway.secure_store import trusted_windows_system_executable
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_CONNECTOR_ID = "kimi-code"
_PUBLIC_MODEL_ID = "kimi-code-subscription"
_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_TEXT_BYTES = 4 * 1024 * 1024
_MAX_SESSION_ID_BYTES = 1024
_BOUND_VERSION_PATTERN = re.compile(
    r"0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)
_ACTIVE_CONFIG_NAMES = frozenset(
    {"agents.md", "mcp.json", "skills", "plugins"}
)
_STABLE_FAILURE_CODES = frozenset(
    {
        "auth_required",
        "process_tree_rejected",
        "protocol_rejected",
    }
)


class KimiSubscriptionError(RuntimeError):
    """Stable, prompt-redacted controller failure."""

    def __init__(self, code: str, *, process_exit_verified: bool = True) -> None:
        self.code = code
        self.process_exit_verified = process_exit_verified
        super().__init__(code)


def is_stable_kimi_failure_code(value: object) -> bool:
    """Return whether ``value`` is a bounded product failure identifier."""

    return isinstance(value, str) and value in _STABLE_FAILURE_CODES


@dataclass(frozen=True)
class KimiWorkerRequest:
    """One internal ACP request with sensitive values absent from ``repr``."""

    operation: Literal["invoke"]
    executable_path: str = field(repr=False)
    executable_sha256: str = field(repr=False)
    bound_version: str
    prompt: str = field(repr=False)
    timeout_seconds: float = 180.0

    def prompt_bytes(self) -> bytes:
        try:
            payload = self.prompt.encode("utf-8", errors="strict")
        except (AttributeError, UnicodeEncodeError):
            raise KimiSubscriptionError("prompt_encoding_rejected") from None
        if (
            self.operation != "invoke"
            or not payload
            or len(payload) > _MAX_PROMPT_BYTES
        ):
            raise KimiSubscriptionError("prompt_size_rejected")
        return payload


@dataclass(frozen=True)
class KimiWorkerResult:
    """Closed result produced by the separately contained ACP helper."""

    returncode: int
    text: str
    session_id: str
    stop_reason: str
    actual_served_model: str | None
    tool_activity_observed: bool
    process_tree_exit_verified: bool
    failure_code: str | None = None


class KimiWorkerRunner(Protocol):
    def __call__(self, request: KimiWorkerRequest) -> KimiWorkerResult: ...


@dataclass(frozen=True)
class KimiInvocation:
    text: str
    session_id: str
    model_id: str
    actual_served_model: str | None


def _canonical_non_reparse_directory(raw: object) -> Path:
    value = str(raw or "").strip()
    candidate = Path(value)
    if not value or not candidate.is_absolute():
        raise KimiSubscriptionError("worker_environment_rejected")
    try:
        if not candidate.is_dir():
            raise OSError("directory is unavailable")
        for component in reversed((candidate, *candidate.parents)):
            metadata = os.lstat(component)
            attributes = int(getattr(metadata, "st_file_attributes", 0))
            if component.is_symlink() or (
                attributes
                & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            ):
                raise OSError("directory redirection rejected")
        canonical = candidate.resolve(strict=True)
        if os.path.normcase(os.path.abspath(str(candidate))) != os.path.normcase(
            os.path.abspath(str(canonical))
        ):
            raise OSError("directory identity rejected")
        return canonical
    except OSError:
        raise KimiSubscriptionError("worker_environment_rejected") from None


def _create_private_profile_directory(root: Path, relative: Path) -> Path:
    candidate = root / relative
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        canonical = _canonical_non_reparse_directory(candidate)
        canonical.relative_to(root)
        return canonical
    except (OSError, ValueError, KimiSubscriptionError):
        raise KimiSubscriptionError("worker_environment_rejected") from None


def kimi_worker_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Build a fixed, secret-free environment for the product ACP helper."""

    if not isinstance(source, Mapping):
        raise KimiSubscriptionError("worker_environment_rejected")
    temp_root = _canonical_non_reparse_directory(source.get("KIMI_CLI_TEMP_ROOT"))
    kimi_home = _canonical_non_reparse_directory(source.get("KIMI_CODE_HOME"))
    private_home = _create_private_profile_directory(temp_root, Path("os-home"))
    roaming = _create_private_profile_directory(
        temp_root,
        Path("os-home") / "AppData" / "Roaming",
    )
    local = _create_private_profile_directory(
        temp_root,
        Path("os-home") / "AppData" / "Local",
    )
    try:
        trusted_command_processor = trusted_windows_system_executable("cmd.exe")
        trusted_system32 = trusted_command_processor.parent.resolve(strict=True)
        system_root = trusted_system32.parent.resolve(strict=True)
        system32 = system_root / "System32"
        command_processor = system32 / "cmd.exe"
        if (
            os.path.normcase(os.path.abspath(str(command_processor)))
            != os.path.normcase(os.path.abspath(str(trusted_command_processor)))
        ):
            raise OSError("trusted command processor identity rejected")
    except (OSError, RuntimeError):
        raise KimiSubscriptionError("worker_environment_rejected") from None
    system_drive = system_root.drive
    if not system_drive:
        raise KimiSubscriptionError("worker_environment_rejected")

    return {
        "SYSTEMROOT": str(system_root),
        "WINDIR": str(system_root),
        "SYSTEMDRIVE": system_drive,
        "COMSPEC": str(command_processor),
        "PATH": str(system32),
        "PATHEXT": ".COM;.EXE",
        "HOME": str(private_home),
        "USERPROFILE": str(private_home),
        "APPDATA": str(roaming),
        "LOCALAPPDATA": str(local),
        "KIMI_CLI_TEMP_ROOT": str(temp_root),
        "TEMP": str(temp_root),
        "TMP": str(temp_root),
        "KIMI_CODE_HOME": str(kimi_home),
        "KIMI_DISABLE_TELEMETRY": "1",
        "KIMI_CODE_NO_AUTO_UPDATE": "1",
        "KIMI_DISABLE_CRON": "1",
        "KIMI_CODE_BACKGROUND_KEEP_ALIVE_ON_EXIT": "0",
        "KIMI_LOG_LEVEL": "off",
        "NO_COLOR": "1",
        "CI": "1",
    }


def kimi_cli_argv(request: KimiWorkerRequest) -> tuple[str, ...]:
    """Return the only accepted product CLI command."""

    if not isinstance(request, KimiWorkerRequest) or request.operation != "invoke":
        raise KimiSubscriptionError("operation_rejected")
    request.prompt_bytes()
    return (request.executable_path, "acp")


def _default_runner(
    request: KimiWorkerRequest,
    source_environment: Mapping[str, str],
    *,
    cancellation_event: threading.Event | None = None,
) -> KimiWorkerResult:
    # Imported lazily so controller and protocol tests never start a process.
    from cli.kimi_worker_entrypoint import run_kimi_worker_request

    return run_kimi_worker_request(
        request,
        source_environment=source_environment,
        cancellation_event=cancellation_event,
    )


def _assert_no_active_config_surfaces(kimi_home: Path) -> None:
    try:
        current_home = _canonical_non_reparse_directory(kimi_home)
        entries = tuple(current_home.iterdir())
    except (OSError, KimiSubscriptionError):
        raise KimiSubscriptionError("active_config_surface_rejected") from None
    if any(entry.name.casefold() in _ACTIVE_CONFIG_NAMES for entry in entries):
        raise KimiSubscriptionError("active_config_surface_rejected")


def _closed_invocation(result: KimiWorkerResult) -> KimiInvocation:
    if not isinstance(result, KimiWorkerResult):
        raise KimiSubscriptionError("worker_result_rejected")
    if not isinstance(result.process_tree_exit_verified, bool):
        raise KimiSubscriptionError("worker_result_rejected")
    if not result.process_tree_exit_verified:
        raise KimiSubscriptionError(
            "process_cleanup_unverified",
            process_exit_verified=False,
        )
    if (
        isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not -(1 << 31) <= result.returncode < (1 << 31)
    ):
        raise KimiSubscriptionError("worker_result_rejected")
    if (
        result.failure_code is not None
        and not is_stable_kimi_failure_code(result.failure_code)
    ):
        raise KimiSubscriptionError("worker_result_rejected")
    if result.returncode == 0 and result.failure_code is not None:
        raise KimiSubscriptionError("worker_result_rejected")
    if result.returncode != 0:
        raise KimiSubscriptionError(result.failure_code or "cli_failed")
    if result.stop_reason != "end_turn":
        raise KimiSubscriptionError("stop_reason_rejected")
    if result.actual_served_model is not None:
        raise KimiSubscriptionError("served_model_receipt_unverified")
    if not isinstance(result.tool_activity_observed, bool):
        raise KimiSubscriptionError("worker_result_rejected")
    if result.tool_activity_observed:
        raise KimiSubscriptionError("tool_activity_rejected")
    if not isinstance(result.text, str) or not isinstance(result.session_id, str):
        raise KimiSubscriptionError("protocol_rejected")
    try:
        text_bytes = result.text.encode("utf-8", errors="strict")
        session_bytes = result.session_id.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise KimiSubscriptionError("protocol_rejected") from None
    if (
        not text_bytes
        or len(text_bytes) > _MAX_TEXT_BYTES
        or "\x00" in result.text
        or result.text.startswith("\ufeff")
        or not session_bytes
        or len(session_bytes) > _MAX_SESSION_ID_BYTES
        or "\x00" in result.session_id
        or result.session_id.startswith("\ufeff")
    ):
        raise KimiSubscriptionError("protocol_rejected")
    return KimiInvocation(
        text=result.text,
        session_id=result.session_id,
        model_id=_PUBLIC_MODEL_ID,
        actual_served_model=None,
    )


class KimiSubscriptionWorker:
    """Re-attest the bound Kimi CLI and accept only closed text results."""

    def __init__(
        self,
        *,
        environment: Mapping[str, str],
        runner: KimiWorkerRunner | None = None,
    ) -> None:
        self._environment = dict(environment)
        self._custom_runner = runner
        self._operation_lock = threading.Lock()

    def _attested_request(self, prompt: str) -> tuple[KimiWorkerRequest, dict[str, str]]:
        try:
            runner_environment = kimi_worker_environment(self._environment)
        except KimiSubscriptionError:
            raise KimiSubscriptionError("worker_unavailable") from None
        bound_version = str(
            self._environment.get("KIMI_CLI_VERSION") or ""
        ).strip()
        if not _BOUND_VERSION_PATTERN.fullmatch(bound_version):
            raise KimiSubscriptionError("binding_version_rejected")
        kimi_home = Path(runner_environment["KIMI_CODE_HOME"])
        _assert_no_active_config_surfaces(kimi_home)

        descriptors = SubscriptionCliDiscovery(
            environment=self._environment
        ).list_public()
        descriptor = next(
            (
                item
                for item in descriptors
                if str(item.get("id") or "") == _CONNECTOR_ID
            ),
            None,
        )
        if descriptor is None:
            raise KimiSubscriptionError("worker_unavailable")
        state = str(descriptor.get("state") or "unavailable")
        if state != "installed_unprobed":
            raise KimiSubscriptionError(
                "binary_untrusted"
                if state == "untrusted_binary"
                else "worker_unavailable"
            )
        request = KimiWorkerRequest(
            operation="invoke",
            executable_path=str(self._environment.get("KIMI_CLI_PATH") or "").strip(),
            executable_sha256=str(
                self._environment.get("KIMI_CLI_SHA256") or ""
            ).strip().lower(),
            bound_version=bound_version,
            prompt=prompt,
        )
        request.prompt_bytes()
        return request, runner_environment

    def invoke(
        self,
        prompt: str,
        *,
        cancellation_event: threading.Event | None = None,
    ) -> KimiInvocation:
        if not isinstance(prompt, str):
            raise KimiSubscriptionError("prompt_encoding_rejected")
        try:
            prompt_bytes = prompt.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise KimiSubscriptionError("prompt_encoding_rejected") from None
        if not prompt_bytes or len(prompt_bytes) > _MAX_PROMPT_BYTES:
            raise KimiSubscriptionError("prompt_size_rejected")

        with self._operation_lock:
            request, runner_environment = self._attested_request(prompt)
            if self._custom_runner is None:
                result = _default_runner(
                    request,
                    runner_environment,
                    cancellation_event=cancellation_event,
                )
            else:
                result = self._custom_runner(request)
        return _closed_invocation(result)


__all__ = [
    "KimiInvocation",
    "KimiSubscriptionError",
    "KimiSubscriptionWorker",
    "KimiWorkerRequest",
    "KimiWorkerResult",
    "KimiWorkerRunner",
    "is_stable_kimi_failure_code",
    "kimi_cli_argv",
    "kimi_worker_environment",
]
