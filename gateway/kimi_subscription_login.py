"""Isolated login controller for a user-owned Kimi Code installation."""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from gateway.kimi_subscription_worker import (
    KimiSubscriptionError,
    kimi_worker_environment,
)
from gateway.providers.attested_cli import AttestedCliPinError, pin_attested_cli
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_CONNECTOR_ID = "kimi-code"
_SUCCESS_STATE = "authenticated_unprobed"
_PROTECTED_OVERLAY_FIELDS = frozenset(
    {
        "KIMI_CLI_PATH",
        "KIMI_CLI_SHA256",
        "KIMI_CLI_VERSION",
        "KIMI_CODE_HOME",
        "KIMI_CLI_TEMP_ROOT",
    }
)
_ACTIVE_CONFIG_NAMES = frozenset(
    {"agents.md", "mcp.json", "skills", "plugins"}
)
_SEMANTIC_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class KimiSubscriptionLoginError(RuntimeError):
    """Stable login failure that never includes vendor output or credentials."""

    def __init__(self, code: str, *, process_exit_verified: bool = True) -> None:
        self.code = code
        self.process_exit_verified = process_exit_verified
        super().__init__(code)


@dataclass(frozen=True)
class KimiLoginRequest:
    executable_path: str = field(repr=False)
    executable_sha256: str = field(repr=False)
    executable_version: str
    kimi_code_home: str = field(repr=False)
    timeout_seconds: float = 600.0


@dataclass(frozen=True)
class KimiLoginResult:
    returncode: int
    timed_out: bool
    cancelled: bool
    process_tree_exit_verified: bool


@dataclass(frozen=True)
class KimiAuthProbeResult:
    token_present: bool
    returncode: int
    timed_out: bool
    process_tree_exit_verified: bool


class KimiLoginRunner(Protocol):
    def __call__(
        self,
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiLoginResult: ...


class KimiAuthProbeRunner(Protocol):
    def __call__(
        self,
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiAuthProbeResult: ...


def _default_login_runner(
    request: KimiLoginRequest,
    *,
    environment: dict[str, str],
) -> KimiLoginResult:
    from cli.kimi_login_entrypoint import run_kimi_login_request

    return run_kimi_login_request(request, environment=environment)


def _default_auth_probe(
    request: KimiLoginRequest,
    *,
    environment: dict[str, str],
) -> KimiAuthProbeResult:
    from cli.kimi_auth_probe_entrypoint import run_kimi_auth_probe_request

    return run_kimi_auth_probe_request(request, environment=environment)


def kimi_login_argv(request: KimiLoginRequest) -> tuple[str, ...]:
    """Return the sole accepted vendor login command."""

    if not isinstance(request, KimiLoginRequest):
        raise KimiSubscriptionLoginError("login_request_rejected")
    if not Path(request.executable_path).is_absolute():
        raise KimiSubscriptionLoginError("login_request_rejected")
    return (request.executable_path, "login")


def _assert_no_active_config_surfaces(kimi_home: Path) -> None:
    try:
        entries = tuple(kimi_home.iterdir())
    except OSError:
        raise KimiSubscriptionLoginError(
            "active_config_surface_rejected"
        ) from None
    if any(entry.name.casefold() in _ACTIVE_CONFIG_NAMES for entry in entries):
        raise KimiSubscriptionLoginError("active_config_surface_rejected")


def _validated_login_result(result: KimiLoginResult) -> KimiLoginResult:
    if not isinstance(result, KimiLoginResult):
        raise KimiSubscriptionLoginError("login_result_rejected")
    if (
        not isinstance(result.process_tree_exit_verified, bool)
        or not isinstance(result.timed_out, bool)
        or not isinstance(result.cancelled, bool)
        or isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not -(1 << 31) <= result.returncode < (1 << 31)
        or (result.timed_out and result.cancelled)
    ):
        raise KimiSubscriptionLoginError("login_result_rejected")
    return result


def _closed_login_state(result: KimiLoginResult) -> str:
    result = _validated_login_result(result)
    if not result.process_tree_exit_verified:
        raise KimiSubscriptionLoginError(
            "process_cleanup_unverified",
            process_exit_verified=False,
        )
    if result.timed_out:
        raise KimiSubscriptionLoginError("login_timeout")
    if result.cancelled:
        raise KimiSubscriptionLoginError("login_cancelled")
    if result.returncode != 0:
        raise KimiSubscriptionLoginError("login_failed")
    return _SUCCESS_STATE


def _closed_auth_probe_state(result: KimiAuthProbeResult) -> str:
    if (
        not isinstance(result, KimiAuthProbeResult)
        or not isinstance(result.token_present, bool)
        or isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not -(1 << 31) <= result.returncode < (1 << 31)
        or not isinstance(result.timed_out, bool)
        or not isinstance(result.process_tree_exit_verified, bool)
    ):
        raise KimiSubscriptionLoginError("auth_probe_result_rejected")
    if not result.process_tree_exit_verified:
        raise KimiSubscriptionLoginError(
            "auth_probe_process_cleanup_unverified",
            process_exit_verified=False,
        )
    if result.timed_out:
        raise KimiSubscriptionLoginError("auth_probe_timeout")
    if result.returncode != 0:
        raise KimiSubscriptionLoginError("auth_probe_failed")
    return "authenticated_unprobed" if result.token_present else "login_required"


class KimiSubscriptionLoginController:
    """Run login only from a protected binding overlay and a supplied runner."""

    def __init__(
        self,
        *,
        protected_overlay: Mapping[str, str],
        runner: KimiLoginRunner | None = None,
        auth_probe: KimiAuthProbeRunner | None = None,
    ) -> None:
        if not isinstance(protected_overlay, Mapping):
            raise KimiSubscriptionLoginError("login_overlay_rejected")
        self._overlay = {
            key: str(protected_overlay.get(key) or "").strip()
            for key in _PROTECTED_OVERLAY_FIELDS
        }
        self._runner = runner or _default_login_runner
        self._auth_probe = auth_probe or _default_auth_probe
        self._operation_lock = threading.Lock()

    def _request_and_environment(
        self,
    ) -> tuple[KimiLoginRequest, dict[str, str]]:
        path = self._overlay["KIMI_CLI_PATH"]
        digest = self._overlay["KIMI_CLI_SHA256"].lower()
        version = self._overlay["KIMI_CLI_VERSION"]
        if (
            not path
            or not digest
            or not _SEMANTIC_VERSION.fullmatch(version)
            or not self._overlay["KIMI_CODE_HOME"]
            or not self._overlay["KIMI_CLI_TEMP_ROOT"]
        ):
            raise KimiSubscriptionLoginError("login_overlay_rejected")
        try:
            environment = kimi_worker_environment(self._overlay)
        except KimiSubscriptionError:
            raise KimiSubscriptionLoginError("login_overlay_rejected") from None
        kimi_home = Path(environment["KIMI_CODE_HOME"])
        _assert_no_active_config_surfaces(kimi_home)

        descriptor = next(
            (
                item
                for item in SubscriptionCliDiscovery(
                    environment=self._overlay
                ).list_public()
                if str(item.get("id") or "") == _CONNECTOR_ID
            ),
            None,
        )
        if descriptor is None:
            raise KimiSubscriptionLoginError("login_unavailable")
        state = str(descriptor.get("state") or "unavailable")
        if state != "installed_unprobed":
            raise KimiSubscriptionLoginError(
                "binary_untrusted"
                if state == "untrusted_binary"
                else "login_unavailable"
            )
        try:
            canonical_path = str(Path(path).resolve(strict=True))
        except OSError:
            raise KimiSubscriptionLoginError("binary_untrusted") from None
        return (
            KimiLoginRequest(
                executable_path=canonical_path,
                executable_sha256=digest,
                executable_version=version,
                kimi_code_home=str(kimi_home),
            ),
            environment,
        )

    def login(self) -> str:
        with self._operation_lock:
            request, environment = self._request_and_environment()
            kimi_login_argv(request)
            try:
                with pin_attested_cli(
                    request.executable_path,
                    request.executable_sha256,
                ):
                    before = _closed_auth_probe_state(
                        self._auth_probe(
                            request,
                            environment=environment,
                        )
                    )
                    result = self._runner(
                        request,
                        environment=environment,
                    )
                    result = _validated_login_result(result)
                    if (
                        not result.process_tree_exit_verified
                        or result.timed_out
                        or result.cancelled
                    ):
                        return _closed_login_state(result)
                    after = _closed_auth_probe_state(
                        self._auth_probe(
                            request,
                            environment=environment,
                        )
                    )
            except AttestedCliPinError:
                raise KimiSubscriptionLoginError("binary_untrusted") from None
        if result.returncode != 0:
            if (
                before == "login_required"
                and after == "authenticated_unprobed"
            ):
                raise KimiSubscriptionLoginError(
                    "login_process_failed_token_present"
                )
            raise KimiSubscriptionLoginError("login_failed")
        if after != "authenticated_unprobed":
            raise KimiSubscriptionLoginError("login_failed")
        return _SUCCESS_STATE

    def probe_status(self) -> str:
        with self._operation_lock:
            request, environment = self._request_and_environment()
            try:
                with pin_attested_cli(
                    request.executable_path,
                    request.executable_sha256,
                ):
                    result = self._auth_probe(
                        request,
                        environment=environment,
                    )
            except AttestedCliPinError:
                raise KimiSubscriptionLoginError("binary_untrusted") from None
        return _closed_auth_probe_state(result)


__all__ = [
    "KimiAuthProbeRunner",
    "KimiAuthProbeResult",
    "KimiLoginRequest",
    "KimiLoginResult",
    "KimiLoginRunner",
    "KimiSubscriptionLoginController",
    "KimiSubscriptionLoginError",
    "kimi_login_argv",
]
