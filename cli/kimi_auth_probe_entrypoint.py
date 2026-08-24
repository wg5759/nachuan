"""Contained, prompt-free ACP authentication probe for Kimi Code."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from cli.kimi_login_entrypoint import (
    _validated_environment,
    _validated_timeout,
)
from cli.kimi_worker_entrypoint import (
    KimiCliProcessError,
    _AcpPipeChannel,
    _PROCESS_CLEANUP_GRACE_SECONDS,
    _close_process_pipes,
    _close_windows_handle,
    _kill_contained_process_tree,
    _private_directory,
    _spawn_contained_process,
    _wait_contained_tree_empty,
)
from gateway.kimi_acp_auth_probe_protocol import (
    KimiAcpAuthProbeRequest,
    run_kimi_acp_auth_probe_protocol,
)
from gateway.kimi_acp_product_protocol import KimiAcpProductError
from gateway.kimi_subscription_login import (
    KimiAuthProbeResult,
    KimiLoginRequest,
    KimiSubscriptionLoginError,
)
from gateway.kimi_subscription_worker import KimiSubscriptionError


class KimiAuthProbeProcessRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
        bound_version: str,
    ) -> KimiAuthProbeResult: ...


def _validated_result(result: KimiAuthProbeResult) -> KimiAuthProbeResult:
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
    return result


def _run_acp_auth_probe_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    bound_version: str,
) -> KimiAuthProbeResult:
    process = None
    windows_job: int | None = None
    posix_group: int | None = None
    channel: _AcpPipeChannel | None = None
    try:
        process, windows_job, posix_group = _spawn_contained_process(
            argv,
            cwd=cwd,
            environment=environment,
        )
        channel = _AcpPipeChannel(
            process,
            deadline=time.monotonic() + timeout_seconds,
        )
        try:
            protocol_result = run_kimi_acp_auth_probe_protocol(
                KimiAcpAuthProbeRequest(bound_version=bound_version),
                channel,
            )
        except KimiAcpProductError:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            raise KimiSubscriptionLoginError(
                (
                    "auth_probe_timeout"
                    if channel.timed_out
                    else "auth_probe_protocol_rejected"
                ),
                process_exit_verified=verified,
            ) from None

        deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE_SECONDS
        if not _wait_contained_tree_empty(
            process,
            windows_job=windows_job,
            posix_group=posix_group,
            deadline=deadline,
        ):
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            raise KimiSubscriptionLoginError(
                "auth_probe_process_cleanup_unverified",
                process_exit_verified=verified,
            )
        channel.finish_readers(deadline)
        if channel.stderr_oversize:
            raise KimiSubscriptionLoginError("auth_probe_output_rejected")
        return KimiAuthProbeResult(
            token_present=protocol_result.token_present,
            returncode=int(process.returncode),
            timed_out=False,
            process_tree_exit_verified=True,
        )
    except KimiSubscriptionLoginError:
        raise
    except KimiCliProcessError as exc:
        raise KimiSubscriptionLoginError(
            "auth_probe_transport_failed",
            process_exit_verified=exc.cleanup_verified,
        ) from None
    except BaseException:
        verified = True
        if process is not None:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
        raise KimiSubscriptionLoginError(
            "auth_probe_transport_failed",
            process_exit_verified=verified,
        ) from None
    finally:
        if process is not None:
            _close_process_pipes(process)
        if windows_job is not None and not _close_windows_handle(windows_job):
            raise KimiSubscriptionLoginError(
                "auth_probe_process_cleanup_unverified",
                process_exit_verified=False,
            )


def run_kimi_auth_probe_request(
    request: KimiLoginRequest,
    *,
    environment: Mapping[str, str],
    process_runner: KimiAuthProbeProcessRunner | None = None,
) -> KimiAuthProbeResult:
    """Probe only the official ACP auth gate in an empty private directory."""

    if not isinstance(request, KimiLoginRequest):
        raise KimiSubscriptionLoginError("auth_probe_request_rejected")
    child_environment = _validated_environment(request, environment)
    timeout_seconds = _validated_timeout(request)
    runner = process_runner or _run_acp_auth_probe_process
    try:
        with _private_directory(
            prefix="nachuan-kimi-auth-probe-",
            environment=child_environment,
        ) as workdir:
            if not workdir.is_dir() or any(workdir.iterdir()):
                raise KimiSubscriptionLoginError(
                    "auth_probe_private_workdir_rejected"
                )
            result = runner(
                (request.executable_path, "acp"),
                cwd=workdir,
                environment=child_environment,
                timeout_seconds=timeout_seconds,
                bound_version=request.executable_version,
            )
    except KimiSubscriptionError as exc:
        raise KimiSubscriptionLoginError(
            "auth_probe_private_workdir_rejected",
            process_exit_verified=exc.process_exit_verified,
        ) from None
    return _validated_result(result)


__all__ = [
    "KimiAuthProbeProcessRunner",
    "run_kimi_auth_probe_request",
]
