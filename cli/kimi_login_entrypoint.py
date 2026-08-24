"""Contained interactive runner for the user-owned Kimi Code login command.

The vendor process inherits the caller's terminal handles so that the user can
complete the official login flow directly.  This module never reads, captures,
parses, or logs terminal output, device codes, or tokens.
"""

from __future__ import annotations

import math
import os
import subprocess
import time
from collections.abc import Mapping
from typing import Any

from cli.kimi_worker_entrypoint import (
    _assign_and_resume_windows_process,
    _close_windows_handle,
    _create_windows_kill_on_close_job,
    _kill_contained_process_tree,
    _wait_contained_tree_empty,
)
from gateway.kimi_subscription_login import (
    KimiLoginRequest,
    KimiLoginResult,
    KimiSubscriptionLoginError,
    kimi_login_argv,
)


_PROCESS_CLEANUP_GRACE_SECONDS = 2.0
_CANCELLATION_FLUSH_GRACE_SECONDS = 0.05
_STRICT_CHILD_ENV_FIELDS = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "KIMI_CLI_TEMP_ROOT",
        "TEMP",
        "TMP",
        "KIMI_CODE_HOME",
        "KIMI_DISABLE_TELEMETRY",
        "KIMI_CODE_NO_AUTO_UPDATE",
        "KIMI_DISABLE_CRON",
        "KIMI_CODE_BACKGROUND_KEEP_ALIVE_ON_EXIT",
        "KIMI_LOG_LEVEL",
        "NO_COLOR",
        "CI",
    }
)


def _validated_environment(
    request: KimiLoginRequest,
    environment: Mapping[str, str],
) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise KimiSubscriptionLoginError("login_environment_rejected")
    child = dict(environment)
    if set(child) != _STRICT_CHILD_ENV_FIELDS:
        raise KimiSubscriptionLoginError("login_environment_rejected")
    if any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or not value
        or "\x00" in key
        or "\x00" in value
        for key, value in child.items()
    ):
        raise KimiSubscriptionLoginError("login_environment_rejected")
    try:
        requested_home = os.path.normcase(
            os.path.abspath(request.kimi_code_home)
        )
        child_home = os.path.normcase(
            os.path.abspath(child["KIMI_CODE_HOME"])
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise KimiSubscriptionLoginError("login_environment_rejected") from None
    if requested_home != child_home:
        raise KimiSubscriptionLoginError("login_environment_rejected")
    return child


def _validated_timeout(request: KimiLoginRequest) -> float:
    value = request.timeout_seconds
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise KimiSubscriptionLoginError("login_request_rejected")
    return float(value)


def _validated_result(result: KimiLoginResult) -> KimiLoginResult:
    if (
        not isinstance(result, KimiLoginResult)
        or isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not -(1 << 31) <= result.returncode < (1 << 31)
        or not isinstance(result.timed_out, bool)
        or not isinstance(result.cancelled, bool)
        or not isinstance(result.process_tree_exit_verified, bool)
        or (result.timed_out and result.cancelled)
    ):
        raise KimiSubscriptionLoginError("login_result_rejected")
    return result


def _interrupted_returncode(process: Any, fallback: int) -> int:
    try:
        returncode = process.poll()
    except BaseException:
        return fallback
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or returncode == 0
    ):
        return fallback
    return returncode


def _contained_login_transport(
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: float,
) -> KimiLoginResult:
    """Run one terminal-inheriting login inside a whole-tree boundary."""

    windows_job: int | None = None
    posix_group: int | None = None
    process: Any = None
    try:
        try:
            if os.name == "nt":
                windows_job = _create_windows_kill_on_close_job()
                process = subprocess.Popen(
                    argv,
                    env=environment,
                    stdin=None,
                    stdout=None,
                    stderr=None,
                    creationflags=0x00000004,
                )
                _assign_and_resume_windows_process(windows_job, process.pid)
            else:
                process = subprocess.Popen(
                    argv,
                    env=environment,
                    stdin=None,
                    stdout=None,
                    stderr=None,
                    start_new_session=True,
                )
                posix_group = process.pid
        except BaseException:
            verified = process is None
            if process is not None:
                verified = _kill_contained_process_tree(
                    process,
                    windows_job=windows_job,
                    posix_group=posix_group,
                )
            raise KimiSubscriptionLoginError(
                "login_process_tree_setup_failed",
                process_exit_verified=verified,
            ) from None

        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            return KimiLoginResult(
                returncode=_interrupted_returncode(process, 124),
                timed_out=True,
                cancelled=False,
                process_tree_exit_verified=verified,
            )
        except (KeyboardInterrupt, GeneratorExit):
            # The job/process group is already active.  The bounded yield lets
            # a descendant finish an already-issued diagnostic write before
            # the complete tree is terminated and verified.
            try:
                if process.poll() is None:
                    time.sleep(_CANCELLATION_FLUSH_GRACE_SECONDS)
            except BaseException:
                pass
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            return KimiLoginResult(
                returncode=_interrupted_returncode(process, 130),
                timed_out=False,
                cancelled=True,
                process_tree_exit_verified=verified,
            )
        except BaseException:
            verified = _kill_contained_process_tree(
                process,
                windows_job=windows_job,
                posix_group=posix_group,
            )
            raise KimiSubscriptionLoginError(
                "login_transport_failed",
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
            return KimiLoginResult(
                returncode=returncode if returncode != 0 else 1,
                timed_out=False,
                cancelled=False,
                process_tree_exit_verified=verified,
            )
        return KimiLoginResult(
            returncode=returncode,
            timed_out=False,
            cancelled=False,
            process_tree_exit_verified=True,
        )
    finally:
        if windows_job is not None and not _close_windows_handle(windows_job):
            raise KimiSubscriptionLoginError(
                "process_cleanup_unverified",
                process_exit_verified=False,
            )


def run_kimi_login_request(
    request: KimiLoginRequest,
    *,
    environment: Mapping[str, str],
) -> KimiLoginResult:
    """Run the fixed official login command without observing auth material."""

    if not isinstance(request, KimiLoginRequest):
        raise KimiSubscriptionLoginError("login_request_rejected")
    argv = kimi_login_argv(request)
    timeout_seconds = _validated_timeout(request)
    child_environment = _validated_environment(request, environment)
    return _validated_result(
        _contained_login_transport(
            argv,
            environment=child_environment,
            timeout_seconds=timeout_seconds,
        )
    )


__all__ = ["run_kimi_login_request"]
