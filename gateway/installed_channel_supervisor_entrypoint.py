"""Frozen installed-channel Supervisor entrypoint.

ICS-003 has frozen the verb, installation/config/anchor contracts, real Win32
suspended child-Job adapter, persistent stop/status stores and watchdog core.
The installer-owned anchor/bootstrap and production health probes are
deliberately not connected yet; default execution therefore remains
unavailable instead of spawning an unowned or partially configured tree.
"""

from __future__ import annotations

import math
import os
import secrets
import stat
import sys
import time
from pathlib import Path

from gateway.installed_channel_default_paths import (
    InstalledChannelDefaultPaths,
    resolve_installed_channel_default_paths,
)
from gateway.installed_channel_embedded_trust import (
    PRODUCTION_EMBEDDED_TRUST_SHA256,
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_file_lock import InstalledChannelFileLock
from gateway.installed_channel_installer_trust_acl import (
    InstalledChannelInstallerTrustAclError,
    assert_installed_runtime_principal,
    assert_installer_trust_boundary_acl,
    assert_installer_trust_public_file_acl,
)
from gateway.installed_channel_health_probe import (
    InstalledChannelHealthProbe,
    InstalledChannelRuntimeHealthAdapter,
)
from gateway.installed_channel_supervisor_bootstrap import (
    assemble_default_installed_supervisor_coordinator,
    load_default_installed_supervisor_authority,
)
from gateway.secure_store import assert_restricted_windows_acl
from gateway.windows_installed_process_manager import (
    WindowsInstalledProcessManager,
    current_windows_process_receipt,
)


_EXIT_UNAVAILABLE = 69
_EXIT_RUNTIME_FAILURE = 70
_EXIT_INTERRUPTED = 130


class InstalledChannelEntrypointError(RuntimeError):
    pass


def _assert_current_user_acl(path: Path, directory: bool) -> None:
    metadata = os.lstat(path)
    if directory != stat.S_ISDIR(metadata.st_mode):
        raise InstalledChannelEntrypointError("Supervisor ACL target is invalid")
    assert_restricted_windows_acl(path)


def _owner_lock(paths: InstalledChannelDefaultPaths):
    return InstalledChannelFileLock(
        paths.data_directory / "installed-channel-supervisor.owner.lock",
        error_type=InstalledChannelEntrypointError,
        busy_message="Supervisor owner is already active",
    )


def run_embedded_trust_gate(path, *, continuation) -> int:
    """Enter the remaining bootstrap only with one enabled embedded trust root."""

    if not callable(continuation):
        return _EXIT_RUNTIME_FAILURE
    try:
        trust = load_installed_channel_embedded_trust(path)
        trust.require_verifier()
    except Exception:
        return _EXIT_UNAVAILABLE
    try:
        result = continuation(trust)
    except Exception:
        return _EXIT_RUNTIME_FAILURE
    if isinstance(result, bool) or not isinstance(result, int) or not 0 <= result <= 255:
        return _EXIT_RUNTIME_FAILURE
    return result


def run_coordinator_loop(
    coordinator,
    *,
    stop_event=None,
    on_stopping=None,
    close_on_exit: bool = True,
    initial_transition=None,
    healthy_interval_seconds: float = 2.0,
    sleeper=time.sleep,
) -> int:
    """Run one coordinator until persistent Stop, external Stop, or failure."""

    interval = float(healthy_interval_seconds)
    if (
        not callable(getattr(coordinator, "step", None))
        or not callable(getattr(coordinator, "close", None))
        or not callable(sleeper)
        or type(close_on_exit) is not bool
        or (on_stopping is not None and not callable(on_stopping))
        or (
            stop_event is not None
            and (
                not callable(getattr(stop_event, "is_set", None))
                or not callable(getattr(stop_event, "wait", None))
            )
        )
        or not math.isfinite(interval)
        or not 0.1 <= interval <= 60.0
    ):
        return _EXIT_RUNTIME_FAILURE
    stopping_notified = False
    pending_transition = initial_transition

    def notify_stopping() -> None:
        nonlocal stopping_notified
        if stopping_notified:
            return
        stopping_notified = True
        if on_stopping is not None:
            on_stopping()

    result = _EXIT_RUNTIME_FAILURE
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                notify_stopping()
                result = 0
                break
            if pending_transition is None:
                transition = coordinator.step()
            else:
                transition, pending_transition = pending_transition, None
            if stop_event is not None and stop_event.is_set():
                notify_stopping()
                result = 0
                break
            watchdog = getattr(transition, "watchdog", None)
            action = getattr(watchdog, "action", None)
            retry_delay = getattr(watchdog, "retry_delay_seconds", None)
            if action == "stopped":
                if stop_event is None:
                    result = 0
                    break
                delay = interval
            elif action in {"retry_scheduled", "backoff"}:
                if (
                    isinstance(retry_delay, bool)
                    or not isinstance(retry_delay, (int, float))
                    or not math.isfinite(float(retry_delay))
                    or float(retry_delay) <= 0
                ):
                    result = _EXIT_RUNTIME_FAILURE
                    break
                delay = min(float(retry_delay), 60.0)
            elif action in {"started", "healthy"}:
                delay = interval
            else:
                result = _EXIT_RUNTIME_FAILURE
                break
            if stop_event is None:
                sleeper(delay)
            else:
                stopped = stop_event.wait(delay)
                if type(stopped) is not bool:
                    result = _EXIT_RUNTIME_FAILURE
                    break
                if stopped:
                    notify_stopping()
                    result = 0
                    break
    except KeyboardInterrupt:
        result = _EXIT_INTERRUPTED
    except BaseException:  # noqa: BLE001 - process tree must still be closed
        result = _EXIT_RUNTIME_FAILURE
    if close_on_exit:
        try:
            coordinator.close()
        except BaseException:  # noqa: BLE001 - close failure must not escape
            return _EXIT_RUNTIME_FAILURE
    return result


def run_default_installed_supervisor(
    *,
    paths: InstalledChannelDefaultPaths,
    expected_trust_sha256: str = PRODUCTION_EMBEDDED_TRUST_SHA256,
    installation_root_open=None,
    assert_installer_acl=None,
    assert_user_acl=_assert_current_user_acl,
    process_manager_factory=WindowsInstalledProcessManager,
    health_adapter_factory=None,
    supervisor_receipt_factory=current_windows_process_receipt,
    owner_lock_factory=None,
    engine_boot_token_factory=lambda: secrets.token_hex(32),
    loop_runner=run_coordinator_loop,
) -> int:
    """Run the fixed installed authority while holding one long-lived owner lock."""

    if (
        not isinstance(paths, InstalledChannelDefaultPaths)
        or (assert_installer_acl is not None and not callable(assert_installer_acl))
        or not callable(assert_user_acl)
        or not callable(process_manager_factory)
        or (health_adapter_factory is not None and not callable(health_adapter_factory))
        or not callable(supervisor_receipt_factory)
        or (owner_lock_factory is not None and not callable(owner_lock_factory))
        or not callable(engine_boot_token_factory)
        or not callable(loop_runner)
    ):
        return _EXIT_UNAVAILABLE
    try:
        if assert_installer_acl is None:
            runtime_sid = assert_installed_runtime_principal()

            def selected_installer_acl(path: Path, directory: bool) -> None:
                candidate = Path(os.path.abspath(os.fspath(path)))
                if directory and candidate == paths.installer_trust_root:
                    assert_installer_trust_boundary_acl(
                        program_data_boundary=paths.program_data_boundary,
                        installer_trust_boundary=paths.installer_trust_root,
                        runtime_sid=runtime_sid,
                    )
                    return
                if (
                    not directory
                    and candidate.parent == paths.installer_trust_root
                    and candidate
                    in {paths.host_signer_enrollment, paths.installer_anchor}
                ):
                    assert_installer_trust_public_file_acl(
                        candidate,
                        runtime_sid=runtime_sid,
                    )
                    return
                raise InstalledChannelInstallerTrustAclError(
                    "unexpected InstallerTrust ACL target"
                )

        else:
            selected_installer_acl = assert_installer_acl
        trust = load_installed_channel_embedded_trust(
            paths.embedded_trust,
            expected_sha256=expected_trust_sha256,
        )
        loader_kwargs = {}
        if installation_root_open is not None:
            if not callable(installation_root_open):
                return _EXIT_UNAVAILABLE
            loader_kwargs["installation_root_open"] = installation_root_open
        loaded = load_default_installed_supervisor_authority(
            paths=paths,
            trust=trust,
            assert_installer_acl=selected_installer_acl,
            assert_user_acl=assert_user_acl,
            **loader_kwargs,
        )
        token = engine_boot_token_factory()
        if not isinstance(token, str):
            return _EXIT_UNAVAILABLE
        receipt = supervisor_receipt_factory()
        if health_adapter_factory is None:
            probe = InstalledChannelHealthProbe(
                data_directory=paths.data_directory,
                engine_port=loaded.config.engine_port,
                engine_boot_token=token,
            )

            def selected_health_adapter_factory(manager):
                return InstalledChannelRuntimeHealthAdapter(
                    probe=probe,
                    process_manager=manager,
                )

        else:
            selected_health_adapter_factory = health_adapter_factory
        lock = (
            owner_lock_factory()
            if owner_lock_factory is not None
            else _owner_lock(paths)
        )
        if not callable(getattr(lock, "__enter__", None)) or not callable(
            getattr(lock, "__exit__", None)
        ):
            return _EXIT_UNAVAILABLE
        with lock:
            coordinator = assemble_default_installed_supervisor_coordinator(
                paths=paths,
                loaded_authority=loaded,
                engine_boot_token=token,
                process_manager_factory=process_manager_factory,
                health_adapter_factory=selected_health_adapter_factory,
                supervisor_receipt=receipt,
            )
            result = loop_runner(coordinator)
    except Exception:
        return _EXIT_UNAVAILABLE
    if isinstance(result, bool) or not isinstance(result, int) or not 0 <= result <= 255:
        return _EXIT_RUNTIME_FAILURE
    return result


def run() -> int:
    """Resolve the frozen layout and enter the installed authority."""

    try:
        if not bool(getattr(sys, "frozen", False)) or os.name != "nt":
            return _EXIT_UNAVAILABLE
        frozen_root = Path(str(getattr(sys, "_MEIPASS", ""))).resolve(strict=True)
        engine = Path(sys.executable).resolve(strict=True)
        paths = resolve_installed_channel_default_paths(
            engine_executable=engine,
            frozen_resource_root=frozen_root,
        )
    except Exception:
        return _EXIT_UNAVAILABLE
    return run_default_installed_supervisor(paths=paths)


__all__ = [
    "InstalledChannelEntrypointError",
    "run",
    "run_coordinator_loop",
    "run_default_installed_supervisor",
    "run_embedded_trust_gate",
]
