"""Closed launch contracts for an installer-owned channel supervisor.

This module only builds validated child launch descriptions.  It does not
register a task, start a service, or spawn processes; those persistent actions
remain installer-controlled.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from gateway.installed_channel_config import InstalledChannelSupervisorConfig
from gateway.installation_root import (
    InstallationRootSnapshot,
    installation_principal,
)


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_APP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_DRAIN_PROTOCOL_TIMEOUT_MS = 24_000
_NATURAL_EXIT_TIMEOUT_MS = 4_000
_SAFE_OS_ENVIRONMENT = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
        "HOME",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
)


class InstalledChannelSupervisorContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class InstalledChildLaunch:
    command: str
    args: tuple[str, ...]
    cwd: str
    environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class InstalledChannelSupervisorState:
    pids: Mapping[str, int]
    ready: bool
    start_allowed: bool = True
    proofs: Mapping[str, object] = field(default_factory=dict)


class InstalledChannelSupervisorRuntime:
    """Start one prevalidated three-role tree under an external Job owner."""

    def __init__(
        self,
        *,
        launches,
        process_manager,
        health_probe,
        drain_controller_factory=None,
    ) -> None:
        if (
            not isinstance(launches, dict)
            or tuple(launches) != ("engine", "weixin", "feishu")
            or any(not isinstance(value, InstalledChildLaunch) for value in launches.values())
        ):
            raise InstalledChannelSupervisorContractError("installed launches are invalid")
        for method in (
            "spawn_suspended",
            "assign_to_job",
            "resume",
            "terminate_job",
        ):
            if not callable(getattr(process_manager, method, None)):
                raise InstalledChannelSupervisorContractError(
                    "installed process manager is invalid"
                )
        if not callable(health_probe):
            raise InstalledChannelSupervisorContractError("health probe is invalid")
        if drain_controller_factory is not None:
            if not callable(drain_controller_factory):
                raise InstalledChannelSupervisorContractError(
                    "installed drain controller factory is invalid"
                )
            for method in (
                "process_receipt",
                "wait_for_quiescence",
                "close_quiescent",
                "force_close",
                "is_quiescent",
            ):
                if not callable(getattr(process_manager, method, None)):
                    raise InstalledChannelSupervisorContractError(
                        "installed graceful process manager is invalid"
                    )
        self._launches = dict(launches)
        self._manager = process_manager
        self._health_probe = health_probe
        self._drain_controller_factory = drain_controller_factory
        self._processes: dict[str, object] = {}
        self._proofs: dict[str, object] = {}
        self._started = False
        self._closed = False
        self._grace_in_progress = False
        self._lifecycle_lock = threading.RLock()

    @staticmethod
    def _external_stop_requested(stop_event) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if not callable(checker):
            raise InstalledChannelSupervisorContractError(
                "external stop event is invalid"
            )
        stopped = checker()
        if type(stopped) is not bool:
            raise InstalledChannelSupervisorContractError(
                "external stop event is invalid"
            )
        return stopped

    def _require_external_run(self, stop_event) -> None:
        if self._external_stop_requested(stop_event):
            raise InstalledChannelSupervisorContractError(
                "external stop interrupted installed startup"
            )

    def _start_role(self, role: str, *, stop_event=None) -> int:
        try:
            self._require_external_run(stop_event)
            process = self._manager.spawn_suspended(role, self._launches[role])
            self._require_external_run(stop_event)
            pid = getattr(process, "pid", None)
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                raise RuntimeError("invalid process identity")
            self._manager.assign_to_job(role, process)
            self._require_external_run(stop_event)
            self._manager.resume(role, process)
            self._require_external_run(stop_event)
            proof = self._health_probe(role, process)
            self._require_external_run(stop_event)
            if proof is True:
                pass
            elif (
                getattr(proof, "role", None) == role
                and getattr(proof, "pid", None) == pid
                and type(getattr(proof, "attested", None)) is bool
                and type(getattr(proof, "start_allowed", None)) is bool
                and type(getattr(proof, "ready", None)) is bool
                and type(getattr(proof, "restart_recommended", None)) is bool
            ):
                if not proof.start_allowed:
                    raise RuntimeError("health proof unavailable")
                self._proofs[role] = proof
            else:
                raise RuntimeError("health proof unavailable")
            self._processes[role] = process
            return pid
        except Exception:
            raise InstalledChannelSupervisorContractError(
                f"installed {role} startup failed"
            ) from None

    def start(self, *, stop_event=None) -> InstalledChannelSupervisorState:
        if self._closed or self._started:
            raise InstalledChannelSupervisorContractError(
                "installed supervisor state is invalid"
            )
        pids: dict[str, int] = {}
        try:
            pids["engine"] = self._start_role("engine", stop_event=stop_event)
            pids["weixin"] = self._start_role("weixin", stop_event=stop_event)
            pids["feishu"] = self._start_role("feishu", stop_event=stop_event)
        except Exception:
            try:
                self._manager.terminate_job()
            finally:
                self._closed = True
            raise
        self._started = True
        start_allowed = all(
            bool(getattr(self._proofs.get(role), "start_allowed", True))
            for role in ("engine", "weixin", "feishu")
        )
        ready = all(
            bool(getattr(self._proofs.get(role), "ready", True))
            for role in ("engine", "weixin", "feishu")
        )
        return InstalledChannelSupervisorState(
            pids=MappingProxyType(pids),
            ready=ready,
            start_allowed=start_allowed,
            proofs=MappingProxyType(dict(self._proofs)),
        )

    def process_receipts(self) -> Mapping[str, object]:
        """Return identity receipts bound to the exact started child objects."""

        if self._closed or not self._started or tuple(self._processes) != (
            "engine",
            "weixin",
            "feishu",
        ):
            raise InstalledChannelSupervisorContractError(
                "installed supervisor state is invalid"
            )
        reader = getattr(self._manager, "process_receipt", None)
        if not callable(reader):
            raise InstalledChannelSupervisorContractError(
                "installed process identity reader is unavailable"
            )
        receipts: dict[str, object] = {}
        for role, process in self._processes.items():
            try:
                receipt = reader(role, process)
                pid = getattr(receipt, "pid", None)
                started = getattr(receipt, "started_utc_ticks", None)
                digest = getattr(receipt, "command_line_sha256", None)
                if (
                    isinstance(pid, bool)
                    or not isinstance(pid, int)
                    or pid != getattr(process, "pid", None)
                    or isinstance(started, bool)
                    or not isinstance(started, int)
                    or started <= 0
                    or not isinstance(digest, str)
                    or _HEX64.fullmatch(digest) is None
                ):
                    raise RuntimeError("invalid process receipt")
            except Exception:
                raise InstalledChannelSupervisorContractError(
                    f"installed {role} process identity is unavailable"
                ) from None
            receipts[role] = receipt
        return MappingProxyType(receipts)

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            if self._grace_in_progress:
                raise InstalledChannelSupervisorContractError(
                    "installed process tree graceful close is already running"
                )
            self._grace_in_progress = True
        try:
            if self._drain_controller_factory is None:
                self._manager.terminate_job()
            else:
                from gateway.installed_channel_drain import (
                    InstalledDrainOperation,
                    InstalledDrainSummary,
                )

                receipts = self.process_receipts()
                controller = self._drain_controller_factory(receipts)
                drain = getattr(controller, "drain", None)
                expected_operation = getattr(controller, "operation", None)
                if (
                    not callable(drain)
                    or not isinstance(expected_operation, InstalledDrainOperation)
                    or expected_operation.deadline_utc_ns <= time.time_ns()
                ):
                    raise RuntimeError("drain controller is invalid")
                summary = drain(timeout_ms=_DRAIN_PROTOCOL_TIMEOUT_MS)
                expected_actions = (
                    "weixin:close_claims",
                    "feishu:close_claims",
                    "engine:close_admission",
                    "weixin:exit",
                    "feishu:exit",
                    "engine:exit",
                )
                if (
                    not isinstance(summary, InstalledDrainSummary)
                    or summary.operation != expected_operation
                    or not summary.business_drained
                    or not summary.exit_acknowledged
                    or summary.action_sequence != expected_actions
                    or set(summary.role_receipts) != set(receipts)
                    or any(
                        summary.role_receipts[role].process != receipts[role]
                        or summary.role_receipts[role].operation != expected_operation
                        or summary.role_receipts[role].phase != "exit_requested"
                        or summary.role_receipts[role].provider_open_calls != 0
                        or summary.role_receipts[role].unknown_unpersisted != 0
                        or summary.role_receipts[role].active_claims != 0
                        or summary.role_receipts[role].active_requests != 0
                        or summary.role_receipts[role].active_background_jobs != 0
                        for role in receipts
                    )
                    or summary.submitted_unknown
                    != sum(
                        receipt.submitted_unknown
                        for receipt in summary.role_receipts.values()
                    )
                ):
                    raise RuntimeError("drain receipt is invalid")
                quiescent = self._manager.wait_for_quiescence(
                    timeout_ms=_NATURAL_EXIT_TIMEOUT_MS
                )
                if type(quiescent) is not bool or not quiescent:
                    raise RuntimeError("process tree did not exit naturally")
                if self._manager.close_quiescent() is not None:
                    raise RuntimeError("process tree close receipt is invalid")
        except Exception:
            raise InstalledChannelSupervisorContractError(
                "installed process tree graceful close failed"
            ) from None
        else:
            with self._lifecycle_lock:
                self._closed = True
                self._processes.clear()
                self._proofs.clear()
        finally:
            with self._lifecycle_lock:
                self._grace_in_progress = False

    def force_close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return None
        force = getattr(self._manager, "force_close", None)
        if not callable(force) or force() is not None:
            raise InstalledChannelSupervisorContractError(
                "installed process tree force close failed"
            )
        with self._lifecycle_lock:
            self._closed = True
            self._processes.clear()
            self._proofs.clear()
        return None

    def is_quiescent(self) -> bool:
        probe = getattr(self._manager, "is_quiescent", None)
        if not callable(probe):
            raise InstalledChannelSupervisorContractError(
                "installed process tree quiescence is unavailable"
            )
        quiescent = probe()
        if type(quiescent) is not bool:
            raise InstalledChannelSupervisorContractError(
                "installed process tree quiescence is invalid"
            )
        return quiescent


@dataclass(frozen=True, slots=True)
class InstalledChannelEpochAnchor:
    installation_id: str
    installation_epoch: int
    installation_principal: str
    config_generation: int

    def __post_init__(self) -> None:
        if _HEX64.fullmatch(str(self.installation_id or "")) is None:
            raise InstalledChannelSupervisorContractError(
                "installation anchor id is invalid"
            )
        if (
            isinstance(self.installation_epoch, bool)
            or not isinstance(self.installation_epoch, int)
            or self.installation_epoch < 1
            or isinstance(self.config_generation, bool)
            or not isinstance(self.config_generation, int)
            or self.config_generation < 1
        ):
            raise InstalledChannelSupervisorContractError(
                "installation anchor generation is invalid"
            )
        expected = installation_principal(
            self.installation_id, self.installation_epoch
        )
        if not hmac.compare_digest(
            str(self.installation_principal or ""), expected
        ):
            raise InstalledChannelSupervisorContractError(
                "installation anchor principal is invalid"
            )

    @classmethod
    def from_snapshot(
        cls,
        snapshot: InstallationRootSnapshot,
        *,
        config_generation: int,
    ) -> "InstalledChannelEpochAnchor":
        if (
            not isinstance(snapshot, InstallationRootSnapshot)
            or snapshot.status != "active"
            or snapshot.reanchor_pending
            or snapshot.lock_kind != "none"
        ):
            raise InstalledChannelSupervisorContractError(
                "installation snapshot is not active"
            )
        return cls(
            installation_id=snapshot.installation_id,
            installation_epoch=snapshot.epoch,
            installation_principal=snapshot.principal_digest,
            config_generation=config_generation,
        )

    def validate(
        self,
        *,
        snapshot: InstallationRootSnapshot,
        config: InstalledChannelSupervisorConfig,
    ) -> None:
        if not isinstance(snapshot, InstallationRootSnapshot):
            raise InstalledChannelSupervisorContractError(
                "installation snapshot is invalid"
            )
        active = InstalledChannelEpochAnchor.from_snapshot(
            snapshot,
            config_generation=config.generation,
        )
        if (
            self.installation_id != active.installation_id
            or self.installation_epoch != active.installation_epoch
            or not hmac.compare_digest(
                self.installation_principal, active.installation_principal
            )
        ):
            raise InstalledChannelSupervisorContractError(
                "installation epoch anchor differs from active installation"
            )
        if self.config_generation != config.generation:
            raise InstalledChannelSupervisorContractError(
                "configuration generation differs from installation anchor"
            )


def _nonreparse(info: os.stat_result) -> bool:
    return not (int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE)


def _absolute_path(value: str | os.PathLike[str], field: str) -> Path:
    path = Path(os.path.abspath(os.fspath(value)))
    if not Path(value).is_absolute() or ".." in Path(value).parts:
        raise InstalledChannelSupervisorContractError(f"{field} is invalid")
    return path


def _regular_file(
    value: str | os.PathLike[str],
    field: str,
    *,
    exact_name: str | None = None,
) -> Path:
    path = _absolute_path(value, field)
    if exact_name is not None and path.name.casefold() != exact_name.casefold():
        raise InstalledChannelSupervisorContractError(f"{field} is invalid")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise InstalledChannelSupervisorContractError(f"{field} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or not _nonreparse(info):
        raise InstalledChannelSupervisorContractError(f"{field} is invalid")
    return path.resolve(strict=True)


def _directory(value: str | os.PathLike[str], field: str) -> Path:
    path = _absolute_path(value, field)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise InstalledChannelSupervisorContractError(f"{field} is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or not _nonreparse(info):
        raise InstalledChannelSupervisorContractError(f"{field} is invalid")
    return path.resolve(strict=True)


def _secret(value: object, pattern: str, field: str) -> str:
    rendered = str(value or "")
    if re.fullmatch(pattern, rendered) is None:
        raise InstalledChannelSupervisorContractError(f"{field} is invalid")
    return rendered


def _closed_environment(source: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_name, raw_value in (source or {}).items():
        name = str(raw_name).upper()
        if name in _SAFE_OS_ENVIRONMENT and raw_value is not None:
            result[name] = str(raw_value)
    return result


def build_installed_channel_launches(
    *,
    engine_executable: str | os.PathLike[str],
    data_directory: str | os.PathLike[str],
    connections_path: str | os.PathLike[str],
    engine_port: int,
    engine_generation: int,
    engine_boot_token: str,
    runtime_key: str,
    approval_key: str,
    paid_media_key: str,
    weixin_bridge_key: str,
    feishu_bridge_key: str,
    feishu_app_id: str,
    feishu_app_secret: str,
    runtime_profile_manifest: str | os.PathLike[str],
    runtime_profile_sha256: str,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, InstalledChildLaunch]:
    """Return one three-role plan with no ambient credential inheritance."""

    engine = _regular_file(engine_executable, "engine executable", exact_name="engine.exe")
    data = _directory(data_directory, "data directory")
    vault = _regular_file(connections_path, "connection vault", exact_name="connections.json")
    _regular_file(
        f"{vault}.verification-key",
        "connection verification key",
        exact_name="connections.json.verification-key",
    )
    profile = _regular_file(
        runtime_profile_manifest,
        "runtime profile manifest",
        exact_name="store-runtime-profile.v1.json",
    )
    profile_digest = str(runtime_profile_sha256 or "")
    if _HEX64.fullmatch(profile_digest) is None:
        raise InstalledChannelSupervisorContractError("runtime profile digest is invalid")
    if hashlib.sha256(profile.read_bytes()).hexdigest() != profile_digest:
        raise InstalledChannelSupervisorContractError("runtime profile digest mismatch")
    if (
        isinstance(engine_port, bool)
        or not isinstance(engine_port, int)
        or not 1024 <= engine_port <= 65535
    ):
        raise InstalledChannelSupervisorContractError("engine port is invalid")
    if (
        isinstance(engine_generation, bool)
        or not isinstance(engine_generation, int)
        or engine_generation < 1
    ):
        raise InstalledChannelSupervisorContractError("engine generation is invalid")
    boot_token = _secret(engine_boot_token, r"[0-9a-f]{64}", "engine boot token")
    runtime = _secret(runtime_key, r"sk-local-[0-9a-f]{64}", "runtime key")
    approval = _secret(approval_key, r"sk-approval-[0-9a-f]{64}", "approval key")
    paid = _secret(paid_media_key, r"sk-paid-media-[0-9a-f]{64}", "paid media key")
    weixin = _secret(
        weixin_bridge_key,
        r"sk-bridge-v2-weixin-[0-9a-f]{64}",
        "Weixin bridge key",
    )
    feishu = _secret(
        feishu_bridge_key,
        r"sk-bridge-v2-feishu-[0-9a-f]{64}",
        "Feishu bridge key",
    )
    if len({runtime, approval, paid, weixin, feishu}) != 5:
        raise InstalledChannelSupervisorContractError("installed capabilities overlap")
    app_id = str(feishu_app_id or "")
    app_secret = str(feishu_app_secret or "")
    if _APP_ID.fullmatch(app_id) is None:
        raise InstalledChannelSupervisorContractError("Feishu app id is invalid")
    if not 8 <= len(app_secret) <= 512 or any(ord(char) < 0x20 for char in app_secret):
        raise InstalledChannelSupervisorContractError("Feishu app secret is invalid")

    common = _closed_environment(source_environment)
    common.update(
        {
            "NACHUAN_ENV": "production",
            "DATA_DIR": str(data),
            "USAGE_DB_PATH": str(data / "usage.db"),
            "BRIDGE_ENGINE_URL": f"http://127.0.0.1:{engine_port}",
            "GATEWAY_HOST": "127.0.0.1",
            "GATEWAY_PORT": str(engine_port),
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
            "NACHUAN_RUNTIME_PROFILE": "store",
            "NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST": str(profile),
            "NACHUAN_STORE_RUNTIME_PROFILE_SHA256": profile_digest,
        }
    )
    engine_env = dict(common)
    engine_env.update(
        {
            "GATEWAY_API_KEYS": runtime,
            "APPROVAL_ADMIN_KEY": approval,
            "NACHUAN_PAID_MEDIA_API_KEY": paid,
            "NACHUAN_WEIXIN_BRIDGE_API_KEY": weixin,
            "NACHUAN_FEISHU_BRIDGE_API_KEY": feishu,
            "NACHUAN_CONNECTIONS_PATH": str(vault),
            "NACHUAN_ENGINE_BOOT_TOKEN": boot_token,
            "NACHUAN_ENGINE_GENERATION": str(engine_generation),
            "NACHUAN_ENGINE_PORT": str(engine_port),
            "NACHUAN_PROVIDER_CALL_LEDGER_MODE": "required",
            "NACHUAN_PROVIDER_CALL_LEDGER_PATH": str(data / "provider-calls.db"),
        }
    )
    weixin_env = dict(common)
    weixin_env.update(
        {
            "BRIDGE_API_KEY": weixin,
            "NACHUAN_WEIXIN_BRIDGE_API_KEY": weixin,
        }
    )
    feishu_env = dict(common)
    feishu_env.update(
        {
            "BRIDGE_API_KEY": feishu,
            "NACHUAN_FEISHU_BRIDGE_API_KEY": feishu,
            "FEISHU_APP_ID": app_id,
            "FEISHU_APP_SECRET": app_secret,
        }
    )
    cwd = str(engine.parent)
    command = str(engine)
    return {
        "engine": InstalledChildLaunch(
            command=command,
            args=(),
            cwd=cwd,
            environment=MappingProxyType(engine_env),
        ),
        "weixin": InstalledChildLaunch(
            command=command,
            args=("--nachuan-weixin-bridge",),
            cwd=cwd,
            environment=MappingProxyType(weixin_env),
        ),
        "feishu": InstalledChildLaunch(
            command=command,
            args=("--nachuan-feishu-bridge",),
            cwd=cwd,
            environment=MappingProxyType(feishu_env),
        ),
    }


def build_installed_channel_launches_from_config(
    *,
    config: InstalledChannelSupervisorConfig,
    installation_snapshot: InstallationRootSnapshot,
    epoch_anchor: InstalledChannelEpochAnchor,
    engine_executable: str | os.PathLike[str],
    data_directory: str | os.PathLike[str],
    connections_path: str | os.PathLike[str],
    engine_boot_token: str,
    runtime_profile_manifest: str | os.PathLike[str],
    runtime_profile_sha256: str,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, InstalledChildLaunch]:
    """Build launches only from one already verified DPAPI config snapshot."""

    if not isinstance(config, InstalledChannelSupervisorConfig):
        raise InstalledChannelSupervisorContractError(
            "installed channel configuration is invalid"
        )
    if not isinstance(epoch_anchor, InstalledChannelEpochAnchor):
        raise InstalledChannelSupervisorContractError(
            "installation epoch anchor is invalid"
        )
    epoch_anchor.validate(snapshot=installation_snapshot, config=config)
    return build_installed_channel_launches(
        engine_executable=engine_executable,
        data_directory=data_directory,
        connections_path=connections_path,
        engine_port=config.engine_port,
        engine_generation=config.generation,
        engine_boot_token=engine_boot_token,
        runtime_key=config.runtime_key,
        approval_key=config.approval_key,
        paid_media_key=config.paid_media_key,
        weixin_bridge_key=config.weixin_bridge_key,
        feishu_bridge_key=config.feishu_bridge_key,
        feishu_app_id=config.feishu_app_id,
        feishu_app_secret=config.feishu_app_secret,
        runtime_profile_manifest=runtime_profile_manifest,
        runtime_profile_sha256=runtime_profile_sha256,
        source_environment=source_environment,
    )


__all__ = [
    "InstalledChannelSupervisorContractError",
    "InstalledChannelEpochAnchor",
    "InstalledChannelSupervisorRuntime",
    "InstalledChannelSupervisorState",
    "InstalledChildLaunch",
    "build_installed_channel_launches",
    "build_installed_channel_launches_from_config",
]
