"""Identity-bound persistent status receipts for the installed Supervisor."""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from gateway.installed_channel_file_lock import InstalledChannelFileLock
from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControl,
)
from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json,
    write_protected_json_if_absent,
)


_SCHEMA = "nachuan.installed-channel-supervisor-runtime-status.v1"
_PURPOSE = "nachuan/installed-channel-supervisor-runtime-status"
_FILENAME = "installed-channel-supervisor-status.json"
_ROLES = ("engine", "weixin", "feishu")
_STATES = frozenset({"starting", "ready", "degraded", "stopped", "failed"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LOCK = threading.RLock()


class InstalledChannelStatusError(ValueError):
    pass


class InstalledChannelStatusConflict(InstalledChannelStatusError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelProcessReceipt:
    pid: int
    started_utc_ticks: int
    command_line_sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.pid, bool)
            or not isinstance(self.pid, int)
            or self.pid <= 0
            or isinstance(self.started_utc_ticks, bool)
            or not isinstance(self.started_utc_ticks, int)
            or self.started_utc_ticks <= 0
            or not isinstance(self.command_line_sha256, str)
            or _HEX64.fullmatch(self.command_line_sha256) is None
        ):
            raise InstalledChannelStatusError("process receipt is invalid")


@dataclass(frozen=True, slots=True)
class InstalledChannelSupervisorStatus:
    status_generation: int
    installation_id: str
    installation_epoch: int
    installation_principal: str
    config_generation: int
    control_generation: int
    published_utc_ns: int
    stop_requested: bool
    supervisor: InstalledChannelProcessReceipt
    roles: Mapping[str, InstalledChannelProcessReceipt]
    state: str
    restart_attempt: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_generation, bool)
            or not isinstance(self.status_generation, int)
            or not 1 <= self.status_generation <= 2**63 - 1
            or isinstance(self.control_generation, bool)
            or not isinstance(self.control_generation, int)
            or self.control_generation < 1
            or isinstance(self.published_utc_ns, bool)
            or not isinstance(self.published_utc_ns, int)
            or self.published_utc_ns <= 0
            or type(self.stop_requested) is not bool
            or not isinstance(self.supervisor, InstalledChannelProcessReceipt)
            or self.state not in _STATES
            or isinstance(self.restart_attempt, bool)
            or not isinstance(self.restart_attempt, int)
            or not 0 <= self.restart_attempt <= 1_000_000
        ):
            raise InstalledChannelStatusError("status receipt is invalid")
        try:
            InstalledChannelEpochAnchor(
                installation_id=self.installation_id,
                installation_epoch=self.installation_epoch,
                installation_principal=self.installation_principal,
                config_generation=self.config_generation,
            )
        except Exception as exc:
            raise InstalledChannelStatusError("status receipt is invalid") from exc
        roles = dict(self.roles)
        if tuple(roles) not in {(), _ROLES} or any(
            not isinstance(value, InstalledChannelProcessReceipt)
            for value in roles.values()
        ):
            raise InstalledChannelStatusError("status process roles are invalid")
        if self.state == "ready" and (
            tuple(roles) != _ROLES or self.stop_requested
        ):
            raise InstalledChannelStatusError("ready status is invalid")
        if self.state == "stopped" and roles:
            raise InstalledChannelStatusError("stopped status is invalid")
        object.__setattr__(self, "roles", MappingProxyType(roles))

    @property
    def ready(self) -> bool:
        return self.state == "ready" and not self.stop_requested

    def matches(self, anchor: InstalledChannelEpochAnchor) -> bool:
        return (
            isinstance(anchor, InstalledChannelEpochAnchor)
            and self.installation_id == anchor.installation_id
            and self.installation_epoch == anchor.installation_epoch
            and self.installation_principal == anchor.installation_principal
            and self.config_generation == anchor.config_generation
        )


def _process_document(receipt: InstalledChannelProcessReceipt) -> dict[str, object]:
    return {
        "pid": receipt.pid,
        "started_utc_ticks": receipt.started_utc_ticks,
        "command_line_sha256": receipt.command_line_sha256,
    }


def _parse_process(value: object) -> InstalledChannelProcessReceipt:
    if not isinstance(value, dict) or set(value) != {
        "pid",
        "started_utc_ticks",
        "command_line_sha256",
    }:
        raise InstalledChannelStatusError("process receipt is invalid")
    return InstalledChannelProcessReceipt(
        pid=value.get("pid"),  # type: ignore[arg-type]
        started_utc_ticks=value.get("started_utc_ticks"),  # type: ignore[arg-type]
        command_line_sha256=value.get("command_line_sha256"),  # type: ignore[arg-type]
    )


def _document(status: InstalledChannelSupervisorStatus) -> dict[str, object]:
    return {
        "schema": _SCHEMA,
        "status_generation": status.status_generation,
        "installation_id": status.installation_id,
        "installation_epoch": status.installation_epoch,
        "installation_principal": status.installation_principal,
        "config_generation": status.config_generation,
        "control_generation": status.control_generation,
        "published_utc_ns": status.published_utc_ns,
        "stop_requested": status.stop_requested,
        "supervisor": _process_document(status.supervisor),
        "roles": {
            role: _process_document(receipt)
            for role, receipt in status.roles.items()
        },
        "state": status.state,
        "restart_attempt": status.restart_attempt,
    }


def _parse(document: object) -> InstalledChannelSupervisorStatus:
    expected = {
        "schema",
        "status_generation",
        "installation_id",
        "installation_epoch",
        "installation_principal",
        "config_generation",
        "control_generation",
        "published_utc_ns",
        "stop_requested",
        "supervisor",
        "roles",
        "state",
        "restart_attempt",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != _SCHEMA
        or not isinstance(document.get("roles"), dict)
    ):
        raise InstalledChannelStatusError("status receipt is invalid")
    raw_roles = document["roles"]
    roles = {
        role: _parse_process(raw_roles[role])
        for role in _ROLES
        if role in raw_roles
    }
    if set(roles) != set(raw_roles):
        raise InstalledChannelStatusError("status process roles are invalid")
    return InstalledChannelSupervisorStatus(
        status_generation=document.get("status_generation"),  # type: ignore[arg-type]
        installation_id=document.get("installation_id"),  # type: ignore[arg-type]
        installation_epoch=document.get("installation_epoch"),  # type: ignore[arg-type]
        installation_principal=document.get("installation_principal"),  # type: ignore[arg-type]
        config_generation=document.get("config_generation"),  # type: ignore[arg-type]
        control_generation=document.get("control_generation"),  # type: ignore[arg-type]
        published_utc_ns=document.get("published_utc_ns"),  # type: ignore[arg-type]
        stop_requested=document.get("stop_requested"),  # type: ignore[arg-type]
        supervisor=_parse_process(document.get("supervisor")),
        roles=roles,
        state=document.get("state"),  # type: ignore[arg-type]
        restart_attempt=document.get("restart_attempt"),  # type: ignore[arg-type]
    )


class InstalledChannelSupervisorStatusStore:
    def __init__(
        self,
        path: str | Path,
        *,
        wall_clock_ns: Callable[[], int] | None = None,
    ) -> None:
        candidate = Path(os.path.abspath(os.fspath(path)))
        if not Path(path).is_absolute() or candidate.name.casefold() != _FILENAME:
            raise InstalledChannelStatusError("status path is invalid")
        self.path = candidate
        self.lock_path = candidate.with_name(candidate.name + ".lock")
        self._wall_clock_ns = wall_clock_ns or time.time_ns

    def _now_ns(self) -> int:
        try:
            value = self._wall_clock_ns()
        except Exception as exc:
            raise InstalledChannelStatusError("status clock is unavailable") from exc
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise InstalledChannelStatusError("status clock is invalid")
        return value

    @staticmethod
    def _validate_binding(
        anchor: object, control: object | None = None
    ) -> tuple[InstalledChannelEpochAnchor, InstalledChannelSupervisorControl | None]:
        if not isinstance(anchor, InstalledChannelEpochAnchor):
            raise InstalledChannelStatusError("installation anchor is invalid")
        if control is not None and (
            not isinstance(control, InstalledChannelSupervisorControl)
            or not control.matches(anchor)
        ):
            raise InstalledChannelStatusConflict(
                "control document differs from installation anchor"
            )
        return anchor, control

    def _load_locked(
        self, anchor: InstalledChannelEpochAnchor
    ) -> InstalledChannelSupervisorStatus:
        try:
            status = _parse(
                read_protected_json(
                    self.path,
                    purpose=_PURPOSE,
                    migrate_plaintext=False,
                )
            )
        except (FileNotFoundError, SecureStorageError) as exc:
            raise InstalledChannelStatusError("status receipt is unavailable") from exc
        if not status.matches(anchor):
            raise InstalledChannelStatusConflict(
                "status receipt differs from installation anchor"
            )
        return status

    def load(
        self, *, anchor: InstalledChannelEpochAnchor
    ) -> InstalledChannelSupervisorStatus:
        active, _ = self._validate_binding(anchor)
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelStatusConflict,
            busy_message="status store is busy",
        ):
            return self._load_locked(active)

    def safe_status(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        maximum_age_ns: int,
    ) -> dict[str, object]:
        if (
            isinstance(maximum_age_ns, bool)
            or not isinstance(maximum_age_ns, int)
            or maximum_age_ns <= 0
        ):
            raise InstalledChannelStatusError("status freshness budget is invalid")
        status = self.load(anchor=anchor)
        now = self._now_ns()
        if now < status.published_utc_ns:
            raise InstalledChannelStatusConflict("status clock moved backwards")
        age = now - status.published_utc_ns
        fresh = age <= maximum_age_ns
        return {
            "schema": "nachuan.installed-channel-supervisor-safe-status.v1",
            "status_generation": status.status_generation,
            "installation_epoch": status.installation_epoch,
            "installation_principal": status.installation_principal,
            "config_generation": status.config_generation,
            "control_generation": status.control_generation,
            "published_utc_ns": status.published_utc_ns,
            "age_ns": age,
            "fresh": fresh,
            "state": status.state,
            "ready": bool(status.ready and fresh),
            "stop_requested": status.stop_requested,
            "restart_attempt": status.restart_attempt,
            "supervisor_pid": status.supervisor.pid,
            "supervisor_started_utc_ticks": status.supervisor.started_utc_ticks,
            "supervisor_command_line_sha256": status.supervisor.command_line_sha256,
            "role_pids": {
                role: receipt.pid for role, receipt in status.roles.items()
            },
            "role_started_utc_ticks": {
                role: receipt.started_utc_ticks
                for role, receipt in status.roles.items()
            },
            "role_command_line_sha256": {
                role: receipt.command_line_sha256
                for role, receipt in status.roles.items()
            },
        }

    def publish(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        control: InstalledChannelSupervisorControl,
        expected_status_generation: int,
        supervisor: InstalledChannelProcessReceipt,
        roles: Mapping[str, InstalledChannelProcessReceipt],
        state: str,
        restart_attempt: int,
    ) -> InstalledChannelSupervisorStatus:
        active, bound_control = self._validate_binding(anchor, control)
        assert bound_control is not None
        if (
            isinstance(expected_status_generation, bool)
            or not isinstance(expected_status_generation, int)
            or expected_status_generation < 0
        ):
            raise InstalledChannelStatusConflict("expected generation is invalid")
        status = InstalledChannelSupervisorStatus(
            status_generation=expected_status_generation + 1,
            installation_id=active.installation_id,
            installation_epoch=active.installation_epoch,
            installation_principal=active.installation_principal,
            config_generation=active.config_generation,
            control_generation=bound_control.control_generation,
            published_utc_ns=self._now_ns(),
            stop_requested=bound_control.stop_requested,
            supervisor=supervisor,
            roles=roles,
            state=state,
            restart_attempt=restart_attempt,
        )
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelStatusConflict,
            busy_message="status store is busy",
        ):
            if self.path.exists():
                current = self._load_locked(active)
                if current.status_generation != expected_status_generation:
                    raise InstalledChannelStatusConflict("status generation changed")
                if status.published_utc_ns < current.published_utc_ns:
                    raise InstalledChannelStatusConflict("status clock moved backwards")
                write_protected_json(self.path, _document(status), purpose=_PURPOSE)
            elif expected_status_generation != 0 or not write_protected_json_if_absent(
                self.path, _document(status), purpose=_PURPOSE
            ):
                raise InstalledChannelStatusConflict("status generation changed")
        return status


__all__ = [
    "InstalledChannelProcessReceipt",
    "InstalledChannelStatusConflict",
    "InstalledChannelStatusError",
    "InstalledChannelSupervisorStatus",
    "InstalledChannelSupervisorStatusStore",
]
