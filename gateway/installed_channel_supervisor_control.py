"""Persistent, fail-closed control latch for the installed channel Supervisor."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path

from gateway.installed_channel_file_lock import InstalledChannelFileLock
from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json,
    write_protected_json_if_absent,
)


_SCHEMA = "nachuan.installed-channel-supervisor-control.v1"
_PURPOSE = "nachuan/installed-channel-supervisor-control"
_FILENAME = "installed-channel-supervisor-control.json"
_LOCK = threading.RLock()


class InstalledChannelControlError(ValueError):
    pass


class InstalledChannelControlConflict(InstalledChannelControlError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelSupervisorControl:
    control_generation: int
    installation_id: str
    installation_epoch: int
    installation_principal: str
    config_generation: int
    stop_requested: bool

    def __post_init__(self) -> None:
        if (
            isinstance(self.control_generation, bool)
            or not isinstance(self.control_generation, int)
            or not 1 <= self.control_generation <= 2**63 - 1
            or type(self.stop_requested) is not bool
        ):
            raise InstalledChannelControlError("control document is invalid")
        try:
            InstalledChannelEpochAnchor(
                installation_id=self.installation_id,
                installation_epoch=self.installation_epoch,
                installation_principal=self.installation_principal,
                config_generation=self.config_generation,
            )
        except Exception as exc:
            raise InstalledChannelControlError("control document is invalid") from exc

    def matches(self, anchor: InstalledChannelEpochAnchor) -> bool:
        return (
            isinstance(anchor, InstalledChannelEpochAnchor)
            and self.installation_id == anchor.installation_id
            and self.installation_epoch == anchor.installation_epoch
            and self.installation_principal == anchor.installation_principal
            and self.config_generation == anchor.config_generation
        )


def _document(control: InstalledChannelSupervisorControl) -> dict[str, object]:
    return {
        "schema": _SCHEMA,
        "control_generation": control.control_generation,
        "installation_id": control.installation_id,
        "installation_epoch": control.installation_epoch,
        "installation_principal": control.installation_principal,
        "config_generation": control.config_generation,
        "stop_requested": control.stop_requested,
    }


def _parse(document: object) -> InstalledChannelSupervisorControl:
    expected = {
        "schema",
        "control_generation",
        "installation_id",
        "installation_epoch",
        "installation_principal",
        "config_generation",
        "stop_requested",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != _SCHEMA
    ):
        raise InstalledChannelControlError("control document is invalid")
    return InstalledChannelSupervisorControl(
        control_generation=document.get("control_generation"),  # type: ignore[arg-type]
        installation_id=document.get("installation_id"),  # type: ignore[arg-type]
        installation_epoch=document.get("installation_epoch"),  # type: ignore[arg-type]
        installation_principal=document.get("installation_principal"),  # type: ignore[arg-type]
        config_generation=document.get("config_generation"),  # type: ignore[arg-type]
        stop_requested=document.get("stop_requested"),  # type: ignore[arg-type]
    )


class InstalledChannelSupervisorControlStore:
    def __init__(self, path: str | Path) -> None:
        candidate = Path(os.path.abspath(os.fspath(path)))
        if not Path(path).is_absolute() or candidate.name.casefold() != _FILENAME:
            raise InstalledChannelControlError("control path is invalid")
        self.path = candidate
        self.lock_path = candidate.with_name(candidate.name + ".lock")

    @staticmethod
    def _require_anchor(anchor: object) -> InstalledChannelEpochAnchor:
        if not isinstance(anchor, InstalledChannelEpochAnchor):
            raise InstalledChannelControlError("installation anchor is invalid")
        return anchor

    def _load_locked(
        self, anchor: InstalledChannelEpochAnchor
    ) -> InstalledChannelSupervisorControl:
        try:
            control = _parse(
                read_protected_json(
                    self.path,
                    purpose=_PURPOSE,
                    migrate_plaintext=False,
                )
            )
        except (FileNotFoundError, SecureStorageError) as exc:
            raise InstalledChannelControlError("control document is unavailable") from exc
        if not control.matches(anchor):
            raise InstalledChannelControlConflict(
                "control document differs from installation anchor"
            )
        return control

    def initialize(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        stop_requested: bool = False,
    ) -> InstalledChannelSupervisorControl:
        active = self._require_anchor(anchor)
        if type(stop_requested) is not bool:
            raise InstalledChannelControlError("initial Stop state is invalid")
        control = InstalledChannelSupervisorControl(
            control_generation=1,
            installation_id=active.installation_id,
            installation_epoch=active.installation_epoch,
            installation_principal=active.installation_principal,
            config_generation=active.config_generation,
            stop_requested=stop_requested,
        )
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelControlConflict,
            busy_message="control store is busy",
        ):
            if self.path.exists() or not write_protected_json_if_absent(
                self.path,
                _document(control),
                purpose=_PURPOSE,
            ):
                raise InstalledChannelControlConflict("control document already exists")
        return control

    def load(
        self, *, anchor: InstalledChannelEpochAnchor
    ) -> InstalledChannelSupervisorControl:
        active = self._require_anchor(anchor)
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelControlConflict,
            busy_message="control store is busy",
        ):
            return self._load_locked(active)

    def _set_stop_requested(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        expected_control_generation: int,
        stop_requested: bool,
    ) -> InstalledChannelSupervisorControl:
        active = self._require_anchor(anchor)
        if (
            isinstance(expected_control_generation, bool)
            or not isinstance(expected_control_generation, int)
            or expected_control_generation < 1
        ):
            raise InstalledChannelControlConflict("expected generation is invalid")
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelControlConflict,
            busy_message="control store is busy",
        ):
            current = self._load_locked(active)
            if current.control_generation != expected_control_generation:
                raise InstalledChannelControlConflict("control generation changed")
            if current.control_generation >= 2**63 - 1:
                raise InstalledChannelControlConflict("control generation exhausted")
            updated = InstalledChannelSupervisorControl(
                control_generation=current.control_generation + 1,
                installation_id=current.installation_id,
                installation_epoch=current.installation_epoch,
                installation_principal=current.installation_principal,
                config_generation=current.config_generation,
                stop_requested=stop_requested,
            )
            write_protected_json(self.path, _document(updated), purpose=_PURPOSE)
            return updated

    def request_stop(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        expected_control_generation: int,
    ) -> InstalledChannelSupervisorControl:
        return self._set_stop_requested(
            anchor=anchor,
            expected_control_generation=expected_control_generation,
            stop_requested=True,
        )

    def request_resume(
        self,
        *,
        anchor: InstalledChannelEpochAnchor,
        expected_control_generation: int,
    ) -> InstalledChannelSupervisorControl:
        return self._set_stop_requested(
            anchor=anchor,
            expected_control_generation=expected_control_generation,
            stop_requested=False,
        )


__all__ = [
    "InstalledChannelControlConflict",
    "InstalledChannelControlError",
    "InstalledChannelSupervisorControl",
    "InstalledChannelSupervisorControlStore",
]
