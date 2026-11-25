"""Service-owned machine-scope DPAPI vault with no user credentials."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from gateway.secure_store import (
    SecureStorageError,
    _crypt_protect,
    _crypt_unprotect,
)
from gateway.installed_nachuan_core_identity import (
    validate_nachuan_core_service_sid,
)
from gateway.installation_root import installation_principal as derive_installation_principal


_ENVELOPE_SCHEMA = "nachuan.service-machine-protected-json.v1"
_PROTECTION = "windows-dpapi-local-machine"
_DOCUMENT_SCHEMA = "nachuan.installed-service-machine-secrets.v1"
_STATUS_SCHEMA = "nachuan.installed-service-machine-vault-status.v1"
_PURPOSE = "nachuan/installed-service-machine-secrets"
_FILENAME = "installed-service-secrets.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledServiceMachineSecretStoreError(RuntimeError):
    pass


class InstalledServiceMachineSecretStoreConflict(
    InstalledServiceMachineSecretStoreError
):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class InstalledServiceMachineSecrets:
    installation_id: str
    installation_epoch: int
    installation_principal: str
    service_sid: str
    generation: int
    service_instance_id: str
    pipe_root_key: str = field(repr=False)
    control_key: str = field(repr=False)
    state_hmac_key: str = field(repr=False)

    def __post_init__(self) -> None:
        values = {
            "pipe_root_key": (self.pipe_root_key, "sk-service-pipe-"),
            "control_key": (self.control_key, "sk-service-control-"),
            "state_hmac_key": (self.state_hmac_key, "sk-service-state-"),
        }
        if (
            _HEX64.fullmatch(str(self.installation_id or "")) is None
            or isinstance(self.installation_epoch, bool)
            or not isinstance(self.installation_epoch, int)
            or self.installation_epoch < 1
            or _HEX64.fullmatch(str(self.installation_principal or "")) is None
            or validate_nachuan_core_service_sid(self.service_sid)
            != self.service_sid.upper()
            or
            isinstance(self.generation, bool)
            or self.generation != 1
            or _HEX64.fullmatch(str(self.service_instance_id or "")) is None
            or any(
                not isinstance(value, str)
                or not value.startswith(prefix)
                or _HEX64.fullmatch(value[len(prefix) :]) is None
                for value, prefix in values.values()
            )
            or len({value for value, _prefix in values.values()}) != len(values)
        ):
            raise InstalledServiceMachineSecretStoreError(
                "service machine secrets are invalid"
            )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _plain(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise InstalledServiceMachineSecretStoreError(
            "service machine vault path is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    ):
        raise InstalledServiceMachineSecretStoreError(
            "service machine vault path is invalid"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _body(secrets_value: InstalledServiceMachineSecrets) -> dict[str, object]:
    return {
        "schema": _DOCUMENT_SCHEMA,
        "installation_id": secrets_value.installation_id,
        "installation_epoch": secrets_value.installation_epoch,
        "installation_principal": secrets_value.installation_principal,
        "service_sid": secrets_value.service_sid,
        "generation": secrets_value.generation,
        "service_instance_id": secrets_value.service_instance_id,
        "pipe_root_key": secrets_value.pipe_root_key,
        "control_key": secrets_value.control_key,
        "state_hmac_key": secrets_value.state_hmac_key,
    }


def _parse(
    value: object,
    *,
    installation_id: str,
    installation_epoch: int,
    installation_principal: str,
    service_sid: str,
) -> InstalledServiceMachineSecrets:
    expected = {
        "schema",
        "installation_id",
        "installation_epoch",
        "installation_principal",
        "service_sid",
        "generation",
        "service_instance_id",
        "pipe_root_key",
        "control_key",
        "state_hmac_key",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != _DOCUMENT_SCHEMA
    ):
        raise InstalledServiceMachineSecretStoreError(
            "service machine secrets document is invalid"
        )
    return InstalledServiceMachineSecrets(
        installation_id=value.get("installation_id"),  # type: ignore[arg-type]
        installation_epoch=value.get("installation_epoch"),  # type: ignore[arg-type]
        installation_principal=value.get("installation_principal"),  # type: ignore[arg-type]
        service_sid=value.get("service_sid"),  # type: ignore[arg-type]
        generation=value.get("generation"),  # type: ignore[arg-type]
        service_instance_id=value.get("service_instance_id"),  # type: ignore[arg-type]
        pipe_root_key=value.get("pipe_root_key"),  # type: ignore[arg-type]
        control_key=value.get("control_key"),  # type: ignore[arg-type]
        state_hmac_key=value.get("state_hmac_key"),  # type: ignore[arg-type]
    )


class InstalledServiceMachineSecretStore:
    def __init__(
        self,
        path: str | Path,
        *,
        trusted_boundary: str | Path,
        installation_id: str,
        installation_epoch: int,
        installation_principal: str,
        service_sid: str,
        harden_state_acl: Callable[[Path, bool], None],
        assert_state_acl: Callable[[Path, bool], None],
        assert_state_handle_acl: Callable[[int, bool], None],
    ) -> None:
        target = Path(os.path.abspath(os.fspath(path)))
        boundary = Path(os.path.abspath(os.fspath(trusted_boundary)))
        if (
            not Path(path).is_absolute()
            or not Path(trusted_boundary).is_absolute()
            or target.parent != boundary
            or target.name.casefold() != _FILENAME
            or boundary.name.casefold() != "servicestate"
            or _HEX64.fullmatch(str(installation_id or "")) is None
            or isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
            or _HEX64.fullmatch(str(installation_principal or "")) is None
            or not callable(harden_state_acl)
            or not callable(assert_state_acl)
            or not callable(assert_state_handle_acl)
        ):
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault location is invalid"
            )
        if str(installation_principal) != derive_installation_principal(
            installation_id, installation_epoch
        ):
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault installation principal is invalid"
            )
        self.path = target
        self.boundary = boundary
        self.installation_id = installation_id
        self.installation_epoch = installation_epoch
        self.installation_principal = installation_principal
        try:
            self.service_sid = validate_nachuan_core_service_sid(service_sid)
        except ValueError as exc:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault service SID is invalid"
            ) from exc
        self._purpose = (
            f"{_PURPOSE}/{installation_id}/{installation_epoch}/"
            f"{installation_principal}/{self.service_sid}"
        )
        self._harden_acl = harden_state_acl
        self._assert_acl = assert_state_acl
        self._assert_handle_acl = assert_state_handle_acl

    def initialize(self) -> InstalledServiceMachineSecrets:
        _plain(self.boundary, directory=True)
        self._harden_acl(self.boundary, True)
        self._assert_acl(self.boundary, True)
        if self.path.exists():
            raise InstalledServiceMachineSecretStoreConflict(
                "service machine vault already exists"
            )
        created = InstalledServiceMachineSecrets(
            installation_id=self.installation_id,
            installation_epoch=self.installation_epoch,
            installation_principal=self.installation_principal,
            service_sid=self.service_sid,
            generation=1,
            service_instance_id=secrets.token_hex(32),
            pipe_root_key="sk-service-pipe-" + secrets.token_hex(32),
            control_key="sk-service-control-" + secrets.token_hex(32),
            state_hmac_key="sk-service-state-" + secrets.token_hex(32),
        )
        try:
            ciphertext = _crypt_protect(
                _canonical(_body(created)),
                purpose=self._purpose,
                machine_scope=True,
            )
        except SecureStorageError as exc:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault encryption failed"
            ) from exc
        envelope = _canonical(
            {
                "schema": _ENVELOPE_SCHEMA,
                "protection": _PROTECTION,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
        )
        temporary = ""
        published = False
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.boundary,
                delete=False,
            ) as stream:
                temporary = stream.name
                stream.write(envelope)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, self.path)
                published = True
            except FileExistsError as exc:
                raise InstalledServiceMachineSecretStoreConflict(
                    "service machine vault already exists"
                ) from exc
            except OSError as exc:
                raise InstalledServiceMachineSecretStoreError(
                    "service machine vault could not be created atomically"
                ) from exc
        finally:
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass
        if not published:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault was not published"
            )
        self._harden_acl(self.path, False)
        self._assert_acl(self.path, False)
        loaded = self.load()
        if loaded != created:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault readback differs"
            )
        return loaded

    def load(self) -> InstalledServiceMachineSecrets:
        before_boundary = _plain(self.boundary, directory=True)
        self._assert_acl(self.boundary, True)
        before = _plain(self.path, directory=False)
        self._assert_acl(self.path, False)
        if before[3] > 64 * 1024:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault exceeds its byte limit"
            )
        try:
            with self.path.open("rb") as stream:
                descriptor = stream.fileno()
                handle_before = os.fstat(descriptor)
                self._assert_handle_acl(descriptor, False)
                raw = stream.read(64 * 1024 + 1)
                handle_after = os.fstat(descriptor)
        except OSError as exc:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault is unavailable"
            ) from exc
        handle_before_identity = (
            int(handle_before.st_dev),
            int(handle_before.st_ino),
            int(stat.S_IFMT(handle_before.st_mode)),
            int(handle_before.st_size),
        )
        handle_after_identity = (
            int(handle_after.st_dev),
            int(handle_after.st_ino),
            int(stat.S_IFMT(handle_after.st_mode)),
            int(handle_after.st_size),
        )
        if (
            _plain(self.boundary, directory=True) != before_boundary
            or _plain(self.path, directory=False) != before
            or len(raw) != before[3]
            or handle_before_identity != before
            or handle_after_identity != before
        ):
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault changed during verification"
            )
        try:
            envelope = json.loads(raw.decode("ascii", errors="strict"))
            if (
                not isinstance(envelope, dict)
                or set(envelope) != {"schema", "protection", "ciphertext"}
                or envelope.get("schema") != _ENVELOPE_SCHEMA
                or envelope.get("protection") != _PROTECTION
                or raw != _canonical(envelope)
                or not isinstance(envelope.get("ciphertext"), str)
            ):
                raise ValueError("invalid envelope")
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            plaintext = _crypt_unprotect(
                ciphertext,
                purpose=self._purpose,
                machine_scope=True,
            )
            document = json.loads(plaintext.decode("ascii", errors="strict"))
        except (ValueError, UnicodeError, json.JSONDecodeError, SecureStorageError) as exc:
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault is invalid"
            ) from exc
        parsed = _parse(
            document,
            installation_id=self.installation_id,
            installation_epoch=self.installation_epoch,
            installation_principal=self.installation_principal,
            service_sid=self.service_sid,
        )
        if (
            parsed.installation_id != self.installation_id
            or parsed.installation_epoch != self.installation_epoch
            or parsed.installation_principal != self.installation_principal
            or parsed.service_sid != self.service_sid
        ):
            raise InstalledServiceMachineSecretStoreError(
                "service machine vault differs from installation"
            )
        return parsed

    def safe_status(self) -> dict[str, object]:
        value = self.load()
        return {
            "schema": _STATUS_SCHEMA,
            "generation": value.generation,
            "service_instance_id": value.service_instance_id,
            "service_keys_configured": True,
        }


__all__ = [
    "InstalledServiceMachineSecretStore",
    "InstalledServiceMachineSecretStoreConflict",
    "InstalledServiceMachineSecretStoreError",
    "InstalledServiceMachineSecrets",
]
