"""Host-signed v2 anchor for one installed Supervisor authority."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from gateway.installation_root import InstallationRootSnapshot
from gateway.installed_channel_host_enrollment import (
    InstalledChannelHostSignerEnrollment,
)


_SCHEMA = "nachuan.installed-channel-supervisor-host-anchor.v2"
_FILENAME = "installed-channel-supervisor.anchor.json"
_CONFIG_FILENAME = "installed-channel-supervisor.json"
_KEY_FILENAME = "installed-channel-supervisor.json.verification-key"
_ALGORITHM = "ecdsa-p256-sha256"
_DOMAIN = b"nachuan-installed-channel-supervisor-host-anchor-v2\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledChannelHostAnchorError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelHostAnchor:
    installation_id: str
    installation_epoch: int
    installation_principal: str
    installer_release_sequence: int
    installer_keyring_sequence: int
    config_generation: int
    config_ciphertext_sha256: str
    verification_key_ciphertext_sha256: str
    host_signer_key_id: str
    host_enrollment_sha256: str


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
        raise InstalledChannelHostAnchorError(
            "host anchor path is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    ):
        raise InstalledChannelHostAnchorError("host anchor path is invalid")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _stable_read(path: Path, *, maximum_bytes: int) -> bytes:
    before = _plain(path, directory=False)
    if not 1 <= before[3] <= maximum_bytes:
        raise InstalledChannelHostAnchorError("host anchor input size is invalid")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstalledChannelHostAnchorError(
            "host anchor input is unavailable"
        ) from exc
    if _plain(path, directory=False) != before or len(raw) != before[3]:
        raise InstalledChannelHostAnchorError(
            "host anchor input changed during verification"
        )
    return raw


def _snapshot(value: object) -> InstallationRootSnapshot:
    if (
        not isinstance(value, InstallationRootSnapshot)
        or value.status != "active"
        or value.lock_kind != "none"
        or value.reanchor_pending
    ):
        raise InstalledChannelHostAnchorError(
            "host anchor installation is invalid"
        )
    return value


def _paths(
    *,
    config_path: str | Path,
    verification_key_path: str | Path,
    user_boundary: Path,
) -> tuple[Path, Path]:
    config = Path(os.path.abspath(os.fspath(config_path)))
    key = Path(os.path.abspath(os.fspath(verification_key_path)))
    if (
        not Path(config_path).is_absolute()
        or not Path(verification_key_path).is_absolute()
        or config.parent != user_boundary
        or key.parent != user_boundary
        or config.name.casefold() != _CONFIG_FILENAME
        or key.name.casefold() != _KEY_FILENAME
    ):
        raise InstalledChannelHostAnchorError("host anchor binding is invalid")
    return config, key


class InstalledChannelHostAnchorStore:
    def __init__(
        self,
        path: str | Path,
        *,
        trusted_boundary: str | Path,
        user_config_boundary: str | Path,
        assert_installer_acl: Callable[[Path, bool], None],
        assert_user_acl: Callable[[Path, bool], None],
    ) -> None:
        target = Path(os.path.abspath(os.fspath(path)))
        trusted = Path(os.path.abspath(os.fspath(trusted_boundary)))
        user = Path(os.path.abspath(os.fspath(user_config_boundary)))
        if (
            not Path(path).is_absolute()
            or not Path(trusted_boundary).is_absolute()
            or not Path(user_config_boundary).is_absolute()
            or target.parent != trusted
            or target.name.casefold() != _FILENAME
            or trusted == user
            or not callable(assert_installer_acl)
            or not callable(assert_user_acl)
        ):
            raise InstalledChannelHostAnchorError(
                "host anchor location is invalid"
            )
        self.path = target
        self.trusted_boundary = trusted
        self.user_config_boundary = user
        self._assert_installer_acl = assert_installer_acl
        self._assert_user_acl = assert_user_acl

    def load(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        config_path: str | Path,
        verification_key_path: str | Path,
        enrollment: InstalledChannelHostSignerEnrollment,
    ) -> InstalledChannelHostAnchor:
        snapshot = _snapshot(installation_snapshot)
        config, key = _paths(
            config_path=config_path,
            verification_key_path=verification_key_path,
            user_boundary=self.user_config_boundary,
        )
        if not isinstance(enrollment, InstalledChannelHostSignerEnrollment):
            raise InstalledChannelHostAnchorError(
                "host anchor enrollment is invalid"
            )
        _plain(self.trusted_boundary, directory=True)
        self._assert_installer_acl(self.trusted_boundary, True)
        _plain(self.path, directory=False)
        self._assert_installer_acl(self.path, False)
        _plain(self.user_config_boundary, directory=True)
        self._assert_user_acl(self.user_config_boundary, True)
        for candidate in (config, key):
            _plain(candidate, directory=False)
            self._assert_user_acl(candidate, False)
        raw = _stable_read(self.path, maximum_bytes=16 * 1024)
        config_raw = _stable_read(config, maximum_bytes=4 * 1024 * 1024)
        key_raw = _stable_read(key, maximum_bytes=4 * 1024 * 1024)
        try:
            document = json.loads(raw.decode("ascii", errors="strict"))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstalledChannelHostAnchorError(
                "host anchor JSON is invalid"
            ) from exc
        expected = {
            "schema",
            "installation_id",
            "installation_epoch",
            "installation_principal",
            "installer_release_sequence",
            "installer_keyring_sequence",
            "config_generation",
            "config_ciphertext_sha256",
            "verification_key_ciphertext_sha256",
            "signature_algorithm",
            "host_signer_key_id",
            "host_enrollment_sha256",
            "signature_base64",
        }
        if (
            not isinstance(document, dict)
            or set(document) != expected
            or document.get("schema") != _SCHEMA
            or document.get("signature_algorithm") != _ALGORITHM
            or raw != _canonical(document)
        ):
            raise InstalledChannelHostAnchorError(
                "host anchor document is invalid"
            )
        if (
            document.get("installation_id") != snapshot.installation_id
            or document.get("installation_epoch") != snapshot.epoch
            or document.get("installation_principal") != snapshot.principal_digest
            or document.get("installer_release_sequence")
            != snapshot.updater.release_sequence
            or document.get("installer_keyring_sequence")
            != snapshot.updater.keyring_sequence
            or document.get("host_signer_key_id") != enrollment.key_id
            or document.get("host_enrollment_sha256")
            != enrollment.document_sha256
            or document.get("config_ciphertext_sha256")
            != hashlib.sha256(config_raw).hexdigest()
            or document.get("verification_key_ciphertext_sha256")
            != hashlib.sha256(key_raw).hexdigest()
        ):
            raise InstalledChannelHostAnchorError(
                "host anchor differs from active installation"
            )
        generation = document.get("config_generation")
        encoded_signature = document.get("signature_base64")
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= 2**63 - 1
            or not isinstance(encoded_signature, str)
        ):
            raise InstalledChannelHostAnchorError(
                "host anchor fields are invalid"
            )
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
        except ValueError as exc:
            raise InstalledChannelHostAnchorError(
                "host anchor signature is invalid"
            ) from exc
        body = {name: value for name, value in document.items() if name != "signature_base64"}
        if not enrollment.verify(_DOMAIN + _canonical(body), signature):
            raise InstalledChannelHostAnchorError(
                "host anchor signature is invalid"
            )
        return InstalledChannelHostAnchor(
            installation_id=snapshot.installation_id,
            installation_epoch=snapshot.epoch,
            installation_principal=snapshot.principal_digest,
            installer_release_sequence=snapshot.updater.release_sequence,
            installer_keyring_sequence=snapshot.updater.keyring_sequence,
            config_generation=generation,
            config_ciphertext_sha256=str(document["config_ciphertext_sha256"]),
            verification_key_ciphertext_sha256=str(
                document["verification_key_ciphertext_sha256"]
            ),
            host_signer_key_id=enrollment.key_id,
            host_enrollment_sha256=enrollment.document_sha256,
        )

    def create_if_absent(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        config_generation: int,
        config_path: str | Path,
        verification_key_path: str | Path,
        enrollment: InstalledChannelHostSignerEnrollment,
        signer,
        harden_installer_acl: Callable[[Path, bool], None],
    ) -> tuple[InstalledChannelHostAnchor, bool]:
        snapshot = _snapshot(installation_snapshot)
        config, key = _paths(
            config_path=config_path,
            verification_key_path=verification_key_path,
            user_boundary=self.user_config_boundary,
        )
        if (
            not isinstance(enrollment, InstalledChannelHostSignerEnrollment)
            or getattr(signer, "algorithm", None) != _ALGORITHM
            or getattr(signer, "key_id", None) != enrollment.key_id
            or getattr(signer, "public_key_spki_der", None)
            != enrollment.public_key_spki_der
            or not callable(getattr(signer, "sign", None))
            or not callable(harden_installer_acl)
            or isinstance(config_generation, bool)
            or not isinstance(config_generation, int)
            or not 1 <= config_generation <= 2**63 - 1
        ):
            raise InstalledChannelHostAnchorError(
                "host anchor publication is invalid"
            )
        if self.path.exists():
            return (
                self.load(
                    installation_snapshot=snapshot,
                    config_path=config,
                    verification_key_path=key,
                    enrollment=enrollment,
                ),
                False,
            )
        _plain(self.trusted_boundary, directory=True)
        harden_installer_acl(self.trusted_boundary, True)
        self._assert_installer_acl(self.trusted_boundary, True)
        _plain(self.user_config_boundary, directory=True)
        self._assert_user_acl(self.user_config_boundary, True)
        for candidate in (config, key):
            _plain(candidate, directory=False)
            self._assert_user_acl(candidate, False)
        config_raw = _stable_read(config, maximum_bytes=4 * 1024 * 1024)
        key_raw = _stable_read(key, maximum_bytes=4 * 1024 * 1024)
        body = {
            "schema": _SCHEMA,
            "installation_id": snapshot.installation_id,
            "installation_epoch": snapshot.epoch,
            "installation_principal": snapshot.principal_digest,
            "installer_release_sequence": snapshot.updater.release_sequence,
            "installer_keyring_sequence": snapshot.updater.keyring_sequence,
            "config_generation": config_generation,
            "config_ciphertext_sha256": hashlib.sha256(config_raw).hexdigest(),
            "verification_key_ciphertext_sha256": hashlib.sha256(
                key_raw
            ).hexdigest(),
            "signature_algorithm": _ALGORITHM,
            "host_signer_key_id": enrollment.key_id,
            "host_enrollment_sha256": enrollment.document_sha256,
        }
        try:
            signature = signer.sign(_DOMAIN + _canonical(body))
        except Exception as exc:
            raise InstalledChannelHostAnchorError(
                "host anchor signature is unavailable"
            ) from exc
        if not enrollment.verify(_DOMAIN + _canonical(body), signature):
            raise InstalledChannelHostAnchorError(
                "host anchor signature is invalid"
            )
        raw = _canonical(
            {
                **body,
                "signature_base64": base64.b64encode(signature).decode("ascii"),
            }
        )
        temporary = ""
        created = False
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.trusted_boundary,
                delete=False,
            ) as stream:
                temporary = stream.name
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, self.path)
                created = True
            except FileExistsError:
                created = False
            except OSError as exc:
                raise InstalledChannelHostAnchorError(
                    "host anchor could not be created atomically"
                ) from exc
        finally:
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass
        if created:
            harden_installer_acl(self.path, False)
            self._assert_installer_acl(self.path, False)
        return (
            self.load(
                installation_snapshot=snapshot,
                config_path=config,
                verification_key_path=key,
                enrollment=enrollment,
            ),
            created,
        )


__all__ = [
    "InstalledChannelHostAnchor",
    "InstalledChannelHostAnchorError",
    "InstalledChannelHostAnchorStore",
]
