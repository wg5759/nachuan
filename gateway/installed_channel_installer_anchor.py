"""Read-only installer anchor for the installed channel Supervisor config."""

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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gateway.installation_root import InstallationRootSnapshot


_SCHEMA = "nachuan.installed-channel-supervisor-installer-anchor.v1"
_FILENAME = "installed-channel-supervisor.anchor.json"
_CONFIG_FILENAME = "installed-channel-supervisor.json"
_KEY_FILENAME = "installed-channel-supervisor.json.verification-key"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledChannelInstallerAnchorError(ValueError):
    pass


class Ed25519InstallerAnchorVerifier:
    """One embedded installer trust root with a domain-separated signature."""

    def __init__(self, public_key_spki_der: bytes) -> None:
        if (
            not isinstance(public_key_spki_der, bytes)
            or not 32 <= len(public_key_spki_der) <= 1024
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor public key is invalid"
            )
        try:
            key = serialization.load_der_public_key(public_key_spki_der)
        except (TypeError, ValueError) as exc:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor public key is invalid"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor public key is invalid"
            )
        canonical = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if canonical != public_key_spki_der:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor public key is not canonical"
            )
        self._key = key
        self.key_id = hashlib.sha256(canonical).hexdigest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if (
            not isinstance(payload, bytes)
            or not 1 <= len(payload) <= 16 * 1024
            or not isinstance(signature, bytes)
            or len(signature) != 64
        ):
            return False
        try:
            self._key.verify(
                signature,
                b"nachuan-installed-channel-supervisor-anchor-v1\0" + payload,
            )
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class InstalledChannelInstallerAnchorDependencies:
    assert_installer_acl: Callable[[Path, bool], None]
    assert_user_acl: Callable[[Path, bool], None]
    signer_key_id: str
    verify_signature: Callable[[bytes, bytes], bool]
    minimum_installer_release_sequence: int = 0
    minimum_keyring_sequence: int = 0

    def __post_init__(self) -> None:
        if (
            not callable(self.assert_installer_acl)
            or not callable(self.assert_user_acl)
            or not isinstance(self.signer_key_id, str)
            or _HEX64.fullmatch(self.signer_key_id) is None
            or not callable(self.verify_signature)
            or isinstance(self.minimum_installer_release_sequence, bool)
            or not isinstance(self.minimum_installer_release_sequence, int)
            or self.minimum_installer_release_sequence < 0
            or isinstance(self.minimum_keyring_sequence, bool)
            or not isinstance(self.minimum_keyring_sequence, int)
            or self.minimum_keyring_sequence < 0
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor dependencies are invalid"
            )


@dataclass(frozen=True, slots=True)
class InstalledChannelInstallerAnchor:
    installation_id: str
    installation_epoch: int
    installation_principal: str
    installer_release_sequence: int
    installer_keyring_sequence: int
    config_generation: int
    config_ciphertext_sha256: str
    verification_key_ciphertext_sha256: str
    signature_algorithm: str = "ed25519"
    signer_key_id: str = ""

    def __post_init__(self) -> None:
        if (
            _HEX64.fullmatch(str(self.installation_id or "")) is None
            or _HEX64.fullmatch(str(self.installation_principal or "")) is None
            or _HEX64.fullmatch(str(self.config_ciphertext_sha256 or "")) is None
            or _HEX64.fullmatch(
                str(self.verification_key_ciphertext_sha256 or "")
            )
            is None
            or self.signature_algorithm != "ed25519"
            or _HEX64.fullmatch(str(self.signer_key_id or "")) is None
            or isinstance(self.installation_epoch, bool)
            or not isinstance(self.installation_epoch, int)
            or self.installation_epoch < 1
            or isinstance(self.installer_release_sequence, bool)
            or not isinstance(self.installer_release_sequence, int)
            or self.installer_release_sequence < 0
            or isinstance(self.installer_keyring_sequence, bool)
            or not isinstance(self.installer_keyring_sequence, int)
            or self.installer_keyring_sequence < 0
            or isinstance(self.config_generation, bool)
            or not isinstance(self.config_generation, int)
            or not 1 <= self.config_generation <= 2**63 - 1
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor fields are invalid"
            )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _plain_identity(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise InstalledChannelInstallerAnchorError(
            "installer anchor path is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    ):
        raise InstalledChannelInstallerAnchorError(
            "installer anchor path is invalid"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _stable_read(path: Path, *, maximum_bytes: int) -> bytes:
    before = _plain_identity(path, directory=False)
    if not 1 <= before[3] <= maximum_bytes:
        raise InstalledChannelInstallerAnchorError(
            "installer anchor file size is invalid"
        )
    try:
        with path.open("rb") as stream:
            payload = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise InstalledChannelInstallerAnchorError(
            "installer anchor file is unavailable"
        ) from exc
    after = _plain_identity(path, directory=False)
    if before != after or len(payload) != before[3] or len(payload) > maximum_bytes:
        raise InstalledChannelInstallerAnchorError(
            "installer anchor file changed during verification"
        )
    return payload


class InstalledChannelInstallerAnchorStore:
    def __init__(
        self,
        path: str | Path,
        *,
        trusted_boundary: str | Path,
        user_config_boundary: str | Path,
        dependencies: InstalledChannelInstallerAnchorDependencies,
    ) -> None:
        anchor_path = Path(os.path.abspath(os.fspath(path)))
        boundary = Path(os.path.abspath(os.fspath(trusted_boundary)))
        user_boundary = Path(os.path.abspath(os.fspath(user_config_boundary)))
        if (
            not Path(path).is_absolute()
            or not Path(trusted_boundary).is_absolute()
            or not Path(user_config_boundary).is_absolute()
            or anchor_path.name.casefold() != _FILENAME
            or anchor_path.parent != boundary
            or user_boundary == boundary
            or not isinstance(dependencies, InstalledChannelInstallerAnchorDependencies)
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor location is invalid"
            )
        self.path = anchor_path
        self.boundary = boundary
        self.user_config_boundary = user_boundary
        self.dependencies = dependencies

    def create(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        config_generation: int,
        config_path: str | Path,
        verification_key_path: str | Path,
        sign_payload: Callable[[bytes], bytes],
        harden_installer_acl: Callable[[Path, bool], None],
    ) -> tuple[InstalledChannelInstallerAnchor, bool]:
        """Create one signed anchor without ever replacing an existing identity."""

        config = Path(os.path.abspath(os.fspath(config_path)))
        verification_key = Path(os.path.abspath(os.fspath(verification_key_path)))
        if (
            not isinstance(installation_snapshot, InstallationRootSnapshot)
            or installation_snapshot.status != "active"
            or installation_snapshot.lock_kind != "none"
            or installation_snapshot.reanchor_pending
            or isinstance(config_generation, bool)
            or not isinstance(config_generation, int)
            or not 1 <= config_generation <= 2**63 - 1
            or not Path(config_path).is_absolute()
            or not Path(verification_key_path).is_absolute()
            or config.parent != self.user_config_boundary
            or verification_key.parent != self.user_config_boundary
            or config.name.casefold() != _CONFIG_FILENAME
            or verification_key.name.casefold() != _KEY_FILENAME
            or not callable(sign_payload)
            or not callable(harden_installer_acl)
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor publication is invalid"
            )
        if self.path.exists():
            return (
                self.load(
                    installation_snapshot=installation_snapshot,
                    config_path=config,
                    verification_key_path=verification_key,
                ),
                False,
            )
        _plain_identity(self.boundary, directory=True)
        harden_installer_acl(self.boundary, True)
        self.dependencies.assert_installer_acl(self.boundary, True)
        _plain_identity(self.user_config_boundary, directory=True)
        self.dependencies.assert_user_acl(self.user_config_boundary, True)
        for candidate in (config, verification_key):
            _plain_identity(candidate, directory=False)
            self.dependencies.assert_user_acl(candidate, False)
        config_bytes = _stable_read(config, maximum_bytes=4 * 1024 * 1024)
        key_bytes = _stable_read(verification_key, maximum_bytes=4 * 1024 * 1024)
        body = {
            "schema": _SCHEMA,
            "installation_id": installation_snapshot.installation_id,
            "installation_epoch": installation_snapshot.epoch,
            "installation_principal": installation_snapshot.principal_digest,
            "installer_release_sequence": (
                installation_snapshot.updater.release_sequence
            ),
            "installer_keyring_sequence": (
                installation_snapshot.updater.keyring_sequence
            ),
            "config_generation": config_generation,
            "config_ciphertext_sha256": hashlib.sha256(config_bytes).hexdigest(),
            "verification_key_ciphertext_sha256": hashlib.sha256(
                key_bytes
            ).hexdigest(),
            "signature_algorithm": "ed25519",
            "signer_key_id": self.dependencies.signer_key_id,
        }
        canonical_body = _canonical(body)
        try:
            signature = sign_payload(canonical_body)
        except Exception as exc:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is unavailable"
            ) from exc
        if (
            not isinstance(signature, bytes)
            or len(signature) != 64
            or self.dependencies.verify_signature(canonical_body, signature) is not True
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is invalid"
            )
        raw = _canonical(
            {
                **body,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )
        temporary = ""
        created = False
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.boundary,
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
                raise InstalledChannelInstallerAnchorError(
                    "installer anchor could not be created atomically"
                ) from exc
        finally:
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass
        if created:
            harden_installer_acl(self.path, False)
            self.dependencies.assert_installer_acl(self.path, False)
        return (
            self.load(
                installation_snapshot=installation_snapshot,
                config_path=config,
                verification_key_path=verification_key,
            ),
            created,
        )

    def load(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        config_path: str | Path,
        verification_key_path: str | Path,
    ) -> InstalledChannelInstallerAnchor:
        config = Path(os.path.abspath(os.fspath(config_path)))
        verification_key = Path(os.path.abspath(os.fspath(verification_key_path)))
        if (
            not isinstance(installation_snapshot, InstallationRootSnapshot)
            or installation_snapshot.status != "active"
            or installation_snapshot.lock_kind != "none"
            or installation_snapshot.reanchor_pending
            or not Path(config_path).is_absolute()
            or not Path(verification_key_path).is_absolute()
            or config.parent != self.user_config_boundary
            or verification_key.parent != self.user_config_boundary
            or config.name.casefold() != _CONFIG_FILENAME
            or verification_key.name.casefold() != _KEY_FILENAME
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor binding is invalid"
            )
        _plain_identity(self.boundary, directory=True)
        self.dependencies.assert_installer_acl(self.boundary, True)
        _plain_identity(self.path, directory=False)
        self.dependencies.assert_installer_acl(self.path, False)
        _plain_identity(self.user_config_boundary, directory=True)
        self.dependencies.assert_user_acl(self.user_config_boundary, True)
        for candidate in (config, verification_key):
            _plain_identity(candidate, directory=False)
            self.dependencies.assert_user_acl(candidate, False)
        raw_anchor = _stable_read(self.path, maximum_bytes=16 * 1024)
        config_bytes = _stable_read(config, maximum_bytes=4 * 1024 * 1024)
        key_bytes = _stable_read(verification_key, maximum_bytes=4 * 1024 * 1024)
        try:
            document = json.loads(
                raw_anchor.decode("ascii", errors="strict"),
                parse_constant=_reject_constant,
                object_pairs_hook=_without_duplicates,
            )
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor JSON is invalid"
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
            "signer_key_id",
            "signature_b64",
        }
        if (
            not isinstance(document, dict)
            or set(document) != expected
            or document.get("schema") != _SCHEMA
            or raw_anchor != _canonical(document)
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor document is invalid"
            )
        encoded_signature = document.get("signature_b64")
        if (
            document.get("signature_algorithm") != "ed25519"
            or document.get("signer_key_id") != self.dependencies.signer_key_id
            or not isinstance(encoded_signature, str)
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is invalid"
            )
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
        except ValueError as exc:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is invalid"
            ) from exc
        if len(signature) != 64:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is invalid"
            )
        body = {key: value for key, value in document.items() if key != "signature_b64"}
        try:
            signature_valid = self.dependencies.verify_signature(
                _canonical(body), signature
            )
        except Exception as exc:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is unavailable"
            ) from exc
        if signature_valid is not True:
            raise InstalledChannelInstallerAnchorError(
                "installer anchor signature is invalid"
            )
        anchor = InstalledChannelInstallerAnchor(
            installation_id=document.get("installation_id"),  # type: ignore[arg-type]
            installation_epoch=document.get("installation_epoch"),  # type: ignore[arg-type]
            installation_principal=document.get("installation_principal"),  # type: ignore[arg-type]
            installer_release_sequence=document.get("installer_release_sequence"),  # type: ignore[arg-type]
            installer_keyring_sequence=document.get("installer_keyring_sequence"),  # type: ignore[arg-type]
            config_generation=document.get("config_generation"),  # type: ignore[arg-type]
            config_ciphertext_sha256=document.get("config_ciphertext_sha256"),  # type: ignore[arg-type]
            verification_key_ciphertext_sha256=document.get(
                "verification_key_ciphertext_sha256"
            ),  # type: ignore[arg-type]
            signature_algorithm=document.get("signature_algorithm"),  # type: ignore[arg-type]
            signer_key_id=document.get("signer_key_id"),  # type: ignore[arg-type]
        )
        if (
            anchor.installation_id != installation_snapshot.installation_id
            or anchor.installation_epoch != installation_snapshot.epoch
            or anchor.installation_principal
            != installation_snapshot.principal_digest
            or anchor.installer_release_sequence
            != installation_snapshot.updater.release_sequence
            or anchor.installer_keyring_sequence
            != installation_snapshot.updater.keyring_sequence
            or anchor.installer_release_sequence
            < self.dependencies.minimum_installer_release_sequence
            or anchor.installer_keyring_sequence
            < self.dependencies.minimum_keyring_sequence
            or anchor.config_ciphertext_sha256
            != hashlib.sha256(config_bytes).hexdigest()
            or anchor.verification_key_ciphertext_sha256
            != hashlib.sha256(key_bytes).hexdigest()
        ):
            raise InstalledChannelInstallerAnchorError(
                "installer anchor differs from active installation"
            )
        return anchor


__all__ = [
    "Ed25519InstallerAnchorVerifier",
    "InstalledChannelInstallerAnchor",
    "InstalledChannelInstallerAnchorDependencies",
    "InstalledChannelInstallerAnchorError",
    "InstalledChannelInstallerAnchorStore",
]
