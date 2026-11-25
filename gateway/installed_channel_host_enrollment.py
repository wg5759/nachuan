"""Per-installation host signer enrollment protected by InstallerTrust ACLs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from gateway.installation_root import InstallationRootSnapshot


_SCHEMA = "nachuan.installed-channel-host-signer-enrollment.v1"
_FILENAME = "installed-channel-supervisor.host-enrollment.json"
_ALGORITHM = "ecdsa-p256-sha256"
_PROOF_DOMAIN = b"nachuan-installed-channel-host-enrollment-v1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER = re.compile(r"^[A-Za-z0-9._ -]{1,96}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledChannelHostEnrollmentError(ValueError):
    pass


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
        raise InstalledChannelHostEnrollmentError(
            "host enrollment path is unavailable"
        ) from exc
    if (
        stat.S_ISDIR(metadata.st_mode) != directory
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
    ):
        raise InstalledChannelHostEnrollmentError(
            "host enrollment path is invalid"
        )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
    )


def _stable_read(path: Path) -> bytes:
    before = _plain(path, directory=False)
    if not 1 <= before[3] <= 16 * 1024:
        raise InstalledChannelHostEnrollmentError(
            "host enrollment file size is invalid"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstalledChannelHostEnrollmentError(
            "host enrollment is unavailable"
        ) from exc
    if _plain(path, directory=False) != before or len(raw) != before[3]:
        raise InstalledChannelHostEnrollmentError(
            "host enrollment changed during verification"
        )
    return raw


def _public_key(spki_der: bytes) -> ec.EllipticCurvePublicKey:
    if not isinstance(spki_der, bytes) or not 64 <= len(spki_der) <= 1024:
        raise InstalledChannelHostEnrollmentError(
            "host signer public key is invalid"
        )
    try:
        key = serialization.load_der_public_key(spki_der)
    except (TypeError, ValueError) as exc:
        raise InstalledChannelHostEnrollmentError(
            "host signer public key is invalid"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise InstalledChannelHostEnrollmentError(
            "host signer public key is invalid"
        )
    canonical = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical != spki_der:
        raise InstalledChannelHostEnrollmentError(
            "host signer public key is not canonical"
        )
    return key


@dataclass(frozen=True, slots=True)
class InstalledChannelHostSignerEnrollment:
    installation_id: str
    installation_epoch: int
    release_sequence: int
    keyring_sequence: int
    embedded_trust_sha256: str
    key_id: str
    provider: str
    hardware_backed: bool
    document_sha256: str
    public_key_spki_der: bytes = field(repr=False)
    _key: ec.EllipticCurvePublicKey = field(repr=False, compare=False)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > 16 * 1024
            or not isinstance(signature, bytes)
            or not 64 <= len(signature) <= 80
        ):
            return False
        try:
            self._key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            return False
        return True


def _body(
    *,
    snapshot: InstallationRootSnapshot,
    embedded_trust_sha256: str,
    key_id: str,
    provider: str,
    hardware_backed: bool,
    public_key_spki_der: bytes,
) -> dict[str, object]:
    return {
        "schema": _SCHEMA,
        "installation_id": snapshot.installation_id,
        "installation_epoch": snapshot.epoch,
        "release_sequence": snapshot.updater.release_sequence,
        "keyring_sequence": snapshot.updater.keyring_sequence,
        "embedded_trust_sha256": embedded_trust_sha256,
        "signature_algorithm": _ALGORITHM,
        "host_signer_key_id": key_id,
        "provider": provider,
        "hardware_backed": hardware_backed,
        "public_key_spki_base64": base64.b64encode(public_key_spki_der).decode(
            "ascii"
        ),
    }


class InstalledChannelHostSignerEnrollmentStore:
    def __init__(
        self,
        path: str | Path,
        *,
        trusted_boundary: str | Path,
        assert_installer_acl: Callable[[Path, bool], None],
    ) -> None:
        target = Path(os.path.abspath(os.fspath(path)))
        boundary = Path(os.path.abspath(os.fspath(trusted_boundary)))
        if (
            not Path(path).is_absolute()
            or not Path(trusted_boundary).is_absolute()
            or target.name.casefold() != _FILENAME
            or target.parent != boundary
            or not callable(assert_installer_acl)
        ):
            raise InstalledChannelHostEnrollmentError(
                "host enrollment location is invalid"
            )
        self.path = target
        self.boundary = boundary
        self._assert_acl = assert_installer_acl

    @staticmethod
    def _snapshot(snapshot: object) -> InstallationRootSnapshot:
        if (
            not isinstance(snapshot, InstallationRootSnapshot)
            or snapshot.status != "active"
            or snapshot.lock_kind != "none"
            or snapshot.reanchor_pending
        ):
            raise InstalledChannelHostEnrollmentError(
                "host enrollment installation is invalid"
            )
        return snapshot

    def load(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        embedded_trust_sha256: str,
    ) -> InstalledChannelHostSignerEnrollment:
        snapshot = self._snapshot(installation_snapshot)
        trust_digest = str(embedded_trust_sha256 or "").casefold()
        if _HEX64.fullmatch(trust_digest) is None:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment trust digest is invalid"
            )
        _plain(self.boundary, directory=True)
        self._assert_acl(self.boundary, True)
        _plain(self.path, directory=False)
        self._assert_acl(self.path, False)
        raw = _stable_read(self.path)
        try:
            document = json.loads(raw.decode("ascii", errors="strict"))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment JSON is invalid"
            ) from exc
        expected = {
            "schema",
            "installation_id",
            "installation_epoch",
            "release_sequence",
            "keyring_sequence",
            "embedded_trust_sha256",
            "signature_algorithm",
            "host_signer_key_id",
            "provider",
            "hardware_backed",
            "public_key_spki_base64",
            "proof_signature_base64",
        }
        if (
            not isinstance(document, dict)
            or set(document) != expected
            or document.get("schema") != _SCHEMA
            or document.get("signature_algorithm") != _ALGORITHM
            or raw != _canonical(document)
        ):
            raise InstalledChannelHostEnrollmentError(
                "host enrollment document is invalid"
            )
        key_id = document.get("host_signer_key_id")
        provider = document.get("provider")
        hardware_backed = document.get("hardware_backed")
        encoded_key = document.get("public_key_spki_base64")
        encoded_proof = document.get("proof_signature_base64")
        if (
            not isinstance(key_id, str)
            or _HEX64.fullmatch(key_id) is None
            or not isinstance(provider, str)
            or _PROVIDER.fullmatch(provider) is None
            or type(hardware_backed) is not bool
            or not isinstance(encoded_key, str)
            or not isinstance(encoded_proof, str)
        ):
            raise InstalledChannelHostEnrollmentError(
                "host enrollment signer is invalid"
            )
        try:
            public_der = base64.b64decode(encoded_key, validate=True)
            proof = base64.b64decode(encoded_proof, validate=True)
        except ValueError as exc:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment signer is invalid"
            ) from exc
        key = _public_key(public_der)
        if hashlib.sha256(public_der).hexdigest() != key_id:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment signer identity is invalid"
            )
        body = {key: value for key, value in document.items() if key != "proof_signature_base64"}
        try:
            key.verify(
                proof,
                _PROOF_DOMAIN + _canonical(body),
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError) as exc:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment proof is invalid"
            ) from exc
        if (
            document.get("installation_id") != snapshot.installation_id
            or document.get("installation_epoch") != snapshot.epoch
            or document.get("release_sequence") != snapshot.updater.release_sequence
            or document.get("keyring_sequence") != snapshot.updater.keyring_sequence
            or document.get("embedded_trust_sha256") != trust_digest
        ):
            raise InstalledChannelHostEnrollmentError(
                "host enrollment differs from active installation"
            )
        return InstalledChannelHostSignerEnrollment(
            installation_id=snapshot.installation_id,
            installation_epoch=snapshot.epoch,
            release_sequence=snapshot.updater.release_sequence,
            keyring_sequence=snapshot.updater.keyring_sequence,
            embedded_trust_sha256=trust_digest,
            key_id=key_id,
            provider=provider,
            hardware_backed=hardware_backed,
            document_sha256=hashlib.sha256(raw).hexdigest(),
            public_key_spki_der=public_der,
            _key=key,
        )

    def create_if_absent(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        signer,
        embedded_trust_sha256: str,
        harden_installer_acl: Callable[[Path, bool], None],
    ) -> tuple[InstalledChannelHostSignerEnrollment, bool]:
        snapshot = self._snapshot(installation_snapshot)
        trust_digest = str(embedded_trust_sha256 or "").casefold()
        public_der = getattr(signer, "public_key_spki_der", None)
        key_id = getattr(signer, "key_id", None)
        provider = getattr(signer, "provider", None)
        hardware_backed = getattr(signer, "hardware_backed", None)
        sign = getattr(signer, "sign", None)
        if (
            _HEX64.fullmatch(trust_digest) is None
            or getattr(signer, "algorithm", None) != _ALGORITHM
            or not isinstance(public_der, bytes)
            or not isinstance(key_id, str)
            or _HEX64.fullmatch(key_id) is None
            or not isinstance(provider, str)
            or _PROVIDER.fullmatch(provider) is None
            or type(hardware_backed) is not bool
            or not callable(sign)
            or not callable(harden_installer_acl)
        ):
            raise InstalledChannelHostEnrollmentError(
                "host signer is invalid"
            )
        key = _public_key(public_der)
        if hashlib.sha256(public_der).hexdigest() != key_id:
            raise InstalledChannelHostEnrollmentError(
                "host signer identity is invalid"
            )
        if self.path.exists():
            loaded = self.load(
                installation_snapshot=snapshot,
                embedded_trust_sha256=trust_digest,
            )
            if loaded.key_id != key_id or loaded.public_key_spki_der != public_der:
                raise InstalledChannelHostEnrollmentError(
                    "host signer differs from enrollment"
                )
            return loaded, False
        _plain(self.boundary, directory=True)
        harden_installer_acl(self.boundary, True)
        self._assert_acl(self.boundary, True)
        body = _body(
            snapshot=snapshot,
            embedded_trust_sha256=trust_digest,
            key_id=key_id,
            provider=provider,
            hardware_backed=hardware_backed,
            public_key_spki_der=public_der,
        )
        try:
            proof = sign(_PROOF_DOMAIN + _canonical(body))
            key.verify(
                proof,
                _PROOF_DOMAIN + _canonical(body),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as exc:
            raise InstalledChannelHostEnrollmentError(
                "host signer proof is unavailable"
            ) from exc
        raw = _canonical(
            {
                **body,
                "proof_signature_base64": base64.b64encode(proof).decode("ascii"),
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
                raise InstalledChannelHostEnrollmentError(
                    "host enrollment could not be created atomically"
                ) from exc
        finally:
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass
        if created:
            harden_installer_acl(self.path, False)
            self._assert_acl(self.path, False)
        loaded = self.load(
            installation_snapshot=snapshot,
            embedded_trust_sha256=trust_digest,
        )
        if loaded.key_id != key_id:
            raise InstalledChannelHostEnrollmentError(
                "host enrollment signer changed during publication"
            )
        return loaded, created


__all__ = [
    "InstalledChannelHostEnrollmentError",
    "InstalledChannelHostSignerEnrollment",
    "InstalledChannelHostSignerEnrollmentStore",
]
